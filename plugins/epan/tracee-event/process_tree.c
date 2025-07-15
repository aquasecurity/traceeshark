#include "tracee.h"

// map from PID to process info
wmem_map_t *processes;

// map from PID to process parent exctracted from fork events
wmem_map_t *process_real_parents;

void process_tree_init(void)
{
    processes = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int_hash, g_int_equal);
    process_real_parents = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int_hash, g_int_equal);

    // register fields needed from fork event
    register_wanted_field("tracee.args.sched_process_fork.child_pid");
    register_wanted_field("tracee.args.sched_process_fork.child_tid");
}

static struct container_info *dup_container_info(const struct container_info *container)
{
    struct container_info *new_container = wmem_new0(wmem_file_scope(), struct container_info);
    if (container->id != NULL)
        new_container->id = wmem_strdup(wmem_file_scope(), container->id);
    if (container->name != NULL)
        new_container->name = wmem_strdup(wmem_file_scope(), container->name);
    if (container->image != NULL)
        new_container->image = wmem_strdup(wmem_file_scope(), container->image);
    
    return new_container;
}

void process_tree_update(struct tracee_dissector_data *data)
{
    const gint *fork_child_pid, *fork_child_tid;
    gint *pid_key, *pid_val;
    struct process_info *process;

    // this is a fork event - update the real parents map
    if (strcmp(data->event_name, "sched_process_fork") == 0) {
        DISSECTOR_ASSERT((fork_child_pid = wanted_field_get_int("tracee.args.sched_process_fork.child_pid")) != NULL);
        DISSECTOR_ASSERT((fork_child_tid = wanted_field_get_int("tracee.args.sched_process_fork.child_tid")) != NULL);

        // PID and TID are the same - this is a new process
        if (*fork_child_pid == *fork_child_tid) {
            pid_key = wmem_new(wmem_file_scope(), gint);
            *pid_key = *fork_child_pid;
            pid_val = wmem_new(wmem_file_scope(), gint);
            *pid_val = data->process->host_pid;
            wmem_map_insert(process_real_parents, pid_key, pid_val);
        }
    }

    // ignore PID 0
    if (data->process->host_pid == 0)
        return;

    // this process does not exist in the processes map yet - insert it
    if ((process = wmem_map_lookup(processes, &data->process->host_pid)) == NULL) {
        process = wmem_memdup(wmem_file_scope(), data->process, sizeof(struct process_info));
        process->name = wmem_strdup(wmem_file_scope(), data->process->name);
        if (process->exec_path != NULL)
            process->exec_path = wmem_strdup(wmem_file_scope(), process->exec_path);
        if (process->command_line != NULL)
            process->command_line = wmem_strdup(wmem_file_scope(), process->command_line);
        if (process->container != NULL)
            process->container = dup_container_info(process->container);
        pid_key = wmem_new(wmem_file_scope(), gint);
        *pid_key = process->host_pid;
        wmem_map_insert(processes, pid_key, process);
    }
    // this process already has info
    else {
        // update the process name from the event if needed
        if (strcmp(process->name, data->process->name) != 0)
            process->name = wmem_strdup(wmem_file_scope(), data->process->name);
        
        // update the command line from the event if needed
        if (strcmp(data->event_name, "sched_process_exec") == 0) {
            process->exec_path = wmem_strdup(wmem_file_scope(), data->process->exec_path);
            process->command_line = wmem_strdup(wmem_file_scope(), data->process->command_line);
        }

        // update the container info if it didn't have any already
        if (process->container == NULL && data->process->container != NULL)
            process->container = dup_container_info(data->process->container);
    }
}

struct process_info *process_tree_get_process(gint32 pid)
{
    return wmem_map_lookup(processes, &pid);
}

struct process_info *process_tree_get_parent(gint32 pid)
{
    gint32 ppid, *ppid_val;
    struct process_info *process;

    // get effective PPID of this process
    if ((ppid_val = wmem_map_lookup(process_real_parents, &pid)) != NULL)
        ppid = *ppid_val;
    else {
        DISSECTOR_ASSERT((process = wmem_map_lookup(processes, &pid)) != NULL);
        ppid = process->host_ppid;
    }
    
    if (ppid == 0)
        return NULL;
    
    return wmem_map_lookup(processes, &ppid);
}