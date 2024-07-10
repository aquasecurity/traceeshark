#include "tracee.h"

struct process_node {
    struct process_info *process;
    gint32 parent_pid;
};

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

void process_tree_update(struct tracee_dissector_data *data)
{
    gint *fork_child_pid, *fork_child_tid;
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
    }
}

static void process_tree_construct_cb(gpointer key, gpointer value, gpointer user_data)
{
    struct process_node *node, *parent_node;
    gint32 *pid_key, *ppid_val, ppid;
    gint32 pid = *(gint32 *)key;
    struct process_info *process = (struct process_info *)value;
    GTree *process_tree = (GTree *)user_data;

    // this process already exists in the tree (as a parent of a previously seen process) - update its info
    if ((node = g_tree_lookup(process_tree, &process->host_pid)) != NULL)
        node->process = process;
    // create process node and insert it
    else {
        node = g_new0(struct process_node, 1);
        node->process = process;
        pid_key = g_new(gint32, 1);
        *pid_key = pid;
        g_tree_insert(process_tree, pid_key, node);
    }

    // get effective PPID of this process
    if ((ppid_val = wmem_map_lookup(process_real_parents, &pid)) != NULL)
        ppid = *ppid_val;
    else
        ppid = process->host_ppid;
    
    if (ppid == 0) {
        return;
    }

    node->parent_pid = ppid;
    
    // the parent is not in the tree yet - insert it
    if ((parent_node = g_tree_lookup(process_tree, &ppid)) == NULL) {
        parent_node = g_new0(struct process_node, 1);
        pid_key = g_new(gint32, 1);
        *pid_key = ppid;
        g_tree_insert(process_tree, pid_key, parent_node);
    }
}

static gint pid_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    return *(gint32 *)a - *(gint32 *)b;
}

GTree *process_tree_construct(void)
{
    GTree *process_tree = g_tree_new_full(pid_compare, NULL, g_free, g_free);
    
    // iterate through all processes, adding them to the tree
    wmem_map_foreach(processes, process_tree_construct_cb, process_tree);

    return process_tree;
}

struct process_info *process_tree_get_process(GTree *process_tree, gint32 pid)
{
    struct process_node *node;

    if ((node = g_tree_lookup(process_tree, &pid)) == NULL)
        return NULL;
    
    return node->process;
}

struct process_info *process_tree_get_parent(GTree *process_tree, gint32 pid)
{
    struct process_node *node, *parent_node;

    if ((node = g_tree_lookup(process_tree, &pid)) == NULL)
        return NULL;
    
    if (node->parent_pid == 0)
        return NULL;
    
    DISSECTOR_ASSERT((parent_node = g_tree_lookup(process_tree, &node->parent_pid)) != NULL);
    return parent_node->process;
}