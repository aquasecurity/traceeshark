#include "tracee.h"

struct process_node {
    struct process_info *process;
    GHashTable *children;
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

static void free_process_node_cb(gpointer data)
{
    struct process_node *node = (struct process_node *)data;

    g_hash_table_destroy(node->children);
    g_free(node);
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
        node->children = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);

        // insert node into the tree
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
        parent_node->children = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
        pid_key = g_new(gint32, 1);
        *pid_key = ppid;
        g_tree_insert(process_tree, pid_key, parent_node);
    }
    
    // update chidren list
    pid_key = g_new(gint32, 1);
    *pid_key = pid;
    g_hash_table_insert(parent_node->children, pid_key, node);
}

static gint pid_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    return *(gint32 *)a - *(gint32 *)b;
}

GTree *process_tree_construct(void)
{
    GTree *process_tree = g_tree_new_full(pid_compare, NULL, g_free, free_process_node_cb);
    
    // iterate through all processes, adding them to the tree
    wmem_map_foreach(processes, process_tree_construct_cb, process_tree);

    return process_tree;
}

static gboolean get_root_pids_cb(gpointer key, gpointer value, gpointer data)
{
    gint32 pid = *(gint32 *)key;
    struct process_node *node = (struct process_node *)value;
    GArray *root_pids = (GArray *)data;

    if (node->parent_pid == 0)
        g_array_append_val(root_pids, pid);

    // return FALSE so the traversal isn't stopped
    return FALSE;
}

GArray *process_tree_get_root_pids(GTree *process_tree)
{
    GArray *root_pids = g_array_new(FALSE, FALSE, sizeof(gint32));

    g_tree_foreach(process_tree, get_root_pids_cb, root_pids);
    return root_pids;
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

static void get_children_pids_cb(gpointer key, gpointer value _U_, gpointer user_data)
{
    gint32 pid = *(gint32 *)key;
    GArray *children_pids = (GArray *)user_data;

    g_array_append_val(children_pids, pid);
}

GArray *process_tree_get_children_pids(GTree *process_tree, gint32 pid)
{
    struct process_node *node;
    GArray *children_pids;

    DISSECTOR_ASSERT((node = g_tree_lookup(process_tree, &pid)) != NULL);
    children_pids = g_array_new(FALSE, FALSE, sizeof(gint32));

    g_hash_table_foreach(node->children, get_children_pids_cb, children_pids);

    return children_pids;
}