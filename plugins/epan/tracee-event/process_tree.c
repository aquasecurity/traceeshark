#include "tracee.h"

struct process_node {
    struct process_info *process;
    wmem_map_t *children;
    bool has_parent;
};

wmem_tree_t *process_tree;

void process_tree_init(void)
{
    process_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

void process_tree_update(struct process_info *process)
{
    struct process_node *node, *parent;
    gint32 *children_list_key;

    // ignore PID 0
    if (process->host_pid == 0)
        return;

    // this process does not exist in the tree yet - insert it
    if ((node = wmem_tree_lookup32(process_tree, process->host_pid)) == NULL) {
        node = wmem_new0(wmem_file_scope(), struct process_node);
        node->children = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
        wmem_tree_insert32(process_tree, process->host_pid, node);
    }

    // this process has no info yet - add it
    if (node->process == NULL) {
        node->process = wmem_memdup(wmem_file_scope(), process, sizeof(*process));
        node->process->name = wmem_strdup(wmem_file_scope(), node->process->name);
    }
    // this process already has info
    else {
        // update the process name from the event if needed
        if (strcmp(node->process->name, process->name) != 0)
            node->process->name = wmem_strdup(wmem_file_scope(), process->name);

        // the logic from this point onwards deals with the parent, it should be done only
        // if this is the first time we encounter this process to avoid inconsistencies
        // when a process has multiple parents across the capture (can happen if it got orphaned)
        return;
    }
    
    // this process has no parent
    if (process->host_ppid == 0)
        return;
    
    // make sure the parent process exists in the tree
    if ((parent = wmem_tree_lookup32(process_tree, process->host_ppid)) == NULL) {
        parent = wmem_new0(wmem_file_scope(), struct process_node);
        parent->children = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
        parent->has_parent = FALSE;
        wmem_tree_insert32(process_tree, process->host_ppid, parent);
        node->has_parent = TRUE;
    }
    else
        node->has_parent = TRUE;

    // this process is not in its parent's children list - add it
    if (!wmem_map_contains(parent->children, &process->host_pid)) {
        children_list_key = wmem_new(wmem_file_scope(), gint32);
        *children_list_key = process->host_pid;
        wmem_map_insert(parent->children, children_list_key, node);
    }
}

static bool get_root_pids_cb(const void *key, void *value, void *userdata)
{
    guint key_val;
    struct process_node *node = (struct process_node *)value;
    GArray *root_pids = (GArray *)userdata;

    if (!node->has_parent) {
        key_val = GPOINTER_TO_UINT(key);
        g_array_append_val(root_pids, key_val);
    }

    // return FALSE so the traversal isn't stopped
    return FALSE;
}

GArray *process_tree_get_root_pids(void)
{
    GArray *root_pids = g_array_new(FALSE, FALSE, sizeof(gint32));

    wmem_tree_foreach(process_tree, get_root_pids_cb, root_pids);
    return root_pids;
}

struct process_info *process_tree_get_process(gint32 pid)
{
    struct process_node *node;

    if ((node = wmem_tree_lookup32(process_tree, pid)) == NULL)
        return NULL;
    
    return node->process;
}

static void get_children_pids_cb(gpointer key, gpointer value _U_, gpointer user_data)
{
    gint32 pid = *(gint32 *)key;
    GArray *children_pids = (GArray *)user_data;

    g_array_append_val(children_pids, pid);
}

GArray *process_tree_get_children_pids(gint32 pid)
{
    struct process_node *node;
    GArray *children_pids;

    DISSECTOR_ASSERT((node = wmem_tree_lookup32(process_tree, pid)) != NULL);
    children_pids = g_array_new(FALSE, FALSE, sizeof(gint32));

    wmem_map_foreach(node->children, get_children_pids_cb, children_pids);

    return children_pids;
}