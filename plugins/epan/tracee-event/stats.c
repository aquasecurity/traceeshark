#include "tracee.h"
#include "../common.h"

#include <epan/stats_tree.h>

#if ((WIRESHARK_VERSION_MAJOR > 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR > 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO >= 1)))
#define STATS_TREE_PACKET_HAS_FLAGS
#endif

#if ((WIRESHARK_VERSION_MAJOR > 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR >= 3)))
#define STATS_TREE_NEW_API
#endif

#define STATS_TREE_INIT_FUNC_NAME(name) name##_stats_tree_init
#define STATS_TREE_INIT_FUNC(name) static void STATS_TREE_INIT_FUNC_NAME(name)(stats_tree *st)

#define STATS_TREE_CLEANUP_FUNC_NAME(name) name##_stats_tree_cleanup
#define STATS_TREE_CLEANUP_FUNC(name) static void STATS_TREE_CLEANUP_FUNC_NAME(name)(stats_tree *st)

#define STATS_TREE_PACKET_FUNC_NAME(name) name##_stats_tree_packet

#ifdef STATS_TREE_PACKET_HAS_FLAGS
#define STATS_TREE_PACKET_FUNC(name) static tap_packet_status STATS_TREE_PACKET_FUNC_NAME(name)(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt, const void *p, tap_flags_t flags)
#else /* !STATS_TREE_PACKET_HAS_FLAGS */
#define STATS_TREE_PACKET_FUNC(name) static tap_packet_status STATS_TREE_PACKET_FUNC_NAME(name)(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt , const void *p)
#endif /* STATS_TREE_PACKET_HAS_FLAGS */

#define STATS_TREE_PACKET_GLOBAL_FUNC(name)         STATS_TREE_PACKET_FUNC(name##_global)
#define STATS_TREE_PACKET_PER_CONTAINER_FUNC(name)  STATS_TREE_PACKET_FUNC(name##_container)

#define STATS_TREE_PACKET_GENERIC_FUNC_NAME(name) STATS_TREE_PACKET_FUNC_NAME(name##_generic)

#ifdef STATS_TREE_PACKET_HAS_FLAGS

#define STATS_TREE_PACKET_GENERIC_FUNC(name) static tap_packet_status STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt , const void *p, tap_flags_t flags, bool per_container)

#define STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(name)                                                                      \
    STATS_TREE_PACKET_GLOBAL_FUNC(name) { return STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(st, pinfo, edt, p, flags, false); }          \
    STATS_TREE_PACKET_PER_CONTAINER_FUNC(name) { return STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(st, pinfo, edt, p, flags, true); }

#else /* !STATS_TREE_PACKET_HAS_FLAGS */

#define STATS_TREE_PACKET_GENERIC_FUNC(name) static tap_packet_status STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt , const void *p, bool per_container)

#define STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(name)                                                              \
    STATS_TREE_PACKET_GLOBAL_FUNC(name) { return STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(st, pinfo, edt, p, false); }         \
    STATS_TREE_PACKET_PER_CONTAINER_FUNC(name) { return STATS_TREE_PACKET_GENERIC_FUNC_NAME(name)(st, pinfo, edt, p, true); }

#endif /* STATS_TREE_PACKET_HAS_FLAGS */

#ifdef STATS_TREE_NEW_API

#define __REGISTER_STATS_TREE(name, menu_display, column_name, init_func, cleanup_func) \
    stats_tree_cfg *name##_st = stats_tree_register_plugin("tracee", "tracee_" #name,   \
        "Tracee" STATS_TREE_MENU_SEPARATOR menu_display, 0,                             \
        STATS_TREE_PACKET_FUNC_NAME(name), init_func, cleanup_func);                    \
    stats_tree_set_first_column_name(name##_st, column_name)

#define __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name, init_func, cleanup_func)            \
    __REGISTER_STATS_TREE(name##_global, menu_display STATS_TREE_MENU_SEPARATOR "Global", column_name, init_func, cleanup_func); \
    __REGISTER_STATS_TREE(name##_container, menu_display STATS_TREE_MENU_SEPARATOR "Per Container", column_name, init_func, cleanup_func)

#else /* !STATS_TREE_NEW_API */

#define __REGISTER_STATS_TREE(name, menu_display, column_name, init_func, cleanup_func) \
    stats_tree_register_plugin("tracee", "tracee_" #name, "Tracee/" menu_display, 0, STATS_TREE_PACKET_FUNC_NAME(name), init_func, cleanup_func)

#define __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name, init_func, cleanup_func) \
    __REGISTER_STATS_TREE(name##_global, menu_display " (global)", column_name, init_func, cleanup_func);           \
    __REGISTER_STATS_TREE(name##_container, menu_display " (per container)", column_name, init_func, cleanup_func)

#endif /* STATS_TREE_NEW_API */

#define REGISTER_STATS_TREE(name, menu_display, column_name) \
    __REGISTER_STATS_TREE(name, menu_display, column_name, STATS_TREE_INIT_FUNC_NAME(name), NULL)

#define REGISTER_STATS_TREE_WITH_CLEANUP(name, menu_display, column_name) \
    __REGISTER_STATS_TREE(name, menu_display, column_name, STATS_TREE_INIT_FUNC_NAME(name), STATS_TREE_CLEANUP_FUNC_NAME(name))

#define REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name) \
    __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name, STATS_TREE_INIT_FUNC_NAME(name), NULL)

#define REGISTER_STATS_TREE_WITH_CLEANUP_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name) \
    __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(name, menu_display, column_name, STATS_TREE_INIT_FUNC_NAME(name), STATS_TREE_CLEANUP_FUNC_NAME(name))

#define UNUSED_PARAM(param) (void)param

STATS_TREE_INIT_FUNC(event_counts)
{
    UNUSED_PARAM(st);
    return;
}

static const gchar *container_node_name(const struct container_info *container)
{
    const gchar *node_name;

    if (preferences_container_identifier == CONTAINER_IDENTIFIER_ID && container->id != NULL)
        node_name = wmem_strndup(wmem_packet_scope(), container->id, 12);
    else if (container->name != NULL)
        node_name = container->name;
    else
        DISSECTOR_ASSERT_NOT_REACHED();
    
    if (preferences_show_container_image && container->image != NULL)
        node_name = wmem_strdup_printf(wmem_packet_scope(), "%s (%s)", node_name, container->image);
    
    return node_name;
}

STATS_TREE_PACKET_GENERIC_FUNC(event_counts)
{
    UNUSED_PARAM(pinfo);
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    int node;
    const gchar *node_name;

    if (per_container) {
        if (data->process->container == NULL) {
            node = tick_stat_node(st, "Host", 0, TRUE);
            // keep host on top
            stat_node_set_flags(st, "Host", 0, TRUE, ST_FLG_SORT_TOP);
        }
        else
            node = tick_stat_node(st, container_node_name(data->process->container), 0, TRUE);
    }
    else
        node = 0; // tree root

    if (!data->is_signature) {
        node = tick_stat_node(st, "Events", node, TRUE);
        tick_stat_node(st, data->event_name, node, FALSE);
    }
    else {
        node = tick_stat_node(st, "Signatures", node, TRUE);

        switch (data->signature_severity) {
            case 0:
                node_name = "Severity 0";
                break;
            case 1:
                node_name = "Severity 1";
                break;
            case 2:
                node_name = "Severity 2";
                break;
            case 3:
                node_name = "Severity 3";
                break;
            default:
                node_name = "Other Severities";
                break;
        }

        node = tick_stat_node(st, node_name, node, TRUE);
        tick_stat_node(st, data->event_name, node, FALSE);
    }

    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(event_counts)

STATS_TREE_INIT_FUNC(file_types)
{
    UNUSED_PARAM(st);
    return;
}

static const gchar *get_file_extension(const gchar *file_path)
{
    const gchar *basename, *tmp;
    
    tmp = g_path_get_basename(file_path);
    basename = wmem_strdup(wmem_packet_scope(), tmp);
    g_free((gpointer)tmp);
    return g_strrstr(basename, ".");
}

STATS_TREE_PACKET_GENERIC_FUNC(file_types)
{
    UNUSED_PARAM(pinfo);
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    const gchar *file_type, *pathname, *extension = NULL;
    int node;

    // we only care about magic_write events
    if (strcmp(data->event_name, "magic_write") != 0)
        return TAP_PACKET_DONT_REDRAW;
    
    if (per_container) {
        if (data->process->container == NULL) {
            node = tick_stat_node(st, "Host", 0, TRUE);
            // keep host on top
            stat_node_set_flags(st, "Host", 0, TRUE, ST_FLG_SORT_TOP);
        }
        else
            node = tick_stat_node(st, container_node_name(data->process->container), 0, TRUE);
    }
    else
        node = 0; // tree root
    
    file_type = wanted_field_get_str("tracee.args.magic_write.file_type");
    pathname = wanted_field_get_str("tracee.args.magic_write.pathname");

    // unknown file type
    if (file_type == NULL) {
        // group unknown file types by their extension
        if (pathname != NULL)
            extension = get_file_extension(pathname);
        
        // no pathname or no extension
        if (extension == NULL)
            node = tick_stat_node(st, "Unknown", node, TRUE);
        else {
            node = tick_stat_node(st, "Other Extensions", node, TRUE);
            node = tick_stat_node(st, extension, node, TRUE);
        }
    }
    else
        node = tick_stat_node(st, file_type, node, TRUE);
    
    // add file path under the file type node
    if (pathname != NULL)
        tick_stat_node(st, pathname, node, FALSE);
    
    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(file_types)

struct process_stat_node {
    int id;
    int parent_id;
    gchar *name;
};

struct process_tree_stats_context {
    GHashTable *process_stat_nodes;
};

// Hash table mapping from stats tree address to the context of the stats tree.
// The cleanup function must be able to free all of the saved data,
// and it doesn't receive any private context, so the data must be global.
// Because multiple stats windows can be opened at once, we cannot use a global hash table of nodes,
// so we use an ugly hack that saves the data of each window as an entry in a global hash table indexed
// by the stats tree data structure address, which is unique for each window.
GHashTable *stats_tree_context;

static void free_process_stat_node(gpointer data)
{
    struct process_stat_node *node = (struct process_stat_node *)data;

    g_free(node->name);
    g_free(node);
}

STATS_TREE_INIT_FUNC(process_tree)
{
    struct process_tree_stats_context *context;

    // create the context for this process tree stats window and insert it into the global context hash table
    context = g_new(struct process_tree_stats_context, 1);
    context->process_stat_nodes = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, free_process_stat_node);
    gint64 *key = g_new(gint64, 1);
    *key = (gint64)st;
    g_hash_table_insert(stats_tree_context, key, context);
}

static gchar *process_tree_get_node_name(gint32 pid, struct process_info *process)
{
    gchar *node_name, *tmp_str;

    if (process == NULL)
        return g_strdup_printf("%d", pid);
    
    switch (preferences_pid_format) {
        case PID_FORMAT_CONTAINER_ONLY:
            node_name = g_strdup_printf("%d", process->pid);
            break;
        case PID_FORMAT_HOST_ONLY:
            node_name = g_strdup_printf("%d", process->host_pid);
            break;
        default:
            node_name = g_strdup_printf("%d", process->pid);
            if (process->pid != process->host_pid) {
                tmp_str = node_name;
                node_name = g_strdup_printf("%s [%d]", node_name, process->host_pid);
                g_free(tmp_str);
            }
            break;
    }
    
    tmp_str = node_name;
    node_name = g_strdup_printf("%s (%s)", node_name, process->name);
    g_free(tmp_str);

    if (process->exec_path != NULL) {
        if (process->command_line == NULL || strncmp(process->exec_path, process->command_line, strlen(process->exec_path)) != 0) {
            tmp_str = node_name;
            node_name = g_strdup_printf("%s: %s", node_name, process->exec_path);
            g_free(tmp_str);
        }
    }

    if (process->command_line != NULL) {
        tmp_str = node_name;
        node_name = g_strdup_printf("%s: %s", node_name, process->command_line);
        g_free(tmp_str);
    }
    
    return node_name;
}

static struct process_stat_node *process_tree_stats_tree_add_process(stats_tree *st, struct process_tree_stats_context *context, gint32 pid, int parent_node_id)
{
    struct process_stat_node *node;
    int *nodes_key;

    // this process already has a stat node
    if ((node = g_hash_table_lookup(context->process_stat_nodes, &pid)) != NULL)
        return node;

    node = g_new0(struct process_stat_node, 1);
    node->parent_id = parent_node_id;
    node->name = process_tree_get_node_name(pid, process_tree_get_process(pid));
    node->id = stats_tree_create_node(st, node->name, parent_node_id, STAT_DT_INT, TRUE);

    nodes_key = g_new(int, 1);
    *nodes_key = pid;
    g_hash_table_insert(context->process_stat_nodes, nodes_key, node);

    return node;
}

static struct process_stat_node *process_tree_stats_tree_add_process_and_ancestors(stats_tree *st,
    struct process_tree_stats_context *context, gint32 pid, bool per_container, const struct container_info *container)
{
    struct process_info *parent;
    const char *container_id = NULL, *parent_container_id = NULL;
    struct process_stat_node *parent_node = NULL;
    const char *parent_node_name;
    int parent_node_id;

    if ((parent = process_tree_get_parent(pid)) != NULL) {
        if (container != NULL)
            container_id = container->id;
        if (parent->container != NULL)
            parent_container_id = parent->container->id;
        
        // make sure parent belongs to the same container
        if (per_container) {
            if (container_id != NULL && parent_container_id == NULL)
                parent = NULL;
            else if (container_id == NULL && parent_container_id != NULL)
                parent = NULL;
            else if (container_id != NULL && parent_container_id != NULL && strcmp(container_id, parent_container_id) != 0)
                parent = NULL;
        }

        // not per-container or parent belongs to the same container
        if (parent != NULL)
            parent_node = process_tree_stats_tree_add_process_and_ancestors(st, context, parent->host_pid, per_container, container);
    }

    if (parent_node == NULL) {
        if (per_container) {
            parent_node_name = container == NULL ? "Host" : container_node_name(container);
            if ((parent_node_id = stats_tree_parent_id_by_name(st, parent_node_name)) == 0) {
                parent_node_id = stats_tree_create_node(st, parent_node_name, 0, STAT_DT_INT, TRUE);

                // keep host on top
                if (container == NULL)
                    stat_node_set_flags(st, "Host", 0, TRUE, ST_FLG_SORT_TOP);
            }
        }
        else
            parent_node_id = 0;
    }
    else
        parent_node_id = parent_node->id;
    
    return process_tree_stats_tree_add_process(st, context, pid, parent_node_id);
}

STATS_TREE_PACKET_GENERIC_FUNC(process_tree)
{
    UNUSED_PARAM(pinfo);
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    struct process_info *process = NULL;
    const struct container_info *container = NULL;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // get container ID for per container view
    if (per_container) {
        if ((process = process_tree_get_process(data->process->host_pid)) != NULL)
                container = process->container;
    }
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid, per_container, container);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(process_tree);

STATS_TREE_PACKET_GENERIC_FUNC(process_tree_with_files)
{
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    const gchar *pathname, *file_type, *file_node_name;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    struct process_info *process = NULL;
    const struct container_info *container = NULL;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // we only care about magic_write events
    if (strcmp(data->event_name, "magic_write") != 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // get container ID for per container view
    if (per_container) {
        if ((process = process_tree_get_process(data->process->host_pid)) != NULL)
                container = process->container;
    }
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid, per_container, container);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    DISSECTOR_ASSERT((pathname = wanted_field_get_str("tracee.args.magic_write.pathname")) != NULL);
    file_type = wanted_field_get_str("tracee.args.magic_write.file_type");

    file_node_name = wmem_strdup_printf(pinfo->pool, "%s file%s: %s", file_type == NULL ? "Unknown" : file_type, file_type == NULL ? " type": "", pathname);
    tick_stat_node(st, file_node_name, node->id, FALSE);

    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_files)

STATS_TREE_PACKET_GENERIC_FUNC(process_tree_with_network)
{
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    gchar *description;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    struct process_info *process = NULL;
    const struct container_info *container = NULL;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // we only care about connect, bind and accept events
    if (strcmp(data->event_name, "security_socket_connect") == 0)
        description = enrichments_get_security_socket_bind_connect_description(pinfo, "Connect");
    else if (strcmp(data->event_name, "security_socket_bind") == 0)
        description = enrichments_get_security_socket_bind_connect_description(pinfo, "Bind");
    else
        return TAP_PACKET_DONT_REDRAW;
    
    // get container ID for per container view
    if (per_container) {
        if ((process = process_tree_get_process(data->process->host_pid)) != NULL)
                container = process->container;
    }
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid, per_container, container);
    
    if (description != NULL) {
        tick_stat_node(st, node->name, node->parent_id, TRUE);
        tick_stat_node(st, description, node->id, FALSE);
    }
    
    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_network)

STATS_TREE_PACKET_GENERIC_FUNC(process_tree_with_signatures)
{
    UNUSED_PARAM(edt);
#ifdef STATS_TREE_PACKET_HAS_FLAGS
    UNUSED_PARAM(flags);
#endif

    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    struct process_info *process = NULL;
    const struct container_info *container = NULL;
    gchar *node_name;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // we only care about signatures
    if (!data->is_signature || strcmp(data->event_name, "sig_process_execution") == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // get container ID for per container view
    if (per_container) {
        if ((process = process_tree_get_process(data->process->host_pid)) != NULL)
                container = process->container;
    }
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid, per_container, container);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    node_name = wmem_strdup_printf(pinfo->pool, "(Severity %d): %s", data->signature_severity, data->signature_name);
    tick_stat_node(st, node_name, node->id, FALSE);

    return TAP_PACKET_REDRAW;
}

STATS_TREE_PACKET_FUNC_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_signatures)

STATS_TREE_CLEANUP_FUNC(process_tree)
{
    struct process_tree_stats_context *context;

    if ((context = g_hash_table_lookup(stats_tree_context, &st)) == NULL)
        return;

    g_hash_table_destroy(context->process_stat_nodes);
    g_hash_table_remove(stats_tree_context, &st);
}

void register_tracee_statistics(void)
{
    // needed for file types
    register_wanted_field("tracee.args.magic_write.file_type");
    register_wanted_field("tracee.args.magic_write.pathname");

    // needed for process tree with files
    register_wanted_field("tracee.args.magic_write.pathname");
    register_wanted_field("tracee.args.magic_write.file_type");

    // needed for process tree with network
    register_wanted_field("tracee.sockaddr.sa_family");
    register_wanted_field("tracee.sockaddr.sin_addr");
    register_wanted_field("tracee.sockaddr.sin_port");
    register_wanted_field("tracee.sockaddr.sin6_addr");
    register_wanted_field("tracee.sockaddr.sin6_port");
    register_wanted_field("tracee.sockaddr.sun_path");

    stats_tree_context = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(event_counts, "Event Counts", "Event Name");
    REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(file_types, "File Types", "File Type");

#ifdef STATS_TREE_NEW_API

#define PROCESS_TREE_MENU                 "Process Tree" STATS_TREE_MENU_SEPARATOR "Standard"
#define PROCESS_TREE_WITH_FILES_MENU      "Process Tree" STATS_TREE_MENU_SEPARATOR "With Files"
#define PROCESS_TREE_WITH_NETWORK_MENU    "Process Tree" STATS_TREE_MENU_SEPARATOR "With Network"
#define PROCESS_TREE_WITH_SIGNATURES_MENU "Process Tree" STATS_TREE_MENU_SEPARATOR "With Signatures"

#else /* !STATS_TREE_NEW_API */

#define PROCESS_TREE_MENU                 "Process Tree"
#define PROCESS_TREE_WITH_FILES_MENU      "Process Tree with files"
#define PROCESS_TREE_WITH_NETWORK_MENU    "Process Tree with network"
#define PROCESS_TREE_WITH_SIGNATURES_MENU "Process Tree with signatures"

#endif /* STATS_TREE_NEW_API */

    REGISTER_STATS_TREE_WITH_CLEANUP_WITH_GLOBAL_AND_PER_CONTAINER(process_tree, PROCESS_TREE_MENU, "Process");
    __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_files, PROCESS_TREE_WITH_FILES_MENU,
        "Process/File", STATS_TREE_INIT_FUNC_NAME(process_tree), STATS_TREE_CLEANUP_FUNC_NAME(process_tree));
    __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_network, PROCESS_TREE_WITH_NETWORK_MENU,
        "Process/Network activity", STATS_TREE_INIT_FUNC_NAME(process_tree), STATS_TREE_CLEANUP_FUNC_NAME(process_tree));
    __REGISTER_STATS_TREE_WITH_GLOBAL_AND_PER_CONTAINER(process_tree_with_signatures, PROCESS_TREE_WITH_SIGNATURES_MENU,
        "Process/Signature", STATS_TREE_INIT_FUNC_NAME(process_tree), STATS_TREE_CLEANUP_FUNC_NAME(process_tree));
}