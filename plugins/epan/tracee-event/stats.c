#include "tracee.h"
#include "../common.h"

#include <epan/stats_tree.h>

static int events_node = -1;
static int signatures_node = -1;
static int severity_0_node = -1;
static int severity_1_node = -1;
static int severity_2_node = -1;
static int severity_3_node = -1;
static int other_severity_node = -1;

static const gchar *events_node_name = "Events";
static const gchar *signatures_node_name = "Signatures";
static const gchar *severity_0_node_name = "Severity 0";
static const gchar *severity_1_node_name = "Severity 1";
static const gchar *severity_2_node_name = "Severity 2";
static const gchar *severity_3_node_name = "Severity 3";
static const gchar *other_severity_node_name = "Other Severities";

static void event_counts_stats_tree_init(stats_tree *st)
{
    events_node = stats_tree_create_node(st, events_node_name, 0, STAT_DT_INT, TRUE);
    signatures_node = stats_tree_create_node(st, signatures_node_name, 0, STAT_DT_INT, FALSE);
    severity_0_node = stats_tree_create_node(st, severity_0_node_name, signatures_node, STAT_DT_INT, TRUE);
    severity_1_node = stats_tree_create_node(st, severity_1_node_name, signatures_node, STAT_DT_INT, TRUE);
    severity_2_node = stats_tree_create_node(st, severity_2_node_name, signatures_node, STAT_DT_INT, TRUE);
    severity_3_node = stats_tree_create_node(st, severity_3_node_name, signatures_node, STAT_DT_INT, TRUE);
    other_severity_node = stats_tree_create_node(st, other_severity_node_name, signatures_node, STAT_DT_INT, TRUE);
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status event_counts_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status event_counts_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    int node;
    const gchar *node_name;

    if (!data->is_signature) {
        tick_stat_node(st, events_node_name, 0, FALSE);
        tick_stat_node(st, data->event_name, events_node, FALSE);
    }
    else {
        tick_stat_node(st, signatures_node_name, 0, FALSE);

        switch (data->signature_severity) {
            case 0:
                node = severity_0_node;
                node_name = severity_0_node_name;
                break;
            case 1:
                node = severity_1_node;
                node_name = severity_1_node_name;
                break;
            case 2:
                node = severity_2_node;
                node_name = severity_2_node_name;
                break;
            case 3:
                node = severity_3_node;
                node_name = severity_3_node_name;
                break;
            default:
                node = other_severity_node;
                node_name = other_severity_node_name;
                break;
        }

        tick_stat_node(st, node_name, signatures_node, FALSE);
        tick_stat_node(st, data->event_name, node, FALSE);
    }

    return TAP_PACKET_REDRAW;
}

static int other_extensions_node = -1;

static const gchar *other_extensions_node_name = "Other Extensions";

static void file_types_stats_tree_init(stats_tree *st)
{
    other_extensions_node = stats_tree_create_node(st, other_extensions_node_name, 0, STAT_DT_INT, TRUE);
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status file_types_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status file_types_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    const gchar *file_type, *pathname, *extension = NULL;
    int node_id;

    // we only care about magic_write events
    if (strcmp(data->event_name, "magic_write") != 0)
        return TAP_PACKET_DONT_REDRAW;
    
    file_type = wanted_field_get_str("tracee.args.magic_write.file_type");
    pathname = wanted_field_get_str("tracee.args.magic_write.pathname");

    // unknown file type
    if (file_type == NULL) {
        // group unknown file types by their extension
        if (pathname != NULL)
            extension = g_strrstr(pathname, ".");
        
        // no pathname or no extension
        if (extension == NULL)
            node_id = tick_stat_node(st, "Unknown", 0, TRUE);
        else {
            tick_stat_node(st, other_extensions_node_name, 0, FALSE);
            node_id = tick_stat_node(st, extension, other_extensions_node, TRUE);
        }
    }
    else
        node_id = tick_stat_node(st, file_type, 0, TRUE);
    
    // add file path under the file type node
    if (node_id != -1 && pathname != NULL)
        tick_stat_node(st, pathname, node_id, FALSE);
    
    return TAP_PACKET_REDRAW;
}

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

static void process_tree_stats_tree_init(stats_tree *st)
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

static struct process_stat_node *process_tree_stats_tree_add_process_and_ancestors(stats_tree *st, struct process_tree_stats_context *context, gint32 pid)
{
    struct process_info *parent;
    struct process_stat_node *parent_node = NULL;

    if ((parent = process_tree_get_parent(pid)) != NULL)
        parent_node = process_tree_stats_tree_add_process_and_ancestors(st, context, parent->host_pid);
    
    return process_tree_stats_tree_add_process(st, context, pid, parent_node == NULL ? 0 : parent_node->id);
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status process_tree_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status process_tree_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    return TAP_PACKET_REDRAW;
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status process_tree_with_files_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status process_tree_with_files_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    const gchar *pathname, *file_type, *file_node_name;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // we only care about magic_write events
    if (strcmp(data->event_name, "magic_write") != 0)
        return TAP_PACKET_DONT_REDRAW;
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    DISSECTOR_ASSERT((pathname = wanted_field_get_str("tracee.args.magic_write.pathname")) != NULL);
    file_type = wanted_field_get_str("tracee.args.magic_write.file_type");

    file_node_name = wmem_strdup_printf(pinfo->pool, "%s file%s: %s", file_type == NULL ? "Unknown" : file_type, file_type == NULL ? " type": "", pathname);
    tick_stat_node(st, file_node_name, node->id, FALSE);

    return TAP_PACKET_REDRAW;
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status process_tree_with_network_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status process_tree_with_network_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    gchar *description;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;

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
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid);
    
    if (description != NULL) {
        tick_stat_node(st, node->name, node->parent_id, TRUE);
        tick_stat_node(st, description, node->id, FALSE);
    }
    
    return TAP_PACKET_REDRAW;
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status process_tree_with_signatures_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status process_tree_with_signatures_stats_tree_packet(stats_tree* st, packet_info* pinfo,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct process_tree_stats_context *context;
    struct process_stat_node *node;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;
    gchar *node_name;

    DISSECTOR_ASSERT((context = g_hash_table_lookup(stats_tree_context, &st)) != NULL);

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    // we only care about signatures
    if (!data->is_signature || strcmp(data->event_name, "sig_process_execution") == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    node = process_tree_stats_tree_add_process_and_ancestors(st, context, data->process->host_pid);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    node_name = wmem_strdup_printf(pinfo->pool, "(Severity %d): %s", data->signature_severity, data->signature_name);
    tick_stat_node(st, node_name, node->id, FALSE);

    return TAP_PACKET_REDRAW;
}

static void process_tree_stats_tree_cleanup(stats_tree *st)
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

#if ((WIRESHARK_VERSION_MAJOR > 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR >= 3))) // new stats tree API
    stats_tree_cfg *event_counts_st, *file_types_st, *process_tree_st, *process_tree_with_files_st,
        *process_tree_with_network_st, *process_tree_with_signatures_st;

    event_counts_st = stats_tree_register_plugin("tracee", "tracee_events", "Tracee" STATS_TREE_MENU_SEPARATOR "Event Counts",
        0, event_counts_stats_tree_packet, event_counts_stats_tree_init, NULL);
    stats_tree_set_first_column_name(event_counts_st, "Event Name");

    file_types_st = stats_tree_register_plugin("tracee", "tracee_file_types", "Tracee" STATS_TREE_MENU_SEPARATOR "File Types",
        0, file_types_stats_tree_packet, file_types_stats_tree_init, NULL);
    stats_tree_set_first_column_name(file_types_st, "File Type");

    process_tree_st = stats_tree_register_plugin("tracee", "tracee_process_tree", "Tracee" STATS_TREE_MENU_SEPARATOR "Process Tree",
        0, process_tree_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_set_first_column_name(process_tree_st, "Process");

    process_tree_with_files_st = stats_tree_register_plugin("tracee", "tracee_process_tree_files", "Tracee" STATS_TREE_MENU_SEPARATOR "Process Tree (with files)",
        0, process_tree_with_files_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_set_first_column_name(process_tree_with_files_st, "Process/File");

    process_tree_with_network_st = stats_tree_register_plugin("tracee", "tracee_process_tree_network", "Tracee" STATS_TREE_MENU_SEPARATOR "Process Tree (with network)",
        0, process_tree_with_network_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_set_first_column_name(process_tree_with_network_st, "Process/Network activity");

    process_tree_with_signatures_st = stats_tree_register_plugin("tracee", "tracee_process_tree_signatures", "Tracee" STATS_TREE_MENU_SEPARATOR "Process Tree (with signatures)",
        0, process_tree_with_signatures_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_set_first_column_name(process_tree_with_signatures_st, "Process/Signature");
#else // old stats tree API
    stats_tree_register_plugin("tracee", "tracee_events", "Tracee/Event Counts",
        0, event_counts_stats_tree_packet, event_counts_stats_tree_init, NULL);
    stats_tree_register_plugin("tracee", "tracee_file_types", "Tracee/File Types",
        0, file_types_stats_tree_packet, file_types_stats_tree_init, NULL);
    stats_tree_register_plugin("tracee", "tracee_process_tree", "Tracee/Process Tree",
        0, process_tree_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_register_plugin("tracee", "tracee_process_tree_files", "Tracee/Process Tree (with files)",
        0, process_tree_with_files_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_register_plugin("tracee", "tracee_process_tree_network", "Tracee/Process Tree (with network)",
        0, process_tree_with_network_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_register_plugin("tracee", "tracee_process_tree_signatures", "Tracee/Process Tree (with signatures)",
        0, process_tree_with_signatures_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
#endif
}