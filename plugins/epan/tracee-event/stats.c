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

struct pid_stat_node {
    int parent_id;
    gchar *name;
};

GHashTable *pid_stat_nodes;

static void free_pid_stat_node(gpointer data)
{
    struct pid_stat_node *node = (struct pid_stat_node *)data;

    g_free(node->name);
    g_free(node);
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
    return node_name;
}

static void process_tree_stats_tree_add_process(stats_tree *st, gint32 pid, int parent_node_id)
{
    guint i;
    int node_id;
    int *nodes_key;
    struct pid_stat_node *node = g_new0(struct pid_stat_node, 1);
    struct process_info *process = process_tree_get_process(pid);
    GArray *children_pids = process_tree_get_children_pids(pid);

    node->parent_id = parent_node_id;
    node->name = process_tree_get_node_name(pid, process);
    
    node_id = stats_tree_create_node(st, node->name, parent_node_id, STAT_DT_INT, (children_pids->len > 0));

    nodes_key = g_new(int, 1);
    *nodes_key = pid;
    g_hash_table_insert(pid_stat_nodes, nodes_key, node);

    // iterate through all children, adding each one to the stats tree by calling this function recursively
    for (i = 0; i < children_pids->len; i++)
        process_tree_stats_tree_add_process(st, g_array_index(children_pids, gint32, i), node_id);
    
    g_array_free(children_pids, FALSE);
}

static void process_tree_stats_tree_init(stats_tree *st)
{
    guint i;
    GArray *root_pids = process_tree_get_root_pids();

    pid_stat_nodes = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, free_pid_stat_node);

    for (i = 0; i < root_pids->len; i++)
        process_tree_stats_tree_add_process(st, g_array_index(root_pids, gint32, i), 0);
    
    g_array_free(root_pids, FALSE);
}

#if ((WIRESHARK_VERSION_MAJOR < 3) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR < 7)) || ((WIRESHARK_VERSION_MAJOR == 3) && (WIRESHARK_VERSION_MINOR == 7) && (WIRESHARK_VERSION_MICRO < 1)))
static tap_packet_status process_tree_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status process_tree_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
#endif
{
    struct pid_stat_node *node;
    struct tracee_dissector_data *data = (struct tracee_dissector_data *)p;

    if (data->process == NULL || data->process->host_pid == 0)
        return TAP_PACKET_DONT_REDRAW;
    
    DISSECTOR_ASSERT((node = g_hash_table_lookup(pid_stat_nodes, &data->process->host_pid)) != NULL);
    tick_stat_node(st, node->name, node->parent_id, TRUE);

    return TAP_PACKET_REDRAW;
}

static void process_tree_stats_tree_cleanup(stats_tree *st _U_)
{
    g_hash_table_destroy(pid_stat_nodes);
}

void register_tracee_statistics(void)
{
#if ((WIRESHARK_VERSION_MAJOR > 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR >= 3))) // new stats tree API
    stats_tree_cfg *event_counts_st, *process_tree_st;

    event_counts_st = stats_tree_register_plugin("tracee", "tracee_events", "Tracee" STATS_TREE_MENU_SEPARATOR "Event Counts",
        0, event_counts_stats_tree_packet, event_counts_stats_tree_init, NULL);
    stats_tree_set_first_column_name(event_counts_st, "Event Name");

    process_tree_st = stats_tree_register_plugin("tracee", "tracee_processes", "Tracee" STATS_TREE_MENU_SEPARATOR "Process Tree",
        0, process_tree_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
    stats_tree_set_first_column_name(process_tree_st, "Process");
#else // old stats tree API
    stats_tree_register_plugin("tracee", "tracee_events", "Tracee/Event Counts",
        0, event_counts_stats_tree_packet, event_counts_stats_tree_init, NULL);
    stats_tree_register_plugin("tracee", "tracee_events", "Tracee/Process Tree",
        0, process_tree_stats_tree_packet, process_tree_stats_tree_init, process_tree_stats_tree_cleanup);
#endif
}