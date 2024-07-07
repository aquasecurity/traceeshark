#include "tracee.h"

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

static void tracee_stats_tree_init(stats_tree *st)
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
static tap_packet_status tracee_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
    epan_dissect_t* edt _U_, const void* p)
#else
static tap_packet_status tracee_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_,
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

void register_tracee_statistics(void)
{
#if ((WIRESHARK_VERSION_MAJOR > 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR >= 3))) // new stats tree API
    stats_tree_cfg *st_config;

    st_config = stats_tree_register_plugin("tracee", "tracee_events", "Tracee" STATS_TREE_MENU_SEPARATOR "Event Counts",
        0, tracee_stats_tree_packet, tracee_stats_tree_init, NULL);
    stats_tree_set_first_column_name(st_config, "Event Name");
#else // old stats tree API
    stats_tree_register_plugin("tracee", "tracee_events", "Tracee/Event Counts",
        0, tracee_stats_tree_packet, tracee_stats_tree_init, NULL);
#endif
}