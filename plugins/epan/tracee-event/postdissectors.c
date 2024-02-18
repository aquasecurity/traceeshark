#include <epan/packet.h>
#include "tracee.h"

static dissector_handle_t event_postdissector;

wmem_map_t *event_postdissectors;

static int dissect_sig_machine_fingerprint(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *file_path;

    if ((file_path = wanted_field_get_str("tracee.args.File_path")) != NULL)
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s was opened", file_path);
    
    return 0;
}

static int dissect_sched_process_exec(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *pathname, *argv_line;

    pathname = wanted_field_get_str("tracee.args.pathname");
    argv_line = wanted_field_get_str("tracee.args.argv_line");

    if (pathname && argv_line) {
        if (strncmp(pathname, argv_line, strlen(pathname)) == 0)
            col_add_str(pinfo->cinfo, COL_INFO, argv_line);
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", pathname, argv_line);
    }

    return 0;
}

static int dissect_net_packet_http_request(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *method, *protocol, *uri_path, *content_type;

    method = wanted_field_get_str("tracee.http_request.method");
    protocol = wanted_field_get_str("tracee.http_request.protocol");
    uri_path = wanted_field_get_str("tracee.http_request.uri_path");
    
    if (method && protocol && uri_path)
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s %s", method, uri_path, protocol);
    
    if (strcmp(method, "POST") && ((content_type = wanted_field_get_str("http.content_type")) != NULL))
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", content_type);

    return 0;
}

static int postdissect_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const char *event_name;
    dissector_t dissector;

    event_name = wanted_field_get_str("tracee.eventName");
    if (event_name == NULL)
        return 0;
    
    if ((dissector = wmem_map_lookup(event_postdissectors, event_name)) == NULL)
        return 0;
    
    return dissector(tvb, pinfo, tree, data);
}

static void register_tracee_event_postdissector(const gchar *event_name, dissector_t dissector_func)
{
    wmem_map_insert(event_postdissectors, event_name, dissector_func);
}

static void register_wanted_fields(void)
{
    // needed for general postdissector
    register_wanted_field("tracee.eventName");

    // needed for dissect_sig_machine_fingerprint
    register_wanted_field("tracee.args.File_path");

    // needed for dissect_sched_process_exec
    register_wanted_field("tracee.args.pathname");
    register_wanted_field("tracee.args.argv_line");

    // needed for dissect_net_packet_http_request
    register_wanted_field("tracee.http_request.method");
    register_wanted_field("tracee.http_request.protocol");
    register_wanted_field("tracee.http_request.uri_path");
    register_wanted_field("http.content_type");
}

void register_tracee_postdissectors(int proto)
{
    event_postdissector = register_dissector("tracee-event-postdissector", postdissect_event, proto);
    register_postdissector(event_postdissector);

    event_postdissectors = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    register_tracee_event_postdissector("sig_machine_fingerprint", dissect_sig_machine_fingerprint);
    register_tracee_event_postdissector("sched_process_exec", dissect_sched_process_exec);
    register_tracee_event_postdissector("net_packet_http_request", dissect_net_packet_http_request);

    register_wanted_fields();
}