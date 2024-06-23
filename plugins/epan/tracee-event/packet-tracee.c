#define WS_BUILD_DLL

#include <errno.h>
#include <inttypes.h>

#include "tracee.h"
#include "../common.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>
#include <wsutil/plugins.h>
#include <wsutil/wslog.h>
#include <ws_version.h>

#ifndef WIRESHARK_PLUGIN_REGISTER // old plugin API
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif
#endif

#define START_SIGNATURE_ID 6000
#define MAX_SIGNATURE_ID   6999

const value_string packet_metadata_directions[] = {
    { 0, "Invalid" },
    { 1, "Ingress" },
    { 2, "Egress"  },
    { 0, NULL      }
};

static int proto_tracee = -1;

//static dissector_table_t event_name_dissector_table;

static int hf_timestamp = -1;
static int hf_thread_start_time = -1;
static int hf_processor_id = -1;
static int hf_process_id = -1;
static int hf_cgroup_id = -1;
static int hf_thread_id = -1;
static int hf_parent_process_id = -1;
static int hf_host_process_id = -1;
static int hf_pid_col = -1;
static int hf_ppid_col = -1;
static int hf_host_thread_id = -1;
static int hf_host_parent_process_id = -1;
static int hf_user_id = -1;
static int hf_mount_namespace = -1;
static int hf_pid_namespace = -1;
static int hf_process_name = -1;
static int hf_executable_path = -1;
static int hf_hostname = -1;
static int hf_container_id = -1;
static int hf_container_name = -1;
static int hf_container_image = -1;
static int hf_container_image_digest = -1;
static int hf_is_container = -1;
static int hf_container_col = -1;
static int hf_k8s_pod_name = -1;
static int hf_k8s_pod_namespace = -1;
static int hf_k8s_pod_uid = -1;
static int hf_event_id = -1;
static int hf_event_name = -1;
static int hf_is_signature = -1;
static int hf_matched_policies = -1;
static int hf_args_num = -1;
static int hf_return_value = -1;
static int hf_syscall = -1;
//static int hf_stack_addresses = -1;
//CONTEXT FLAFS INFO
static int hf_thread_entity_id = -1;
static int hf_process_entity_id = -1;
static int hf_parent_entity_id = -1;
static int hf_args_command_line = -1;
static int hf_process_lineage_pid = -1;
static int hf_process_lineage_ppid = -1;
static int hf_process_lineage_start_time = -1;
static int hf_process_lineage_process_name = -1;
static int hf_process_lineage_pathname = -1;
static int hf_process_lineage_sha256 = -1;
static int hf_process_lineage_command = -1;
static int hf_tiggered_by_id = -1;
static int hf_tiggered_by_name = -1;
static int hf_tiggered_by_return_value = -1;
static int hf_metadata_version = -1;
static int hf_metadata_description = -1;
//static int hf_metadata_tags = -1;
static int hf_metadata_properties_category = -1;
static int hf_metadata_properties_kubernetes_technique = -1;
static int hf_metadata_properties_severity = -1;
static int hf_metadata_properties_technique = -1;
static int hf_metadata_properties_aggregation_keys = -1;
static int hf_metadata_properties_external_id = -1;
static int hf_metadata_properties_id = -1;
static int hf_metadata_properties_release = -1;
static int hf_metadata_properties_signature_id = -1;
static int hf_metadata_properties_signature_name = -1;

// dynamic fields needed by builtin filters
static int hf_ptrace_request = -1;

// network fields
static int hf_ip_addr = -1;
static int hf_ip_src = -1;
static int hf_ip_dst = -1;
static int hf_ipv6_addr = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_dst = -1;
static int hf_ip_proto = -1;
static int hf_tcp_port = -1;
static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_udp_port = -1;
static int hf_udp_srcport = -1;
static int hf_udp_dstport = -1;
static int hf_dns_qry_name = -1;
static int hf_dns_resp_ttl = -1;
static int hf_dns_resp_name = -1;
static int hf_http_request = -1;
static int hf_http_response = -1;
static int hf_http_request_method = -1;
static int hf_http_request_version = -1;
static int hf_http_response_version = -1;
static int hf_http_response_code = -1;
static int hf_http_response_code_desc = -1;
static int hf_http_response_phrase = -1;
static int hf_http_host = -1;
static int hf_http_request_uri = -1;
static int hf_http_content_length = -1;
static int hf_http_request_line = -1;
static int hf_http_accept = -1;
static int hf_http_user_agent = -1;
static int hf_http_referer = -1;
static int hf_http_cookie = -1;
static int hf_http_content_type = -1;
static int hf_http_connection = -1;
static int hf_http_accept_language = -1;
static int hf_http_accept_encoding = -1;
static int hf_http_content_length_header = -1;
static int hf_http_upgrade = -1;

// sockaddr fields
static int hf_sockaddr_sa_family = -1;
static int hf_sockaddr_sun_path = -1;
static int hf_sockaddr_sin_addr = -1;
static int hf_sockaddr_sin_port = -1;
static int hf_sockaddr_sin6_addr = -1;
static int hf_sockaddr_sin6_port = -1;
static int hf_sockaddr_sin6_flowinfo = -1;
static int hf_sockaddr_sin6_scopeid = -1;

// slim_cred_t fields
static int hf_slim_cred_t_uid = -1;
static int hf_slim_cred_t_gid = -1;
static int hf_slim_cred_t_suid = -1;
static int hf_slim_cred_t_sgid = -1;
static int hf_slim_cred_t_euid = -1;
static int hf_slim_cred_t_egid = -1;
static int hf_slim_cred_t_fsuid = -1;
static int hf_slim_cred_t_fsgid = -1;
static int hf_slim_cred_t_user_namespace = -1;
static int hf_slim_cred_t_secure_bits = -1;
static int hf_slim_cred_t_cap_inheritable = -1;
static int hf_slim_cred_t_cap_permitted = -1;
static int hf_slim_cred_t_cap_effective = -1;
static int hf_slim_cred_t_cap_bounding = -1;
static int hf_slim_cred_t_cap_ambient = -1;

// trace.PktMeta fields
static int hf_pktmeta_src_ip = -1;
static int hf_pktmeta_dst_ip = -1;
static int hf_pktmeta_src_port = -1;
static int hf_pktmeta_dst_port = -1;
static int hf_pktmeta_protocol = -1;
static int hf_pktmeta_packet_len = -1;
static int hf_pktmeta_iface = -1;

// trace.DnsQueryData fields
static int hf_dnsquery_query = -1;
static int hf_dnsquery_type = -1;
static int hf_dnsquery_class = -1;

// DnsAnswer fields
static int hf_dnsanswer_type = -1;
static int hf_dnsanswer_ttl = -1;
static int hf_dnsanswer_answer = -1;

// trace.ProtoHTTPRequest fields
static int hf_proto_http_request_method = -1;
static int hf_proto_http_request_protocol = -1;
static int hf_proto_http_request_host = -1;
static int hf_proto_http_request_uri_path = -1;
static int hf_proto_http_request_header = -1;
static int hf_proto_http_request_content_length = -1;

// trace.PacketMetadata fields
static int hf_packet_metadata_direction = -1;

// trace.ProtoHTTP fields
static int hf_proto_http_direction = -1;
static int hf_proto_http_method = -1;
static int hf_proto_http_protocol = -1;
static int hf_proto_http_host = -1;
static int hf_proto_http_uri_path = -1;
static int hf_proto_http_status = -1;
static int hf_proto_http_status_code = -1;
static int hf_proto_http_header = -1;
static int hf_proto_http_content_length = -1;

// trace.HookedSymbolData fields
static int hf_hooked_symbol_name = -1;
static int hf_hooked_symbol_module_owner = -1;

// map[string]trace.HookedSymbolData fields
static int hf_hooked_symbol_entry = -1;

static gint ett_tracee = -1;
static gint ett_context = -1;
static gint ett_container = -1;
static gint ett_k8s = -1;
static gint ett_metadata = -1;
static gint ett_metadata_properties = -1;
static gint ett_args = -1;
static gint ett_string_arr = -1;
static gint ett_process_lineage = -1;
static gint ett_process_lineage_process = -1;
static gint ett_triggered_by = -1;
static gint ett_arg_obj = -1;
static gint ett_arg_obj_arr = -1;
static gint ett_http_headers = -1;
static gint ett_hooked_symbols_map = -1;
static gint ett_dns_query_data = -1;

// preferences
enum pid_format {
    PID_FORMAT_CONTAINER_ONLY = 0,
    PID_FORMAT_HOST_ONLY,
    PID_FORMAT_BOTH,
};
static gint pid_format = PID_FORMAT_CONTAINER_ONLY;
enum container_identifier {
    CONTAINER_IDENTIFIER_ID = 0,
    CONTAINER_IDENTIFIER_NAME,
};
static gint container_identifier = CONTAINER_IDENTIFIER_ID;
static gboolean show_container_image = FALSE;

struct event_dynamic_hf {
    GPtrArray *hf_ptrs;         // GPtrArray containing pointers to the registered fields
    wmem_map_t *arg_idx_map;    // mapping between argument name to its index in the hf array
};

/**
 * This map contains registered dynamic field arrays for each event type in the capture file.
 * These dynamic fields are for the arguments, which differ between event types but are always
 * the same for each event type.
 */
static wmem_map_t *event_dynamic_hf_map;

/**
 * This map contains dissector functions for known complex argument types.
 * Types that don't have a dissector yet have an entry with a NULL value.
 */
static wmem_map_t *complex_type_dissectors;

static void dissect_arguments(tvbuff_t *, packet_info *,
    proto_tree *, gchar *, jsmntok_t *, const gchar *, gboolean);

static void free_dynamic_hf(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    guint i;
    struct hf_register_info *hf;
    struct event_dynamic_hf *dynamic_hf = value;
    gpointer *hf_ptrs;

    for (i = 0; i < dynamic_hf->hf_ptrs->len; i++) {
        hf = (hf_register_info *)dynamic_hf->hf_ptrs->pdata[i];
        proto_deregister_field(proto_tracee, *(hf->p_id));
    }
    hf_ptrs = g_ptr_array_free(dynamic_hf->hf_ptrs, FALSE);
    proto_add_deregistered_data(hf_ptrs);
}

#if ((WIRESHARK_VERSION_MAJOR < 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR < 1)))
static gboolean dynamic_hf_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
#else
static bool dynamic_hf_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
#endif
{
    wmem_map_foreach(event_dynamic_hf_map, free_dynamic_hf, NULL);

    // return true so this callback isn't unregistered
    return TRUE;
}

static void dissect_container_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok)
{
    proto_item *container_item, *tmp_item;
    proto_tree *container_tree;
    jsmntok_t *container_tok;
    gchar *id, *name, *image, *image_digest, *container_col_str;

    container_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(container_item, "Container");
    container_tree = proto_item_add_subtree(container_item, ett_container);

    DISSECTOR_ASSERT((container_tok = json_get_object(json_data, root_tok, "container")) != NULL);

    // add container id
    if ((id = json_get_string(json_data, container_tok, "id")) != NULL) {
        proto_tree_add_string(container_tree, hf_container_id, tvb, 0, 0, id);
        proto_item_append_text(container_item, ": %s", id);
    }

    // add container name
    if ((name = json_get_string(json_data, container_tok, "name")) != NULL)
        proto_tree_add_string(container_tree, hf_container_name, tvb, 0, 0, name);
    
    // add container image
    if ((image = json_get_string(json_data, container_tok, "image")) != NULL)
        proto_tree_add_string(container_tree, hf_container_image, tvb, 0, 0, image);
    
    // add container image digest
    if ((image_digest = json_get_string(json_data, container_tok, "imageDigest")) != NULL)
        proto_tree_add_string(container_tree, hf_container_image_digest, tvb, 0, 0, image_digest);
    
    // no container
    if (!id && !name && !image && !image_digest) {
        proto_item_append_text(container_item, ": none");
        tmp_item = proto_tree_add_boolean(container_tree, hf_is_container, tvb, 0, 0, FALSE);
    }
    else
        tmp_item = proto_tree_add_boolean(container_tree, hf_is_container, tvb, 0, 0, TRUE);
    proto_item_set_generated(tmp_item);

    // add container column
    if (id != NULL) {
        if (container_identifier == CONTAINER_IDENTIFIER_ID)
            container_col_str = wmem_strndup(pinfo->pool, id, 12);
        else
            container_col_str = wmem_strdup(pinfo->pool, name);

        if (image != NULL && show_container_image)
            container_col_str = wmem_strdup_printf(pinfo->pool, "%s (%s)", container_col_str, image);
        
        tmp_item = proto_tree_add_string(tree, hf_container_col, tvb, 0, 0, container_col_str);
        proto_item_set_hidden(tmp_item);
    }
}

static void dissect_k8s_fields(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok)
{
    proto_item *k8s_item;
    proto_tree *k8s_tree;
    jsmntok_t *k8s_tok;
    gchar *pod_name, *pod_namespace, *pod_uid;

    k8s_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(k8s_item, "Kubernetes");
    k8s_tree = proto_item_add_subtree(k8s_item, ett_k8s);

    // get k8s object
    DISSECTOR_ASSERT((k8s_tok = json_get_object(json_data, root_tok, "kubernetes")) != NULL);

    // add pod name
    if ((pod_name = json_get_string(json_data, k8s_tok, "podName")) != NULL) {
        proto_tree_add_string(k8s_tree, hf_k8s_pod_name, tvb, 0, 0, pod_name);
        proto_item_append_text(k8s_item, ": %s", pod_name);
    }

    // add pod namespace
    if ((pod_namespace = json_get_string(json_data, k8s_tok, "podNamespace")) != NULL) {
        proto_tree_add_string(k8s_tree, hf_k8s_pod_namespace, tvb, 0, 0, pod_namespace);
        if (pod_name != NULL)
            proto_item_append_text(k8s_item, " (%s)", pod_namespace);
    }

    // add pod UID
    if ((pod_uid = json_get_string(json_data, k8s_tok, "podUID")) != NULL)
        proto_tree_add_string(k8s_tree, hf_k8s_pod_uid, tvb, 0, 0, pod_uid);
    
    // no kubernetes info
    if (!pod_name && !pod_namespace && !pod_uid)
        proto_item_append_text(k8s_item, ": none");
}

static void dissect_event_context(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok)
{
    proto_item *context_item, *tmp_item;
    proto_tree *context_tree;
    nstime_t timestamp;
    gint64 tmp_int;
    gint32 pid, host_pid, ppid, host_ppid;
    gchar *pid_col_str = NULL, *ppid_col_str = NULL, *tmp_str;
    jsmntok_t *tmp_tok;

    context_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(context_item, "Context");
    context_tree = proto_item_add_subtree(context_item, ett_context);

    // add thread start time
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadStartTime", &tmp_int));
    timestamp.secs = (guint64)tmp_int / 1000000000;
    timestamp.nsecs = (guint64)tmp_int % 1000000000;
    proto_tree_add_time(context_tree, hf_thread_start_time, tvb, 0, 0, &timestamp);

    // add processor ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processorId", &tmp_int));
    proto_tree_add_int64(context_tree, hf_processor_id, tvb, 0, 0, tmp_int);

    // add cgroup ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "cgroupId", &tmp_int));
    proto_tree_add_int64(context_tree, hf_cgroup_id, tvb, 0, 0, tmp_int);

    // add process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processId", &tmp_int));
    pid = (gint32)tmp_int;
    proto_tree_add_int(context_tree, hf_process_id, tvb, 0, 0, pid);

    // add thread ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadId", &tmp_int));
    proto_tree_add_int(context_tree, hf_thread_id, tvb, 0, 0, (gint32)tmp_int);        

    // add parent process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "parentProcessId", &tmp_int));
    ppid = (gint32)tmp_int;
    proto_tree_add_int(context_tree, hf_parent_process_id, tvb, 0, 0, ppid);

    // add host process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostProcessId", &tmp_int));
    host_pid = (gint32)tmp_int;
    proto_tree_add_int(context_tree, hf_host_process_id, tvb, 0, 0, host_pid);

    // add PID column
    if (pid != 0) {
        switch (pid_format) {
            case PID_FORMAT_CONTAINER_ONLY:
                pid_col_str = wmem_strdup_printf(pinfo->pool, "%d", pid);
                break;
            case PID_FORMAT_HOST_ONLY:
                pid_col_str = wmem_strdup_printf(pinfo->pool, "%d", host_pid);
                break;
            default:
                pid_col_str = wmem_strdup_printf(pinfo->pool, "%d", pid);
                if (pid != host_pid)
                    pid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", pid_col_str, host_pid);
                break;
        }
        tmp_item = proto_tree_add_string(context_tree, hf_pid_col, tvb, 0, 0, pid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add host thread ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostThreadId", &tmp_int));
    proto_tree_add_int(context_tree, hf_host_thread_id, tvb, 0, 0, (gint32)tmp_int);

    // add host parent process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostParentProcessId", &tmp_int));
    host_ppid = (gint32)tmp_int;
    proto_tree_add_int(context_tree, hf_host_parent_process_id, tvb, 0, 0, host_ppid);

    // add PPID column
    if (ppid != 0) {
        switch (pid_format) {
            case PID_FORMAT_CONTAINER_ONLY:
                ppid_col_str = wmem_strdup_printf(pinfo->pool, "%d", ppid);
                break;
            case PID_FORMAT_HOST_ONLY:
                ppid_col_str = wmem_strdup_printf(pinfo->pool, "%d", host_ppid);
                break;
            default:
                ppid_col_str = wmem_strdup_printf(pinfo->pool, "%d", ppid);
                if (ppid != host_ppid)
                    ppid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", ppid_col_str, host_ppid);
                break;
        }
        tmp_item = proto_tree_add_string(context_tree, hf_ppid_col, tvb, 0, 0, ppid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add user ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "userId", &tmp_int));
    proto_tree_add_uint(context_tree, hf_user_id, tvb, 0, 0, (guint32)tmp_int);

    // add mount namespace
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "mountNamespace", &tmp_int));
    proto_tree_add_uint(context_tree, hf_mount_namespace, tvb, 0, 0, (guint32)tmp_int);

    // add PID namespace
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "pidNamespace", &tmp_int));
    proto_tree_add_uint(context_tree, hf_pid_namespace, tvb, 0, 0, (guint32)tmp_int);

    // add process name
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_tok, "processName")) != NULL);
    proto_tree_add_string(context_tree, hf_process_name, tvb, 0, 0, tmp_str);

    // add executable path
    DISSECTOR_ASSERT((tmp_tok = json_get_object(json_data, root_tok, "executable")) != NULL);
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, tmp_tok, "path")) != NULL);
    proto_tree_add_string(context_tree, hf_executable_path, tvb, 0, 0, tmp_str);

    // add hostname
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_tok, "hostName")) != NULL);
    proto_tree_add_string(context_tree, hf_hostname, tvb, 0, 0, tmp_str);

    // add container fields
    dissect_container_fields(tvb, pinfo, context_tree, json_data, root_tok);

    // add k8s fields
    dissect_k8s_fields(tvb, context_tree, json_data, root_tok);

    // add thread entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadEntityId", &tmp_int));
    proto_tree_add_int64(context_tree, hf_thread_entity_id, tvb, 0, 0, tmp_int);

    // add process entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processEntityId", &tmp_int));
    proto_tree_add_int64(context_tree, hf_process_entity_id, tvb, 0, 0, tmp_int);

    // add parent entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "parentEntityId", &tmp_int));
    proto_tree_add_int64(context_tree, hf_parent_entity_id, tvb, 0, 0, tmp_int);
}

struct type_display {
    enum ftenum type;
    int display;
    const void *format_cb;
};

static gchar *normalize_arg_name(const gchar *name)
{
    // replace spaces with underscores
    return g_strdelimit(g_strdup(name), " ", '_');
}

/**
 * Determine the field type and display based on the type string.
 */
static void get_arg_field_type_display(const gchar *type, struct type_display *info, const gchar *event_name, const gchar *arg_name)
{
    info->format_cb = NULL;

    // string
    if (strcmp(type, "const char *")        == 0 ||
        strcmp(type, "const char*")         == 0 ||
        strcmp(type, "string")              == 0 ||
        strcmp(type, "char*")               == 0 ||
        strcmp(type, "bytes")               == 0 ||
        strcmp(type, "void*")               == 0 ||
        strcmp(type, "int*")                == 0) {
        
        info->type = FT_STRINGZ;
        info->display = BASE_NONE;
    }

    // bool
    else if (strcmp(type, "bool") == 0) {
        info->type = FT_BOOLEAN;
        info->display = BASE_NONE;
    }

    // u8
    else if (strcmp(type, "u8") == 0) {
        info->type = FT_UINT8;
        info->display = BASE_DEC;
    }

    // u16
    else if (strcmp(type, "umode_t")    == 0 ||
             strcmp(type, "u16")        == 0) {
        
        info->type = FT_UINT16;
        info->display = BASE_DEC;
    }

    // s32
    else if (strcmp(type, "int")    == 0 ||
             strcmp(type, "pid_t")  == 0) {
        
        info->type = FT_INT32;
        info->display = BASE_DEC;

    }

    // u32
    else if (strcmp(type, "dev_t")          == 0 ||
             strcmp(type, "u32")            == 0 ||
             strcmp(type, "unsigned int")   == 0 ||
             strcmp(type, "mode_t")         == 0 ||
             strcmp(type, "uid_t")          == 0 ||
             strcmp(type, "gid_t")          == 0) {
        
        info->type = FT_UINT32;
        info->display = BASE_DEC;
    }

    // s64
    else if (strcmp(type, "long")   == 0 ||
             strcmp(type, "off_t")  == 0) {
        
        info->type = FT_INT64;
        info->display = BASE_DEC;
    }

    // u64
    else if (strcmp(type, "unsigned long")  == 0 ||
             strcmp(type, "u64")            == 0 ||
             strcmp(type, "size_t")         == 0) {
        
        info->type = FT_UINT64;
        info->display = BASE_DEC;
    }

    // other types
    else {        
        info->type = FT_NONE;
        info->display = BASE_NONE;

        // check if we are aware of this type
        if (!wmem_map_contains(complex_type_dissectors, type))
            ws_warning("unknown type \"%s\" of arg \"%s\" in event \"%s\"", type, arg_name, event_name);
    }
}

static void dynamic_hf_populate_arg_field(hf_register_info *hf, const gchar *event_name, const gchar *arg_name, const gchar *type)
{
    gchar *name_normalized;
    struct type_display info;

    hf->p_id = wmem_new(wmem_file_scope(), int);
    *(hf->p_id) = -1;

    hf->hfinfo.name = g_strdup(arg_name);
    name_normalized = normalize_arg_name(arg_name);
    hf->hfinfo.abbrev = g_strdup_printf("tracee.args.%s", name_normalized);
    g_free(name_normalized);

    get_arg_field_type_display(type, &info, event_name, arg_name);

    hf->hfinfo.type = info.type;
    hf->hfinfo.display = info.display;
    hf->hfinfo.strings = info.format_cb;
    hf->hfinfo.bitmask = 0;
    hf->hfinfo.blurb = g_strdup(arg_name);
    HFILL_INIT(hf[0]);
}

static hf_register_info *get_arg_hf(const gchar *event_name, gchar *json_data, jsmntok_t *arg_tok)
{
    struct event_dynamic_hf *dynamic_hf;
    gchar *event_name_copy, *arg_name, *arg_type, *arg_name_copy;
    int *hf_idx;
    hf_register_info *hf;

    // try fetching the dynamic hf for this event
    if ((dynamic_hf = wmem_map_lookup(event_dynamic_hf_map, event_name)) == NULL) {
        // no dynamic hf for this event - create it
        dynamic_hf = wmem_new(wmem_file_scope(), struct event_dynamic_hf);
        dynamic_hf->hf_ptrs = g_ptr_array_new();
        dynamic_hf->arg_idx_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
        event_name_copy = wmem_strdup(wmem_file_scope(), event_name);
        wmem_map_insert(event_dynamic_hf_map, event_name_copy, dynamic_hf);
    }

    // check if the field for this argument is already registered, if so return it
    DISSECTOR_ASSERT((arg_name = json_get_string(json_data, arg_tok, "name")) != NULL);
    if ((hf_idx = wmem_map_lookup(dynamic_hf->arg_idx_map, arg_name)) != NULL)
        return (hf_register_info *)dynamic_hf->hf_ptrs->pdata[*hf_idx];
    
    // field not registered yet - create it
    DISSECTOR_ASSERT((arg_type = json_get_string(json_data, arg_tok, "type")) != NULL);

    // override for sepcific problematic fields which are supposed to be strings but are sometimes integers
    if (strcmp(event_name, "security_file_open") == 0 && strcmp(arg_name, "flags") == 0)
        arg_type = "string";
    else if (strcmp(event_name, "security_file_mprotect") == 0) {
        if (strcmp(arg_name, "prot") == 0 || strcmp(arg_name, "prev_prot") == 0)
            arg_type = "string";
    }
    
    // create the hf and add it to the array
    hf = g_new0(hf_register_info, 1);
    g_ptr_array_add(dynamic_hf->hf_ptrs, hf);
    hf_idx = wmem_new(wmem_file_scope(), int);
    *hf_idx = dynamic_hf->hf_ptrs->len - 1;

    // populate the field info
    dynamic_hf_populate_arg_field(hf, event_name, arg_name, arg_type);

    // update arg name to idx map
    arg_name_copy = wmem_strdup(wmem_file_scope(), arg_name);
    wmem_map_insert(dynamic_hf->arg_idx_map, arg_name_copy, hf_idx);

    // register the added field with wireshark
    proto_register_field_array(proto_tracee, hf, 1);

    return hf;
}

static void do_dissect_string_array(tvbuff_t *tvb, proto_tree *arr_tree, int hf_id,
    const gchar *arr_name, gchar *json_data, jsmntok_t *arr_tok, wmem_array_t *arr_data)
{
    int i, arr_len;
    jsmntok_t *elem_tok;
    gchar *str;
    proto_item *tmp_item;

    // get array length
    DISSECTOR_ASSERT((arr_len = json_get_array_len(arr_tok)) >= 0);

    // iterate through all elements
    for (i = 0; i < arr_len; i++) {
        // get element
        DISSECTOR_ASSERT((elem_tok = json_get_array_index(arr_tok, i)) != NULL);
        
        // make sure it's a string
        DISSECTOR_ASSERT(elem_tok->type == JSMN_STRING);

        // get the value
        json_data[elem_tok->end] = '\0';
        str = &json_data[elem_tok->start];
        DISSECTOR_ASSERT(json_decode_string_inplace(str));
        if (arr_data != NULL)
            wmem_array_append_one(arr_data, str);

        // add the value to the dissection tree
        tmp_item = proto_tree_add_string_wanted(arr_tree, hf_id, tvb, 0, 0, str);
        proto_item_set_text(tmp_item, "%s[%d]: %s", arr_name, i, proto_item_get_display_repr(wmem_packet_scope(), tmp_item));
    }
}

static wmem_array_t *add_string_array(tvbuff_t *tvb, proto_tree *tree, int hf_id, const gchar *item_name,
    const gchar *arr_name, gchar *json_data, jsmntok_t *parent_tok, const gchar *arr_tok_name, gboolean get_data)
{
    proto_item *arr_item;
    proto_tree *arr_tree;
    jsmntok_t *arr_tok;
    int arr_len;
    wmem_array_t *arr_data = NULL;

    // create the item
    arr_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(arr_item, "%s", item_name);

    // get array
    if ((arr_tok = json_get_array(json_data, parent_tok, arr_tok_name)) != NULL) {
        DISSECTOR_ASSERT((arr_len = json_get_array_len(arr_tok)) >= 0);
        proto_item_append_text(arr_item, ": %d item%s", arr_len, arr_len == 1 ? "" : "s");
    }
    // not an array - try getting a null
    else if (json_get_null(json_data, parent_tok, arr_tok_name)) {
        proto_item_append_text(arr_item, ": (null)");
        return NULL;
    }
    else {
        proto_item_set_hidden(arr_item);
        return NULL;
    }
    
    // create the subtree
    arr_tree = proto_item_add_subtree(arr_item, ett_string_arr);
    
    if (get_data)
        arr_data = wmem_array_sized_new(wmem_packet_scope(), sizeof(gchar *), arr_len);

    do_dissect_string_array(tvb, arr_tree, hf_id, arr_name, json_data, arr_tok, arr_data);

    return arr_data;
}

static void add_network_filter(tvbuff_t *tvb, proto_tree *tree, const gchar *filter)
{
    proto_item *item;
    int proto;

    DISSECTOR_ASSERT((proto = proto_get_id_by_filter_name(filter)) != -1);
    item = proto_tree_add_item(tree, proto, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(item);
}

typedef gchar * (*object_dissector_t) (tvbuff_t*, proto_tree*, gchar*, jsmntok_t*);

static gchar *do_dissect_sockaddr(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *arg_str, *tmp_str;
    proto_item *tmp_item;
    ws_in4_addr in4_addr;
    ws_in6_addr in6_addr;
    gint64 tmp_int;

    // add sa_family
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "sa_family")) != NULL);
    proto_tree_add_string_wanted(tree, hf_sockaddr_sa_family, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "sa_family = %s", tmp_str);
    if (strcmp(tmp_str, "AF_INET") == 0)
        add_network_filter(tvb, tree, "ip");
    else if (strcmp(tmp_str, "AF_INET6") == 0)
        add_network_filter(tvb, tree, "ipv6");    
    
    // add sun_path
    if ((tmp_str = json_get_string(json_data, obj_tok, "sun_path")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sun_path, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sun_path = %s", arg_str, tmp_str);
    }
    
    // add sin_addr
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin_addr")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin_addr, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin_addr = %s", arg_str, tmp_str);
        DISSECTOR_ASSERT(ws_inet_pton4(tmp_str, &in4_addr));
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_addr, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);

        // add address as both src and dst because we don't know which it is
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_src, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_dst, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
    }
    
    // add sin_port
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin_port")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin_port, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin_port = %s", arg_str, tmp_str);
        errno = 0;
        tmp_int = strtoll(tmp_str, NULL, 10);
        DISSECTOR_ASSERT(errno == 0);

        // add port as both tcp and udp and bot src and dst because we don't know which it is
        tmp_item = proto_tree_add_uint(tree, hf_tcp_port, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_srcport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_dstport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_port, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_srcport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_dstport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
    }
    
    // add sin6_addr
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_addr")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin6_addr, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin6_addr = %s", arg_str, tmp_str);
        if (ws_inet_pton6(tmp_str, &in6_addr)) {
            tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_addr, tvb, 0, 0, &in6_addr);
            proto_item_set_hidden(tmp_item);

            // add address as both src and dst because we don't know which it is
            tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_src, tvb, 0, 0, &in6_addr);
            proto_item_set_hidden(tmp_item);
            tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_dst, tvb, 0, 0, &in6_addr);
            proto_item_set_hidden(tmp_item);
        }
        // sometimes and IPv4 address appears in the sin6_addr field, ignore these
        else
            ws_info("error decoding ipv6 addr %s", tmp_str);
    }
    
    // add sin6_port
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_port")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin6_port, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin6_port = %s", arg_str, tmp_str);
        errno = 0;
        tmp_int = strtoll(tmp_str, NULL, 10);
        DISSECTOR_ASSERT(errno == 0);

        // add port as both tcp and udp and bot src and dst because we don't know which it is
        tmp_item = proto_tree_add_uint(tree, hf_tcp_port, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_srcport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_dstport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_port, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_srcport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_dstport, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
    }
    
    // add sin6_flowinfo
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_flowinfo")) != NULL) {
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin6_flowinfo, tvb, 0, 0, tmp_str);
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin6_flowinfo = %s", arg_str, tmp_str);
    }
    
    // add sin6_scopeid
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_scopeid")) != NULL) {
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, sin6_scopeid = %s", arg_str, tmp_str);
        proto_tree_add_string_wanted(tree, hf_sockaddr_sin6_scopeid, tvb, 0, 0, tmp_str);
    }

    return arg_str;
}

static gchar *do_dissect_slim_cred_t(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gint64 tmp_int;

    // add uid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Uid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_uid, tvb, 0, 0, tmp_int);

    // add gid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Gid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_gid, tvb, 0, 0, tmp_int);

    // add suid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Suid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_suid, tvb, 0, 0, tmp_int);

    // add sgid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Sgid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_sgid, tvb, 0, 0, tmp_int);

    // add euid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Euid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_euid, tvb, 0, 0, tmp_int);

    // add egid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Egid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_egid, tvb, 0, 0, tmp_int);

    // add fsuid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Fsuid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_fsuid, tvb, 0, 0, tmp_int);

    // add fsgid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Fsgid", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_fsgid, tvb, 0, 0, tmp_int);

    // add user namespace
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "UserNamespace", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_user_namespace, tvb, 0, 0, tmp_int);

    // add secure bits
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "SecureBits", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_secure_bits, tvb, 0, 0, tmp_int);

    // add capinh
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapInheritable", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_cap_inheritable, tvb, 0, 0, tmp_int);

    // add capprm
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapPermitted", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_cap_permitted, tvb, 0, 0, tmp_int);

    // add capeff
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapEffective", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_cap_effective, tvb, 0, 0, tmp_int);

    // add capbnd
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapBounding", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_cap_bounding, tvb, 0, 0, tmp_int);

    // add capamb
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapAmbient", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_slim_cred_t_cap_ambient, tvb, 0, 0, tmp_int);

    return NULL;
}

static gchar *do_dissect_pktmeta(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gint64 tmp_int;
    gchar *arg_str, *tmp_str;
    ws_in4_addr in4_addr;
    ws_in6_addr in6_addr;
    proto_item *tmp_item;
    guint32 src_port, dst_port;

    // add src ip
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "src_ip")) != NULL);
    proto_tree_add_string_wanted(tree, hf_pktmeta_src_ip, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "src_ip = %s", tmp_str);
    if (ws_inet_pton4(tmp_str, &in4_addr)) {
        add_network_filter(tvb, tree, "ip");
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_addr, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_src, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
    }
    else if (ws_inet_pton6(tmp_str, &in6_addr)) {
        add_network_filter(tvb, tree, "ipv6");
        tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_addr, tvb, 0, 0, &in6_addr);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_src, tvb, 0, 0, &in6_addr);
        proto_item_set_hidden(tmp_item);
    }
    
    // add dst ip
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "dst_ip")) != NULL);
    proto_tree_add_string_wanted(tree, hf_pktmeta_dst_ip, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, dst_ip = %s", arg_str, tmp_str);
    if (ws_inet_pton4(tmp_str, &in4_addr)) {
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_addr, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_ipv4(tree, hf_ip_dst, tvb, 0, 0, in4_addr);
        proto_item_set_hidden(tmp_item);
    }
    else if (ws_inet_pton6(tmp_str, &in6_addr)) {
        add_network_filter(tvb, tree, "ipv6");
        tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_addr, tvb, 0, 0, &in6_addr);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_ipv6(tree, hf_ipv6_dst, tvb, 0, 0, &in6_addr);
        proto_item_set_hidden(tmp_item);
    }
    
    // add src port
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "src_port", &tmp_int));
    src_port = (guint32)tmp_int;
    proto_tree_add_uint_wanted(tree, hf_pktmeta_src_port, tvb, 0, 0, src_port);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, src_port = %u", arg_str, src_port);

    // add dst port
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "dst_port", &tmp_int));
    dst_port = (guint32)tmp_int;
    proto_tree_add_uint_wanted(tree, hf_pktmeta_dst_port, tvb, 0, 0, dst_port);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, dst_port = %u", arg_str, dst_port);

    // add protocol
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "protocol", &tmp_int));
    proto_tree_add_uint_wanted(tree, hf_pktmeta_protocol, tvb, 0, 0, (guint32)tmp_int);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, ipproto = %u", arg_str, (guint32)tmp_int);
    tmp_item = proto_tree_add_uint(tree, hf_ip_proto, tvb, 0, 0, (guint8)tmp_int);
    proto_item_set_hidden(tmp_item);
    if (tmp_int == IP_PROTO_TCP) {
        add_network_filter(tvb, tree, "tcp");
        tmp_item = proto_tree_add_uint(tree, hf_tcp_port, tvb, 0, 0, src_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_port, tvb, 0, 0, dst_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_srcport, tvb, 0, 0, src_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_tcp_dstport, tvb, 0, 0, dst_port);
        proto_item_set_hidden(tmp_item);
    }
    else if (tmp_int == IP_PROTO_UDP) {
        add_network_filter(tvb, tree, "udp");
        tmp_item = proto_tree_add_uint(tree, hf_udp_port, tvb, 0, 0, src_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_port, tvb, 0, 0, dst_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_srcport, tvb, 0, 0, src_port);
        proto_item_set_hidden(tmp_item);
        tmp_item = proto_tree_add_uint(tree, hf_udp_dstport, tvb, 0, 0, dst_port);
        proto_item_set_hidden(tmp_item);
    }
    else if (tmp_int == IP_PROTO_ICMP)
        add_network_filter(tvb, tree, "icmp");
    else if (tmp_int == IP_PROTO_ICMPV6)
        add_network_filter(tvb, tree, "icmpv6");

    // add packet len
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "packet_len", &tmp_int));
    proto_tree_add_uint_wanted(tree, hf_pktmeta_packet_len, tvb, 0, 0, (guint32)tmp_int);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, len = %u", arg_str, (guint32)tmp_int);

    // add iface
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "iface")) != NULL);
    proto_tree_add_string_wanted(tree, hf_pktmeta_iface, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, iface = %s", arg_str, tmp_str);

    return arg_str;
}

static gchar *do_dissect_dns_query_data(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *arg_str, *tmp_str;
    proto_item *tmp_item;

    add_network_filter(tvb, tree, "dns");

    // add query
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "query")) != NULL);
    proto_tree_add_string_wanted(tree, hf_dnsquery_query, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_dns_qry_name, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "query = %s", tmp_str);

    // add type
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "query_type")) != NULL);
    proto_tree_add_string_wanted(tree, hf_dnsquery_type, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, type = %s", arg_str, tmp_str);

    // add class
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "query_class")) != NULL);
    proto_tree_add_string_wanted(tree, hf_dnsquery_class, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, class = %s", arg_str, tmp_str);

    return arg_str;
}

static gchar *do_dissect_dns_answer(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *tmp_str;
    gint64 tmp_int;
    proto_item *tmp_item;

    // add type
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "answer_type")) != NULL);
    proto_tree_add_string_wanted(tree, hf_dnsanswer_type, tvb, 0, 0, tmp_str);

    // add TTL
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "ttl", &tmp_int));
    proto_tree_add_uint_wanted(tree, hf_dnsanswer_ttl, tvb, 0, 0, (guint32)tmp_int);
    tmp_item = proto_tree_add_uint(tree, hf_dns_resp_ttl, tvb, 0, 0, (guint32)tmp_int);
    proto_item_set_hidden(tmp_item);

    // add answer
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "answer")) != NULL);
    proto_tree_add_string_wanted(tree, hf_dnsanswer_answer, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_dns_resp_name, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);

    return NULL;
}

static gchar *do_dissect_dns_response_data(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    jsmntok_t *query_tok, *answers_arr, *answer_tok;
    proto_item *query_item, *answers_item, *answer_item;
    proto_tree *query_tree, *answers_tree, *answer_tree;
    int answers_len, i;

    // dissect query data
    DISSECTOR_ASSERT((query_tok = json_get_object(json_data, obj_tok, "query_data")) != NULL);
    query_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(query_item, "%s", "query_data");
    query_tree = proto_item_add_subtree(query_item, ett_dns_query_data);
    do_dissect_dns_query_data(tvb, query_tree, json_data, query_tok);

    // dissect query answer array
    DISSECTOR_ASSERT((answers_arr = json_get_array(json_data, obj_tok, "dns_answer")) != NULL);
    DISSECTOR_ASSERT((answers_len = json_get_array_len(answers_arr)) >= 0);
    answers_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(answers_item, "dns_answer: %d item%s", answers_len, answers_len == 1 ? "" : "s");
    answers_tree = proto_item_add_subtree(answers_item, ett_arg_obj_arr);

    // go through each answer and dissect it
    for (i = 0; i < answers_len; i++) {
        // add item subtree
        answer_item = proto_tree_add_item(answers_tree, proto_tracee, tvb, 0, 0, ENC_NA);
        proto_item_set_text(answer_item, "dns_answer[%d]", i);
        answer_tree = proto_item_add_subtree(answer_item, ett_arg_obj);

        // call dissector for the object
        DISSECTOR_ASSERT((answer_tok = json_get_array_index(answers_arr, i)) != NULL);
        do_dissect_dns_answer(tvb, answer_tree, json_data, answer_tok);
    }
    
    return NULL;
}

static gchar *dissect_http_headers(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *headers_tok)
{
    proto_item *headers_item, *tmp_item;
    proto_tree *headers_tree;
    int i, j, curr_arr_size, header_hf;
    jsmntok_t *curr_header_tok, *curr_arr_tok, *curr_elem_tok;
    gchar *header_name, *header_value, *tmp_str, *headers_str = NULL;

    // add headers tree
    headers_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(headers_item, "Headers");
    headers_tree = proto_item_add_subtree(headers_item, ett_http_headers);

    // iterate through objects under the main headers object
    curr_header_tok = headers_tok + 1;
    for (i = 0; i < headers_tok->size; i++, curr_header_tok = json_get_next_object(curr_header_tok)) {
        // get header name
        json_data[curr_header_tok->end] = '\0';
        header_name = &json_data[curr_header_tok->start];
        DISSECTOR_ASSERT(json_decode_string_inplace(header_name));

        // get header array
        curr_arr_tok = curr_header_tok + 1;
        DISSECTOR_ASSERT(curr_arr_tok->type == JSMN_ARRAY);
        DISSECTOR_ASSERT((curr_arr_size = json_get_array_len(curr_arr_tok)) >= 0);
        
        // iterate through header values
        for (j = 0; j < curr_arr_size; j++) {
            // get header value
            DISSECTOR_ASSERT((curr_elem_tok = json_get_array_index(curr_arr_tok, j)) != NULL);
            DISSECTOR_ASSERT(curr_elem_tok->type == JSMN_STRING);
            json_data[curr_elem_tok->end] = '\0';
            header_value = &json_data[curr_elem_tok->start];
            DISSECTOR_ASSERT(json_decode_string_inplace(header_value));

            // add header value to dissection
            tmp_str = wmem_strdup_printf(wmem_packet_scope(), "%s: %s", header_name, header_value);
            tmp_item = proto_tree_add_string_wanted(headers_tree, hf_proto_http_request_header, tvb, 0, 0, tmp_str);
            proto_item_set_text(tmp_item, "%s", tmp_str);
            if (headers_str == NULL)
                headers_str = wmem_strdup(wmem_packet_scope(), tmp_str);
            else
                headers_str = wmem_strdup_printf(wmem_packet_scope(), "%s, %s", headers_str, tmp_str);
            
            // add header value to relevant http fields
            header_hf = -1;
            if (strcmp(header_name, "Accept") == 0)
                header_hf = hf_http_accept;
            else if (strcmp(header_name, "User-Agent") == 0)
                header_hf = hf_http_user_agent;
            else if (strcmp(header_name, "Referer") == 0)
                header_hf = hf_http_referer;
            else if (strcmp(header_name, "Cookie") == 0)
                header_hf = hf_http_cookie;
            else if (strcmp(header_name, "Content-Type") == 0)
                header_hf = hf_http_content_type;
            else if (strcmp(header_name, "Connection") == 0)
                header_hf = hf_http_connection;
            else if (strcmp(header_name, "Accept-Language") == 0)
                header_hf = hf_http_accept_language;
            else if (strcmp(header_name, "Accept-Encoding") == 0)
                header_hf = hf_http_accept_encoding;
            else if (strcmp(header_name, "Content-Length") == 0)
                header_hf = hf_http_content_length_header;
            else if (strcmp(header_name, "Upgrade") == 0)
                header_hf = hf_http_upgrade;
            else
                ws_info("unknown HTTP header \"%s\"", header_name);
            
            if (header_hf != -1) {
                tmp_item = proto_tree_add_string_wanted(headers_tree, header_hf, tvb, 0, 0, header_value);
                proto_item_set_hidden(tmp_item);
            }

            // add as request line, append "\r\n" to the end for compliance with the HTTP dissector's format
            tmp_str = wmem_strdup_printf(wmem_packet_scope(), "%s\r\n", tmp_str);
            tmp_item = proto_tree_add_string(headers_tree, hf_http_request_line, tvb, 0, 0, tmp_str);
            proto_item_set_hidden(tmp_item);
        }
    }

    return headers_str;
}

static gchar *do_dissect_proto_http_request(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    proto_item *tmp_item;
    gchar *arg_str, *headers_str, *tmp_str;
    jsmntok_t *headers_tok;
    gint64 tmp_int;

    add_network_filter(tvb, tree, "http");
    tmp_item = proto_tree_add_boolean_wanted(tree, hf_http_request, tvb, 0, 0, TRUE);
    proto_item_set_hidden(tmp_item);

    // add method
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "method")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_request_method, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_http_request_method, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "method = %s", tmp_str);

    // add protocol
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "protocol")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_request_protocol, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_http_request_version, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, protocol = %s", arg_str, tmp_str);

    // add host
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "host")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_request_host, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_http_host, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, host = %s", arg_str, tmp_str);

    // add URI path
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "uri_path")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_request_uri_path, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, hf_http_request_uri, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, URI = %s", arg_str, tmp_str);

    // add headers
    DISSECTOR_ASSERT((headers_tok = json_get_object(json_data, obj_tok, "headers")) != NULL);
    headers_str = dissect_http_headers(tvb, tree, json_data, headers_tok);
    if (headers_str != NULL)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, headers = [%s]", arg_str, headers_str);
    
    // add content length
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "content_length", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_proto_http_request_content_length, tvb, 0, 0, tmp_int);
    tmp_item = proto_tree_add_uint64(tree, hf_http_content_length, tvb, 0, 0, (guint64)tmp_int);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, content_length = %" PRId64, arg_str, tmp_int);

    return arg_str;
}

static gchar *do_dissect_packet_metadata(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gint64 tmp_int;
    const gchar *tmp_str;

    // add direction
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "direction", &tmp_int));
    proto_tree_add_int_wanted(tree, hf_packet_metadata_direction, tvb, 0, 0, (gint32)tmp_int);
    tmp_str = try_val_to_str((guint32)tmp_int, packet_metadata_directions);
    if (tmp_str != NULL)
        return wmem_strdup_printf(wmem_packet_scope(), "direction = %s", tmp_str);
    else
        return wmem_strdup_printf(wmem_packet_scope(), "direction = %d", (gint32)tmp_int);
}

static gchar *do_dissect_proto_http(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *arg_str, *status_desc, *headers_str, *tmp_str;
    gboolean request;
    proto_item *tmp_item;
    gint64 tmp_int;
    jsmntok_t *headers_tok;

    add_network_filter(tvb, tree, "http");

    // add direction
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "direction")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_direction, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "direction = %s", tmp_str);
    if (strcmp(tmp_str, "request") == 0)
        request = TRUE;
    else {
        DISSECTOR_ASSERT(strcmp(tmp_str, "response") == 0);
        request = FALSE;
    }
    tmp_item = proto_tree_add_boolean_wanted(tree, request ? hf_http_request : hf_http_response, tvb, 0, 0, TRUE);
    proto_item_set_hidden(tmp_item);

    // add method
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "method")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_method, tvb, 0, 0, tmp_str);
    if (request) {
        tmp_item = proto_tree_add_string(tree, hf_http_request_method, tvb, 0, 0, tmp_str);
        proto_item_set_hidden(tmp_item);
    }
    if (strlen(tmp_str) > 0)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, method = %s", arg_str, tmp_str);

    // add protocol
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "protocol")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_protocol, tvb, 0, 0, tmp_str);
    tmp_item = proto_tree_add_string(tree, request ? hf_http_request_version : hf_http_response_version, tvb, 0, 0, tmp_str);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, protocol = %s", arg_str, tmp_str);

    // add host
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "host")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_host, tvb, 0, 0, tmp_str);
    if (request) {
        tmp_item = proto_tree_add_string(tree, hf_http_host, tvb, 0, 0, tmp_str);
        proto_item_set_hidden(tmp_item);
    }
    if (strlen(tmp_str) > 0)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, host = %s", arg_str, tmp_str);

    // add URI path
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "uri_path")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_uri_path, tvb, 0, 0, tmp_str);
    if (request) {
        tmp_item = proto_tree_add_string(tree, hf_http_request_uri, tvb, 0, 0, tmp_str);
        proto_item_set_hidden(tmp_item);
    }
    if (strlen(tmp_str) > 0)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, URI = %s", arg_str, tmp_str);

    // add status
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "status")) != NULL);
    proto_tree_add_string_wanted(tree, hf_proto_http_status, tvb, 0, 0, tmp_str);
    if (!request) {
        status_desc = strchr(tmp_str, ' ');
        if (status_desc != NULL) {
            status_desc += 1; // skip whitespace
            tmp_item = proto_tree_add_string(tree, hf_http_response_code_desc, tvb, 0, 0, status_desc);
            proto_item_set_hidden(tmp_item);
            tmp_item = proto_tree_add_string(tree, hf_http_response_phrase, tvb, 0, 0, status_desc);
            proto_item_set_hidden(tmp_item);
        }
    }
    if (strlen(tmp_str) > 0)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, status = %s", arg_str, tmp_str);
    
    // add status code
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "status_code", &tmp_int));
    proto_tree_add_int_wanted(tree, hf_proto_http_status_code, tvb, 0, 0, (gint32)tmp_int);
    if (!request) {
        tmp_item = proto_tree_add_uint(tree, hf_http_response_code, tvb, 0, 0, (guint32)tmp_int);
        proto_item_set_hidden(tmp_item);
    }
    
    // add headers
    DISSECTOR_ASSERT((headers_tok = json_get_object(json_data, obj_tok, "headers")) != NULL);
    headers_str = dissect_http_headers(tvb, tree, json_data, headers_tok);
    if (headers_str != NULL)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, headers = [%s]", arg_str, headers_str);
    
    // add content length
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "content_length", &tmp_int));
    proto_tree_add_int64_wanted(tree, hf_proto_http_content_length, tvb, 0, 0, tmp_int);
    tmp_item = proto_tree_add_uint64(tree, hf_http_content_length, tvb, 0, 0, (guint64)tmp_int);
    proto_item_set_hidden(tmp_item);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, content_length = %" PRId64, arg_str, tmp_int);

    return arg_str;
}

static gchar *do_dissect_hooked_symbol_data(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *tmp_str, *arg_str;

    // add symbol name
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "SymbolName")) != NULL);
    proto_tree_add_string_wanted(tree, hf_hooked_symbol_name, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "SymbolName = %s", tmp_str);

    // add module owner
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "ModuleOwner")) != NULL);
    proto_tree_add_string_wanted(tree, hf_hooked_symbol_module_owner, tvb, 0, 0, tmp_str);
    arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, ModuleOwner = %s", arg_str, tmp_str);

    return arg_str;
}

static gchar *dissect_object_arg(tvbuff_t *tvb, proto_tree *tree, gchar *json_data,
    jsmntok_t *arg_tok, const gchar *arg_name, object_dissector_t dissector)
{
    proto_item *obj_item;
    proto_tree *obj_tree;
    jsmntok_t *obj_tok;
    gchar *arg_str;

    // create object subtree
    obj_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(obj_item, "%s", arg_name);
    obj_tree = proto_item_add_subtree(obj_item, ett_arg_obj);

    // try getting object
    if ((obj_tok = json_get_object(json_data, arg_tok, "value")) == NULL) {
        // couldn't get object - try getting a null
        DISSECTOR_ASSERT(json_get_null(json_data, arg_tok, "value"));
        proto_item_append_text(obj_item, ": (null)");
        return NULL;
    }

    // call dissector for this object
    arg_str = dissector(tvb, obj_tree, json_data, obj_tok);

    // wrap arg str in brackets
    if (arg_str != NULL)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "{%s}", arg_str);
    
    return arg_str;
}

static gchar *dissect_object_array_arg(tvbuff_t *tvb, proto_tree *tree, gchar *json_data,
    jsmntok_t *arg_tok, const gchar *arg_name, object_dissector_t dissector)
{
    proto_item *arr_item, *obj_item;
    proto_tree *arr_tree, *obj_tree;
    jsmntok_t *arr_tok, *obj_tok;
    int arr_len, i;
    gchar *arg_str, *arg_arr_str = NULL;

    // create array subtree
    arr_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(arr_item, "%s", arg_name);
    arr_tree = proto_item_add_subtree(arr_item, ett_arg_obj_arr);

    // get the array
    DISSECTOR_ASSERT((arr_tok = json_get_array(json_data, arg_tok, "value")) != NULL);
    DISSECTOR_ASSERT((arr_len = json_get_array_len(arr_tok)) >= 0);
    proto_item_append_text(arr_item, ": %d item%s", arr_len, arr_len == 1 ? "" : "s");

    // go through each array element and dissect it
    for (i = 0; i < arr_len; i++) {
        // add item subtree
        obj_item = proto_tree_add_item(arr_tree, proto_tracee, tvb, 0, 0, ENC_NA);
        proto_item_set_text(obj_item, "%s[%d]", arg_name, i);
        obj_tree = proto_item_add_subtree(obj_item, ett_arg_obj);

        // call dissector for the object
        DISSECTOR_ASSERT((obj_tok = json_get_array_index(arr_tok, i)) != NULL);
        arg_str = dissector(tvb, obj_tree, json_data, obj_tok);

        // add arg str to array str
        if (arg_str != NULL) {
            // array str not initialized yet
            if (arg_arr_str == NULL)
                arg_arr_str = wmem_strdup_printf(wmem_packet_scope(), "[{%s}", arg_str);
            else
                arg_arr_str = wmem_strdup_printf(wmem_packet_scope(), "%s, {%s}", arg_arr_str, arg_str);
        }
    }
    
    // finalize array str
    if (arg_arr_str != NULL)
        arg_arr_str = wmem_strdup_printf(wmem_packet_scope(), "%s]", arg_arr_str);
    
    return arg_arr_str;
}

static void dissect_process_lineage(tvbuff_t *tvb,
    proto_tree *tree, gchar *json_data, jsmntok_t *arg_tok)
{
    proto_item *process_lineage_item, *process_item, *tmp_item;
    proto_tree *process_lineage_tree, *process_tree;
    jsmntok_t *arr_tok, *elem_tok;
    int arr_len, i;
    wmem_array_t *process_arr;
    struct process_info {
        gint32 pid;
        gint32 ppid;
        gchar *name;
    } process_info;
    gint64 tmp_int;
    nstime_t start_time;
    gchar *tmp_str, *process_lineage_desc = NULL;
    struct process_info *process_info_ptr;
    gint32 prev_pid = 0;
    gboolean process_lineage_intact = TRUE;

    // place process lineage outside of args tree
    tree = proto_tree_get_parent_tree(tree);

    // create process lineage subtree
    process_lineage_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(process_lineage_item, "Process Lineage");
    process_lineage_tree = proto_item_add_subtree(process_lineage_item, ett_process_lineage);

    // get process lineage array
    if ((arr_tok = json_get_array(json_data, arg_tok, "value")) == NULL) {
        // not an array - try getting a null
        DISSECTOR_ASSERT(json_get_null(json_data, arg_tok, "value"));
        proto_item_append_text(process_lineage_item, ": (null)");
        return;
    }
      
    DISSECTOR_ASSERT((arr_len = json_get_array_len(arr_tok)) >= 0);
    
    // save an array of processes in the process lineage
    process_arr = wmem_array_sized_new(wmem_packet_scope(), sizeof(struct process_info), arr_len);
    
    // iterate through all elements
    for (i = 0; i < arr_len; i++) {
        // get element
        DISSECTOR_ASSERT((elem_tok = json_get_array_index(arr_tok, i)) != NULL);

        // make sure it's an object
        DISSECTOR_ASSERT(elem_tok->type == JSMN_OBJECT);
        
        // create process subtree
        process_item = proto_tree_add_item(process_lineage_tree, proto_tracee, tvb, 0, 0, ENC_NA);
        proto_item_set_text(process_item, "Process");
        process_tree = proto_item_add_subtree(process_item, ett_process_lineage_process);

        // add pid
        DISSECTOR_ASSERT(json_get_int(json_data, elem_tok, "PID", &tmp_int));
        process_info.pid = (gint32)tmp_int;
        proto_tree_add_int(process_tree, hf_process_lineage_pid, tvb, 0, 0, process_info.pid);

        // add ppid
        DISSECTOR_ASSERT(json_get_int(json_data, elem_tok, "PPID", &tmp_int));
        process_info.ppid = (gint32)tmp_int;
        proto_tree_add_int(process_tree, hf_process_lineage_ppid, tvb, 0, 0, process_info.ppid);

        // add ppid as a hidden pid item so we can filter based on any pid in the process lineage
        tmp_item = proto_tree_add_int(process_tree, hf_process_lineage_pid, tvb, 0, 0, process_info.ppid);
        proto_item_set_hidden(tmp_item);

        // add start time
        DISSECTOR_ASSERT(json_get_int(json_data, elem_tok, "StartTime", &tmp_int));
        start_time.secs = (guint64)tmp_int / 1000000000;
        start_time.nsecs = (guint64)tmp_int % 1000000000;
        proto_tree_add_time(process_tree, hf_process_lineage_start_time, tvb, 0, 0, &start_time);

        // add process name
        DISSECTOR_ASSERT((process_info.name = json_get_string(json_data, elem_tok, "ProcessName")) != NULL);
        proto_tree_add_string(process_tree, hf_process_lineage_process_name, tvb, 0, 0, process_info.name);

        // add pathname
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, elem_tok, "Pathname")) != NULL);
        proto_tree_add_string(process_tree, hf_process_lineage_pathname, tvb, 0, 0, tmp_str);

        // add sha256
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, elem_tok, "SHA256")) != NULL);
        proto_tree_add_string(process_tree, hf_process_lineage_sha256, tvb, 0, 0, tmp_str);

        // add command
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, elem_tok, "Command")) != NULL);
        proto_tree_add_string(process_tree, hf_process_lineage_command, tvb, 0, 0, tmp_str);

        // set process item text
        proto_item_set_text(process_item, "%d -> %d", process_info.ppid, process_info.pid);
        if (strlen(process_info.name) > 0)
            proto_item_append_text(process_item, " (%s)", process_info.name);
        
        // add process to process array
        wmem_array_append_one(process_arr, process_info);
    }

    // traverse process array backwards and build process lineage description string
    for (i = arr_len - 1; i >= 0; i--) {
        process_info_ptr = (struct process_info *)wmem_array_index(process_arr, i);

        // first iteration - initialize description string
        if (prev_pid == 0)
            process_lineage_desc = wmem_strdup_printf(wmem_packet_scope(), "%d", process_info_ptr->ppid);
        
        // make sure the ppid of this process is the pid of the last process
        else {
            if (process_info_ptr->ppid != prev_pid) {
                process_lineage_intact = FALSE;
                break;
            }
        }
        prev_pid = process_info_ptr->pid;

        // add this process to the process lineage description
        process_lineage_desc = wmem_strdup_printf(wmem_packet_scope(), "%s -> %d", process_lineage_desc, process_info_ptr->pid);
        if (strlen(process_info_ptr->name) > 0)
            process_lineage_desc = wmem_strdup_printf(wmem_packet_scope(), "%s (%s)", process_lineage_desc, process_info_ptr->name);
    }

    // process lineage intact - add description to process lineage item
    if (process_lineage_intact && process_lineage_desc != NULL)
        proto_item_append_text(process_lineage_item, ": %s", process_lineage_desc);
    // process lineage not intact
    else if (!process_lineage_intact)
        proto_item_append_text(process_lineage_item, ": (not intact!)");
    // no description (empty process lineage)
    else
        proto_item_append_text(process_lineage_item, ": %d entries", arr_len);
}

/**
 * Callback function for dissecting a complex arg type.
 * 
 * Arguments:
 * 
 * tvbuff_t *tvb
 * packet_info *pinfo
 * proto_tree *tree
 * hf_register_info *hf - field registration structure representing the complex argument
 * gchar *json_data
 * jsmntok_t *arg_tok - JSON token of the complex argument
 * 
 * Returns the string representation of the argument (for display in the info column)
 */
typedef gchar * (*complex_arg_dissector_t) (tvbuff_t*, proto_tree*, hf_register_info*, gchar*, jsmntok_t*);

/**
 * Dissect a complex argument of type "unknown".
 * Not to be confused with unknown argument types.
 */
static gchar *dissect_unknown_arg(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    proto_item *tmp_item;
    gchar *arg_str = NULL;

    if (strcmp(hf->hfinfo.name, "Process lineage") == 0)
        dissect_process_lineage(tvb, tree, json_data, arg_tok);
    else {
        ws_info("cannot dissect arg \"%s\" of type \"unknown\"", hf->hfinfo.name);
        tmp_item = proto_tree_add_item(tree, *(hf->p_id), tvb, 0, 0, ENC_NA);
        proto_item_append_text(tmp_item, " (unsupported type \"unknown\")");
    }
    
    return arg_str;
}

static gchar *dissect_string_array(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    wmem_array_t *arr;
    int i, len;
    gchar *str = NULL;

    // change field type to string, as it was registered as FT_NONE
    hf->hfinfo.type = FT_STRINGZ;

    if ((arr = add_string_array(tvb, tree, *(hf->p_id), hf->hfinfo.name, hf->hfinfo.name, json_data, arg_tok, "value", TRUE)) != NULL) {
        // argv array - add a field that displays all arguments together
        len = wmem_array_get_count(arr);
        if (strcmp(hf->hfinfo.name, "argv") == 0) {
            for (i = 0; i < len; i++) {
                if (str == NULL)
                    str = wmem_strdup(wmem_packet_scope(), *(gchar **)wmem_array_index(arr, i));
                else
                    str = wmem_strdup_printf(wmem_packet_scope(), "%s %s", str, *(gchar **)wmem_array_index(arr, i));
            }
            proto_tree_add_string_wanted(tree, hf_args_command_line, tvb, 0, 0, str);
        }
    }

    return str;
}

static gchar *dissect_sockaddr(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_sockaddr);
}

static gchar *dissect_slim_cred_t(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_slim_cred_t);
}

static gchar *dissect_pktmeta(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_pktmeta);
}

static gchar *dissect_dns_query_data(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_array_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_dns_query_data);
}

static gchar *dissect_dns_response_data(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_array_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_dns_response_data);
}

static gchar *dissect_proto_http_request(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_proto_http_request);
}

static gchar *dissect_packet_metadata(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_packet_metadata);
}

static gchar *dissect_proto_http(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_proto_http);
}

static gchar *dissect_hooked_symbol_data_map(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    proto_item *symbols_item, *entry_item;
    proto_tree *symbols_tree, *entry_tree;
    jsmntok_t *obj_tok, *curr_entry_tok, *curr_symbol_data_tok;
    int i;
    gchar *entry_name, *symbol_data_str, *arg_str = NULL;

    // add hooked symbols tree
    symbols_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(symbols_item, "%s", hf->hfinfo.name);
    symbols_tree = proto_item_add_subtree(symbols_item, ett_hooked_symbols_map);

    // iterate through objects under the main argument object
    DISSECTOR_ASSERT((obj_tok = json_get_object(json_data, arg_tok, "value")) != NULL);
    curr_entry_tok = obj_tok + 1;
    for (i = 0; i < obj_tok->size; i++, curr_entry_tok = json_get_next_object(curr_entry_tok)) {
        // get entry name
        json_data[curr_entry_tok->end] = '\0';
        entry_name = &json_data[curr_entry_tok->start];
        DISSECTOR_ASSERT(json_decode_string_inplace(entry_name));

        // get entry object
        curr_symbol_data_tok = curr_entry_tok + 1;
        DISSECTOR_ASSERT(curr_symbol_data_tok->type == JSMN_OBJECT);

        // create entry tree
        entry_item = proto_tree_add_item(symbols_tree, hf_hooked_symbol_entry, tvb, 0, 0, ENC_NA);
        proto_item_set_text(entry_item, "%s", entry_name);
        entry_tree = proto_item_add_subtree(entry_item, ett_hooked_symbols_map);

        // dissect entry
        symbol_data_str = do_dissect_hooked_symbol_data(tvb, entry_tree, json_data, curr_symbol_data_tok);

        // add entry str to argument str
        if (symbol_data_str != NULL) {
            if (arg_str != NULL)
                arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s, %s: {%s}", arg_str, entry_name, symbol_data_str);
            else
                arg_str = wmem_strdup_printf(wmem_packet_scope(), "{%s: {%s}", entry_name, symbol_data_str);
        }
    }

    // finalize argument str
    if (arg_str != NULL)
        arg_str = wmem_strdup_printf(wmem_packet_scope(), "%s}", arg_str);

    proto_item_append_text(symbols_item, ": %d item%s", i, i == 1 ? "" : "s");

    return arg_str;
}

static gchar *dissect_hooked_symbol_data_arr(tvbuff_t *tvb, proto_tree *tree,
    hf_register_info *hf, gchar *json_data, jsmntok_t *arg_tok)
{
    return dissect_object_array_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, do_dissect_hooked_symbol_data);
}

static void dissect_triggered_by(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    gchar *json_data, jsmntok_t *arg_tok, const gchar *event_name)
{
    proto_item *triggered_by_item;
    proto_tree *triggered_by_tree;
    jsmntok_t *triggered_by_tok;
    gint64 tmp_int;
    gchar *tmp_str;

    // create triggered by subtree
    triggered_by_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(triggered_by_item, "Triggered By");
    triggered_by_tree = proto_item_add_subtree(triggered_by_item, ett_triggered_by);

    // get triggered by object
    DISSECTOR_ASSERT((triggered_by_tok = json_get_object(json_data, arg_tok, "value")) != NULL);

    // add id
    if (!json_get_int(json_data, triggered_by_tok, "id", &tmp_int)) {
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, triggered_by_tok, "id")) != NULL);
        errno = 0;
        tmp_int = strtoll(tmp_str, NULL, 10);
        DISSECTOR_ASSERT(errno == 0);
    }
    proto_tree_add_int64(triggered_by_tree, hf_tiggered_by_id, tvb, 0, 0, tmp_int);

    // add name
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, triggered_by_tok, "name")) != NULL);
    proto_tree_add_string(triggered_by_tree, hf_tiggered_by_name, tvb, 0, 0, tmp_str);
    if (strlen(tmp_str) > 0)
        proto_item_append_text(triggered_by_item, ": %s", tmp_str);

    // add return value
    DISSECTOR_ASSERT(json_get_int(json_data, triggered_by_tok, "returnValue", &tmp_int));
    proto_tree_add_int64(triggered_by_tree, hf_tiggered_by_return_value, tvb, 0, 0, tmp_int);

    // add args
    dissect_arguments(tvb, pinfo, triggered_by_tree, json_data, triggered_by_tok,
        wmem_strdup_printf(wmem_packet_scope(), "%s.triggered_by", event_name), FALSE);
}

static void dissect_arguments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gchar *json_data, jsmntok_t *root_tok, const gchar *event_name, gboolean set_info)
{
    jsmntok_t *args_tok, *curr_arg;
    int nargs, i;
    proto_item *args_item;
    proto_tree *args_tree;
    hf_register_info *hf;
    gchar *arg_type, *arg_str;
    gint64 tmp_int;
    bool tmp_bool;
    complex_arg_dissector_t dissector;
    proto_item *tmp_item;
    const gchar *info_col;

    DISSECTOR_ASSERT((args_tok = json_get_array(json_data, root_tok, "args")) != NULL);

    args_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(args_item, "Args");
    args_tree = proto_item_add_subtree(args_item, ett_args);

    if ((nargs = json_get_array_len(args_tok)) == 0)
        proto_item_append_text(args_item, " (none)");

    // go through all arguments
    for (i = 0; i < nargs; i++) {
        DISSECTOR_ASSERT((curr_arg = json_get_array_index(args_tok, i)) != NULL);
        DISSECTOR_ASSERT((arg_type = json_get_string(json_data, curr_arg, "type")) != NULL);
        arg_str = NULL;

        // get hf for this argument
        hf = get_arg_hf(event_name, json_data, curr_arg);

        // special case of trggieredBy argument which will recursively
        // call back into dissect_arguments (needs extra parameters)
        if (strcmp(arg_type, "unknown") == 0 && strcmp(hf->hfinfo.name, "triggeredBy") == 0)
            dissect_triggered_by(tvb, tree, pinfo, json_data, curr_arg, event_name);

        // try dissecting this as a complex arg
        else if ((dissector = wmem_map_lookup(complex_type_dissectors, arg_type)) != NULL)
            arg_str = dissector(tvb, args_tree, hf, json_data, curr_arg);

        // parse value according to type
        else {
            switch (hf->hfinfo.type) {
                // small signed integer types
                case FT_INT8:
                case FT_INT16:
                case FT_INT32:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &tmp_int));
                    proto_tree_add_int_wanted(args_tree, *(hf->p_id), tvb, 0, 0, (gint32)tmp_int);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%d", (gint32)tmp_int);
                    break;
                
                // small unsigned integer types
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT32:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &tmp_int));
                    proto_tree_add_uint_wanted(args_tree, *(hf->p_id), tvb, 0, 0, (guint32)tmp_int);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%u", (guint32)tmp_int);
                    break;
                
                // large signed integer
                case FT_INT64:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &tmp_int));
                    proto_tree_add_int64_wanted(args_tree, *(hf->p_id), tvb, 0, 0, tmp_int);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%" PRId64 , tmp_int);
                    break;
                
                // large unsigned integer
                case FT_UINT64:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &tmp_int));
                    proto_tree_add_uint64_wanted(args_tree, *(hf->p_id), tvb, 0, 0, (guint64)tmp_int);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%" PRIu64 , (guint64)tmp_int);
                    break;
                
                // boolean
                case FT_BOOLEAN:
                    DISSECTOR_ASSERT(json_get_boolean(json_data, curr_arg, "value", &tmp_bool));
                    proto_tree_add_boolean_wanted(args_tree, *(hf->p_id), tvb, 0, 0, (guint32)tmp_bool);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%s", tmp_bool ? "true" : "false");
                    break;
                
                // string
                case FT_STRINGZ:
                    // try reading a string
                    if ((arg_str = json_get_string(json_data, curr_arg, "value")) == NULL) {
                        // not a string - try reading a null
                        if (json_get_null(json_data, curr_arg, "value"))
                            arg_str = "null";
                        
                        // not a null - try reading a false
                        else if (json_get_boolean(json_data, curr_arg, "value", &tmp_bool)) {
                            DISSECTOR_ASSERT(tmp_bool == false);
                            arg_str = "false";
                        }
                        // not a boolean - try getting an int (this is a special case for arguments
                        // that are supposed to be strings but are sometimes integers)
                        else {
                            DISSECTOR_ASSERT(json_get_int(json_data, curr_arg, "value", &tmp_int));
                            arg_str = wmem_strdup_printf(pinfo->pool, "%" PRId64, tmp_int);
                        }
                    }
                    proto_tree_add_string_wanted(args_tree, *(hf->p_id), tvb, 0, 0, arg_str);
                    break;
                
                // unsupported or unknown types
                case FT_NONE:
                    ws_info("cannot dissect arg \"%s\" of unsupported type \"%s\"",
                        hf->hfinfo.name, arg_type);
                    tmp_item = proto_tree_add_item(args_tree, *(hf->p_id), tvb, 0, 0, ENC_NA);
                    proto_item_append_text(tmp_item, " (unsupported type \"%s\")", arg_type);
                    break;
                
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
            }
        }

        // add argument to info column
        if (arg_str != NULL && set_info) {
            if ((info_col = col_get_text(pinfo->cinfo, COL_INFO)) != NULL && strlen(info_col) > 0)
                col_append_str(pinfo->cinfo, COL_INFO, ", ");
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %s", hf->hfinfo.name, arg_str);
        }
    }
}

static gchar *dissect_metadata_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok)
{
    jsmntok_t *metadata_tok, *properties_tok;
    proto_item *metadata_item;
    proto_tree *metadata_tree, *properties_tree;
    gchar *signature_name, *tmp_str;
    gint64 tmp_int;

    if ((metadata_tok = json_get_object(json_data, root_tok, "metadata")) == NULL)
        return NULL;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACEE/SIG");

    metadata_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(metadata_item, "Metadata");
    metadata_tree = proto_item_add_subtree(metadata_item, ett_metadata);

    // add version
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, metadata_tok, "Version")) != NULL);
    proto_tree_add_string(metadata_tree, hf_metadata_version, tvb, 0, 0, tmp_str);
    
    // add description
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, metadata_tok, "Description")) != NULL);
    proto_tree_add_string(metadata_tree, hf_metadata_description, tvb, 0, 0, tmp_str);

    DISSECTOR_ASSERT((properties_tok = json_get_object(json_data, metadata_tok, "Properties")) != NULL);

    properties_tree = proto_tree_add_subtree(metadata_tree, tvb, 0, 0, ett_metadata_properties, NULL, "Properties");

    // add category
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "Category")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_category, tvb, 0, 0, tmp_str);

    // add kubernetes technique
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "Kubernetes_Technique")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_kubernetes_technique, tvb, 0, 0, tmp_str);

    // add severity
    DISSECTOR_ASSERT((json_get_int(json_data, properties_tok, "Severity", &tmp_int)));
    proto_tree_add_int(properties_tree, hf_metadata_properties_severity, tvb, 0, 0, (gint32)tmp_int);

    // add technique
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "Technique")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_technique, tvb, 0, 0, tmp_str);

    // add aggregation keys
    add_string_array(tvb, properties_tree, hf_metadata_properties_aggregation_keys, "Aggregation Keys",
        "aggregation_keys", json_data, properties_tok, "aggregation_keys", FALSE);

    // add external ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "external_id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_external_id, tvb, 0, 0, tmp_str);

    // add ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_id, tvb, 0, 0, tmp_str);

    // add release
    if ((tmp_str = json_get_string(json_data, properties_tok, "release")) != NULL)
        proto_tree_add_string(properties_tree, hf_metadata_properties_release, tvb, 0, 0, tmp_str);

    // add signature ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "signatureID")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_id, tvb, 0, 0, tmp_str);

    // add signature name
    DISSECTOR_ASSERT((signature_name = json_get_string(json_data, properties_tok, "signatureName")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_name, tvb, 0, 0, signature_name);

    return signature_name;
}

static void dissect_event_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, gchar *json_data)
{
    int num_toks;
    jsmntok_t *root_tok;
    gint64 event_id, tmp_int;
    nstime_t timestamp;
    gchar *event_name, *syscall, *signature_name, *tmp_str;
    proto_item *tmp_item;
    gboolean is_signature;

    num_toks = json_parse(json_data, NULL, 0);
    DISSECTOR_ASSERT_HINT(num_toks > 0, "JSON decode error: non-positive num_toks");

    root_tok = wmem_alloc_array(pinfo->pool, jsmntok_t, num_toks);
    if (json_parse(json_data, root_tok, num_toks) <= 0)
        DISSECTOR_ASSERT_NOT_REACHED();
    
    // add timestamp
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "timestamp", &tmp_int));
    timestamp.secs = (guint64)tmp_int / 1000000000;
    timestamp.nsecs = (guint64)tmp_int % 1000000000;
    proto_tree_add_time(tree, hf_timestamp, tvb, 0, 0, &timestamp);

    // add event context
    dissect_event_context(tvb, pinfo, tree, json_data, root_tok);

    // add event ID
    if (!json_get_int(json_data, root_tok, "eventId", &event_id)) {
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_tok, "eventId")) != NULL);
        errno = 0;
        event_id = strtoll(tmp_str, NULL, 10);
        DISSECTOR_ASSERT(errno == 0);
    }
    proto_tree_add_int64(tree, hf_event_id, tvb, 0, 0, event_id);

    // add event name
    DISSECTOR_ASSERT((event_name = json_get_string(json_data, root_tok, "eventName")) != NULL && strlen(event_name) > 0);
    proto_tree_add_string_wanted(tree, hf_event_name, tvb, 0, 0, event_name);
    if (strlen(event_name) > 0)
        proto_item_append_text(item, ": %s", event_name);
    
    // check if event is a signature
    is_signature = FALSE;
    if (event_id >= START_SIGNATURE_ID && event_id <= MAX_SIGNATURE_ID)
        is_signature = TRUE;
    else if (strncmp(event_name, "sig_", 4) == 0)
        is_signature = TRUE;
    tmp_item = proto_tree_add_boolean(tree, hf_is_signature, tvb, 0, 0, is_signature);
    proto_item_set_generated(tmp_item);

    // add matched policies
    add_string_array(tvb, tree, hf_matched_policies, "Matched Policies",
        "matched_policies", json_data, root_tok, "matchedPolicies", FALSE);

    // add args num
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "argsNum", &tmp_int));
    proto_tree_add_int64(tree, hf_args_num, tvb, 0, 0, tmp_int);

    // add return value
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "returnValue", &tmp_int));
    proto_tree_add_int(tree, hf_return_value, tvb, 0, 0, (gint)tmp_int);

    // add syscall
    DISSECTOR_ASSERT((syscall = json_get_string(json_data, root_tok, "syscall")) != NULL);
    proto_tree_add_string(tree, hf_syscall, tvb, 0, 0, syscall);
    
    // add arguments
    dissect_arguments(tvb, pinfo, tree, json_data, root_tok, event_name, TRUE);

    // add signature metadata fields
    if ((signature_name = dissect_metadata_fields(tvb, pinfo, tree, json_data, root_tok)) != NULL)
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s. ", signature_name);
}

static int dissect_tracee_json(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *tracee_json_item;
    proto_tree *tracee_json_tree;
    guint len;
    gchar *json_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACEE");

    // create tracee tree
    tracee_json_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, -1, ENC_NA);
    tracee_json_tree = proto_item_add_subtree(tracee_json_item, ett_tracee);

    proto_item_set_text(tracee_json_tree, "Tracee Event (JSON)");

    // make sure this is a valid JSON
    len = tvb_captured_length(tvb);
    json_data = wmem_alloc(pinfo->pool, len + 1);
    tvb_memcpy(tvb, json_data, 0, len);
    json_data[len] = '\0';

    // dissect event fields
    dissect_event_fields(tvb, pinfo, tracee_json_tree, tracee_json_item, json_data);

    return tvb_captured_length(tvb);
}

static void add_supported_type(const gchar *type, complex_arg_dissector_t dissector)
{
    wmem_map_insert(complex_type_dissectors, wmem_strdup(wmem_epan_scope(), type), dissector);
}

static void add_unsupported_type(const gchar *type)
{
    wmem_map_insert(complex_type_dissectors, wmem_strdup(wmem_epan_scope(), type), NULL);
}

static void init_complex_types(void) {
    complex_type_dissectors = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    // add supported types
    add_supported_type("unknown", dissect_unknown_arg);
    add_supported_type("const char*const*", dissect_string_array);
    add_supported_type("const char**", dissect_string_array);
    add_supported_type("const char **", dissect_string_array);
    add_supported_type("struct sockaddr*", dissect_sockaddr);
    add_supported_type("slim_cred_t", dissect_slim_cred_t);
    add_supported_type("trace.PktMeta", dissect_pktmeta);
    add_supported_type("[]trace.DnsQueryData", dissect_dns_query_data);
    add_supported_type("trace.ProtoHTTPRequest", dissect_proto_http_request);
    add_supported_type("trace.PacketMetadata", dissect_packet_metadata);
    add_supported_type("trace.ProtoHTTP", dissect_proto_http);
    add_supported_type("map[string]trace.HookedSymbolData", dissect_hooked_symbol_data_map);
    add_supported_type("[]trace.HookedSymbolData", dissect_hooked_symbol_data_arr);
    add_supported_type("[]trace.DnsResponseData", dissect_dns_response_data);

    // add unsupported types (these are types that were encountered but aren't dissected yet)
    add_unsupported_type("trace.ProtoTCP");
    add_unsupported_type("trace.ProtoUDP");
    add_unsupported_type("struct file_operations *");
    add_unsupported_type("const struct iovec*");
    add_unsupported_type("trace.ProtoDNS");
    add_unsupported_type("struct stat*");
    add_unsupported_type("const struct timespec*");
    add_unsupported_type("struct utsname*");
    add_unsupported_type("struct rusage*");
    add_unsupported_type("struct linux_dirent*");
    add_unsupported_type("struct statfs*");
    add_unsupported_type("struct sysinfo*");
    add_unsupported_type("const struct sigaction*");
    add_unsupported_type("struct sigaction*");
    add_unsupported_type("struct robust_list_head*");
    add_unsupported_type("sigset_t*");
    add_unsupported_type("struct rlimit*");
    add_unsupported_type("fd_set*");
    add_unsupported_type("struct epoll_event*");
    add_unsupported_type("struct timespec*");
    add_unsupported_type("const sigset_t*");
    add_unsupported_type("struct msghdr*");
    add_unsupported_type("struct pollfd*");
    add_unsupported_type("const struct itimerspec*");
    add_unsupported_type("struct statx*");
    add_unsupported_type("const stack_t*");
    add_unsupported_type("struct itimerspec*");
    add_unsupported_type("struct itimerval*");
    add_unsupported_type("union bpf_attr*");
    add_unsupported_type("struct perf_event_attr*");
    add_unsupported_type("stack_t*");
    add_unsupported_type("cap_user_header_t");
    add_unsupported_type("const cap_user_data_t");
    add_unsupported_type("const clockid_t");
    add_unsupported_type("cap_user_data_t");
    add_unsupported_type("const struct rlimit64*");
    add_unsupported_type("struct rseq*");
    add_unsupported_type("int[2]");
    add_unsupported_type("struct linux_dirent64*");
    add_unsupported_type("struct rlimit64*");
    add_unsupported_type("struct timex*");
    add_unsupported_type("const void*");
    add_unsupported_type("trace.ProtoICMP");
    add_unsupported_type("struct timeval*");
    add_unsupported_type("struct siginfo*");
    add_unsupported_type("gid_t*");
    add_unsupported_type("struct clone_args*");
    add_unsupported_type("trace.ProtoIPv4");
    add_unsupported_type("trace.ProtoHTTPResponse");
    add_unsupported_type("struct mmsghdr*");
    add_unsupported_type("trace.ProtoICMPv6");
    add_unsupported_type("struct tms*");
}

void proto_register_tracee(void)
{
    static gint *ett[] = {
        &ett_tracee,
        &ett_context,
        &ett_container,
        &ett_k8s,
        &ett_metadata,
        &ett_metadata_properties,
        &ett_args,
        &ett_string_arr,
        &ett_process_lineage,
        &ett_process_lineage_process,
        &ett_triggered_by,
        &ett_arg_obj,
        &ett_arg_obj_arr,
        &ett_http_headers,
        &ett_hooked_symbols_map,
        &ett_dns_query_data
    };

    static hf_register_info hf[] = {
        { &hf_timestamp,
          { "Timestamp", "tracee.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_thread_start_time,
          { "Thread Start Time", "tracee.threadStartTime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_processor_id,
          { "Processor ID", "tracee.processorId",
            FT_INT64, BASE_DEC, NULL, 0,
            "Processor (CPU) ID", HFILL }
        },
        { &hf_cgroup_id,
          { "Cgroup ID", "tracee.cgroupId",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_process_id,
          { "Process ID", "tracee.processId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process ID (in PID namespace)", HFILL }
        },
        { &hf_thread_id,
          { "Thread ID", "tracee.threadId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Thread ID (in PID namespace)", HFILL }
        },
        { &hf_parent_process_id,
          { "Parent Process ID", "tracee.parentProcessId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Parent process ID (in PID namespace)", HFILL }
        },
        { &hf_host_process_id,
          { "Host Process ID", "tracee.hostProcessId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process ID (in root PID namespace, a.k.a host)", HFILL }
        },
        { &hf_pid_col,
          { "PID Column", "tracee.pid_col",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ppid_col,
          { "PPID Column", "tracee.ppid_col",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_host_thread_id,
          { "Host Thread ID", "tracee.hostThreadId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Thread ID (in root PID namespace, a.k.a host)", HFILL }
        },
        { &hf_host_parent_process_id,
          { "Host Parent Process ID", "tracee.hostParentProcessId",
            FT_INT32, BASE_DEC, NULL, 0,
            "Parent process ID (in root PID namespace, a.k.a host)", HFILL }
        },
        { &hf_user_id,
          { "User ID", "tracee.userId",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mount_namespace,
          { "Mount Namespace", "tracee.mountNamespace",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pid_namespace,
          { "PID Namespace", "tracee.pidNamespace",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_process_name,
          { "Process Name", "tracee.processName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_executable_path,
          { "Executable Path", "tracee.executable.path",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hostname,
          { "Hostname", "tracee.hostName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_container_id,
          { "Container ID", "tracee.container.id",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_container_name,
          { "Container Name", "tracee.container.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_container_image,
          { "Container Image", "tracee.container.image",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_container_image_digest,
          { "Container Image Digest", "tracee.container.imageDigest",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_is_container,
          { "Is Container", "tracee.isContainer",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "This event happened inside a container", HFILL }
        },
        { &hf_container_col,
          { "Container Column", "tracee.container_col",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_k8s_pod_name,
          { "Pod Name", "tracee.kubernetes.podName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_k8s_pod_namespace,
          { "Pod Namespace", "tracee.kubernetes.podNamespace",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_k8s_pod_uid,
          { "Pod UID", "tracee.kubernetes.podUID",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_event_id,
          { "Event ID", "tracee.eventId",
            FT_INT64, BASE_DEC, NULL, 0,
            "Tracee event ID", HFILL }
        },
        { &hf_event_name,
          { "Event Name", "tracee.eventName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Tracee event name", HFILL }
        },
        { &hf_matched_policies,
          { "Matched Policies", "tracee.matchedPolicies",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Matched Tracee policies", HFILL }
        },
        { &hf_args_num,
          { "Args Num", "tracee.argsNum",
            FT_INT64, BASE_DEC, NULL, 0,
            "Number of arguments", HFILL }
        },
        { &hf_is_signature,
          { "Is Signature", "tracee.isSignature",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "This event is a signature", HFILL }
        },
        { &hf_return_value,
          { "Return Value", "tracee.returnValue",
            FT_INT32, BASE_DEC, NULL, 0,
            "Return value of the hooked function or syscall", HFILL }
        },
        { &hf_syscall,
          { "Syscall", "tracee.syscall",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Originating syscall", HFILL }
        },
        { &hf_thread_entity_id,
          { "Thread Entity ID", "tracee.threadEntityId",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_process_entity_id,
          { "Process Entity ID", "tracee.processEntityId",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_parent_entity_id,
          { "Parent Entity ID", "tracee.parentEntityId",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_args_command_line,
          { "Command Line", "tracee.args.command_line",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process arguments", HFILL }
        },
        { &hf_process_lineage_pid,
          { "PID", "tracee.process_lineage.pid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Process ID (in root PID namespace, a.k.a host)", HFILL }
        },
        { &hf_process_lineage_ppid,
          { "PPID", "tracee.process_lineage.ppid",
            FT_INT32, BASE_DEC, NULL, 0,
            "Parent process ID (in root PID namespace, a.k.a host)", HFILL }
        },
        { &hf_process_lineage_start_time,
          { "Start Time", "tracee.process_lineage.start_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_process_lineage_process_name,
          { "Process Name", "tracee.process_lineage.process_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_process_lineage_pathname,
          { "Pathname", "tracee.process_lineage.pathname",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process executable path", HFILL }
        },
        { &hf_process_lineage_sha256,
          { "SHA256", "tracee.process_lineage.sha256",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "SHA256 hash of the process executable", HFILL }
        },
        { &hf_process_lineage_command,
          { "Command", "tracee.process_lineage.command",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Process command line", HFILL }
        },
        { &hf_tiggered_by_id,
          { "Event ID", "tracee.triggered_by.id",
            FT_INT64, BASE_DEC, NULL, 0,
            "ID of the event that triggered the signature", HFILL }
        },
        { &hf_tiggered_by_name,
          { "Event Name", "tracee.triggered_by.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Name of the event that triggered the signature", HFILL }
        },
        { &hf_tiggered_by_return_value,
          { "Return Value", "tracee.triggered_by.return_value",
            FT_INT64, BASE_DEC, NULL, 0,
            "Return value of the event that triggered the signature", HFILL }
        },
        { &hf_metadata_version,
          { "Version", "tracee.metadata.Version",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Signature version", HFILL }
        },
        { &hf_metadata_description,
          { "Description", "tracee.metadata.Description",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Signature description", HFILL }
        },
        { &hf_metadata_properties_category,
          { "Category", "tracee.metadata.Properties.Category",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Signature category", HFILL }
        },
        { &hf_metadata_properties_kubernetes_technique,
          { "Kubernetes Technique", "tracee.metadata.Properties.Kubernetes_Technique",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_severity,
          { "Severity", "tracee.metadata.Properties.Severity",
            FT_INT32, BASE_DEC, NULL, 0,
            "Severity of the signature (0 is lowest, 4 is highest)", HFILL }
        },
        { &hf_metadata_properties_technique,
          { "Technique", "tracee.metadata.Properties.Technique",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_aggregation_keys,
          { "Aggregation Keys", "tracee.metadata.Properties.aggregation_keys",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_external_id,
          { "External ID", "tracee.metadata.Properties.external_id",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "External technique ID (e.g. MITRE)", HFILL }
        },
        { &hf_metadata_properties_id,
          { "Unified External ID", "tracee.metadata.Properties.id",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_release,
          { "Release", "tracee.metadata.Properties.release",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_signature_id,
          { "Internal ID", "tracee.metadata.Properties.signatureID",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_metadata_properties_signature_name,
          { "Signature Name", "tracee.metadata.Properties.signatureName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    // dynamic fields needed by builtin filters
    static hf_register_info filter_hf[] = {
        { &hf_ptrace_request,
          { "request", "tracee.args.request",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    static hf_register_info network_hf[] = {
        { &hf_ip_addr,
          { "ip.addr", "ip.addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ip_src,
          { "ip.src", "ip.src",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ip_dst,
          { "ip.dst", "ip.dst",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ipv6_addr,
          { "ipv6.addr", "ipv6.addr",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ipv6_src,
          { "ipv6.src", "ipv6.src",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ipv6_dst,
          { "ipv6.dst", "ipv6.dst",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ip_proto,
          { "ip.proto", "ip.proto",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_tcp_port,
          { "tcp.port", "tcp.port",
            FT_UINT16, BASE_PT_TCP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_tcp_srcport,
          { "tcp.srcport", "tcp.srcport",
            FT_UINT16, BASE_PT_TCP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_tcp_dstport,
          { "tcp.dstport", "tcp.dstport",
            FT_UINT16, BASE_PT_TCP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_udp_port,
          { "udp.port", "udp.port",
            FT_UINT16, BASE_PT_UDP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_udp_srcport,
          { "udp.srcport", "udp.srcport",
            FT_UINT16, BASE_PT_UDP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_udp_dstport,
          { "udp.dstport", "udp.dstport",
            FT_UINT16, BASE_PT_UDP, NULL, 0,
            NULL, HFILL }
        },
        { &hf_dns_qry_name,
          { "dns.qry.name", "dns.qry.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_dns_resp_ttl,
          { "dns.resp.ttl", "dns.resp.ttl",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_dns_resp_name,
          { "dns.resp.name", "dns.resp.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_request,
          { "http.request", "http.request",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_response,
          { "http.response", "http.response",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_request_method,
          { "http.request.method", "http.request.method",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_request_version,
          { "http.request.version", "http.request.version",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_response_version,
          { "http.response.version", "http.response.version",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_response_code,
          { "http.response.code", "http.response.code",
            FT_UINT24, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_response_code_desc,
          { "http.response.code.desc", "http.response.code.desc",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_response_phrase,
          { "http.response.phrase", "http.response.phrase",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_host,
          { "http.host", "http.host",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_request_uri,
          { "http.request.uri", "http.request.uri",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_content_length,
          { "http.content_length", "http.content_length",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_request_line,
          { "http.request.line", "http.request.line",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_accept,
          { "http.accept", "http.accept",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_user_agent,
          { "http.user_agent", "http.user_agent",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_referer,
          { "http.referer", "http.referer",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_cookie,
          { "http.cookie", "http.cookie",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_content_type,
          { "http.content_type", "http.content_type",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_connection,
          { "http.connection", "http.connection",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_accept_language,
          { "http.accept_language", "http.accept_language",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_accept_encoding,
          { "http.accept_encoding", "http.accept_encoding",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_content_length_header,
          { "http.content_length_header", "http.content_length_header",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_http_upgrade,
          { "http.upgrade", "http.upgrade",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    static hf_register_info sockaddr_hf[] = {
        { &hf_sockaddr_sa_family,
          { "sa_family", "tracee.sockaddr.sa_family",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket family", HFILL }
        },
        { &hf_sockaddr_sun_path,
          { "sun_path", "tracee.sockaddr.sun_path",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Unix socket path", HFILL }
        },
        { &hf_sockaddr_sin_addr,
          { "sin_addr", "tracee.sockaddr.sin_addr",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket IPv4 address", HFILL }
        },
        { &hf_sockaddr_sin_port,
          { "sin_port", "tracee.sockaddr.sin_port",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket TCP/UDP port", HFILL }
        },
        { &hf_sockaddr_sin6_addr,
          { "sin6_addr", "tracee.sockaddr.sin6_addr",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket IPv6 address", HFILL }
        },
        { &hf_sockaddr_sin6_port,
          { "sin6_port", "tracee.sockaddr.sin6_port",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket TCP/UDP port", HFILL }
        },
        { &hf_sockaddr_sin6_flowinfo,
          { "sin6_flowinfo", "tracee.sockaddr.sin6_flowinfo",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket IPv6 flow info", HFILL }
        },
        { &hf_sockaddr_sin6_scopeid,
          { "sin6_scopeid", "tracee.sockaddr.sin6_scopeid",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Socket IPv6 scope id (new in RFC2553)", HFILL }
        }
    };

    static hf_register_info slim_cred_t_hf[] = {
        { &hf_slim_cred_t_uid,
          { "UID", "tracee.slim_cred_t.uid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Real user ID", HFILL }
        },
        { &hf_slim_cred_t_gid,
          { "GID", "tracee.slim_cred_t.gid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Real group ID", HFILL }
        },
        { &hf_slim_cred_t_suid,
          { "SUID", "tracee.slim_cred_t.suid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Saved user ID", HFILL }
        },
        { &hf_slim_cred_t_sgid,
          { "SGID", "tracee.slim_cred_t.sgid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Saved group ID", HFILL }
        },
        { &hf_slim_cred_t_euid,
          { "EUID", "tracee.slim_cred_t.euid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Effective user ID", HFILL }
        },
        { &hf_slim_cred_t_egid,
          { "EGID", "tracee.slim_cred_t.egid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Effective group ID", HFILL }
        },
        { &hf_slim_cred_t_fsuid,
          { "FSUID", "tracee.slim_cred_t.fsuid",
            FT_INT64, BASE_DEC, NULL, 0,
            "User ID for VFS operations", HFILL }
        },
        { &hf_slim_cred_t_fsgid,
          { "FSGID", "tracee.slim_cred_t.fsgid",
            FT_INT64, BASE_DEC, NULL, 0,
            "Group ID for VFS operations", HFILL }
        },
        { &hf_slim_cred_t_user_namespace,
          { "User Namespace", "tracee.slim_cred_t.user_namespace",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_slim_cred_t_secure_bits,
          { "Secure Bits", "tracee.slim_cred_t.secure_bits",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_slim_cred_t_cap_inheritable,
          { "CapInh", "tracee.slim_cred_t.cap_inheritable",
            FT_INT64, BASE_DEC, NULL, 0,
            "Inheritable capabilities", HFILL }
        },
        { &hf_slim_cred_t_cap_permitted,
          { "CapPrm", "tracee.slim_cred_t.cap_permitted",
            FT_INT64, BASE_DEC, NULL, 0,
            "Permitted capabilities", HFILL }
        },
        { &hf_slim_cred_t_cap_effective,
          { "CapEff", "tracee.slim_cred_t.cap_effective",
            FT_INT64, BASE_DEC, NULL, 0,
            "Effective capabilities", HFILL }
        },
        { &hf_slim_cred_t_cap_bounding,
          { "CapBnd", "tracee.slim_cred_t.cap_bounding",
            FT_INT64, BASE_DEC, NULL, 0,
            "Bounding capabilities", HFILL }
        },
        { &hf_slim_cred_t_cap_ambient,
          { "CapAmb", "tracee.slim_cred_t.cap_ambient",
            FT_INT64, BASE_DEC, NULL, 0,
            "Ambient capabilities", HFILL }
        }
    };

    static hf_register_info pktmeta_hf[] = {
        { &hf_pktmeta_src_ip,
          { "Src IP", "tracee.pktmeta.src_ip",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Source IP", HFILL }
        },
        { &hf_pktmeta_dst_ip,
          { "Dst IP", "tracee.pktmeta.dst_ip",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Destination IP", HFILL }
        },
        { &hf_pktmeta_src_port,
          { "Src Port", "tracee.pktmeta.src_port",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Source port", HFILL }
        },
        { &hf_pktmeta_dst_port,
          { "Dst Port", "tracee.pktmeta.dst_port",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Destination port", HFILL }
        },
        { &hf_pktmeta_protocol,
          { "Protocol", "tracee.pktmeta.protocol",
            FT_UINT32, BASE_DEC, VALS(ipproto_val), 0,
            "IP protocol", HFILL }
        },
        { &hf_pktmeta_packet_len,
          { "Len", "tracee.pktmeta.packet_len",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Packet length", HFILL }
        },
        { &hf_pktmeta_iface,
          { "Iface", "tracee.pktmeta.iface",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Interface", HFILL }
        },
    };

    static hf_register_info dns_hf[] = {
        { &hf_dnsquery_query,
          { "Query", "tracee.dnsquery.query",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "DNS query", HFILL }
        },
        { &hf_dnsquery_type,
          { "Type", "tracee.dnsquery.type",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "DNS query type", HFILL }
        },
        { &hf_dnsquery_class,
          { "Class", "tracee.dnsquery.class",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "DNS query class", HFILL }
        },
        { &hf_dnsanswer_type,
          { "Type", "tracee.dnsanswer.type",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "DNS answer type", HFILL }
        },
        { &hf_dnsanswer_ttl,
          { "TTL", "tracee.dnsanswer.ttl",
            FT_UINT32, BASE_DEC, NULL, 0,
            "DNS answer TTL", HFILL }
        },
        { &hf_dnsanswer_answer,
          { "Answer", "tracee.dnsanswer.answer",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "DNS answer", HFILL }
        },
    };

    static hf_register_info proto_http_request_hf[] = {
        { &hf_proto_http_request_method,
          { "Method", "tracee.proto_http_request.method",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP method", HFILL }
        },
        { &hf_proto_http_request_protocol,
          { "Protocol", "tracee.proto_http_request.protocol",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP protocol version", HFILL }
        },
        { &hf_proto_http_request_host,
          { "Host", "tracee.proto_http_request.host",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP host", HFILL }
        },
        { &hf_proto_http_request_uri_path,
          { "URI Path", "tracee.proto_http_request.uri_path",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP URI path", HFILL }
        },
        { &hf_proto_http_request_header,
          { "Header", "tracee.proto_http_request.header",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP header", HFILL }
        },
        { &hf_proto_http_request_content_length,
          { "Content Length", "tracee.proto_http_request.content_length",
            FT_INT64, BASE_DEC, NULL, 0,
            "HTTP content length", HFILL }
        }
    };

    static hf_register_info packet_metadata_hf[] = {
        { &hf_packet_metadata_direction,
          { "Direction", "tracee.packet_metadata.direction",
            FT_INT32, BASE_DEC, VALS(packet_metadata_directions), 0,
            "Packet direction", HFILL }
        }
    };

    static hf_register_info proto_http_hf[] = {
        { &hf_proto_http_direction,
          { "Direction", "tracee.proto_http.direction",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP direction", HFILL }
        },
        { &hf_proto_http_method,
          { "Method", "tracee.proto_http.method",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP method", HFILL }
        },
        { &hf_proto_http_protocol,
          { "Protocol", "tracee.proto_http.protocol",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP protocol version", HFILL }
        },
        { &hf_proto_http_host,
          { "Host", "tracee.proto_http.host",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP host", HFILL }
        },
        { &hf_proto_http_uri_path,
          { "URI Path", "tracee.proto_http.uri_path",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP URI path", HFILL }
        },
        { &hf_proto_http_status,
          { "Status", "tracee.proto_http.status",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP status", HFILL }
        },
        { &hf_proto_http_status_code,
          { "Status Code", "tracee.proto_http.status_code",
            FT_INT32, BASE_DEC, NULL, 0,
            "HTTP status code", HFILL }
        },
        { &hf_proto_http_header,
          { "Header", "tracee.proto_http.header",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "HTTP header", HFILL }
        },
        { &hf_proto_http_content_length,
          { "Content Length", "tracee.proto_http.content_length",
            FT_INT64, BASE_DEC, NULL, 0,
            "HTTP content length", HFILL }
        }
    };

    static hf_register_info hooked_symbols_hf[] = {
        { &hf_hooked_symbol_entry,
          { "Entry", "tracee.hooked_symbols.entry",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Hooked symbol entry", HFILL }
        },
        { &hf_hooked_symbol_name,
          { "Name", "tracee.hooked_symbols.name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Hooked symbol name", HFILL }
        },
        { &hf_hooked_symbol_module_owner,
          { "Module Owner", "tracee.hooked_symbols.module_owner",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Hooked symbol module owner", HFILL }
        }
    };

    module_t *tracee_module;

    static const enum_val_t pid_format_vals[] = {
        {"container", "Show PID in container", PID_FORMAT_CONTAINER_ONLY},
        {"host", "Show PID on host", PID_FORMAT_HOST_ONLY},
        {"both", "Show both PID in container and on host", PID_FORMAT_BOTH},
        {NULL, NULL, -1}
    };

    static const enum_val_t container_identifier_vals[] = {
        {"id", "Container ID", CONTAINER_IDENTIFIER_ID},
        {"name", "Container name", CONTAINER_IDENTIFIER_NAME},
        {NULL, NULL, -1}
    };

    proto_tracee = proto_register_protocol("Tracee", "TRACEE", "tracee");
    proto_register_field_array(proto_tracee, hf, array_length(hf));
    proto_register_field_array(proto_tracee, filter_hf, array_length(filter_hf));
    proto_register_field_array(proto_tracee, network_hf, array_length(network_hf));
    proto_register_field_array(proto_tracee, sockaddr_hf, array_length(sockaddr_hf));
    proto_register_field_array(proto_tracee, slim_cred_t_hf, array_length(slim_cred_t_hf));
    proto_register_field_array(proto_tracee, pktmeta_hf, array_length(pktmeta_hf));
    proto_register_field_array(proto_tracee, dns_hf, array_length(dns_hf));
    proto_register_field_array(proto_tracee, proto_http_request_hf, array_length(proto_http_request_hf));
    proto_register_field_array(proto_tracee, packet_metadata_hf, array_length(packet_metadata_hf));
    proto_register_field_array(proto_tracee, proto_http_hf, array_length(proto_http_hf));
    proto_register_field_array(proto_tracee, hooked_symbols_hf, array_length(hooked_symbols_hf));
    proto_register_subtree_array(ett, array_length(ett));

    tracee_module = prefs_register_protocol(proto_tracee, NULL);

    prefs_register_enum_preference(tracee_module, "pid_format", "PID column format",
        "Whether to show only PID in container, only PID on host, or both",
        &pid_format, pid_format_vals, FALSE);

    prefs_register_enum_preference(tracee_module, "container_identifier", "Container identifier in column",
        "Whether to show container ID or name in the container column",
        &container_identifier, container_identifier_vals, FALSE);
    
    prefs_register_bool_preference(tracee_module, "container_image", "Show container image",
        "Whether to show the container image in the container column", &show_container_image);

    // initialize mapping of supported complex types and their dissection functions
    init_complex_types();

    // create dynamic field array map for event arguments
    // and register a callback to unregister the dynamic fields when the map is destroyed
    event_dynamic_hf_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_str_hash, g_str_equal);
    wmem_register_callback(wmem_file_scope(), dynamic_hf_map_destroy_cb, NULL);

    // register event name dissector table
    /*event_name_dissector_table = register_dissector_table("tracee.eventName",
        "Tracee event name", proto_tracee, FT_STRINGZ, FALSE);*/
    
    register_tracee_postdissectors(proto_tracee);
}

void proto_reg_handoff_tracee(void)
{
    static dissector_handle_t tracee_json_handle;

    tracee_json_handle = create_dissector_handle(dissect_tracee_json, proto_tracee);
    
    // register to encapsulation dissector table (we use a user-reserved encapsulation)
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, tracee_json_handle);
}

#ifdef WIRESHARK_PLUGIN_REGISTER // new plugin API
static void plugin_register(void)
#else
void plugin_register(void)
#endif
{
    static proto_plugin plugin;

    plugin.register_protoinfo = proto_register_tracee;
    plugin.register_handoff = proto_reg_handoff_tracee;
    proto_register_plugin(&plugin);
}

#ifdef WIRESHARK_PLUGIN_REGISTER // new plugin API
static struct ws_module module = {
    .flags = WS_PLUGIN_DESC_DISSECTOR,
    .version = PLUGIN_VERSION,
    .spdx_id = "GPL-2.0-or-later",
    .home_url = "",
    .blurb = "Tracee event dissector",
    .register_cb = &plugin_register,
};

WIRESHARK_PLUGIN_REGISTER_EPAN(&module, 0)
#endif

#ifdef WS_PLUGIN_DESC_DISSECTOR
uint32_t plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}
#endif