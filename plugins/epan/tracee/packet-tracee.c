#include "tracee.h"
#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>
#include <epan/ipproto.h>

static int proto_tracee = -1;

static dissector_table_t event_name_dissector_table;

static int hf_timestamp = -1;
static int hf_thread_start_time = -1;
static int hf_processor_id = -1;
static int hf_process_id = -1;
static int hf_cgroup_id = -1;
static int hf_thread_id = -1;
static int hf_parent_process_id = -1;
int hf_host_process_id = -1; // needs to be accessible by tracee network capture dissector
static int hf_pid_col = -1;
static int hf_tid_col = -1;
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
// KUBERNETES INFO
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
static int hf_args_argv = -1;
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

// network fields
/*static int hf_ip_addr = -1;
static int hf_ip_src = -1;
static int hf_ip_dst = -1;
static int hf_ipproto = -1;
static int hf_*/

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
static gint ett_tracee = -1;
static gint ett_container = -1;
static gint ett_metadata = -1;
static gint ett_metadata_properties = -1;
static gint ett_args = -1;
static gint ett_string_arr = -1;
static gint ett_process_lineage = -1;
static gint ett_process_lineage_process = -1;
static gint ett_triggered_by = -1;
static gint ett_arg_obj = -1;

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

static proto_item *dissect_arguments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok, const gchar *event_name);

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

static bool dynamic_hf_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(event_dynamic_hf_map, free_dynamic_hf, NULL);

    // return TRUE so this callback isn't unregistered
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
        container_col_str = wmem_strndup(pinfo->pool, id, 12);

        if (image != NULL)
            container_col_str = wmem_strdup_printf(pinfo->pool, "%s (%s)", container_col_str, image);
        
        proto_tree_add_string(tree, hf_container_col, tvb, 0, 0, container_col_str);
    }
}

struct type_display {
    enum ftenum type;
    int display;
    const void *format_cb;
};

static gchar *normalize_arg_name(const gchar *name)
{
    GString *new_name;

    // replace spaces with underscores
    DISSECTOR_ASSERT((new_name = g_string_new(name)) != NULL);
    g_string_replace(new_name, " ", "_", 0);

    return g_string_free(new_name, FALSE);
}

/**
 * Determine the field type and display based on the type string.
 */
static void get_arg_field_type_display(const gchar *type, struct type_display *info)
{
    info->format_cb = NULL;

    // string
    if (strcmp(type, "const char *")        == 0 ||
        strcmp(type, "const char*")         == 0 ||
        strcmp(type, "string")              == 0 ||
        strcmp(type, "char*")               == 0 ||
        strcmp(type, "bytes")               == 0 ||
        strcmp(type, "void*")               == 0 ||
        strcmp(type, "const char*const*")   == 0 ||
        strcmp(type, "const char**")        == 0 ||
        strcmp(type, "int*")                == 0) {
        
        info->type = FT_STRINGZ;
        info->display = BASE_NONE;
    }

    // bool
    else if (strcmp(type, "bool") == 0) {
        info->type = FT_BOOLEAN;
        info->display = BASE_NONE;
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
             strcmp(type, "unsigned int")   == 0) {
        
        info->type = FT_UINT32;
        info->display = BASE_DEC;
    }

    // s64
    else if (strcmp(type, "long") == 0) {
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

    // complex types
    else if (strcmp(type, "unknown")                            == 0 ||
             strcmp(type, "struct sockaddr*")                   == 0 ||
             strcmp(type, "slim_cred_t")                        == 0 ||
             strcmp(type, "map[string]trace.HookedSymbolData")  == 0 ||
             strcmp(type, "trace.PktMeta")                      == 0 ||
             strcmp(type, "[]trace.DnsResponseData")            == 0 ||
             strcmp(type, "[]trace.DnsQueryData")               == 0 ||
             strcmp(type, "trace.ProtoHTTPRequest")             == 0 ||
             strcmp(type, "trace.ProtoTCP")                     == 0 ||
             strcmp(type, "trace.ProtoHTTP")                    == 0 ||
             strcmp(type, "trace.ProtoUDP")                     == 0 ||
             strcmp(type, "[]trace.HookedSymbolData")           == 0 ||
             strcmp(type, "struct file_operations *")           == 0 ||
             strcmp(type, "const struct iovec*")                == 0 ||
             strcmp(type, "trace.ProtoDNS")                     == 0) {
        
        info->type = FT_NONE;
        info->display = BASE_NONE;
    }

    else {
        ws_warning("unknown type \"%s\"", type);
        DISSECTOR_ASSERT_NOT_REACHED();
    }
}

static void dynamic_hf_populate_arg_field(hf_register_info *hf, const gchar *name, const gchar *type)
{
    gchar *name_normalized;
    struct type_display info;

    hf->p_id = wmem_new(wmem_file_scope(), int);
    *(hf->p_id) = -1;

    hf->hfinfo.name = g_strdup(name);
    name_normalized = normalize_arg_name(name);
    hf->hfinfo.abbrev = g_strdup_printf("tracee.args.%s", name_normalized);
    g_free(name_normalized);

    get_arg_field_type_display(type, &info);

    hf->hfinfo.type = info.type;
    hf->hfinfo.display = info.display;
    hf->hfinfo.strings = info.format_cb;
    hf->hfinfo.bitmask = 0;
    hf->hfinfo.blurb = g_strdup(name);
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
    
    // create the hf and add it to the array
    hf = g_new0(hf_register_info, 1);
    g_ptr_array_add(dynamic_hf->hf_ptrs, hf);
    hf_idx = wmem_new(wmem_file_scope(), int);
    *hf_idx = dynamic_hf->hf_ptrs->len - 1;

    // populate the field info
    dynamic_hf_populate_arg_field(hf, arg_name, arg_type);

    // update arg name to idx map
    arg_name_copy = wmem_strdup(wmem_file_scope(), arg_name);
    wmem_map_insert(dynamic_hf->arg_idx_map, arg_name_copy, hf_idx);

    // register the added field with wireshark
    proto_register_field_array(proto_tracee, hf, 1);

    return hf;
}

static void dissect_string_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *arr_tree, int hf_id,
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
        json_data[(elem_tok)->end] = '\0';
        str = &json_data[elem_tok->start];
        DISSECTOR_ASSERT(json_decode_string_inplace(str));
        if (arr_data != NULL)
            wmem_array_append_one(arr_data, str);

        // add the value to the dissection tree
        tmp_item = proto_tree_add_string(arr_tree, hf_id, tvb, 0, 0, str);
        proto_item_set_text(tmp_item, "%s[%d]: %s", arr_name, i, proto_item_get_display_repr(pinfo->pool, tmp_item));
    }
}

static wmem_array_t *add_string_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hf_id, const gchar *item_name,
    const gchar *arr_name, gchar *json_data, jsmntok_t *parent_tok, const gchar *arr_tok_name, gboolean get_data)
{
    proto_item *arr_item;
    proto_tree *arr_tree;
    jsmntok_t *arr_tok;
    int arr_len;
    wmem_array_t *arr_data = NULL;

    // create the subtree
    arr_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(arr_item, "%s", item_name);
    arr_tree = proto_item_add_subtree(arr_item, ett_string_arr);

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
    else
        DISSECTOR_ASSERT_NOT_REACHED();
    
    if (get_data)
        arr_data = wmem_array_sized_new(pinfo->pool, sizeof(gchar *), arr_len);

    dissect_string_array(tvb, pinfo, arr_tree, hf_id, arr_name, json_data, arr_tok, arr_data);

    return arr_data;
}

static void dissect_process_lineage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *arg_tok)
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

    // create process lineage subtree
    process_lineage_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(process_lineage_item, "Process Lineage");
    process_lineage_tree = proto_item_add_subtree(process_lineage_item, ett_process_lineage);

    // get process lineage array
    if ((arr_tok = json_get_array(json_data, arg_tok, "value")) != NULL)
        DISSECTOR_ASSERT((arr_len = json_get_array_len(arr_tok)) >= 0);
    
    // not an array - try getting a null
    else if (json_get_null(json_data, arg_tok, "value")) {
        proto_item_append_text(process_lineage_item, ": (null)");
        return;
    }
    else
        DISSECTOR_ASSERT_NOT_REACHED();
    
    // save an array of processes in the process lineage
    process_arr = wmem_array_sized_new(pinfo->pool, sizeof(struct process_info), arr_len);
    
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
            process_lineage_desc = wmem_strdup_printf(pinfo->pool, "%d", process_info_ptr->ppid);
        
        // make sure the ppid of this process is the pid of the last process
        else {
            if (process_info_ptr->ppid != prev_pid) {
                process_lineage_intact = FALSE;
                break;
            }
        }
        prev_pid = process_info_ptr->pid;

        // add this process to the process lineage description
        process_lineage_desc = wmem_strdup_printf(pinfo->pool, "%s -> %d", process_lineage_desc, process_info_ptr->pid);
        if (strlen(process_info_ptr->name) > 0)
            process_lineage_desc = wmem_strdup_printf(pinfo->pool, "%s (%s)", process_lineage_desc, process_info_ptr->name);
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

static void dissect_triggered_by(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *arg_tok, const gchar *event_name)
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

    // add args
    dissect_arguments(tvb, pinfo, triggered_by_tree, json_data, triggered_by_tok, wmem_strdup_printf(pinfo->pool, "%s.triggered_by", event_name));

    // add id
    if (!json_get_int(json_data, triggered_by_tok, "id", &tmp_int)) {
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, triggered_by_tok, "id")) != NULL);
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
}

static void add_network_filter(tvbuff_t *tvb, proto_tree *tree, const gchar *filter)
{
    proto_item *item;
    int proto;

    DISSECTOR_ASSERT((proto = proto_get_id_by_filter_name(filter)) != -1);
    item = proto_tree_add_item(tree, proto, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(item);
}

typedef void (*object_dissector_t) (tvbuff_t*, proto_tree*, gchar*, jsmntok_t*);

static void dissect_object_arg(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *arg_tok, const gchar *arg_name, object_dissector_t dissector)
{
    proto_item *obj_item;
    proto_tree *obj_tree;
    jsmntok_t *obj_tok;

    // create object subtree
    obj_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(obj_item, "%s", arg_name);
    obj_tree = proto_item_add_subtree(obj_item, ett_arg_obj);

    // try getting object
    if ((obj_tok = json_get_object(json_data, arg_tok, "value")) == NULL) {
        // couldn't get object - try getting a null
        DISSECTOR_ASSERT(json_get_null(json_data, arg_tok, "value"));
        proto_item_append_text(obj_item, ": (null)");
        return;
    }

    // call dissector for this object
    dissector(tvb, obj_tree, json_data, obj_tok);
}

static void dissect_sockaddr(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gchar *tmp_str;

    // add sa_family
    if ((tmp_str = json_get_string(json_data, obj_tok, "sa_family")) != NULL) {
        proto_tree_add_string(tree, hf_sockaddr_sa_family, tvb, 0, 0, tmp_str);
        if (strcmp(tmp_str, "AF_INET") == 0)
            add_network_filter(tvb, tree, "ip");
        else if (strcmp(tmp_str, "AF_INET6") == 0)
            add_network_filter(tvb, tree, "ipv6");
    }
    
    // add sun_path
    if ((tmp_str = json_get_string(json_data, obj_tok, "sun_path")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sun_path, tvb, 0, 0, tmp_str);
    
    // add sin_addr
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin_addr")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin_addr, tvb, 0, 0, tmp_str);
    
    // add sin_port
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin_port")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin_port, tvb, 0, 0, tmp_str);
    
    // add sin6_addr
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_addr")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin6_addr, tvb, 0, 0, tmp_str);
    
    // add sin6_port
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_port")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin6_port, tvb, 0, 0, tmp_str);
    
    // add sin6_flowinfo
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_flowinfo")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin6_flowinfo, tvb, 0, 0, tmp_str);
    
    // add sin6_scopeid
    if ((tmp_str = json_get_string(json_data, obj_tok, "sin6_scopeid")) != NULL)
        proto_tree_add_string(tree, hf_sockaddr_sin6_scopeid, tvb, 0, 0, tmp_str);
}

static void dissect_slim_cred_t(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gint64 tmp_int;

    // add uid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Uid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_uid, tvb, 0, 0, tmp_int);

    // add gid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Gid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_gid, tvb, 0, 0, tmp_int);

    // add suid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Suid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_suid, tvb, 0, 0, tmp_int);

    // add sgid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Sgid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_sgid, tvb, 0, 0, tmp_int);

    // add euid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Euid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_euid, tvb, 0, 0, tmp_int);

    // add egid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Egid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_egid, tvb, 0, 0, tmp_int);

    // add fsuid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Fsuid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_fsuid, tvb, 0, 0, tmp_int);

    // add fsgid
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "Fsgid", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_fsgid, tvb, 0, 0, tmp_int);

    // add user namespace
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "UserNamespace", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_user_namespace, tvb, 0, 0, tmp_int);

    // add secure bits
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "SecureBits", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_secure_bits, tvb, 0, 0, tmp_int);

    // add capinh
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapInheritable", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_cap_inheritable, tvb, 0, 0, tmp_int);

    // add capprm
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapPermitted", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_cap_permitted, tvb, 0, 0, tmp_int);

    // add capeff
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapEffective", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_cap_effective, tvb, 0, 0, tmp_int);

    // add capbnd
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapBounding", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_cap_bounding, tvb, 0, 0, tmp_int);

    // add capamb
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "CapAmbient", &tmp_int));
    proto_tree_add_int64(tree, hf_slim_cred_t_cap_ambient, tvb, 0, 0, tmp_int);
}

static void dissect_pktmeta(tvbuff_t *tvb, proto_tree *tree, gchar *json_data, jsmntok_t *obj_tok)
{
    gint64 tmp_int;
    gchar *tmp_str;
    ws_in4_addr in4_addr;
    ws_in6_addr in6_addr;

    // add src ip
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "src_ip")) != NULL);
    proto_tree_add_string(tree, hf_pktmeta_src_ip, tvb, 0, 0, tmp_str);
    if (ws_inet_pton4(tmp_str, &in4_addr))
        add_network_filter(tvb, tree, "ip");
    else if (ws_inet_pton6(tmp_str, &in6_addr))
        add_network_filter(tvb, tree, "ipv6");
    
    // add dst ip
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "dst_ip")) != NULL);
    proto_tree_add_string(tree, hf_pktmeta_dst_ip, tvb, 0, 0, tmp_str);
    
    // add src port
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "src_port", &tmp_int));
    proto_tree_add_uint(tree, hf_pktmeta_src_port, tvb, 0, 0, (guint32)tmp_int);

    // add dst port
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "dst_port", &tmp_int));
    proto_tree_add_uint(tree, hf_pktmeta_dst_port, tvb, 0, 0, (guint32)tmp_int);

    // add protocol
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "protocol", &tmp_int));
    proto_tree_add_uint(tree, hf_pktmeta_protocol, tvb, 0, 0, (guint32)tmp_int);
    if (tmp_int == IP_PROTO_TCP)
        add_network_filter(tvb, tree, "tcp");
    else if (tmp_int == IP_PROTO_UDP)
        add_network_filter(tvb, tree, "udp");
    else if (tmp_int == IP_PROTO_ICMP)
        add_network_filter(tvb, tree, "icmp");
    else if (tmp_int == IP_PROTO_ICMPV6)
        add_network_filter(tvb, tree, "icmpv6");

    // add packet len
    DISSECTOR_ASSERT(json_get_int(json_data, obj_tok, "packet_len", &tmp_int));
    proto_tree_add_uint(tree, hf_pktmeta_packet_len, tvb, 0, 0, (guint32)tmp_int);

    // add iface
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, obj_tok, "iface")) != NULL);
    proto_tree_add_string(tree, hf_pktmeta_iface, tvb, 0, 0, tmp_str);
}

static gboolean dissect_complex_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, hf_register_info *hf,
    const gchar *arg_type, gchar *json_data, jsmntok_t *arg_tok, gchar **arg_str, const gchar *event_name)
{
    wmem_array_t *arr;
    int i, len;
    gchar *str = NULL;

    // string array
    if (strcmp(arg_type, "const char*const*")   == 0 ||
            strcmp(arg_type, "const char**")    == 0) {
        if ((arr = add_string_array(tvb, pinfo, tree, *(hf->p_id), hf->hfinfo.name, hf->hfinfo.name, json_data, arg_tok, "value", TRUE)) != NULL) {
            // argv array - add a field that displays all arguments together
            if (strcmp(hf->hfinfo.name, "argv") == 0) {
                len = wmem_array_get_count(arr);
                for (i = 0; i < len; i++) {
                    if (str == NULL)
                        str = wmem_strdup(pinfo->pool, *(gchar **)wmem_array_index(arr, i));
                    else
                        str = wmem_strdup_printf(pinfo->pool, "%s %s", str, *(gchar **)wmem_array_index(arr, i));
                }
                proto_tree_add_string(tree, hf_args_argv, tvb, 0, 0, str);
                *arg_str = str;
            }
        }
    }

    // process lineage
    else if (strcmp(arg_type, "unknown") == 0 && strcmp(hf->hfinfo.name, "Process lineage") == 0)
        dissect_process_lineage(tvb, pinfo, tree, json_data, arg_tok);
    
    // triggered by
    else if (strcmp(arg_type, "unknown") == 0 && strcmp(hf->hfinfo.name, "triggeredBy") == 0)
        dissect_triggered_by(tvb, pinfo, tree, json_data, arg_tok, event_name);
    
    // sockaddr
    else if (strcmp(arg_type, "struct sockaddr*") == 0)
        dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, dissect_sockaddr);
    
    // slim_cred_t
    else if (strcmp(arg_type, "slim_cred_t") == 0)
        dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, dissect_slim_cred_t);
    
    // trace.PktMeta
    else if (strcmp(arg_type, "trace.PktMeta") == 0)
        dissect_object_arg(tvb, tree, json_data, arg_tok, hf->hfinfo.name, dissect_pktmeta);

    else
        return FALSE;
    
    return TRUE;
}

static proto_item *dissect_arguments(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok, const gchar *event_name)
{
    jsmntok_t *args_tok, *curr_arg;
    int nargs, i;
    proto_item *args_item;
    proto_tree *args_tree;
    hf_register_info *hf;
    union {
        gint32 s32;
        guint32 u32;
        gint64 s64;
        guint64 u64;
        bool boolean;
        gchar *str;
    } val;
    gchar *arg_type, *arg_str;
    const gchar *info_col;
    proto_item *tmp_item;

    DISSECTOR_ASSERT((args_tok = json_get_array(json_data, root_tok, "args")) != NULL);
    DISSECTOR_ASSERT((nargs = json_get_array_len(args_tok)) > 0);

    args_item = proto_tree_add_item(tree, proto_tracee, tvb, 0, 0, ENC_NA);
    proto_item_set_text(args_item, "Args");
    args_tree = proto_item_add_subtree(args_item, ett_args);

    // go through all arguments
    for (i = 0; i < nargs; i++) {
        DISSECTOR_ASSERT((curr_arg = json_get_array_index(args_tok, i)) != NULL);
        DISSECTOR_ASSERT((arg_type = json_get_string(json_data, curr_arg, "type")) != NULL);
        arg_str = NULL;

        // get hf for this argument
        hf = get_arg_hf(event_name, json_data, curr_arg);

        // try dissecting it as a complex type
        if (!dissect_complex_arg(tvb, pinfo, args_tree, hf, arg_type, json_data, curr_arg, &arg_str, event_name)) {
            // not a complex arg - parse value according to type
            switch (hf->hfinfo.type) {
                // small signed integer types
                case FT_INT8:
                case FT_INT16:
                case FT_INT32:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &(val.s64)));
                    proto_tree_add_int(args_tree, *(hf->p_id), tvb, 0, 0, val.s32);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%d", val.s32);
                    break;
                
                // small unsigned integer types
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT32:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &(val.s64)));
                    proto_tree_add_uint(args_tree, *(hf->p_id), tvb, 0, 0, val.u32);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%u", val.u32);
                    break;
                
                // large signed integer
                case FT_INT64:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &(val.s64)));
                    proto_tree_add_int64(args_tree, *(hf->p_id), tvb, 0, 0, val.s64);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%" PRId64 , val.s64);
                    break;
                
                // large unsigned integer
                case FT_UINT64:
                    DISSECTOR_ASSERT(json_get_int_or_null(json_data, curr_arg, "value", &(val.s64)));
                    proto_tree_add_uint64(args_tree, *(hf->p_id), tvb, 0, 0, val.u64);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%" PRIu64 , val.u64);
                    break;
                
                // boolean
                case FT_BOOLEAN:
                    DISSECTOR_ASSERT(json_get_boolean(json_data, curr_arg, "value", &(val.boolean)));
                    proto_tree_add_boolean(args_tree, *(hf->p_id), tvb, 0, 0, val.u32);
                    arg_str = wmem_strdup_printf(pinfo->pool, "%s", val.boolean ? "true" : "false");
                    break;
                
                // string
                case FT_STRINGZ:
                    // try reading a string
                    if ((val.str = json_get_string(json_data, curr_arg, "value")) != NULL) {
                        proto_tree_add_string(args_tree, *(hf->p_id), tvb, 0, 0, val.str);
                        arg_str = val.str;
                    }
                    // no a string - try reading a null
                    else if (json_get_null(json_data, curr_arg, "value")) {
                            proto_tree_add_string(args_tree, *(hf->p_id), tvb, 0, 0, "null");
                            arg_str = "null";
                    }
                    // not a null - try reading a false
                    else {
                        DISSECTOR_ASSERT(json_get_boolean(json_data, curr_arg, "value", &val.boolean));
                        DISSECTOR_ASSERT(val.boolean == false);
                        proto_tree_add_string(args_tree, *(hf->p_id), tvb, 0, 0, "false");
                        arg_str = "false";
                    }
                    break;
                
                // unsupported types
                case FT_NONE:
                    ws_info("cannot dissect unsupported type \"%s\"", arg_type);
                    tmp_item = proto_tree_add_item(args_tree, *(hf->p_id), tvb, 0, 0, ENC_NA);
                    proto_item_append_text(tmp_item, " (unsupported type \"%s\")", arg_type);
                    break;
                
                default:
                    DISSECTOR_ASSERT_NOT_REACHED();
            }
        }

        // add argument to info column
        if (arg_str != NULL) {
            if ((info_col = col_get_text(pinfo->cinfo, COL_INFO)) != NULL && strlen(info_col) > 0)
                col_append_str(pinfo->cinfo, COL_INFO, ", ");
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %s", hf->hfinfo.name, arg_str);
        }
    }

    return args_item;
}

static proto_item *dissect_metadata_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gchar *json_data, jsmntok_t *root_tok)
{
    jsmntok_t *metadata_tok, *properties_tok;
    proto_item *metadata_item;
    proto_tree *metadata_tree, *properties_tree;
    gchar *tmp_str;
    gint64 tmp_int;

    if ((metadata_tok = json_get_object(json_data, root_tok, "metadata")) == NULL)
        return NULL;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACEE-SIG");

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
    add_string_array(tvb, pinfo, properties_tree, hf_metadata_properties_aggregation_keys, "Aggregation Keys",
        "aggregation_keys", json_data, properties_tok, "aggregation_keys", FALSE);

    // add external ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "external_id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_external_id, tvb, 0, 0, tmp_str);

    // add ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_id, tvb, 0, 0, tmp_str);

    // add release
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "release")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_release, tvb, 0, 0, tmp_str);

    // add signature ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "signatureID")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_id, tvb, 0, 0, tmp_str);

    // add signature name
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_tok, "signatureName")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_name, tvb, 0, 0, tmp_str);
    col_set_str(pinfo->cinfo, COL_INFO, tmp_str);

    return metadata_item;
}

static gchar *dissect_event_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, gchar *json_data)
{
    int num_toks;
    jsmntok_t *root_tok, *tmp_tok;
    gint64 tmp_int;
    nstime_t timestamp;
    gint32 pid, host_pid, tid, host_tid, ppid, host_ppid;
    gchar *event_name, *process_name, *syscall, *tmp_str, *pid_col_str = NULL, *tid_col_str = NULL, *ppid_col_str = NULL;
    proto_item *metadata_item, *args_item, *tmp_item;

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

    // add thread start time
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadStartTime", &tmp_int));
    timestamp.secs = (guint64)tmp_int / 1000000000;
    timestamp.nsecs = (guint64)tmp_int % 1000000000;
    proto_tree_add_time(tree, hf_thread_start_time, tvb, 0, 0, &timestamp);

    // add processor ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processorId", &tmp_int));
    proto_tree_add_int64(tree, hf_processor_id, tvb, 0, 0, tmp_int);

    // add cgroup ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "cgroupId", &tmp_int));
    proto_tree_add_int64(tree, hf_cgroup_id, tvb, 0, 0, tmp_int);

    // add process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processId", &tmp_int));
    pid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_process_id, tvb, 0, 0, pid);

    // add thread ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadId", &tmp_int));
    tid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_thread_id, tvb, 0, 0, tid);        

    // add parent process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "parentProcessId", &tmp_int));
    ppid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_parent_process_id, tvb, 0, 0, ppid);

    // add host process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostProcessId", &tmp_int));
    host_pid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_host_process_id, tvb, 0, 0, host_pid);

    // add PID column
    if (pid != 0) {
        pid_col_str = wmem_strdup_printf(pinfo->pool, "%d", pid);
        if (pid != host_pid)
            pid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", pid_col_str, host_pid);
        tmp_item = proto_tree_add_string(tree, hf_pid_col, tvb, 0, 0, pid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add host thread ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostThreadId", &tmp_int));
    host_tid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_host_thread_id, tvb, 0, 0, host_tid);

    // add TID column
    if (tid != 0) {
        tid_col_str = wmem_strdup_printf(pinfo->pool, "%d", tid);
        if (tid != host_tid)
            tid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", tid_col_str, host_tid);
        tmp_item = proto_tree_add_string(tree, hf_tid_col, tvb, 0, 0, tid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add host parent process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "hostParentProcessId", &tmp_int));
    host_ppid = (gint32)tmp_int;
    proto_tree_add_int(tree, hf_host_parent_process_id, tvb, 0, 0, host_ppid);

    // add PPID column
    if (ppid != 0) {
        ppid_col_str = wmem_strdup_printf(pinfo->pool, "%d", ppid);
        if (ppid != host_ppid)
            ppid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", ppid_col_str, host_ppid);
        tmp_item = proto_tree_add_string(tree, hf_ppid_col, tvb, 0, 0, ppid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add user ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "userId", &tmp_int));
    proto_tree_add_uint(tree, hf_user_id, tvb, 0, 0, (guint32)tmp_int);

    // add mount namespace
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "mountNamespace", &tmp_int));
    proto_tree_add_uint(tree, hf_mount_namespace, tvb, 0, 0, (guint32)tmp_int);

    // add PID namespace
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "pidNamespace", &tmp_int));
    proto_tree_add_uint(tree, hf_pid_namespace, tvb, 0, 0, (guint32)tmp_int);

    // add process name
    DISSECTOR_ASSERT((process_name = json_get_string(json_data, root_tok, "processName")) != NULL);
    proto_tree_add_string(tree, hf_process_name, tvb, 0, 0, process_name);

    // add executable path
    DISSECTOR_ASSERT((tmp_tok = json_get_object(json_data, root_tok, "executable")) != NULL);
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, tmp_tok, "path")) != NULL);
    proto_tree_add_string(tree, hf_executable_path, tvb, 0, 0, tmp_str);

    // add hostname
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_tok, "hostName")) != NULL);
    proto_tree_add_string(tree, hf_hostname, tvb, 0, 0, tmp_str);

    // add container fields
    dissect_container_fields(tvb, pinfo, tree, json_data, root_tok);

    // add event ID
    if (!json_get_int(json_data, root_tok, "eventId", &tmp_int)) {
        DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_tok, "eventId")) != NULL);
        tmp_int = strtoll(tmp_str, NULL, 10);
        DISSECTOR_ASSERT(errno == 0);
    }
    proto_tree_add_int64(tree, hf_event_id, tvb, 0, 0, tmp_int);

    // add event name
    DISSECTOR_ASSERT((event_name = json_get_string(json_data, root_tok, "eventName")) != NULL && strlen(event_name) > 0);
    proto_tree_add_string(tree, hf_event_name, tvb, 0, 0, event_name);
    if (strlen(event_name) > 0) {
        proto_item_append_text(item, ": %s", event_name);

        // check if event is a signature
        tmp_item = proto_tree_add_boolean(tree, hf_is_signature, tvb, 0, 0, strncmp(event_name, "sig_", 4) == 0);
        proto_item_set_generated(tmp_item);
    }

    // add matched policies
    add_string_array(tvb, pinfo, tree, hf_matched_policies, "Matched Policies",
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

    // add thread entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "threadEntityId", &tmp_int));
    proto_tree_add_int64(tree, hf_thread_entity_id, tvb, 0, 0, tmp_int);

    // add process entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "processEntityId", &tmp_int));
    proto_tree_add_int64(tree, hf_process_entity_id, tvb, 0, 0, tmp_int);

    // add parent entity ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_tok, "parentEntityId", &tmp_int));
    proto_tree_add_int64(tree, hf_parent_entity_id, tvb, 0, 0, tmp_int);

    // add signature metadata fields
    metadata_item = dissect_metadata_fields(tvb, pinfo, tree, json_data, root_tok);
    
    // add arguments
    args_item = dissect_arguments(tvb, pinfo, tree, json_data, root_tok, event_name);

    // move arguments above metadata
    if (args_item && metadata_item)
        proto_tree_move_item(tree, args_item, metadata_item);

    return event_name;
}

static int dissect_tracee_json(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *tracee_json_item;
    proto_tree *tracee_json_tree;
    guint len;
    gchar *json_data;
    gchar *event_name _U_;

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
    DISSECTOR_ASSERT_HINT(json_validate(json_data, len), "Invalid JSON");

    // dissect event fields
    event_name = dissect_event_fields(tvb, pinfo, tracee_json_tree, tracee_json_item, json_data);

    // call dissector for this event
    //dissector_try_string(event_name_dissector_table, event_name, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void proto_register_tracee(void)
{
    static gint *ett[] = {
        &ett_tracee,
        &ett_container,
        &ett_metadata,
        &ett_metadata_properties,
        &ett_args,
        &ett_string_arr,
        &ett_process_lineage,
        &ett_process_lineage_process,
        &ett_triggered_by,
        &ett_arg_obj
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
        { &hf_tid_col,
          { "TID Column", "tracee.tid_col",
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
        { &hf_args_argv,
          { "Argv Line", "tracee.args.argv_line",
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

    proto_tracee = proto_register_protocol("Tracee", "TRACEE", "tracee");
    proto_register_field_array(proto_tracee, hf, array_length(hf));
    proto_register_field_array(proto_tracee, sockaddr_hf, array_length(sockaddr_hf));
    proto_register_field_array(proto_tracee, slim_cred_t_hf, array_length(slim_cred_t_hf));
    proto_register_field_array(proto_tracee, pktmeta_hf, array_length(pktmeta_hf));
    proto_register_subtree_array(ett, array_length(ett));

    // create dynamic field array map for event arguments
    // and register a callback to unregister the dynamic fields when the map is destroyed
    event_dynamic_hf_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_str_hash, g_str_equal);
    wmem_register_callback(wmem_file_scope(), dynamic_hf_map_destroy_cb, NULL);

    // register event name dissector table
    event_name_dissector_table = register_dissector_table("tracee.eventName",
        "Tracee event name", proto_tracee, FT_STRINGZ, FALSE);
}

void proto_reg_handoff_tracee(void)
{
    static dissector_handle_t tracee_json_handle;

    tracee_json_handle = create_dissector_handle(dissect_tracee_json, proto_tracee);
    
    // register to encapsulation dissector table (we use a user-reserved encapsulation)
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, tracee_json_handle);
}