#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>

static int proto_tracee_json = -1;

static dissector_table_t event_name_dissector_table;

static int hf_timestamp = -1;
//static int hf_thread_start_time = -1;
//static int processor_id = -1;
static int hf_process_id = -1;
//static int hf_cgroup_id = -1;
static int hf_thread_id = -1;
static int hf_parent_process_id = -1;
static int hf_host_process_id = -1;
static int hf_host_thread_id = -1;
static int hf_host_parent_process_id = -1;
//static int hf_user_id = -1;
//static int hf_mount_namespace = -1;
//static int hf_pid_namespace = -1;
static int hf_process_name = -1;
static int hf_pid_col = -1;
static int hf_tid_col = -1;
/* EXECUTABLE INFO
static int hf_executable_path = -1;*/
//static int hf_hostname = -1;
//static int hf_container_id_standalone = -1;
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
//static int hf_matched_policies = -1;
//static int hf_args_num = -1;
static int hf_return_value = -1;
static int hf_syscall = -1;
//static int hf_stack_address = -1;
//CONTEXT FLAFS INFO
//static int hf_thread_entity_id = -1;
//static int hf_process_entity_id = -1;
//static int parent_entity_id = -1;
// ARGS
static int hf_metadata_version = -1;
static int hf_metadata_description = -1;
//static int hf_metadata_tags = -1;
static int hf_metadata_properties_category = -1;
static int hf_metadata_properties_kubernetes_technique = -1;
static int hf_metadata_properties_severity = -1;
static int hf_metadata_properties_technique = -1;
//static int hf_metadata_properties_aggregation_keys = -1;
static int hf_metadata_properties_external_id = -1;
static int hf_metadata_properties_id = -1;
static int hf_metadata_properties_release = -1;
static int hf_metadata_properties_signature_id = -1;
static int hf_metadata_properties_signature_name = -1;

static gint ett_tracee_json = -1;
static gint ett_container = -1;
static gint ett_metadata = -1;
static gint ett_metadata_properties = -1;

struct container_fields {
    gchar *id;
    gchar *name;
    gchar *image;
    gchar *image_digest;
};

/*
 * From wsutil/jsmn.c
 */
static jsmntok_t *json_get_next_object(jsmntok_t *cur)
{
    int i;
    jsmntok_t *next = cur+1;

    for (i = 0; i < cur->size; i++) {
        next = json_get_next_object(next);
    }
    return next;
}

/**
 * Get the value of a number object belonging to parent object and named as the name variable.
 * Returns FALSE if not found. Caution: it modifies input buffer.
 */
static bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_PRIMITIVE) {
            buf[(cur+1)->end] = '\0';
            errno = 0; // for some reason we have to clear errno manually, because it has an unrelated error stuck which isn't cleared
            *val = g_ascii_strtoll(&buf[(cur+1)->start], NULL, 10);
            if (errno != 0)
                return false;
            return true;
        }
        cur = json_get_next_object(cur);
    }
    return false;
}

static void dissect_container_fields(tvbuff_t *tvb, proto_tree *tree, char *json_data, jsmntok_t *root_token, struct container_fields *fields)
{
    proto_item *container_item, *tmp_item;
    proto_tree *container_tree;
    jsmntok_t *container_token;

    container_item = proto_tree_add_item(tree, proto_tracee_json, tvb, 0, 0, ENC_NA);
    proto_item_set_text(container_item, "Container");
    container_tree = proto_item_add_subtree(container_item, ett_container);

    DISSECTOR_ASSERT((container_token = json_get_object(json_data, root_token, "container")) != NULL);

    // add container id
    if ((fields->id = json_get_string(json_data, container_token, "id")) != NULL) {
        proto_tree_add_string(container_tree, hf_container_id, tvb, 0, 0, fields->id);
        proto_item_append_text(container_item, ": %s", fields->id);
    }

    // add container name
    if ((fields->name = json_get_string(json_data, container_token, "name")) != NULL)
        proto_tree_add_string(container_tree, hf_container_name, tvb, 0, 0, fields->name);
    
    // add container image
    if ((fields->image = json_get_string(json_data, container_token, "image")) != NULL)
        proto_tree_add_string(container_tree, hf_container_image, tvb, 0, 0, fields->image);
    
    // add container image digest
    if ((fields->image_digest = json_get_string(json_data, container_token, "imageDigest")) != NULL)
        proto_tree_add_string(container_tree, hf_container_image_digest, tvb, 0, 0, fields->image_digest);
    
    // no container
    if (!fields->id && !fields->name && !fields->image && !fields->image_digest) {
        proto_item_append_text(container_item, ": none");
        tmp_item = proto_tree_add_boolean(container_tree, hf_is_container, tvb, 0, 0, FALSE);
    }
    else
        tmp_item = proto_tree_add_boolean(container_tree, hf_is_container, tvb, 0, 0, TRUE);
    
    proto_item_set_generated(tmp_item);
}

static void dissect_metadata_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *json_data, jsmntok_t *root_token)
{
    jsmntok_t *metadata_token, *properties_token;
    proto_tree *metadata_tree, *properties_tree;
    gchar *tmp_str;
    gint64 tmp_int;

    if ((metadata_token = json_get_object(json_data, root_token, "metadata")) == NULL)
        return;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACEE-SIG");

    metadata_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_metadata, NULL, "Metadata");

    // add version
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, metadata_token, "Version")) != NULL);
    proto_tree_add_string(metadata_tree, hf_metadata_version, tvb, 0, 0, tmp_str);
    
    // add description
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, metadata_token, "Description")) != NULL);
    proto_tree_add_string(metadata_tree, hf_metadata_description, tvb, 0, 0, tmp_str);

    DISSECTOR_ASSERT((properties_token = json_get_object(json_data, metadata_token, "Properties")) != NULL);

    properties_tree = proto_tree_add_subtree(metadata_tree, tvb, 0, 0, ett_metadata_properties, NULL, "Properties");

    // add category
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "Category")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_category, tvb, 0, 0, tmp_str);

    // add kubernetes technique
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "Kubernetes_Technique")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_kubernetes_technique, tvb, 0, 0, tmp_str);

    // add severity
    DISSECTOR_ASSERT((json_get_int(json_data, properties_token, "Severity", &tmp_int)));
    proto_tree_add_int(properties_tree, hf_metadata_properties_severity, tvb, 0, 0, tmp_int);

    // add technique
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "Technique")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_technique, tvb, 0, 0, tmp_str);

    // add external ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "external_id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_external_id, tvb, 0, 0, tmp_str);

    // add ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "id")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_id, tvb, 0, 0, tmp_str);

    // add release
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "release")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_release, tvb, 0, 0, tmp_str);

    // add signature ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "signatureID")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_id, tvb, 0, 0, tmp_str);

    // add signature name
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, properties_token, "signatureName")) != NULL);
    proto_tree_add_string(properties_tree, hf_metadata_properties_signature_name, tvb, 0, 0, tmp_str);
    col_set_str(pinfo->cinfo, COL_INFO, tmp_str);
}

static gchar *dissect_event_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, char *json_data)
{
    int num_tokens;
    jsmntok_t *root_token;
    gint64 tmp_int;
    pid_t pid, host_pid, tid, host_tid;
    gchar *event_name, *process_name, *syscall, *tmp_str, *pid_col_str = NULL, *tid_col_str = NULL, *container_col_str = NULL;
    proto_item *tmp_item;
    struct container_fields container_fields;

    num_tokens = json_parse(json_data, NULL, 0);
    DISSECTOR_ASSERT_HINT(num_tokens > 0, "JSON decode error: non-positive max_tokens");

    root_token = wmem_alloc_array(pinfo->pool, jsmntok_t, num_tokens);
    if (json_parse(json_data, root_token, num_tokens) <= 0)
        DISSECTOR_ASSERT_NOT_REACHED();
    
    // add timestamp
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "timestamp", &tmp_int));
    proto_tree_add_uint64(tree, hf_timestamp, tvb, 0, 0, (guint64)tmp_int);

    // add process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "processId", &tmp_int));
    pid = (pid_t)tmp_int;
    proto_tree_add_int(tree, hf_process_id, tvb, 0, 0, pid);

    // add thread ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "threadId", &tmp_int));
    tid = (pid_t)tmp_int;
    proto_tree_add_int(tree, hf_thread_id, tvb, 0, 0, tid);        

    // add parent process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "parentProcessId", &tmp_int));
    proto_tree_add_int(tree, hf_parent_process_id, tvb, 0, 0, (gint)tmp_int);

    // add host process ID
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "hostProcessId", &tmp_int));
    host_pid = (pid_t)tmp_int;
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
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "hostThreadId", &tmp_int));
    host_tid = (pid_t)tmp_int;
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
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "hostParentProcessId", &tmp_int));
    proto_tree_add_int(tree, hf_host_parent_process_id, tvb, 0, 0, (gint)tmp_int);

    // add process name
    DISSECTOR_ASSERT((process_name = json_get_string(json_data, root_token, "processName")) != NULL);
    proto_tree_add_string(tree, hf_process_name, tvb, 0, 0, process_name);

    // add container fields
    dissect_container_fields(tvb, tree, json_data, root_token, &container_fields);
    if (container_fields.id != NULL) {
        container_col_str = wmem_strndup(pinfo->pool, container_fields.id, 12);

        if (container_fields.image != NULL)
            container_col_str = wmem_strdup_printf(pinfo->pool, "%s (%s)", container_col_str, container_fields.image);
        
        proto_tree_add_string(tree, hf_container_col, tvb, 0, 0, container_col_str);
    }

    // add event ID
    DISSECTOR_ASSERT((tmp_str = json_get_string(json_data, root_token, "eventId")) != NULL);
    proto_tree_add_string(tree, hf_event_id, tvb, 0, 0, tmp_str);

    // add event name
    DISSECTOR_ASSERT((event_name = json_get_string(json_data, root_token, "eventName")) != NULL && strlen(event_name) > 0);
    proto_tree_add_string(tree, hf_event_name, tvb, 0, 0, event_name);
    if (strlen(event_name) > 0) {
        proto_item_append_text(item, ": %s", event_name);

        // check if event is a signature
        tmp_item = proto_tree_add_boolean(tree, hf_is_signature, tvb, 0, 0, strncmp(event_name, "sig_", 4) == 0);
        proto_item_set_generated(tmp_item);
    }

    // add return value
    DISSECTOR_ASSERT(json_get_int(json_data, root_token, "returnValue", &tmp_int));
    proto_tree_add_int(tree, hf_return_value, tvb, 0, 0, (gint)tmp_int);

    // add syscall
    DISSECTOR_ASSERT((syscall = json_get_string(json_data, root_token, "syscall")) != NULL);
    proto_tree_add_string(tree, hf_syscall, tvb, 0, 0, syscall);

    // set info column
    col_add_fstr(pinfo->cinfo, COL_INFO, "EVENT=%s", event_name);
    if (container_col_str != NULL && strlen(container_col_str) > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CONTAINER=%s", container_col_str);
    if (process_name != NULL && strlen(process_name) > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", PROCESS=%s", process_name);
    if (syscall != NULL && strlen(syscall) > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", SYSCALL=%s", syscall);
    
    // add signature metadata fields
    dissect_metadata_fields(tvb, pinfo, tree, json_data, root_token);

    return event_name;
}

static int dissect_tracee_json(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    proto_tree *tracee_json_tree;
    proto_item *tracee_json_item;
    guint len;
    char *json_data;
    gchar *event_name _U_;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRACEE");

    // create tracee tree
    tracee_json_tree = proto_tree_add_item(tree, proto_tracee_json, tvb, 0, -1, ENC_NA);
    tracee_json_item = proto_item_add_subtree(tracee_json_tree, ett_tracee_json);

    proto_item_set_text(tracee_json_tree, "Tracee Event (JSON)");

    // make sure this is a valid JSON
    len = tvb_captured_length(tvb);
    json_data = wmem_alloc(pinfo->pool, len + 1);
    tvb_memcpy(tvb, json_data, 0, len);
    json_data[len] = '\0';
    DISSECTOR_ASSERT_HINT(json_validate(json_data, len), "Invalid JSON");

    // dissect basic fields
    event_name = dissect_event_fields(tvb, pinfo, tracee_json_tree, tracee_json_item, json_data);

    // call dissector for this event
    //dissector_try_string(event_name_dissector_table, event_name, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void proto_register_tracee_json(void)
{
    static gint *ett[] = {
        &ett_tracee_json,
        &ett_container,
        &ett_metadata,
        &ett_metadata_properties
    };

    static hf_register_info hf[] = {
        { &hf_timestamp,
          { "Timestamp", "tracee.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0,
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
        { &hf_process_name,
          { "Process Name", "tracee.processName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
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
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Tracee event ID", HFILL }
        },
        { &hf_event_name,
          { "Event Name", "tracee.eventName",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Tracee event name", HFILL }
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

    proto_tracee_json = proto_register_protocol("Tracee JSON", "TRACEE", "tracee_json");
    proto_register_field_array(proto_tracee_json, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // register event name dissector table
    event_name_dissector_table = register_dissector_table("tracee_json.eventName",
        "Tracee event name", proto_tracee_json, FT_STRINGZ, FALSE);
}

void proto_reg_handoff_tracee_json(void)
{
    static dissector_handle_t tracee_json_handle;

    tracee_json_handle = create_dissector_handle(dissect_tracee_json, proto_tracee_json);
    
    // register to event type dissector table
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, tracee_json_handle);
}