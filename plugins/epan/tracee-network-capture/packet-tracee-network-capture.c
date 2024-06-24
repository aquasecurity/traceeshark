#include "../common.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>
#include <ws_version.h>

static int proto_tracee_network_capture = -1;

static int hf_hostname = -1;
static int hf_process_name = -1;
static int hf_executable_path = -1;
static int hf_process_id = -1;
static int hf_thread_id = -1;
static int hf_parent_process_id = -1;
static int hf_host_process_id = -1;
static int hf_host_thread_id = -1;
static int hf_host_parent_process_id = -1;
static int hf_pid_col = -1;
static int hf_ppid_col = -1;
static int hf_thread_start_time = -1;
static int hf_user_id = -1;
static int hf_cgroup_id = -1;
static int hf_mount_namespace = -1;
static int hf_pid_namespace = -1;
static int hf_container_id = -1;
static int hf_container_name = -1;
static int hf_container_image = -1;
static int hf_container_image_digest = -1;
static int hf_is_container = -1;
static int hf_container_col = -1;
static int hf_k8s_pod_name = -1;
static int hf_k8s_pod_namespace = -1;
static int hf_k8s_pod_uid = -1;

static gint ett_tracee_network_capture = -1;
static gint ett_process = -1;
static gint ett_container = -1;
static gint ett_k8s = -1;

struct context_version {
    unsigned int major, minor;
};

static bool parse_version(const char *version_string, struct context_version *version)
{
    gchar **parts;

    if ((parts = g_strsplit(version_string, ".", 2)) == NULL)
        return false;
    if (parts[0] == NULL || parts[1] == NULL)
        goto err;
    
    errno = 0;
    version->major = (unsigned int)strtoul(parts[0], NULL, 10);
    if (errno != 0)
        goto err;
    errno = 0;
    version->minor = (unsigned int)strtoul(parts[0], NULL, 10);
    if (errno != 0)
        goto err;

    g_strfreev(parts);
    return true;

err:
    g_strfreev(parts);
    return false;
}

static void find_first_item(proto_node *curr_item, void *data)
{
    proto_item **out_item = (proto_item **)data;

    if (*out_item == NULL)
        *out_item = curr_item;
}

static proto_item *get_first_item(proto_tree *tree)
{
    proto_item *first_item = NULL;

    proto_tree_children_foreach(tree, find_first_item, &first_item);

    return first_item;
}

static void dissect_process_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *if_descr, jsmntok_t *root_tok)
{
    jsmntok_t *process_tok;
    proto_item *process_item, *tmp_item;
    proto_tree *process_tree;
    gint64 tmp_int;
    nstime_t timestamp;
    gint32 pid, host_pid, ppid, host_ppid;
    gchar *process_name, *tmp_str, *pid_col_str = NULL, *ppid_col_str = NULL;
    guint pid_format;

    if ((process_name = json_get_string(if_descr, root_tok, "processName")) == NULL)
        return;
    
    if ((process_tok = json_get_object(if_descr, root_tok, "process")) == NULL) {
        // command capture - add process name to main tree
        proto_tree_add_string(tree, hf_process_name, tvb, 0, 0, process_name);
        return;
    }

    process_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, 0, ENC_NA);
    proto_item_set_text(process_item, "Process");
    process_tree = proto_item_add_subtree(process_item, ett_process);

    // add process name
    proto_tree_add_string(process_tree, hf_process_name, tvb, 0, 0, process_name);

    // add executable path
    DISSECTOR_ASSERT((tmp_str = json_get_string(if_descr, process_tok, "executable")) != NULL);
    if (strlen(tmp_str) > 0)
        proto_tree_add_string(process_tree, hf_executable_path, tvb, 0, 0, tmp_str);

    // add process ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "processId", &tmp_int));
    pid = (gint32)tmp_int;
    proto_tree_add_int(process_tree, hf_process_id, tvb, 0, 0, pid);

    // add thread ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "threadId", &tmp_int));
    proto_tree_add_int(process_tree, hf_thread_id, tvb, 0, 0, (gint32)tmp_int);

    // add parent process ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "parentProcessId", &tmp_int));
    ppid = (gint32)tmp_int;
    proto_tree_add_int(process_tree, hf_parent_process_id, tvb, 0, 0, ppid);

    // add host process ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "hostProcessId", &tmp_int));
    host_pid = (gint32)tmp_int;
    proto_tree_add_int(process_tree, hf_host_process_id, tvb, 0, 0, host_pid);
    proto_item_append_text(process_item, ": %d (%s)", host_pid, process_name);

    // add host thread ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "hostThreadId", &tmp_int));
    proto_tree_add_int(process_tree, hf_host_thread_id, tvb, 0, 0, (gint32)tmp_int);

    // add host parent process ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "hostParentProcessId", &tmp_int));
    host_ppid = (gint32)tmp_int;
    proto_tree_add_int(process_tree, hf_host_parent_process_id, tvb, 0, 0, host_ppid);

    pid_format = prefs_get_uint_value("tracee", "pid_format");

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
        tmp_item = proto_tree_add_string(process_tree, hf_pid_col, tvb, 0, 0, pid_col_str);
        proto_item_set_hidden(tmp_item);
    }

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
        tmp_item = proto_tree_add_string(process_tree, hf_ppid_col, tvb, 0, 0, ppid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add thread start time
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "threadStartTime", &tmp_int));
    timestamp.secs = (guint64)tmp_int / 1000000000;
    timestamp.nsecs = (guint64)tmp_int % 1000000000;
    proto_tree_add_time(process_tree, hf_thread_start_time, tvb, 0, 0, &timestamp);

    // add user ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "userId", &tmp_int));
    proto_tree_add_uint(process_tree, hf_user_id, tvb, 0, 0, (guint32)tmp_int);

    // add cgroup ID
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "cgroupId", &tmp_int));
    proto_tree_add_int64(process_tree, hf_cgroup_id, tvb, 0, 0, tmp_int);

    // add mount namespace
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "mountNamespace", &tmp_int));
    proto_tree_add_uint(process_tree, hf_mount_namespace, tvb, 0, 0, (guint32)tmp_int);

    // add PID namespace
    DISSECTOR_ASSERT(json_get_int(if_descr, process_tok, "pidNamespace", &tmp_int));
    proto_tree_add_uint(process_tree, hf_pid_namespace, tvb, 0, 0, (guint32)tmp_int);
}

static void dissect_container_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *if_descr, jsmntok_t *root_tok)
{
    jsmntok_t *container_tok;
    proto_item *container_item, *tmp_item;
    proto_tree *container_tree;
    gchar *id, *name, *image, *image_digest, *container_col_str;

    // get container object, if present
    if ((container_tok = json_get_object(if_descr, root_tok, "container")) == NULL)
        return;

    container_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, 0, ENC_NA);
    proto_item_set_text(container_item, "Container");
    container_tree = proto_item_add_subtree(container_item, ett_container);

    // add container id
    if ((id = json_get_string(if_descr, container_tok, "id")) != NULL)
        proto_tree_add_string(container_tree, hf_container_id, tvb, 0, 0, id);

    // add container name
    if ((name = json_get_string(if_descr, container_tok, "name")) != NULL)
        proto_tree_add_string(container_tree, hf_container_name, tvb, 0, 0, name);
    
    // add container image
    if ((image = json_get_string(if_descr, container_tok, "image")) != NULL)
        proto_tree_add_string(container_tree, hf_container_image, tvb, 0, 0, image);
    
    // add container image digest
    if ((image_digest = json_get_string(if_descr, container_tok, "imageDigest")) != NULL)
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
        if (prefs_get_uint_value("tracee", "container_identifier") == CONTAINER_IDENTIFIER_ID)
            container_col_str = wmem_strndup(pinfo->pool, id, 12);
        else
            container_col_str = wmem_strdup(pinfo->pool, name);
        
        proto_item_append_text(container_item, ": %s", container_col_str);

        if (image) {
            if (prefs_get_uint_value("tracee", "container_image"))
                container_col_str = wmem_strdup_printf(pinfo->pool, "%s (%s)", container_col_str, image);
            proto_item_append_text(container_item, " (%s)", image);
        }
        
        tmp_item = proto_tree_add_string(tree, hf_container_col, tvb, 0, 0, container_col_str);
        proto_item_set_hidden(tmp_item);
    }
}

static void dissect_kubernetes_info(tvbuff_t *tvb, proto_tree *tree, char *if_descr, jsmntok_t *root_tok)
{
    proto_item *k8s_item;
    proto_tree *k8s_tree;
    jsmntok_t *k8s_tok;
    gchar *pod_name, *pod_namespace, *pod_uid;

    // get kubernetes object, if present
    if ((k8s_tok = json_get_object(if_descr, root_tok, "kubernetes")) == NULL)
        return;

    k8s_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, 0, ENC_NA);
    proto_item_set_text(k8s_item, "Kubernetes");
    k8s_tree = proto_item_add_subtree(k8s_item, ett_k8s);

    // add pod name
    if ((pod_name = json_get_string(if_descr, k8s_tok, "podName")) != NULL) {
        proto_tree_add_string(k8s_tree, hf_k8s_pod_name, tvb, 0, 0, pod_name);
        proto_item_append_text(k8s_item, ": %s", pod_name);
    }

    // add pod namespace
    if ((pod_namespace = json_get_string(if_descr, k8s_tok, "podNamespace")) != NULL) {
        proto_tree_add_string(k8s_tree, hf_k8s_pod_namespace, tvb, 0, 0, pod_namespace);
        if (pod_name != NULL)
            proto_item_append_text(k8s_item, " (%s)", pod_namespace);
    }

    // add pod UID
    if ((pod_uid = json_get_string(if_descr, k8s_tok, "podUID")) != NULL)
        proto_tree_add_string(k8s_tree, hf_k8s_pod_uid, tvb, 0, 0, pod_uid);
    
    // no kubernetes info
    if (!pod_name && !pod_namespace && !pod_uid)
        proto_item_append_text(k8s_item, ": none");
}

static void dissect_interface_description(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, char *if_descr, jsmntok_t *root_tok, struct context_version *version)
{
    gchar *tmp_str;

    DISSECTOR_ASSERT(version->major == 1);

    // add hostname
    if ((tmp_str = json_get_string(if_descr, root_tok, "hostName")) != NULL) {
        proto_tree_add_string(tree, hf_hostname, tvb, 0, 0, tmp_str);
    }

    // add process info
    dissect_process_info(tvb, pinfo, tree, if_descr, root_tok);

    // add container info
    dissect_container_info(tvb, pinfo, tree, if_descr, root_tok);

    // add kubernetes info
    dissect_kubernetes_info(tvb, tree, if_descr, root_tok);
}

static void dissect_interface_description_compat(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, proto_item *item, char *if_descr, jsmntok_t *root_tok)
{
    gint64 tmp_int;
    gint32 pid = -1, ns_pid = -1, ppid = -1, ns_ppid = -1;
    gchar *tmp_str, *container_id, *container_image, *pid_col_str, *ppid_col_str, *container_col_str;
    proto_item *tmp_item;

    // add PID
    if (json_get_int(if_descr, root_tok, "pid", &tmp_int)) {
        pid = (gint32)tmp_int;
        proto_tree_add_int(tree, hf_host_process_id, tvb, 0, 0, pid);
        proto_item_append_text(item, ": PID = %d", pid);
    }

    // add NS PID
    if (json_get_int(if_descr, root_tok, "ns_pid", &tmp_int)) {
        ns_pid = (gint32)tmp_int;
        proto_tree_add_int(tree, hf_process_id, tvb, 0, 0, ns_pid);
    }
    
    // add PID column
    if (pid != -1) {
        pid_col_str = wmem_strdup_printf(pinfo->pool, "%d", ns_pid);
        if (ns_pid != -1 && pid != ns_pid)
            pid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", pid_col_str, pid);
        tmp_item = proto_tree_add_string(tree, hf_pid_col, tvb, 0, 0, pid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add PPID
    if (json_get_int(if_descr, root_tok, "ppid", &tmp_int)) {
        ppid = (gint32)tmp_int;
        proto_tree_add_int(tree, hf_host_parent_process_id, tvb, 0, 0, ppid);
        proto_item_append_text(item, ", PPID = %d", ppid);
    }

    // add NS PPID
    if (json_get_int(if_descr, root_tok, "ns_ppid", &tmp_int)) {
        ns_ppid = (gint32)tmp_int;
        proto_tree_add_int(tree, hf_parent_process_id, tvb, 0, 0, ns_ppid);
    }

    // add PPID column
    if (ppid != -1) {
        ppid_col_str = wmem_strdup_printf(pinfo->pool, "%d", ns_ppid);
        if (ns_ppid != -1 && ppid != ns_ppid)
            ppid_col_str = wmem_strdup_printf(pinfo->pool, "%s (%d)", ppid_col_str, ppid);
        tmp_item = proto_tree_add_string(tree, hf_ppid_col, tvb, 0, 0, ppid_col_str);
        proto_item_set_hidden(tmp_item);
    }

    // add process name
    if ((tmp_str = json_get_string(if_descr, root_tok, "name")) != NULL) {
        proto_tree_add_string(tree, hf_process_name, tvb, 0, 0, tmp_str);
        proto_item_append_text(item, ", Name = %s", tmp_str);
    }

    // add container ID
    if ((container_id = json_get_string(if_descr, root_tok, "container_id")) != NULL)
        proto_tree_add_string(tree, hf_container_id, tvb, 0, 0, container_id);
    
    // add container name
    if ((tmp_str = json_get_string(if_descr, root_tok, "container_name")) != NULL)
        proto_tree_add_string(tree, hf_container_name, tvb, 0, 0, tmp_str);
    
    // add container image
    if ((container_image = json_get_string(if_descr, root_tok, "container_image")) != NULL)
        proto_tree_add_string(tree, hf_container_image, tvb, 0, 0, container_image);
    
    // add container column
    if (container_id != NULL) {
        container_col_str = wmem_strndup(pinfo->pool, container_id, 12);

        if (container_image != NULL)
            container_col_str = wmem_strdup_printf(pinfo->pool, "%s (%s)", container_col_str, container_image);
        
        tmp_item = proto_tree_add_string(tree, hf_container_col, tvb, 0, 0, container_col_str);
        proto_item_set_hidden(tmp_item);
    }
    
    // add k8s pod name
    if ((tmp_str = json_get_string(if_descr, root_tok, "k8s_pod_name")) != NULL)
        proto_tree_add_string(tree, hf_k8s_pod_name, tvb, 0, 0, tmp_str);
    
    // add k8s pod namesapce
    if ((tmp_str = json_get_string(if_descr, root_tok, "k8s_pod_namespace")) != NULL)
        proto_tree_add_string(tree, hf_k8s_pod_namespace, tvb, 0, 0, tmp_str);
    
    // add k8s pod UID
    if ((tmp_str = json_get_string(if_descr, root_tok, "k8s_pod_uid")) != NULL)
        proto_tree_add_string(tree, hf_k8s_pod_uid, tvb, 0, 0, tmp_str);
}

static int postdissect_tracee_network_capture(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *tracee_network_capture_tree;
    proto_item *tracee_network_capture_item, *tmp_item;
    char *if_descr;
    int num_toks;
    jsmntok_t *root_tok;
    gchar *tmp_str;
    struct context_version version;
    
    // make sure this is a packet recorded by Tracee
#if (WIRESHARK_VERSION_MAJOR > 4 || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 3))
    guint section_number = pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0;
    if (strcmp(epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number), "tracee") != 0)
#else
    if (strcmp(epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id), "tracee") != 0)
#endif
        return 0;
    
    // make sure this is not a live event capture
    if (pinfo->rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_USER0)
        return 0;

    // create tracee network capture tree
    tracee_network_capture_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, -1, ENC_NA);
    tracee_network_capture_tree = proto_item_add_subtree(tracee_network_capture_item, ett_tracee_network_capture);

    // move tracee network capture item below frame item
    tmp_item = get_first_item(tree);
    proto_tree_move_item(tree, tmp_item, tracee_network_capture_item);

#if (WIRESHARK_VERSION_MAJOR > 4 || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 3))
    if_descr = wmem_strdup(pinfo->pool, epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number));
#else
    if_descr = wmem_strdup(pinfo->pool, epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id));
#endif

    if (!json_validate((guint8 *)if_descr, strlen(if_descr)))
        return 0;
    
    num_toks = json_parse(if_descr, NULL, 0);
    DISSECTOR_ASSERT_HINT(num_toks > 0, "JSON decode error: non-positive num_toks");

    root_tok = wmem_alloc_array(pinfo->pool, jsmntok_t, num_toks);
    if (json_parse(if_descr, root_tok, num_toks) <= 0)
        DISSECTOR_ASSERT_NOT_REACHED();
    
    if ((tmp_str = json_get_string(if_descr, root_tok, "version")) != NULL) {
        DISSECTOR_ASSERT(parse_version(tmp_str, &version));
        dissect_interface_description(tvb, pinfo, tracee_network_capture_tree, if_descr, root_tok, &version);
    }
    // no version field means this is an old exerimental version of packet context, for now this is dissected for compatibility
    else
        dissect_interface_description_compat(tvb, pinfo, tracee_network_capture_tree, tracee_network_capture_item, if_descr, root_tok);

    return 0;
}

void proto_register_tracee_network_capture(void)
{
    dissector_handle_t tracee_network_capture_handle;

    static gint *ett[] = {
        &ett_tracee_network_capture,
        &ett_process,
        &ett_container,
        &ett_k8s,
    };

    proto_tracee_network_capture = proto_register_protocol("Tracee Network Capture", "TRACEE-NETWORK-CAPTURE", "tracee-network-capture");
    proto_register_subtree_array(ett, array_length(ett));

    tracee_network_capture_handle = register_dissector("tracee-network-capture", postdissect_tracee_network_capture, proto_tracee_network_capture);
    register_postdissector(tracee_network_capture_handle);
}

void proto_reg_handoff_tracee_network_capture(void)
{
    // get hf id for tracee event fields we need
    hf_hostname = proto_registrar_get_id_byname("tracee.hostName");
    hf_executable_path = proto_registrar_get_id_byname("tracee.executable.path");
    hf_process_name = proto_registrar_get_id_byname("tracee.processName");
    hf_process_id = proto_registrar_get_id_byname("tracee.processId");
    hf_thread_id = proto_registrar_get_id_byname("tracee.threadId");
    hf_parent_process_id = proto_registrar_get_id_byname("tracee.parentProcessId");
    hf_host_process_id = proto_registrar_get_id_byname("tracee.hostProcessId");
    hf_host_thread_id = proto_registrar_get_id_byname("tracee.hostThreadId");
    hf_host_parent_process_id = proto_registrar_get_id_byname("tracee.hostParentProcessId");
    hf_pid_col = proto_registrar_get_id_byname("tracee.pid_col");
    hf_ppid_col = proto_registrar_get_id_byname("tracee.ppid_col");
    hf_thread_start_time = proto_registrar_get_id_byname("tracee.threadStartTime");
    hf_user_id = proto_registrar_get_id_byname("tracee.userId");
    hf_cgroup_id = proto_registrar_get_id_byname("tracee.cgroupId");
    hf_mount_namespace = proto_registrar_get_id_byname("tracee.mountNamespace");
    hf_pid_namespace = proto_registrar_get_id_byname("tracee.pidNamespace");
    hf_container_id = proto_registrar_get_id_byname("tracee.container.id");
    hf_container_name = proto_registrar_get_id_byname("tracee.container.name");
    hf_container_image = proto_registrar_get_id_byname("tracee.container.image");
    hf_container_image_digest = proto_registrar_get_id_byname("tracee.container.imageDigest");
    hf_is_container = proto_registrar_get_id_byname("tracee.isContainer");
    hf_container_col = proto_registrar_get_id_byname("tracee.container_col");
    hf_k8s_pod_name = proto_registrar_get_id_byname("tracee.kubernetes.podName");
    hf_k8s_pod_namespace = proto_registrar_get_id_byname("tracee.kubernetes.podNamespace");
    hf_k8s_pod_uid = proto_registrar_get_id_byname("tracee.kubernetes.podUID");
}