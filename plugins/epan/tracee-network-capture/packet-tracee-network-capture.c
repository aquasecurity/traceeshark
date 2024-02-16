#define WS_BUILD_DLL

#include "wireshark.h"
#include "../common.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>
#include <wsutil/plugins.h>

#ifndef VERSION
#define VERSION "0.1.0"
#endif

#ifndef WIRESHARK_PLUGIN_REGISTER // old plugin API
WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif
#endif

static int proto_tracee_network_capture = -1;

static int hf_process_id = -1;
static int hf_parent_process_id = -1;
static int hf_host_process_id = -1;
static int hf_pid_col = -1;
static int hf_ppid_col = -1;
static int hf_host_parent_process_id = -1;
static int hf_process_name = -1;
static int hf_container_id = -1;
static int hf_container_name = -1;
static int hf_container_image = -1;
static int hf_container_col = -1;
static int hf_k8s_pod_name = -1;
static int hf_k8s_pod_namespace = -1;
static int hf_k8s_pod_uid = -1;

static gint ett_tracee_network_capture = -1;

static int dissect_tracee_network_capture(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dissector_handle_t null_dissector;
    proto_tree *tracee_network_capture_tree;
    proto_item *tracee_network_capture_item, *tmp_item;
    char *if_descr;
    int num_toks;
    jsmntok_t *root_tok;
    gint64 tmp_int;
    gint32 pid = -1, ns_pid = -1, ppid = -1, ns_ppid = -1;
    gchar *tmp_str, *container_id, *container_image, *pid_col_str, *ppid_col_str, *container_col_str;
    
    DISSECTOR_ASSERT_HINT((null_dissector = find_dissector("null")) != NULL, "Cannot find Null/Loopback dissector");

    // create tracee network capture tree
    tracee_network_capture_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, -1, ENC_NA);
    tracee_network_capture_tree = proto_item_add_subtree(tracee_network_capture_item, ett_tracee_network_capture);

#if (WIRESHARK_VERSION_MAJOR > 4 || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 3))
    guint section_number = pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0;
    if_descr = wmem_strdup(pinfo->pool, epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number));
#else
    if_descr = wmem_strdup(pinfo->pool, epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id));
#endif

    if (!json_validate((uint8_t *)if_descr, strlen(if_descr)))
        goto call_original_dissector;
    
    num_toks = json_parse(if_descr, NULL, 0);
    DISSECTOR_ASSERT_HINT(num_toks > 0, "JSON decode error: non-positive num_toks");

    root_tok = wmem_alloc_array(pinfo->pool, jsmntok_t, num_toks);
    if (json_parse(if_descr, root_tok, num_toks) <= 0)
        DISSECTOR_ASSERT_NOT_REACHED();
    
    // add PID
    if (json_get_int(if_descr, root_tok, "pid", &tmp_int)) {
        pid = (gint32)tmp_int;
        proto_tree_add_int(tracee_network_capture_tree, hf_host_process_id, tvb, 0, 0, pid);
        proto_item_append_text(tracee_network_capture_item, ": PID = %d", pid);
    }

    // add NS PID
    if (json_get_int(if_descr, root_tok, "ns_pid", &tmp_int)) {
        ns_pid = (gint32)tmp_int;
        proto_tree_add_int(tracee_network_capture_tree, hf_process_id, tvb, 0, 0, ns_pid);
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
        proto_tree_add_int(tracee_network_capture_tree, hf_host_parent_process_id, tvb, 0, 0, ppid);
        proto_item_append_text(tracee_network_capture_item, ", PPID = %d", ppid);
    }

    // add NS PPID
    if (json_get_int(if_descr, root_tok, "ns_ppid", &tmp_int)) {
        ns_ppid = (gint32)tmp_int;
        proto_tree_add_int(tracee_network_capture_tree, hf_parent_process_id, tvb, 0, 0, ns_ppid);
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
        proto_tree_add_string(tracee_network_capture_tree, hf_process_name, tvb, 0, 0, tmp_str);
        proto_item_append_text(tracee_network_capture_item, ", Name = %s", tmp_str);
    }

    // add container ID
    if ((container_id = json_get_string(if_descr, root_tok, "container_id")) != NULL)
        proto_tree_add_string(tracee_network_capture_tree, hf_container_id, tvb, 0, 0, container_id);
    
    // add container name
    if ((tmp_str = json_get_string(if_descr, root_tok, "container_name")) != NULL)
        proto_tree_add_string(tracee_network_capture_tree, hf_container_name, tvb, 0, 0, tmp_str);
    
    // add container image
    if ((container_image = json_get_string(if_descr, root_tok, "container_image")) != NULL)
        proto_tree_add_string(tracee_network_capture_tree, hf_container_image, tvb, 0, 0, container_image);
    
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
        proto_tree_add_string(tracee_network_capture_tree, hf_k8s_pod_name, tvb, 0, 0, tmp_str);
    
    // add k8s pod namesapce
    if ((tmp_str = json_get_string(if_descr, root_tok, "k8s_pod_namespace")) != NULL)
        proto_tree_add_string(tracee_network_capture_tree, hf_k8s_pod_namespace, tvb, 0, 0, tmp_str);
    
    // add k8s pod UID
    if ((tmp_str = json_get_string(if_descr, root_tok, "k8s_pod_uid")) != NULL)
        proto_tree_add_string(tracee_network_capture_tree, hf_k8s_pod_uid, tvb, 0, 0, tmp_str);

call_original_dissector:
    return call_dissector_only(null_dissector, tvb, pinfo, tree, data);
}

void proto_register_tracee_network_capture(void)
{
    static gint *ett[] = {
        &ett_tracee_network_capture
    };

    proto_tracee_network_capture = proto_register_protocol("Tracee Network Capture", "TRACEE-NETWORK-CAPTURE", "tracee-network-capture");
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_tracee_network_capture(void)
{
    static dissector_handle_t tracee_network_capture_handle;

    tracee_network_capture_handle = create_dissector_handle(dissect_tracee_network_capture, proto_tracee_network_capture);
    
    // override the Null/Loopback dissector's registration, so we can perform our dissection before it is invoked
    dissector_add_uint("wtap_encap", WTAP_ENCAP_NULL, tracee_network_capture_handle);

    // get hf id for tracee event fields we need
    hf_process_id = proto_registrar_get_id_byname("tracee.processId");
    hf_parent_process_id = proto_registrar_get_id_byname("tracee.parentProcessId");
    hf_host_process_id = proto_registrar_get_id_byname("tracee.hostProcessId");
    hf_pid_col = proto_registrar_get_id_byname("tracee.pid_col");
    hf_ppid_col = proto_registrar_get_id_byname("tracee.ppid_col");
    hf_host_parent_process_id = proto_registrar_get_id_byname("tracee.hostParentProcessId");
    hf_process_name = proto_registrar_get_id_byname("tracee.processName");
    hf_container_id = proto_registrar_get_id_byname("tracee.container.id");
    hf_container_name = proto_registrar_get_id_byname("tracee.container.name");
    hf_container_image = proto_registrar_get_id_byname("tracee.container.image");
    hf_container_col = proto_registrar_get_id_byname("tracee.container_col");
    hf_k8s_pod_name = proto_registrar_get_id_byname("tracee.kubernetes.podName");
    hf_k8s_pod_namespace = proto_registrar_get_id_byname("tracee.kubernetes.podNamespace");
    hf_k8s_pod_uid = proto_registrar_get_id_byname("tracee.kubernetes.podUID");
}

#ifdef WIRESHARK_PLUGIN_REGISTER // new plugin API
static void plugin_register(void)
#else
void plugin_register(void)
#endif
{
    static proto_plugin plugin;

    plugin.register_protoinfo = proto_register_tracee_network_capture;
    plugin.register_handoff = proto_reg_handoff_tracee_network_capture;
    proto_register_plugin(&plugin);
}

#ifdef WIRESHARK_PLUGIN_REGISTER // new plugin API
static struct ws_module module = {
    .flags = WS_PLUGIN_DESC_DISSECTOR,
    .version = VERSION,
    .spdx_id = "GPL-2.0-or-later",
    .home_url = "",
    .blurb = "Tracee network capture dissector",
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