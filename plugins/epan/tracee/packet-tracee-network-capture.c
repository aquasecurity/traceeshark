#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/wsjson.h>

#include "tracee.h"

static int proto_tracee_network_capture = -1;

static gint ett_tracee_network_capture = -1;

static int dissect_null_override(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dissector_handle_t null_dissector;
    proto_tree *tracee_network_capture_tree;
    proto_item *tracee_network_capture_item;
    guint section_number;
    char *if_descr;
    int num_toks;
    jsmntok_t *root_tok;
    gint64 tmp_int;
    
    DISSECTOR_ASSERT_HINT((null_dissector = find_dissector("null")) != NULL, "Cannot find Null/Loopback dissector");

    // create tracee network capture tree
    tracee_network_capture_item = proto_tree_add_item(tree, proto_tracee_network_capture, tvb, 0, -1, ENC_NA);
    tracee_network_capture_tree = proto_item_add_subtree(tracee_network_capture_item, ett_tracee_network_capture);

    section_number = pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0;
    if_descr = wmem_strdup(pinfo->pool, epan_get_interface_description(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id, section_number));

    if (!json_validate(if_descr, strlen(if_descr)))
        goto call_original_dissector;
    
    num_toks = json_parse(if_descr, NULL, 0);
    DISSECTOR_ASSERT_HINT(num_toks > 0, "JSON decode error: non-positive num_toks");

    root_tok = wmem_alloc_array(pinfo->pool, jsmntok_t, num_toks);
    if (json_parse(if_descr, root_tok, num_toks) <= 0)
        DISSECTOR_ASSERT_NOT_REACHED();
    
    if (json_get_int(if_descr, root_tok, "pid", &tmp_int)) {
        proto_tree_add_int(tracee_network_capture_tree, hf_host_process_id, tvb, 0, 0, (gint32)tmp_int);
        proto_item_append_text(tracee_network_capture_item, ": PID = %d", (gint32)tmp_int);
    }

call_original_dissector:
    return call_dissector_only(null_dissector, tvb, pinfo, tree, data);
}

void proto_register_null_override(void)
{
    static gint *ett[] = {
        &ett_tracee_network_capture
    };

    proto_tracee_network_capture = proto_register_protocol("Tracee Network Capture", "TRACEE-NETWORK-CAPTURE", "tracee-network-capture");
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_null_override(void)
{
    static dissector_handle_t tracee_network_capture_handle;

    tracee_network_capture_handle = create_dissector_handle(dissect_null_override, proto_tracee_network_capture);
    
    // override the Null/Loopback dissector's registration, so we can perform our dissection before it is invoked
    dissector_add_uint("wtap_encap", WTAP_ENCAP_NULL, tracee_network_capture_handle);
}