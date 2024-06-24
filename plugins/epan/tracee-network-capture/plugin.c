#define WS_BUILD_DLL

#include <wsutil/plugins.h>
#include <epan/proto.h>
#include <ws_version.h>

extern void proto_register_tracee_network_capture(void);
extern void proto_reg_handoff_tracee_network_capture(void);

#ifndef WIRESHARK_PLUGIN_REGISTER // old plugin API
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif
WS_DLL_PUBLIC void plugin_register(void)
#else // new plugin API
static void plugin_register(void)
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
    .version = PLUGIN_VERSION,
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