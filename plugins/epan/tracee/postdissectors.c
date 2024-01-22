#include <epan/packet.h>
#include "tracee.h"

static dissector_handle_t event_postdissector;

typedef enum {
    HF_INTEREST_EVENT_NAME = 0,

    HF_INTEREST_END_OF_LIST
} ehf_of_interest;

typedef struct _HF_OF_INTEREST_INFO
{
    int hf;
    const char *filter_name;

} HF_OF_INTEREST_INFO;

HF_OF_INTEREST_INFO hf_of_interest[HF_INTEREST_END_OF_LIST] = {
    { -1, "tracee.eventName" }
};

wmem_map_t *event_postdissectors;

static int dissect_sig_machine_fingerprint(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *file_path;

    if ((file_path = saved_args_get_str("tracee.args.File_path")) != NULL)
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s was opened", file_path);
    
    return 0;
}

static int postdissect_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const char *event_name;
    dissector_t dissector;

    event_name = extract_str(tree, hf_of_interest[HF_INTEREST_EVENT_NAME].hf);
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

static void init_wanted_fields(void)
{
    GArray *wanted_fields;

    wanted_fields = g_array_sized_new(FALSE, FALSE, (guint)sizeof(int), HF_INTEREST_END_OF_LIST);
    for (int i = 0; i < HF_INTEREST_END_OF_LIST; i++)
    {
        if (hf_of_interest[i].hf != -1)
            g_array_append_val(wanted_fields, hf_of_interest[i].hf);
        else
            ws_warning("Tracee: unknown field %s", hf_of_interest[i].filter_name);
    }
    set_postdissector_wanted_hfids(event_postdissector, wanted_fields);
}

static void cleanup_wanted_fields(void)
{
    /* Clear the list of wanted fields as it will be reinitialized. */
    set_postdissector_wanted_hfids(event_postdissector, NULL);
}

void register_tracee_postdissectors(int proto)
{
    event_postdissector = register_dissector("tracee-event-postdissector", postdissect_event, proto);

    register_init_routine(init_wanted_fields);
    register_cleanup_routine(cleanup_wanted_fields);

    register_postdissector(event_postdissector);

    event_postdissectors = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);

    register_tracee_event_postdissector("sig_machine_fingerprint", dissect_sig_machine_fingerprint);
}

void register_tracee_postdissectors_wanted_fields(void)
{
    int i;

    /* Get the field id for each field we will need */
    for (i = 0; i < HF_INTEREST_END_OF_LIST; i++)
        hf_of_interest[i].hf = proto_registrar_get_id_byname(hf_of_interest[i].filter_name);
}