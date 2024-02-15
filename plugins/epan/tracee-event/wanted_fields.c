#include "tracee.h"

wmem_map_t *wanted_fields = NULL;
wmem_map_t *wanted_field_values = NULL;

static void free_values_cb(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
    fvalue_t *fv;
    guint i;
    wmem_array_t *arr = (wmem_array_t *)value;

    for (i = 0; i < wmem_array_get_count(arr); i++) {
        fv = *((fvalue_t **)wmem_array_index(arr, i));
        fvalue_free(fv);
    }
}

static bool wanted_field_values_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
    wmem_map_foreach(wanted_field_values, free_values_cb, NULL);

    // return TRUE so this callback isn't unregistered
    return TRUE;
}

void register_wanted_field(const gchar *filter_name)
{
    gchar *key;

    ws_info("registering wanted field %s", filter_name);

    // make sure wanted fields map exists
    if (wanted_fields == NULL) {
        wanted_fields = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wanted_field_values = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_str_hash, g_str_equal);
        wmem_register_callback(wmem_packet_scope(), wanted_field_values_destroy_cb, NULL);
    }

    // check if this field was already registered
    if (wmem_map_contains(wanted_fields, filter_name))
        return;
    
    // add field to wanted fields map
    key = wmem_strdup(wmem_epan_scope(), filter_name);
    wmem_map_insert(wanted_fields, key, NULL);
}

wmem_array_t *wanted_field_get(const gchar *filter_name)
{
    return wmem_map_lookup(wanted_field_values, filter_name);
}

fvalue_t *wanted_field_get_one(const gchar *filter_name)
{
    wmem_array_t *values = wanted_field_get(filter_name);

    if (values && wmem_array_get_count(values) >= 1)
        return *((fvalue_t **)wmem_array_index(values, 0));
    
    return NULL;
}

const gchar *wanted_field_get_str(const gchar *filter_name)
{
    fvalue_t *fv;

    if ((fv = wanted_field_get_one(filter_name)) == NULL)
        return NULL;
    
    return fvalue_get_string(fv);
}

static gboolean field_is_wanted(header_field_info *hf)
{
    // make sure wanted fields map exists
    if (wanted_fields == NULL || wanted_field_values == NULL)
        return FALSE;
    
    // make sure this field has a filter string (registrations are based off this string)
    if (!hf || !hf->abbrev)
        return FALSE;
    
    // check if there is a subscription for this field
    return wmem_map_contains(wanted_fields, hf->abbrev);
}

#define handle_wanted_field(hfindex, value, fvalue_set_func) { \
    /* get field info */ \
    header_field_info *_hf = proto_registrar_get_nth(hfindex); \
    \
    /* make sure this field is registered */ \
    if (field_is_wanted(_hf)) { \
        \
        /* create value */ \
        fvalue_t *_fv = fvalue_new(_hf->type); \
        fvalue_set_func(_fv, value); \
        \
        /* check if a value for this field was added already */ \
        wmem_array_t *_values = wmem_map_lookup(wanted_field_values, _hf->abbrev); \
        \
        /* lookup succeeded - add this value to the value list for this field */ \
        if (_values) \
            wmem_array_append_one(_values, _fv); \
        /* lookup failed - create new value array and insert it into the values map */ \
        else { \
            _values = wmem_array_new(wmem_packet_scope(), sizeof(fvalue_t *)); \
            wmem_array_append_one(_values, _fv); \
            wmem_map_insert(wanted_field_values, _hf->abbrev, _values); \
        } \
    } \
}

proto_item *proto_tree_add_int_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value)
{
    handle_wanted_field(hfindex, value, fvalue_set_sinteger);
    return proto_tree_add_int(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_uint_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{    
    handle_wanted_field(hfindex, value, fvalue_set_uinteger);
    return proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_int64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value)
{
    handle_wanted_field(hfindex, value, fvalue_set_sinteger64);
    return proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_uint64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value)
{
    handle_wanted_field(hfindex, value, fvalue_set_uinteger64);
    return proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_string_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value)
{
    handle_wanted_field(hfindex, value, fvalue_set_string);
    return proto_tree_add_string(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_boolean_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{
    handle_wanted_field(hfindex, value, fvalue_set_uinteger64);
    return proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
}