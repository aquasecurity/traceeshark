#include "tracee.h"

#include <wsutil/wslog.h>

wmem_map_t *wanted_fields = NULL;
wmem_map_t *wanted_field_values = NULL;

void register_wanted_field(const gchar *filter_name)
{
    gchar *key;

    // make sure wanted fields map exists
    if (wanted_fields == NULL) {
        wanted_fields = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
        wanted_field_values = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_str_hash, g_str_equal);
    }

    // check if this field was already registered
    if (wmem_map_contains(wanted_fields, filter_name))
        return;
    
    ws_info("registering wanted field %s", filter_name);
    
    // add field to wanted fields map
    key = wmem_strdup(wmem_epan_scope(), filter_name);
    wmem_map_insert(wanted_fields, key, NULL);
}

wmem_array_t *wanted_field_get(const gchar *filter_name)
{
    return wmem_map_lookup(wanted_field_values, filter_name);
}

struct field_value *wanted_field_get_one(const gchar *filter_name)
{
    wmem_array_t *values = wanted_field_get(filter_name);

    if (values && wmem_array_get_count(values) >= 1)
        return *((struct field_value **)wmem_array_index(values, 0));
    
    return NULL;
}

const gchar *wanted_field_get_str(const gchar *filter_name)
{
    struct field_value *fv;

    if ((fv = wanted_field_get_one(filter_name)) == NULL)
        return NULL;
    
    DISSECTOR_ASSERT(fv->type == FIELD_TYPE_STRING);
    return fv->val.val_string;
}

gint *wanted_field_get_int(const gchar *filter_name)
{
    struct field_value *fv;

    if ((fv = wanted_field_get_one(filter_name)) == NULL)
        return NULL;
    
    DISSECTOR_ASSERT(fv->type == FIELD_TYPE_INT);
    return &fv->val.val_int;
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

#define handle_wanted_field(hfindex, value, field_type, value_union_member) { \
    /* get field info */ \
    header_field_info *_hf = proto_registrar_get_nth(hfindex); \
    \
    /* make sure this field is registered */ \
    if (field_is_wanted(_hf)) { \
        \
        /* create value */ \
        struct field_value *_fv = wmem_new0(wmem_packet_scope(), struct field_value); \
        _fv->type = field_type; \
        _fv->val.value_union_member = value; \
        \
        /* check if a value for this field was added already */ \
        wmem_array_t *_values = wmem_map_lookup(wanted_field_values, _hf->abbrev); \
        \
        /* lookup succeeded - add this value to the value list for this field */ \
        if (_values) \
            wmem_array_append_one(_values, _fv); \
        /* lookup failed - create new value array and insert it into the values map */ \
        else { \
            _values = wmem_array_new(wmem_packet_scope(), sizeof(struct field_value *)); \
            wmem_array_append_one(_values, _fv); \
            wmem_map_insert(wanted_field_values, _hf->abbrev, _values); \
        } \
    } \
}

proto_item *proto_tree_add_int_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value)
{
    handle_wanted_field(hfindex, value, FIELD_TYPE_INT, val_int);
    return proto_tree_add_int(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_uint_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{    
    handle_wanted_field(hfindex, value, FIELD_TYPE_UINT, val_uint);
    return proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_int64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value)
{
    handle_wanted_field(hfindex, value, FIELD_TYPE_INT64, val_int64);
    return proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_uint64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value)
{
    handle_wanted_field(hfindex, value, FIELD_TYPE_UINT64, val_uint64);
    return proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_string_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value)
{
    handle_wanted_field(hfindex, wmem_strdup(wmem_packet_scope(), value), FIELD_TYPE_STRING, val_string);
    return proto_tree_add_string(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_boolean_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value)
{
    handle_wanted_field(hfindex, value, FIELD_TYPE_BOOLEAN, val_boolean);
    return proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
}

proto_item *proto_tree_add_double_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, double value)
{
    handle_wanted_field(hfindex, value, FIELD_TYPE_DOUBLE, val_double);
    return proto_tree_add_double(tree, hfindex, tvb, start, length, value);
}