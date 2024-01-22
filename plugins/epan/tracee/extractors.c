#include "tracee.h"

wmem_map_t *saved_args = NULL;

void saved_args_add(hf_register_info *hf, struct saved_arg saved_arg)
{
    wmem_array_t *values;

    // initialize map of saved args
    if (saved_args == NULL)
        saved_args = wmem_map_new_autoreset(wmem_epan_scope(), wmem_packet_scope(), g_str_hash, g_str_equal);
    
    // no saved value for this arg yet - create an array for the saved values
    if ((values = wmem_map_lookup(saved_args, hf->hfinfo.abbrev)) == NULL) {
        values = wmem_array_new(wmem_packet_scope(), sizeof(struct saved_arg));
        wmem_map_insert(saved_args, hf->hfinfo.abbrev, values);
    }

    wmem_array_append_one(values, saved_arg);
}

wmem_array_t *saved_args_get(const gchar *filter_name)
{
    if (saved_args == NULL)
        return NULL;
    
    return wmem_map_lookup(saved_args, filter_name);
}

struct saved_arg *saved_args_get_one(const gchar *filter_name)
{
    wmem_array_t *values;

    values = saved_args_get(filter_name);

    if (values == NULL)
        return NULL;
    
    if (wmem_array_get_count(values) == 0)
        return NULL;
    
    return wmem_array_index(values, 0);
}

const gchar *saved_args_get_str(const gchar *filter_name)
{
    struct saved_arg *arg;

    if ((arg = saved_args_get_one(filter_name)) == NULL)
        return NULL;
    
    if (arg->type != ARG_STR)
        return NULL;
    
    return arg->val.str;
}

wmem_array_t *extract_values(proto_tree *tree, int hf_id)
{
    GPtrArray *finfo_array;
    guint i, len;
    wmem_array_t *values;

    if (tree == NULL)
        return NULL;

    if ((finfo_array = proto_get_finfo_ptr_array(tree, hf_id)) == NULL)
        return NULL;

    len = g_ptr_array_len(finfo_array);
    values = wmem_array_sized_new(wmem_packet_scope(), sizeof(fvalue_t *), len);

    for (i = 0; i < len; i++)
        wmem_array_append_one(values, ((field_info *)finfo_array->pdata[i])->value);

    return values;
}

// TODO: extract only a single value instead of extracting all and returning only the first
fvalue_t *extract_single_value(proto_tree *tree, int hf_id)
{
    wmem_array_t *values;

    if ((values = extract_values(tree, hf_id)) == NULL)
        return NULL;
    
    if (wmem_array_get_count(values) == 0)
        return NULL;
    
    return *(fvalue_t **)wmem_array_index(values, 0);
}

const char *extract_str(proto_tree *tree, int hf_id)
{
    fvalue_t *fv;

    if ((fv = extract_single_value(tree, hf_id)) == NULL)
        return NULL;
    
    return fvalue_get_string(fv);
}