#include <epan/packet.h>

extern const value_string ipproto_val[];
extern value_string_ext dns_types_vals_ext;
extern const value_string dns_classes[];

void register_wanted_field(const gchar *filter_name);
wmem_array_t *wanted_field_get(const gchar *filter_name);
fvalue_t *wanted_field_get_one(const gchar *filter_name);
const gchar *wanted_field_get_str(const gchar *filter_name);

proto_item *proto_tree_add_int_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value);
proto_item *proto_tree_add_uint_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *proto_tree_add_int64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value);
proto_item *proto_tree_add_uint64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value);
proto_item *proto_tree_add_string_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value);
proto_item *proto_tree_add_boolean_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);

void register_tracee_postdissectors(int proto);
void register_tracee_postdissectors_wanted_fields(void);