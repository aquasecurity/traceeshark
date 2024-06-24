#include <epan/packet.h>

extern const value_string ipproto_val[];
extern value_string_ext dns_types_vals_ext;
extern const value_string dns_classes[];

struct tracee_dissector_data {
    proto_tree *args_tree;
    const gchar *event_name;
    gboolean is_signature;
    gint32 signature_severity;
};

enum field_type {
    FIELD_TYPE_INT,
    FIELD_TYPE_UINT,
    FIELD_TYPE_INT64,
    FIELD_TYPE_UINT64,
    FIELD_TYPE_STRING,
    FIELD_TYPE_BOOLEAN
};

struct field_value {
    enum field_type type;
    union {
        gint val_int;
        guint val_uint;
        gint64 val_int64;
        guint64 val_uint64;
        gchar *val_string;
        gboolean val_boolean;
    } val;
};

void register_wanted_field(const gchar *filter_name);
wmem_array_t *wanted_field_get(const gchar *filter_name);
struct field_value *wanted_field_get_one(const gchar *filter_name);
const gchar *wanted_field_get_str(const gchar *filter_name);
gint *wanted_field_get_int(const gchar *filter_name);

proto_item *proto_tree_add_int_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value);
proto_item *proto_tree_add_uint_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *proto_tree_add_int64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value);
proto_item *proto_tree_add_uint64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value);
proto_item *proto_tree_add_string_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value);
proto_item *proto_tree_add_boolean_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);

void register_tracee_enrichments(int proto);
void register_tracee_statistics(void);