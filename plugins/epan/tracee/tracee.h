#include <epan/packet.h>
#include <wsutil/wsjson.h>

extern int hf_process_id;
extern int hf_host_process_id;
extern int hf_parent_process_id;
extern int hf_host_parent_process_id;
extern int hf_process_name;
extern int hf_container_id;
extern int hf_container_name;
extern int hf_container_image;
extern int hf_k8s_pod_name;
extern int hf_k8s_pod_namespace;
extern int hf_k8s_pod_uid;
extern int hf_pid_col;
extern int hf_ppid_col;
extern int hf_container_col;

extern const value_string ipproto_val[];
extern value_string_ext dns_types_vals_ext;
extern const value_string dns_classes[];

jsmntok_t *json_get_next_object(jsmntok_t *cur);
bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val);
bool json_get_null(char *buf, jsmntok_t *parent, const char *name);
bool json_get_int_or_null(char *buf, jsmntok_t *parent, const char *name, gint64 *val);

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