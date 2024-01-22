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

enum arg_type {
    ARG_S32,
    ARG_U32,
    ARG_S64,
    ARG_U64,
    ARG_BOOLEAN,
    ARG_STR
};

struct saved_arg {
    enum arg_type type;
    union {
        gint32 s32;
        guint32 u32;
        gint64 s64;
        guint64 u64;
        bool boolean;
        gchar *str;
    } val;
};

void saved_args_add(hf_register_info *hf, struct saved_arg val);
wmem_array_t *saved_args_get(const gchar *filter_name);
struct saved_arg *saved_args_get_one(const gchar *filter_name);
const gchar *saved_args_get_str(const gchar *filter_name);

wmem_array_t *extract_values(proto_tree *tree, int hf_id);
fvalue_t *extract_single_value(proto_tree *tree, int hf_id);
const char *extract_str(proto_tree *tree, int hf_id);

void register_tracee_postdissectors(int proto);
void register_tracee_postdissectors_wanted_fields(void);