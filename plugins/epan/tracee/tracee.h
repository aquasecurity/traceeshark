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