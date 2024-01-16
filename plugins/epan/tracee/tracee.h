#include <epan/packet.h>
#include <wsutil/wsjson.h>

extern int hf_host_process_id;

extern const value_string ipproto_val[];
extern value_string_ext dns_types_vals_ext;
extern const value_string dns_classes[];

jsmntok_t *json_get_next_object(jsmntok_t *cur);
bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val);
bool json_get_null(char *buf, jsmntok_t *parent, const char *name);
bool json_get_int_or_null(char *buf, jsmntok_t *parent, const char *name, gint64 *val);