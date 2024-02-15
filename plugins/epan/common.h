#include <wsutil/wsjson.h>

jsmntok_t *json_get_next_object(jsmntok_t *cur);
bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val);
bool json_get_null(char *buf, jsmntok_t *parent, const char *name);
bool json_get_int_or_null(char *buf, jsmntok_t *parent, const char *name, gint64 *val);