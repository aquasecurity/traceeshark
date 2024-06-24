#include <stdbool.h>
#include <glib.h>

#include <wsutil/wsjson.h>
#include <ws_version.h>

enum pid_format {
    PID_FORMAT_CONTAINER_ONLY = 0,
    PID_FORMAT_HOST_ONLY,
    PID_FORMAT_BOTH,
};
enum container_identifier {
    CONTAINER_IDENTIFIER_ID = 0,
    CONTAINER_IDENTIFIER_NAME,
};

jsmntok_t *json_get_next_object(jsmntok_t *cur);
bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val);
bool json_get_null(char *buf, jsmntok_t *parent, const char *name);
bool json_get_int_or_null(char *buf, jsmntok_t *parent, const char *name, gint64 *val);
#if ((WIRESHARK_VERSION_MAJOR < 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR < 3)))
bool json_get_boolean(char *buf, jsmntok_t *parent, const char *name, bool *val);
#endif