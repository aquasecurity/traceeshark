#include <errno.h>

#include "common.h"

#include <wsutil/wsjson.h>

/*
 * From wsutil/jsmn.c
 */
jsmntok_t *json_get_next_object(jsmntok_t *cur)
{
    int i;
    jsmntok_t *next = cur+1;

    for (i = 0; i < cur->size; i++) {
        next = json_get_next_object(next);
    }
    return next;
}

/**
 * Get the value of a number object belonging to parent object and named as the name variable.
 * Returns FALSE if not found. Caution: it modifies input buffer.
 */
bool json_get_int(char *buf, jsmntok_t *parent, const char *name, gint64 *val)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_PRIMITIVE) {
            buf[(cur+1)->end] = '\0';
            errno = 0;
            *val = (gint64)strtoull(&buf[(cur+1)->start], NULL, 10);
            if (errno != 0)
                return false;
            return true;
        }
        cur = json_get_next_object(cur);
    }
    return false;
}

/**
 * Get a null object belonging to parent object and named as the name variable.
 * Returns FALSE if not found or the object is not a null. Caution: it modifies input buffer.
 */
bool json_get_null(char *buf, jsmntok_t *parent, const char *name)
{
    int i;
    size_t tok_len;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_PRIMITIVE) {
            /* JSMN_STRICT guarantees that a primitive starts with the
             * correct character.
             */
            tok_len = (cur+1)->end - (cur+1)->start;
            if (tok_len == 4 && strncmp(&buf[(cur+1)->start], "null", tok_len) == 0)
                return true;
            return false;
        }
        cur = json_get_next_object(cur);
    }
    return false;
}

bool json_get_int_or_null(char *buf, jsmntok_t *parent, const char *name, gint64 *val)
{
    return json_get_int(buf, parent, name, val) ? true : json_get_null(buf, parent, name);
    
}

#if ((WIRESHARK_VERSION_MAJOR < 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR < 3)))
bool json_get_boolean(char *buf, jsmntok_t *parent, const char *name, bool *val)
{
    int i;
    size_t tok_len;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_PRIMITIVE) {
            /* JSMN_STRICT guarantees that a primitive starts with the
             * correct character.
             */
            tok_len = (cur+1)->end - (cur+1)->start;
            switch (buf[(cur+1)->start]) {
            case 't':
                if (tok_len == 4 && strncmp(&buf[(cur+1)->start], "true", tok_len) == 0) {
                    *val = true;
                    return true;
                }
                return false;
            case 'f':
                if (tok_len == 5 && strncmp(&buf[(cur+1)->start], "false", tok_len) == 0) {
                    *val = false;
                    return true;
                }
                return false;
            default:
                return false;
            }
        }
        cur = json_get_next_object(cur);
    }
    return false;
}
#endif