#include "wtap-int.h"
#include "file_wrappers.h"

static int tracee_json_file_type_subtype;

int tracee_json_get_file_type_subtype(void)
{
    return tracee_json_file_type_subtype;
}

struct tracee_json {
    /*
     * Event timestamps are stored inside the JSON data, which requires some (costly) parsing to retrieve.
     * We parse the timestamps only once, so that they can be accessed directly when the event is retrieved again.
     */
    GHashTable *event_timestamps;
};

/**
 * TODO: this line reading method may be bad for performance, consider a buffer read approach.
 * Read a line from a file.
 * The string is allocated by this function,
 * and the caller is responsible for freeing it.
 * Any read failure, including not finding a null-terminator
 * after reading the specified max number of bytes,
 * will result in a NULL being returned.
 * Specifying a max_read of 0 means no limit.
*/
static gchar *file_gets_line(FILE_T file, gsize max_read)
{
    // no read limit
    if (max_read == 0)
        max_read = (gsize)-1;

    // start with a 1024-byte allocation
    gsize current_size = 1024;
    gchar *buf = g_malloc(current_size);

    int tmp;
    gsize offset = 0;

    while (offset < max_read)
    {
        // extend the buffer
        if (offset >= current_size) {
            // make sure we're not overflowing (if we are, something's seriously wrong)
            if (current_size >= (gsize)(1 << 31)) { /* check overflow against 32-bit size_t, for extra caution */
                g_free(buf);
                return NULL;
            }
            current_size *= 2;
            buf = g_realloc(buf, current_size);
        }

        tmp = file_getc(file);

        buf[offset++] = (char)tmp;

        // newline or null-terminator found or failed to read (EOF)
        if (tmp == '\n' || tmp == 0 || tmp == -1)
            break;
    }

    // nothing was read - we were at the EOF already
    if (offset == 1)
        goto fail;

    // no newline or null-terminator found
    if (offset == max_read && buf[offset - 1] != '\n' && buf[offset -1] != 0 && (int)buf[offset - 1] != -1)
        goto fail;

    // replace trailing newline or EOF marker with null-terminator
    if (buf[offset - 1] == '\n' || (int)buf[offset -1] == -1)
        buf[offset -1] = 0;
    
    // line may have a linefeed preceding the newline, replace with null-terminator
    if (buf[offset - 2] == '\r')
        buf[offset - 2] = 0;

    return buf;

fail:
    g_free(buf);
    return NULL;
}

/**
 * Parse the timestamp manually because parsing the JSON is very expensive.
 */
static nstime_t *parse_ts(char *event)
{
    // Event should start like this: {"timestamp":1704197356801892470,....
    // so timestamp is assumed to start at index 13
    gsize ts_start = 13;
    gint64 ts_int;
    nstime_t *ts;

    // skip any whitespace
    while (event[ts_start] == ' ')
        ts_start++;
    
    // make sure this is a digit
    if (event[ts_start] < '0' || event[ts_start] > '9')
        return NULL;
    
    // parse the timestamp to an int
    errno = 0;
    ts_int = g_ascii_strtoll(event + ts_start, NULL, 10);
    if (errno != 0)
        return NULL;
    
    ts = g_new(nstime_t, 1);
    
    // timestamp assumed to be in nanoseconds
    ts->secs = (time_t)(ts_int / 1000000000);
    ts->nsecs = (int)(ts_int % 1000000000);

    return ts;
}

static gboolean tracee_json_read_event(FILE_T fh, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 offset, struct tracee_json *tracee_json)
{
    char *data, *data_copy = NULL;
    size_t len;
    nstime_t *ts;
    gint64 *key;
    gboolean res;

    // read lines from the log file until an event is found
    while (TRUE) {
        // read a line
        ws_info("reading line at offset 0x%08" PRIx64, offset);
        if ((data = file_gets_line(fh, 0)) == NULL)
            return FALSE;
        
        // tracee events start with {"timestamp":
        if (strncmp(data, "{\"timestamp\":", 13) == 0)
            break;
        
        offset = file_tell(fh);
    }

    ws_info("found an event");

    // try retrieving timestamp from hash table
    if ((ts = g_hash_table_lookup(tracee_json->event_timestamps, &offset)) == NULL) {
        // timestamp not saved yet - parse it
        data_copy = g_strdup(data);
        if ((ts = parse_ts(data_copy)) == NULL) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("cannot parse timestamp from event at offset 0x%08" PRIx64, offset);
            res = FALSE;
            goto cleanup;
        }

        // insert timestamp into hash table
        key = g_new(gint64, 1);
        *key = offset;
        g_hash_table_insert(tracee_json->event_timestamps, key, ts);
    }

    // copy event data to buffer
    len = strlen(data);
    ws_buffer_assure_space(buf, len);
    memcpy(ws_buffer_start_ptr(buf), data, len);

    // set up record
    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->rec_header.packet_header.caplen = (guint32)len;
	rec->rec_header.packet_header.len = (guint32)len;

    rec->ts.secs = ts->secs;
    rec->ts.nsecs = ts->nsecs;
    rec->presence_flags = WTAP_HAS_TS;

    res = TRUE;

cleanup:
    g_free(data);
    if (data_copy != NULL)
        g_free(data_copy);
    
    return res;
}

static gboolean
tracee_json_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
             gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return tracee_json_read_event(wth->fh, rec, buf, err, err_info, *data_offset, wth->priv);
}

static gboolean
tracee_json_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
                  Buffer *buf, int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;
    
    return tracee_json_read_event(wth->random_fh, rec, buf, err, err_info, seek_off, wth->priv);
}

/**
 * Free all the allocations we made.
 * The allocation we made for struct tracee_json, referenced by wth->priv,
 * is freed automatically by Wireshark.
*/
static void tracee_json_close(wtap *wth)
{
    struct tracee_json *tracee_json = (struct tracee_json *)wth->priv;

    g_hash_table_destroy(tracee_json->event_timestamps);
}

static wtap_open_return_val
tracee_json_open(wtap *wth, int *err, char **err_info)
{
    char buf[13]; // enough to hold {"timestamp":
    struct tracee_json *tracee_json;

    // assume the file is ours if it starts with an opening bracket (TODO: find a better way to determine if this is a tracee json log)
    if (!wtap_read_bytes(wth->fh, &buf, sizeof(buf), err, err_info)) {
        // EOF
        if (*err == 0)
            return WTAP_OPEN_NOT_MINE;
        return WTAP_OPEN_ERROR;
    }

    // compare beginning of file to the beginning of the 2 possible JSON types (events and logs)
    if (strncmp(buf, "{\"level\":", 9) != 0 && strncmp(buf, "{\"timestamp\":", 13) != 0) {
        ws_warning("not ours");
        return WTAP_OPEN_NOT_MINE;
    }
    
    ws_info("file starts with '{\"level\":' or with '{\"timestamp\":', assuming it's a tracee json log");

    // seek back to the beginning of the file
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;
    
    tracee_json = g_new0(struct tracee_json, 1);
    tracee_json->event_timestamps = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);

    wth->file_type_subtype = tracee_json_file_type_subtype;
    wth->subtype_read = tracee_json_read;
    wth->subtype_seek_read = tracee_json_seek_read;
    wth->subtype_close = tracee_json_close;
    wth->file_encap = WTAP_ENCAP_USER0;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->snapshot_length = 0;
    wth->priv = tracee_json;

    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/*
 * Register with wiretap.
 * Register how we can handle an unknown file to see if this is a valid
 * usbdump file and register information about this file format.
 */
static const struct supported_block_type tracee_json_blocks_supported[] = {
    /* We support packet blocks, with no comments or other options. */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};
static const struct file_type_subtype_info tracee_json_info = {
    "Tracee JSON Log",
    "tracee-json",
    "log",
    "json",
    FALSE,
    BLOCKS_SUPPORTED(tracee_json_blocks_supported),
    NULL,
    NULL,
    NULL
};

void
wtap_register_tracee_json(void)
{
    struct open_info oi = {
        "Tracee JSON",
        OPEN_INFO_MAGIC,
        tracee_json_open,
        NULL,
        NULL,
        NULL
    };

    wtap_register_open_info(&oi, FALSE);

    tracee_json_file_type_subtype = wtap_register_file_type_subtype(&tracee_json_info);
}