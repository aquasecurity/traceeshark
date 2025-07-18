#include <epan/packet.h>

extern const value_string ipproto_val[];
extern value_string_ext dns_types_vals_ext;
extern const value_string dns_classes[];

extern gint preferences_pid_format;
extern gint preferences_container_identifier;
#if ((WIRESHARK_VERSION_MAJOR > 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR >= 3)))
extern bool preferences_show_container_image;
extern bool preferences_include_unix_sockets;
extern bool preferences_exclude_nscd_socket;
#else
extern gboolean preferences_show_container_image;
extern gboolean preferences_include_unix_sockets;
extern gboolean preferences_exclude_nscd_socket;
#endif

struct container_info {
    const char *id;
    const char *name;
    const char *image;
};

struct process_info {
    gint32 pid;
    gint32 host_pid;
    gint32 ppid;
    gint32 host_ppid;
    const char *name;
    const char *exec_path;
    const char *command_line;
    struct container_info *container;
};

struct tracee_dissector_data {
    proto_tree *args_tree;
    const gchar *event_name;
    gboolean is_signature;
    gint32 signature_severity;
    const gchar *signature_name;
    tvbuff_t *packet_tvb;
    struct process_info *process;
};

enum field_type {
    FIELD_TYPE_INT,
    FIELD_TYPE_UINT,
    FIELD_TYPE_INT64,
    FIELD_TYPE_UINT64,
    FIELD_TYPE_STRING,
    FIELD_TYPE_BOOLEAN,
    FIELD_TYPE_DOUBLE,
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
        double val_double;
    } val;
};

void register_wanted_field(const gchar *filter_name);
const wmem_array_t *wanted_field_get(const gchar *filter_name);
const struct field_value *wanted_field_get_one(const gchar *filter_name);
const gchar *wanted_field_get_str(const gchar *filter_name);
const gint *wanted_field_get_int(const gchar *filter_name);

proto_item *proto_tree_add_int_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint32 value);
proto_item *proto_tree_add_uint_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *proto_tree_add_int64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value);
proto_item *proto_tree_add_uint64_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint64 value);
proto_item *proto_tree_add_string_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, const char* value);
proto_item *proto_tree_add_boolean_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, guint32 value);
proto_item *proto_tree_add_double_wanted(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, double value);

gchar *enrichments_get_security_socket_bind_connect_description(packet_info *pinfo, const gchar *verb);

void process_tree_init(void);
void process_tree_update(struct tracee_dissector_data *data);
struct process_info *process_tree_get_process(gint32 pid);
struct process_info *process_tree_get_parent(gint32 pid);

void register_tracee_enrichments(int proto);
void register_tracee_statistics(void);