#include <ctype.h>

#include <epan/packet.h>
#include "tracee.h"

static int hf_decoded_data = -1;
static int hf_file_type = -1;
static int hf_ptrace_request = -1;

static int enrich_sched_process_exec(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
    const gchar *pathname, *cmdline, *prev_comm;
    struct tracee_dissector_data *dissector_data = (struct tracee_dissector_data *)data;

    pathname = wanted_field_get_str("tracee.args.sched_process_exec.pathname");
    cmdline = wanted_field_get_str("tracee.args.command_line");
    prev_comm = wanted_field_get_str("tracee.args.sched_process_exec.prev_comm");

    dissector_data->process->exec_path = pathname;
    dissector_data->process->command_line = cmdline;

    if (pathname && cmdline) {
        if (strncmp(pathname, cmdline, strlen(pathname)) == 0)
            col_add_str(pinfo->cinfo, COL_INFO, cmdline);
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", pathname, cmdline);
    }

    if (prev_comm)
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "(%s) -> ", prev_comm);

    return 0;
}

static int enrich_net_packet_http_request(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *method, *protocol, *uri_path, *content_type;

    method = wanted_field_get_str("tracee.proto_http_request.method");
    protocol = wanted_field_get_str("tracee.proto_http_request.protocol");
    uri_path = wanted_field_get_str("tracee.proto_http_request.uri_path");

    if (!method || !protocol || !uri_path)
        return 0;
    
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s %s", method, uri_path, protocol);
    
    if (strcmp(method, "POST") && ((content_type = wanted_field_get_str("http.content_type")) != NULL))
        col_append_fstr(pinfo->cinfo, COL_INFO, "  (%s)", content_type);

    return 0;
}

static int enrich_net_packet_http(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *direction, *method, *protocol, *uri_path, *content_type, *status;
    gchar *tmp, *content_type_short = NULL;
    gboolean request;

    direction = wanted_field_get_str("tracee.proto_http.direction");
    if (direction == NULL)
        return 0;
    if (strcmp(direction, "request") == 0)
        request = TRUE;
    else if (strcmp(direction, "response") == 0)
        request = FALSE;
    else
        return 0;
    
    protocol = wanted_field_get_str("tracee.proto_http.protocol");
    content_type = wanted_field_get_str("http.content_type");

    // discard semicolon in content type
    if (content_type != NULL) {
        content_type_short = wmem_strdup(pinfo->pool, content_type);
        tmp = strchr(content_type_short, ';');
        if (tmp != NULL)
            *tmp = '\0';
    }

    if (request) {
        method = wanted_field_get_str("tracee.proto_http.method");
        uri_path = wanted_field_get_str("tracee.proto_http.uri_path");

        if (!method || !protocol || !uri_path)
            return 0;
        
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s %s", method, uri_path, protocol);
        
        if (content_type_short != NULL)
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", content_type_short);
    }

    else {
        status = wanted_field_get_str("tracee.proto_http.status");

        if (!protocol || !status)
            return 0;
        
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", protocol, status);

        if (content_type_short != NULL)
            col_append_fstr(pinfo->cinfo, COL_INFO, "  (%s)", content_type_short);
    }

    return 0;
}

gchar *enrichments_get_security_socket_bind_connect_description(packet_info *pinfo, const gchar *verb)
{
    const gchar *family, *addr, *port = NULL;

    if ((family = wanted_field_get_str("tracee.sockaddr.sa_family")) == NULL)
        return NULL;
    
    if (strcmp(family, "AF_INET") == 0) {
        addr = wanted_field_get_str("tracee.sockaddr.sin_addr");
        port = wanted_field_get_str("tracee.sockaddr.sin_port");
    }
    else if (strcmp(family, "AF_INET6") == 0) {
        addr = wanted_field_get_str("tracee.sockaddr.sin6_addr");
        port = wanted_field_get_str("tracee.sockaddr.sin6_port");
    }
    else if (strcmp(family, "AF_UNIX") == 0) {
        addr = wanted_field_get_str("tracee.sockaddr.sun_path");
    }
    else
        return NULL;
    
    if (addr) {
        if (port)
            return wmem_strdup_printf(pinfo->pool, "%s to %s port %s", verb, addr, port);
        else
            return wmem_strdup_printf(pinfo->pool, "%s to %s", verb, addr);
    }
    
    return NULL;
}

static int enrich_security_socket_bind_connect(packet_info *pinfo, const gchar *verb)
{
    gchar *description = enrichments_get_security_socket_bind_connect_description(pinfo,verb);

    if (description != NULL)
        col_add_str(pinfo->cinfo, COL_INFO, description);
    
    return 0;
}

static int enrich_security_socket_bind(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    return enrich_security_socket_bind_connect(pinfo, "Bind");
}

static int enrich_security_socket_connect(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    return enrich_security_socket_bind_connect(pinfo, "Connect");
}

static const gchar *get_mem_prot_alert_str(guint alert)
{
    switch (alert) {
        case 1:
            return "Mmaped region with W+E permissions!";
        case 2:
            return "Protection changed to Executable!";
        case 3:
            return "Protection changed from E to W+E!";
        case 4:
            return "Protection changed from W to E!";
        default:
            return "Unknown alert";
    }
}

static int enrich_dynamic_code_loading(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const struct field_value *alert;
    const gchar *alert_str = NULL;
    
    if ((alert = wanted_field_get_one("tracee.args.dynamic_code_loading.triggered_by.alert")) == NULL)
        return 0;
    
    if (alert->type == FIELD_TYPE_STRING)
        alert_str = alert->val.val_string;
    else if (alert->type == FIELD_TYPE_UINT)
        alert_str = get_mem_prot_alert_str(alert->val.val_uint);

    if (alert_str != NULL)
        col_append_str(pinfo->cinfo, COL_INFO, alert_str);
    
    return 0;
}

static int enrich_fileless_execution(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *pathname = wanted_field_get_str("tracee.args.fileless_execution.triggered_by.pathname");

    if (pathname)
        col_append_fstr(pinfo->cinfo, COL_INFO, "Running from %s", pathname);
    
    return 0;
}

static int enrich_stdio_over_socket(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gint *fd;
    const gchar *addr, *port, *stream;

    fd = wanted_field_get_int("tracee.args.stdio_over_socket.File_descriptor");
    addr = wanted_field_get_str("tracee.args.stdio_over_socket.IP_address");
    port = wanted_field_get_str("tracee.args.stdio_over_socket.Port");

    if (fd && addr && port) {
        switch (*fd) {
            case 0:
                stream = "STDIN";
                break;
            case 1:
                stream = "STDOUT";
                break;
            case 2:
                stream = "STDERR";
                break;
            default:
                return 0;
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s forwarded to %s port %s", stream, addr, port);
    }

    return 0;
}

static const char *stringify_decoded_data(packet_info *pinfo, guchar *decoded_data, gsize len)
{
    gsize i;
#if ((WIRESHARK_VERSION_MAJOR < 4) || ((WIRESHARK_VERSION_MAJOR == 4) && (WIRESHARK_VERSION_MINOR < 1)))
    wmem_strbuf_t *str = wmem_strbuf_sized_new(pinfo->pool, len, 0);
#else
    wmem_strbuf_t *str = wmem_strbuf_new_sized(pinfo->pool, len);
#endif

    for (i = 0; i < len; i++) {
        if (isprint(decoded_data[i]))
            wmem_strbuf_append_c(str, (char)decoded_data[i]);
        else {
            switch (decoded_data[i]) {
                case '\n':
                    wmem_strbuf_append(str, "\\n");
                    break;
                case '\r':
                    wmem_strbuf_append(str, "\\r");
                    break;
                case '\t':
                    wmem_strbuf_append(str, "\\t");
                    break;
                default:
                    wmem_strbuf_append_printf(str, "\\x%s%x", decoded_data[i] < 16 ? "0" : "", decoded_data[i]);
                    break;
            }
        }
    }

    return wmem_strbuf_get_str(str);
}

static const char *get_file_type_magic(const gchar *data)
{
    if (g_str_has_prefix(data, "\x7F" "ELF"))
        return "ELF";
    else if (g_str_has_prefix(data, "#!"))
        return "Script";
    else if (g_str_has_prefix(data, "\xED\xAB\xEE\xDB"))
        return "RPM package";
    else if (g_str_has_prefix(data, "!<arch>\x0A"))
        return "DEB package";
    else if (g_str_has_prefix(data, "<?php"))
        return "PHP script";
    else if (g_str_has_prefix(data, "<%@"))
        return "JSP script";
    else if (g_str_has_prefix(data, "<%"))
        return "ASP script";
    else if (g_str_has_prefix(data, "PK"))
        return "ZIP archive";
    else if (g_str_has_prefix(data, "\xCA\xFE\xBA\xBE"))
        return "Java class";
    else if (g_str_has_prefix(data, "\x33\x0D\x0A\x63"))
        return "Python compiled bytecode";
    else if (g_str_has_prefix(data, "MZ"))
        return "Windows executable/DLL";
    else if (g_str_has_prefix(data, "BZh"))
        return "BZIP2 archive";
    else if (g_str_has_prefix(data, "\x1F\x8B"))
        return "GZIP archive";
    else if (g_str_has_prefix(data, "ustar"))
        return "TAR archive";
    else if (g_str_has_prefix(data, "\x52\x61\x72\x21\x1A\x07"))
        return "RAR archive";
    else if (g_str_has_prefix(data, "\xFE\xED\xFA\xCE"))
        return "Mach-O 32-bit big-endian";
    else if (g_str_has_prefix(data, "\xCE\xFA\xED\xFE"))
        return "Mach-O 32-bit little-endian";
    else if (g_str_has_prefix(data, "\xFE\xED\xFA\xCF"))
        return "Mach-O 64-bit big-endian";
    else if (g_str_has_prefix(data, "\xCF\xFA\xED\xFE"))
        return "Mach-O 64-bit little-endian";
    else if (g_str_has_prefix(data, "REDIS"))
        return "Redis RDB";
    else if (g_str_has_prefix(data, "\xAC\xED"))
        return "Java serialized object";
    else if (g_str_has_prefix(data, "X50!P"))
        return "EICAR antivirus test file";
    
    return NULL;
}

static const char *get_file_type_extension(const char *file_path)
{
    if (g_str_has_suffix(file_path, ".tar"))
        return "TAR archive";
    else if (g_str_has_suffix(file_path, ".gz"))
        return "GZIP archive";
    else if (g_str_has_suffix(file_path, ".xz"))
        return "XZ archive";
    else if (g_str_has_suffix(file_path, ".bz2"))
        return "BZIP2 archive";
    else if (g_str_has_suffix(file_path, ".json"))
        return "JSON";
    else if (g_str_has_suffix(file_path, ".java"))
        return "Java source";
    else if (g_str_has_suffix(file_path, ".class"))
        return "Java class";
    else if (g_str_has_suffix(file_path, ".jar"))
        return "Java package";
    else if (g_str_has_suffix(file_path, ".war"))
        return "Java package";
    else if (g_str_has_suffix(file_path, ".pl"))
        return "Perl script";
    else if (g_str_has_suffix(file_path, ".py"))
        return "Python script";
    else if (g_str_has_suffix(file_path, ".pyc"))
        return "Python compiled bytecode";
    else if (g_str_has_suffix(file_path, ".rb"))
        return "Ruby script";
    else if (g_str_has_suffix(file_path, ".js"))
        return "JavaScript source";
    else if (g_str_has_suffix(file_path, ".mjs"))
        return "Module JavaScript source";
    else if (g_str_has_suffix(file_path, ".lua"))
        return "Lua script";
    else if (g_str_has_suffix(file_path, ".sh"))
        return "Shell script";
    else if (g_str_has_suffix(file_path, ".ps1"))
        return "Powershell script";
    else if (g_str_has_suffix(file_path, ".sql"))
        return "SQL script";
    else if (g_str_has_suffix(file_path, ".asp"))
        return "ASP script";
    else if (g_str_has_suffix(file_path, ".jsp"))
        return "JSP script";
    else if (g_str_has_suffix(file_path, ".jspx"))
        return "JSPX script";
    else if (g_str_has_suffix(file_path, ".php"))
        return "PHP source";
    else if (g_str_has_suffix(file_path, ".aspx"))
        return "ASP.NET script";
    else if (g_str_has_suffix(file_path, ".so"))
        return "Linux shared library";
    else if (g_str_has_suffix(file_path, ".dll"))
        return "Windows DLL";
    else if (g_str_has_suffix(file_path, ".exe"))
        return "Windows executable";
    else if (g_str_has_suffix(file_path, ".com"))
        return "DOS executable";
    else if (g_str_has_suffix(file_path, ".dylib"))
        return "macOS dynamic library";
    else if (g_str_has_suffix(file_path, ".docx"))
        return "Word document";
    else if (g_str_has_suffix(file_path, ".zip"))
        return "ZIP archive";
    else if (g_str_has_suffix(file_path, ".swift"))
        return "Swift source";
    else if (g_str_has_suffix(file_path, ".c"))
        return "C source";
    else if (g_str_has_suffix(file_path, ".cpp"))
        return "C++ source";
    else if (g_str_has_suffix(file_path, ".h"))
        return "C/C++ header";
    else if (g_str_has_suffix(file_path, ".hpp"))
        return "C++ header";
    else if (g_str_has_suffix(file_path, ".go"))
        return "Go source";
    else if (g_str_has_suffix(file_path, ".ts"))
        return "TypeScript source";
    else if (g_str_has_suffix(file_path, ".rs"))
        return "Rust source";
    else if (g_str_has_suffix(file_path, ".kt"))
        return "Kotlin source";
    else if (g_str_has_suffix(file_path, ".scala"))
        return "Scala source";
    else if (g_str_has_suffix(file_path, ".groovy"))
        return "Groovy script";
    
    return NULL;
}

const char *choose_file_type(const char *file_type_magic, const char *file_type_extension)
{
    if (file_type_magic == NULL && file_type_extension == NULL)
        return NULL;
    if (file_type_magic != NULL && file_type_extension == NULL)
        return file_type_magic;
    if (file_type_magic == NULL && file_type_extension != NULL)
        return file_type_extension;
    
    // prefer specific script types
    if (strcmp(file_type_magic, "Script") == 0 && g_str_has_suffix(file_type_extension, "script"))
        return file_type_extension;
    
    // prefer specific executable types
    if (strcmp(file_type_magic, "ELF") == 0 && strcmp(file_type_extension, "Linux shared library") == 0)
        return file_type_extension;
    if (strcmp(file_type_magic, "Windows executable/DLL") == 0 &&
        (strcmp(file_type_extension, "Windows executable") == 0 || strcmp(file_type_extension, "Windows DLL") == 0))
        return file_type_extension;
    if (g_str_has_prefix(file_type_magic, "Mach-O") && strcmp(file_type_extension, "macOS dynamic library") == 0)
        return wmem_strdup_printf(wmem_packet_scope(), "%s (dynamic library)", file_type_magic);
    
    // prefer file type from magic for all other cases
    return file_type_magic;
}

static int enrich_magic_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
    struct tracee_dissector_data *dissector_data = (struct tracee_dissector_data *)data;
    const gchar *bytes, *pathname;
    guchar *decoded_data;
    gsize len;
    const char *decoded_data_repr, *decoded_data_str, *file_type_magic, *file_type_extension = NULL, *file_type;
    proto_item *tmp_item;

    if ((bytes = wanted_field_get_str("tracee.args.magic_write.bytes")) == NULL)
        return 0;
    
    // decode written data
    decoded_data = g_base64_decode(bytes, &len);

    // add decoded data
    decoded_data_repr = stringify_decoded_data(pinfo, decoded_data, len);
    tmp_item = proto_tree_add_string_wanted(dissector_data->args_tree, hf_decoded_data, tvb, 0, 0, decoded_data_repr);
    proto_item_set_generated(tmp_item);

    pathname = wanted_field_get_str("tracee.args.magic_write.pathname");

    // add file type, if known
    decoded_data_str = wmem_strndup(pinfo->pool, decoded_data, len);
    file_type_magic = get_file_type_magic(decoded_data_str);
    if (pathname != NULL)
        file_type_extension = get_file_type_extension(pathname);
    file_type = choose_file_type(file_type_magic, file_type_extension);
    if (file_type != NULL) {
        tmp_item = proto_tree_add_string_wanted(dissector_data->args_tree, hf_file_type, tvb, 0, 0, file_type);
        proto_item_set_generated(tmp_item);
    }

    // set info column
    if (pathname != NULL)
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s written to %s", file_type != NULL ? file_type : "Unknown file type", pathname);

    g_free(decoded_data);
    return 0;
}

static int enrich_security_file_open(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const gchar *pathname, *syscall_pathname;

    if ((syscall_pathname = wanted_field_get_str("tracee.args.security_file_open.syscall_pathname")) == NULL)
        return 0;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Open %s", syscall_pathname);

    if ((pathname = wanted_field_get_str("tracee.args.security_file_open.pathname")) == NULL)
        return 0;
    
    if (strlen(pathname) > 0 && strcmp(pathname, syscall_pathname) != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", pathname);
    
    return 0;
}

static int enrich_ptrace(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
    struct tracee_dissector_data *dissector_data = (struct tracee_dissector_data *)data;
    const gchar *request, *request_name;
    char *endptr;
    gint64 request_int;
    bool req_field_is_int;
    proto_item *request_name_item;

    if ((request = wanted_field_get_str("tracee.args.ptrace.request")) == NULL)
        return 0;
    
    // Try converting request field to int
    errno = 0;
    request_int = strtoull(request, &endptr, 10);
    DISSECTOR_ASSERT(errno == 0);
    if (*endptr == '\0') {
        // There are no invalid characters - entire string is an int
        req_field_is_int = true;

        // Convert request number to name
        switch (request_int) {
            case 0:
                request_name = "PTRACE_TRACEME";
                break;
            case 1:
                request_name = "PTRACE_PEEKTEXT";
                break;
            case 2:
                request_name = "PTRACE_PEEKDATA";
                break;
            case 3:
                request_name = "PTRACE_PEEKUSER";
                break;
            case 4:
                request_name = "PTRACE_POKETEXT";
                break;
            case 5:
                request_name = "PTRACE_POKEDATA";
                break;
            case 6:
                request_name = "PTRACE_POKEUSER";
                break;
            case 7:
                request_name = "PTRACE_CONT";
                break;
            case 8:
                request_name = "PTRACE_KILL";
                break;
            case 9:
                request_name = "PTRACE_SINGLESTEP";
                break;
            case 16:
                request_name = "PTRACE_ATTACH";
                break;
            case 17:
                request_name = "PTRACE_DETACH";
                break;
            case 24:
                request_name = "PTRACE_SYSCALL";
                break;
            case 31:
                request_name = "PTRACE_SYSEMU";
                break;
            case 32:
                request_name = "PTRACE_SYSEMU_SINGLESTEP";
                break;
            case 0x4200:
                request_name = "PTRACE_SETOPTIONS";
                break;
            case 0x4201:
                request_name = "PTRACE_GETEVENTMSG";
                break;
            case 0x4202:
                request_name = "PTRACE_GETSIGINFO";
                break;
            case 0x4203:
                request_name = "PTRACE_SETSIGINFO";
                break;
            case 0x4204:
                request_name = "PTRACE_GETREGSET";
                break;
            case 0x4205:
                request_name = "PTRACE_SETREGSET";
                break;
            case 0x4206:
                request_name = "PTRACE_SEIZE";
                break;
            case 0x4207:
                request_name = "PTRACE_INTERRUPT";
                break;
            case 0x4208:
                request_name = "PTRACE_LISTEN";
                break;
            case 0x4209:
                request_name = "PTRACE_PEEKSIGINFO";
                break;
            case 0x420a:
                request_name = "PTRACE_GETSIGMASK";
                break;
            case 0x420b:
                request_name = "PTRACE_SETSIGMASK";
                break;
            case 0x420c:
                request_name = "PTRACE_SECCOMP_GET_FILTER";
                break;
            case 0x420d:
                request_name = "PTRACE_SECCOMP_GET_METADATA";
                break;
            case 0x420e:
                request_name = "PTRACE_GET_SYSCALL_INFO";
                break;
            case 0x420f:
                request_name = "PTRACE_GET_RSEQ_CONFIGURATION";
                break;
            default:
                request_name = request;
        }
    }
    else {
        req_field_is_int = false;
        request_name = request;
    }

    request_name_item = proto_tree_add_string_wanted(dissector_data->args_tree, hf_ptrace_request, tvb, 0, 0, request_name);
    proto_item_set_generated(request_name_item);

    if (!req_field_is_int)
        proto_item_set_hidden(request_name_item);
    
    return 0;
}

static void register_wanted_fields(void)
{
    // needed for enrich_sched_process_exec
    register_wanted_field("tracee.args.sched_process_exec.pathname");
    register_wanted_field("tracee.args.command_line");
    register_wanted_field("tracee.args.sched_process_exec.prev_comm");

    // needed for enrich_net_packet_http_request
    register_wanted_field("tracee.proto_http_request.method");
    register_wanted_field("tracee.proto_http_request.protocol");
    register_wanted_field("tracee.proto_http_request.uri_path");
    register_wanted_field("http.content_type");

    // needed for enrich_net_packet_http
    register_wanted_field("tracee.proto_http.direction");
    register_wanted_field("tracee.proto_http.method");
    register_wanted_field("tracee.proto_http.protocol");
    register_wanted_field("tracee.proto_http.uri_path");
    register_wanted_field("tracee.proto_http.status");

    // needed for enrich_security_socket_bind_connect
    register_wanted_field("tracee.sockaddr.sa_family");
    register_wanted_field("tracee.sockaddr.sin_addr");
    register_wanted_field("tracee.sockaddr.sin_port");
    register_wanted_field("tracee.sockaddr.sin6_addr");
    register_wanted_field("tracee.sockaddr.sin6_port");
    register_wanted_field("tracee.sockaddr.sun_path");

    // needed for enrich_dynamic_code_loading
    register_wanted_field("tracee.args.dynamic_code_loading.triggered_by.alert");

    // needed for enrich_fileless_execution
    register_wanted_field("tracee.args.fileless_execution.triggered_by.pathname");

    // needed for enrich_stdio_over_socket
    register_wanted_field("tracee.args.stdio_over_socket.File_descriptor");
    register_wanted_field("tracee.args.stdio_over_socket.IP_address");
    register_wanted_field("tracee.args.stdio_over_socket.Port");

    // needed for enrich_magic_write
    register_wanted_field("tracee.args.magic_write.bytes");
    register_wanted_field("tracee.args.magic_write.pathname");

    // needed for enrich_security_file_open
    register_wanted_field("tracee.args.security_file_open.pathname");
    register_wanted_field("tracee.args.security_file_open.syscall_pathname");

    // needed for ptrace
    register_wanted_field("tracee.args.ptrace.request");
}

void register_tracee_enrichments(int proto)
{
    static hf_register_info hf[] = {
        { &hf_decoded_data,
          { "Decoded data", "tracee.args.magic_write.decoded_data",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_file_type,
          { "File type", "tracee.args.magic_write.file_type",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ptrace_request,
          { "Request Name", "tracee.args.ptrace.request_name",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    proto_register_field_array(proto, hf, array_length(hf));

    register_wanted_fields();
}

static void register_tracee_event_enrichment(const gchar *event_name, dissector_t dissector)
{
    int proto_tracee;
    dissector_handle_t dissector_handle;
    
    DISSECTOR_ASSERT((proto_tracee = proto_get_id_by_filter_name("tracee")) != -1);

    dissector_handle = create_dissector_handle(dissector, proto_tracee);
    dissector_add_string("tracee.eventName", event_name, dissector_handle);
}

void proto_reg_handoff_tracee_enrichments(void)
{
    register_tracee_event_enrichment("sched_process_exec", enrich_sched_process_exec);
    register_tracee_event_enrichment("net_packet_http_request", enrich_net_packet_http_request);
    register_tracee_event_enrichment("net_packet_http", enrich_net_packet_http);
    register_tracee_event_enrichment("security_socket_bind", enrich_security_socket_bind);
    register_tracee_event_enrichment("security_socket_connect", enrich_security_socket_connect);
    register_tracee_event_enrichment("dynamic_code_loading", enrich_dynamic_code_loading);
    register_tracee_event_enrichment("fileless_execution", enrich_fileless_execution);
    register_tracee_event_enrichment("stdio_over_socket", enrich_stdio_over_socket);
    register_tracee_event_enrichment("magic_write", enrich_magic_write);
    register_tracee_event_enrichment("security_file_open", enrich_security_file_open);
    register_tracee_event_enrichment("ptrace", enrich_ptrace);
}