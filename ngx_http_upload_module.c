/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 * Client body reception code Copyright (c) 2002-2007 Igor Sysoev
 * Temporary file name generation code Copyright (c) 2002-2007 Igor Sysoev
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if nginx_version >= 1011002

#include <ngx_md5.h>

typedef ngx_md5_t MD5_CTX;

#define MD5Init ngx_md5_init
#define MD5Update ngx_md5_update
#define MD5Final ngx_md5_final

#define MD5_DIGEST_LENGTH 16

#include <openssl/sha.h>

#else

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif


#endif


#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
 // workaround for compiling error on windows because of _OFF_T_DEFINED being defined in ngx_win32_config.h.
#ifdef _WIN32
typedef long _off_t;
#endif
#include <sys/stat.h>
#ifdef _WIN32
typedef struct _stat stat_t;
#define ngx_stat(path, buffer) _stat(path, buffer)
#define alloca _alloca
#else
typedef struct stat stat_t;
#define ngx_stat(path, buffer) stat(path, buffer)
#endif


#ifdef _WIN32
#define ngx_lock_fd(fd)
#define ngx_unlock_fd(fd)
#define strncasecmp(s1, s2, size) _strnicmp((char*)s1, (char*)s2, size)

#if 0
#pragma warning(push)
#pragma warning(disable: 4293)
// TODO: check errors
int ftruncate(HANDLE fd, _off_t length)
{
    LONG high = 0;
    DWORD low = SetFilePointer(fd, 0, &high, FILE_CURRENT);

    _off_t pos = ((_off_t)high << 32) | (_off_t)low;

    high = length >> 32;
    low = (DWORD)length;

    SetFilePointer(fd, low, &high, FILE_BEGIN);
    SetEndOfFile(fd);

    if (length > pos) {
        high = (LONG)((ULONG)pos >> 32);
        low = (DWORD)pos;
        SetFilePointer(fd, low, &high, FILE_BEGIN);
    }

    return 0;
}
#pragma warning(pop)
#endif

#endif

#define ngx_fsize(file) ngx_file_size(&file->info)


#define MULTIPART_FORM_DATA_STRING              "multipart/form-data"
#define BOUNDARY_STRING                         "boundary="
#define CONTENT_DISPOSITION_STRING              "Content-Disposition:"
#define CONTENT_TYPE_STRING                     "Content-Type:"
#define FORM_DATA_STRING                        "form-data"
#define ATTACHMENT_STRING                       "attachment"
#define FILENAME_STRING                         "filename="
#define FIELDNAME_STRING                        "name="
#define BYTES_UNIT_STRING                       "bytes "

#define NGX_UPLOAD_MALFORMED    -11
#define NGX_UPLOAD_NOMEM        -12
#define NGX_UPLOAD_IOERROR      -13
#define NGX_UPLOAD_SCRIPTERROR  -14
#define NGX_UPLOAD_TOOLARGE     -15

#ifndef NGX_HTTP_V2
#define NGX_HTTP_V2 0
#endif

/*
 * State of multipart/form-data parser
 */
typedef enum {
    upload_state_boundary_seek,
    upload_state_after_boundary,
    upload_state_headers,
    upload_state_data,
    upload_state_finish
} upload_state_t;

/*
 * Range
 */
typedef struct {
    off_t       start, end, total;
} ngx_http_upload_range_t;

/*
 * Template for a field to generate in output form
 */
typedef struct {
    ngx_table_elt_t         value;
    ngx_array_t* field_lengths;
    ngx_array_t* field_values;
    ngx_array_t* value_lengths;
    ngx_array_t* value_values;
} ngx_http_upload_field_template_t;

/*
 * Filter for fields in output form
 */
typedef struct {
#if (NGX_PCRE)
    ngx_regex_t* regex;
    ngx_int_t                ncaptures;
#else
    ngx_str_t                text;
#endif
} ngx_http_upload_field_filter_t;

/*
 * Upload cleanup record
 */
typedef struct ngx_http_upload_cleanup_s {
    ngx_fd_t                         fd;
    u_char* filename;
    ngx_http_headers_out_t* headers_out;
    ngx_array_t* cleanup_statuses;
    ngx_log_t* log;
    unsigned int                     aborted : 1;
} ngx_upload_cleanup_t;

/*
 * Upload configuration for specific location
 */
typedef struct {
    ngx_str_t                     url;
    ngx_http_complex_value_t* url_cv;
    ngx_str_t                     store_path;
    ngx_uint_t                    store_access;
    size_t                        buffer_size;
    size_t                        max_header_len;
    size_t                        max_output_body_len;
    off_t                         max_file_size;
    ngx_array_t* aggregate_field_templates;
    ngx_array_t* field_filters;
    ngx_array_t* cleanup_statuses;
    ngx_array_t* header_templates;
    ngx_flag_t                    forward_args;
    ngx_flag_t                    tame_arrays;
    ngx_flag_t                    empty_field_names;
    size_t                        limit_rate;

    unsigned int                  md5 : 1;
    unsigned int                  sha1 : 1;
    unsigned int                  sha256 : 1;
    unsigned int                  sha512 : 1;
    unsigned int                  crc32 : 1;
} ngx_http_upload_loc_conf_t;

typedef struct ngx_http_upload_md5_ctx_s {
    MD5_CTX     md5;
    u_char      md5_digest[MD5_DIGEST_LENGTH * 2];
} ngx_http_upload_md5_ctx_t;

typedef struct ngx_http_upload_sha1_ctx_s {
    SHA_CTX     sha1;
    u_char      sha1_digest[SHA_DIGEST_LENGTH * 2];
} ngx_http_upload_sha1_ctx_t;

typedef struct ngx_http_upload_sha256_ctx_s {
    SHA256_CTX  sha256;
    u_char      sha256_digest[SHA256_DIGEST_LENGTH * 2];
} ngx_http_upload_sha256_ctx_t;

typedef struct ngx_http_upload_sha512_ctx_s {
    SHA512_CTX  sha512;
    u_char      sha512_digest[SHA512_DIGEST_LENGTH * 2];
} ngx_http_upload_sha512_ctx_t;

struct ngx_http_upload_ctx_s;

/*
 * Request body data handler
 */
typedef ngx_int_t(*ngx_http_request_body_data_handler_pt)
(struct ngx_http_upload_ctx_s*, u_char*, u_char*);


typedef struct ngx_http_uploaded_file_s {
    ngx_str_t original_name;
    ngx_str_t stored_name;
}
ngx_http_uploaded_file_t;

/*
 * Upload module context
 */
typedef struct ngx_http_upload_ctx_s {
    ngx_str_t           boundary;
    u_char* boundary_start;
    u_char* boundary_pos;

    upload_state_t		state;

    u_char* header_accumulator;
    u_char* header_accumulator_end;
    u_char* header_accumulator_pos;

    ngx_str_t           field_name;
    ngx_str_t           file_name;
    ngx_str_t           content_type;
    ngx_str_t           content_range;
    ngx_http_upload_range_t     content_range_n;

    ngx_array_t*        files_uploaded;

    ngx_uint_t          ordinal;

    u_char* output_buffer;
    u_char* output_buffer_end;
    u_char* output_buffer_pos;

    ngx_http_request_body_data_handler_pt data_handler;

    ngx_int_t(*start_part_f)(struct ngx_http_upload_ctx_s* upload_ctx);
    void (*finish_part_f)(struct ngx_http_upload_ctx_s* upload_ctx);
    void (*abort_part_f)(struct ngx_http_upload_ctx_s* upload_ctx);
    ngx_int_t(*flush_output_buffer_f)(struct ngx_http_upload_ctx_s* upload_ctx, u_char* buf, size_t len);

    ngx_http_request_t* request;
    ngx_log_t* log;

    ngx_file_t          output_file;
    ngx_file_t          state_file;
    ngx_chain_t* chain;
    ngx_chain_t* last;
    ngx_chain_t* checkpoint;
    ngx_chain_t* to_write;
    size_t              output_body_len;
    size_t              limit_rate;
    ssize_t             received;

    ngx_pool_cleanup_t* cln;

    ngx_http_upload_md5_ctx_t* md5_ctx;
    ngx_http_upload_sha1_ctx_t* sha1_ctx;
    ngx_http_upload_sha256_ctx_t* sha256_ctx;
    ngx_http_upload_sha512_ctx_t* sha512_ctx;
    uint32_t                    crc32;
    ngx_str_t           store_path;

    unsigned int        first_part : 1;
    unsigned int        discard_data : 1;
    unsigned int        is_file : 1;
    unsigned int        calculate_crc32 : 1;
    unsigned int        started : 1;
    unsigned int        unencoded : 1;
    unsigned int        no_content : 1;
    unsigned int        raw_input : 1;
} ngx_http_upload_ctx_t;

#if 0
static int ngx_casecmp(ngx_str_t s1, ngx_str_t s2)
{
    int clen = min(s1.len, s2.len);
    int cmp = ngx_strncasecmp(s1.data, s2.data, clen);
    
    if (cmp == 0 && s1.len != s2.len)
        cmp = s1.len > s2.len ? 1 : -1;

    return cmp;
}
#endif

static ngx_int_t ngx_http_upload_test_expect(ngx_http_request_t* r);

#if (NGX_HTTP_V2)
static void ngx_http_upload_read_event_handler(ngx_http_request_t* r);
#endif
static ngx_int_t ngx_http_upload_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_upload_options_handler(ngx_http_request_t* r);

static void* ngx_http_upload_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_upload_merge_loc_conf(ngx_conf_t* cf,
    void* parent, void* child);
static ngx_int_t ngx_http_upload_add_variables(ngx_conf_t* cf);
static ngx_int_t ngx_http_upload_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_md5_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_sha1_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_sha256_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_sha512_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_file_size_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static void ngx_http_upload_content_range_variable_set(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_content_range_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_crc32_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static ngx_int_t ngx_http_upload_uint_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data);
static char* ngx_http_upload_module_init(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static ngx_int_t upload_done(ngx_http_request_t* r, ngx_array_t* files);

static ngx_int_t
ngx_http_upload_process_field_templates(ngx_http_request_t* r,
    ngx_http_upload_field_template_t* t, ngx_str_t* field_name, ngx_str_t* field_value);

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t* u);
static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t* u);
static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t* u);

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t* u,
    u_char* buf, size_t len);
static ngx_int_t ngx_http_upload_append_field(ngx_http_upload_ctx_t* u,
    ngx_str_t* name, ngx_str_t* value);
static ngx_int_t ngx_http_upload_parse_range(ngx_str_t* range, ngx_http_upload_range_t* range_n);

static void ngx_http_read_upload_client_request_body_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_do_read_upload_client_request_body(ngx_http_request_t* r);
static ngx_int_t ngx_http_process_request_body(ngx_http_request_t* r, ngx_chain_t* body);

static ngx_int_t ngx_http_read_upload_client_request_body(ngx_http_request_t* r);

static char* ngx_http_upload_set_form_field(ngx_conf_t* cf, ngx_command_t* cmd,
    void* conf);
static ngx_int_t ngx_http_upload_eval_path(ngx_http_request_t* r);
static char* ngx_http_upload_store_path(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static char* ngx_http_upload_cleanup(ngx_conf_t* cf, ngx_command_t* cmd,
    void* conf);
static void ngx_upload_cleanup_handler(void* data);

#if defined nginx_version && nginx_version >= 7052
static ngx_path_init_t        ngx_http_upload_temp_path = {
    ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};
#endif

/*
 * upload_shutdown_ctx
 *
 * Shutdown upload context. Discard all remaining data and
 * free all memory associated with upload context.
 *
 * Parameter:
 *     upload_ctx -- upload context which is being shut down
 *
 */
static void upload_shutdown_ctx(ngx_http_upload_ctx_t* upload_ctx);

/*
 * upload_start
 *
 * Starts multipart stream processing. Initializes internal buffers
 * and pointers
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 *
 * Return value:
 *               NGX_OK on success
 *               NGX_ERROR if error has occured
 *
 */
static ngx_int_t setup_context(ngx_http_request_t* r);

/*
 * upload_parse_request_headers
 *
 * Parse and verify HTTP headers, extract boundary or
 * content disposition
 *
 * Parameters:
 *     r -- http request
 *
 * Return value:
 *     NGX_OK on success
 *     NGX_ERROR if error has occured
 */
static ngx_int_t upload_parse_request_headers(ngx_http_request_t* upload_ctx);

/*
 * upload_process_buf
 *
 * Process buffer with multipart stream starting from start and terminating
 * by end, operating on upload_ctx. The header information is accumulated in
 * This call can invoke one or more calls to start_upload_file, finish_upload_file,
 * abort_upload_file and flush_output_buffer routines.
 *
 * Returns value NGX_OK successful
 *               NGX_UPLOAD_MALFORMED stream is malformed
 *               NGX_UPLOAD_NOMEM insufficient memory
 *               NGX_UPLOAD_IOERROR input-output error
 *               NGX_UPLOAD_SCRIPTERROR nginx script engine failed
 *               NGX_UPLOAD_TOOLARGE field body is too large
 */
static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t* upload_ctx, u_char* start, u_char* end);

static ngx_command_t  ngx_http_upload_commands[] = { /* {{{ */

    /*
     * Enables uploads for location and specifies location to pass modified request to
     */
    { ngx_string("upload_module"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_NOARGS,
      ngx_http_upload_module_init,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies base path of file store
     */
    { ngx_string("upload_store"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE1234,
      ngx_http_upload_store_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_path),
      NULL },

    /*
     * Specifies the access mode for files in store
     */
    { ngx_string("upload_store_access"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_access),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * to write data to disk
     */
    { ngx_string("upload_buffer_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, buffer_size),
      NULL },

    /*
     * Specifies the maximal length of the part header
     */
    { ngx_string("upload_max_part_header_len"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_header_len),
      NULL },

    /*
     * Specifies the maximal size of the file to be uploaded
     */
    { ngx_string("upload_max_file_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_file_size),
      NULL },

    /*
     * Specifies the maximal length of output body
     */
    { ngx_string("upload_max_output_body_len"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_output_body_len),
      NULL },

    /*
     * Specifies the field with aggregate parameters
     * to set in altered response body
     */
    { ngx_string("upload_aggregate_form_field"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates),
      NULL},

    /*
     * Specifies http statuses upon reception of
     * which cleanup of uploaded files will be initiated
     */
    { ngx_string("upload_cleanup"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_1MORE,
      ngx_http_upload_cleanup,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    /*
     * Specifies the whether or not to forward query args
     * to the upload_pass redirect location
     */
    { ngx_string("upload_pass_args"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, forward_args),
      NULL },

    /*
     * Specifies request body reception rate limit
     */
   { ngx_string("upload_limit_rate"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF
                       | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_upload_loc_conf_t, limit_rate),
     NULL },

    /*
     * Specifies whether array brackets in file field names must be dropped
     */
    { ngx_string("upload_tame_arrays"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, tame_arrays),
      NULL },

    /*
     * Specifies whether empty field names are allowed
     */
    { ngx_string("upload_empty_field_names"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, empty_field_names),
      NULL },

    /*
     * Specifies the name and content of the header that will be added to the response
     */
    { ngx_string("upload_add_header"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_HTTP_LIF_CONF
                        | NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, header_templates),
      NULL},

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_http_upload_module_ctx = { /* {{{ */
    ngx_http_upload_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upload_create_loc_conf,       /* create location configuration */
    ngx_http_upload_merge_loc_conf         /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_http_upload_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_upload_module_ctx,           /* module context */
    ngx_http_upload_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
}; /* }}} */

static ngx_http_variable_t  ngx_http_upload_variables[] = { /* {{{ */

    { ngx_string("upload_field_name"), NULL, ngx_http_upload_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, field_name),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_content_type"),
      NULL,
      ngx_http_upload_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, content_type),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_name"), NULL, ngx_http_upload_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, file_name),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_number"), NULL, ngx_http_upload_uint_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, ordinal),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_tmp_path"), NULL, ngx_http_upload_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, output_file.name),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_content_range"),
      ngx_http_upload_content_range_variable_set,
      ngx_http_upload_content_range_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, content_range_n),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_http_variable_t  ngx_http_upload_aggregate_variables[] = { /* {{{ */

    { ngx_string("upload_file_md5"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t)"0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_md5_uc"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t)"0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t)"0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1_uc"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t)"0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha256"), NULL, ngx_http_upload_sha256_variable,
      (uintptr_t)"0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha256_uc"), NULL, ngx_http_upload_sha256_variable,
      (uintptr_t)"0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha512"), NULL, ngx_http_upload_sha512_variable,
      (uintptr_t)"0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha512_uc"), NULL, ngx_http_upload_sha512_variable,
      (uintptr_t)"0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_crc32"), NULL, ngx_http_upload_crc32_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, crc32),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_size"), NULL, ngx_http_upload_file_size_variable,
      (uintptr_t)offsetof(ngx_http_upload_ctx_t, output_file.offset),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

#define get_context(req) ngx_http_get_module_ctx((req), ngx_http_upload_module)
#define get_loc_conf(req) ngx_http_get_module_loc_conf((req), ngx_http_upload_module);

static ngx_str_t  ngx_http_upload_empty_field_value = ngx_null_string;

static ngx_str_t  ngx_upload_field_part1 = { /* {{{ */
    sizeof(CRLF CONTENT_DISPOSITION_STRING " form-data; name=\"") - 1,
    (u_char*)CRLF CONTENT_DISPOSITION_STRING " form-data; name=\""
}; /* }}} */

static ngx_str_t  ngx_upload_field_part2 = { /* {{{ */
    sizeof("\"" CRLF CRLF) - 1,
    (u_char*)"\"" CRLF CRLF
}; /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_handler */
ngx_http_upload_handler(ngx_http_request_t* r)
{
    ngx_int_t                 rc;

    if (r->method & NGX_HTTP_OPTIONS)
        return ngx_http_upload_options_handler(r);

    if (!(r->method & NGX_HTTP_POST))
        return NGX_HTTP_NOT_ALLOWED;

    if ((rc = setup_context(r)) != NGX_OK)
        return rc;

    if ((rc = upload_parse_request_headers(r)) != NGX_OK) {
        upload_shutdown_ctx(get_context(r));
        return rc;
    }

    if (ngx_http_upload_test_expect(r) != NGX_OK) {
        upload_shutdown_ctx(get_context(r));
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


#if (NGX_HTTP_V2)
    if (r->stream) {
        r->request_body_no_buffering = 1;

        rc = ngx_http_read_client_request_body(r, ngx_http_upload_read_event_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            upload_shutdown_ctx(u);
            return rc;
        }

        return NGX_DONE;
    }
#endif

    rc = ngx_http_read_upload_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
} /* }}} */

#if (NGX_HTTP_V2)
static void
ngx_http_upload_read_event_handler(ngx_http_request_t* r)
{
    ngx_http_upload_ctx_t* u;
    ngx_http_request_body_t* rb;
    ngx_int_t                   rc;
    ngx_chain_t* in;
    ssize_t                     n, limit, buf_read_size, next_buf_size, remaining;
    ngx_msec_t                  delay;
    ngx_event_t* rev;

    if (ngx_exiting || ngx_terminate) {
        ngx_http_finalize_request(r, NGX_HTTP_CLOSE);
        return;
    }

    rev = r->connection->read;
    rb = r->request_body;

    if (rb == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = ngx_http_upload_read_event_handler;

    u = get_context(r);

    for (;; ) {
        buf_read_size = 0;

        for (in = rb->bufs; in; in = in->next) {
            n = in->buf->last - in->buf->pos;

            rc = u->data_handler(u, in->buf->pos, in->buf->pos + n);

            in->buf->pos += n;
            u->received += n;
            buf_read_size += n;

            if (rc != NGX_OK) {
                goto err;
            }
        }
        rb->bufs = NULL;

        // We're done reading the request body, break out of loop
        if (!r->reading_body) {
            rc = u->data_handler(u, NULL, NULL);
            if (rc == NGX_OK) {
                break;
            }
            else {
                goto err;
            }
        }

        // Check whether we have exceeded limit_rate and should delay the next
        // buffer read
        if (u->limit_rate) {
            remaining = ((ssize_t)r->headers_in.content_length_n) - u->received;
            next_buf_size = (buf_read_size > remaining) ? remaining : buf_read_size;
            limit = u->limit_rate * (ngx_time() - r->start_sec + 1) - (u->received + next_buf_size);
            if (limit < 0) {
                rev->delayed = 1;
                ngx_add_timer(rev, (ngx_msec_t)((limit * -1000 / u->limit_rate) + 1));
                return;
            }
        }

        rc = ngx_http_read_unbuffered_request_body(r);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            goto err;
        }

        if (rb->bufs == NULL) {
            return;
        }

        // Check whether we should delay processing the latest request body
        // buffers to stay within limit_rate
        if (u->limit_rate) {
            buf_read_size = 0;
            for (in = rb->bufs; in; in = in->next) {
                buf_read_size += (in->buf->last - in->buf->pos);
            }
            delay = (ngx_msec_t)(buf_read_size * 1000 / u->limit_rate + 1);
            if (delay > 0) {
                rev->delayed = 1;
                ngx_add_timer(rev, delay);
                return;
            }
        }
    }

    // Finally, send the response
    rc = ngx_http_upload_body_handler(r);

err:
    switch (rc) {
    case NGX_UPLOAD_MALFORMED:
        rc = NGX_HTTP_BAD_REQUEST;
        break;
    case NGX_UPLOAD_TOOLARGE:
        rc = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        break;
    case NGX_UPLOAD_IOERROR:
        rc = NGX_HTTP_SERVICE_UNAVAILABLE;
        break;
    case NGX_UPLOAD_NOMEM:
    case NGX_UPLOAD_SCRIPTERROR:
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        ngx_http_finalize_request(r, rc);
    }
}
#endif

static ngx_int_t ngx_http_upload_add_headers(ngx_http_request_t* r, ngx_http_upload_loc_conf_t* ulcf) { /* {{{ */
    ngx_str_t                            name;
    ngx_str_t                            value;
    ngx_http_upload_field_template_t* t;
    ngx_table_elt_t* h;
    ngx_uint_t                           i;

    if (ulcf->header_templates != NULL) {
        t = ulcf->header_templates->elts;
        for (i = 0; i < ulcf->header_templates->nelts; i++) {
            if (ngx_http_upload_process_field_templates(r, &t[i], &name, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (name.len != 0 && value.len != 0) {
                h = ngx_list_push(&r->headers_out.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = 1;
                h->key.len = name.len;
                h->key.data = name.data;
                h->value.len = value.len;
                h->value.data = value.data;
            }
        }
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t ngx_http_upload_options_handler(ngx_http_request_t* r) { /* {{{ */
    ngx_http_upload_loc_conf_t* ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    r->headers_out.status = NGX_HTTP_OK;

    if (ngx_http_upload_add_headers(r, ulcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    r->allow_ranges = 0;

    return ngx_http_send_header(r);
} /* }}} */

static ngx_int_t
ngx_http_upload_process_field_templates(
    ngx_http_request_t* r, ngx_http_upload_field_template_t* t,
    ngx_str_t* name, ngx_str_t* value)
{
    if (t->field_lengths == NULL) {
        *name = t->value.key;
    }
    else if (ngx_http_script_run(r, name, t->field_lengths->elts, 0,
        t->field_values->elts) == NULL) {
        return NGX_UPLOAD_SCRIPTERROR;
    }

    if (t->value_lengths == NULL) {
        *value = t->value.value;
    }
    else if (ngx_http_script_run(r, value, t->value_lengths->elts, 0,
        t->value_values->elts) == NULL) {
        return NGX_UPLOAD_SCRIPTERROR;
    }
    return NGX_OK;
}

static ngx_str_t ngx_stringf(ngx_pool_t* pool, const char* fmt, ...)
{
    const ngx_str_t err = {0, NULL};

    va_list args;
    va_start(args, fmt);

    int size = vsnprintf(NULL, 0, fmt, args);
    if (size < 0) {
        va_end(args);
        return err;
    }

    ngx_str_t ret = { size, ngx_pcalloc(pool, size + 1) };
    if (ret.data == NULL) {
        va_end(args);
        return err;
    }

    vsnprintf((char*)ret.data, size + 1, fmt, args);

    va_end(args);

    return ret;
}

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t* u) { /* {{{ */
    ngx_http_request_t* r = u->request;
    ngx_http_upload_loc_conf_t* ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    ngx_file_t* file = &u->output_file;
    ngx_str_t  path = u->store_path;
    uint32_t    n;
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_err_t   err;
    ngx_http_upload_field_filter_t* f;
    ngx_uint_t  pass_field;
    ngx_upload_cleanup_t* ucln;

    if (u->is_file) {
        u->ordinal++;

        u->cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_upload_cleanup_t));
        if (u->cln == NULL)
            return NGX_UPLOAD_NOMEM;

        uint64_t timestamp = UINT64_MAX;
        struct timespec ts;
        if (timespec_get(&ts, TIME_UTC))
            timestamp = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

        file->name.len = path.len + 25; // {directory path} + '/' + {filename} + '~'
        file->name.data = ngx_palloc(u->request->pool, file->name.len + 1);
        if (file->name.data == NULL)
            return NGX_UPLOAD_NOMEM;
        ngx_memcpy(file->name.data, path.data, path.len);
        sprintf((char*)file->name.data + path.len, "/%020" PRIu64 "000~\0", timestamp);
        file->log = r->connection->log;

        for (n = 0; n < 1000; ++n) {
            ngx_sprintf(file->name.data + path.len + 21, "%03d", n);
            file->fd = ngx_open_tempfile(file->name.data, 1, ulcf->store_access);

            if (file->fd != NGX_INVALID_FILE) {
                file->offset = 0;
                break;
            }

            err = ngx_errno;

            if (err == NGX_EEXIST)
                continue;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
            return NGX_UPLOAD_IOERROR;
        }
        if (n == 1000) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
            return NGX_UPLOAD_IOERROR;
        }

        {
            ngx_http_uploaded_file_t* _f = ngx_array_push(u->files_uploaded);
            _f->original_name = u->file_name;
            _f->stored_name = ngx_stringf(r->pool, "%020" PRIu64 "%03d", timestamp, n);
        }
            
        u->cln->handler = ngx_upload_cleanup_handler;

        ucln = u->cln->data;
        ucln->fd = file->fd;
        ucln->filename = file->name.data;
        ucln->log = r->connection->log;
        ucln->headers_out = &r->headers_out;
        ucln->cleanup_statuses = ulcf->cleanup_statuses;
        ucln->aborted = 0;

        if (u->md5_ctx != NULL)
            MD5Init(&u->md5_ctx->md5);

        if (u->sha1_ctx != NULL)
            SHA1_Init(&u->sha1_ctx->sha1);

        if (u->sha256_ctx != NULL)
            SHA256_Init(&u->sha256_ctx->sha256);

        if (u->sha512_ctx != NULL)
            SHA512_Init(&u->sha512_ctx->sha512);

        if (u->calculate_crc32)
            ngx_crc32_init(u->crc32);

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
            , "started uploading file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
            , &u->file_name
            , &u->output_file.name
            , &u->field_name
            , &u->content_type
        );
    }
    else {
        pass_field = 0;

        if (ulcf->field_filters) {
            f = ulcf->field_filters->elts;
            for (i = 0; i < ulcf->field_filters->nelts; i++) {
#if (NGX_PCRE)
                rc = ngx_regex_exec(f[i].regex, &u->field_name, NULL, 0);

                /* Modified by Naren to work around iMovie and Quicktime which send empty values Added:  &&  u->field_name.len > 0 */
                if ((ulcf->empty_field_names && rc != NGX_REGEX_NO_MATCHED && rc < 0 && u->field_name.len != 0)
                    || (!ulcf->empty_field_names && rc != NGX_REGEX_NO_MATCHED && rc < 0))
                {
                    return NGX_UPLOAD_SCRIPTERROR;
                }

                /*
                 * If at least one filter succeeds, we pass the field
                 */
                if (rc == 0)
                    pass_field = 1;
#else
                if (ngx_strncmp(f[i].text.data, u->field_name.data, u->field_name.len) == 0)
                    pass_field = 1;
#endif
            }
        }

        if (pass_field && u->field_name.len != 0) {
            /*
             * Here we do a small hack: the content of a non-file field
             * is not known until ngx_http_upload_flush_output_buffer
             * is called. We pass empty field value to simplify things.
             */
            rc = ngx_http_upload_append_field(u, &u->field_name, &ngx_http_upload_empty_field_value);

            if (rc != NGX_OK)
                return rc;
        }
        else
            u->discard_data = 1;
    }


    if (ngx_http_upload_add_headers(r, ulcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
} /* }}} */


static int upload_rename_file(ngx_str_t old, ngx_str_t new_, ngx_log_t* log)
{
    char* o = alloca(old.len + 1);
    char* n = alloca(new_.len + 1);

    memcpy(o, old.data, old.len); o[old.len] = '\0';
    memcpy(n, new_.data, new_.len); n[new_.len] = '\0';

#ifdef _WIN32
    if (!DeleteFileA(n)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            ngx_log_error(NGX_LOG_INFO, log, 0, "delete file failed with error code %d: %s with error code", err, n);
            return 1;
        }
    }
    if (!MoveFile(o, n)) {
        DWORD err = GetLastError();
        ngx_log_error(NGX_LOG_INFO, log, 0, "move file failed with error code %d: %s with error code", err, n);
        return 1;
    }
    return 0;
#else
    rename(o, n); // TODO: check errno
#endif
}

static void upload_close_file(ngx_file_t* file)
{
    if (file->fd != NGX_INVALID_FILE)
        ngx_close_file(file->fd);
    file->fd = NGX_INVALID_FILE;
}

static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t* u) { /* {{{ */
    ngx_http_upload_field_template_t* af;
    ngx_str_t   aggregate_field_name, aggregate_field_value;
    ngx_http_request_t* r = u->request;
    ngx_http_upload_loc_conf_t* ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_upload_cleanup_t* ucln;

    if (u->is_file) {
        ucln = u->cln->data;
        ucln->fd = NGX_INVALID_FILE;

        upload_close_file(&u->output_file);

        ngx_str_t final_name = u->output_file.name;
        final_name.len -= 1; // remove trailing tilda
        if (upload_rename_file(u->output_file.name, final_name, r->connection->log) != 0)
            goto rollback;

        if (u->md5_ctx)
            MD5Final(u->md5_ctx->md5_digest, &u->md5_ctx->md5);

        if (u->sha1_ctx)
            SHA1_Final(u->sha1_ctx->sha1_digest, &u->sha1_ctx->sha1);

        if (u->sha256_ctx)
            SHA256_Final(u->sha256_ctx->sha256_digest, &u->sha256_ctx->sha256);

        if (u->sha512_ctx)
            SHA512_Final(u->sha512_ctx->sha512_digest, &u->sha512_ctx->sha512);

        if (u->calculate_crc32)
            ngx_crc32_final(u->crc32);

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
            , "finished uploading file \"%V\" to \"%V\""
            , &u->file_name
            , &u->output_file.name
        );

        if (ulcf->aggregate_field_templates) {
            af = ulcf->aggregate_field_templates->elts;
            for (i = 0; i < ulcf->aggregate_field_templates->nelts; i++) {
                rc = ngx_http_upload_process_field_templates(r, &af[i], &aggregate_field_name,
                    &aggregate_field_value);
                if (rc != NGX_OK) {
                    goto rollback;
                }

                rc = ngx_http_upload_append_field(u, &aggregate_field_name, &aggregate_field_value);

                if (rc != NGX_OK)
                    goto rollback;
            }
        }
    }

    // Checkpoint current output chain state
    u->checkpoint = u->last;
    return;

rollback:
    ngx_http_upload_abort_handler(u);
} /* }}} */

static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t* u) { /* {{{ */
    ngx_upload_cleanup_t* ucln;

    if (u->is_file) {
        /*
         * Upload of a part could be aborted due to temporary reasons, thus
         * next body part will be potentially processed successfuly.
         *
         * Therefore we don't postpone cleanup to the request finallization
         * in order to save additional resources, instead we mark existing
         * cleanup record as aborted.
         */
        ucln = u->cln->data;
        ucln->fd = NGX_INVALID_FILE;
        ucln->aborted = 1;

        upload_close_file(&u->output_file);
    }

    // Rollback output chain to the previous consistant state
    if (u->checkpoint != NULL) {
        u->last = u->checkpoint;
        u->last->next = NULL;
    }
    else {
        u->chain = u->last = NULL;
        u->first_part = 1;
    }
} /* }}} */

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t* u, u_char* buf, size_t len) { /* {{{ */
    ngx_http_request_t* r = u->request;
    ngx_buf_t* b;
    ngx_chain_t* cl;
    ngx_http_upload_loc_conf_t* ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    if (u->is_file) {
        if (u->md5_ctx)
            MD5Update(&u->md5_ctx->md5, buf, len);

        if (u->sha1_ctx)
            SHA1_Update(&u->sha1_ctx->sha1, buf, len);

        if (u->sha256_ctx)
            SHA256_Update(&u->sha256_ctx->sha256, buf, len);

        if (u->sha512_ctx)
            SHA512_Update(&u->sha512_ctx->sha512, buf, len);

        if (u->calculate_crc32)
            ngx_crc32_update(&u->crc32, buf, len);

        if (ulcf->max_file_size != 0) {
            if (u->output_file.offset + (off_t)len > ulcf->max_file_size)
                return NGX_UPLOAD_TOOLARGE;
        }

        if (ngx_write_file(&u->output_file, buf, len, u->output_file.offset) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                "write to file \"%V\" failed", &u->output_file.name);
            return NGX_UPLOAD_IOERROR;
        }
        else
            return NGX_OK;
    }
    else {
        if (ulcf->max_output_body_len != 0) {
            if (u->output_body_len + len > ulcf->max_output_body_len)
                return NGX_UPLOAD_TOOLARGE;
        }

        u->output_body_len += len;

        b = ngx_create_temp_buf(u->request->pool, len);

        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(u->request->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b->last_in_chain = 0;

        cl->buf = b;
        cl->next = NULL;

        b->last = ngx_cpymem(b->last, buf, len);

        if (u->chain == NULL) {
            u->chain = cl;
            u->last = cl;
        }
        else {
            u->last->next = cl;
            u->last = cl;
        }

        return NGX_OK;
    }
} /* }}} */

static void /* {{{ ngx_http_upload_append_str */
ngx_http_upload_append_str(ngx_http_upload_ctx_t* u, ngx_buf_t* b, ngx_chain_t* cl, ngx_str_t* s)
{
    b->start = b->pos = s->data;
    b->end = b->last = s->data + s->len;
    b->memory = 1;
    b->temporary = 1;
    b->in_file = 0;
    b->last_buf = 0;

    b->last_in_chain = 0;
    b->last_buf = 0;

    cl->buf = b;
    cl->next = NULL;

    if (u->chain == NULL) {
        u->chain = cl;
        u->last = cl;
    }
    else {
        u->last->next = cl;
        u->last = cl;
    }

    u->output_body_len += s->len;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_append_field */
ngx_http_upload_append_field(ngx_http_upload_ctx_t* u, ngx_str_t* name, ngx_str_t* value)
{
    ngx_http_upload_loc_conf_t* ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);
    ngx_str_t   boundary = { u->first_part ? u->boundary.len - 2 : u->boundary.len,
         u->first_part ? u->boundary.data + 2 : u->boundary.data };

    ngx_buf_t* b;
    ngx_chain_t* cl;

    if (name->len > 0) {
        if (ulcf->max_output_body_len != 0) {
            if (u->output_body_len + boundary.len + ngx_upload_field_part1.len + name->len
                + ngx_upload_field_part2.len + value->len > ulcf->max_output_body_len)
                return NGX_UPLOAD_TOOLARGE;
        }

        b = ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_buf_t) : 4 * sizeof(ngx_buf_t));

        if (b == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        cl = ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_chain_t) : 4 * sizeof(ngx_chain_t));

        if (cl == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        ngx_http_upload_append_str(u, b, cl, &boundary);

        ngx_http_upload_append_str(u, b + 1, cl + 1, &ngx_upload_field_part1);

        ngx_http_upload_append_str(u, b + 2, cl + 2, name);

        ngx_http_upload_append_str(u, b + 3, cl + 3, &ngx_upload_field_part2);

        if (value->len > 0)
            ngx_http_upload_append_str(u, b + 4, cl + 4, value);

        u->output_body_len += boundary.len + ngx_upload_field_part1.len + name->len
            + ngx_upload_field_part2.len + value->len;

        u->first_part = 0;

        u->no_content = 0;
    }

    return NGX_OK;
} /* }}} */

static void* /* {{{ ngx_http_upload_create_loc_conf */
ngx_http_upload_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_upload_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upload_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->store_access = NGX_CONF_UNSET_UINT;
    conf->forward_args = NGX_CONF_UNSET;
    conf->tame_arrays = NGX_CONF_UNSET;
    conf->empty_field_names = NGX_CONF_UNSET;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_header_len = NGX_CONF_UNSET_SIZE;
    conf->max_output_body_len = NGX_CONF_UNSET_SIZE;
    conf->max_file_size = NGX_CONF_UNSET;
    conf->limit_rate = NGX_CONF_UNSET_SIZE;

    /*
     * conf->header_templates,
     * conf->field_templates,
     * conf->aggregate_field_templates,
     * and conf->field_filters are
     * zeroed by ngx_pcalloc
     */

    return conf;
} /* }}} */

static char* /* {{{ ngx_http_upload_merge_loc_conf */
ngx_http_upload_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_upload_loc_conf_t* prev = parent;
    ngx_http_upload_loc_conf_t* conf = child;

    if ((conf->url.len == 0) && (conf->url_cv == NULL)) {
        conf->url = prev->url;
        conf->url_cv = prev->url_cv;
    }

    ngx_conf_merge_uint_value(conf->store_access,
        prev->store_access, 0600);

    ngx_conf_merge_size_value(conf->buffer_size,
        prev->buffer_size,
        (size_t)ngx_pagesize);

    ngx_conf_merge_size_value(conf->max_header_len,
        prev->max_header_len,
        (size_t)512);

    ngx_conf_merge_size_value(conf->max_output_body_len,
        prev->max_output_body_len,
        (size_t)100 * 1024);

    ngx_conf_merge_off_value(conf->max_file_size,
        prev->max_file_size,
        0);

    ngx_conf_merge_size_value(conf->limit_rate, prev->limit_rate, 0);

    if (conf->forward_args == NGX_CONF_UNSET) {
        conf->forward_args = (prev->forward_args != NGX_CONF_UNSET) ?
            prev->forward_args : 0;
    }

    if (conf->tame_arrays == NGX_CONF_UNSET) {
        conf->tame_arrays = (prev->tame_arrays != NGX_CONF_UNSET) ?
            prev->tame_arrays : 0;
    }

    if (conf->empty_field_names == NGX_CONF_UNSET) {
        conf->empty_field_names = (prev->empty_field_names != NGX_CONF_UNSET) ?
            prev->empty_field_names : 0;
    }

    if (conf->aggregate_field_templates == NULL) {
        conf->aggregate_field_templates = prev->aggregate_field_templates;

        if (prev->md5) {
            conf->md5 = prev->md5;
        }

        if (prev->sha1) {
            conf->sha1 = prev->sha1;
        }

        if (prev->sha256) {
            conf->sha256 = prev->sha256;
        }

        if (prev->sha512) {
            conf->sha512 = prev->sha512;
        }

        if (prev->crc32) {
            conf->crc32 = prev->crc32;
        }
    }

    if (conf->field_filters == NULL) {
        conf->field_filters = prev->field_filters;
    }

    if (conf->cleanup_statuses == NULL) {
        conf->cleanup_statuses = prev->cleanup_statuses;
    }

    if (conf->header_templates == NULL) {
        conf->header_templates = prev->header_templates;
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_add_variables */
ngx_http_upload_add_variables(ngx_conf_t* cf)
{
    ngx_http_variable_t* var, * v;

    for (v = ngx_http_upload_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_variable */
ngx_http_upload_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    ngx_str_t* value;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    u = get_context(r);

    value = (ngx_str_t*)((char*)u + data);

    v->data = value->data;
    v->len = value->len;

    return NGX_OK;
} /* }}} */

static ngx_int_t
ngx_http_upload_hash_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data, u_char* digest,
    ngx_uint_t digest_len)
{
    ngx_uint_t             i;
    u_char* c;
    u_char* p;
    u_char* hex_table;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    hex_table = (u_char*)data;

    p = ngx_palloc(r->pool, digest_len * 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    c = p + digest_len * 2;
    i = digest_len;

    do {
        i--;
        *--c = hex_table[digest[i] & 0xf];
        *--c = hex_table[digest[i] >> 4];
    } while (i != 0);

    v->data = c;
    v->len = digest_len * 2;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_md5_variable */
ngx_http_upload_md5_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;

    u = get_context(r);

    if (u->md5_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    return ngx_http_upload_hash_variable(r, v, data, u->md5_ctx->md5_digest, MD5_DIGEST_LENGTH);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_sha1_variable */
ngx_http_upload_sha1_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;

    u = get_context(r);

    if (u->sha1_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_upload_hash_variable(r, v, data, u->sha1_ctx->sha1_digest, SHA_DIGEST_LENGTH);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_sha256_variable */
ngx_http_upload_sha256_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;

    u = get_context(r);

    if (u->sha256_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_upload_hash_variable(r, v, data, u->sha256_ctx->sha256_digest, SHA256_DIGEST_LENGTH);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_sha512_variable */
ngx_http_upload_sha512_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;

    u = get_context(r);

    if (u->sha512_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_upload_hash_variable(r, v, data, u->sha512_ctx->sha512_digest, SHA512_DIGEST_LENGTH);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_crc32_variable */
ngx_http_upload_crc32_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    u_char* p;
    uint32_t* value;

    u = get_context(r);

    value = (uint32_t*)((char*)u + data);

    p = ngx_palloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08uxd", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_file_size_variable */
ngx_http_upload_file_size_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    u_char* p;
    off_t* value;

    u = get_context(r);

    value = (off_t*)((char*)u + data);

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_upload_content_range_variable_set */
ngx_http_upload_content_range_variable_set(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    ngx_str_t                val;
    ngx_http_upload_range_t* value;

    u = get_context(r);

    value = (ngx_http_upload_range_t*)((char*)u + data);

    val.len = v->len;
    val.data = v->data;

    if (ngx_http_upload_parse_range(&val, value) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "invalid range \"%V\"", &val);
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_content_range_variable */
ngx_http_upload_content_range_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    u_char* p;
    ngx_http_upload_range_t* value;

    u = get_context(r);

    value = (ngx_http_upload_range_t*)((char*)u + data);

    p = ngx_palloc(r->pool, sizeof("bytes ") - 1 + 3 * NGX_OFF_T_LEN + 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "bytes %O-%O/%O", (off_t)0, u->output_file.offset, u->output_file.offset) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_uint_variable */
ngx_http_upload_uint_variable(ngx_http_request_t* r,
    ngx_http_variable_value_t* v, uintptr_t data)
{
    ngx_http_upload_ctx_t* u;
    u_char* p;
    ngx_uint_t* value;

    u = get_context(r);

    value = (ngx_uint_t*)((char*)u + data);

    p = ngx_palloc(r->pool, sizeof("18446744073709551616") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static char* /* {{{ ngx_http_upload_set_form_field */
ngx_http_upload_set_form_field(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_int_t                   n, i;
    ngx_str_t* value;
    ngx_http_script_compile_t   sc;
    ngx_http_upload_field_template_t* h;
    ngx_array_t** field;
    ngx_http_variable_t* v;
    u_char* match;
    ngx_http_upload_loc_conf_t* ulcf = conf;

    field = (ngx_array_t**)(((u_char*)conf) + cmd->offset);

    value = cf->args->elts;

    if (*field == NULL) {
        *field = ngx_array_create(cf->pool, 1,
            sizeof(ngx_http_upload_field_template_t));
        if (*field == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(*field);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    h->value.hash = 1;
    h->value.key = value[1];
    h->value.value = value[2];
    h->field_lengths = NULL;
    h->field_values = NULL;
    h->value_lengths = NULL;
    h->value_values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &h->field_lengths;
        sc.values = &h->field_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[2];
        sc.lengths = &h->value_lengths;
        sc.values = &h->value_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Check for aggregate variables in script
     */
    for (i = 1; i <= 2; i++) {
        for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
            match = ngx_strcasestrn(value[i].data, (char*)v->name.data, v->name.len - 1);

            /*
             * ngx_http_script_compile does check for final bracket earlier,
             * therefore we don't need to care about it, which simplifies things
             */
            if (match != NULL
                && ((match - value[i].data >= 1 && match[-1] == '$')
                    || (match - value[i].data >= 2 && match[-2] == '$' && match[-1] == '{')))
            {
                if (cmd->offset != offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "variables upload_file_md5"
                        ", upload_file_md5_uc"
                        ", upload_file_sha1"
                        ", upload_file_sha1_uc"
                        ", upload_file_sha256"
                        ", upload_file_sha256_uc"
                        ", upload_file_sha512"
                        ", upload_file_sha512_uc"
                        ", upload_file_crc32"
                        ", upload_content_range"
                        " and upload_file_size"
                        " could be specified only in upload_aggregate_form_field directive");
                    return NGX_CONF_ERROR;
                }

                if (v->get_handler == ngx_http_upload_md5_variable)
                    ulcf->md5 = 1;

                if (v->get_handler == ngx_http_upload_sha1_variable)
                    ulcf->sha1 = 1;

                if (v->get_handler == ngx_http_upload_sha256_variable)
                    ulcf->sha256 = 1;

                if (v->get_handler == ngx_http_upload_sha512_variable)
                    ulcf->sha512 = 1;

                if (v->get_handler == ngx_http_upload_crc32_variable)
                    ulcf->crc32 = 1;
            }
        }
    }

    return NGX_CONF_OK;
} /* }}} */

static char* /* {{{ ngx_http_upload_cleanup */
ngx_http_upload_cleanup(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_http_upload_loc_conf_t* ulcf = conf;

    ngx_str_t* value;
    ngx_uint_t                 i;
    ngx_int_t                  status, lo, hi;
    uint16_t* s;

    value = cf->args->elts;

    if (ulcf->cleanup_statuses == NULL) {
        ulcf->cleanup_statuses = ngx_array_create(cf->pool, 1,
            sizeof(uint16_t));
        if (ulcf->cleanup_statuses == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len > 4 && value[i].data[3] == '-') {
            lo = ngx_atoi(value[i].data, 3);

            if (lo == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid lower bound \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            hi = ngx_atoi(value[i].data + 4, value[i].len - 4);

            if (hi == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid upper bound \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (hi < lo) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "upper bound must be greater then lower bound in \"%V\"",
                    &value[i]);
                return NGX_CONF_ERROR;
            }

        }
        else {
            status = ngx_atoi(value[i].data, value[i].len);

            if (status == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            hi = lo = status;
        }

        if (lo < 200 || hi > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "value(s) \"%V\" must be between 200 and 599",
                &value[i]);
            return NGX_CONF_ERROR;
        }

        for (status = lo; status <= hi; status++) {
            s = ngx_array_push(ulcf->cleanup_statuses);
            if (s == NULL) {
                return NGX_CONF_ERROR;
            }

            *s = status;
        }
    }


    return NGX_CONF_OK;
} /* }}} */

static char* /* {{{ ngx_http_upload_module_init */
ngx_http_upload_module_init(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    //__debugbreak();
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upload_handler;

    return NGX_CONF_OK;
} /* }}} */

static char*
ngx_http_upload_store_path(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    char* p = conf;

    ngx_str_t value;
    ngx_conf_post_t* post;
    stat_t st;

    ngx_str_t* field = (ngx_str_t*)(p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = ((ngx_str_t*)cf->args->elts)[1];
    if (ngx_stat((char*)value.data, &st) != 0)
        return "directory does not exists";

    if ((st.st_mode & _S_IFMT) != _S_IFDIR)
        return "is not directory";

    if (value.data[value.len - 1] == '/')
        value.len -= 1;

    *field = value;
    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}


ngx_int_t /* {{{ ngx_http_read_upload_client_request_body */
ngx_http_read_upload_client_request_body(ngx_http_request_t* r) {
    ssize_t                    size, preread;
    ngx_buf_t* b;
    ngx_chain_t* cl, ** next;
    ngx_http_request_body_t* rb;
    ngx_http_core_loc_conf_t* clcf;
    ngx_http_upload_ctx_t* u = get_context(r);

#if defined nginx_version && nginx_version >= 8011
    r->main->count++;
#endif

    if (r->request_body || r->discard_body) {
        return NGX_OK;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n <= 0) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_BAD_REQUEST;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http client request body preread %uz", preread);

        u->received = preread;

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;
        rb->buf = b;

        if (preread >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            if (ngx_http_process_request_body(r, rb->bufs) != NGX_OK) {
                upload_shutdown_ctx(u);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            upload_shutdown_ctx(u);
            
            return NGX_DONE;
        }

        /*
         * to not consider the body as pipelined request in
         * ngx_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (off_t)(b->end - b->last)) {

            /* the whole request body may be placed in r->header_in */

            u->to_write = rb->bufs;

            r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

            return ngx_http_do_read_upload_client_request_body(r);
        }

        next = &rb->bufs->next;

    }
    else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    if (rb->rest < (ssize_t)size) {
        size = rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    }
    else {
        size = clcf->client_body_buffer_size;

        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        size = b->last - b->pos;
        ngx_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    u->to_write = rb->bufs;

    r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

    return ngx_http_do_read_upload_client_request_body(r);
} /* }}} */

static void /* {{{ ngx_http_read_upload_client_request_body_handler */
ngx_http_read_upload_client_request_body_handler(ngx_http_request_t* r)
{
    ngx_int_t  rc;
    ngx_http_upload_ctx_t* u = get_context(r);
    ngx_event_t* rev = r->connection->read;
    ngx_http_core_loc_conf_t* clcf;

    if (rev->timedout) {
        if (!rev->delayed) {
            r->connection->timedout = 1;
            upload_shutdown_ctx(u);
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
            return;
        }

        rev->timedout = 0;
        rev->delayed = 0;

        if (!rev->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, clcf->client_body_timeout);

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                upload_shutdown_ctx(u);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }
    else {
        if (r->connection->read->delayed) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                "http read delayed");

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                upload_shutdown_ctx(u);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    rc = ngx_http_do_read_upload_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        ngx_http_finalize_request(r, rc);
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_do_read_upload_client_request_body */
ngx_http_do_read_upload_client_request_body(ngx_http_request_t* r)
{
    ssize_t                     size, n, limit;
    ngx_connection_t* c;
    ngx_http_request_body_t* rb;
    ngx_http_upload_ctx_t* u = get_context(r);
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t* clcf;
    ngx_msec_t                 delay;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
        "http read client request body");

    for (;; ) {
        for (;; ) {
            if (rb->buf->last == rb->buf->end) {

                rc = ngx_http_process_request_body(r, u->to_write);

                switch (rc) {
                case NGX_OK:
                    break;
                case NGX_UPLOAD_MALFORMED:
                    return NGX_HTTP_BAD_REQUEST;
                case NGX_UPLOAD_TOOLARGE:
                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                case NGX_UPLOAD_IOERROR:
                    return NGX_HTTP_SERVICE_UNAVAILABLE;
                case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
                default:
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                u->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;

            if ((off_t)size > rb->rest) {
                size = (size_t)rb->rest;
            }

            if (u->limit_rate) {
                limit = u->limit_rate * (ngx_time() - r->start_sec + 1) - u->received;

                if (limit < 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read,
                        (ngx_msec_t)(-limit * 1000 / u->limit_rate + 1));

                    return NGX_AGAIN;
                }

                if (limit > 0 && size > limit) {
                    size = limit;
                }
            }

            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "client closed prematurely connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;
            u->received += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }

            if (u->limit_rate) {
                delay = (ngx_msec_t)(n * 1000 / u->limit_rate + 1);

                if (delay > 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read, delay);
                    return NGX_AGAIN;
                }
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "http client request body rest %uz", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    r->read_event_handler = ngx_http_block_reading;

    rc = ngx_http_process_request_body(r, u->to_write);

    switch (rc) {
    case NGX_OK:
        break;
    case NGX_UPLOAD_MALFORMED:
        return NGX_HTTP_BAD_REQUEST;
    case NGX_UPLOAD_TOOLARGE:
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    case NGX_UPLOAD_IOERROR:
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    upload_shutdown_ctx(u);
    return upload_done(r, u->files_uploaded);
} /* }}} */

static ngx_int_t upload_done(ngx_http_request_t* r, ngx_array_t* files)
{
    const char* content_type = "text/plain";
    const char* text = "upload completed successfully";

    ngx_int_t rc;

    ngx_http_headers_out_t* hs = &r->headers_out;
    hs->content_type.len = strlen(content_type);
    hs->content_type.data = (u_char*)content_type;
    hs->status = NGX_HTTP_OK;
    hs->content_length_n = strlen(text);

    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_chain_t out = { buf, NULL };
    u_char* buff = ngx_palloc(r->pool, hs->content_length_n);
    if (buff == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buff, text, hs->content_length_n);

    buf->pos = buff;
    buf->last = buff + hs->content_length_n;
    buf->memory = 1;
    buf->last_buf = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "handle sem suggest GET");

    rc = ngx_http_output_filter(r, &out);
    if (rc < NGX_HTTP_SPECIAL_RESPONSE)
        ngx_http_finalize_request(r, rc);
    return rc;
}

static ngx_int_t /* {{{ ngx_http_process_request_body */
ngx_http_process_request_body(ngx_http_request_t* r, ngx_chain_t* body)
{
    ngx_int_t rc;
    ngx_http_upload_ctx_t* u = get_context(r);

    // Feed all the buffers into data handler
    while (body) {
        rc = u->data_handler(u, body->buf->pos, body->buf->last);

        if (rc != NGX_OK)
            return rc;

        body = body->next;
    }

    if (u->raw_input) {
        // Signal end of body
        if (r->request_body->rest == 0) {
            rc = u->data_handler(u, NULL, NULL);

            if (rc != NGX_OK)
                return rc;
        }
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_content_disposition(ngx_http_upload_ctx_t* upload_ctx, ngx_str_t* content_disposition) { /* {{{ */
    char* filename_start, * filename_end;
    char* fieldname_start, * fieldname_end;
    char* p, * q;

    p = (char*)content_disposition->data;

    if (strncasecmp(FORM_DATA_STRING, p, sizeof(FORM_DATA_STRING) - 1) &&
        strncasecmp(ATTACHMENT_STRING, p, sizeof(ATTACHMENT_STRING) - 1)) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
            "Content-Disposition is not form-data or attachment");
        return NGX_UPLOAD_MALFORMED;
    }

    filename_start = strstr(p, FILENAME_STRING);

    if (filename_start != 0) {

        filename_start += sizeof(FILENAME_STRING) - 1;

        if (*filename_start == '\"') {
            filename_start++;
        }

        filename_end = filename_start + strcspn(filename_start, "\";");

        /*
         * IE sends full path, strip path from filename
         * Also strip all UNIX path references
         */
        for (q = filename_end - 1; q > filename_start; q--)
            if (*q == '\\' || *q == '/') {
                filename_start = q + 1;
                break;
            }

        upload_ctx->file_name.len = filename_end - filename_start;
        upload_ctx->file_name.data = ngx_palloc(upload_ctx->request->pool, upload_ctx->file_name.len + 1);

        if (upload_ctx->file_name.data == NULL)
            return NGX_UPLOAD_NOMEM;

        strncpy((char*)upload_ctx->file_name.data, filename_start, filename_end - filename_start);
    }

    fieldname_start = p;

    //    do{
    fieldname_start = strstr(fieldname_start, FIELDNAME_STRING);
    //    }while((fieldname_start != 0) && (fieldname_start + sizeof(FIELDNAME_STRING) - 1 == filename_start));

    if (fieldname_start != 0) {
        fieldname_start += sizeof(FIELDNAME_STRING) - 1;

        if (*fieldname_start == '\"') {
            fieldname_start++;
        }

        if (fieldname_start != filename_start) {
            fieldname_end = fieldname_start + strcspn(fieldname_start, "\";");

            upload_ctx->field_name.len = fieldname_end - fieldname_start;
            upload_ctx->field_name.data = ngx_pcalloc(upload_ctx->request->pool, upload_ctx->field_name.len + 1);

            if (upload_ctx->field_name.data == NULL)
                return NGX_UPLOAD_NOMEM;

            strncpy((char*)upload_ctx->field_name.data, fieldname_start, fieldname_end - fieldname_start);
        }
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_part_header(ngx_http_upload_ctx_t* upload_ctx, char* header, char* header_end) { /* {{{ */
    ngx_str_t s;

    if (!strncasecmp(CONTENT_DISPOSITION_STRING, header, sizeof(CONTENT_DISPOSITION_STRING) - 1)) {
        char* p = header + sizeof(CONTENT_DISPOSITION_STRING) - 1;

        p += strspn(p, " ");

        s.data = (u_char*)p;
        s.len = header_end - p;

        if (upload_parse_content_disposition(upload_ctx, &s) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                "invalid Content-Disposition header");
            return NGX_UPLOAD_MALFORMED;
        }
    }
    else if (!strncasecmp(CONTENT_TYPE_STRING, header, sizeof(CONTENT_TYPE_STRING) - 1)) {
        char* content_type_str = header + sizeof(CONTENT_TYPE_STRING) - 1;

        content_type_str += strspn(content_type_str, " ");
        upload_ctx->content_type.len = header_end - content_type_str;

        if (upload_ctx->content_type.len == 0) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                "empty Content-Type in part header");
            return NGX_UPLOAD_MALFORMED; // Empty Content-Type field
        }

        upload_ctx->content_type.data = ngx_pcalloc(upload_ctx->request->pool, upload_ctx->content_type.len + 1);

        if (upload_ctx->content_type.data == NULL)
            return NGX_UPLOAD_NOMEM; // Unable to allocate memory for string

        strncpy((char*)upload_ctx->content_type.data, content_type_str, upload_ctx->content_type.len);
    }

    return NGX_OK;
} /* }}} */

static void upload_discard_part_attributes(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    upload_ctx->file_name.len = 0;
    upload_ctx->file_name.data = NULL;

    upload_ctx->field_name.len = 0;
    upload_ctx->field_name.data = NULL;

    upload_ctx->content_type.len = 0;
    upload_ctx->content_type.data = NULL;

    upload_ctx->content_range.len = 0;
    upload_ctx->content_range.data = NULL;
} /* }}} */

static ngx_int_t upload_start_file(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    if (upload_ctx->start_part_f)
        return upload_ctx->start_part_f(upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void upload_finish_file(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if (upload_ctx->finish_part_f)
        upload_ctx->finish_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_abort_file(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    if (upload_ctx->abort_part_f)
        upload_ctx->abort_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_flush_output_buffer(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    if (upload_ctx->output_buffer_pos > upload_ctx->output_buffer) {
        if (upload_ctx->flush_output_buffer_f)
            if (upload_ctx->flush_output_buffer_f(upload_ctx, (void*)upload_ctx->output_buffer,
                (size_t)(upload_ctx->output_buffer_pos - upload_ctx->output_buffer)) != NGX_OK)
                upload_ctx->discard_data = 1;

        upload_ctx->output_buffer_pos = upload_ctx->output_buffer;
    }
} /* }}} */

static void upload_shutdown_ctx(ngx_http_upload_ctx_t* upload_ctx) { /* {{{ */
    if (upload_ctx != 0) {
        // Abort file if we still processing it
        if (upload_ctx->state == upload_state_data) {
            upload_flush_output_buffer(upload_ctx);
            upload_abort_file(upload_ctx);
        }

        upload_discard_part_attributes(upload_ctx);
    }
} /* }}} */


static ngx_int_t setup_context(ngx_http_request_t* r) { /* {{{ */
    ngx_http_upload_loc_conf_t* ulcf = get_loc_conf(r);
    ngx_http_upload_ctx_t* u = get_context(r);

    if (u == NULL) {
        u = ngx_pcalloc(r->pool, sizeof(ngx_http_upload_ctx_t));
        if (u == NULL)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_http_set_ctx(r, u, ngx_http_upload_module);
    }

    if (ulcf->md5) {
        if (u->md5_ctx == NULL) {
            u->md5_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_md5_ctx_t));
            if (u->md5_ctx == NULL)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else
        u->md5_ctx = NULL;

    if (ulcf->sha1) {
        if (u->sha1_ctx == NULL) {
            u->sha1_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_sha1_ctx_t));
            if (u->sha1_ctx == NULL)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else
        u->sha1_ctx = NULL;

    if (ulcf->sha256) {
        if (u->sha256_ctx == NULL) {
            u->sha256_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_sha256_ctx_t));
            if (u->sha256_ctx == NULL)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else
        u->sha256_ctx = NULL;

    if (ulcf->sha512) {
        if (u->sha512_ctx == NULL) {
            u->sha512_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_sha512_ctx_t));
            if (u->sha512_ctx == NULL)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else
        u->sha512_ctx = NULL;

    u->calculate_crc32 = ulcf->crc32;

    u->request = r;
    u->log = r->connection->log;
    u->chain = u->last = u->checkpoint = NULL;
    u->output_body_len = 0;

    u->no_content = 1;
    u->limit_rate = ulcf->limit_rate;
    u->received = 0;
    u->ordinal = 0;

    u->files_uploaded = ngx_array_create(r->pool, 4, sizeof(ngx_http_uploaded_file_t));

    u->boundary.data = u->boundary_start = u->boundary_pos = 0;
    u->state = upload_state_boundary_seek;
    upload_discard_part_attributes(u);
    u->discard_data = 0;

    u->started = 0;
    u->unencoded = 0;

    // set handlers
    u->start_part_f = ngx_http_upload_start_handler;
    u->finish_part_f = ngx_http_upload_finish_handler;
    u->abort_part_f = ngx_http_upload_abort_handler;
    u->flush_output_buffer_f = ngx_http_upload_flush_output_buffer;
    u->data_handler = upload_process_buf;

    u->store_path = ulcf->store_path; // TODO: is ngx_str_t assignable?

    u->header_accumulator = ngx_pcalloc(r->pool, ulcf->max_header_len + 1);
    if (u->header_accumulator == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    u->header_accumulator_pos = u->header_accumulator;
    u->header_accumulator_end = u->header_accumulator + ulcf->max_header_len;

    u->output_buffer = ngx_pcalloc(r->pool, ulcf->buffer_size);
    if (u->output_buffer == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    u->output_buffer_pos = u->output_buffer;
    u->output_buffer_end = u->output_buffer + ulcf->buffer_size;

    u->first_part = 1;

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_request_headers(ngx_http_request_t* r) { /* {{{ */
    ngx_str_t* content_type;
    u_char* mime_type_end_ptr;
    u_char* boundary_start_ptr, * boundary_end_ptr;
    
    ngx_http_upload_ctx_t* upload_ctx = get_context(r);
    ngx_http_headers_in_t* headers_in = &r->headers_in;

    // Check whether Content-Type header is missing
    if (headers_in->content_type == NULL) {
        ngx_log_error(NGX_LOG_ERR, upload_ctx->log, ngx_errno,
            "missing Content-Type header");
        return NGX_HTTP_BAD_REQUEST;
    }

    content_type = &headers_in->content_type->value;

    if (ngx_strncasecmp(content_type->data, (u_char*)MULTIPART_FORM_DATA_STRING,
        sizeof(MULTIPART_FORM_DATA_STRING) - 1)) {

        ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
            "Content-Type is not multipart/form-data and resumable uploads are off: %V", content_type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    // Find colon in content type string, which terminates mime type
    mime_type_end_ptr = (u_char*)ngx_strchr(content_type->data, ';');

    upload_ctx->boundary.data = 0;

    if (mime_type_end_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
            "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED;
    }

    boundary_start_ptr = ngx_strstrn(mime_type_end_ptr, BOUNDARY_STRING, sizeof(BOUNDARY_STRING) - 2);

    if (boundary_start_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
            "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED; // No boundary found
    }

    boundary_start_ptr += sizeof(BOUNDARY_STRING) - 1;
    boundary_end_ptr = boundary_start_ptr + strcspn((char*)boundary_start_ptr, " ;\n\r");

    // Handle quoted boundaries
    if ((boundary_end_ptr - boundary_start_ptr) >= 2 && boundary_start_ptr[0] == '"' && *(boundary_end_ptr - 1) == '"') {
        boundary_start_ptr++;
        boundary_end_ptr--;
    }

    if (boundary_end_ptr == boundary_start_ptr) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
            "boundary is empty");
        return NGX_UPLOAD_MALFORMED;
    }

    // Allocate memory for entire boundary plus \r\n-- plus terminating character
    upload_ctx->boundary.len = boundary_end_ptr - boundary_start_ptr + 4;
    upload_ctx->boundary.data = ngx_palloc(r->pool, upload_ctx->boundary.len + 1);

    if (upload_ctx->boundary.data == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_cpystrn(upload_ctx->boundary.data + 4, boundary_start_ptr,
        boundary_end_ptr - boundary_start_ptr + 1);

    // Prepend boundary data by \r\n--
    upload_ctx->boundary.data[0] = '\r';
    upload_ctx->boundary.data[1] = '\n';
    upload_ctx->boundary.data[2] = '-';
    upload_ctx->boundary.data[3] = '-';

    /*
     * NOTE: first boundary doesn't start with \r\n. Here we
     * advance 2 positions forward. We will return 2 positions back
     * later
     */
    upload_ctx->boundary_start = upload_ctx->boundary.data + 2;
    upload_ctx->boundary_pos = upload_ctx->boundary_start;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_parse_range */
ngx_http_upload_parse_range(ngx_str_t* range, ngx_http_upload_range_t* range_n)
{
    u_char* p = range->data;
    u_char* last = range->data + range->len;
    off_t* field = &range_n->start;

    if (range_n == NULL)
        return NGX_ERROR;

    do {
        *field = 0;

        while (p < last) {

            if (*p >= '0' && *p <= '9') {
                (*field) = (*field) * 10 + (*p - '0');
            }
            else if (*p == '-') {
                if (field != &range_n->start) {
                    return NGX_ERROR;
                }

                field = &range_n->end;
                p++;
                break;
            }
            else if (*p == '/') {
                if (field != &range_n->end) {
                    return NGX_ERROR;
                }

                field = &range_n->total;
                p++;
                break;
            }
            else {
                return NGX_ERROR;
            }

            p++;
        }
    } while (p < last);

    if (field != &range_n->total) {
        return NGX_ERROR;
    }

    if (range_n->start > range_n->end || range_n->start >= range_n->total
        || range_n->end >= range_n->total)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
} /* }}} */

static void upload_putc(ngx_http_upload_ctx_t* upload_ctx, u_char c) { /* {{{ */
    if (!upload_ctx->discard_data) {
        *upload_ctx->output_buffer_pos = c;

        upload_ctx->output_buffer_pos++;

        if (upload_ctx->output_buffer_pos == upload_ctx->output_buffer_end)
            upload_flush_output_buffer(upload_ctx);
    }
} /* }}} */

static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t* upload_ctx, u_char* start, u_char* end) { /* {{{ */

    u_char* p;
    ngx_int_t rc;

    // No more data?
    if (start == end) {
        if (upload_ctx->state != upload_state_finish) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0, "premature end of body");
            return NGX_UPLOAD_MALFORMED; // Signal error if still haven't finished
        }
        else
            return NGX_OK; // Otherwise confirm end of stream
    }

    for (p = start; p != end; p++) {
        switch (upload_ctx->state) {
            /*
             * Seek the boundary
             */
        case upload_state_boundary_seek:
            if (*p == *upload_ctx->boundary_pos)
                upload_ctx->boundary_pos++;
            else
                upload_ctx->boundary_pos = upload_ctx->boundary_start;

            if (upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
                upload_ctx->state = upload_state_after_boundary;
                upload_ctx->boundary_start = upload_ctx->boundary.data;
                upload_ctx->boundary_pos = upload_ctx->boundary_start;
            }
            break;
        case upload_state_after_boundary:
            switch (*p) {
            case '\n':
                upload_ctx->state = upload_state_headers;
                upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
            case '\r':
                break;
            case '-':
                upload_ctx->state = upload_state_finish;
                break;
            }
            break;
            /*
             * Collect and store headers
             */
        case upload_state_headers:
            switch (*p) {
            case '\n':
                if (upload_ctx->header_accumulator_pos == upload_ctx->header_accumulator) {
                    upload_ctx->is_file = (upload_ctx->file_name.data == 0) || (upload_ctx->file_name.len == 0) ? 0 : 1;

                    rc = upload_start_file(upload_ctx);

                    if (rc != NGX_OK) {
                        upload_ctx->state = upload_state_finish;
                        return rc; // User requested to cancel processing
                    }
                    else {
                        upload_ctx->state = upload_state_data;
                        upload_ctx->output_buffer_pos = upload_ctx->output_buffer;
                    }
                }
                else {
                    *upload_ctx->header_accumulator_pos = '\0';

                    rc = upload_parse_part_header(upload_ctx, (char*)upload_ctx->header_accumulator,
                        (char*)upload_ctx->header_accumulator_pos);

                    if (rc != NGX_OK) {
                        upload_ctx->state = upload_state_finish;
                        return rc; // Malformed header
                    }
                    else
                        upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
                }
            case '\r':
                break;
            default:
                if (upload_ctx->header_accumulator_pos < upload_ctx->header_accumulator_end - 1)
                    *upload_ctx->header_accumulator_pos++ = *p;
                else {
                    ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0, "part header is too long");

                    upload_ctx->state = upload_state_finish;
                    return NGX_UPLOAD_MALFORMED;
                }
                break;
            }
            break;
            /*
             * Search for separating or terminating boundary
             * and output data simultaneously
             */
        case upload_state_data:
            if (*p == *upload_ctx->boundary_pos)
                upload_ctx->boundary_pos++;
            else {
                if (upload_ctx->boundary_pos == upload_ctx->boundary_start) {
                    // IE 5.0 bug workaround
                    if (*p == '\n') {
                        /*
                         * Set current matched position beyond LF and prevent outputting
                         * CR in case of unsuccessful match by altering boundary_start
                         */
                        upload_ctx->boundary_pos = upload_ctx->boundary.data + 2;
                        upload_ctx->boundary_start = upload_ctx->boundary.data + 1;
                    }
                    else
                        upload_putc(upload_ctx, *p);
                }
                else {
                    // Output partially matched lump of boundary
                    u_char* q;
                    for (q = upload_ctx->boundary_start; q != upload_ctx->boundary_pos; q++)
                        upload_putc(upload_ctx, *q);

                    p--; // Repeat reading last character

                    // And reset matched position
                    upload_ctx->boundary_start = upload_ctx->boundary.data;
                    upload_ctx->boundary_pos = upload_ctx->boundary_start;
                }
            }

            if (upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
                upload_ctx->state = upload_state_after_boundary;
                upload_ctx->boundary_pos = upload_ctx->boundary_start;

                upload_flush_output_buffer(upload_ctx);
                if (!upload_ctx->discard_data)
                    upload_finish_file(upload_ctx);
                else
                    upload_abort_file(upload_ctx);
            }
            break;
            /*
             * Skip trailing garbage
             */
        case upload_state_finish:
            break;
        }
    }

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_upload_cleanup_handler */
ngx_upload_cleanup_handler(void* data)
{
    ngx_upload_cleanup_t* cln = data;
    ngx_uint_t                  i;
    uint16_t* s;
    u_char                      do_cleanup = 0;

    if (!cln->aborted) {
        if (cln->fd != NGX_INVALID_FILE) {
            if (ngx_close_file(cln->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, cln->log, ngx_errno,
                    ngx_close_file_n " \"%s\" failed", cln->filename);
            }
        }

        if (cln->cleanup_statuses != NULL) {
            s = cln->cleanup_statuses->elts;

            for (i = 0; i < cln->cleanup_statuses->nelts; i++) {
                if (cln->headers_out->status == s[i]) {
                    do_cleanup = 1;
                }
            }
        }

        if (do_cleanup) {
            if (ngx_delete_file(cln->filename) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, cln->log, ngx_errno
                    , "failed to remove destination file \"%s\" after http status %l"
                    , cln->filename
                    , cln->headers_out->status
                );
            }
            else
                ngx_log_error(NGX_LOG_INFO, cln->log, 0
                    , "finished cleanup of file \"%s\" after http status %l"
                    , cln->filename
                    , cln->headers_out->status
                );
        }
    }
} /* }}} */

static ngx_int_t /* {{{ */
ngx_http_upload_test_expect(ngx_http_request_t* r)
{
    ngx_int_t   n;
    ngx_str_t* expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char*)"100-continue",
            sizeof("100-continue") - 1)
        != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "send 100 Continue");

    n = r->connection->send(r->connection,
        (u_char*)"HTTP/1.1 100 Continue" CRLF CRLF,
        sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
} /* }}} */
