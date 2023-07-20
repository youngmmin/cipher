/*******************************************************************
 *   File Type          :       interface class implementation
 *   Classes            :       PcaMysqlCrypto
 *   Implementor        :       mwpark
 *   Create Date        :       2011. 11. 03
 *   Description        :       petra cipher mysql crypto external caller
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PcAPIL.h"
#include "PcaSessionPool.h"
#include "PcaThreadSessionPool.h"

typedef unsigned long ulong;
typedef char my_bool;

enum Item_result {
    STRING_RESULT = 0,
    REAL_RESULT,
    INT_RESULT,
    ROW_RESULT,
    DECIMAL_RESULT
};

typedef struct st_udf_args {
    unsigned int arg_count;           /* Number of arguments */
    enum Item_result *arg_type;       /* Pointer to item_results */
    char **args;                      /* Pointer to argument */
    unsigned long *lengths;           /* Length of string arguments */
    char *maybe_null;                 /* Set to 1 for all maybe_null args */
    char **attributes;                /* Pointer to attribute name */
    unsigned long *attribute_lengths; /* Length of attribute arguments */
    void *extension;
} UDF_ARGS;

/* This holds information about the result */

typedef struct st_udf_init {
    my_bool maybe_null;       /* 1 if function can return NULL */
    unsigned int decimals;    /* for real functions */
    unsigned long max_length; /* For string functions */
    char *ptr;                /* free pointer for function data */
    my_bool const_item;       /* 1 if function always returns the same value */
    void *extension;
} UDF_INIT;

#include <string.h>
#define strmov(a, b) strcpy(a, b)
#define bzero(a, b) memset(a, 0, b)

void cipher_logger(const char *fmt, ...) {
    FILE *fp;
    struct tm *cl;
    time_t current;

    if (fmt == NULL) return;
    fp = (FILE *)fopen("/tmp/petra_cipher.log", "a");
    if (fp == NULL) return;
    time(&current);
    cl = localtime(&current);
    fprintf(fp, "\n[%d.%02d.%02d.%02d:%02d:%02d] : ", cl->tm_year + 1900,
            cl->tm_mon + 1, cl->tm_mday, cl->tm_hour, cl->tm_min, cl->tm_sec);
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(fp, fmt, argptr);
    va_end(argptr);
    fflush(fp);
    fclose(fp);
    return;
}

#ifdef HAVE_DLOPEN

#if !defined(HAVE_GETHOSTBYADDR_R) || !defined(HAVE_SOLARIS_STYLE_GETHOST)
static pthread_mutex_t LOCK_hostname;
#endif
#endif

#define ERROR 20000
extern "C" {
#ifdef WIN32
__declspec(dllexport) my_bool
    pls_opnsess_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_opnsess_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{

    if (args->arg_count != 4 || args->arg_type[0] != STRING_RESULT ||
        args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT || args->arg_type[3] != INT_RESULT) {
        strmov(message, "Wrong arguments ");
        return 1;
    }
    /*
    ** As this function wants to have everything as strings, force all arguments
    ** to strings.
    */
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    args->arg_type[2] = STRING_RESULT;
    args->arg_type[3] = INT_RESULT;
    initid->maybe_null = 1; /* The result may be null */
    initid->max_length = 6; /* 3 digits + . + 2 decimals */
    return 0;
}

#ifdef WIN32
__declspec(dllexport) double pls_opnsess(UDF_INIT *initid, UDF_ARGS *args,
                                         char *is_null, char *error)
#else
double pls_opnsess(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#endif
{
    char instance_name[33];
    char db_user[33];
    char ip_address[33];
    memset(instance_name, 0, 33);
    memset(db_user, 0, 33);
    memset(ip_address, 0, 33);

    int src_len = args->lengths[0];
    memcpy(instance_name, args->args[0], src_len);
    instance_name[src_len] = 0;

    src_len = args->lengths[1];
    memcpy(db_user, args->args[1], src_len);
    db_user[src_len] = 0;

    src_len = args->lengths[2];
    memcpy(ip_address, args->args[2], src_len);
    ip_address[src_len] = 0;

    /* change domain to ipv4 */
    struct sockaddr_in addr;
    memset(&addr, '0', sizeof(addr));

    struct hostent *host = 0;
    if (inet_aton(args->args[2], &addr.sin_addr) == 0) {
        host = gethostbyname(args->args[2]);
        if (host && host->h_addrtype == AF_INET) {
            strncpy(ip_address,
                    inet_ntoa(*(struct in_addr *)host->h_addr_list[0]), 32);
        }
    }

#if 0
	dgt_sint64 db_sid=*((dgt_sint64*) args->args[3]);

	PcaThreadSession* session = PcaThreadSessionPool::openSession(ip_address,
	                                                              instance_name,
	                                                              instance_name,
	                                                              db_user,
	                                                              "not defined",
	                                                              db_sid,
	                                                              "",
	                                                              0,
	                                                              "");
	if ( session == 0 ) {
		return ERROR;
	}
#endif
    return 0;
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT || args->arg_type[2] != INT_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(80000);
    memset(ret_buf, 0, 80000);
    initid->ptr = ret_buf;
    initid->max_length = 80000;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_encrypt_deinit(UDF_INIT *initid)
#else
void pls_encrypt_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_encrypt(UDF_INIT *initid, UDF_ARGS *args,
                                        char *result, unsigned long *res_length,
                                        char *null_value, char *error)
#else
char *pls_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result,
                  unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 enc_col_id = *((dgt_sint64 *)args->args[2]);
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    char *ret_buf = initid->ptr;
    dgt_schar src_buf[80000];
    dgt_uint8 enc_buf[80000];
    memset(src_buf, 0, 80000);
    memset(enc_buf, 0, 80000);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 80000;
    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        return ret_buf;
    } else {
        //		if
        //((ret=session->encrypt(enc_col_id,(dgt_uint8*)src_buf,src_len,enc_buf,&dst_len))
        //< 0 ) {
        if ((ret = PcAPI_encrypt(sid, enc_col_id, (dgt_uint8 *)src_buf, src_len,
                                 enc_buf, &dst_len)) < 0) {
            if (ret == -30301) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                return ret_buf;
            }
        } else {
            strmov(ret_buf, (dgt_schar *)enc_buf);
            *res_length = dst_len;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_encrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_encrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(80000);
    memset(ret_buf, 0, 80000);
    initid->ptr = ret_buf;
    initid->max_length = 80000;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_encrypt_name_deinit(UDF_INIT *initid)
#else
void pls_encrypt_name_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_encrypt_name(UDF_INIT *initid, UDF_ARGS *args,
                                             char *result,
                                             unsigned long *res_length,
                                             char *null_value, char *error)
#else
char *pls_encrypt_name(UDF_INIT *initid, UDF_ARGS *args, char *result,
                       unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar *src_buf = new dgt_schar[80000];
    dgt_uint8 *enc_buf = new dgt_uint8[80000];
    dgt_schar enc_col_name[256];
    char *ret_buf = initid->ptr;
    memset(src_buf, 0, 80000);
    memset(enc_buf, 0, 80000);
    memset(enc_col_name, 0, 256);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 80000;
    int enc_col_name_len = args->lengths[2];

    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        delete src_buf;
        delete enc_buf;
        return 0;
    }
    if (args->args[2] != 0) {
        memcpy(enc_col_name, args->args[2], enc_col_name_len);
    } else {
        enc_col_name_len = 0;
    }
    enc_col_name[enc_col_name_len] = 0;
    if (enc_col_name_len == 0) {
        delete src_buf;
        delete enc_buf;
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        delete src_buf;
        delete enc_buf;
        return ret_buf;
    } else {
        // if
        // ((ret=session->encrypt(enc_col_name,(dgt_uint8*)src_buf,src_len,enc_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_encrypt_name(sid, enc_col_name, (dgt_uint8 *)src_buf,
                                      src_len, enc_buf, &dst_len)) < 0) {
            if (ret == -30301) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            }
        } else {
            strmov(ret_buf, (dgt_schar *)enc_buf);
            *res_length = dst_len;
            delete src_buf;
            delete enc_buf;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT || args->arg_type[2] != INT_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(80000);
    memset(ret_buf, 0, 80000);
    initid->ptr = ret_buf;
    initid->max_length = 80000;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_decrypt_deinit(UDF_INIT *initid)
#else
void pls_decrypt_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_decrypt(UDF_INIT *initid, UDF_ARGS *args,
                                        char *result, unsigned long *res_length,
                                        char *null_value, char *error)
#else
char *pls_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result,
                  unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 enc_col_id = *((dgt_sint64 *)args->args[2]);
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar src_buf[80000];
    dgt_uint8 dec_buf[80000];
    memset(src_buf, 0, 80000);
    memset(dec_buf, 0, 80000);
    char *ret_buf = initid->ptr;
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 80000;
    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        return ret_buf;
    } else {
        // if
        // ((ret=session->decrypt(enc_col_id,(dgt_uint8*)src_buf,src_len,dec_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_decrypt(sid, enc_col_id, (dgt_uint8 *)src_buf, src_len,
                                 dec_buf, &dst_len)) < 0) {
            if (ret == -30401) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                return ret_buf;
            }
        } else {
            //			strmov(ret_buf, (dgt_schar*)dec_buf);
            memcpy((dgt_uint8 *)ret_buf, dec_buf, dst_len);
            *res_length = dst_len;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_decrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_decrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(80000);
    memset(ret_buf, 0, 80000);
    initid->ptr = ret_buf;
    initid->max_length = 80000;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_decrypt_name_deinit(UDF_INIT *initid)
#else
void pls_decrypt_name_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_decrypt_name(UDF_INIT *initid, UDF_ARGS *args,
                                             char *result,
                                             unsigned long *res_length,
                                             char *null_value, char *error)
#else
char *pls_decrypt_name(UDF_INIT *initid, UDF_ARGS *args, char *result,
                       unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar src_buf[80000];
    dgt_uint8 dec_buf[80000];
    dgt_schar enc_col_name[256];
    char *ret_buf = initid->ptr;
    memset(src_buf, 0, 80000);
    memset(dec_buf, 0, 80000);
    memset(enc_col_name, 0, 256);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 80000;
    int enc_col_name_len = args->lengths[2];

    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        return 0;
    }
    if (args->args[2] != 0) {
        memcpy(enc_col_name, args->args[2], enc_col_name_len);
    } else {
        enc_col_name_len = 0;
    }
    enc_col_name[enc_col_name_len] = 0;
    if (enc_col_name_len == 0) {
        return 0;
    }

    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        return ret_buf;
    } else {
        // if
        // ((ret=session->decrypt(enc_col_name,(dgt_uint8*)src_buf,src_len,dec_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_decrypt_name(sid, enc_col_name, (dgt_uint8 *)src_buf,
                                      src_len, dec_buf, &dst_len)) < 0) {
            if (ret == -30401) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                return ret_buf;
            }
        } else {
            // strmov(ret_buf, (dgt_schar*)dec_buf);
            memcpy((dgt_uint8 *)ret_buf, dec_buf, dst_len);
            *res_length = dst_len;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_l_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_l_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT || args->arg_type[2] != INT_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(1048576);
    memset(ret_buf, 0, 1048576);
    initid->ptr = ret_buf;
    initid->max_length = 1048576;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_l_encrypt_deinit(UDF_INIT *initid)
#else
void pls_l_encrypt_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_l_encrypt(UDF_INIT *initid, UDF_ARGS *args,
                                          char *result,
                                          unsigned long *res_length,
                                          char *null_value, char *error)
#else
char *pls_l_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result,
                    unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 enc_col_id = *((dgt_sint64 *)args->args[2]);
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    char *ret_buf = initid->ptr;
    dgt_schar *src_buf = new dgt_schar[1048576];
    dgt_uint8 *enc_buf = new dgt_uint8[1048576];
    memset(src_buf, 0, 1048576);
    memset(enc_buf, 0, 1048576);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 1048576;
    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        delete src_buf;
        delete enc_buf;
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        delete src_buf;
        delete enc_buf;
        return ret_buf;
    } else {
        // if
        // ((ret=session->encrypt(enc_col_id,(dgt_uint8*)src_buf,src_len,enc_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_encrypt(sid, enc_col_id, (dgt_uint8 *)src_buf, src_len,
                                 enc_buf, &dst_len)) < 0) {
            if (ret == -30301) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            }
        } else {
            strmov(ret_buf, (dgt_schar *)enc_buf);
            *res_length = dst_len;
            delete src_buf;
            delete enc_buf;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_l_encrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_l_encrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(1048576);
    memset(ret_buf, 0, 1048576);
    initid->ptr = ret_buf;
    initid->max_length = 1048576;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_l_encrypt_name_deinit(UDF_INIT *initid)
#else
void pls_l_encrypt_name_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_l_encrypt_name(UDF_INIT *initid, UDF_ARGS *args,
                                               char *result,
                                               unsigned long *res_length,
                                               char *null_value, char *error)
#else
char *pls_l_encrypt_name(UDF_INIT *initid, UDF_ARGS *args, char *result,
                         unsigned long *res_length, char *null_value,
                         char *error)
#endif
{
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar *src_buf = new dgt_schar[1048576];
    dgt_uint8 *enc_buf = new dgt_uint8[1048576];
    dgt_schar enc_col_name[256];
    char *ret_buf = initid->ptr;
    memset(src_buf, 0, 1048576);
    memset(enc_buf, 0, 1048576);
    memset(enc_col_name, 0, 256);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 1048576;
    int enc_col_name_len = args->lengths[2];

    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        delete src_buf;
        delete enc_buf;
        return 0;
    }
    if (args->args[2] != 0) {
        memcpy(enc_col_name, args->args[2], enc_col_name_len);
    } else {
        enc_col_name_len = 0;
    }
    enc_col_name[enc_col_name_len] = 0;
    if (enc_col_name_len == 0) {
        delete src_buf;
        delete enc_buf;
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        delete src_buf;
        delete enc_buf;
        return ret_buf;
    } else {
        // if
        // ((ret=session->encrypt(enc_col_name,(dgt_uint8*)src_buf,src_len,enc_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_encrypt_name(sid, enc_col_name, (dgt_uint8 *)src_buf,
                                      src_len, enc_buf, &dst_len)) < 0) {
            if (ret == -30301) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete enc_buf;
                return ret_buf;
            }
        } else {
            strmov(ret_buf, (dgt_schar *)enc_buf);
            *res_length = dst_len;
            delete src_buf;
            delete enc_buf;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_l_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_l_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT || args->arg_type[2] != INT_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(1048576);
    memset(ret_buf, 0, 1048576);
    initid->ptr = ret_buf;
    initid->max_length = 1048576;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_l_decrypt_deinit(UDF_INIT *initid)
#else
void pls_l_decrypt_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_l_decrypt(UDF_INIT *initid, UDF_ARGS *args,
                                          char *result,
                                          unsigned long *res_length,
                                          char *null_value, char *error)
#else
char *pls_l_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result,
                    unsigned long *res_length, char *null_value, char *error)
#endif
{
    dgt_sint64 enc_col_id = *((dgt_sint64 *)args->args[2]);
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar *src_buf = new dgt_schar[1048576];
    dgt_uint8 *dec_buf = new dgt_uint8[1048576];
    memset(src_buf, 0, 1048576);
    memset(dec_buf, 0, 1048576);
    char *ret_buf = initid->ptr;
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 1048576;
    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        delete src_buf;
        delete dec_buf;
        return 0;
    }
    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        delete src_buf;
        delete dec_buf;
        return ret_buf;
    } else {
        // if
        // ((ret=session->decrypt(enc_col_id,(dgt_uint8*)src_buf,src_len,dec_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_decrypt(sid, enc_col_id, (dgt_uint8 *)src_buf, src_len,
                                 dec_buf, &dst_len)) < 0) {
            if (ret == -30401) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete dec_buf;
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete dec_buf;
                return ret_buf;
            }
        } else {
            //			strmov(ret_buf, (dgt_schar*)dec_buf);
            memcpy((dgt_uint8 *)ret_buf, dec_buf, dst_len);
            *res_length = dst_len;
            delete src_buf;
            delete dec_buf;
            return ret_buf;
        }
    }
}

#ifdef WIN32
__declspec(dllexport) my_bool
    pls_l_decrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#else
my_bool pls_l_decrypt_name_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
#endif
{
    if (args->arg_count != 3 || args->arg_type[0] != INT_RESULT ||
        args->arg_type[1] != STRING_RESULT ||
        args->arg_type[2] != STRING_RESULT) {
        strmov(message, "Super_priv is on or Wrong arguments ");
        return 1;
    }
    char *ret_buf = (char *)malloc(1048576);
    memset(ret_buf, 0, 1048576);
    initid->ptr = ret_buf;
    initid->max_length = 1048576;
    initid->maybe_null = 1;
    return 0;
}

#ifdef WIN32
__declspec(dllexport) void pls_l_decrypt_name_deinit(UDF_INIT *initid)
#else
void pls_l_decrypt_name_deinit(UDF_INIT *initid)
#endif
{
    char *ret_buf = initid->ptr;
    if (ret_buf) free(ret_buf);
}

#ifdef WIN32
__declspec(dllexport) char *pls_l_decrypt_name(UDF_INIT *initid, UDF_ARGS *args,
                                               char *result,
                                               unsigned long *res_length,
                                               char *null_value, char *error)
#else
char *pls_l_decrypt_name(UDF_INIT *initid, UDF_ARGS *args, char *result,
                         unsigned long *res_length, char *null_value,
                         char *error)
#endif
{
    dgt_sint64 db_sid = *((dgt_sint64 *)args->args[0]);
    dgt_schar *src_buf = new dgt_schar[1048576];
    dgt_uint8 *dec_buf = new dgt_uint8[1048576];
    dgt_schar enc_col_name[256];
    char *ret_buf = initid->ptr;
    memset(src_buf, 0, 1048576);
    memset(dec_buf, 0, 1048576);
    memset(enc_col_name, 0, 256);
    int src_len = args->lengths[1];
    dgt_uint32 dst_len = 1048576;
    int enc_col_name_len = args->lengths[2];

    if (args->args[1] != 0) {
        memcpy(src_buf, args->args[1], src_len);
    } else {
        src_len = 0;
    }
    src_buf[src_len] = 0;
    if (src_len == 0) {
        delete src_buf;
        delete dec_buf;
        return 0;
    }
    if (args->args[2] != 0) {
        memcpy(enc_col_name, args->args[2], enc_col_name_len);
    } else {
        enc_col_name_len = 0;
    }
    enc_col_name[enc_col_name_len] = 0;
    if (enc_col_name_len == 0) {
        delete src_buf;
        delete dec_buf;
        return 0;
    }

    int ret = 0;
    int sid = 0;
    if ((sid = PcAPI_getSession("")) < 0) {
        strmov(ret_buf, "petra_error");
        *res_length = strlen(ret_buf);
        delete src_buf;
        delete dec_buf;
        return ret_buf;
    } else {
        // if
        // ((ret=session->decrypt(enc_col_name,(dgt_uint8*)src_buf,src_len,dec_buf,&dst_len))
        // < 0 ) {
        if ((ret = PcAPI_decrypt_name(sid, enc_col_name, (dgt_uint8 *)src_buf,
                                      src_len, dec_buf, &dst_len)) < 0) {
            if (ret == -30401) {
                strmov(ret_buf, "petra_reject");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete dec_buf;
                return ret_buf;
            } else {
                strmov(ret_buf, "petra_error");
                *res_length = strlen(ret_buf);
                delete src_buf;
                delete dec_buf;
                return ret_buf;
            }
        } else {
            // strmov(ret_buf, (dgt_schar*)dec_buf);
            memcpy((dgt_uint8 *)ret_buf, dec_buf, dst_len);
            *res_length = dst_len;
            delete src_buf;
            delete dec_buf;
            return ret_buf;
        }
    }
}
}
