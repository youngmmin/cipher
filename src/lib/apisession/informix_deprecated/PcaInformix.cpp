#include <stdio.h>
#include <string.h>

#include "PcaThreadSessionPool.h"
#include "milib.h"

//#define NO_QUERY_VERSION

void informix_logger(const char *fmt, ...) {
    FILE *fp;

    if (fmt == NULL) return;
    fp = (FILE *)fopen("/tmp/informix_cipher.log", "a");
    if (fp == NULL) return;
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(fp, fmt, argptr);
    va_end(argptr);
    fflush(fp);
    fclose(fp);
    return;
}

extern "C" {

mi_lvarchar *pls_encrypt_b64_id(mi_integer sid, mi_lvarchar *src_data,
                                mi_integer enc_col_id, MI_FPARAM *fp) {
    char *srcDataTmp = mi_get_vardata(src_data);
    int db_sid = sid;

    int ret = 0;
    PcaThreadSession *session = PcaThreadSessionPool::getSession(sid);
    if (session == 0) {
#ifndef NO_QUERY_VERSION
        MI_CONNECTION *conn;
        char cmd_buffer[512];
        char *cmd = NULL;
        MI_STATEMENT *stmt_hdl1 = NULL;
        mi_integer count, result;
        MI_ROW *row;
        MI_ROW_DESC *rowdesc;
        mi_integer error;
        mi_integer numcols;
        mi_integer i;
        mi_integer res = 0;
        mi_integer *collen;
        MI_DATUM *colval;
        MI_TYPE_DESC **coltypedesc;
        MI_MEMORY_DURATION lastduration;
        if ((conn = mi_open(NULL, NULL, NULL)) == NULL) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 1");
        }
        sprintf(
            cmd_buffer,
            "select FIRST 1 sid, nvl(username,'null') db_user, "
            "nvl(decode(pid,-1,replace(replace(hostname,':',''),'f',''),'127.0."
            "0.1'),'127.0.0.1') ipaddr from sysmaster:syssessions where sid=%d",
            db_sid);
        if ((stmt_hdl1 = mi_prepare(conn, cmd_buffer, NULL)) == NULL) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 2");
        }
        if ((result = mi_exec_prepared_statement(stmt_hdl1, MI_BINARY, 0, 0,
                                                 NULL, 0, 0, NULL, 0, NULL)) ==
            MI_ERROR) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 3");
        }
        while ((result = mi_get_result(conn)) != MI_NO_MORE_RESULTS) {
            switch (result) {
                case MI_ERROR:
                    mi_db_error_raise(NULL, MI_FATAL,
                                      (char *)"Petra Open Session Failed 4");
                case MI_DDL: /* fall through */
                case MI_DML:
                    cmd = mi_result_command_name(conn);
                    if ((count = mi_result_row_count(conn)) == MI_ERROR) {
                        mi_db_error_raise(
                            NULL, MI_FATAL,
                            (char *)"Petra Open Session Failed 5");
                    } else
                        break;
                case MI_ROWS:
                    /* for first row */
                    if ((row = mi_next_row(conn, &error)) != NULL) {
                        rowdesc = mi_get_row_desc_without_row(conn);
                        numcols = mi_column_count(rowdesc);
                        colval =
                            (MI_DATUM *)mi_alloc(sizeof(MI_DATUM) * numcols);
                        collen = (mi_integer *)mi_alloc(sizeof(mi_integer) *
                                                        numcols);
                        coltypedesc = (MI_TYPE_DESC **)mi_alloc(
                            sizeof(MI_TYPE_DESC *) * numcols);
                        for (i = 0; i < numcols; i++) {
                            res = mi_value(row, i, &colval[i], &collen[i]);
                            coltypedesc[i] = mi_column_typedesc(rowdesc, i);
                            switch (res) {
                                case MI_ERROR:
                                    mi_db_error_raise(
                                        NULL, MI_FATAL,
                                        (char *)"Petra Open Session Failed 6");
                                case MI_NULL_VALUE:
                                    break;
                                case MI_NORMAL_VALUE:
                                case MI_COLLECTION_VALUE:
                                case MI_ROW_VALUE:
                                    break;
                                default:
                                    mi_db_error_raise(
                                        NULL, MI_FATAL,
                                        (char *)"Petra Open Session Failed 7");
                            } /* switch */
                        }     /* for */
                    }
                    if (error == MI_ERROR) {
                        mi_db_error_raise(
                            NULL, MI_FATAL,
                            (char *)"Petra Open Session Failed 7");
                    }
                    break;
                default:
                    mi_db_error_raise(NULL, MI_FATAL,
                                      (char *)"Petra Open Session Failed 8");
            }
        }
        char db_user[32];
        char ipaddr[65];
        memset(db_user, 0, 32);
        memset(ipaddr, 0, 65);
        memcpy(db_user, (char *)mi_get_vardata((mi_lvarchar *)colval[1]), 32);
        memcpy(ipaddr, (char *)mi_get_vardata((mi_lvarchar *)colval[2]), 16);
        if (mi_query_finish(conn) == MI_ERROR) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 9");
        }
        if (conn != NULL) mi_close(conn);
        session = PcaThreadSessionPool::openSession(
            ipaddr, "null", "null", db_user, "null", sid, "null", 0, db_user);
        if (session == 0) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 10");
        }
#else
        char db_user[32];
        char ipaddr[65];
        memset(db_user, 0, 32);
        memset(ipaddr, 0, 65);
        sprintf(ipaddr, "127.0.0.1");
        sprintf(db_user, "informix");
        session = PcaThreadSessionPool::openSession(
            ipaddr, "null", "null", db_user, "null", sid, "null", 0, db_user);
        if (session == 0) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char*)"Petra Open Session Failed 10");
        }
#endif
    }
    dgt_uint8 *dst = 0;
    dgt_uint32 dst_len = 0;
    dgt_uint32 src_len = mi_get_varlen(src_data);
    if (src_len > 4000) src_len = 0;
    mi_lvarchar *dst_data;
    if ((ret = session->encrypt(enc_col_id, (dgt_uint8 *)srcDataTmp, src_len,
                                &dst, &dst_len)) < 0) {
        if (ret == -30301) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Encryption Rejected By Petra");
        } else {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Encryption failed");
        }
    } else {
        dst_data = mi_new_var(dst_len);
        mi_set_vardata(dst_data, (dgt_schar *)dst);
        if (session->getNewSqlFlag() != 0) {
            session->setSqlHash((dgt_schar *)"Encrypt Request", 5);
        }
    }
    if (dst_len == 0) {
        mi_fp_setreturnisnull(fp, 0, MI_TRUE);
    }
    return dst_data;
}

mi_lvarchar *pls_decrypt_b64_id(mi_integer sid, mi_lvarchar *src_data,
                                mi_integer enc_col_id, MI_FPARAM *fp) {
    char *srcDataTmp = mi_get_vardata(src_data);

    int db_sid = sid;
    int ret = 0;
    PcaThreadSession *session = PcaThreadSessionPool::getSession(sid);
    if (session == 0) {
#ifndef NO_QUERY_VERSION
        MI_CONNECTION *conn;
        char cmd_buffer[512];
        char *cmd = NULL;
        MI_STATEMENT *stmt_hdl1 = NULL;
        mi_integer count, result;
        MI_ROW *row;
        MI_ROW_DESC *rowdesc;
        mi_integer error;
        mi_integer numcols;
        mi_integer i;
        mi_integer res = 0;
        mi_integer *collen;
        MI_DATUM *colval;
        MI_TYPE_DESC **coltypedesc;
        MI_MEMORY_DURATION lastduration;
        if ((conn = mi_open(NULL, NULL, NULL)) == NULL) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 1");
        }
        sprintf(
            cmd_buffer,
            "select FIRST 1 sid, nvl(username,'null') db_user, "
            "nvl(decode(pid,-1,replace(replace(hostname,':',''),'f',''),'127.0."
            "0.1'),'127.0.0.1') ipaddr from sysmaster:syssessions where sid=%d",
            db_sid);
        if ((stmt_hdl1 = mi_prepare(conn, cmd_buffer, NULL)) == NULL) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 2");
        }
        if ((result = mi_exec_prepared_statement(stmt_hdl1, MI_BINARY, 0, 0,
                                                 NULL, 0, 0, NULL, 0, NULL)) ==
            MI_ERROR) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 3");
        }
        while ((result = mi_get_result(conn)) != MI_NO_MORE_RESULTS) {
            switch (result) {
                case MI_ERROR:
                    mi_db_error_raise(NULL, MI_FATAL,
                                      (char *)"Petra Open Session Failed 4");
                case MI_DDL: /* fall through */
                case MI_DML:
                    cmd = mi_result_command_name(conn);
                    if ((count = mi_result_row_count(conn)) == MI_ERROR) {
                        mi_db_error_raise(
                            NULL, MI_FATAL,
                            (char *)"Petra Open Session Failed 5");
                    } else
                        break;
                case MI_ROWS:
                    /* for first row */
                    if ((row = mi_next_row(conn, &error)) != NULL) {
                        rowdesc = mi_get_row_desc_without_row(conn);
                        numcols = mi_column_count(rowdesc);
                        colval =
                            (MI_DATUM *)mi_alloc(sizeof(MI_DATUM) * numcols);
                        collen = (mi_integer *)mi_alloc(sizeof(mi_integer) *
                                                        numcols);
                        coltypedesc = (MI_TYPE_DESC **)mi_alloc(
                            sizeof(MI_TYPE_DESC *) * numcols);
                        for (i = 0; i < numcols; i++) {
                            res = mi_value(row, i, &colval[i], &collen[i]);
                            coltypedesc[i] = mi_column_typedesc(rowdesc, i);
                            switch (res) {
                                case MI_ERROR:
                                    mi_db_error_raise(
                                        NULL, MI_FATAL,
                                        (char *)"Petra Open Session Failed 6");
                                case MI_NULL_VALUE:
                                    break;
                                case MI_NORMAL_VALUE:
                                case MI_COLLECTION_VALUE:
                                case MI_ROW_VALUE:
                                    break;
                                default:
                                    mi_db_error_raise(
                                        NULL, MI_FATAL,
                                        (char *)"Petra Open Session Failed 7");
                            } /* switch */
                        }     /* for */
                    }
                    if (error == MI_ERROR) {
                        mi_db_error_raise(
                            NULL, MI_FATAL,
                            (char *)"Petra Open Session Failed 7");
                    }
                    break;
                default:
                    mi_db_error_raise(NULL, MI_FATAL,
                                      (char *)"Petra Open Session Failed 8");
            }
        }
        char db_user[32];
        char ipaddr[65];
        memset(db_user, 0, 32);
        memset(ipaddr, 0, 65);
        memcpy(db_user, (char *)mi_get_vardata((mi_lvarchar *)colval[1]), 32);
        memcpy(ipaddr, (char *)mi_get_vardata((mi_lvarchar *)colval[2]), 16);
        if (mi_query_finish(conn) == MI_ERROR) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 9");
        }
        if (conn != NULL) mi_close(conn);
        session = PcaThreadSessionPool::openSession(ipaddr, "null", "null",
                                                    db_user, "null", db_sid,
                                                    "null", 0, db_user);
        if (session == 0) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Open Session Failed 10");
        }
#else
        char db_user[32];
        char ipaddr[65];
        memset(db_user, 0, 32);
        memset(ipaddr, 0, 65);
        sprintf(ipaddr, "127.0.0.1");
        sprintf(db_user, "informix");
        session = PcaThreadSessionPool::openSession(ipaddr, "null", "null",
                                                    db_user, "null", db_sid,
                                                    "null", 0, db_user);
        if (session == 0) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char*)"Petra Open Session Failed 10");
        }
#endif
    }
    dgt_uint8 *dst = 0;
    dgt_uint32 dst_len = 0;
    dgt_uint32 src_len = mi_get_varlen(src_data);
    if (src_len > 4000) src_len = 0;
    mi_lvarchar *dst_data;
    if ((ret = session->decrypt(enc_col_id, (dgt_uint8 *)srcDataTmp, src_len,
                                &dst, &dst_len)) < 0) {
        if (ret == -30301) {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Decryption Rejected By Petra");
        } else {
            mi_db_error_raise(NULL, MI_FATAL,
                              (char *)"Petra Decryption failed");
        }
    } else {
        dst_data = mi_new_var(dst_len);
        mi_set_vardata(dst_data, (dgt_schar *)dst);
        if (session->getNewSqlFlag() != 0) {
            session->setSqlHash((dgt_schar *)"Decryption Request", 5);
        }
    }
    if (dst_len == 0) {
        mi_fp_setreturnisnull(fp, 0, MI_TRUE);
    }
    return dst_data;
}
}
