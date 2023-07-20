#include "./tibero/sqlcli.h"
#include "PcaSessionPool.h"

static const int PcAPI_ERR_INVALID_SID = -30302;

#ifdef __cplusplus
extern "C" {
#endif

static int SID = 0;

int opnSession(ExtProcContext* epc) {
    //
    // gathering the session information (using tbcli local connection)
    //
    SQLRETURN rc;
    SQLHENV henv;
    SQLHDBC hdbc;
    SQLHSTMT hstmt;
    SQLSMALLINT errHdlType;
    SQLHANDLE errHdl;
    SQLCHAR* sessQuery = (SQLCHAR *)"select sid, nvl(sys_context('USERENV','INSTANCE_NAME'),'NULL') instance_name, "
			  "nvl(sys_context('USERENV','db_name'),'NULL') db_name, nvl(ipaddr,'127.0.0.1') ipaddr, "
			  "nvl(username,'NULL') db_user, nvl(osuser,'NULL') os_user, nvl(prog_name,'NULL') pgm, "
			  "DECODE(nvl(SYS_CONTEXT('userenv','network_protocol'),'BEQ'),'BEQ',1,'IPC',2,'TCP',3) protocol "
			  "from v$session where sid = (select tid from vt_mytid)";
    SQLINTEGER cnt;
    rc = SQLGetExtProcConnect(epc, &henv, &hdbc, &errHdlType, &errHdl);
    if (rc != 0)
        SQLExtProcRaiseErrorWithMsg(epc, 20100,
                                    (char*)"SQLGetExtProcConnect Failed");
    rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
    if (rc != 0)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"SQLAllocHandle Failed");
    rc = SQLExecDirect(hstmt, sessQuery, SQL_NTS);
    if (rc != 0) {
        SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"SQLExecDirect Failed");
    }

    struct {
        SQLINTEGER ind;
        SQLINTEGER val;
    } sid;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[33];
    } instance_name;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[33];
    } db_name;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[129];
    } ipaddr;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[33];
    } db_user;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[33];
    } os_user;
    struct {
        SQLINTEGER ind;
        SQLCHAR val[129];
    } pgm;
    struct {
        SQLINTEGER ind;
        SQLINTEGER val;
    } protocol;

    rc = SQLRowCount(hstmt, &cnt);
    if (rc != 0) {
        SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
        SQLExtProcRaiseErrorWithMsg(epc, 20100,
                                    (char*)"OpenSession Query Failed");
    } else {
        rc = SQLBindCol(hstmt, 1, SQL_C_LONG, &sid.val, 0, &sid.ind);
        rc = SQLBindCol(hstmt, 2, SQL_C_CHAR, &instance_name.val, 33,
                        &instance_name.ind);
        rc = SQLBindCol(hstmt, 3, SQL_C_CHAR, &db_name.val, 33, &db_name.ind);
        rc = SQLBindCol(hstmt, 4, SQL_C_CHAR, &ipaddr.val, 129, &ipaddr.ind);
        rc = SQLBindCol(hstmt, 5, SQL_C_CHAR, &db_user.val, 33, &db_user.ind);
        rc = SQLBindCol(hstmt, 6, SQL_C_CHAR, &os_user.val, 33, &os_user.ind);
        rc = SQLBindCol(hstmt, 7, SQL_C_CHAR, &pgm.val, 129, &pgm.ind);
        rc = SQLBindCol(hstmt, 8, SQL_C_LONG, &protocol.val, 0, &protocol.ind);
        rc = SQLFetch(hstmt);
        if (rc != 0) {
            SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"SQLFetch Failed");
        } else {
            PcaSession* session = PcaSessionPool::openSession(sid.val);
            if (!session)
                SQLExtProcRaiseErrorWithMsg(epc, 20100,
                                            (char*)"getSession Failed");
            ;
            SID = session->openSession(sid.val, (char*)instance_name.val,
                                       (char*)db_name.val, (char*)ipaddr.val,
                                       (char*)db_user.val, (char*)os_user.val,
                                       (char*)pgm.val, protocol.val, "", "");
        }
    }
    SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
    return 0;
}

unsigned char* EXT_ENC_RAW(ExtProcContext* epc, char* data, int data_len,
                           int enc_col_id, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return (unsigned char*)dst;
}

unsigned char* EXT_ENC_RAW_NM(ExtProcContext* epc, char* data, int data_len,
                              char* enc_col_nm, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt(enc_col_nm, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return (unsigned char*)dst;
}

unsigned char* EXT_ENC_RAW_RAW(ExtProcContext* epc, unsigned char* data,
                               int data_len, int enc_col_id, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return (unsigned char*)dst;
}

char* EXT_ENC_B64(ExtProcContext* epc, char* data, int data_len,
                  int enc_col_id) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    char* ret_str;
    ret_str = (char*)SQLExtProcAllocMemory(epc, dst_len + 1);
    memset(ret_str, 0, dst_len + 1);
    strncpy(ret_str, (char*)dst, dst_len);
    return ret_str;
}

char* EXT_ENC_B64_NM(ExtProcContext* epc, char* data, int data_len,
                     char* enc_col_nm) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt(enc_col_nm, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    char* ret_str;
    ret_str = (char*)SQLExtProcAllocMemory(epc, dst_len + 1);
    memset(ret_str, 0, dst_len + 1);
    strncpy(ret_str, (char*)dst, dst_len);
    return ret_str;
}

char* EXT_ENC_B64_C(ExtProcContext* epc, char* data, int data_len,
                    int enc_col_id) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->encrypt_c(enc_col_id, in_buffer, in_len, &dst,
                                  &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30301) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Encryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Encryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    char* ret_str;
    ret_str = (char*)SQLExtProcAllocMemory(epc, dst_len + 1);
    memset(ret_str, 0, dst_len + 1);
    strncpy(ret_str, (char*)dst, dst_len);
    return ret_str;
}

char* EXT_DEC_RAW(ExtProcContext* epc, unsigned char* data, int data_len,
                  int enc_col_id, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->decrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30401) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Decryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Decryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return (char*)dst;
}

char* EXT_DEC_RAW_NM(ExtProcContext* epc, unsigned char* data, int data_len,
                     char* enc_col_nm, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->decrypt(enc_col_nm, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30401) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Decryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Decryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return (char*)dst;
}

unsigned char* EXT_DEC_RAW_RAW(ExtProcContext* epc, unsigned char* data,
                               int data_len, int enc_col_id, int* ret_len) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->decrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30401) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Decryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Decryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    *ret_len = dst_len;
    return dst;
}

char* EXT_DEC_B64(ExtProcContext* epc, char* data, int data_len,
                  int enc_col_id) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->decrypt(enc_col_id, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30401) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Decryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Decryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    char* ret_str;
    ret_str = (char*)SQLExtProcAllocMemory(epc, dst_len + 1);
    memset(ret_str, 0, dst_len + 1);
    strncpy(ret_str, (char*)dst, dst_len);
    return ret_str;
}

char* EXT_DEC_B64_NM(ExtProcContext* epc, char* data, int data_len,
                     char* enc_col_nm) {
    if (!SID) {
        opnSession(epc);
    }
    PcaSession* session = PcaSessionPool::getSession(SID);
    if (!session)
        SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"getSession Failed");
    dgt_uint32 dst_len = 0;
    dgt_uint8* dst = 0;
    dgt_sint32 in_len = data_len;
    dgt_uint8* in_buffer = session->inBuffer(in_len);
    memcpy(in_buffer, data, in_len);
    dgt_sint32 rtn = 0;
    if ((rtn = session->decrypt(enc_col_nm, in_buffer, in_len, &dst,
                                &dst_len)) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        if (rtn == -30401) {
            SQLExtProcRaiseErrorWithMsg(
                epc, 20100, (char*)"Decryption Reject by Petra Cipher");
        } else {
            SQLExtProcRaiseErrorWithMsg(epc, 20100, (char*)"Decryption Failed");
        }
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    char* ret_str;
    ret_str = (char*)SQLExtProcAllocMemory(epc, dst_len + 1);
    memset(ret_str, 0, dst_len + 1);
    strncpy(ret_str, (char*)dst, dst_len);
    return ret_str;
}

#ifdef __cplusplus
}
#endif
