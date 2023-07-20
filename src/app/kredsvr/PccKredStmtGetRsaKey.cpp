/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetRsaKey
 *   Implementor        :       mwpark
 *   Create Date        :       2019. 04. 30
 *   Description        :       KRED get rsa key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetRsaKey.h"

#include "DgcDbProcess.h"
#include "DgcSqlHandle.h"
#include "PccKredSessionPool.h"

PccKredStmtGetRsaKey::PccKredStmtGetRsaKey(DgcPhyDatabase* pdb,
                                           DgcSession* session,
                                           DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_ACHR, 2049, "param");
    ResultParam = 0;
    if (strlen(Session->clientCommIP()) == 0) {
        // beq (get local server ip)
        struct hostent* host;
        struct in_addr addr;
        char hostname[512];
        memset(hostname, 0, 512);
        gethostname(hostname, 512);
        host = gethostbyname(hostname);
        if (host) {
            if (*host->h_addr_list) {
                bcopy(*host->h_addr_list, (char*)&addr, sizeof(addr));
                Session->setClientCommIP(inet_ntoa(addr));
            }
        }
    }
}

PccKredStmtGetRsaKey::~PccKredStmtGetRsaKey() {
    if (ResultParam) delete ResultParam;
}

dgt_sint32 PccKredStmtGetRsaKey::getKeyPriv(dgt_sint64 key_id, dgt_schar* ip) {
    dgt_schar sql_text[512];
    DgcMemRows v_bind_key(1);
    v_bind_key.addAttr(DGC_SB8, 0, "key_id");
    v_bind_key.reset();
    v_bind_key.add();
    v_bind_key.next();
    memcpy(v_bind_key.getColPtr(1), &key_id, sizeof(dgt_sint64));
    v_bind_key.rewind();
    dg_sprintf(sql_text, "select key_id from pct_ip_key_ctrl where key_id=:1");
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    DgcExcept* e = 0;
    if (sql_stmt == 0 || sql_stmt->execute(&v_bind_key, 0) < 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        delete e;
        DgcWorker::PLOG.tprintf(0, "[%s] execute failed\n", sql_text);
        return 1;
    }
    dgt_sint64* cnt = 0;
    dgt_sint64 temp = 0;
    if ((cnt = (dgt_sint64*)sql_stmt->fetch()) == 0) {
        e = EXCEPTnC;
        delete e;
        delete sql_stmt;
        return 1;
    } else {
        memcpy(&temp, cnt, sizeof(*cnt));
        delete sql_stmt;
        delete EXCEPTnC;
        if (temp == 0) return 1;
    }
    DgcMemRows v_bind(2);
    v_bind.addAttr(DGC_SB8, 0, "key_id");
    v_bind.addAttr(DGC_SCHR, 65, "ip");
    v_bind.reset();
    v_bind.add();
    v_bind.next();
    memcpy(v_bind.getColPtr(1), &key_id, sizeof(dgt_sint64));
    memcpy(v_bind.getColPtr(2), ip, 65);
    v_bind.rewind();
    memset(sql_text, 0, 512);
    dg_sprintf(sql_text,
               "select key_id from pct_ip_key_ctrl where key_id=:1 and "
               "(allow_ip_addr=:2 or allow_ip_addr='*')");
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                          strlen(sql_text));
    e = 0;
    if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        delete e;
        DgcWorker::PLOG.tprintf(0, "[%s] execute failed\n", sql_text);
        return 1;
    }
    cnt = 0;
    temp = 0;
    if ((cnt = (dgt_sint64*)sql_stmt->fetch()) == 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        delete e;
    } else {
        memcpy(&temp, cnt, sizeof(*cnt));
        delete sql_stmt;
        delete EXCEPTnC;
        if (temp > 0) return 1;
    }

    v_bind.reset();
    v_bind.add();
    v_bind.next();
    memcpy(v_bind.getColPtr(1), &key_id, sizeof(dgt_sint64));
    memcpy(v_bind.getColPtr(2), ip, 65);
    v_bind.rewind();
    memset(sql_text, 0, 512);
    dg_sprintf(sql_text,
               "select key_id from pct_ip_key_ctrl where (key_id=:1 or "
               "key_id=0) and allow_ip_addr=:2");
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                          strlen(sql_text));
    e = 0;
    if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        delete e;
        DgcWorker::PLOG.tprintf(0, "[%s] execute failed\n", sql_text);
        return 1;
    }
    cnt = 0;
    temp = 0;
    if ((cnt = (dgt_sint64*)sql_stmt->fetch()) == 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        delete e;
    } else {
        memcpy(&temp, cnt, sizeof(*cnt));
        delete sql_stmt;
        delete EXCEPTnC;
        if (temp > 0) return 1;
    }

    return 0;
}

dgt_sint32 PccKredStmtGetRsaKey::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    dgt_schar* key_name = (dgt_schar*)mrows->data();

    if (!ResultParam) ResultParam = new dgt_schar[2049];
    memset(ResultParam, 0, 2049);
    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar stext[512];
    memset(stext, 0, 512);

    // 1. get rsa key info
    memset(stext, 0, 512);
    sprintf(stext,
            "select	 rsa_key_id, key_str "
            "from    pct_rsa_key "
            "where   upper(key_name) = upper('%s') ",
            key_name);

    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    typedef struct {
        dgt_sint64 rsa_key_id;
        dgt_schar key_str[2049];
    } rsa_key_rtn;
    rsa_key_rtn rtn;
    memset(&rtn, 0, sizeof(rsa_key_rtn));
    if (sql_handle.execute(stext) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    if (!sql_handle.fetch(rtn_row) && rtn_row) {
        memcpy(&rtn, (rsa_key_rtn*)rtn_row, sizeof(rsa_key_rtn));
        memcpy(ResultParam, (dgt_schar*)rtn.key_str,
               strlen((dgt_schar*)rtn.key_str));
    } else {
        THROWnR(DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "get rsa key[%s] failed", key_name)),
                -1);
    }
    dgt_sint64 key_id = rtn.rsa_key_id;
    dgt_sint32 priv_flag = getKeyPriv(key_id, Session->clientCommIP());
    if (priv_flag == 0) {
        //
        // log key reject history
        //
        pct_type_key_request_hist rqst_hist;
        memset(&rqst_hist, 0, sizeof(rqst_hist));
        rqst_hist.key_id = key_id;
        rqst_hist.request_date = dgtime(&rqst_hist.request_date);
        strncpy(rqst_hist.request_ip, Session->clientCommIP(), 65);
        sprintf(rqst_hist.reserved, "[%d]",
                DgcDbProcess::db().pdb()->dbHeader()->productID());
        DgcTableSegment* tab =
            (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
                "PCT_KEY_REJECT_HIST_TEMP");
        if (tab == 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcWorker::PLOG.tprintf(
                    0, *e, "getTable[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                delete e;
            } else {
                DgcWorker::PLOG.tprintf(
                    0, "Table[PCT_KEY_REJECT_HIST_TEMP] not found.\n");
            }
        } else {
            tab->unlockShare();
            DgcRowList rows(tab);
            rows.reset();
            if (tab->pinInsert(DgcDbProcess::sess(), rows, 1) != 0) {
                DgcExcept* e = EXCEPTnC;
                DgcWorker::PLOG.tprintf(
                    0, *e, "pinInsert[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                delete e;
            } else {
                rows.rewind();
                rows.next();
                memcpy(rows.data(), &rqst_hist, rows.rowSize());
                rows.rewind();
                if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
                    DgcExcept* e = EXCEPTnC;
                    rows.rewind();
                    if (tab->pinRollback(rows)) delete EXCEPTnC;
                    DgcWorker::PLOG.tprintf(
                        0, *e,
                        "insertCommit[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                    delete e;
                }
            }
        }
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "not allowed ip[%s]-key[%lld]",
                                          Session->clientCommIP(), key_id)),
                -1);
    }
    IsExecuted = 1;
    NumRtnRows = 0;
    //
    // log key request history
    //
    pct_type_key_request_hist rqst_hist;
    memset(&rqst_hist, 0, sizeof(rqst_hist));
    rqst_hist.key_id = key_id;
    rqst_hist.request_date = dgtime(&rqst_hist.request_date);
    strncpy(rqst_hist.request_ip, Session->clientCommIP(), 65);
    sprintf(rqst_hist.reserved, "[%d]",
            DgcDbProcess::db().pdb()->dbHeader()->productID());
    DgcTableSegment* tab =
        (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
            "PCT_KEY_REQUEST_HIST_TEMP");
    if (tab == 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(
                0, *e, "getTable[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
            delete e;
        } else {
            DgcWorker::PLOG.tprintf(
                0, "Table[PCT_KEY_REQUEST_HIST_TEMP] not found.\n");
        }
    } else {
        tab->unlockShare();
        DgcRowList rows(tab);
        rows.reset();
        if (tab->pinInsert(DgcDbProcess::sess(), rows, 1) != 0) {
            DgcExcept* e = EXCEPTnC;
            DgcWorker::PLOG.tprintf(
                0, *e, "pinInsert[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
            delete e;
        } else {
            rows.rewind();
            rows.next();
            memcpy(rows.data(), &rqst_hist, rows.rowSize());
            rows.rewind();
            if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
                DgcExcept* e = EXCEPTnC;
                rows.rewind();
                if (tab->pinRollback(rows)) delete EXCEPTnC;
                DgcWorker::PLOG.tprintf(
                    0, *e, "insertCommit[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
                delete e;
            }
        }
    }
    IsExecuted = 1;
    NumRtnRows = 0;
    return 0;
}

dgt_uint8* PccKredStmtGetRsaKey::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (NumRtnRows++ == 0) return (dgt_uint8*)ResultParam;
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
