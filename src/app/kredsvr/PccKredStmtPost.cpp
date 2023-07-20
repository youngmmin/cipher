/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtPost
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 12. 15
 *   Description        :       KRED post statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtPost.h"

#include "DgcDbProcess.h"
#include "PaccUserGroup.h"
#include "PccPostControl.h"
#include "PccTableTypes.h"

PccKredStmtPost::PccKredStmtPost(DgcPhyDatabase* pdb, DgcSession* session,
                                 DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0), Result(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_SB4, 0, "result");
}

PccKredStmtPost::~PccKredStmtPost() {}

dgt_sint32 PccKredStmtPost::execute(DgcMemRows* mrows,
                                    dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                                 DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    pc_type_posting_in* brow = (pc_type_posting_in*)mrows->data();
    //
    // get session user info
    //
    dgt_schar sql_text[1024];
    memset(sql_text, 0, 1024);
    dg_sprintf(sql_text, "select * from pt_sess_user where psu_id=%lld",
               brow->user_sid);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    DgcExcept* e = 0;
    pt_type_sess_user sess_user;
    dgt_uint8* tmp_row = 0;
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        delete EXCEPTnC;
        delete sql_stmt;
        //              RTHROWnR(e,DgcError(SPOS,"execute[%lld]
        //              failed.",brow->user_sid),-1);
    } else {
        if ((tmp_row = sql_stmt->fetch()) == 0) {
            delete EXCEPTnC;
            delete sql_stmt;
            //                      RTHROWnR(e,DgcError(SPOS,"fetch[%lld]
            //                      failed",brow->user_sid),-1);
        } else {
            memcpy(&sess_user, tmp_row, sizeof(sess_user));
            delete sql_stmt;
        }
    }

    //
    // get encryption column info
    //
    memset(sql_text, 0, 1024);
    dg_sprintf(sql_text,
               "select b.table_name, a.column_name "
               "from pct_enc_column a, pct_enc_table b "
               "where a.enc_tab_id = b.enc_tab_id "
               "and   a.enc_col_id=%lld",
               brow->enc_col_id);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                          strlen(sql_text));
    e = 0;
    tmp_row = 0;
    typedef struct {
        dgt_schar table_name[130];
        dgt_schar column_name[130];
    } column_info;
    column_info col_info;
    memset(&col_info, 0, sizeof(column_info));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        delete EXCEPTnC;
        delete sql_stmt;
    } else {
        if ((tmp_row = sql_stmt->fetch()) == 0) {
            delete EXCEPTnC;
            delete sql_stmt;
        } else {
            memcpy(&col_info, tmp_row, sizeof(column_info));
            delete sql_stmt;
        }
    }
    //
    // posting the msg to cipher`s client
    //

    pt_sess_stat sess_stat;
    memset(&sess_stat, 0, sizeof(pt_sess_stat));
    sess_stat.psu_id = brow->user_sid;
    dgt_session sess_info;
    memset(&sess_info, 0, sizeof(dgt_session));
    sess_info.user = &sess_user;
    sess_info.stat = &sess_stat;
    DgcSession cipher_session(&sess_info);
    PaccUserGroup user_group(cipher_session);
    PccPostControl post_ctl(cipher_session, user_group);

    dgt_schar msg[512];
    memset(msg, 0, 512);
    if (brow->err_code == -30301) {
        //
        // no privilege encryption
        //
        sprintf(msg, "\r\n\r\n[%s.%s] Encryption Rejected by Petra Cipher.",
                col_info.table_name, col_info.column_name);
        post_ctl.postCipherMsg(msg);
    } else if (brow->err_code == -30389) {
        //
        // src_Data Length > max Column Length exceed
        //
        sprintf(msg, "\r\n\r\n[%s.%s] data max length exceeds.",
                col_info.table_name, col_info.column_name);
        post_ctl.postCipherMsg(msg);
    } else if (brow->err_code == -30115) {
        //
        // double encryption  error
        //
        sprintf(msg, "\r\n\r\n[%s.%s] already encrypted data.",
                col_info.table_name, col_info.column_name);
        post_ctl.postCipherMsg(msg);
    }

    IsExecuted = 1;
    NumRtnRows = 0;
    Result = 1;
    return 0;
}

dgt_uint8* PccKredStmtPost::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (NumRtnRows++ == 0) return (dgt_uint8*)&Result;
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
