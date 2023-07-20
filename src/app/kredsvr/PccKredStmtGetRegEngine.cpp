/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetRegEngine
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 08. 29
 *   Description        :       KRED get reg engine
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetRegEngine.h"

#include "DgcDbProcess.h"
#include "DgcSqlHandle.h"
#include "PccKredSessionPool.h"

PccKredStmtGetRegEngine::PccKredStmtGetRegEngine(DgcPhyDatabase* pdb,
                                                 DgcSession* session,
                                                 DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_ACHR, 2049, "param");
    ResultParam = 0;
}

PccKredStmtGetRegEngine::~PccKredStmtGetRegEngine() {
    if (ResultParam) delete ResultParam;
}

dgt_sint32 PccKredStmtGetRegEngine::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    dgt_sint64 reg_engine_id = *((dgt_sint64*)mrows->data());

    if (!ResultParam) ResultParam = new dgt_schar[2049];
    memset(ResultParam, 0, 2049);
    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar stext[512];
    memset(stext, 0, 512);

    // 1. get zone info
    memset(stext, 0, 512);
    sprintf(stext,
            "select	pattern_expr "
            "from    pfct_pattern a, pfct_pattern_expr b "
            "where   a.pattern_id = b.pattern_id "
            "  and   a.pattern_id = '%lld'",
            reg_engine_id);

    sprintf(ResultParam, "(regular=(1=");
    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    if (sql_handle.execute(stext) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    // ex)
    //      (regular=
    //              (1=
    //                      (1=[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9][0-9])
    //                      (2=[0-9]{13})
    //                      (3=[0-9]{4})
    //              ) column no end
    //      ) regular end
    dgt_schar reg_pttn_expr[257];  // pattern_expr
    dgt_sint32 pttn_idx = 1;
    dgt_schar buf[512];
    memset(buf, 0, 512);
    while (!sql_handle.fetch(rtn_row) && rtn_row) {
        memset(reg_pttn_expr, 0, 257);
        memcpy(reg_pttn_expr, (dgt_schar*)rtn_row, strlen((dgt_schar*)rtn_row));
        sprintf(buf, "(%d=\"%s\")", pttn_idx, reg_pttn_expr);
        strcat(ResultParam, buf);
        pttn_idx++;
    }
    strcat(ResultParam, "))");
    if (pttn_idx == 1)
        NumRtnRows = 0;
    else
        NumRtnRows = 1;
    IsExecuted = 1;
    return 0;
}

dgt_uint8* PccKredStmtGetRegEngine::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (NumRtnRows == 1) return (dgt_uint8*)ResultParam;
    THROWnR(
        DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found pttn")),
        0);
    return 0;
}
