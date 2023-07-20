/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetCryptParam
 *   Implementor        :       shson
 *   Create Date        :       2017. 08. 29
 *   Description        :       KRED get crypt param
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetCryptParam.h"

#include "DgcDbProcess.h"
#include "DgcSqlHandle.h"
#include "PccKredSessionPool.h"

PccKredStmtGetCryptParam::PccKredStmtGetCryptParam(DgcPhyDatabase* pdb,
                                                   DgcSession* session,
                                                   DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_ACHR, 2049, "param");
    ResultParam = 0;
}

PccKredStmtGetCryptParam::~PccKredStmtGetCryptParam() {
    if (ResultParam) delete ResultParam;
}

dgt_sint32 PccKredStmtGetCryptParam::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    dgt_schar* crypt_param_name = (dgt_schar*)mrows->data();

    if (!ResultParam) ResultParam = new dgt_schar[2049];
    memset(ResultParam, 0, 2049);
    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar stext[512];
    memset(stext, 0, 512);

    // 1. get crypt param info
    memset(stext, 0, 512);
    sprintf(stext,
            "select	 crypt_param "
            "from    pfct_crypt_param "
            "where   param_name = '%s' ",
            crypt_param_name);

    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    if (sql_handle.execute(stext) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    while (!sql_handle.fetch(rtn_row) && rtn_row) {
        memcpy(ResultParam, (dgt_schar*)rtn_row, strlen((dgt_schar*)rtn_row));
    }

    IsExecuted = 1;
    NumRtnRows = 0;
    return 0;
}

dgt_uint8* PccKredStmtGetCryptParam::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
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
