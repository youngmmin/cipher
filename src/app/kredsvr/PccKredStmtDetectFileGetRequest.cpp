/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtDetectFileGetRequest
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 29
 *   Description        :       KRED
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtDetectFileGetRequest.h"

#include "DgcDbProcess.h"
#include "DgcSqlHandle.h"
#include "PccKredSessionPool.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccKredStmtDetectFileGetRequest::PccKredStmtDetectFileGetRequest(
    DgcPhyDatabase* pdb, DgcSession* session, DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term) {
    SelectListDef = new DgcClass("select_list", 4);
    SelectListDef->addAttr(DGC_SB8, 0, "DIR_ID");
    SelectListDef->addAttr(DGC_SB8, 0, "FILD_ID");
    SelectListDef->addAttr(DGC_SB8, 0, "PTTN_NUM");
    SelectListDef->addAttr(DGC_SCHR, 2048, "FILE_NAME");

    RqstList = new DgcMemRows(SelectListDef);
    RqstList->reset();
}

PccKredStmtDetectFileGetRequest::~PccKredStmtDetectFileGetRequest() {}

dgt_sint32 PccKredStmtDetectFileGetRequest::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);

    dgt_sint64 dir_id = *(dgt_sint64*)mrows->getColPtr(1);

    dgt_schar sql_text[512] = {0};
    dg_sprintf(sql_text,
               "select dir_id, file_id, pttn_num, file_name from "
               "pct_file_detect_hist where dir_id = %lld\n",
               dir_id);

    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    if (sql_handle.execute(sql_text) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);

    dgt_void* rtn_row = 0;
    while ((rtn_row = sql_handle.fetch())) {
        RqstList->add();
        RqstList->next();
        memcpy(RqstList->data(), rtn_row, RqstList->rowSize());
    }

    RqstList->rewind();
    IsExecuted = 1;
    return 0;
}

dgt_uint8* PccKredStmtDetectFileGetRequest::fetch() throw(DgcLdbExcept,
                                                          DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (RqstList->next()) return (dgt_uint8*)RqstList->data();
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
