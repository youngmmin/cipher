/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtFileLogRequest
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 02. 07
 *   Description        :       KRED
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtFileLogRequest.h"

#include "DgcDbProcess.h"
#include "PccKredSessionPool.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccKredStmtFileLogRequest::PccKredStmtFileLogRequest(DgcPhyDatabase* pdb,
                                                     DgcSession* session,
                                                     DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0), Result(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_SB4, 0, "result");
}

PccKredStmtFileLogRequest::~PccKredStmtFileLogRequest() {}

dgt_sint32 PccKredStmtFileLogRequest::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    pc_type_file_request_in* brow = (pc_type_file_request_in*)mrows->data();
    DgcTableSegment* tab =
        (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
            "PCT_FILE_CRYPT_HIST_TEMP");
    if (tab == 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(
                0, *e, "getTable[PCT_FILE_CRYPT_HIST_TEMP] failed:\n");
            delete e;
        } else {
            DgcWorker::PLOG.tprintf(
                0, "Table[PCT_FILE_CRYPT_HIST_TEMP] not found.\n");
        }
    } else {
        tab->unlockShare();
        DgcRowList rows(tab);
        rows.reset();
        if (tab->pinInsert(DgcDbProcess::sess(), rows, 1) != 0) {
            DgcExcept* e = EXCEPTnC;
            DgcWorker::PLOG.tprintf(
                0, *e, "pinInsert[PCT_FILE_CRYPT_HIST_TEMP] failed:\n");
            delete e;
        } else {
            rows.rewind();
            rows.next();
            memcpy(rows.data(), brow, sizeof(pc_type_file_request_in));
            rows.rewind();
            if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
                DgcExcept* e = EXCEPTnC;
                rows.rewind();
                if (tab->pinRollback(rows)) delete EXCEPTnC;
                DgcWorker::PLOG.tprintf(
                    0, *e, "insertCommit[PCT_FILE_CRYPT_HIST_TEMP] failed:\n");
                delete e;
            }
        }
    }
    IsExecuted = 1;
    NumRtnRows = 0;
    Result = 1;
    return 0;
}

dgt_uint8* PccKredStmtFileLogRequest::fetch() throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
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
