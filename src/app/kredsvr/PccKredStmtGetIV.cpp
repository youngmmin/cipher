/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetIV.h"

#include "DgcDbProcess.h"
#include "PccExternalIV.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccKredStmtGetIV::PccKredStmtGetIV(DgcPhyDatabase* pdb, DgcSession* session,
                                   DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term), NumRtnRows(0) {
    SelectListDef = new DgcClass("select_list", 2);
    SelectListDef->addAttr(DGC_UB2, 0, "iv_size");
    SelectListDef->addAttr(DGC_ACHR, 64, "iv");
}

PccKredStmtGetIV::~PccKredStmtGetIV() {}

dgt_sint32 PccKredStmtGetIV::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    //
    // get encrypt key info
    //
    pc_type_get_iv_in* iv_in = (pc_type_get_iv_in*)mrows->data();
    dgt_schar sql_text[256];
    DgcMemRows v_bind(1);
    v_bind.addAttr(DGC_UB1, 0, "iv_type");
    v_bind.reset();
    v_bind.add();
    v_bind.next();
    memcpy(v_bind.getColPtr(1), &iv_in->iv_type, sizeof(dgt_uint8));
    v_bind.rewind();
    dg_sprintf(sql_text, "select * from pct_ext_iv where iv_no = :1");
    DgcSqlStmt* sql_stmt =
        DgcDbProcess::db().getStmt(Session, sql_text, strlen(sql_text));
    DgcExcept* e = 0;
    if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
        e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute[%u] failed.", iv_in->iv_type), -1);
    }
    pct_type_ext_iv* ext_iv;
    if ((ext_iv = (pct_type_ext_iv*)sql_stmt->fetch())) {
        PccExternalIV eiv;
        IVInfo.iv_size = iv_in->iv_size;
        eiv.getIV(ext_iv->iv_no, ext_iv->seiv, ext_iv->seivs, IVInfo.iv_size,
                  IVInfo.iv);
    }
    e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        RTHROWnR(
            e,
            DgcError(SPOS, "fetch external iv_no[%u] failed", iv_in->iv_type),
            -1);
    }
    IsExecuted = 1;
    NumRtnRows = 0;
    return 0;
}

dgt_uint8* PccKredStmtGetIV::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (NumRtnRows++ == 0) return (dgt_uint8*)&IVInfo;
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
