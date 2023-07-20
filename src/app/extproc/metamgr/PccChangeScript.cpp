/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccChangeScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       get script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccChangeScript.h"

#include "PccTableTypes.h"

PccChangeScript::PccChangeScript(const dgt_schar* name)
    : PccMetaProcedure(name) {}

PccChangeScript::~PccChangeScript() {}

DgcExtProcedure* PccChangeScript::clone() {
    return new PccChangeScript(procName());
}

dgt_sint32 PccChangeScript::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (!(InRow = (pc_type_change_script_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }

    //
    // delete script
    //
    dgt_schar sql_text[256];
    sprintf(sql_text,
            "delete pct_script where enc_tab_id=%lld and version_no=%d and "
            "step_no=%d and stmt_no=%d",
            InRow->enc_tab_id, InRow->version_no, InRow->step_no,
            InRow->stmt_no);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "delete failed."), -1);
    }
    delete sql_stmt;

    //
    // insert the new script
    //
    DgcTableSegment* cs_tab = 0;
    if ((cs_tab = (DgcTableSegment*)Database->pdb()->segMgr()->getTable(
             "PCT_SCRIPT", DGC_SEG_TABLE, Session->databaseUser())) == 0) {
        ATHROWnR(DgcError(SPOS, "getTable failed"), -1);
        THROWnR(DgcPdbExcept(DGC_EC_PDO_NOT_FOUND,
                             new DgcError(SPOS, "table[PCT_SCRIPT] not found")),
                -1);
    }
    cs_tab->unlockShare();
    DgcRowList cs_rows(cs_tab);
    dgt_uint32 remains = strlen(InRow->script_text);
    dgt_schar* cp = InRow->script_text;
    dgt_uint32 seg_no = 0;
    cs_rows.reset();
    while (remains > 0) {
        if (cs_tab->pinInsert(Session, cs_rows, 1) != 0) {
            DgcExcept* e = EXCEPTnC;
            cs_rows.rewind();
            if (cs_tab->pinRollback(cs_rows)) delete EXCEPTnC;
            RTHROWnR(e, DgcError(SPOS, "pinInsert failed"), -1);
        }
        cs_rows.next();
        pct_type_script* csp = (pct_type_script*)cs_rows.data();
        csp->enc_tab_id = InRow->enc_tab_id;
        csp->version_no = InRow->version_no;
        csp->step_no = InRow->step_no;
        csp->stmt_no = InRow->stmt_no;
        csp->seg_no = ++seg_no;
        dgt_schar* tmp = 0;
        if (remains < 64) {
            memcpy(csp->seg_text, cp, remains);
            for (dgt_sint32 i = 0; i < 63; i++) {
                tmp = strchr(csp->seg_text, '\r');
                if (tmp) *(tmp) = ' ';
            }
            remains = 0;
        } else {
            memcpy(csp->seg_text, cp, 64);
            for (dgt_sint32 i = 0; i < 63; i++) {
                tmp = strchr(csp->seg_text, '\r');
                if (tmp) *(tmp) = ' ';
            }
            remains -= 64;
            cp += 64;
        }
    }
    cs_rows.rewind();
    if (cs_tab->insertCommit(Session, cs_rows) != 0) {
        DgcExcept* e = EXCEPTnC;
        if (cs_tab->pinRollback(cs_rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "insertCommit[PCT_SCRIPT] failed"), -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    memset(ReturnRows->data(), 0, ReturnRows->rowSize());
    sprintf((dgt_schar*)ReturnRows->data(), "script changed.");
    ReturnRows->rewind();
    return 0;
}
