/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccEncrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       encrypt table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccEncrypt.h"

PccEncrypt::PccEncrypt(const dgt_schar* name) : DgcExtProcedure(name) {}

PccEncrypt::~PccEncrypt() {}

DgcExtProcedure* PccEncrypt::clone() { return new PccEncrypt(procName()); }

#include "PcbJobRunner.h"

dgt_sint32 PccEncrypt::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64* enc_tab_id = (dgt_sint64*)BindRows->data();
    dgt_sint16 max_step_no = 0;
    dgt_schar sql_text[128];
    sprintf(sql_text,
            "select max(step_no) from pct_script where enc_tab_id=%lld",
            *enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    } else {
        dgt_uint8* rtn_row;
        if (!(rtn_row = sql_stmt->fetch())) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
        max_step_no = *((dgt_sint16*)rtn_row);
    }
    delete sql_stmt;
    max_step_no++;
    if (PcbJobRunner::startJob(*enc_tab_id, max_step_no)) {
        ATHROWnR(DgcError(SPOS, "startJob[%lld,%d] failed", *enc_tab_id,
                          max_step_no),
                 -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "encrypting[%d] started",
               max_step_no);
    ReturnRows->rewind();
    return 0;
}
