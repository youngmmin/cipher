/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccDropKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       drop key set- master, encryption key set,
ecryption key set signature
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccDropKey.h"

#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccDropKey::PccDropKey(const dgt_schar* name) : DgcExtProcedure(name) {}

PccDropKey::~PccDropKey() {}

DgcExtProcedure* PccDropKey::clone() { return new PccDropKey(procName()); }

dgt_sint32 PccDropKey::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_schar* pw = (dgt_schar*)BindRows->data();
    if (*pw == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "null password not allowed")),
                -1);
    }
    DgcTableSegment* tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
    if (tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_KEY] failed"), -1);
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "Table[PCT_KEY] not found")),
                -1);
    }
    tab->unlockShare();
    DgcRowRef rows(tab);
    if (rows.next()) {
        pct_type_key* key_row = (pct_type_key*)rows.data();
        dgt_sint32 rtn = 0;
        //
        // added by mwpark
        // 2017.02.11
        // for hsm
        //
        dgt_sys_param* param;
        dgt_sint32 hsm_mode = 0;
        dgt_schar hsm_password[128];
        memset(hsm_password, 0, 128);
        if ((param = DG_PARAM("USE_HSM_FLAG")) == 0)
            delete EXCEPTnC;
        else {
            if (param->val_number == 1) {
                hsm_mode = 1;
                if ((param = DG_PARAM("HSM_PASSWORD")) == 0)
                    delete EXCEPTnC;
                else {
                    strncpy(hsm_password, param->val_string,
                            strlen(param->val_string));
                }
            }
        }
        if ((rtn = PCI_checkPassword(pw, key_row->smk, strlen(key_row->smk),
                                     key_row->seks, strlen(key_row->seks),
                                     key_row->sks, strlen(key_row->sks),
                                     hsm_mode, hsm_password)) < 0) {
            THROWnR(DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())),
                    -1);
        }
        dgt_schar sql_text[256];
        memset(sql_text, 0, 256);
        sprintf(sql_text, "select * from pct_key_stat where key_id=%lld",
                key_row->key_id);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            sql_stmt = 0;
            RTHROWnR(e, DgcError(SPOS, "delete failed"), -1);
        }
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            delete sql_stmt;
            sql_stmt = 0;
            THROWnR(DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS,
                                     "the key opened, should be closed first")),
                    -1);
        }
        delete EXCEPTnC;
        delete sql_stmt;
        sql_stmt = 0;
        memset(sql_text, 0, 256);
        sprintf(sql_text,
                "DELETE PCT_KEY WHERE nextLastUpdate('PCT_KEY', %lld, 3) > 0",
                key_row->key_id);
        sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            sql_stmt = 0;
            RTHROWnR(e, DgcError(SPOS, "delete failed"), -1);
        }
        delete sql_stmt;
        DgcWorker::PLOG.tprintf(0, "the key set dropped.\n");
    } else {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "there's no key to drop")),
                -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "key dropped");
    ReturnRows->rewind();
    return 0;
}
