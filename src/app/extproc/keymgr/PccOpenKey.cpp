/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccOpenKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       drop key set- master, encryption key set,
ecryption key set signature
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccOpenKey.h"

#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccOpenKey::PccOpenKey(const dgt_schar* name) : DgcExtProcedure(name) {}

PccOpenKey::~PccOpenKey() {}

DgcExtProcedure* PccOpenKey::clone() { return new PccOpenKey(procName()); }

dgt_sint32 PccOpenKey::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (ReturnRows == 0) {
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
    DgcTableSegment* key_tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
    if (key_tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_KEY] failed"), -1);
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "Table[PCT_KEY] not found")),
                -1);
    }
    key_tab->unlockShare();
    DgcRowRef key_rows(key_tab);
    if (key_rows.next()) {
        pct_type_key* key_row = (pct_type_key*)key_rows.data();
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
        if ((rtn = PCI_openKey(pw, key_row->smk, strlen(key_row->smk),
                               key_row->seks, strlen(key_row->seks),
                               key_row->sks, strlen(key_row->sks), hsm_mode,
                               hsm_password)) < 0) {
            THROWnR(DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())),
                    -1);
        }
        dgt_uint32 open_date;
        open_date = dgtime(&open_date);
        dgt_schar sql_text[256];
        memset(sql_text, 0, 256);
        sprintf(sql_text, "insert into pct_key_stat values(%lld,%d,%d)",
                key_row->key_id, open_date, 1);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        DgcWorker::PLOG.tprintf(0, "the key set opened.\n");

#if 0
dgt_uint8       dbuf[102400];
dgt_uint32      db_size=PCI_dumpKeyStash(dbuf);
DgcWorker::PLOG.pprintf(0,"dbuf:%u\n",db_size);
for(dgt_uint32 i=1; i<=db_size; i++) { DgcWorker::PLOG.pprintf(0,"%02x",*(dbuf+i)); if (i%40 == 0) DgcWorker::PLOG.pprintf(0,"\n"); }
DgcWorker::PLOG.pprintf(0,"\n");
#endif

    } else {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "there's no key")),
                -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "key opened");
    ReturnRows->rewind();
    return 0;
}
