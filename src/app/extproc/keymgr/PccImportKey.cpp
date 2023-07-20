/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccImportKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       import key set- master, encryption key set,
ecryption key set signature
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccImportKey.h"

#include "DgcDbProcess.h"
#include "PcSyncIudLogInserter.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccImportKey::PccImportKey(const dgt_schar* name) : DgcExtProcedure(name) {}

PccImportKey::~PccImportKey() {}

DgcExtProcedure* PccImportKey::clone() { return new PccImportKey(procName()); }

dgt_sint32 PccImportKey::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->numRows() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    //
    // check and build key row
    //
    dgt_schar* old_pw = 0;
    dgt_schar* new_pw = 0;
    dgt_schar* tmp_keys =
        new dgt_schar[BindRows->numRows() * BindRows->rowSize() + 1];
    *tmp_keys = 0;
    for (dgt_uint32 i = 0; BindRows->next(); i++) {
        if (i == 0) {
            old_pw = (dgt_schar*)BindRows->getColPtr(1);
            new_pw = (dgt_schar*)BindRows->getColPtr(2);
        }
        dg_strcat(tmp_keys, (dgt_schar*)BindRows->getColPtr(3));
        if (EXCEPT) {
            DgcExcept* e = EXCEPTnC;
            delete tmp_keys;
            RTHROWnR(e, DgcError(SPOS, "getColPtr failed"), -1);
        }
    }
    DgcBgrammer bg;
    if (bg.parse(tmp_keys) < 0 || bg.pstatus() != DGC_BGPS_FINISH) {
        delete tmp_keys;
        ATHROWnR(DgcError(SPOS, "parse failed"), -1);
        THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                              new DgcError(SPOS, "incomplete key")),
                -1);
    }
    dgt_schar* key_id = bg.getValue("key.key_id");
    dgt_schar* smk = bg.getValue("key.smk");
    dgt_schar* seks = bg.getValue("key.seks");
    dgt_schar* sks = bg.getValue("key.sks");
    dgt_schar* description = bg.getValue("key.description");
    //	dgt_schar*	create_date=bg.getValue("key.create_date");
    dgt_schar tmp_emsg[128] = {
        0,
    };
    if (!key_id)
        strncpy(tmp_emsg, "key_id not found", 127);
    else if (!smk)
        strncpy(tmp_emsg, "smk not found", 127);
    else if (!seks)
        strncpy(tmp_emsg, "seks not found", 127);
    else if (!sks)
        strncpy(tmp_emsg, "sks not found", 127);
    //	else if (!create_date) strncpy(tmp_emsg,"create_date not found",127);
    if (*tmp_emsg) {
        delete tmp_keys;
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, tmp_emsg)),
                -1);
    }
    //
    // check password & key integrity
    //
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
    dgt_sint32 rtn = 0;
    if ((rtn = PCI_checkPassword(old_pw, smk, strlen(smk), seks, strlen(seks),
                                 sks, strlen(sks), hsm_mode, hsm_password)) <
        0) {
        delete tmp_keys;
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())),
            -1);
    }
    pct_type_key key_row;
    memset(&key_row, 0, sizeof(key_row));
    key_row.key_id = dg_strtoll(key_id, 0, 10);
    strncpy(key_row.smk, smk, sizeof(key_row.smk) - 1);
    strncpy(key_row.seks, seks, sizeof(key_row.seks) - 1);
    strncpy(key_row.sks, sks, sizeof(key_row.sks) - 1);
    strncpy(key_row.description, description, sizeof(key_row.description) - 1);
    //	key_row.create_date=strtoul(create_date,0,10);
    key_row.load_date = dgtime(&(key_row.load_date));
    delete tmp_keys;
    //
    // change password
    //
    if (*new_pw && (rtn = PCI_changePassword(
                        old_pw, new_pw, key_row.smk, strlen(key_row.smk),
                        key_row.seks, strlen(key_row.seks), key_row.sks,
                        strlen(key_row.sks), hsm_mode, hsm_password)) < 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())),
            -1);
    }
    //
    // insert a key row
    //
    DgcTableSegment* tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
    if (tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_KEY] failed"), -1);
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "Table[PCT_KEY] not found")),
                -1);
    }
    tab->unlockShare();
    if (tab->numRows(0) > 0) {
        THROWnR(DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "A key exists already, drop it first.")),
                -1);
    }
    DgcRowList rows(tab);
    rows.reset();
    if (tab->pinInsert(Session, rows, 1) != 0) {
        ATHROWnR(DgcError(SPOS, "pinInsert failed"), -1);
    }
    rows.rewind();
    rows.next();
    memcpy(rows.data(), &key_row, sizeof(key_row));

    PcSyncIudLogInserter iud_log(Session, DgcDbProcess::db().pdb());
    key_row.last_update =
        iud_log.nextLastUpdate((dgt_schar*)"pct_key", key_row.key_id,
                               PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_INSERT);
    if (key_row.last_update < 0) {
        DgcExcept* e = EXCEPTnC;
        rows.rewind();
        if (tab->pinRollback(rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "nextLastUpdate failed"), -1);
    }
    rows.rewind();
    if (tab->insertCommit(Session, rows) != 0) {
        DgcExcept* e = EXCEPTnC;
        rows.rewind();
        if (iud_log.nextLastUpdateRollBack() < 0) delete EXCEPTnC;
        if (tab->pinRollback(rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "insertCommit[PCT_KEY] failed"), -1);
    }
    DgcWorker::PLOG.tprintf(0, "a key set imported.\n");
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "key imported");
    ReturnRows->rewind();
    return 0;
}
