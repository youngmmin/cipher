/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccImportExtKey
 *   Implementor        :       chchung
 *   Create Date        :       2015. 8. 3
 *   Description        :       import an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccImportExtKey.h"

#include "DgcDbProcess.h"
#include "PcSyncIudLogInserter.h"
#include "PccExternalKey.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccImportExtKey::PccImportExtKey(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PccImportExtKey::~PccImportExtKey() {}

DgcExtProcedure* PccImportExtKey::clone() {
    return new PccImportExtKey(procName());
}

dgt_sint32 PccImportExtKey::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->numRows() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_schar* tmp_keys =
        new dgt_schar[BindRows->numRows() * BindRows->rowSize() + 1];
    *tmp_keys = 0;
    for (dgt_uint32 i = 0; BindRows->next(); i++) {
        dg_strcat(tmp_keys, (dgt_schar*)BindRows->getColPtr(1));
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
    dgt_schar* key_id = bg.getValue("ext_key.key_id");
    dgt_schar* create_time = bg.getValue("ext_key.create_time");
    dgt_schar* key_no = bg.getValue("ext_key.key_no");
    dgt_schar* sek = bg.getValue("ext_key.sek");
    dgt_schar* seks = bg.getValue("ext_key.seks");
    dgt_schar* name = bg.getValue("ext_key.name");
    dgt_schar* description = bg.getValue("ext_key.description");
    dgt_schar* reserved = bg.getValue("ext_key.reserved");
    dgt_schar tmp_emsg[128] = {
        0,
    };
    if (!key_id)
        strncpy(tmp_emsg, "key_id not found", 127);
    else if (!create_time)
        strncpy(tmp_emsg, "create_time not found", 127);
    else if (!key_no)
        strncpy(tmp_emsg, "key_no not found", 127);
    else if (!sek)
        strncpy(tmp_emsg, "sek not found", 127);
    else if (!seks)
        strncpy(tmp_emsg, "seks not found", 127);
    else if (!name)
        strncpy(tmp_emsg, "name not found", 127);
    else if (!description)
        strncpy(tmp_emsg, "description not found", 127);
    else if (!reserved)
        strncpy(tmp_emsg, "reserved not found", 127);
    if (*tmp_emsg) {
        delete tmp_keys;
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, tmp_emsg)),
                -1);
    }
    pct_type_ext_key ext_key;
    ext_key.key_id = dg_strtoll(key_id, 0, 10);
    ext_key.create_time = strtol(create_time, 0, 10);
    ext_key.key_no = (dgt_uint16)strtol(key_no, 0, 10);
    //
    // check key
    //
    PccExternalKey ek;
    if (ek.checkKey(ext_key.key_no, sek, seks)) {
        DgcExcept* e = EXCEPTnC;
        delete tmp_keys;
        RTHROWnR(e, DgcError(SPOS, "checkKey failed"), -1);
    }
    //
    // insert the external key
    //
    strncpy(ext_key.sek, sek, 512);
    strncpy(ext_key.seks, seks, 99);
    if (name) strncpy(ext_key.name, name, 32);
    if (description) strncpy(ext_key.description, description, 128);
    if (reserved) strncpy(ext_key.reserved, reserved, 32);
    delete tmp_keys;

    PcSyncIudLogInserter iud_log(Session, Database->pdb());
    ext_key.last_update =
        iud_log.nextLastUpdate((dgt_schar*)"pct_ext_key", ext_key.key_id,
                               PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_INSERT);
    if (ext_key.last_update < 0) {
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "nextLastUpdate failed"), -1);
    }
    DgcTableSegment* tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_KEY");
    if (tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_EXT_KEY] failed"), -1);
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "Table[PCT_EXT_KEY] not found")),
            -1);
    }
    tab->unlockShare();
    DgcRowList rows(tab);
    rows.reset();
    if (tab->pinInsert(Session, rows, 1) != 0) {
        ATHROWnR(DgcError(SPOS, "pinInsert failed"), -1);
    }
    rows.rewind();
    rows.next();
    memcpy(rows.data(), &ext_key, sizeof(ext_key));
    rows.rewind();
    if (tab->insertCommit(Session, rows) != 0) {
        DgcExcept* e = EXCEPTnC;
        rows.rewind();
        if (iud_log.nextLastUpdateRollBack() < 0) delete EXCEPTnC;
        if (tab->pinRollback(rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "insertCommit[PCT_EXT_KEY] failed"), -1);
    }
    DgcWorker::PLOG.tprintf(0, "an external key[%lld] imported.\n", key_id);
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "key imported");
    ReturnRows->rewind();
    return 0;
}
