/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccImportExtIV
 *   Implementor        :       chchung
 *   Create Date        :       2015. 8. 3
 *   Description        :       import an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccImportExtIV.h"

#include "DgcDbProcess.h"
#include "PcSyncIudLogInserter.h"
#include "PccExternalIV.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccImportExtIV::PccImportExtIV(const dgt_schar* name) : DgcExtProcedure(name) {}

PccImportExtIV::~PccImportExtIV() {}

DgcExtProcedure* PccImportExtIV::clone() {
    return new PccImportExtIV(procName());
}

dgt_sint32 PccImportExtIV::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->numRows() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_schar* tmp_ivs =
        new dgt_schar[BindRows->numRows() * BindRows->rowSize() + 1];
    *tmp_ivs = 0;
    for (dgt_uint32 i = 0; BindRows->next(); i++) {
        dg_strcat(tmp_ivs, (dgt_schar*)BindRows->getColPtr(1));
        if (EXCEPT) {
            DgcExcept* e = EXCEPTnC;
            delete tmp_ivs;
            RTHROWnR(e, DgcError(SPOS, "getColPtr failed"), -1);
        }
    }
    DgcBgrammer bg;
    if (bg.parse(tmp_ivs) < 0 || bg.pstatus() != DGC_BGPS_FINISH) {
        delete tmp_ivs;
        ATHROWnR(DgcError(SPOS, "parse failed"), -1);
        THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                              new DgcError(SPOS, "incomplete iv")),
                -1);
    }
    dgt_schar* iv_id = bg.getValue("ext_iv.iv_id");
    dgt_schar* create_time = bg.getValue("ext_iv.create_time");
    dgt_schar* iv_no = bg.getValue("ext_iv.iv_no");
    dgt_schar* seiv = bg.getValue("ext_iv.seiv");
    dgt_schar* seivs = bg.getValue("ext_iv.seivs");
    dgt_schar* name = bg.getValue("ext_iv.name");
    dgt_schar* description = bg.getValue("ext_iv.description");
    dgt_schar* reserved = bg.getValue("ext_iv.reserved");
    dgt_schar tmp_emsg[128] = {
        0,
    };
    if (!iv_id)
        strncpy(tmp_emsg, "iv_id not found", 127);
    else if (!create_time)
        strncpy(tmp_emsg, "create_time not found", 127);
    else if (!iv_no)
        strncpy(tmp_emsg, "iv_no not found", 127);
    else if (!seiv)
        strncpy(tmp_emsg, "seiv not found", 127);
    else if (!seivs)
        strncpy(tmp_emsg, "seivs not found", 127);
    else if (!name)
        strncpy(tmp_emsg, "name not found", 127);
    else if (!description)
        strncpy(tmp_emsg, "description not found", 127);
    else if (!reserved)
        strncpy(tmp_emsg, "reserved not found", 127);
    if (*tmp_emsg) {
        delete tmp_ivs;
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, tmp_emsg)),
                -1);
    }
    pct_type_ext_iv ext_iv;
    ext_iv.iv_id = dg_strtoll(iv_id, 0, 10);
    ext_iv.create_time = strtol(create_time, 0, 10);
    ext_iv.iv_no = (dgt_uint8)strtol(iv_no, 0, 10);
    //
    // check iv
    //
    PccExternalIV ek;
    if (ek.checkIV(ext_iv.iv_no, seiv, seivs)) {
        DgcExcept* e = EXCEPTnC;
        delete tmp_ivs;
        RTHROWnR(e, DgcError(SPOS, "checkIV failed"), -1);
    }
    //
    // insert the external iv
    //
    strncpy(ext_iv.seiv, seiv, 512);
    strncpy(ext_iv.seivs, seivs, 99);
    if (name) strncpy(ext_iv.name, name, 32);
    if (description) strncpy(ext_iv.description, description, 128);
    if (reserved) strncpy(ext_iv.reserved, reserved, 32);
    delete tmp_ivs;

    PcSyncIudLogInserter iud_log(Session, Database->pdb());
    ext_iv.last_update =
        iud_log.nextLastUpdate((dgt_schar*)"pct_ext_iv", ext_iv.iv_id,
                               PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_INSERT);
    if (ext_iv.last_update < 0) {
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "nextLastUpdate failed"), -1);
    }
    DgcTableSegment* tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_IV");
    if (tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_EXT_IV] failed"), -1);
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "Table[PCT_EXT_IV] not found")),
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
    memcpy(rows.data(), &ext_iv, sizeof(ext_iv));
    rows.rewind();
    if (tab->insertCommit(Session, rows) != 0) {
        DgcExcept* e = EXCEPTnC;
        rows.rewind();
        if (iud_log.nextLastUpdateRollBack() < 0) delete EXCEPTnC;
        if (tab->pinRollback(rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "insertCommit[PCT_EXT_IV] failed"), -1);
    }
    DgcWorker::PLOG.tprintf(0, "an external iv[%lld] imported.\n", iv_id);
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "iv imported");
    ReturnRows->rewind();
    return 0;
}
