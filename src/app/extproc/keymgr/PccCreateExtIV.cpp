/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccCreateExtIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       create an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PccCreateExtIV.h"

#include "PcSyncIudLogInserter.h"
#include "PccExternalIV.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

typedef struct {
    dgt_schar name[33];
    dgt_schar iv[513];
    dgt_uint16 format_no;
} pc_type_create_ext_iv_in;

PccCreateExtIV::PccCreateExtIV(const dgt_schar* name) : DgcExtProcedure(name) {}

PccCreateExtIV::~PccCreateExtIV() {}

DgcExtProcedure* PccCreateExtIV::clone() {
    return new PccCreateExtIV(procName());
}

dgt_sint32 PccCreateExtIV::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pc_type_create_ext_iv_in* eki = (pc_type_create_ext_iv_in*)BindRows->data();
    //
    // get a iv id
    //
    pct_type_ext_iv ext_iv;
    memset(&ext_iv, 0, sizeof(ext_iv));
    DgcSequence* pct_seq;
    if ((pct_seq = Database->pdb()->seqMgr()->getSequence(
             Session->dbUser(), "PT_A_KEY_SEQ")) == 0) {
        ATHROWnR(DgcError(SPOS, "getSequence failed"), -1);
    }
    if ((ext_iv.iv_id = pct_seq->nextVal(Session)) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete pct_seq;
        RTHROWnR(e, DgcError(SPOS, "nextVal failed"), -1);
    }
    delete pct_seq;
    //
    // create a iv
    //
    PccExternalIV ek;
    dgt_uint32 seiv_len = MAX_EXT_IV_LEN;
    dgt_uint32 seivs_len = MAX_EXT_SIGN_LEN;
    if (ek.createIV(eki->iv, eki->format_no, ext_iv.iv_id, &ext_iv.iv_no,
                    ext_iv.seiv, &seiv_len, ext_iv.seivs, &seivs_len)) {
        ATHROWnR(DgcError(SPOS, "createIV failed"), -1);
    }
    //
    // get a last update number
    //
    PcSyncIudLogInserter iud_log(Session, Database->pdb());
    ext_iv.last_update =
        iud_log.nextLastUpdate((dgt_schar*)"pct_ext_iv", ext_iv.iv_id,
                               PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_INSERT);
    if (ext_iv.last_update < 0) {
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "nextLastUpdate failed"), -1);
    }
    strncpy(ext_iv.name, eki->name, 32);
    ext_iv.create_time = dgtime(&(ext_iv.create_time));
    //
    // insert the external iv
    //
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
        if (tab->pinRollback(rows)) delete EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "insertCommit[PCT_EXT_IV] failed"), -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "an external iv[%u:%s] created",
               ext_iv.iv_no, ext_iv.name);
    ReturnRows->rewind();
    return 0;
}
