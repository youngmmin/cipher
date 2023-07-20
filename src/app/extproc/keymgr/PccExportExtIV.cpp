/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccExportExtIV
 *   Implementor        :       chchung
 *   Create Date        :       2015. 8. 2
 *   Description        :       export an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccExportExtIV.h"

#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

PccExportExtIV::PccExportExtIV(const dgt_schar* name) : DgcExtProcedure(name) {}

PccExportExtIV::~PccExportExtIV() {}

DgcExtProcedure* PccExportExtIV::clone() {
    return new PccExportExtIV(procName());
}

dgt_sint32 PccExportExtIV::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64 iv_id = *((dgt_sint64*)BindRows->data());
    DgcTableSegment* tab =
        (DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_IV");
    if (tab == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_EXT_IV] failed"), -1);
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "Table[PCT_EXT_IV] not found")),
                -1);
    }
    tab->unlockShare();
    DgcRowRef iv_rows(tab);
    pct_type_ext_iv* iv_row = 0;
    while (iv_rows.next() && (iv_row = (pct_type_ext_iv*)iv_rows.data())) {
        if (iv_row->iv_id == iv_id) {
            dgt_schar* tmp_ivs = new dgt_schar[ReturnRows->rowSize() * 2];
            dg_sprintf(
                tmp_ivs,
                "(ext_iv=(iv_id=%lld)(create_time=%u)(iv_no=%u)(seiv=\"%s\")("
                "seivs=\"%s\")(name=\"%s\")(description=%s)(reserved=%s))",
                iv_row->iv_id, iv_row->create_time, iv_row->iv_no, iv_row->seiv,
                iv_row->seivs, iv_row->name, iv_row->description,
                iv_row->reserved);
            dgt_sint32 remains = strlen(tmp_ivs);
            dgt_schar* cp = tmp_ivs;
            ReturnRows->reset();
            while (remains > 0) {
                ReturnRows->add();
                ReturnRows->next();
                if (remains < (ReturnRows->rowSize() - 1)) {
                    memset(ReturnRows->data(), 0, ReturnRows->rowSize());
                    memcpy(ReturnRows->data(), cp, remains);
                    remains = 0;
                } else {
                    memcpy(ReturnRows->data(), cp, (ReturnRows->rowSize() - 1));
                    remains -= (ReturnRows->rowSize() - 1);
                    cp += (ReturnRows->rowSize() - 1);
                }
            }
            delete tmp_ivs;
            DgcWorker::PLOG.tprintf(0, "the external iv[%lld] exported.\n",
                                    iv_id);
            ReturnRows->rewind();
            return 0;
        }
    }
    THROWnR(DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "the external iv[%lld] not found", iv_id)),
            -1);
    return 0;
}
