/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccExportExtKey
 *   Implementor        :       chchung
 *   Create Date        :       2015. 8. 2
 *   Description        :       export an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccExportExtKey.h"
#include "PccTableTypes.h"

PccExportExtKey::PccExportExtKey(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}

PccExportExtKey::~PccExportExtKey()
{
}

DgcExtProcedure* PccExportExtKey::clone()
{
	return new PccExportExtKey(procName());
}

dgt_sint32 PccExportExtKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64 key_id = *((dgt_sint64*)BindRows->data());
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_EXT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_EXT_KEY] not found")),-1);
	}
	tab->unlockShare();
	DgcRowRef key_rows(tab);
	pct_type_ext_key* key_row=0;
	while (key_rows.next() && (key_row=(pct_type_ext_key*)key_rows.data())) {
		if (key_row->key_id == key_id) {
			dgt_schar* tmp_keys=new dgt_schar[ReturnRows->rowSize()*2];
			dg_sprintf(tmp_keys,"(ext_key=(key_id=%lld)(create_time=%u)(key_no=%u)(sek=\"%s\")(seks=\"%s\")(name=\"%s\")(description=%s)(reserved=%s))",
				key_row->key_id,
				key_row->create_time,
				key_row->key_no,
				key_row->sek,
				key_row->seks,
				key_row->name,
				key_row->description,
				key_row->reserved);
			dgt_sint32	remains = strlen(tmp_keys);
			dgt_schar*	cp = tmp_keys;
			ReturnRows->reset();
			while (remains > 0) {
				ReturnRows->add();
				ReturnRows->next();
				if (remains < (ReturnRows->rowSize()-1)) {
					memset(ReturnRows->data(), 0, ReturnRows->rowSize());
					memcpy(ReturnRows->data(), cp, remains);
					remains=0;
				} else {
					memcpy(ReturnRows->data(), cp, (ReturnRows->rowSize()-1));
					remains -= (ReturnRows->rowSize()-1);
					cp += (ReturnRows->rowSize()-1);
				}
			}
			delete tmp_keys;
			DgcWorker::PLOG.tprintf(0,"the external key[%lld] exported.\n",key_id);
			ReturnRows->rewind();
			return 0;
		}
	}
	THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the external key[%lld] not found",key_id)),-1);
	return 0;
}
