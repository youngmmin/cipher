/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccCreateExtKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       create an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PciKeyMgrIf.h"
#include "PccCreateExtKey.h"
#include "PccTableTypes.h"
#include "PccExternalKey.h"
#include "PcSyncIudLogInserter.h"

typedef struct {
	dgt_schar	name[33];
	dgt_schar	key[513];
	dgt_uint16	format_no;
} pc_type_create_ext_key_in;

PccCreateExtKey::PccCreateExtKey(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}

PccCreateExtKey::~PccCreateExtKey()
{
}

DgcExtProcedure* PccCreateExtKey::clone()
{
	return new PccCreateExtKey(procName());
}

dgt_sint32 PccCreateExtKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pc_type_create_ext_key_in* eki = (pc_type_create_ext_key_in*)BindRows->data();
	//
	// get a key id
	//
	pct_type_ext_key ext_key;
	memset(&ext_key,0,sizeof(ext_key));
	DgcSequence* pct_seq;
	if ((pct_seq=Database->pdb()->seqMgr()->getSequence(Session->dbUser(),"PT_A_KEY_SEQ")) == 0) {
		ATHROWnR(DgcError(SPOS,"getSequence failed"),-1);
	}
	if ((ext_key.key_id=pct_seq->nextVal(Session)) == 0) {
		DgcExcept* e=EXCEPTnC;
		delete pct_seq;
		RTHROWnR(e,DgcError(SPOS,"nextVal failed"),-1);
	}
	delete pct_seq;
	//
	// create a key
	//
	PccExternalKey ek;
	dgt_uint32 sek_len = MAX_EXT_KEY_LEN;
	dgt_uint32 seks_len = MAX_EXT_SIGN_LEN;
	if (ek.createKey(eki->key,eki->format_no,ext_key.key_id,&ext_key.key_no,ext_key.sek,&sek_len,ext_key.seks,&seks_len)) {
		ATHROWnR(DgcError(SPOS,"createKey failed"),-1);
	}
	//
	// get a last update number
	//
	PcSyncIudLogInserter iud_log(Session,Database->pdb());
        ext_key.last_update = iud_log.nextLastUpdate((dgt_schar*)"pct_ext_key", ext_key.key_id, PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_INSERT);
        if (ext_key.last_update  < 0) {
                DgcExcept* e = EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"nextLastUpdate failed"),-1);
        }
	strncpy(ext_key.name,eki->name,32);
	ext_key.create_time=dgtime(&(ext_key.create_time));
	//
	// insert the external key
	//
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_EXT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_EXT_KEY] not found")),-1);
	}
	tab->unlockShare();
	DgcRowList	rows(tab);
	rows.reset();
	if (tab->pinInsert(Session,rows,1) != 0) {
		ATHROWnR(DgcError(SPOS,"pinInsert failed"),-1);
	}
        rows.rewind();
        rows.next();
        memcpy(rows.data(),&ext_key,sizeof(ext_key));
	rows.rewind();
	if (tab->insertCommit(Session,rows) != 0) {
		DgcExcept*      e=EXCEPTnC;
		rows.rewind();
		if (tab->pinRollback(rows)) delete EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"insertCommit[PCT_EXT_KEY] failed"),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"an external key[%u:%s] created",ext_key.key_no,ext_key.name);
	ReturnRows->rewind();
	return 0;
}
