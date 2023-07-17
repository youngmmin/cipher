/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetKeySet
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 7. 15
 *   Description        :       KRED get key set statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetKeySet.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"


PccKredStmtGetKeySet::PccKredStmtGetKeySet(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",4);
        SelectListDef->addAttr(DGC_UB2,0,"key_idx");
        SelectListDef->addAttr(DGC_UB2,0,"key_size");
        SelectListDef->addAttr(DGC_ACHR,PCC_KEY_SET_SIG_LENGTH,"key_signature");
        SelectListDef->addAttr(DGC_ACHR,PCC_MAX_EKEY_SET_LENGTH,"key_set");
}


PccKredStmtGetKeySet::~PccKredStmtGetKeySet()
{
}


dgt_sint32 PccKredStmtGetKeySet::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	//
	// get encrypt key
	//
	dgt_sint32	rtn=0;
	memset(&KeySet, 0, sizeof(KeySet));
	KeySet.key_idx = 0;
	KeySet.key_size = PCC_MAX_EKEY_SET_LENGTH;
	PCT_KEY_STASH*	key_stash = 0;
	if ((rtn=PCI_getKeyStash(&key_stash)) < 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
			new DgcError(SPOS,"PCI_getKeyStash failed due to %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
	if (key_stash->open_status == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
			new DgcError(SPOS,"PCI_getKeyStash failed due to %d:The key set not opened", PCC_ERR_KMGR_KEY_NOT_OPEN)),-1);
	}
	memcpy(KeySet.key_set_signature,key_stash->key_set_signature,PCC_KEY_SET_SIG_LENGTH);
	memcpy(KeySet.key_set,key_stash->key_set,PCC_MAX_EKEY_SET_LENGTH);
	IsExecuted=1;
	NumRtnRows=0;
	//
	// log key request history
	//
#if 0
	pct_type_key_request_hist rqst_hist;
	memset(&rqst_hist, 0, sizeof(rqst_hist));
	rqst_hist.key_id = 1;
	rqst_hist.request_date=dgtime(&rqst_hist.request_date);
	strncpy(rqst_hist.request_ip, Session->clientCommIP(), 65);
	DgcTableSegment*	tab=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_KEY_REQUEST_HIST_TEMP");
	if (tab == 0) {
		DgcExcept*	e=EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"getTable[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
			delete e;
		} else {
			DgcWorker::PLOG.tprintf(0,"Table[PCT_KEY_REQUEST_HIST_TEMP] not found.\n");
		}
	} else {
		tab->unlockShare();
		DgcRowList	rows(tab);
		rows.reset();
		if (tab->pinInsert(DgcDbProcess::sess(),rows,1) != 0) {
			DgcExcept*      e=EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"pinInsert[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
			delete e;
		} else {
			rows.rewind();
			rows.next();
			memcpy(rows.data(), &rqst_hist, rows.rowSize());
			rows.rewind();
			if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
				DgcExcept*	e=EXCEPTnC;
				rows.rewind();
				if (tab->pinRollback(rows)) delete EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"insertCommit[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
				delete e;
			}
		}
	}
#endif
	return 0;
}


dgt_uint8* PccKredStmtGetKeySet::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&KeySet;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
