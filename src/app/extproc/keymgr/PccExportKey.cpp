/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccExportKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       export key set- master, encryption key set, ecryption key set signature
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccExportKey.h"
#include "PccTableTypes.h"
#include "DgcDbProcess.h"


PccExportKey::PccExportKey(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccExportKey::~PccExportKey()
{
}


DgcExtProcedure* PccExportKey::clone()
{
	return new PccExportKey(procName());
}


dgt_sint32 PccExportKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_schar*	old_pw=(dgt_schar*)BindRows->getColPtr(1);
	dgt_schar*	new_pw=(dgt_schar*)BindRows->getColPtr(2);
	ATHROWnR(DgcError(SPOS,"getColPtr failed"),-1);

	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_KEY] not found")),-1);
	}
	tab->unlockShare();
	DgcRowRef	key_rows(tab);
	if (key_rows.next()) {
		pct_type_key*	key_row=(pct_type_key*)key_rows.data();
		dgt_sint32	rtn=0;
		//
		// added by mwpark
        	// 2017.02.11
	        // for hsm
	        //
        	dgt_sys_param*       param;
	        dgt_sint32 hsm_mode=0;
        	dgt_schar  hsm_password[128];
	        memset(hsm_password,0,128);
        	if ((param=DG_PARAM("USE_HSM_FLAG")) == 0) delete EXCEPTnC;
	        else {
        	        if (param->val_number == 1) {
				hsm_mode=1;
                	        if ((param=DG_PARAM("HSM_PASSWORD")) == 0) delete EXCEPTnC;
                        	else {
	                                strncpy(hsm_password,param->val_string,strlen(param->val_string));
        	                }
                	}
	        }
		if ((rtn=PCI_checkPassword(old_pw, key_row->smk, strlen(key_row->smk),
					key_row->seks, strlen(key_row->seks), key_row->sks, strlen(key_row->sks), hsm_mode, hsm_password)) < 0) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg())),-1);
		}
		//
		// change password
		//
		dgt_schar	new_smk[100];
		memcpy(new_smk, key_row->smk, 100);
		if (*new_pw && (rtn=PCI_changePassword(old_pw, new_pw, new_smk, strlen(new_smk),
						 key_row->seks, strlen(key_row->seks), key_row->sks, strlen(key_row->sks), hsm_mode, hsm_password)) < 0) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg())),-1);
		}
		dgt_schar*	tmp_keys=new dgt_schar[ReturnRows->rowSize()*2];
//		dg_sprintf(tmp_keys,"(key=\n(key_id=%lld)\n(smk=\"%s\")\n(seks=\"%s\")\n(sks=\"%s\")\n(description=%s)\n(create_date=%u)\n)",
//				 key_row->key_id, new_smk, key_row->seks, key_row->sks, key_row->description, key_row->create_date);
		dg_sprintf(tmp_keys,"(key=\n(key_id=%lld)\n(smk=\"%s\")\n(seks=\"%s\")\n(sks=\"%s\")\n(description=%s)\n)",
				 key_row->key_id, new_smk, key_row->seks, key_row->sks, key_row->description);
		dgt_sint32	remains=strlen(tmp_keys);
		dgt_schar*	cp=tmp_keys;
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
		DgcWorker::PLOG.tprintf(0,"the key set exported.\n");
		ReturnRows->rewind();
	} else {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"there's no key")),-1);
	}
	return 0;
}
