/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccSetKeyOpenMode
 *   Implementor        :       Jaehun
 *   Create Date        :       2012.10.18
 *   Description        :       set key open mode
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccSetKeyOpenMode.h"
#include "PccTableTypes.h"
#include "PcaCredentials.h"
#include "DgcDbProcess.h"


PccSetKeyOpenMode::PccSetKeyOpenMode(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccSetKeyOpenMode::~PccSetKeyOpenMode()
{
}


DgcExtProcedure* PccSetKeyOpenMode::clone()
{
	return new PccSetKeyOpenMode(procName());
}


typedef struct {
	dgt_schar	passwd[33];
	dgt_schar	open_mode[11];
} pct_set_key_open_in;


dgt_sint32 PccSetKeyOpenMode::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pct_set_key_open_in*	set_in=(pct_set_key_open_in*)BindRows->data();
	if (*set_in->passwd == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"null password not allowed")),-1);
	}
	//
	// password check
	//
	DgcTableSegment* key_tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
	if (key_tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_KEY] not found")),-1);
	}
	key_tab->unlockShare();
	DgcRowRef	key_rows(key_tab);
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
	if (key_rows.next()) {
		pct_type_key*	key_row=(pct_type_key*)key_rows.data();
		if ((rtn=PCI_checkPassword(set_in->passwd, key_row->smk, strlen(key_row->smk), key_row->seks,
					   strlen(key_row->seks), key_row->sks, strlen(key_row->sks), hsm_mode, hsm_password)) < 0) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg())),-1);
		}
        } else {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"there's no key")),-1);
	}
	dgt_schar	pc_file_path[257];
	memset(pc_file_path, 0, 257);
	dg_sprintf(pc_file_path,"%s/%s/svpw.credentials",getenv("SOHA_HOME"),getenv("SOHA_SVC"));
	if (strncasecmp(set_in->open_mode,"AUTO",4) == 0) {
		//
		// create a credential
		//
		PcaCredentials	pc;
		if ((rtn=pc.generate(getenv("SOHA_SVC"),"SAVED_PW",set_in->passwd))) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,pc.errMsg())),-1);
		}
		//
		// save the credential
		//
		dgt_schar*	credentials = pc.credentials();
		DgcFileStream	pc_fs(pc_file_path,O_CREAT|O_TRUNC|O_WRONLY,0666);
		ATHROWnR(DgcError(SPOS,"file[%s] open failed",pc_file_path),-1);
		if (pc_fs.sendData((dgt_uint8*)credentials, strlen(credentials)) < 0) {
			ATHROWnR(DgcError(SPOS,"file[%s] write failed",pc_file_path),-1);
		}
		//
		// update the open_mode -> auto in pct_key
		//
		dgt_schar sql_text[512];
                memset(sql_text,0,512);
		DgcSqlHandle sql_handle(Session);
                sprintf(sql_text, "update pct_key set(open_mode,last_update)=(1,nextlastupdate('PCT_KEY',1,2)) where key_id=1");
                if (sql_handle.execute(sql_text) < 0) {
                	DgcExcept* e=EXCEPTnC;
                        if (e) {
                        	RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                        }
                }
		ReturnRows->reset();
		ReturnRows->add();
		ReturnRows->next();
		*(ReturnRows->data())=0;
		dg_sprintf((dgt_schar*)ReturnRows->data(),"key open mode set as auto");
	} else if (*set_in->open_mode == 0 || strncasecmp(set_in->open_mode,"MANUAL",6) == 0) {
		//
		// remove credentials
		//
		if (remove(pc_file_path) < 0) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"remove[%s] failed due to [%d:%s]",pc_file_path,errno,strerror(errno))),-1);
		}
		//
		// update the open_mode -> manual in pct_key
		//
		dgt_schar sql_text[512];
                memset(sql_text,0,512);
                DgcSqlHandle sql_handle(Session);
                sprintf(sql_text, "update pct_key set(open_mode,last_update)=(0,nextlastupdate('PCT_KEY',1,2)) where key_id=1");
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                        }
                }
		ReturnRows->reset();
		ReturnRows->add();
		ReturnRows->next();
		*(ReturnRows->data())=0;
		dg_sprintf((dgt_schar*)ReturnRows->data(),"key open mode set as manual");
	} else {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"unsupported open mode[%s]",set_in->open_mode)),-1);
	}
	ReturnRows->rewind();
	return 0;
}
