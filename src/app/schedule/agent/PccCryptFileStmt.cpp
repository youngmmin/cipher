/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccCryptFileStmt
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 1. 12
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"
#include "DgcBgmrList.h"
#include "PccFileCryptor.h"

PccCryptFileStmt::PccCryptFileStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef=new DgcClass("select_list",2);
	SelectListDef->addAttr(DGC_SB4,0,"rtn_code");
	SelectListDef->addAttr(DGC_SCHR,1025,"error_message");

	SessionId = 0;
	CryptParamLen = 2049;
	CryptParam = 0;
	CryptFileIn = 0;

	CryptParam = new dgt_schar[CryptParamLen];
	CryptFileOut = new pcct_crypt_file_out;
	TargetList = new DgcMemRows(2);
	TargetList->addAttr(DGC_SCHR,2049,"src_file_name");
	TargetList->addAttr(DGC_SCHR,2049,"dst_file_name");
}
	
PccCryptFileStmt::~PccCryptFileStmt()
{
	if (CryptParam) delete CryptParam;
	if (CryptFileOut) delete CryptFileOut;
	if (TargetList) delete TargetList;
}

#if defined ( sunos5 ) || defined ( sunos5_x86 )
struct ll_dirent {
        struct dirent   entry;
        char            name_buf[256];
};
#endif

dgt_sint32 PccCryptFileStmt::filter(const dgt_schar* src_dir, const dgt_schar* dst_dir) throw(DgcExcept)
{
	DIR*        DirPtr;
	if ((DirPtr=opendir(src_dir)) == NULL) {
		THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"opendir[%s] failed",src_dir)),-1);
	}

	dgt_sint32 src_file_len = 2048 + 1;
	dgt_schar* src_file = new dgt_schar[src_file_len];
	dgt_sint32 dst_file_len = 2048 + 1;
	dgt_schar* dst_file = new dgt_schar[dst_file_len];
#if defined ( sunos5 ) || defined ( sunos5_x86 )
	struct ll_dirent        ll_entry;
#else
	struct dirent        ll_entry;
#endif 
	struct dirent*  entry=(struct dirent*)&ll_entry;
	struct dirent*  result;
	dgt_sint32      rtn = 0;
	if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"src_dir [%s] filter start  \n",src_dir);
	struct stat     fstat;
	for (;(rtn=readdir_r(DirPtr,entry,&result)) == 0;) { // success
		memset(src_file,0,src_file_len);
		memset(dst_file,0,dst_file_len);
		sprintf(src_file,"%s/%s",src_dir,entry->d_name);
		sprintf(dst_file,"%s/%s",dst_dir,entry->d_name);

		if (result == NULL) break; // end of entry
		if (stat(src_file,&fstat) < 0) {
			THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"stat[%s] failed",entry->d_name)),-1);
			delete src_file;
			delete dst_file;
		}

		if (S_ISDIR(fstat.st_mode) == 1) {  //when directory
			if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) {
				if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"src_file : %s  is directory \n",src_file);
				if (src_dir == dst_dir) {
					filter(src_file,dst_file);
				} else {
					if (mkdir(dst_file,0777) < 0 && errno != EEXIST) {
						DgcWorker::PLOG.tprintf(0,"mkdir[%s] failed[%s]:\n",dst_file,strerror(errno));
					} else {
						filter(src_file,dst_file);
					}

				}
			}
			 } else if (S_ISREG(fstat.st_mode)) { //when file
				 if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"src_file : %s  is regular file \n",src_file);
				 if((rtn=(dgt_sint8)PccHeaderManager::isEncrypted(src_file)) < 0) {
					 ATHROWnR(DgcError(SPOS,"header checking crypt status failed"),-1);
					 delete src_file;
					 delete dst_file;
				 }
					//rtn :  1 encrypt file, 0 plain file
				 pcct_target_list *target_list;
				 if ((rtn == 1 && (CryptFileIn->crypt_flag == 2)) || 
					 (rtn == 0 && (CryptFileIn->crypt_flag == 1))) { //add target  
					 TargetList->add();
					 TargetList->next();
					 target_list = (pcct_target_list*)TargetList->data();
					 strncpy(target_list->in_file_name, src_file, dg_strlen(src_file));
					 strncpy(target_list->out_file_name, dst_file, dg_strlen(dst_file));
					 if ((CryptFileIn->crypt_flag == 1) && strlen(OutExtension)) {
						 strcat(target_list->out_file_name,".");
						 strcat(target_list->out_file_name,OutExtension);
					 } else if (CryptFileIn->crypt_flag == 2) strcat(target_list->out_file_name,".dec");
				 }
			 } //else if (S_ISREG(fstat.st_mode)) end
		}//for readdir end
		return 0;
}

dgt_sint32 PccCryptFileStmt::buildParam() throw(DgcExcept)
{
	memset(CryptParam,0,CryptParamLen);
	pc_type_open_sess_in    sess_in;
	memset(&sess_in, 0, sizeof(sess_in));
	SessionId = PcaApiSessionPool::getApiSession(sess_in.client_ip,sess_in.user_id,sess_in.client_program,sess_in.client_mac,sess_in.db_user,sess_in.os_user,sess_in.protocol);

	if (SessionId < 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"openSession failed")),-1);
	}
	PcaApiSession*  session=PcaApiSessionPool::getApiSession(SessionId);
	if (!session) THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"openSession failed")),-1);

	dgt_sint32 rtn = 0;
	dgt_schar* out_param = 0;
	dgt_uint32 out_param_len = 0;
	rtn = session->getZoneParam(CryptFileIn->enc_zone_id,&out_param);
	if (rtn) THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"get zone param failed [%lld]: Error Code - %d",CryptFileIn->enc_zone_id,rtn)),-1);

	out_param_len = dg_strlen(out_param);

	//get out_extension
	dgt_schar* val = 0;
	DgcBgrammer* bg = 0;
	DgcBgmrList* ParamList;
	ParamList = new DgcBgmrList(out_param,1);
	while((bg=ParamList->getNext())) {
		val=bg->getValue("out_extension");
//		printf("val [%s]\n",val);
		if (val) {
			strncpy(OutExtension, val, strlen(val));
			break;
		}
	}
	


	if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"get zone param :%d - %s \n",out_param_len,out_param);
	strncat(CryptParam, out_param, out_param_len); 
	//shson add for logging
	dgt_schar logging_param[1024];
	memset(logging_param, 0, sizeof(logging_param));
	sprintf(logging_param, "(logging_info=(ptu_id=%lld)(client_ip=%s))(mode=(crypt=%s)(user_logging=on))", 
			CryptFileIn->ptu_id, 
			CryptFileIn->client_ip, 
			(CryptFileIn->crypt_flag == 1) ? "encrypt":"decrypt");
	strcat(CryptParam, logging_param); 
	if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"crypt_param:\n%s\n",CryptParam);

	return 0;

}

dgt_sint32 PccCryptFileStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);

	//1. initialize
	CryptFileIn = (pcct_crypt_file_in*)mrows->data();
	memset(CryptFileOut,0,sizeof(pcct_crypt_file_out));
	memset(CryptParam,0,CryptParamLen);
	TargetList->reset();
	memset(OutExtension, 0, sizeof(OutExtension));

	if (JobPool.traceLevel() > 10) {
		DgcWorker::PLOG.tprintf(0,"enc_zone_id: %lld crypt_flag: %d InFileName: %s OutFileName %s\n",
				CryptFileIn->enc_zone_id, 
				CryptFileIn->crypt_flag, 
				CryptFileIn->in_file_name, 
				CryptFileIn->out_file_name);
	}

	//2. build PccFileCryptor parameter
	if (buildParam() < 0) {
		DgcExcept* e = 0;
		if (EXCEPT) e = EXCEPT;
		DgcWorker::PLOG.tprintf(0,*e,"buildParam Failed :");
		ATHROWnR(DgcError(SPOS,"buildParam failed : "),-1);
	}

	//3. check file type about in_file_name
	struct stat     fstat;
	dgt_sint8 file_type = 0; //1 -> directory, 2 -> file
	if (stat(CryptFileIn->in_file_name,&fstat) == 0) {
		file_type = S_ISDIR(fstat.st_mode) ? 1 : 2; // 1 -> direcroty, 2 -> file
	} else { //not exist file
	}

	pcct_target_list *target_list;
	if (file_type == 1) filter(CryptFileIn->in_file_name, CryptFileIn->out_file_name); //is directory
	else if (file_type == 2) {
		TargetList->add();
		TargetList->next();
		target_list = (pcct_target_list*)TargetList->data();
		strncpy(target_list->in_file_name, CryptFileIn->in_file_name, dg_strlen(CryptFileIn->in_file_name));
		strncpy(target_list->out_file_name, CryptFileIn->out_file_name, dg_strlen(CryptFileIn->out_file_name));
	}
	if (JobPool.traceLevel() > 10) {
	DgcWorker::PLOG.tprintf(0,"target_list numrows(): %d \n",TargetList->numRows());
	TargetList->dump(DgcWorker::PLOG.logStream());
	}


#if 1
	dgt_sint32 rtn = 0;
	TargetList->rewind();
	while (TargetList->next()) {
	target_list = (pcct_target_list*)TargetList->data();

	PccFileCryptor* cryptor = new PccFileCryptor(0,0,JobPool.traceLevel());
	if ((rtn=cryptor->crypt(SessionId,CryptParam,target_list->in_file_name,target_list->out_file_name)) < 0) {
		CryptFileOut->rtn_code = rtn;
		dgt_sint32 len = dg_strlen(cryptor->errString());
		strncpy(CryptFileOut->error_message,cryptor->errString(),len>1024?1024:len);
		delete cryptor;
		break;
	}
	delete cryptor;
	}
#endif

	TargetList->reset();
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccCryptFileStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	return (dgt_uint8*)CryptFileOut;
}
