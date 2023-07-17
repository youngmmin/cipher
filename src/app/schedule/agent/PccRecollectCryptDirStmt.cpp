/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccRecollectCryptDirStmt
 *   Implementor        :       shson
 *   Create Date        :       2018. 04.24 
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"

PccRecollectCryptDirStmt::PccRecollectCryptDirStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef = new DgcClass("select_list",2);
	SelectListDef->addAttr(DGC_SB4,0,"rtn_code");
	SelectListDef->addAttr(DGC_SCHR,1025,"error_message");
}
	
PccRecollectCryptDirStmt::~PccRecollectCryptDirStmt()
{
}

dgt_sint32 PccRecollectCryptDirStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pcct_recollect_crypt_dir_in*	param_in = (pcct_recollect_crypt_dir_in*)mrows->data();
	memset(&RecollectCryptDirOut, 0, sizeof(pcct_recollect_crypt_dir_out));
	
	PccAgentCryptJob* job = 0;
	if ((job=JobPool.getJob(param_in->job_id)) == 0) {
		ATHROWnR(DgcError(SPOS,"getJob[%lld] failed.",param_in->job_id),-1);
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"not found job [%lld].",param_in->job_id)),-1);
	}
	//1. crypt_dir status stop 
	dgt_sint32 org_dir_status = 0;
	PccCryptDir* crypt_dir = job->repository().dirPool().getCryptDirWithDid(param_in->dir_id);
	if (crypt_dir == 0) {
		job->unlockShare();
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"not found crypt_dir [%lld].",param_in->dir_id)),-1);
	}
	org_dir_status = crypt_dir->status();
	if (org_dir_status == PCC_STATUS_TYPE_RUN) crypt_dir->setStatus(PCC_STATUS_TYPE_PAUSE);

	//2. remove file list to recollecting in FileQueue
	PccCryptTargetFileQueue* FileQueue = 0;
	PccCryptTargetFile TargetFile;
	for (dgt_sint32 i = 1 ; i < 4 ; i++) {
		switch (i)
		{
			case 1 : FileQueue = &(job->repository().fileQueue()); //target queue
					 break;
			case 2 : FileQueue = &(job->repository().failFileQueue()); //fail queue
					 break;
			case 3 : FileQueue = &(job->repository().nullityFileQueue()); //nullity queue
					 break;
			default :
					 job->unlockShare();
					 crypt_dir->setStatus(org_dir_status);
					 THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"invalied target_type [%d].",i)),-1);

		}
		while(FileQueue->get(&TargetFile)) {
			if (TargetFile.dirID() != param_in->dir_id) 
				FileQueue->put(TargetFile.dirID(),
						TargetFile.zoneID(),
						TargetFile.cryptMir(),
						TargetFile.fileNode(),
						TargetFile.cryptStat(),
						TargetFile.srcFileName(),
						TargetFile.srcFileNamePos(),
						TargetFile.dstFileName(),
						TargetFile.dstFileNamePos(),
						TargetFile.errCode(),
						TargetFile.errMsg());
		} //while end
	} //for end

	//3. crypt_mir reset for recollecting
	if (crypt_dir->cryptMir()) crypt_dir->cryptMir()->reset();
	crypt_dir->cryptStat()->crypt_errors = 0;
	crypt_dir->cryptStat()->used_micros = 0;

	//4. revert to crypt_dir original status
	if (crypt_dir) crypt_dir->setStatus(org_dir_status);
	job->unlockShare();

	RecollectCryptDirOut.rtn_code = 0;
//	strncpy(RecollectCryptDirOut.error_message, "successful!", strlen("successful!"));
	IsExecuted = 1;
	FetchFlag = 0;
	return 0;
}

dgt_uint8* PccRecollectCryptDirStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (!FetchFlag) {
		FetchFlag++;
		return (dgt_uint8*)&RecollectCryptDirOut;
	}   
	THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
