/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetCryptStatStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

PccGetCryptStatStmt::PccGetCryptStatStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef = new DgcClass("select_list", 24);
	SelectListDef->addAttr(DGC_SB8, 0, "job_id");
	SelectListDef->addAttr(DGC_SB8, 0, "dir_id");
	SelectListDef->addAttr(DGC_SB8, 0, "agent_id");
	SelectListDef->addAttr(DGC_SB8, 0, "zone_id");
	SelectListDef->addAttr(DGC_SB8, 0, "filters");
	SelectListDef->addAttr(DGC_SB8, 0, "check_dirs");
	SelectListDef->addAttr(DGC_SB8, 0, "check_errors");
	SelectListDef->addAttr(DGC_SB8, 0, "target_dirs");
	SelectListDef->addAttr(DGC_SB8, 0, "check_files");
	SelectListDef->addAttr(DGC_SB8, 0, "target_files");
	SelectListDef->addAttr(DGC_SB8, 0, "input_files");
	SelectListDef->addAttr(DGC_SB8, 0, "output_files");
	SelectListDef->addAttr(DGC_SB8, 0, "crypt_errors");
	SelectListDef->addAttr(DGC_SB8, 0, "used_cores");
	SelectListDef->addAttr(DGC_SB8, 0, "used_micros");
	SelectListDef->addAttr(DGC_SB8, 0, "input_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "output_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "system_id");
	SelectListDef->addAttr(DGC_UB4, 0, "start_time");
	SelectListDef->addAttr(DGC_UB4, 0, "end_time");
	SelectListDef->addAttr(DGC_SB4, 0, "job_status");
	SelectListDef->addAttr(DGC_SB4, 0, "dir_status");
	SelectListDef->addAttr(DGC_SB8, 0, "migration_target");
	SelectListDef->addAttr(DGC_SB8, 0, "reserved");

	CryptStat = new DgcMemRows(SelectListDef);
	CryptStat->reset();
}
	
PccGetCryptStatStmt::~PccGetCryptStatStmt()
{
	if (CryptStat) delete CryptStat;
}

dgt_sint32 PccGetCryptStatStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	dgt_sint64		job_id = *(dgt_sint64*)mrows->data();
	PccCryptDir*		curr_dir;
	PccAgentCryptJob*	curr_job;
	pcct_crypt_stat*	curr_stat;
	CryptStat->reset();

	if (job_id == 0) { // all jobs
		for(dgt_sint32 i=0; i<JobPool.numJobs(); i++) {
			if ((curr_job=JobPool.jobByIdx(i))) {
				for(dgt_sint32 j=0; (curr_dir=curr_job->repository().dirPool().getCryptDir(j)); j++) {
					CryptStat->add();
					CryptStat->next();
					curr_stat = (pcct_crypt_stat*)CryptStat->data();
					memcpy(curr_stat,curr_dir->cryptStat(),sizeof(pcct_crypt_stat));
					curr_stat->job_id = curr_job->jobID();
					curr_stat->agent_id = JobPool.agentID();
					if (curr_job->collector() && curr_job->collector()->jobStatus() != PCC_STATUS_TYPE_RUN) curr_stat->job_status = curr_job->collector()->jobStatus();
				}
				curr_job->unlockShare();
			}
		}
	} else {
		if ((curr_job=JobPool.getJob(job_id))) {
			for(dgt_sint32 j=0; (curr_dir=curr_job->repository().dirPool().getCryptDir(j)); j++) {
				CryptStat->add();
				CryptStat->next();
				curr_stat = (pcct_crypt_stat*)CryptStat->data();
				memcpy(curr_stat,curr_dir->cryptStat(),sizeof(pcct_crypt_stat));
				curr_stat->job_id = curr_job->jobID();
				curr_stat->agent_id = JobPool.agentID();
				if (curr_job->collector() && curr_job->collector()->jobStatus() != PCC_STATUS_TYPE_RUN) curr_stat->job_status = curr_job->collector()->jobStatus();
			}
			curr_job->unlockShare();
		} else {
			DgcExcept* e = EXCEPTnC;
			if (e) {
				DgcWorker::PLOG.tprintf(0,*e,"getJob[%lld] failed.\n",job_id);
				delete e;
			}
		}
	}

	CryptStat->rewind();
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccGetCryptStatStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
	if (CryptStat->next()) return (dgt_uint8*)CryptStat->data();
	return 0;
}
