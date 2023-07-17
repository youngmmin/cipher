/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccSetParamsStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
 *   180713					 modified parameter parsing
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"
#include "DgcBgmrList.h"

PccSetParamsStmt::PccSetParamsStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool),CurrJob(0)
{
	SelectListDef=new DgcClass("select_list",20);
	SelectListDef->addAttr(DGC_SB8,0,"job_id");
	SelectListDef->addAttr(DGC_SB8,0,"dir_id");
	SelectListDef->addAttr(DGC_SB8,0,"agent_id");
	SelectListDef->addAttr(DGC_SB8,0,"zone_id");
	SelectListDef->addAttr(DGC_SB8,0,"filters");
	SelectListDef->addAttr(DGC_SB8,0,"check_dirs");
	SelectListDef->addAttr(DGC_SB8,0,"check_errors");
	SelectListDef->addAttr(DGC_SB8,0,"target_dirs");
	SelectListDef->addAttr(DGC_SB8,0,"check_files");
	SelectListDef->addAttr(DGC_SB8,0,"target_files");
	SelectListDef->addAttr(DGC_SB8,0,"input_files");
	SelectListDef->addAttr(DGC_SB8,0,"output_files");
	SelectListDef->addAttr(DGC_SB8,0,"crypt_errors");
	SelectListDef->addAttr(DGC_SB8,0,"used_cores");
	SelectListDef->addAttr(DGC_SB8,0,"used_micros");
	SelectListDef->addAttr(DGC_SB8,0,"input_bytes");
	SelectListDef->addAttr(DGC_SB8,0,"output_bytes");
	SelectListDef->addAttr(DGC_UB4,0,"start_time");
	SelectListDef->addAttr(DGC_UB4,0,"end_time");
	SelectListDef->addAttr(DGC_SB4,0,"job_status");
	ParamTextLen = 0;
	ParamText = 0;
}
	
PccSetParamsStmt::~PccSetParamsStmt()
{
	if (ParamText) delete ParamText;
}

dgt_sint32 PccSetParamsStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	dgt_sint64 job_id = 0;
	dgt_sint64 last_update = 0;
	dgt_sint32 file_queue_size = JobPool.fileQueueSize();
	dgt_sint32 collect_interval = JobPool.collectInterval();
	dgt_uint8 job_type = 0;
	dgt_uint8 job_status = 0;

	dgt_uint32	params_len = 1025*mrows->numRows();
	if (params_len > ParamTextLen) {
		if (ParamText) delete ParamText;
		ParamTextLen = params_len;
		ParamText = new dgt_schar[ParamTextLen];
	}

	memset(ParamText,0,ParamTextLen);
	do {
		pcct_set_params*	params = (pcct_set_params*)mrows->data();
		job_id = params->job_id;
		last_update = params->last_update;
		if (params->max_target_files > 0) file_queue_size = params->max_target_files;
		if (params->collecting_interval > 0) collect_interval = params->collecting_interval;
		job_type = params->job_type;
		job_status = params->status;

		strncat(ParamText,params->data,1024);
	} while(mrows->next());

	if (JobPool.traceLevel() > 10) {
		DgcWorker::PLOG.tprintf(0,"job_id[%lld] last_update[%lld] agent_param_size[%u] file_queue_size[%d] collect_interval[%d] job_type[%d] job_status[%u]\n",job_id,last_update,dg_strlen(ParamText),file_queue_size,collect_interval,job_type,job_status);
		DgcWorker::PLOG.tprintf(0,"param:\n%s\n",ParamText);
	}
	DgcBgmrList	params(ParamText,1);
	if (EXCEPT) {
		DgcExcept* e=EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"parse failed"),-1);
	}
	dgt_uint8 new_job_flag = 0;
	PccAgentCryptJob* job = 0;

	if (job_status == PCC_STATUS_TYPE_DELETED || job_status == PCC_STATUS_TYPE_PAUSE) {
		if ((job=JobPool.getJob(job_id)) == 0) {
			ATHROWnR(DgcError(SPOS,"getJob[%lld] failed.",job_id),-1);
			THROWnR(DgcCipherExcept(DGC_EC_CP_NOT_READY,new DgcError(SPOS,"job[%lld] not found",job_id)),-1);
		}
	} else {
		if ((job=JobPool.getJob(job_id)) == 0) {
			ATHROWnR(DgcError(SPOS,"getJob[%lld] failed.",job_id),-1);

			if ((job=JobPool.newJob(job_id)) == 0) {
				ATHROWnR(DgcError(SPOS,"newJob failed"),-1);
			}
			if (job->lockShare() < 0) {
				ATHROWnR(DgcError(SPOS,"lockShare failed"),0);
			}
			new_job_flag = 1;
			if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"create new job:%lld\n",job_id);
		}


		DgcBgrammer* bg = 0;
		job->repository().schedule().resetWeekSchedules();

		while((bg=params.getNext())) {
			if (bg->getNode("schedule")) {
				job->repository().schedule().setParams(bg);
			} else if (bg->getNode("crypt_dir")) {
				job->repository().dirPool().setCryptDirParams(bg);
			} else if (bg->getNode("dir_pttn")) {
				job->repository().dirPool().setDirPttn(bg);
			} else if (bg->getNode("file_pttn")) {
				job->repository().dirPool().setFilePttn(bg);
			} else { //zone
				job->repository().zonePool().setParams(bg);
			}
			if (EXCEPT) {
				DgcExcept* e = EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"job[%lld] occur exception:",job->jobID());
				job->unlockShare();
				if (new_job_flag) {
					if (JobPool.dropJob(job->jobID()) < 0) {
						DgcExcept*  drop_job_e = EXCEPTnC;
						DgcWorker::PLOG.tprintf(0,*drop_job_e,"dropJob[%lld] failed while executing setParams:",job->jobID());
						delete drop_job_e;
					}
				}
				RTHROWnR(e,DgcError(SPOS,"setParams failed"),-1);
			}
		} //while((bg=params.getNext())) end
	} //else end
	if (new_job_flag) {
		if (job->start(job_type,job_status,file_queue_size,collect_interval) < 0) {
			DgcExcept* e = EXCEPTnC;
			job->unlockShare();
			JobPool.dropJob(job->jobID());
			RTHROWnR(e,DgcError(SPOS,"dropJob[%lld] failed",job_id),-1);
		}
	} else {
		if (job->collector()) {
			if (job_status == PCC_STATUS_TYPE_DELETED) {
				job->unlockShare();
				//JobPool.dropJob(job->jobID());
				//for bmt, must uncommeted
				job->collector()->setJobStatus(PCC_STATUS_TYPE_PAUSE);
				job = 0;
				if (JobPool.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"drop job:%lld\n",job_id);
			} else {
				job->collector()->setJobStatus(job_status);
				job->collector()->setCollectingInterval(collect_interval);
			}
		}
	}

	memset(&CryptStat,0,sizeof(pcct_crypt_stat));

	if (job) {
		CryptStat.job_id = job_id;
		CryptStat.job_status = job_status;
		job->unlockShare();
	}

	if (last_update ) {
		if (JobPool.lastUpdate() == 0 || last_update < JobPool.lastUpdate()) {
			JobPool.setLastUpdate(last_update);
		}
	}

	CurrJob = job;
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccSetParamsStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	return (dgt_uint8*)&CryptStat;
}
