/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PetraCipherMigVerifySchedule
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 09. 03 
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PetraCipherMigVerifySchedule.h"
#include "DgcDbProcess.h"
#include "PcbJobRunner.h"


PetraCipherMigVerifySchedule::PetraCipherMigVerifySchedule(dgt_sint64 schedule_id,dgt_worker* wa, dgt_sint64 job_id)
	: DgcPetraWorker(PCB_WT_SCHEDULE,"PetraCipherMigVSchedule",wa),
	  ScheduleID(schedule_id),
	  JobID(job_id)
{
	ScheduleSeg = 0;
	JobSeg = 0;
	ScheduleRowPtr = 0;
	Session = 0;
}


PetraCipherMigVerifySchedule::~PetraCipherMigVerifySchedule()
{
}


dgt_void PetraCipherMigVerifySchedule::commitScheduleRows()
{
	ScheduleRows.rewind();
	if (ScheduleSeg->pinUpdate(ScheduleRows)) {
		DgcExcept*      e=EXCEPTnC;
		PLOG.tprintf(0,*e,"pinUpdate[PCT_SCHEDULE:%lld] failed:\n",ScheduleRowPtr->schedule_id);
		delete e;
	}
	ScheduleRows.rewind();
	if (ScheduleSeg->updateCommit(DgcDbProcess::sess(), ScheduleRows) != 0) {
		DgcExcept*      e=EXCEPTnC;
		PLOG.tprintf(0,*e,"updateCommit[PCT_SCHEDULE:%lld] failed:\n",ScheduleRowPtr->schedule_id);
		delete e;
	}
}


dgt_void PetraCipherMigVerifySchedule::in() throw(DgcExcept)
{
	PLOG.tprintf(0,"CipherMigVerifySchedule[%d_%d] for ID[%lld] started.\n",this->pid(),this->wid(),ScheduleID);
	dgt_uint16 exe_order=0;
	Session=DgcDbProcess::sess();
	Session->setDatabaseUser(DGC_SYS_OWNER,strlen(DGC_SYS_OWNER));
	DgcSqlHandle SqlHandle(Session);
        dgt_sint32 ret=0;
        dgt_schar soha_str[1024]={0,};
        dgt_void* rtn_row=0;

	pct_type_verify_job*	job;
	ScheduleRowPtr->curr_status=100;
	ScheduleRowPtr->process_id=getpid();
	JobRows.rewind();
	//
	// start jobs sequencially
	//
RETRY_SCHEDULE:
	DgcIndexSegment* idx = 0;
	if ((idx =(DgcIndexSegment*) DgcDbProcess::db().pdb()->idxMgr()->getIndex("PCT_VERIFY_JOB_IDX1")) == 0) {
		ScheduleRowPtr->curr_status = 0;
		ATHROW(DgcError(SPOS,"getIndex failed"));
		THROW(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"index[VERIFY_JOB_ID] not found")));
	}
	job=0;
	memset(soha_str,0,1024);
	sprintf(soha_str,"select * from pct_verify_job where schedule_id=%lld and exe_order>%d order by exe_order",ScheduleID,exe_order);
	if (SqlHandle.execute(soha_str) < 0) {
		ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
	}
	while (!(ret=SqlHandle.fetch(rtn_row)) && rtn_row) {
		pct_type_verify_job*	job_order=(pct_type_verify_job*)rtn_row;
		if (JobID && job_order->verify_job_id != JobID) continue;

		JobRows.reset();
		pct_type_verify_job job_row;
		job_row.schedule_id = ScheduleID;
		if (idx->find((dgt_uint8*) &job_row, JobRows)) {
			ScheduleRowPtr->curr_status = 0;
			ATHROW(DgcError(SPOS,"find failed"));
		}
		if (JobRows.numRows() == 0) {
			ScheduleRowPtr->curr_status = 0;
			THROW(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"no jobs in schedule[%lld]",ScheduleID)));
		}
		JobRows.rewind();

		while(JobRows.next() && ((job=(pct_type_verify_job*)JobRows.data()))) {
			if(job_order->verify_job_id==job->verify_job_id && job->schedule_id==ScheduleID) break;
		}

		if(!job) continue;
		job->process_id = 0;
		if (PcbJobRunner::startMigVerify(job->verify_job_id)) {
			DgcExcept*      e=EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"startJob[%lld] failed due to the below:\n",job->verify_job_id);
			delete e;
		} else {
			//
			// wait until the job process died
			//
			for(dgt_sint32 i=0; i < 100 && job->process_id == 0; i++) napAtick();
			if (job->process_id == 0) {
				//
				// considered that startjob failed
				//
				DgcWorker::PLOG.tprintf(0,"startJob[%lld] failed due to delaied process id setting.\n",job->verify_job_id);
			} else {
				while (!(kill(job->process_id,0) != 0 && errno == ESRCH)) napAtick();
			}
		}
		ScheduleRowPtr->curr_status++;
		exe_order=job->exe_order;
	}
	if (JobID == 0) {
		memset(soha_str,0,1024);
		sprintf(soha_str,"select count() from pct_verify_job where schedule_id=%lld and exe_order>%d",ScheduleID,exe_order);
		if (SqlHandle.execute(soha_str) < 0) {
			ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
		}
		if(!(ret=SqlHandle.fetch(rtn_row)) && rtn_row) {
			dgt_sint64 remain_job_count=*(dgt_sint64*)rtn_row;
			if(remain_job_count > 0) goto RETRY_SCHEDULE;
		}
	}

	DgcExcept*	e = EXCEPTnC;
	if (e) {
		//
		// fetch error or the end of fetch
		//
		if (e->errCode() == DGC_EC_PD_NOT_FOUND) {
			delete e;
		} else {
			RTHROW(e, DgcError(SPOS,"fetch failed"));
		}
	}
	ScheduleRowPtr->start_time=dgtime(&ScheduleRowPtr->start_time);
	ScheduleRowPtr->curr_status += 1000;
}


dgt_sint32 PetraCipherMigVerifySchedule::run() throw(DgcExcept)
{
	pct_type_verify_job*	job;
	dgt_sint32	alive_job_cnt=0;
	JobRows.rewind();
	while(JobRows.next() && ((job=(pct_type_verify_job*)JobRows.data()))) {
		if (JobID && job->verify_job_id != JobID) continue;
		if (!(kill(job->process_id,0) != 0 && errno == ESRCH)) alive_job_cnt++;
	}
	if (alive_job_cnt == 0) {
		ScheduleRowPtr->curr_status += 1000;
		return 1;
	}
	napAtick();
	return 0;
}


dgt_void PetraCipherMigVerifySchedule::out() throw(DgcExcept)
{
        //
        //enc_status 2 : after encrypt 
        //
        DgcSqlHandle SqlHandle(Session);
        dgt_schar soha_str[1024]={0,};
	//
	// set the schedule status
	//
	ScheduleRowPtr->curr_status = PetraCipherMigVerifyJob::PCB_JOB_STATUS_DONE;
	pct_type_verify_job*	job = 0;
	JobRows.rewind();
	while(JobRows.next() && ((job=(pct_type_verify_job*)JobRows.data()))) {
		switch(job->curr_status) {
			case PetraCipherMigVerifyJob::PCB_JOB_STATUS_DONE :
				break;
			case PetraCipherMigVerifyJob::PCB_JOB_STATUS_SCHEDULING :
				if (ScheduleRowPtr->curr_status == PetraCipherMigVerifyJob::PCB_JOB_STATUS_DONE) {
					ScheduleRowPtr->curr_status = PetraCipherMigVerifyJob::PCB_JOB_STATUS_SCHEDULING;
				}
				break;
			case PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING :
				ScheduleRowPtr->curr_status = PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING;
				break;
			default :
				//
				// must change this job's status to PCB_JOB_STATUS_PENDING:
				// update pct_verify_job set(curr_status)=(PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING) where job_id=job->job_id;
				// except a default schedule!
				// 
				if (ScheduleRowPtr->schedule_id !=1){
					ScheduleRowPtr->curr_status = PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING;
				        dg_memset(soha_str,0,1024);
				        sprintf(soha_str,"update pct_verify_job set(curr_status)=(%d) where verify_job_id=%lld",
                	                                  PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING, job->verify_job_id);
       					if (SqlHandle.execute(soha_str) < 0) {
               	 				ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
	        			}
				}
				break;
		}
	}
	ScheduleRowPtr->end_time=dgtime(&ScheduleRowPtr->end_time);
	commitScheduleRows();
	PLOG.tprintf(0,"CipherMigVerifySchedule[%d_%d] for ID[%lld] stopped.\n",this->pid(),this->wid(),ScheduleID);
}


dgt_sint32 PetraCipherMigVerifySchedule::initialize() throw(DgcExcept)
{
	//
	// get the schedule table segment
	//
	ScheduleSeg=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_SCHEDULE");
	if (ScheduleSeg == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_SCHEDULE] failed"),-1);
		THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"table[PCT_SCHEDULE] not found")),-1);
	}
	AllScheduleRows.setFsegment(ScheduleSeg);
	ScheduleRows.setFsegment(ScheduleSeg);
	ScheduleSeg->unlockShare();
	//
	// search the schedule row
	//
	AllScheduleRows.rewind();
	while(AllScheduleRows.next() && (ScheduleRowPtr=(pct_type_schedule*)AllScheduleRows.data())) {
		if (ScheduleRowPtr->schedule_id == ScheduleID) {
			if (ScheduleRowPtr->schedule_id !=1 && ScheduleRowPtr->curr_status > 0 && ScheduleRowPtr->curr_status < PetraCipherMigVerifyJob::PCB_JOB_STATUS_PENDING) {
				THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"Schedule[%lld] is running",ScheduleID)),-1);
			}
			ScheduleRowPtr->curr_status = 10;
			ScheduleRows.add(AllScheduleRows.bno(), AllScheduleRows.rno(), AllScheduleRows.data());
			break;
		}
		ScheduleRowPtr=0;
	}
	if (!ScheduleRowPtr) {
		ScheduleRowPtr->curr_status = 0;
		THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"Schedule[%lld] not found",ScheduleID)),-1);
	}

	//
	// get the job table segment
	//
	JobSeg=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_VERIFY_JOB");
	if (JobSeg == 0) {
		ScheduleRowPtr->curr_status = 0;
		ATHROWnR(DgcError(SPOS,"getTable[PCT_VERIFY_JOB] failed"),-1);
		THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"table[PCT_VERIFY_JOB] not found")),-1);
	}
	JobRows.setFsegment(JobSeg);
	JobSeg->unlockShare();

	return 0;
}
