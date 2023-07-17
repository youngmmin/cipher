/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PetraCipherSchedule
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 5
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PetraCipherSchedule.h"
#include "DgcDbProcess.h"
#include "PcbJobRunner.h"


PetraCipherSchedule::PetraCipherSchedule(dgt_sint64 schedule_id,dgt_worker* wa, dgt_sint64 job_id)
	: DgcPetraWorker(PCB_WT_SCHEDULE,"PetraCipherSchedule",wa),
	  ScheduleID(schedule_id),
	  JobID(job_id)
{
	SystemID=0;
	ScheduleRowPtr = 0;
	Session = 0;
	ScheduleSeg = 0;
	JobSeg = 0;
}


PetraCipherSchedule::~PetraCipherSchedule()
{
}


dgt_void PetraCipherSchedule::commitScheduleRows()
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


dgt_void PetraCipherSchedule::in() throw(DgcExcept)
{
	PLOG.tprintf(0,"CipherSchedule[%d_%d] for ID[%lld] started.\n",this->pid(),this->wid(),ScheduleID);
	dgt_uint16 exe_order=0;
	//
	//enc_status 1 : encrypt in progress
	//update enc_status system_stat_schedule table 
	//
	Session=DgcDbProcess::sess();
	Session->setDatabaseUser(DGC_SYS_OWNER,strlen(DGC_SYS_OWNER));
	DgcSqlHandle SqlHandle(Session);
        dgt_sint32 ret=0;
        dgt_schar soha_str[1024]={0,};
        dgt_void* rtn_row=0;

#if 0
	dg_sprintf(soha_str,
		"select distinct ss.system_id " 
		"from pt_db_service ss, "
 			"(select s.db_id from s.pct_enc_schema s, "
				"(select t.schema_id from pct_job j, pct_enc_table t "
				"where j.enc_tab_id=t.enc_tab_id "
				"and j.schedule_id=%lld ) a "
			"where s.schema_id=a.schema_id) d "
		"where ss.db_id=d.db_id",ScheduleID);
	if (SqlHandle.execute(soha_str) < 0) {
		ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
	}
	if(!(ret=SqlHandle.fetch(rtn_row)) && rtn_row) {
		SystemID=*(dgt_sint64*)rtn_row;
	}
	if(ret < 0) ATHROW(DgcError(SPOS,"SqlHandle fetch failed."));
	
	dg_memset(soha_str,0,1024);
	dg_sprintf(soha_str,"update ceea_system_stat_schedule set(enc_status)=(1) where system_id=%lld",SystemID);
	if (SqlHandle.execute(soha_str) < 0) {
		ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
	}
#endif
	pct_type_job*	job;
	ScheduleRowPtr->curr_status=100;
	ScheduleRowPtr->process_id=getpid();
	JobRows.rewind();
	if (strcasecmp(ScheduleRowPtr->job_start_mode,"concurrent")) {
		//
		// start jobs sequencially
		//
RETRY_SCHEDULE:
		DgcIndexSegment* idx = 0;
		if ((idx =(DgcIndexSegment*) DgcDbProcess::db().pdb()->idxMgr()->getIndex("PCT_JOB_IDX1")) == 0) {
			ScheduleRowPtr->curr_status = 0;
			ATHROW(DgcError(SPOS,"getIndex failed"));
			THROW(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"index[PCT_JOB_IDX1] not found")));
		}

		job=0;
		memset(soha_str,0,1024);
		sprintf(soha_str,"select * from pct_job where schedule_id=%lld and exe_order>%d order by exe_order",ScheduleID,exe_order);
		if (SqlHandle.execute(soha_str) < 0) {
			ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
		}
		while (!(ret=SqlHandle.fetch(rtn_row)) && rtn_row) {
			pct_type_job*	job_order=(pct_type_job*)rtn_row;
			if (JobID && job_order->job_id != JobID) continue;

			JobRows.reset();
			pct_type_job job_row;
			job_row.schedule_id = ScheduleID;
			//job_row.job_id = JobID;
			if (idx->find((dgt_uint8*) &job_row, JobRows)) {
				ScheduleRowPtr->curr_status = 0;
				ATHROW(DgcError(SPOS,"find failed"));
			}
			if (JobRows.numRows() == 0) {
				ScheduleRowPtr->curr_status = 0;
				THROW(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"no jobs in schedule[%lld]",ScheduleID)));
			}
			JobRows.rewind();

			while(JobRows.next() && ((job=(pct_type_job*)JobRows.data()))) {
				if(job_order->job_id==job->job_id && job->schedule_id==ScheduleID) break;
			}

			if(!job) continue;
			job->process_id = 0;
			if (PcbJobRunner::startJob(job->job_id)) {
				DgcExcept*      e=EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"startJob[%lld] failed due to the below:\n",job->job_id);
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
					DgcWorker::PLOG.tprintf(0,"startJob[%lld] failed due to delaied process id setting.\n",job->job_id);
				} else {
					while (!(kill(job->process_id,0) != 0 && errno == ESRCH)) napAtick();
				}
			}
			ScheduleRowPtr->curr_status++;
			exe_order=job->exe_order;
		}

		if (JobID == 0) {
			memset(soha_str,0,1024);
			sprintf(soha_str,"select count() from pct_job where schedule_id=%lld and exe_order>%d",ScheduleID,exe_order);
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
	} else {
		//
		// start jobs concurrentlly
		//
		DgcIndexSegment* idx = 0;
		if ((idx =(DgcIndexSegment*) DgcDbProcess::db().pdb()->idxMgr()->getIndex("PCT_JOB_IDX1")) == 0) {
			ScheduleRowPtr->curr_status = 0;
			ATHROW(DgcError(SPOS,"getIndex failed"));
			THROW(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"index[PCT_JOB_IDX1] not found")));
		}
		JobRows.reset();
		pct_type_job job_row;
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

		while(JobRows.next() && ((job=(pct_type_job*)JobRows.data()))) {
			if (JobID && job->job_id != JobID) continue;
			job->process_id = 0;
			if (PcbJobRunner::startJob(job->job_id)) {
				DgcExcept*      e=EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"startJob[%lld] failed due to the below:\n",job->job_id);
				delete e;
			}
			for(dgt_sint32 i=0; i < 100 && job->process_id == 0; i++) napAtick();
			if (job->process_id == 0) {
				DgcWorker::PLOG.tprintf(0,"startJob[%lld] failed due to delaied process id setting.\n",job->job_id);
			} else {
				ScheduleRowPtr->curr_status++;
			}
		}
	}
	ScheduleRowPtr->start_time=dgtime(&ScheduleRowPtr->start_time);
	ScheduleRowPtr->curr_status += 1000;
}


dgt_sint32 PetraCipherSchedule::run() throw(DgcExcept)
{
	pct_type_job*	job;
	dgt_sint32	alive_job_cnt=0;
	JobRows.rewind();
	while(JobRows.next() && ((job=(pct_type_job*)JobRows.data()))) {
		if (JobID && job->job_id != JobID) continue;
		if (!(kill(job->process_id,0) != 0 && errno == ESRCH)) alive_job_cnt++;
	}
	if (alive_job_cnt == 0) {
		ScheduleRowPtr->curr_status += 1000;
		return 1;
	}
	napAtick();
	return 0;
}


dgt_void PetraCipherSchedule::out() throw(DgcExcept)
{
        //
        //enc_status 2 : after encrypt 
        //update enc_status system_stat_schedule table
        //
        DgcSqlHandle SqlHandle(Session);
        dgt_schar soha_str[1024]={0,};
#if 0
        dg_sprintf(soha_str,"update ceea_system_stat_schedule set(enc_status)=(2) where system_id=%lld",SystemID);
        if (SqlHandle.execute(soha_str) < 0) {
                ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
        }
#endif
	//
	// set the schedule status
	//
	ScheduleRowPtr->curr_status = PCB_JOB_STATUS_DONE;
	pct_type_job*	job = 0;
	JobRows.rewind();
	while(JobRows.next() && ((job=(pct_type_job*)JobRows.data()))) {
		switch(job->curr_status) {
			case PCB_JOB_STATUS_DONE :
				break;
			case PCB_JOB_STATUS_SCHEDULING :
				if (ScheduleRowPtr->curr_status == PCB_JOB_STATUS_DONE) {
					ScheduleRowPtr->curr_status = PCB_JOB_STATUS_SCHEDULING;
				}
				break;
			case PCB_JOB_STATUS_PENDING :
				ScheduleRowPtr->curr_status = PCB_JOB_STATUS_PENDING;
				break;
			default :
				//
				// must change this job's status to PCB_JOB_STATUS_PENDING:
				// update pct_job set(curr_status)=(PCB_JOB_STATUS_PENDING) where job_id=job->job_id;
				// except a default schedule!
				// 
				if (ScheduleRowPtr->schedule_id !=1){
					ScheduleRowPtr->curr_status = PCB_JOB_STATUS_PENDING;
			        dg_memset(soha_str,0,1024);
			        sprintf(soha_str,"update pct_job set(curr_status)=(%d) where job_id=%lld",
                                                  PCB_JOB_STATUS_PENDING,job->job_id);
       				if (SqlHandle.execute(soha_str) < 0) {
               	 			ATHROW(DgcError(SPOS,"SqlHandle execute failed."));
        			}
				}
				break;
		}
	}
	ScheduleRowPtr->end_time=dgtime(&ScheduleRowPtr->end_time);
	commitScheduleRows();
	PLOG.tprintf(0,"CipherSchedule[%d_%d] for ID[%lld] stopped.\n",this->pid(),this->wid(),ScheduleID);
}


dgt_sint32 PetraCipherSchedule::initialize() throw(DgcExcept)
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
			if (ScheduleRowPtr->schedule_id !=1 && ScheduleRowPtr->curr_status > 0 && ScheduleRowPtr->curr_status < PCB_JOB_STATUS_PENDING) {
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
	JobSeg=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_JOB");
	if (JobSeg == 0) {
		ScheduleRowPtr->curr_status = 0;
		ATHROWnR(DgcError(SPOS,"getTable[PCT_JOB] failed"),-1);
		THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"table[PCT_JOB] not found")),-1);
	}
	JobRows.setFsegment(JobSeg);
	JobSeg->unlockShare();

	return 0;
}
