/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PetraCipherScheduler
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 5
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PetraCipherScheduler.h"
#include "PetraCipherSchedule.h"
#include "DgcDbProcess.h"


PetraCipherScheduler::PetraCipherScheduler(dgt_worker* wa)
	: DgcPetraWorker(PCB_WT_SCHEDULER,"PetraCipherScheduler",wa)
{
	ScheduleID = 0;
	ScheduleSeg = 0;
	ScheduleRowPtr = 0;
}


PetraCipherScheduler::~PetraCipherScheduler()
{
}


dgt_void PetraCipherScheduler::in() throw(DgcExcept)
{
	PLOG.tprintf(0,"CipherScheduler[%d_%d] started.\n",this->pid(),this->wid());
}


dgt_sint32 PetraCipherScheduler::run() throw(DgcExcept)
{
	pct_type_schedule*	schedule;
	AllScheduleRows.reset();
	while(AllScheduleRows.next() && ((schedule=(pct_type_schedule*)AllScheduleRows.data()))) {
		dgt_time	ct=dgtime(&ct);
		if (!strcasecmp(schedule->executing_mode,"time-base") &&
		    schedule->curr_status == 0 &&
		    ct >= schedule->start_time &&
		    (ct - schedule->start_time) < 3) {
			//
			// find a schedule reaching its starting time
			//
			dgt_worker*	wa;
			if ((wa=DgcDbProcess::db().getWorker(DgcDbProcess::sess())) == 0) {
				DgcExcept*	e=EXCEPTnC;
				PLOG.tprintf(0,*e,"getWorker for schedule[%lld] failed due to the below:\n",schedule->schedule_id);
                                delete e;
			} else {
				dg_strncpy(wa->Owner,DGC_SYS_OWNER,strlen(DGC_SYS_OWNER));
				wa->PID=DgcDbProcess::pa().pid;
				wa->LWID=wa->WID;
				PetraCipherSchedule*	pcs=new PetraCipherSchedule(schedule->schedule_id,wa);
				if (pcs->initialize()) {
					DgcExcept*      e=EXCEPTnC;
					delete pcs;
					PLOG.tprintf(0,*e,"initialize[%lld] failed due to the below:\n",schedule->schedule_id);
					delete e;
				} else if (pcs->start() != 0) {
					DgcExcept*	e=EXCEPTnC;
					PLOG.tprintf(0,*e,"start schedule[%lld] failed due to the below exception:",schedule->schedule_id);
					if (e->classid() == DGC_EXT_WORKER) delete pcs;
					delete e;
				}
			}
		}
	}
	napAtick();
	return 0;
}


dgt_void PetraCipherScheduler::out() throw(DgcExcept)
{
	PLOG.tprintf(0,"CipherScheduler[%d_%d] stopped.\n",this->pid(),this->wid());
}


dgt_sint32 PetraCipherScheduler::initialize() throw(DgcExcept)
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
	ScheduleSeg->unlockShare();
	return 0;
}
