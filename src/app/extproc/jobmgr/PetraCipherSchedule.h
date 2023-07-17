/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PetraCipherSchedule
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PETRA_CIPHER_SCHEDULE_H
#define PETRA_CIPHER_SCHEDULE_H


#include "DgcPetraWorker.h"
#include "DgcSqlHandle.h"
#include "PccTableTypes.h"

class PetraCipherSchedule : public DgcPetraWorker {
  private:
	static const dgt_uint8	PCB_WT_SCHEDULE=71;

	dgt_sint64		ScheduleID;
	dgt_sint64		JobID;
	dgt_sint64		SystemID;
	DgcTableSegment*	ScheduleSeg;
	DgcRowRef		AllScheduleRows;
	DgcRowList		ScheduleRows;
	pct_type_schedule*		ScheduleRowPtr;
	DgcTableSegment*	JobSeg;
	DgcRowList		JobRows;
	DgcSession*	Session;

	dgt_void commitScheduleRows();
//	dgt_sint32 startJob(pct_type_job* job) throw(DgcExcept);

	virtual dgt_void	in() throw(DgcExcept);
	virtual dgt_sint32	run() throw(DgcExcept);
	virtual dgt_void	out() throw(DgcExcept);
  protected:
  public:
  	/**
	 * The PCB_JOB_STATUS status value shares state information with the PetraCipherJob class. The values of these two pieces of information must always be identical.
	 */
	static const dgt_sint16	PCB_JOB_STATUS_SCHEDULING=0;
	static const dgt_sint16	PCB_JOB_STATUS_PENDING=10000;
	static const dgt_sint16	PCB_JOB_STATUS_DONE=20000;

        PetraCipherSchedule(dgt_sint64 schedule_id,dgt_worker* wa,dgt_sint64 job_id=0);
        virtual ~PetraCipherSchedule();

	inline pct_type_schedule* scheduleRow() { return ScheduleRowPtr; };

	dgt_sint32 initialize() throw(DgcExcept);
};


#endif
