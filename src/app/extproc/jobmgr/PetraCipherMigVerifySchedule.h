/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PetraCipherMigVerifySchedule
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 09. 03
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PETRA_CIPHER_MIG_VERIFY_SCHEDULE_H
#define PETRA_CIPHER_MIG_VERIFY_SCHEDULE_H


#include "DgcPetraWorker.h"
#include "PetraCipherMigVerifyJob.h"
#include "DgcSqlHandle.h"

class PetraCipherMigVerifySchedule : public DgcPetraWorker {
  private:
	static const dgt_uint8	PCB_WT_SCHEDULE=71;

	dgt_sint64		ScheduleID;
	dgt_sint64		JobID;
	DgcTableSegment*	ScheduleSeg;
	DgcRowRef		AllScheduleRows;
	DgcRowList		ScheduleRows;
	pct_type_schedule*	ScheduleRowPtr;
	DgcTableSegment*	JobSeg;
	DgcRowList		JobRows;
	DgcSession*		Session;

	dgt_void commitScheduleRows();

	virtual dgt_void	in() throw(DgcExcept);
	virtual dgt_sint32	run() throw(DgcExcept);
	virtual dgt_void	out() throw(DgcExcept);
  protected:
  public:
        PetraCipherMigVerifySchedule(dgt_sint64 schedule_id,dgt_worker* wa,dgt_sint64 job_id=0);
        virtual ~PetraCipherMigVerifySchedule();

	inline pct_type_schedule* scheduleRow() { return ScheduleRowPtr; };

	dgt_sint32 initialize() throw(DgcExcept);
};


#endif
