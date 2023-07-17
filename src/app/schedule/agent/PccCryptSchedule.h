/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptMir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_SCHEDULE_H
#define PCC_CRYPT_SCHEDULE_H

#include "PccCryptZonePool.h"

typedef struct {
	dgt_sint64	id;		// schedule id
	dgt_sint64	last_update;	// last update
	dgt_uint8	week_map;	// week map
	dgt_uint8	start_hour;	// start hour
	dgt_uint8	end_hour;	// end hour
	dgt_uint8	start_min;	// start minute
	dgt_uint8	end_min;	// end minute
	dgt_uint16	use_cores;	// a number of cores to be used in time
	dgt_uint32	buffer_size;	// the size of buffers to be used
	dgt_uint32	buffer_count;	// the number of buffers
	dgt_sint64	run_size;	// the size per threads which is a base to compute the number of threads for a file
} pcct_week_schedule;

class PccCryptSchedule : public DgcObject {
  private:
	static const dgt_sint32	MAX_WEEK_SCHEDULES=100;
	pcct_week_schedule	WeekSchedules[MAX_WEEK_SCHEDULES];
	dgt_sint32		NumSchedules;
	dgt_sint32		CurrScheduleIdx;
	dgt_slock		Lock;       // concurrency control spin lock

	dgt_sint32 weekSchedule(dgt_sint32 fit = 0); // fit : 0 -> first fit, 1 -> best pit
	dgt_sint32 setWeekSchedule(pcct_week_schedule* ws) throw(DgcExcept);
  protected:
  public:
	PccCryptSchedule();
	virtual ~PccCryptSchedule();
	inline dgt_sint32 isWorkingTime() { return weekSchedule()+1; }
	dgt_void resetWeekSchedules();
	dgt_sint32 setParams(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 usingCores();
	dgt_sint32 buildParam(dgt_sint32 threads,PccCryptTargetFile& tf,dgt_schar* buf,dgt_uint32* buf_len) throw(DgcExcept);
};


#endif
