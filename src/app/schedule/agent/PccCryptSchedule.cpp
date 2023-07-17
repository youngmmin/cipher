/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptSchedule
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptSchedule.h"
#include "PcaPrivilege.h"

PccCryptSchedule::PccCryptSchedule()
	: NumSchedules(0), CurrScheduleIdx(-1)
{
	for(dgt_sint32 i=0; i<MAX_WEEK_SCHEDULES; i++) {
		memset(&WeekSchedules[i],0,sizeof(pcct_week_schedule));
	}
	DgcSpinLock::unlock(&Lock);
}


PccCryptSchedule::~PccCryptSchedule()
{
}


dgt_sint32 PccCryptSchedule::weekSchedule(dgt_sint32 fit) // fit : 0 -> first fit, 1 -> best pit
{
	dgt_time	ct = dgtime(&ct);
	time_t          temp_ct = ct;
	struct tm       res;
	struct tm*      now = localtime_r(&temp_ct, &res);
	dgt_sint32	rtn = -1;
	if (DgcSpinLock::lock(&Lock) == 0) {
		for(dgt_sint32 i=0; i<NumSchedules;i++) {
			if(WeekSchedules[i].week_map&PCA_WEEKDAY_MASK_MAP[now->tm_wday]) {
				if (now->tm_hour < WeekSchedules[i].start_hour ||
					(now->tm_hour == WeekSchedules[i].start_hour && now->tm_min < WeekSchedules[i].start_min)) continue; // before start time
				if ((WeekSchedules[i].end_hour && now->tm_hour > WeekSchedules[i].end_hour) ||
					(now->tm_hour == WeekSchedules[i].end_hour && now->tm_min > WeekSchedules[i].end_min)) continue; // after end time
				if (fit == 0) {
					// first fit which return the first schedule meeting the given time conditions
					rtn = i;
					break;
				} else {
					// best fit which return the best schedule meeting the given time conditions with the greatest use cores
					if (rtn < 0 || WeekSchedules[i].use_cores > WeekSchedules[rtn].use_cores) rtn = i;
				}
			}
		}
		DgcSpinLock::unlock(&Lock);
	}
	return rtn;
}


dgt_sint32 PccCryptSchedule::setWeekSchedule(pcct_week_schedule* ws) throw(DgcExcept)
{
	//if (ws->id == 0) THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"invalid schedule id[%lld]",ws->id)),-1);
	if (ws->week_map == 0) THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"invalid week map[%u]",ws->week_map)),-1);
	if (ws->start_hour > ws->end_hour || (ws->start_hour == ws->end_hour && ws->start_min > ws->end_min)) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"invalid time[%d:%d - %d:%d]",
			ws->start_hour,ws->start_min,ws->end_hour,ws->end_min)),-1);
	}
	if (ws->buffer_size && ws->buffer_size < 1024) ws->buffer_size = 0;
	if (ws->buffer_count && ws->buffer_count < 3) ws->buffer_count = 0;
	if (ws->run_size && ws->run_size < 102400) ws->run_size = 0;
	for(dgt_sint32 i=0; i<NumSchedules; i++) { // for update
		if (WeekSchedules[i].id == ws->id) {
			if (DgcSpinLock::lock(&Lock) == 0) {
				memcpy(&(WeekSchedules[i]),ws,sizeof(pcct_week_schedule));
				DgcSpinLock::unlock(&Lock);
			}
			return 0;
		}
	}
	if (DgcSpinLock::lock(&Lock) == 0) {
		if (NumSchedules < MAX_WEEK_SCHEDULES) {
			memcpy(&(WeekSchedules[NumSchedules++]),ws,sizeof(pcct_week_schedule));
		} else {
			DgcSpinLock::unlock(&Lock);
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"reach the max schedules[%d]",NumSchedules)),-1);
		}
		DgcSpinLock::unlock(&Lock);
	}
	return 0;
}


dgt_void PccCryptSchedule::resetWeekSchedules()
{
	if (DgcSpinLock::lock(&Lock) == 0) {
		for(dgt_sint32 i=0; i<NumSchedules; i++) {
			memset(&WeekSchedules[i],0,sizeof(pcct_week_schedule));
		}
		NumSchedules = 0;
		DgcSpinLock::unlock(&Lock);
	}
}


dgt_sint32 PccCryptSchedule::setParams(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_schar*		val;
	pcct_week_schedule	ws;
	memset(&ws,0,sizeof(ws));
#ifndef WIN32
	if ((val=bg->getValue("schedule.id")) && *val) ws.id = dg_strtoll(val,0,10);
#else
	if ((val=bg->getValue("schedule.id")) && *val) ws.id = (dgt_sint64)_strtoi64(val,0,10);
#endif
	if ((val=bg->getValue("schedule.week_map")) && *val) ws.week_map = (dgt_uint8)strtol(val,0,10);
	if ((val=bg->getValue("schedule.start_hour")) && *val) ws.start_hour = (dgt_uint8)strtol(val,0,10);
	if ((val=bg->getValue("schedule.end_hour")) && *val) ws.end_hour = (dgt_uint8)strtol(val,0,10);
	if ((val=bg->getValue("schedule.start_min")) && *val) ws.start_min = (dgt_uint8)strtol(val,0,10);
	if ((val=bg->getValue("schedule.end_min")) && *val) ws.end_min = (dgt_uint8)strtol(val,0,10);
	if ((val=bg->getValue("schedule.use_cores")) && *val) ws.use_cores = (dgt_uint16)strtol(val,0,10);
	if ((val=bg->getValue("schedule.buffer_size")) && *val) ws.buffer_size = (dgt_uint32)strtol(val,0,10);
	if ((val=bg->getValue("schedule.buffer_count")) && *val) ws.buffer_count = (dgt_uint32)strtol(val,0,10);
#ifndef WIN32
	if ((val=bg->getValue("schedule.run_size")) && *val) ws.run_size = dg_strtoll(val,0,10);
#else
	if ((val=bg->getValue("schedule.run_size")) && *val) ws.run_size = (dgt_sint64)_strtoi64(val,0,10);
#endif
	if (setWeekSchedule(&ws) < 0) {
		ATHROWnR(DgcError(SPOS,"setWeekSchedule failed"),-1);
	}
	return 0;
}


dgt_sint32 PccCryptSchedule::usingCores()
{
	CurrScheduleIdx = weekSchedule(1);
	if (CurrScheduleIdx < 0) return 0;
	return WeekSchedules[CurrScheduleIdx].use_cores;
}


dgt_sint32 PccCryptSchedule::buildParam(dgt_sint32 threads,PccCryptTargetFile& tf,dgt_schar* buf,dgt_uint32* buf_len) throw(DgcExcept)
{
	//
	// return the # of threads so as to get necessary cores
	//
	if (CurrScheduleIdx >= 0) {
		//
		// (parallel=(buffer=(amount=3000)(size=1024))(threads=7))
		//
		dgt_schar	tmp_buf[513],tmp[129];
		memset(tmp_buf,0,512);
		sprintf(tmp_buf,"(parallel=(buffer=");
		if (WeekSchedules[CurrScheduleIdx].buffer_count) {
			memset(tmp,0,129);
			sprintf(tmp,"(amount=%u)",WeekSchedules[CurrScheduleIdx].buffer_count);
			strcat(tmp_buf,tmp);
		} else {
			memset(tmp,0,129);
			sprintf(tmp,"(amount=%u)",threads+2);
			strcat(tmp_buf,tmp);
		}
		if (WeekSchedules[CurrScheduleIdx].buffer_size) {
			memset(tmp,0,129);
			sprintf(tmp,"(size=%u)",WeekSchedules[CurrScheduleIdx].buffer_size);
			strcat(tmp_buf,tmp);
		}
		strcat(tmp_buf,")");
#if 0
		if (WeekSchedules[CurrScheduleIdx].run_size) {
			threads = tf.fileNode()->file_size / WeekSchedules[CurrScheduleIdx].run_size;
			if (threads > 1 && threads < WeekSchedules[CurrScheduleIdx].use_cores) {
				memset(tmp,0,129);
				sprintf(tmp,"(threads=%d)",threads);
				strcat(tmp_buf,tmp);
			} else threads = 0;
		}
#else
#if 0 // for bug test
		threads = WeekSchedules[CurrScheduleIdx].use_cores;
#endif
		memset(tmp,0,129);
		sprintf(tmp,"(threads=%d)",threads==1?0:threads);
		strcat(tmp_buf,tmp);
#endif
		strcat(tmp_buf,")");
		dgt_sint32	tmp_len = strlen(tmp_buf);
		if (strlen(tmp_buf) > *buf_len) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"not enough buffer length for [%d]",tmp_len)),-1);
		}
		strncpy(buf,tmp_buf,tmp_len);
		*buf_len = tmp_len;
	}
	return 0;
}
