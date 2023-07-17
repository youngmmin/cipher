/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetStreamStatStmt
 *   Implementor        :       shson
 *   Create Date        :       2019. 07.05 
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"

PccGetStreamStatStmt::PccGetStreamStatStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef=new DgcClass("select_list",12);
	SelectListDef->addAttr(DGC_SB8,0,"file_id");
	SelectListDef->addAttr(DGC_SB8,0,"dir_id");
	SelectListDef->addAttr(DGC_SB8,0,"zone_id");
	SelectListDef->addAttr(DGC_SB8,0,"src_file_size");
	SelectListDef->addAttr(DGC_SB8,0,"dst_file_size");
	SelectListDef->addAttr(DGC_UB4,0,"lm_time");
	SelectListDef->addAttr(DGC_SCHR,2049,"src_file_name");
	SelectListDef->addAttr(DGC_SCHR,2049,"dst_file_name");
	SelectListDef->addAttr(DGC_SB4,0,"error_code");
	SelectListDef->addAttr(DGC_SCHR,1025,"error_msg");
	SelectListDef->addAttr(DGC_SB8,0,"job_id");
	SelectListDef->addAttr(DGC_SB4,0,"total_count");

	StreamFileList = new DgcMemRows(12);
	StreamFileList->addAttr(DGC_SB8,0,"file_id");
	StreamFileList->addAttr(DGC_SB8,0,"dir_id");
	StreamFileList->addAttr(DGC_SB8,0,"zone_id");
	StreamFileList->addAttr(DGC_SB8,0,"src_file_size");
	StreamFileList->addAttr(DGC_SB8,0,"dst_file_size");
	StreamFileList->addAttr(DGC_UB4,0,"lm_time");
	StreamFileList->addAttr(DGC_SCHR,2049,"src_file_name");
	StreamFileList->addAttr(DGC_SCHR,2049,"dst_file_name");
	StreamFileList->addAttr(DGC_SB4,0,"error_code");
	StreamFileList->addAttr(DGC_SCHR,1025,"error_msg");
	StreamFileList->addAttr(DGC_SB8,0,"job_id");
	StreamFileList->addAttr(DGC_SB4,0,"total_count");
}
	
PccGetStreamStatStmt::~PccGetStreamStatStmt()
{
	if (StreamFileList) {
		delete StreamFileList;
		StreamFileList = 0;
	}
}

dgt_sint32 PccGetStreamStatStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pcct_get_stream_stat_in*	param_in = (pcct_get_stream_stat_in*)mrows->data();
	
	PccAgentCryptJob* job = 0;
	if ((job=JobPool.getJob(param_in->job_id)) == 0) {
		ATHROWnR(DgcError(SPOS,"getJob[%lld] failed.",param_in->job_id),-1);
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"not found job [%lld].",param_in->job_id)),-1);
	}

	PccStreamFileStatistic* StreamFileStatistic = job->streamFileStatistic();
	StreamFileList->reset();
	StreamFileStatistic->statisticCopy(StreamFileList, param_in->file_type);
	job->unlockShare();
	StreamFileList->rewind();

	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccGetStreamStatStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (StreamFileList->next()) return (dgt_uint8*)StreamFileList->data();
	else return 0;
	return 0;
}
