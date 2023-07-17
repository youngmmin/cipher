/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccDropJobStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       drop job
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"
#include "DgcBgmrList.h"

PccDropJobStmt::PccDropJobStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
}
	
PccDropJobStmt::~PccDropJobStmt()
{
}

dgt_sint32 PccDropJobStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	dgt_sint64	job_id;
	memcpy(&job_id,mrows->data(),sizeof(job_id));
	if (job_id == 1) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"job[1] can not be dropped")),-1);
	}
	PccAgentCryptJob* job;
	if ((job=JobPool.getJob(job_id)) == 0) {
		ATHROWnR(DgcError(SPOS,"getJob[%lld] failed",job_id),-1);
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"job[%lld] not found",job_id)),-1);
	}
	job->unlockShare();
//	if (job->collector()->isAlive()) {
//		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"job[%lld] does not finish yet",job_id)),-1);
//	}
	if (JobPool.dropJob(job_id) < 0) {
		ATHROWnR(DgcError(SPOS,"dropJob[%lld] failed",job_id),-1);
	}
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccDropJobStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
        THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
        return 0;
}
