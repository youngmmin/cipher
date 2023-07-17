/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccPcfsMountStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2018. 7. 17
 *   Description        :       mount or unmount PCFS
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

PccPcfsMountStmt::PccPcfsMountStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool),CurrFs(0)
{
	SelectListDef = new DgcClass("select_list", 1);
	SelectListDef->addAttr(DGC_SCHR, 300, "rtn_msg");
}

PccPcfsMountStmt::~PccPcfsMountStmt()
{
}

dgt_sint32 PccPcfsMountStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
        pcfst_mount_rqst*	mount_rqst = (pcfst_mount_rqst*)mrows->data();
	PccPcfsConfig		pcfs_config;
	if (pcfs_config.parse() < 0) {
		ATHROWnR(DgcError(SPOS,"parse failed"),-1);
	}
	if (mount_rqst->pcfs_id >= pcfs_config.numFs()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"invalid file system id[%d]",mount_rqst->pcfs_id)),-1);
	}
	if (pcfs_config.mount(mount_rqst->pcfs_id,mount_rqst->mount_type) < 0) {
		ATHROWnR(DgcError(SPOS,"mount failed"),-1);
	}
	if (mount_rqst->mount_type == pcfs_config.MTT_MOUNT) sprintf(RtnMsg,"%s mounted",pcfs_config.fsAttrsByIdx(mount_rqst->pcfs_id)->mount_dir);
	else sprintf(RtnMsg,"%s unmounted",pcfs_config.fsAttrsByIdx(mount_rqst->pcfs_id)->mount_dir);
	IsExecuted = 1;
	CurrFs = 0;
	return 0;
}

dgt_uint8* PccPcfsMountStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
	if (CurrFs) {
		THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
	}
	CurrFs++;
	return (dgt_uint8*)RtnMsg;
}
