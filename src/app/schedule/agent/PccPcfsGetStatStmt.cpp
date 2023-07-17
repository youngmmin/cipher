/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccPcfsGetStatStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2018. 7. 17
 *   Description        :       get PCFS statistics statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

PccPcfsGetStatStmt::PccPcfsGetStatStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool),CurrFs(0),BindFs(0)
{
	SelectListDef = new DgcClass("select_list", 15);
	SelectListDef->addAttr(DGC_UB2, 0, "pcfs_id");
	SelectListDef->addAttr(DGC_SB8, 0, "encrypt_files");
	SelectListDef->addAttr(DGC_SB8, 0, "decrypt_files");
	SelectListDef->addAttr(DGC_SB8, 0, "pass_files");
	SelectListDef->addAttr(DGC_SB8, 0, "encrypt_calls");
	SelectListDef->addAttr(DGC_SB8, 0, "decrypt_calls");
	SelectListDef->addAttr(DGC_SB8, 0, "pass_read_calls");
	SelectListDef->addAttr(DGC_SB8, 0, "pass_write_calls");
	SelectListDef->addAttr(DGC_SB8, 0, "encrypt_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "decrypt_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "pass_read_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "pass_write_bytes");
	SelectListDef->addAttr(DGC_SB8, 0, "all_calls");
	SelectListDef->addAttr(DGC_SB8, 0, "start_time");
	SelectListDef->addAttr(DGC_SB8, 0, "pid");
}

PccPcfsGetStatStmt::~PccPcfsGetStatStmt()
{
}

dgt_sint32 PccPcfsGetStatStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
        BindFs = *(dgt_uint16*)mrows->data();
	if (BindFs >= PccPcfsStat::MAX_FS) {
		PccPcfsConfig	pcfs_config;
		pcfs_config.parse();
		delete EXCEPTnC;
		if ((BindFs=pcfs_config.numFs()) == 0) CurrFs++;
		else BindFs--;
	} else {
		CurrFs = BindFs;
	}
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccPcfsGetStatStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
	if (CurrFs > BindFs) {
		THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
	}
	PccPcfsStat	pcfs_stat(CurrFs);
	pcfs_stat.getStat();
	memcpy(&FsStat,pcfs_stat.statPtr(),sizeof(FsStat));
	CurrFs++;
	return (dgt_uint8*)&FsStat;
}
