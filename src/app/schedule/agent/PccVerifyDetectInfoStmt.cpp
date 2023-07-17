/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccVerifyDetectInfoStmt
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 07. 12
 *   Description        :       verify detection file
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

const dgt_sint32 PCC_VERIFY_DETECT_CODE_SUCCESS = 0;
const dgt_sint32 PCC_VERIFY_DETECT_CODE_FILE_NOT_FOUND = -1;
const dgt_sint32 PCC_VERIFY_DETECT_CODE_DIFFERENT_FILE_SIZE = -2;
const dgt_sint32 PCC_VERIFY_DETECT_CODE_DIFFERENT_FILE_MTIME = -3;

PccVerifyDetectInfoStmt::PccVerifyDetectInfoStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef = new DgcClass("select_list", 2);
	SelectListDef->addAttr(DGC_SB4, 0, "rtn_code");
	SelectListDef->addAttr(DGC_SCHR, 1025, "error_message");

	memset(&VerifyDetectInfo,0,sizeof(pcct_verify_detect_info_out));
}
	
PccVerifyDetectInfoStmt::~PccVerifyDetectInfoStmt()
{
}

dgt_sint32 PccVerifyDetectInfoStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pcct_verify_detect_info_in*	param_in = (pcct_verify_detect_info_in*)mrows->data();

	struct stat	fstat;
	if (stat((dgt_schar*)param_in->file_name,&fstat) < 0) {
		VerifyDetectInfo.rtn_code = PCC_VERIFY_DETECT_CODE_FILE_NOT_FOUND;
		sprintf(VerifyDetectInfo.error_message,"stat[%s] failed[%s]", (dgt_schar*)param_in->file_name, strerror(errno));
		IsExecuted = 1;
		return 0;
	}
	
	if (fstat.st_size != param_in->file_size) {
		VerifyDetectInfo.rtn_code = PCC_VERIFY_DETECT_CODE_DIFFERENT_FILE_SIZE;
		sprintf(VerifyDetectInfo.error_message,"file[%s] has different file size", (dgt_schar*)param_in->file_name);
		IsExecuted = 1;
		return 0;
	}

	if (fstat.st_mtime != param_in->file_mtime) {
		VerifyDetectInfo.rtn_code = PCC_VERIFY_DETECT_CODE_DIFFERENT_FILE_MTIME;
		sprintf(VerifyDetectInfo.error_message,"file[%s] has different modify time", (dgt_schar*)param_in->file_name);
		IsExecuted = 1;
		return 0;
	}

	VerifyDetectInfo.rtn_code = PCC_VERIFY_DETECT_CODE_SUCCESS;
	sprintf(VerifyDetectInfo.error_message,"success");

	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccVerifyDetectInfoStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	return (dgt_uint8*)&VerifyDetectInfo;
}
