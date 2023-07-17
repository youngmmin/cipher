/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetDetectInfoStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"
#include "PccFileCryptor.h"

PccGetDetectInfoStmt::PccGetDetectInfoStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool)
{
	SelectListDef = new DgcClass("select_list", 5);
	SelectListDef->addAttr(DGC_SB8, 0, "START_OFFSET");
	SelectListDef->addAttr(DGC_SB8, 0, "END_OFFSET");
	SelectListDef->addAttr(DGC_SB4, 0, "DATA_SEQ");
	SelectListDef->addAttr(DGC_SCHR, 1024, "EXPR");
	SelectListDef->addAttr(DGC_SCHR, 1024, "DATA");

        DetectList = new DgcMemRows(SelectListDef);
	DetectList->reset();
}
	
PccGetDetectInfoStmt::~PccGetDetectInfoStmt()
{
	if(DetectList) delete DetectList;
}

dgt_sint32 PccGetDetectInfoStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pcct_detect_info_in*	param_in = (pcct_detect_info_in*)mrows->data();
#ifndef WIN32
	DgcFileStream Stream(param_in->file_name,O_RDONLY);
#else
	DgcFileStream Stream(param_in->file_name,O_RDONLY|_O_BINARY);
#endif
	if (EXCEPT) THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"File[%s] open failed",param_in->file_name)),-1);

        PccFileCryptor detector;
	detector.setMaxDetection(0);

	dgt_sint32 rtn = 0;
	if ((rtn = detector.compileParamList(param_in->parameter)) < 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"detect failed:%d:%s",rtn, detector.errString())),-1);
	}
	if ((rtn = detector.detect(param_in->parameter, param_in->file_name)) < 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"detect failed:%d:%s",rtn, detector.errString())),-1);
	}
	DgcMemRows* rtn_rows = detector.detectData();
	rtn_rows->rewind();

	dgt_schar buf[1024] = {0};
	dgt_sint32 file_indicator = 0;
	dgt_sint32 nbytes = 0;
	dgt_sint32 remain = 0;
	dgt_sint32 seq = 0;

	dgt_sint64 curr_offset = 0;
	pc_type_detect_file_data_in* brow = 0;
	while (rtn_rows->next()) {
		brow = (pc_type_detect_file_data_in*)rtn_rows->data();

		if (curr_offset > brow->end_offset) continue;

		// save the text
		remain = brow->start_offset - curr_offset;
		seq = 0;
		while(remain > 0) {
			memset(buf,0,sizeof(buf));
			file_indicator = Stream.seek(curr_offset,SEEK_SET);
			if (file_indicator != curr_offset) {
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"seek failed[%d]", file_indicator)),0);
			}
			if ((nbytes=Stream.recvData((dgt_uint8*)buf, remain>1024?1024:remain)) < 0) {
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"recvData failed : DataLen[%d], ReadLen[%d]", remain, nbytes)),0);
			}
			DetectList->add();
			DetectList->next();
			pcct_detect_info_out* info_out = (pcct_detect_info_out*)DetectList->data();
			info_out->start_offset = curr_offset;
			info_out->end_offset = curr_offset + nbytes -1;
			info_out->data_seq = seq++;
			memcpy(info_out->data, buf, nbytes);
			curr_offset += nbytes;
			remain -= nbytes;
		}

		// save the pttn
		remain = brow->end_offset - curr_offset;
		seq = 0;
		while(remain > 0) {
			memset(buf,0,sizeof(buf));
			file_indicator = Stream.seek(curr_offset,SEEK_SET);
			if (file_indicator != curr_offset) {
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"seek failed[%d]", file_indicator)),0);
			}
			if ((nbytes=Stream.recvData((dgt_uint8*)buf, remain>1024?1024:remain)) < 0) {
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"recvData failed : DataLen[%d], ReadLen[%d]", remain, nbytes)),0);
			}
			DetectList->add();
			DetectList->next();
			pcct_detect_info_out* info_out = (pcct_detect_info_out*)DetectList->data();
			info_out->start_offset = curr_offset;
			info_out->end_offset = curr_offset + nbytes -1;
			memcpy(info_out->expr, brow->expr, strlen(brow->expr));
			info_out->data_seq = seq++;
			memcpy(info_out->data, buf, nbytes);
			curr_offset += nbytes;
			remain -= nbytes;
		}
	}

	DetectList->rewind();
	IsExecuted = 1;
	return 0;
}

dgt_uint8* PccGetDetectInfoStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (DetectList->next()) return (dgt_uint8*)DetectList->data();
	return 0;
}
