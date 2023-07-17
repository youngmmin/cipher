/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetDetectStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccGetDetectStat.h"

PfccGetDetectStat::PfccGetDetectStat(const dgt_schar* name)
	: DgcExtProcedure(name), DetectStat(DETECT_NODE_HASH_SIZE)
{
}


PfccGetDetectStat::~PfccGetDetectStat()
{
	PccHashNode* hnp = 0;
	DetectStat.rewind();
	while((hnp=DetectStat.nextNode())) {
		delete (pfcc_detect_stat*)hnp->value();
		hnp->setValue(0);
	}
}


DgcExtProcedure* PfccGetDetectStat::clone()
{
	return new PfccGetDetectStat(procName());
}


dgt_sint32 PfccGetDetectStat::initialize() throw(DgcExcept)
{
	return 0; 
}

pfcc_detect_stat* PfccGetDetectStat::getDetectStat(dgt_schar* path)
{
	dgt_sint64 key_id = 0;
	key_id = DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)path, strlen(path));

	pfcc_detect_stat* node = 0;
	PccHashNode* hnp = DetectStat.findNode(key_id);
	if (hnp == 0) {
		node = new pfcc_detect_stat();
		memset(node, 0, sizeof(pfcc_detect_stat));
		memcpy(node->path, path, strlen(path));
		DetectStat.addNode(key_id, node);        
	} else {
		node = (pfcc_detect_stat*)hnp->value();
	}
	return node? node : 0;
}

dgt_sint32 PfccGetDetectStat::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}

	dgt_sint64 job_id = *(dgt_sint64*)BindRows->data();
	if (!job_id) THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS,"no input row")),-1);

	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_schar	stext[256] = {0};
	dgt_void*	rtn_row = 0;

	//
	// 1. get pct_file_detect_hist 
	//
	DgcMemRows DetectList(3);
	DetectList.addAttr(DGC_SB8,0,"FILE_ID");
	DetectList.addAttr(DGC_SB8,0,"PTTN_NUM");
	DetectList.addAttr(DGC_SCHR,2048,"PATH");
	DetectList.reset();
	
	memset(stext, 0, sizeof(stext));
	sprintf(stext, "select file_id, pttn_num, file_name, parameter from pct_file_detect_hist where pttn_num != 0 and job_id = %lld", job_id);
	if (sql_handle.execute(stext) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	while (!sql_handle.fetch(rtn_row) && rtn_row) {
		DetectList.add();	
		DetectList.next();
		memcpy(DetectList.data(), rtn_row, DetectList.rowFormat()->length());
	}
	DetectList.rewind();

	//
	// 3. make detect stat
	//
	while (DetectList.next()) {
		pfcc_detect_stat* stat = 0;
		dgt_sint64 file_id = *(dgt_sint64*)DetectList.getColPtr(1);
		dgt_sint64 pttn_num = *(dgt_sint64*)DetectList.getColPtr(2);
		dgt_schar path[2048] = {0};
		sprintf(path,"%s",(dgt_schar*)DetectList.getColPtr(3));
		
		// file 		
		stat = getDetectStat(path);
		stat->file_id = file_id;
		stat->pttn_num = pttn_num;
		stat->pttn_files = pttn_num ? 1 : 0;
		memcpy(stat->path, path, strlen(path));

		// directory 
		dgt_schar* pos = 0;
		while((pos = strrchr(path, '/')) != NULL) {
			*pos = '\0';
			if (strlen(path) == 0) break;
			stat = getDetectStat(path);
			stat->pttn_num += pttn_num;
			stat->pttn_files += pttn_num ? 1 : 0;
		}
	}

	PccHashNode* hnp = 0;
	DetectStat.rewind();
	while((hnp=DetectStat.nextNode())) {
		ReturnRows->add();
		ReturnRows->next();
		memcpy(ReturnRows->data(), hnp->value(), sizeof(pfcc_detect_stat));
	}
	ReturnRows->rewind();
	return 0;
}

dgt_sint32 PfccGetDetectStat::fetch() throw(DgcExcept)
{
	return 0;
}


