/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PetraCipherMigVerifyJob
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 09. 03
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PetraCipherMigVerifyJob.h"

PetraCipherMigVerifyJob::PetraCipherMigVerifyJob(
	dgt_sint64 job_id,
	dgt_sint64 enc_tab_id)
	: JobID(job_id),
	  EncTabID(enc_tab_id)
{
}


PetraCipherMigVerifyJob::~PetraCipherMigVerifyJob()
{
}


#include "DgcDbProcess.h"

dgt_sint32 PetraCipherMigVerifyJob::initJobRows() throw(DgcExcept)
{
	//
	// get the job table segment
	//
	JobSeg=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_VERIFY_JOB");
	if (JobSeg == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_VERIFY_JOB] failed"),-1);
		THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"table[PCT_VERIFY_JOB] not found")),-1);
	}
	AllJobRows.setFsegment(JobSeg);
	JobRows.setFsegment(JobSeg);
	JobSeg->unlockShare();
	//
	// create a job row or search the job row
	//
	if (JobID) {
		//
		// registered job from Cipher Manager
		//
		AllJobRows.rewind();
		while(AllJobRows.next() && (JobRowPtr=(pct_type_verify_job*)AllJobRows.data())) {
			if (JobRowPtr->verify_job_id == JobID) {
				JobRows.add(AllJobRows.bno(), AllJobRows.rno(), AllJobRows.data());
				break;
			}
		}
		if (!JobRowPtr) {
			THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,new DgcError(SPOS,"Job[%lld] not found",JobID)),-1);
		}
		if(JobRowPtr->curr_status > 0 && JobRowPtr->curr_status < PCB_JOB_STATUS_PENDING) {
			THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"Job[%lld] is already running.",JobID)),-1);
		}
	} else {
		//
		// unregisted job from command line
		//
		DgcSequence*	pct_seq;
		if ((pct_seq=DgcDbProcess::db().pdb()->seqMgr()->getSequence(DGC_DG_OWNER,"PCT_SEQ")) == 0) {
			ATHROWnR(DgcError(SPOS,"getSequence failed"),-1);
		}
		if ((JobID=pct_seq->nextVal(DgcDbProcess::sess())) == 0) {
			DgcExcept*	e=EXCEPTnC;
			delete pct_seq;
			RTHROWnR(e,DgcError(SPOS,"nextVal failed"),-1);
		}
		delete pct_seq;
		JobRows.reset();
		if (JobSeg->pinInsert(DgcDbProcess::sess(), JobRows, 1)) {
			ATHROWnR(DgcError(SPOS,"pinInsert[PCT_VERIFY_JOB] for Job[%lld] failed", JobID),-1);
		}
		JobRows.rewind();
		JobRows.next();
		JobRowPtr=(pct_type_verify_job*)JobRows.data();
		JobRowPtr->verify_job_id=JobID;
		JobRowPtr->enc_tab_id=EncTabID;
		JobRows.rewind();
		if (JobSeg->insertCommit(DgcDbProcess::sess(), JobRows)) {
			DgcExcept*      e=EXCEPTnC;
			JobRows.rewind();
			JobSeg->pinRollback(JobRows);
			RTHROWnR(e,DgcError(SPOS,"insertCommit[PCT_VERIFY_JOB] for Job[%lld] failed",JobID),-1);
		}
		JobRows.rewind();
	}
	return 0;
}


dgt_void PetraCipherMigVerifyJob::setPending(DgcExcept* e)
{
	DgcError*       err=e->getErr();
	while(err->next()) err=err->next();
	strncpy(JobRowPtr->curr_err_msg, err->message(), 128);
	JobRowPtr->curr_status=PCB_JOB_STATUS_PENDING;
}


dgt_sint32 PetraCipherMigVerifyJob::getEncTabRow() throw(DgcExcept)
{
	//
        // get the encrypt table row
        //
	dgt_schar       sql_text[128];
	sprintf(sql_text,"select * from pct_enc_table where enc_tab_id=%lld", JobRowPtr->enc_tab_id);
	DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(),sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	dgt_uint8*	rtn_row;
	if (!(rtn_row=sql_stmt->fetch())) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch failed."),-1);
	}
	memcpy(&EncTabRow, rtn_row, sizeof(pct_type_enc_table));
	delete sql_stmt;
	EncTabID=JobRowPtr->enc_tab_id;
	return 0;
}

dgt_void PetraCipherMigVerifyJob::commitJobRows()
{
	JobRows.rewind();
	if (JobSeg->pinUpdate(JobRows)) {
		DgcExcept*      e=EXCEPTnC;
		PLOG.tprintf(0,*e,"pinUpdate[PCT_VERIFY_JOB:%lld] failed:\n",JobRowPtr->verify_job_id);
		delete e;
	}
	JobRows.rewind();
	if (JobSeg->updateCommit(DgcDbProcess::sess(), JobRows) != 0) {
		DgcExcept*      e=EXCEPTnC;
		PLOG.tprintf(0,*e,"updateCommit[PCT_VERIFY_JOB:%lld] failed:\n",JobRowPtr->verify_job_id);
		delete e;
	}
}

dgt_void PetraCipherMigVerifyJob::in() throw(DgcExcept)
{
	//
	// initialize job rows
	//
	if (initJobRows()) ATHROW(DgcError(SPOS,"initJobRows failed"));
	JobRowPtr->process_id=getpid();

	//
	// get the encrypt table row
	//
	if (getEncTabRow()) {
		DgcExcept*	e=EXCEPTnC;
		setPending(e);
		RTHROW(e,DgcError(SPOS,"getEncTabRow failed"));
	}
	if (JobRowPtr->start_time == 0 || 
	    (EncTabRow.curr_enc_step == 0 && EncTabRow.curr_enc_stmt == 0)) {
		JobRowPtr->start_time=dgtime(&JobRowPtr->start_time);
	}
	//
	// delete old result.
	//
        dgt_schar       sql_text[512];
	memset(sql_text,0,512);
	sprintf(sql_text,"delete PCT_VERIFY_JOB_ROW_CNT_RESULT where VERIFY_JOB_ID=%lld",JobID);
        DgcSqlStmt*     sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(),sql_text,strlen(sql_text));
       	if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
	memset(sql_text,0,512);
        sprintf(sql_text,"delete PCT_VERIFY_JOB_DATA_RESULT where VERIFY_JOB_ID=%lld",JobID);
        sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(),sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
}


#include "PccScriptBuilderFactory.h"

dgt_sint32 PetraCipherMigVerifyJob::run() throw(DgcExcept)
{
	if (EncTabRow.curr_enc_step == 2 && EncTabRow.curr_enc_stmt == 0) {
		
	} else {
		//
		// nothing to be done
		//
		JobRowPtr->curr_status=PCB_JOB_STATUS_PENDING;
		memset(JobRowPtr->curr_err_msg,0,129);
		sprintf(JobRowPtr->curr_err_msg,"not current step_no[2]"); 
		return 1;
	}
	//
	// get a script builder for target DBMS
	//
	PccScriptBuilder*       script_builder=0;
	script_builder=PccScriptBuilderFactory::getScriptBuilder(
					DgcDbProcess::dbPtr(),
					DgcDbProcess::sess(),
					JobRowPtr->enc_tab_id,
					PccScriptBuilderFactory::PCC_ID_TYPE_TABLE);
	DgcExcept*      e=0;
	if (!script_builder) {
		e=EXCEPTnC;
		setPending(e);
		RTHROWnR(e,DgcError(SPOS,"getScriptBuilder failed."),-1);
	} else {
		memset(JobRowPtr->curr_err_msg,0,129);
	}
		
	dgt_sint32      rtn=0;
	if ((rtn = script_builder->runVerifyMig(JobRowPtr->enc_tab_id, JobRowPtr)) < 0) {
		delete script_builder;
		e=EXCEPTnC;
		if (e) {
			setPending(e);
			RTHROWnR(e,DgcError(SPOS,"executeScript failed."),-1);
		}
	}
	JobRowPtr->curr_status = PCB_JOB_STATUS_DONE;

	return 1;
}


dgt_void PetraCipherMigVerifyJob::out() throw(DgcExcept)
{

	JobRowPtr->end_time=dgtime(&JobRowPtr->end_time);
	commitJobRows();
}


static dgt_void printUsage()
{
    fputs("\nusage:\n\n", stdout);
    fputs("pcb_mig_verify keyword=value ...\n\n", stdout);
    fputs("keywords:\n", stdout);
    fputs("  verify_job_id         scheduled job ID\n", stdout);
    fputs("\n", stdout);
    fflush(stdout);
}


#include "DgcCmdLine.h"


int main(int argc,char** argv)
{
	if (argc == 1) {
		printUsage();
		exit(1);
	}

	dgt_schar *pnm = nul;
        if (strchr(argv[0], '/')) pnm = (dgt_schar *)dg_basename((char *)argv[0]);
        else if ((pnm=strchr(argv[0], ' '))) pnm += 1;
        else pnm = argv[0];

	//
	// parse comman line
	//
	DgcCmdLine	cmd_line(argv);
	dgt_sint64	job_id=0;
	dgt_sint64	enc_tab_id=0;
	const dgt_schar* val=0;
	//
	// job id
	//
	if ((val=cmd_line.getValue("job_id"))) {
		job_id=dg_strtoll(val,0,10);
	} else {
		exit(1);
	}
	//
        // *********************************************************
        // process initialization: being a demon and a log open.
        // *********************************************************
        //
	dgt_schar*	svc_name=getenv("SOHA_SVC");
        if (DgcDbProcess::initialize(DGC_WT_DG_PETRA,pnm,1,1) != 0) {
                DgcExcept*      e=EXCEPTnC;
                dg_print("process initialization failed due to [%s].\n",e->getErr()->message());
                DgcWorker::PLOG.tprintf(0,*e,"process initialize[%s] failed due to the below:\n",svc_name);
                delete e;
                exit(1);
        }
        dg_signal(SIGCHLD,SIG_IGN);

        //
        //  attach database
        //
        if (DgcDbProcess::openDatabase(svc_name,DGC_LD_ATTACH) != 0) {
                DgcExcept*      e=EXCEPTnC;
                dg_print("database open failed due to [%s].\n",e->getErr()->message());
                DgcWorker::PLOG.tprintf(0,*e,"openDatabase[%s] failed due to the below:\n",svc_name);
                delete e;
                exit(1);
        }
        DgcDbProcess::sess()->setDatabaseUser(DGC_SYS_OWNER);
        dg_strcpy(DgcDbProcess::pa().owner,DGC_SYS_OWNER);

	//
	// run a CipherMigVerifyJob in root thread
	//
	PetraCipherMigVerifyJob pcb(
		job_id,		// job id
		enc_tab_id	// encrypt table id
	);
	pcb.wa()->ThreadID=pthread_self();
	DgcWorker::entry((dgt_void*)&pcb);

	DgcDbProcess::monitorProcess();

	return 0;
}
