/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PetraCipherJob
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PetraCipherJob.h"

PetraCipherJob::PetraCipherJob(dgt_sint64 job_id, dgt_sint64 enc_tab_id,
                               dgt_sint16 target_step, dgt_uint32 array_size,
                               dgt_uint16 num_chunks,
                               dgt_uint16 parallel_degree,
                               const dgt_schar* where_clause,
                               dgt_uint16 print_interval)
    : JobID(job_id),
      EncTabID(enc_tab_id),
      TargetStep(target_step),
      ArraySize(array_size),
      NumChunks(num_chunks),
      ParallelDegree(parallel_degree),
      WhereClause(where_clause),
      PrintInterval(print_interval),
      SleepCount(0),
      CipherTable(0),
      ChunkPool(0),
      Collector(0),
      NumUpdaters(0),
      NumStartedUpdaters(0) {
    if (NumChunks == 0) NumChunks = PCB_MAX_CHUNKS;
    if (ParallelDegree == 0)
        ParallelDegree = PCB_PARALLEL_DEGREE;
    else if (ParallelDegree > PCB_MAX_UPDATERS)
        ParallelDegree = PCB_MAX_UPDATERS;
    for (dgt_uint16 i = 0; i < PCB_MAX_UPDATERS; i++) Updaters[i] = 0;
    KeyStash = 0;
}

PetraCipherJob::~PetraCipherJob() {
    delete ChunkPool;
    delete CipherTable;
}

#include "DgcDbProcess.h"
#include "PcbStmtFactory.h"
#include "PciKeyMgrIf.h"

dgt_sint32 PetraCipherJob::initJobRows() throw(DgcExcept) {
    //
    // get the job & worker table segment
    //
    JobSeg = (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
        "PCT_JOB");
    if (JobSeg == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_JOB] failed"), -1);
        THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,
                            new DgcError(SPOS, "table[PCT_JOB] not found")),
                -1);
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
        while (AllJobRows.next() &&
               (JobRowPtr = (pct_type_job*)AllJobRows.data())) {
            if (JobRowPtr->job_id == JobID) {
                JobRows.add(AllJobRows.bno(), AllJobRows.rno(),
                            AllJobRows.data());
                break;
            }
        }
        if (!JobRowPtr) {
            THROWnR(
                DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,
                            new DgcError(SPOS, "Job[%lld] not found", JobID)),
                -1);
        }
        if (JobRowPtr->curr_status > 0 &&
            JobRowPtr->curr_status < PCB_JOB_STATUS_PENDING) {
            THROWnR(
                DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "Job[%lld] is already running.", JobID)),
                -1);
        }
#if 0
		if (ArraySize) JobRowPtr->array_size=ArraySize;
		if (NumChunks) JobRowPtr->num_chunks=NumChunks;
		if (ParallelDegree) JobRowPtr->parallel_degree=ParallelDegree;
		if (WhereClause) strncpy(JobRowPtr->where_clause, WhereClause, 128);
#endif
        // modified by mwpark
        if (JobRowPtr->array_size) ArraySize = JobRowPtr->array_size;
        if (JobRowPtr->num_chunks) NumChunks = JobRowPtr->num_chunks;
        if (JobRowPtr->parallel_degree)
            ParallelDegree = JobRowPtr->parallel_degree;
        if (JobRowPtr->where_clause) WhereClause = JobRowPtr->where_clause;
    } else {
        //
        // unregisted job from command line
        //
        DgcSequence* pct_seq;
        if ((pct_seq = DgcDbProcess::db().pdb()->seqMgr()->getSequence(
                 DGC_DG_OWNER, "PCT_SEQ")) == 0) {
            ATHROWnR(DgcError(SPOS, "getSequence failed"), -1);
        }
        if ((JobID = pct_seq->nextVal(DgcDbProcess::sess())) == 0) {
            DgcExcept* e = EXCEPTnC;
            delete pct_seq;
            RTHROWnR(e, DgcError(SPOS, "nextVal failed"), -1);
        }
        delete pct_seq;
        JobRows.reset();
        if (JobSeg->pinInsert(DgcDbProcess::sess(), JobRows, 1)) {
            ATHROWnR(DgcError(SPOS, "pinInsert[PCT_JOB] for Job[%lld] failed",
                              JobID),
                     -1);
        }
        JobRows.rewind();
        JobRows.next();
        JobRowPtr = (pct_type_job*)JobRows.data();
        JobRowPtr->job_id = JobID;
        JobRowPtr->enc_tab_id = EncTabID;
        JobRowPtr->target_step = TargetStep;
        JobRowPtr->array_size = ArraySize;
        JobRowPtr->num_chunks = NumChunks;
        JobRowPtr->parallel_degree = ParallelDegree;
        if (WhereClause) strncpy(JobRowPtr->where_clause, WhereClause, 128);
        JobRows.rewind();
        if (JobSeg->insertCommit(DgcDbProcess::sess(), JobRows)) {
            DgcExcept* e = EXCEPTnC;
            JobRows.rewind();
            JobSeg->pinRollback(JobRows);
            RTHROWnR(
                e,
                DgcError(SPOS, "insertCommit[PCT_JOB] for Job[%lld] failed",
                         JobID),
                -1);
        }
        JobRows.rewind();
    }
    return 0;
}

dgt_void PetraCipherJob::setPending(DgcExcept* e) {
    DgcError* err = e->getErr();
    while (err->next()) err = err->next();
    strncpy(JobRowPtr->curr_err_msg, err->message(), 128);
    JobRowPtr->curr_status = PCB_JOB_STATUS_PENDING;
}

dgt_sint32 PetraCipherJob::getEncTabRow() throw(DgcExcept) {
    //
    // get the encrypt table row
    //
    dgt_schar sql_text[128];
    sprintf(sql_text, "select * from pct_enc_table where enc_tab_id=%lld",
            JobRowPtr->enc_tab_id);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_uint8* rtn_row;
    if (!(rtn_row = sql_stmt->fetch())) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed."), -1);
    }
    memcpy(&EncTabRow, rtn_row, sizeof(pct_type_enc_table));
    delete sql_stmt;
    return 0;
}

dgt_sint32 PetraCipherJob::initResource(dgt_uint8 decrypt_flag) throw(
    DgcExcept) {
    //
    // set key stash, preparing for getting a key
    //
    dgt_sint32 rtn = 0;
    DgcExcept* e = 0;

    if (!KeyStash) {
        KeyStash =
            DgcDbProcess::db().pdb()->segMgr()->getStream("_PCS_KEY_STASH");
        if (!KeyStash) {
            if ((e = EXCEPTnC))
                e->addErr(new DgcError(SPOS, "getStream failed"));
            else
                e = new DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "_PCS_KEY_STASH not found"));
        } else if ((rtn = PCI_setKeyStash(
                        (PCT_KEY_STASH*)((dgt_uint8*)KeyStash +
                                         KeyStash->totalSize()))) < 0) {
            e = new DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg()));
        }
        if (e) RTHROWnR(e, DgcError(SPOS, "building a key stash failed"), -1);
    }
    //
    // initialize CipherTable
    //
    CipherTable = new PcbCipherTable(JobRowPtr->enc_tab_id, decrypt_flag);
    if ((rtn = CipherTable->initialize()) < 0) {
        ATHROWnR(DgcError(SPOS, "CipherTable.initialize failed"), -1);
    }

    //
    // initialize select statement
    //
    PcbSelectStmt* select_stmt =
        PcbStmtFactory::getSelectStmt(CipherTable, JobRowPtr->array_size);
    if (!select_stmt) ATHROWnR(DgcError(SPOS, "getSelectStmt failed"), -1);
    if (select_stmt->initialize(JobRowPtr->where_clause)) {
        DgcExcept* e = EXCEPTnC;
        delete select_stmt;
        RTHROWnR(e, DgcError(SPOS, "SelectStmt.initialize failed"), -1);
    }
    JobRowPtr->total_rows = select_stmt->totalRows();

    //
    // initialize chunk pool
    //
    ChunkPool = new PcbDataChunkPool(JobRowPtr->num_chunks);
    ChunkPool->initialize(CipherTable, select_stmt);

    //
    // create worker rows for a collector and updaters
    //
    JobWkrSeg = (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
        "PCT_WORKER");
    if (JobWkrSeg == 0) {
        ATHROWnR(DgcError(SPOS, "getTable[PCT_WORKER] failed"), -1);
        THROWnR(DgcDgExcept(DGC_EC_DG_TAB_NOT_FOUND,
                            new DgcError(SPOS, "table[PCT_WORKER] not found")),
                -1);
    }
    JobWkrRows.setFsegment(JobWkrSeg);
    JobWkrSeg->unlockShare();
    JobWkrRows.reset();
    if (JobWkrSeg->pinInsert(DgcDbProcess::sess(), JobWkrRows,
                             JobRowPtr->parallel_degree + 1)) {
        ATHROWnR(DgcError(SPOS, "pinInsert[PCT_WORKER] for Job[%lld] failed",
                          JobRowPtr->job_id),
                 -1);
    }
    JobWkrRows.rewind();
    pct_type_worker* job_wkr_ptr;
    while (JobWkrRows.next() &&
           (job_wkr_ptr = (pct_type_worker*)JobWkrRows.data())) {
        job_wkr_ptr->job_id = JobRowPtr->job_id;
        job_wkr_ptr->exe_count = JobRowPtr->exe_count;
        job_wkr_ptr->process_id = JobRowPtr->process_id;
    }
    JobWkrRows.rewind();
    if (JobWkrSeg->insertCommit(DgcDbProcess::sess(), JobWkrRows)) {
        DgcExcept* e = EXCEPTnC;
        JobWkrRows.rewind();
        JobWkrSeg->pinRollback(JobWkrRows);
        RTHROWnR(e,
                 DgcError(SPOS, "insertCommit[PCT_WORKER] for Job[%lld] failed",
                          JobRowPtr->job_id),
                 -1);
    }
    //
    // create a collector and updaters
    //
    JobWkrRows.rewind();
    JobWkrRows.next();
    if (Collector) delete Collector;
    Collector = new PcbCollector(select_stmt, ChunkPool,
                                 (pct_type_worker*)JobWkrRows.data());

    if (NumUpdaters > 0) {
        for (dgt_sint32 i = 0; i < NumUpdaters; i++) {
            if (Updaters[i]) delete Updaters[i];
        }
        NumUpdaters = 0;
    }
    for (dgt_uint16 i = 0; i < JobRowPtr->parallel_degree; i++) {
        //
        // initialize update statement
        //
        PcbUpdateStmt* update_stmt =
            PcbStmtFactory::getUpdateStmt(CipherTable, JobRowPtr->array_size);
        if (!update_stmt) ATHROWnR(DgcError(SPOS, "getSelectStmt failed"), -1);
        if (update_stmt->initialize()) {
            DgcExcept* e = EXCEPTnC;
            delete update_stmt;
            RTHROWnR(e, DgcError(SPOS, "initialize failed"), -1);
        }

        JobWkrRows.next();
        Updaters[NumUpdaters++] = new PcbUpdater(
            update_stmt, ChunkPool, (pct_type_worker*)JobWkrRows.data());
    }
    return 0;
}

dgt_void PetraCipherJob::commitJobRows() {
    JobRows.rewind();
    if (JobSeg->pinUpdate(JobRows)) {
        DgcExcept* e = EXCEPTnC;
        PLOG.tprintf(0, *e, "pinUpdate[PCT_JOB:%lld] failed:\n",
                     JobRowPtr->job_id);
        delete e;
    }
    JobRows.rewind();
    if (JobSeg->updateCommit(DgcDbProcess::sess(), JobRows) != 0) {
        DgcExcept* e = EXCEPTnC;
        PLOG.tprintf(0, *e, "updateCommit[PCT_JOB:%lld] failed:\n",
                     JobRowPtr->job_id);
        delete e;
    }
}

dgt_void PetraCipherJob::commitWorkerRows() {
    JobWkrRows.rewind();
    if (JobWkrSeg->pinUpdate(JobWkrRows)) {
        DgcExcept* e = EXCEPTnC;
        PLOG.tprintf(0, *e, "pinUpdate[PCT_WORKER:%lld] failed:\n",
                     JobRowPtr->job_id);
        delete e;
    }
    JobWkrRows.rewind();
    if (JobWkrSeg->updateCommit(DgcDbProcess::sess(), JobWkrRows) != 0) {
        DgcExcept* e = EXCEPTnC;
        PLOG.tprintf(0, *e, "updateCommit[PCT_WORKER:%lld] failed:\n",
                     JobRowPtr->job_id);
        delete e;
    }
}

dgt_void PetraCipherJob::printJobStatus() {
    printf(
        "JobID[%lld] TableID[%lld] Table[%s] TotalRows[%lld] PID[%u] "
        "Lapse[%u]\n",
        JobRowPtr->job_id, JobRowPtr->enc_tab_id, CipherTable->tableName(),
        JobRowPtr->total_rows, JobRowPtr->process_id,
        JobRowPtr->end_time ? (JobRowPtr->end_time - JobRowPtr->start_time)
                            : SleepCount);
    JobWkrRows.rewind();
    pct_type_worker* worker;
    while (JobWkrRows.next() &&
           (worker = (pct_type_worker*)JobWkrRows.data())) {
        printf(
            "\tTID[%u] Role[%s] Status[%d] Chunks[%u] Rows[%lld] Waits[%u] "
            "Time[%f]\n",
            worker->thread_id, worker->assigned_role, worker->curr_status,
            worker->processed_chunks, worker->processed_rows,
            worker->chunk_waits, worker->working_time / 1000000.0);
    }
}

dgt_sint16 PetraCipherJob::getMaxStmtNo(dgt_sint16 step_no) {
    dgt_sint16 rtn = 0;
    dgt_schar sql_text[128];
    sprintf(sql_text,
            "select max(stmt_no) from pct_script where enc_tab_id=%lld and "
            "step_no=%d",
            JobRowPtr->enc_tab_id, step_no);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        delete EXCEPTnC;
    } else {
        dgt_uint8* rtn_row;
        if (!(rtn_row = sql_stmt->fetch())) {
            delete EXCEPTnC;
        } else
            rtn = *((dgt_sint16*)rtn_row);
    }
    delete sql_stmt;
    return rtn;
}

dgt_sint16 PetraCipherJob::getMinStmtNo(dgt_sint16 step_no) {
    dgt_sint16 rtn = 0;
    dgt_schar sql_text[128];
    sprintf(sql_text,
            "select min(stmt_no) from pct_script where enc_tab_id=%lld and "
            "step_no=%d",
            JobRowPtr->enc_tab_id, step_no);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        delete EXCEPTnC;
    } else {
        dgt_uint8* rtn_row;
        if (!(rtn_row = sql_stmt->fetch())) {
            delete EXCEPTnC;
        } else
            rtn = *((dgt_sint16*)rtn_row);
    }
    delete sql_stmt;
    return rtn;
}

dgt_sint32 PetraCipherJob::doCryptoWork(dgt_uint8 decrypt_flag) throw(
    DgcExcept) {
    //
    // inltialize resources like the key stash, cipher table, statements, worker
    // etc
    //
    if (initResource(decrypt_flag)) {
        ATHROWnR(DgcError(SPOS, "initJobRows failed"), -1);
    }
    //
    // start collector
    //
    if (dgt_sint32 ret = Collector->start()) {
        ATHROWnR(DgcError(SPOS, "PcbCollector.start failed"), -1);
    }
    DgcExcept* e = 0;
    for (NumStartedUpdaters = 0; NumStartedUpdaters < NumUpdaters;
         NumStartedUpdaters++) {
        //
        // start updaters
        //
        if (Updaters[NumStartedUpdaters]->start()) {
            e = EXCEPTnC;
            break;
        }
    }
    if (e) {
        if (NumStartedUpdaters) {
            //
            // more than one updater is alive.
            // no need to stop whole job and just logging the exception.
            //
            PLOG.tprintf(0, *e, "PcbUpdater.start failed:\n");
            delete e;
        } else {
            Collector->stop();
            RTHROWnR(e, DgcError(SPOS, "PcbUpdater.start failed"), -1);
        }
    }
    //
    // monitor job workers
    //
    if (PrintInterval) {
        printf("\nstart report::");
        printJobStatus();
    }
    for (;;) {
        //
        // waiting for all job workers to end their mission
        //
        dgt_uint16 num_alive_jobs = 0;
        if (Collector->isAlive())
            num_alive_jobs++;
        else if (Collector->getWorkerPtr()->curr_status ==
                 PCB_WKR_STATUS_ERROR) {
            for (dgt_uint16 i = 0; i < NumUpdaters; i++) {
                if (Updaters[i]->getWorkerPtr()->curr_status ==
                    PCB_WKR_STATUS_WAITING)
                    Updaters[i]->stop();
            }
        }

        for (dgt_uint16 i = 0; i < NumUpdaters; i++) {
            if (Updaters[i]->isAlive()) num_alive_jobs++;
        }

        if (num_alive_jobs == 0) {
            if (Collector->getWorkerPtr()->curr_status == PCB_WKR_STATUS_DONE) {
                dgt_sint32 ret_updater = 0;
                for (dgt_uint16 i = 0; i < NumUpdaters;
                     i++) {  // if more than half of updaters finished normally,
                             // doCryptoWork is not pending
                    if (Updaters[i]->getWorkerPtr()->curr_status ==
                        PCB_WKR_STATUS_DONE)
                        ret_updater += 1;
                    else
                        ret_updater -= 1;
                }
                if (ret_updater > 0)
                    break;  // all job workers finished
                else {
                    THROWnR(DgcDgExcept(
                                DGC_EC_DG_INVALID_STAT,
                                new DgcError(SPOS,
                                             "The updaters got an exception.")),
                            -1);
                }
            } else {
                THROWnR(
                    DgcDgExcept(
                        DGC_EC_DG_INVALID_STAT,
                        new DgcError(SPOS, "The collector got an exception.")),
                    -1);
            }
        }
        sleep(1);
        ++SleepCount;
        if (PrintInterval && !(SleepCount % PrintInterval)) {
            printf("\n%u seconds lapse report::", SleepCount);
            printJobStatus();
        }
    }
    if (PrintInterval) {
        printf("\nend report::");
        printJobStatus();
    }
    commitWorkerRows();
    return 0;
}

dgt_void PetraCipherJob::logJobExecution(dgt_sint16 step_no, dgt_sint16 stmt_no,
                                         struct timeval* stime,
                                         struct timeval* etime, DgcExcept* e) {
    dgt_sint64 lapse = 0;
    dgt_sint32 err_code = 0;
    const dgt_schar* err_msg = "";
    if (e) {
        DgcError* err = e->getErr();
        while (err->next()) err = err->next();
        err_msg = (dgt_schar*)err->message();
        err_code = e->errCode();
    }
    if (etime->tv_sec == stime->tv_sec)
        lapse = etime->tv_usec - stime->tv_usec;
    else
        lapse = (dgt_sint64)(etime->tv_sec - stime->tv_sec) * 1000000 +
                etime->tv_usec - stime->tv_usec;
    dgt_schar sql_text[512];
    if (err_code == 1091 || err_code == 1347) {
        dgt_uint32 pos = 0;
        dgt_uint32 fixed_len = strlen(err_msg) + 32;
        dgt_schar fixed_err_msg[fixed_len];
        memset(fixed_err_msg, 0, fixed_len);
        for (dgt_uint32 i = 0; i < fixed_len; ++i) {
            if (*(err_msg + i) == '\'') fixed_err_msg[pos++] = '\\';
            fixed_err_msg[pos++] = *(err_msg + i);
            if (pos >= fixed_len) break;
        }
        sprintf(sql_text,
                "insert into "
                "pct_job_exe_log(job_id,exe_count,step_no,stmt_no,lapse_time,"
                "err_code,err_msg) "
                "values(%lld,%d,%d,%d,%lld,%d,'%*s')",
                JobRowPtr->job_id, JobRowPtr->exe_count, step_no, stmt_no,
                lapse, err_code, 128, fixed_err_msg);
    } else {
        sprintf(sql_text,
                "insert into "
                "pct_job_exe_log(job_id,exe_count,step_no,stmt_no,lapse_time,"
                "err_code,err_msg) "
                "values(%lld,%d,%d,%d,%lld,%d,'%*s')",
                JobRowPtr->job_id, JobRowPtr->exe_count, step_no, stmt_no,
                lapse, err_code, 128, err_msg);
    }
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
    delete sql_stmt;
    // for after encryption, add column encryption
    if (step_no == 3 && stmt_no == 8001) {
        memset(sql_text, 0, 512);
        sprintf(sql_text,
                "update pct_enc_column set(status)=(1) where status = 2 and "
                "enc_tab_id = %lld and "
                "nextlastupdate('PCT_ENC_COLUMN',0,5,'set(status)=(1)','where "
                "status =2 and enc_tab_id=%lld') > 1",
                JobRowPtr->enc_tab_id, JobRowPtr->enc_tab_id);
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                              strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
        memset(sql_text, 0, 512);
        sprintf(sql_text,
                "update pct_enc_column set(status)=(0) where status >= 3 and "
                "status < 5 and enc_tab_id = %lld and "
                "nextlastupdate('PCT_ENC_COLUMN',0,5,'set(status)=(0)','where "
                "status >= 3 and status < 5 and enc_tab_id = %lld') > 0",
                JobRowPtr->enc_tab_id, JobRowPtr->enc_tab_id);
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                              strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
        memset(sql_text, 0, 512);
        sprintf(sql_text,
                "delete pct_enc_column where status = 5 and enc_tab_id = %lld "
                "and nextlastupdate('PCT_ENC_COLUMN',0,7,'','where status=5 "
                "and enc_tab_id=%lld') > 0 ",
                JobRowPtr->enc_tab_id, JobRowPtr->enc_tab_id);
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                              strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
        memset(sql_text, 0, 512);
        sprintf(sql_text,
                "update pct_enc_table "
                "set(curr_enc_step,curr_enc_stmt,last_update)=(3,0,"
                "nextlastupdate('PCT_ENC_TABLE',%lld,2)) where enc_tab_id=%lld",
                JobRowPtr->enc_tab_id, JobRowPtr->enc_tab_id);
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                              strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
    }
}

dgt_void PetraCipherJob::in() throw(DgcExcept) {
    //
    // initialize job rows
    //
    if (initJobRows()) ATHROW(DgcError(SPOS, "initJobRows failed"));
    JobRowPtr->process_id = getpid();
    // JobRowPtr->exe_count++;

    //
    // get the encrypt table row
    //
    if (getEncTabRow()) {
        DgcExcept* e = EXCEPTnC;
        setPending(e);
        RTHROW(e, DgcError(SPOS, "getEncTabRow failed"));
    }
    if (JobRowPtr->start_time == 0 ||
        (EncTabRow.curr_enc_step == 0 && EncTabRow.curr_enc_stmt == 0)) {
        JobRowPtr->start_time = dgtime(&JobRowPtr->start_time);
    }
    //
    // delete pct_job_exe_log`s old log.
    //
    dgt_schar sql_text[512];
    memset(sql_text, 0, 512);
    if (JobRowPtr->target_step != 0) {
        sprintf(sql_text,
                "delete pct_job_exe_log where (job_id=%lld and step_no > %d) "
                "or (job_id=%lld and step_no = %d and stmt_no >= %d)",
                JobID, EncTabRow.curr_enc_step, JobID, EncTabRow.curr_enc_step,
                EncTabRow.curr_enc_stmt);
    } else {
        sprintf(sql_text,
                "delete pct_job_exe_log where job_id=%lld and step_no < 0",
                JobID);
    }
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
        DgcDbProcess::sess(), sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
    delete sql_stmt;
}

#include "PccScriptBuilderFactory.h"

dgt_sint32 PetraCipherJob::run() throw(DgcExcept) {
    // dg_print("PetraCipherJob::run() JobRowPtr->target_step[%d],
    // EncTabRow.curr_enc_step[%d]\n",JobRowPtr->target_step,
    // EncTabRow.curr_enc_step); DgcWorker::PLOG.tprintf(0,"PetraCipherJob::run()
    // JobRowPtr->target_step[%d],
    // EncTabRow.curr_enc_step[%d]\n",JobRowPtr->target_step,
    // EncTabRow.curr_enc_step);
    if (JobRowPtr->target_step == EncTabRow.curr_enc_step) {
        //
        // nothing to be done
        //
        JobRowPtr->curr_status = PCB_JOB_STATUS_DONE;
        return 1;
    }
    //
    // get a script builder for target DBMS
    //
    PccScriptBuilder* script_builder = 0;
    script_builder = PccScriptBuilderFactory::getScriptBuilder(
        DgcDbProcess::dbPtr(), DgcDbProcess::sess(), JobRowPtr->enc_tab_id,
        PccScriptBuilderFactory::PCC_ID_TYPE_TABLE);
    DgcExcept* e = 0;
    if (!script_builder) {
        e = EXCEPTnC;
        setPending(e);
        RTHROWnR(e, DgcError(SPOS, "getScriptBuilder failed."), -1);
    } else {
        memset(JobRowPtr->curr_err_msg, 0, 129);
    }

    dgt_sint16 cstep_no = EncTabRow.curr_enc_step;
    dgt_sint16 last_step_no = EncTabRow.curr_enc_step;
    dgt_sint16 cstmt_no = EncTabRow.curr_enc_stmt;
    dgt_sint16 last_stmt_no = EncTabRow.curr_enc_stmt;
    dgt_sint32 rtn = 0;

    if (EncTabRow.curr_enc_step >= 0 &&
        JobRowPtr->target_step > EncTabRow.curr_enc_step) {
        //
        // encrypting process
        //
        for (cstep_no = EncTabRow.curr_enc_step;
             cstep_no < JobRowPtr->target_step; cstep_no++) {
            if (cstep_no == EncTabRow.curr_enc_step)
                cstmt_no = EncTabRow.curr_enc_stmt + 1;  // start from middle
            else
                cstmt_no = 1;
            last_stmt_no = cstmt_no - 1;

            dgt_schar sql_text[128];
            dg_memset(sql_text, 0, 128);
            sprintf(sql_text,
                    "select distinct stmt_no from pct_script "
                    "where enc_tab_id=%lld and version_no=0 "
                    "and step_no=%d and stmt_no>=%d order by stmt_no",
                    EncTabRow.enc_tab_id, cstep_no, cstmt_no);
            DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                DgcDbProcess::sess(), sql_text, strlen(sql_text));
            if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                e = EXCEPTnC;
                setPending(e);
                RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
            }
            dgt_uint8* rtn_row = 0;
            while ((rtn_row = sql_stmt->fetch())) {
                cstmt_no = *(dgt_sint16*)rtn_row;
                // for (; cstmt_no <= getMaxStmtNo(cstep_no); cstmt_no++) {
                // /////

                JobRowPtr->curr_status = cstep_no * 100 + cstmt_no;

                if ((rtn = script_builder->getScript(JobRowPtr->enc_tab_id, 0,
                                                     cstep_no, cstmt_no)) > 0) {
                    DgcWorker::PLOG.tprintf(
                        0, "ENC_TAB_ID[%lld]: [%d]Step-[%d]Stmt Execute....\n",
                        EncTabRow.enc_tab_id, cstep_no, cstmt_no);
                    DgcWorker::PLOG.tprintf(0, "[%s]\n",
                                            script_builder->scriptText());
                    struct timeval stime;
                    gettimeofday(&stime, 0);

                    JobRowPtr->curr_enc_step = cstep_no;
                    JobRowPtr->curr_enc_stmt = cstmt_no;

                    if (cstep_no == 1 && cstmt_no == 6001) {
                        //
                        // initial encryption -> delete pct_worker where job_id
                        //
                        dgt_schar sql_text[128];
                        sprintf(sql_text, "delete pct_worker where job_id=%lld",
                                JobRowPtr->job_id);
                        DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                            DgcDbProcess::sess(), sql_text, strlen(sql_text));
                        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                            delete EXCEPTnC;
                            delete sql_stmt;
                        }
                        delete sql_stmt;
                    }
                    if (!strcasecmp(script_builder->scriptText(), "Encrypt")) {
                        rtn = doCryptoWork(PCB_DECRYPT_FLAG_ENCRYPT);
                    } else if (!strcasecmp(script_builder->scriptText(),
                                           "Decrypt")) {
                        rtn = doCryptoWork(PCB_DECRYPT_FLAG_DECRYPT);
                    } else if (!strcasecmp(script_builder->scriptText(),
                                           "Update Null")) {
                        rtn = doCryptoWork(PCB_DECRYPT_FLAG_NULLUPDATE);
                    } else {
                        rtn = script_builder->runScript(
                            script_builder->scriptText());
                    }
                    e = EXCEPTnC;

                    struct timeval etime;
                    gettimeofday(&etime, 0);
                    logJobExecution(cstep_no, cstmt_no, &stime, &etime, e);

                    if (e) {
                        //
                        // for mssql errcode 117 = caution message
                        // trigger,table,proceudre dose not exist error code
                        // -01408 = such column already indexed column
                        //
                        dgt_sint32 errcode = e->errCode();
                        if (cstep_no == 2 && cstmt_no >= 2000 &&
                            cstmt_no < 3000) {
                            if (errcode == 117 || errcode == 0 ||
                                errcode == 942 || errcode == -7071 ||
                                errcode == 2443 || errcode == 1347 ||
                                errcode == 1091) {
                                delete e;
                                e = 0;
                            }
                        } else if (errcode == 117 || errcode == 0 ||
                                   errcode == 234 || errcode == 1408 ||
                                   errcode == 2443 || errcode == 1347 ||
                                   errcode == 1091) {
                            delete e;
                            e = 0;
                        } else {
                            break;
                        }
                    }
                    last_stmt_no = cstmt_no;

                } else if (rtn < 0) {
                    e = EXCEPTnC;
                    break;
                }
            }
            if (sql_stmt) delete sql_stmt;
            if (e) break;
            //
            // finish running all scripts in the "cstep" and upgrade
            //
            last_step_no = cstep_no + 1;
            last_stmt_no = 0;
        }
    } else {
        //
        // decrypting process
        //
        if (EncTabRow.curr_enc_step < 0) {
            //
            // for setting cstmt_no = mixStmtno only first time
            //
            dgt_sint32 sequence = 0;
            for (cstep_no = EncTabRow.curr_enc_step;
                 cstep_no < JobRowPtr->target_step; cstep_no++) {
                if (EncTabRow.curr_enc_stmt < 0 &&
                    cstep_no == EncTabRow.curr_enc_step) {
                    last_step_no = cstep_no;
                    last_stmt_no = EncTabRow.curr_enc_stmt;
                    if (sequence == 0 && EncTabRow.curr_enc_stmt > 4000) {
                        //
                        // 4001 stmt = alter table org_tab rename
                        // org_renamed_tab_name
                        //
                        cstmt_no = getMinStmtNo(cstep_no);
                        last_stmt_no = cstmt_no - 1;
                        sequence = 1;
                    } else
                        cstmt_no = EncTabRow.curr_enc_stmt + 1;
                } else {
                    last_stmt_no = cstmt_no;
                    cstmt_no = getMinStmtNo(cstep_no);
                }

                dgt_schar sql_text[128];
                dg_memset(sql_text, 0, 128);
                sprintf(sql_text,
                        "select distinct stmt_no from pct_script "
                        "where enc_tab_id=%lld and version_no=0 "
                        "and step_no=%d and stmt_no>=%d order by stmt_no",
                        EncTabRow.enc_tab_id, cstep_no, cstmt_no);
                DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                    DgcDbProcess::sess(), sql_text, strlen(sql_text));
                if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                    e = EXCEPTnC;
                    setPending(e);
                    RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
                }
                dgt_uint8* rtn_row = 0;
                while ((rtn_row = sql_stmt->fetch())) {
                    cstmt_no = *(dgt_sint16*)rtn_row;
                    JobRowPtr->curr_status = cstep_no * 100 + cstmt_no;

                    if ((rtn = script_builder->getScript(
                             JobRowPtr->enc_tab_id, 0, cstep_no, cstmt_no)) >
                        0) {
                        struct timeval stime;
                        gettimeofday(&stime, 0);

                        JobRowPtr->curr_enc_step = cstep_no;
                        JobRowPtr->curr_enc_stmt = cstmt_no;

                        if (!strcasecmp(script_builder->scriptText(),
                                        "Encrypt")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_ENCRYPT);
                        } else if (!strcasecmp(script_builder->scriptText(),
                                               "Decrypt")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_DECRYPT);
                        } else if (!strcasecmp(script_builder->scriptText(),
                                               "Update Null")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_NULLUPDATE);
                        } else {
                            rtn = script_builder->runScript(
                                script_builder->scriptText());
                        }
                        e = EXCEPTnC;

                        struct timeval etime;
                        gettimeofday(&etime, 0);
                        // logJobExecution(cstep_no, cstmt_no, &stime, &etime,
                        // EXCEPT);
                        logJobExecution(cstep_no, cstmt_no, &stime, &etime, e);

                        // added by mwpark
                        if (e) {
                            dgt_sint32 errcode = e->errCode();
                            if (cstep_no == -1) {
                                // for mssql errcode 117 = caution message
                                // trigger,table,proceudre dose not exist error
                                // code
                                // -7071 (tibero dose not exist)
                                if (errcode == 117 || errcode == 0 ||
                                    errcode == 234 || errcode == 4080 ||
                                    errcode == 942 || errcode == 4043 ||
                                    errcode == 1418 || errcode == -7071 ||
                                    errcode == 2443 || errcode == 1091 ||
                                    errcode == 1347) {
                                    delete e;
                                    e = 0;
                                } else {
                                    break;
                                }
                            } else {
                                // for mssql errcode 117 = caution message
                                // trigger,proceudre dose not exist error code
                                // -7071 (tibero dose not exist)
                                if (errcode == 117 || errcode == 0 ||
                                    errcode == 234 || errcode == 4080 ||
                                    errcode == 942 || errcode == 4043 ||
                                    errcode == 1418 || errcode == -7071 ||
                                    errcode == 2443 || errcode == 1091 ||
                                    errcode == 1347) {
                                    delete e;
                                    e = 0;
                                } else {
                                    break;
                                }
                            }
                        }
                        last_stmt_no = cstmt_no;
                    } else if (rtn < 0) {
                        e = EXCEPTnC;
                        break;
                    }
                }
                if (sql_stmt) delete sql_stmt;
                if (e) break;
                last_step_no = cstep_no + 1;
                last_stmt_no = 0;
            }
        } else {
            //
            // for setting cstmt_no = mixStmtno only first time
            //
            dgt_sint32 sequence = 0;
            for (cstep_no = -1 * EncTabRow.curr_enc_step;
                 cstep_no < JobRowPtr->target_step; cstep_no++) {
                if (cstep_no == -1 * EncTabRow.curr_enc_step) {
                    last_step_no = cstep_no;
                    last_stmt_no = -1 * EncTabRow.curr_enc_stmt;
                    if (sequence == 0 && EncTabRow.curr_enc_stmt > 4000) {
                        //
                        // 4001 stmt = alter table org_tab rename
                        // org_renamed_tab_name
                        //
                        cstmt_no = getMinStmtNo(cstep_no);
                        last_stmt_no = cstmt_no - 1;
                        sequence = 1;
                    } else
                        cstmt_no = -1 * EncTabRow.curr_enc_stmt + 1;
                } else {
                    last_stmt_no = cstmt_no;
                    cstmt_no = getMinStmtNo(cstep_no);
                }

                dgt_schar sql_text[128];
                dg_memset(sql_text, 0, 128);
                sprintf(sql_text,
                        "select distinct stmt_no from pct_script "
                        "where enc_tab_id=%lld and version_no=0 "
                        "and step_no=%d and stmt_no>=%d order by stmt_no",
                        EncTabRow.enc_tab_id, cstep_no, cstmt_no);
                DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                    DgcDbProcess::sess(), sql_text, strlen(sql_text));
                if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                    e = EXCEPTnC;
                    setPending(e);
                    RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
                }
                dgt_uint8* rtn_row = 0;
                while ((rtn_row = sql_stmt->fetch())) {
                    cstmt_no = *(dgt_sint16*)rtn_row;
                    // for (; cstmt_no <= getMaxStmtNo(cstep_no); cstmt_no++) {
                    // /////

                    JobRowPtr->curr_status = cstep_no * 100 + cstmt_no;

                    if ((rtn = script_builder->getScript(
                             JobRowPtr->enc_tab_id, 0, cstep_no, cstmt_no)) >
                        0) {
                        struct timeval stime;
                        gettimeofday(&stime, 0);

                        JobRowPtr->curr_enc_step = cstep_no;
                        JobRowPtr->curr_enc_stmt = cstmt_no;

                        if (!strcasecmp(script_builder->scriptText(),
                                        "Encrypt")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_ENCRYPT);
                        } else if (!strcasecmp(script_builder->scriptText(),
                                               "Decrypt")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_DECRYPT);
                        } else if (!strcasecmp(script_builder->scriptText(),
                                               "Update Null")) {
                            rtn = doCryptoWork(PCB_DECRYPT_FLAG_NULLUPDATE);
                        } else {
                            rtn = script_builder->runScript(
                                script_builder->scriptText());
                        }
                        e = EXCEPTnC;

                        struct timeval etime;
                        gettimeofday(&etime, 0);
                        // logJobExecution(cstep_no, cstmt_no, &stime, &etime,
                        // EXCEPT);
                        logJobExecution(cstep_no, cstmt_no, &stime, &etime, e);

                        // added by mwpark
                        if (e) {
                            dgt_sint32 errcode = e->errCode();
                            if (cstep_no == -1) {
                                // for mssql errcode 117 = caution message
                                // trigger,table,proceudre dose not exist error
                                // code
                                if (errcode == 117 || errcode == 0 ||
                                    errcode == 234 || errcode == 4080 ||
                                    errcode == 942 || errcode == 4043 ||
                                    errcode == 1418 || errcode == -7071 ||
                                    errcode == 2443 || errcode == 1091 ||
                                    errcode == 1347) {
                                    delete e;
                                    e = 0;
                                } else {
                                    break;
                                }
                            } else {
                                // for mssql errcode 117 = caution message
                                // trigger,proceudre dose not exist error code
                                if (errcode == 117 || errcode == 0 ||
                                    errcode == 234 || errcode == 4080 ||
                                    errcode == 942 || errcode == 4043 ||
                                    errcode == 1418 || errcode == -7071 ||
                                    errcode == 2443 || errcode == 1091 ||
                                    errcode == 1347) {
                                    delete e;
                                    e = 0;
                                } else {
                                    break;
                                }
                            }
                        }
                        last_stmt_no = cstmt_no;
                    } else if (rtn < 0) {
                        e = EXCEPTnC;
                        break;
                    }
                }
                if (sql_stmt) delete sql_stmt;
                if (e) break;
                last_step_no = cstep_no + 1;
                last_stmt_no = 0;
            }
        }
    }
    delete script_builder;

    if (last_step_no != EncTabRow.curr_enc_step ||
        last_stmt_no != EncTabRow.curr_enc_stmt) {
        //
        // update current encrypt status
        //

        if (last_step_no == 4) {
            //
            // step_no 3 , stmt_no 8001 : after encryption add column
            //
        } else {
            dgt_schar sql_text[256];
            sprintf(
                sql_text,
                "update pct_enc_table "
                "set(curr_enc_step,curr_enc_stmt,last_update)=(%d,%d,"
                "nextlastupdate('PCT_ENC_TABLE',%lld,2)) where enc_tab_id=%lld",
                last_step_no, last_stmt_no, JobRowPtr->enc_tab_id,
                JobRowPtr->enc_tab_id);
            DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                DgcDbProcess::sess(), sql_text, strlen(sql_text));
            if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
            delete sql_stmt;
#if 0
			if (last_step_no != EncTabRow.curr_enc_step) {
				sprintf(sql_text,"update pct_enc_column set(curr_enc_step,last_update)=(%d,nextlastupdate('PCT_ENC_COLUMN',0,5,'set(curr_enc_step)=(%d)','where enc_tab_id=%lld')) where enc_tab_id=%lld",
					last_step_no, last_step_no,JobRowPtr->enc_tab_id, JobRowPtr->enc_tab_id);
				DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(),sql_text,strlen(sql_text));
				if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
			}
#endif
        }
    }
    if (e) {
        setPending(e);
        RTHROWnR(e, DgcError(SPOS, "executeScript failed."), -1);
    }
    JobRowPtr->curr_status = PCB_JOB_STATUS_DONE;
    memset(JobRowPtr->curr_err_msg, 0, 129);

    return 1;
}

dgt_void PetraCipherJob::out() throw(DgcExcept) {
    JobRowPtr->end_time = dgtime(&JobRowPtr->end_time);
    commitJobRows();
}

static dgt_void printUsage() {
    fputs("\nusage:\n\n", stdout);
    fputs("pcb_job keyword=value ...\n\n", stdout);
    fputs("keywords:\n", stdout);
    fputs("  job_id         scheduled job ID\n", stdout);
    fputs("  table_id       encryption table ID\n", stdout);
    fputs("  target_step    target step\n", stdout);
    fputs("  chunks         the number of chunks: default=200\n", stdout);
    fputs("  array_size     array size: default=1000\n", stdout);
    fputs("  parallel       parallel degree: default=5\n", stdout);
    fputs("  where          WHERE clause for SELECT\n", stdout);
    fputs("  print_interval job status print interval\n", stdout);
    fputs("\n", stdout);
    fflush(stdout);
}

#include "DgcCmdLine.h"

int main(int argc, char** argv) {
    if (argc == 1) {
        printUsage();
        exit(1);
    }

    dgt_schar* pnm = nul;
    if (strchr(argv[0], '/'))
        pnm = (dgt_schar*)dg_basename((char*)argv[0]);
    else if ((pnm = strchr(argv[0], ' ')))
        pnm += 1;
    else
        pnm = argv[0];

    //
    // parse comman line
    //
    DgcCmdLine cmd_line(argv);
    dgt_sint64 job_id = 0;
    dgt_sint64 enc_tab_id = 0;
    dgt_sint16 target_step = 4;
    dgt_uint32 array_size = 0;
    dgt_uint16 num_chunks = 0;
    dgt_uint16 parallel_degree = 0;
    const dgt_schar* where_clause = 0;
    dgt_uint16 print_interval = 0;
    const dgt_schar* val = 0;
    //
    // job id
    //
    if ((val = cmd_line.getValue("job_id"))) {
        job_id = dg_strtoll(val, 0, 10);
    } else {
        //
        // encrypt table id
        //
        if ((val = cmd_line.getValue("table_id")))
            enc_tab_id = dg_strtoll(val, 0, 10);
        //
        // target step
        //
        if ((val = cmd_line.getValue("target_step")))
            target_step = (dgt_sint16)strtol(val, 0, 10);
        //
        // arrya size
        //
        if ((val = cmd_line.getValue("array_size")))
            array_size = strtol(val, 0, 10);
        //
        // the number of chunks
        //
        if ((val = cmd_line.getValue("chunks")))
            num_chunks = (dgt_uint16)strtol(val, 0, 10);
        //
        // parallel degree
        //
        if ((val = cmd_line.getValue("parallel")))
            parallel_degree = (dgt_uint16)strtol(val, 0, 10);
        //
        // where clause
        //
        where_clause = cmd_line.getValue("where");
        //
        // print interval
        //
        if ((val = cmd_line.getValue("print_interval")))
            print_interval = (dgt_uint16)strtol(val, 0, 10);
    }

    //
    // *********************************************************
    // process initialization: being a demon and a log open.
    // *********************************************************
    //
    dgt_schar* svc_name = getenv("SOHA_SVC");
    if (DgcDbProcess::initialize(DGC_WT_DG_PETRA, pnm, 1, 1) != 0) {
        DgcExcept* e = EXCEPTnC;
        dg_print("process initialization failed due to [%s].\n",
                 e->getErr()->message());
        DgcWorker::PLOG.tprintf(
            0, *e, "process initialize[%s] failed due to the below:\n",
            svc_name);
        delete e;
        exit(1);
    }
    dg_signal(SIGCHLD, SIG_IGN);

    //
    //  attach database
    //
    if (DgcDbProcess::openDatabase(svc_name, DGC_LD_ATTACH) != 0) {
        DgcExcept* e = EXCEPTnC;
        dg_print("database open failed due to [%s].\n", e->getErr()->message());
        DgcWorker::PLOG.tprintf(
            0, *e, "openDatabase[%s] failed due to the below:\n", svc_name);
        delete e;
        exit(1);
    }
    DgcDbProcess::sess()->setDatabaseUser(DGC_SYS_OWNER);
    dg_strcpy(DgcDbProcess::pa().owner, DGC_SYS_OWNER);

    //
    // run a CipherJob in root thread
    //
    PetraCipherJob pcb(job_id,           // job id
                       enc_tab_id,       // encrypt table id
                       target_step,      // target step
                       array_size,       // array size
                       num_chunks,       // max chunks
                       parallel_degree,  // parallel degree
                       where_clause,     // where clause
                       print_interval    // job status print interval
    );
    pcb.wa()->ThreadID = pthread_self();
    DgcWorker::entry((dgt_void*)&pcb);

    DgcDbProcess::monitorProcess();

    return 0;
}
