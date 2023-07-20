/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PetraCipherJob
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PETRA_CIPHER_JOB_H
#define PETRA_CIPHER_JOB_H

#include "DgcPetraWorker.h"
#include "PcbCipherTable.h"
#include "PcbCollector.h"
#include "PcbUpdater.h"

class PetraCipherJob : public DgcPetraWorker {
   private:
    static const dgt_uint16 PCB_MAX_CHUNKS = 200;
    static const dgt_uint16 PCB_MAX_UPDATERS = 100;
    static const dgt_uint32 PCB_PARALLEL_DEGREE = 5;

    dgt_sint64 JobID;
    dgt_sint64 EncTabID;
    dgt_sint16 TargetStep;
    dgt_uint32 ArraySize;
    dgt_uint16 NumChunks;
    dgt_uint16 ParallelDegree;
    const dgt_schar* WhereClause;
    dgt_uint16 PrintInterval;
    dgt_uint32 SleepCount;

    pct_type_enc_table EncTabRow;
    PcbCipherTable* CipherTable;
    PcbDataChunkPool* ChunkPool;
    PcbCollector* Collector;
    dgt_uint16 NumUpdaters;
    PcbUpdater* Updaters[PCB_MAX_UPDATERS];
    dgt_uint16 NumStartedUpdaters;
    DgcStreamSegment* KeyStash;

    DgcTableSegment* JobSeg;
    DgcRowRef AllJobRows;
    DgcRowList JobRows;
    pct_type_job* JobRowPtr;
    DgcTableSegment* JobWkrSeg;
    DgcRowList JobWkrRows;

    dgt_sint32 initJobRows() throw(DgcExcept);
    dgt_void setPending(DgcExcept* e);
    dgt_sint32 getEncTabRow() throw(DgcExcept);
    dgt_sint32 initResource(dgt_uint8 decrypt_flag) throw(DgcExcept);
    dgt_void commitJobRows();
    dgt_void commitWorkerRows();
    dgt_void printJobStatus();
    dgt_sint16 getMaxStmtNo(dgt_sint16 step_no);
    dgt_sint16 getMinStmtNo(dgt_sint16 step_no);
    dgt_sint32 doCryptoWork(dgt_uint8 decrypt_flag = 0) throw(DgcExcept);
    dgt_void logJobExecution(dgt_sint16 step_no, dgt_sint16 stmt_no,
                             struct timeval* stime, struct timeval* etime,
                             DgcExcept* e);

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);
    virtual dgt_void out() throw(DgcExcept);

   protected:
   public:
    static const dgt_uint8 PCB_JOB_ENCRYPT = 1;
    static const dgt_uint8 PCB_JOB_DECRYPT = 2;

    static const dgt_sint16 PCB_JOB_STATUS_SCHEDULING = 0;
    static const dgt_sint16 PCB_JOB_STATUS_PENDING = 10000;
    static const dgt_sint16 PCB_JOB_STATUS_DONE = 20000;

    static const dgt_sint16 PCB_WKR_STATUS_INITIALIZING = 0;
    static const dgt_sint16 PCB_WKR_STATUS_COLLECTING = 1;
    static const dgt_sint16 PCB_WKR_STATUS_UPDATING = 2;
    static const dgt_sint16 PCB_WKR_STATUS_WAITING = 3;
    static const dgt_sint16 PCB_WKR_STATUS_ERROR = 10000;
    static const dgt_sint16 PCB_WKR_STATUS_DONE = 20000;

    PetraCipherJob(dgt_sint64 job_id, dgt_sint64 enc_tab_id = 0,
                   dgt_sint16 target_step = 4, dgt_uint32 array_size = 0,
                   dgt_uint16 num_chunks = 0, dgt_uint16 parallel_degree = 0,
                   const dgt_schar* where_clause = 0,
                   dgt_uint16 print_interval = 0);
    virtual ~PetraCipherJob();
};

#endif
