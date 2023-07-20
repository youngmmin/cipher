/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccAgentCryptJob
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_CRYPT_JOB_H
#define PCC_AGENT_CRYPT_JOB_H

#include "PccCryptTargetCollector.h"

class PccAgentCryptJob : public DgcObject {
   private:
    static const dgt_sint32 INIT_MANAGERS = 5;
    static const dgt_uint32 LOCK_MAX_NAP = 500;
    dgt_sint64 JobID;
    dgt_time StartTime;
    dgt_time EndTime;
    PccJobRepository Repository;
    PccCryptTargetCollector* Collector;

    dgt_slock Lock;
    dgt_uint8 ELF;   // for drop job
    dgt_sint32 NSL;  // for using job
    dgt_sint32 FailFileQueueSize;
    dgt_sint32 NullityFileQueueSize;
    dgt_sint32 TraceLevel;

    dgt_sint32 lock() throw(DgcExcept);
    dgt_void unlock() throw(DgcExcept);

   protected:
   public:
    PccAgentCryptJob(dgt_sint64 job_id, dgt_sint32 trace_level,
                     dgt_sint32 fail_file_queue_size = 200,
                     dgt_sint32 nullity_file_queue_size = 200);
    virtual ~PccAgentCryptJob();
    inline dgt_sint64 jobID() { return JobID; }
    inline dgt_time startTime() { return StartTime; }
    inline dgt_time endTime() { return EndTime; }
    inline PccJobRepository& repository() { return Repository; }
    inline PccCryptTargetCollector* collector() { return Collector; }
    dgt_sint32 lockExclusive() throw(DgcExcept);
    dgt_sint32 unlockExclusive() throw(DgcExcept);
    dgt_sint32 lockShare() throw(DgcExcept);
    dgt_sint32 unlockShare() throw(DgcExcept);

    dgt_sint32 start(dgt_uint8 job_type, dgt_uint8 job_status,
                     dgt_sint32 file_queue_size = 0,
                     dgt_sint32 collecting_interval = 0) throw(DgcExcept);
    dgt_sint32 stop() throw(DgcExcept);
};

#endif
