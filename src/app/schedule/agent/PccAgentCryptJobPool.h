/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccAgentCryptJobPool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_CRYPT_JOB_POOL_H
#define PCC_AGENT_CRYPT_JOB_POOL_H

#include "PccAgentCryptJob.h"

class PccAgentCryptJobPool : public DgcObject {
   private:
    static const dgt_sint32 MAX_JOBS = 200;
    dgt_sint64 AgentID;
    dgt_sint64 LastUpdate;
    PccAgentCryptJob* CryptJobs[MAX_JOBS];
    dgt_sint32 NumJobs;
    dgt_sint32 FileQueueSize;
    dgt_sint32 FailFileQueueSize;
    dgt_sint32 NullityFileQueueSize;
    dgt_sint32 CollectInterval;
    dgt_sint32 TraceLevel;

    dgt_slock ListLock;

   protected:
   public:
    PccAgentCryptJobPool();
    virtual ~PccAgentCryptJobPool();
    inline dgt_void setAgentID(dgt_sint64 agent_id) { AgentID = agent_id; };
    inline dgt_void setLastUpdate(dgt_sint64 last_update) {
        LastUpdate = last_update;
    };
    inline dgt_void setFileQueueSize(dgt_sint32 file_queue_size) {
        FileQueueSize = file_queue_size;
    };
    inline dgt_void setFailFileQueueSize(dgt_sint32 fail_file_queue_size) {
        FailFileQueueSize = fail_file_queue_size;
    };
    inline dgt_void setNullityFileQueueSize(
        dgt_sint32 nullity_file_queue_size) {
        NullityFileQueueSize = nullity_file_queue_size;
    };
    inline dgt_void setCollectInterval(dgt_sint32 interval) {
        CollectInterval = interval;
    };
    inline dgt_void setTraceLevel(dgt_sint32 trace_level) {
        TraceLevel = trace_level;
    };

    inline dgt_sint64 lastUpdate() { return LastUpdate; };
    inline dgt_sint64 agentID() { return AgentID; };
    inline dgt_sint32 numJobs() { return NumJobs; };
    inline dgt_sint32 fileQueueSize() { return FileQueueSize; };
    inline dgt_sint32 failFileQueueSize() { return FailFileQueueSize; };
    inline dgt_sint32 nullityFileQueueSize() { return NullityFileQueueSize; };
    inline dgt_sint32 collectInterval() { return CollectInterval; };
    inline dgt_sint32 traceLevel() { return TraceLevel; };

    PccAgentCryptJob* jobByIdx(dgt_sint32 idx);
    PccAgentCryptJob* getJob(dgt_sint64 job_id) throw(DgcExcept);
    PccAgentCryptJob* newJob(dgt_sint64 job_id = 0) throw(DgcExcept);
    dgt_sint32 dropJob(dgt_sint64 job_id) throw(DgcExcept);
};

#endif
