/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccAgentCryptJobPool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentCryptJobPool.h"

PccAgentCryptJobPool::PccAgentCryptJobPool()
    : AgentID(0),
      LastUpdate(0),
      NumJobs(0),
      FileQueueSize(0),
      FailFileQueueSize(0),
      NullityFileQueueSize(0),
      CollectInterval(0),
      TraceLevel(0) {
    for (dgt_sint32 i = 0; i < MAX_JOBS; i++) CryptJobs[i] = 0;
    DgcSpinLock::unlock(&ListLock);
}

PccAgentCryptJobPool::~PccAgentCryptJobPool() {
    for (dgt_sint32 i = 0; i < NumJobs; i++) {
        if (CryptJobs[i]) {
            CryptJobs[i]->unlockShare();
            if (dropJob(CryptJobs[i]->jobID())) {
                DgcExcept* e = EXCEPTnC;
                DgcWorker::PLOG.tprintf(0, *e, "dropJob failed:\n");
                delete e;
            }
        }
    }
}

PccAgentCryptJob* PccAgentCryptJobPool::jobByIdx(dgt_sint32 idx) {
    PccAgentCryptJob* job = 0;
    if (DgcSpinLock::lock(&ListLock) == 0) {
        if (idx < NumJobs) job = CryptJobs[idx];
        if (job && job->lockShare() < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcWorker::PLOG.tprintf(
                    0, *e, "lockShare idx[%d] job_id[%lld] failed.\n", idx,
                    job->jobID());
                delete e;
            }
            job = 0;
        }
        DgcSpinLock::unlock(&ListLock);
    }
    return job;
}

PccAgentCryptJob* PccAgentCryptJobPool::getJob(dgt_sint64 job_id) throw(
    DgcExcept) {
    PccAgentCryptJob* job = 0;
    if (DgcSpinLock::lock(&ListLock) == 0) {
        for (dgt_sint32 i = 0; i < NumJobs; i++) {
            if (CryptJobs[i] && CryptJobs[i]->jobID() == job_id)
                job = CryptJobs[i];
        }
        if (job && job->lockShare() < 0) {
            DgcSpinLock::unlock(&ListLock);
            ATHROWnR(DgcError(SPOS, "lockShare failed"), 0);
        }
        DgcSpinLock::unlock(&ListLock);
    }
    return job;
}

PccAgentCryptJob* PccAgentCryptJobPool::newJob(dgt_sint64 job_id) throw(
    DgcExcept) {
    PccAgentCryptJob* job = 0;
    if (DgcSpinLock::lock(&ListLock) == 0) {
        for (dgt_sint32 i = 0; i < NumJobs; i++) {
            if (CryptJobs[i] == 0) {
                CryptJobs[i] =
                    new PccAgentCryptJob(job_id, TraceLevel, FailFileQueueSize,
                                         NullityFileQueueSize);
                job = CryptJobs[i];
            }
        }
        if (job == 0) {
            if (NumJobs == MAX_JOBS) {
                DgcSpinLock::unlock(&ListLock);
                THROWnR(
                    DgcBgmrExcept(
                        DGC_EC_BG_INCOMPLETE,
                        new DgcError(SPOS, "job table[%d] is full", NumJobs)),
                    0);
            } else {
                job =
                    new PccAgentCryptJob(job_id, TraceLevel, FailFileQueueSize,
                                         NullityFileQueueSize);
                CryptJobs[NumJobs++] = job;
            }
        }
        DgcSpinLock::unlock(&ListLock);
    }

    return job;
}

dgt_sint32 PccAgentCryptJobPool::dropJob(dgt_sint64 job_id) throw(DgcExcept) {
    if (DgcSpinLock::lock(&ListLock) == 0) {
        for (dgt_sint32 i = 0; i < NumJobs; i++) {
            if (CryptJobs[i] && CryptJobs[i]->jobID() == job_id) {
                if (CryptJobs[i]->lockExclusive() < 0) {
                    DgcSpinLock::unlock(&ListLock);
                    ATHROWnR(DgcError(SPOS, "lockExclusive job_id[%lld] failed",
                                      job_id),
                             -1);
                }
                if (CryptJobs[i]->stop() < 0) {
                    DgcSpinLock::unlock(&ListLock);
                    ATHROWnR(DgcError(SPOS, "stop[job:%lld] failed", job_id),
                             -1);
                } else {
                    if (CryptJobs[i]->collector() &&
                        CryptJobs[i]->collector()->isAlive())
                        napAtick();
                    delete CryptJobs[i];
                    CryptJobs[i] = 0;
                    if (i == NumJobs - 1) NumJobs--;
                }
                break;
            }
        }
        DgcSpinLock::unlock(&ListLock);
    }
    return 0;
}
