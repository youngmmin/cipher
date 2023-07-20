/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccAgentCryptJob
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

#include "PccAgentCryptJob.h"


PccAgentCryptJob::PccAgentCryptJob(dgt_sint64 job_id, dgt_sint32 trace_level, dgt_sint32 fail_file_queue_size, dgt_sint32 nullity_file_queue_size)
	: JobID(job_id),StartTime(0),EndTime(0),Repository(trace_level),Collector(0)
{
	NSL = 0;
	ELF = 0;
	FailFileQueueSize = fail_file_queue_size;
	NullityFileQueueSize = nullity_file_queue_size;
	TraceLevel = trace_level;
	DgcSpinLock::unlock(&Lock);
}


PccAgentCryptJob::~PccAgentCryptJob()
{
	if (Collector) {
		while (Collector->isAlive()) napAtick();
		delete Collector;
		Collector = 0;
	}
}


dgt_sint32 PccAgentCryptJob::lock() throw(DgcExcept)
{
	if (DgcSpinLock::lock(&Lock) != 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
			new DgcError(SPOS,"job_id[%lld] lock timeout.",JobID)),-1);
	}
	return 0;
}


dgt_void PccAgentCryptJob::unlock() throw(DgcExcept)
{
	DgcSpinLock::unlock(&Lock);
}


dgt_sint32 PccAgentCryptJob::lockExclusive() throw(DgcExcept)
{
	dgt_uint32 nap_count = 0;
	dgt_uint32 max_nap = LOCK_MAX_NAP;
	for (;;) {
		if (lock() != 0) ATHROWnR(DgcError(SPOS,"lock failed."),-1);
		if (NSL == 0 && ELF == 0) {
			ELF = 1;
			break;
		}
		unlock();
		++nap_count;
		if (max_nap > 0 && nap_count >= max_nap) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,	new DgcError(SPOS,"job_id[%lld] lockExclusive[ELF:%u][NSL:%d] timeout.",JobID,ELF,NSL)),-1);
		}
		napAtick();
	}
	unlock();
	return 0;
}


dgt_sint32 PccAgentCryptJob::unlockExclusive() throw(DgcExcept)
{
	if (lock() != 0) {
		DgcExcept* e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"job_id[%lld] lock failed while unlockExclusive[ELF:%u][NSL:%d]\n",JobID,ELF,NSL);
			delete e;
		}
		return 0;
	}
	if (ELF) ELF = 0;
	unlock();
	return 0;
}


dgt_sint32 PccAgentCryptJob::lockShare() throw(DgcExcept)
{
	dgt_uint32 nap_count = 0;
	dgt_uint32 max_nap = LOCK_MAX_NAP;
	for(;;) {
		if (lock() != 0) ATHROWnR(DgcError(SPOS,"lock failed."),-1);
		if (ELF == 0) {
			NSL++;
			break;
		}
		unlock();
		++nap_count;
		if (max_nap > 0 && nap_count >= max_nap) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
				new DgcError(SPOS,"job_id[%lld] lockShare[ELF:%u][NSL:%d] timeout.",JobID,ELF,NSL)),-1);
		}
		napAtick();
	}
	unlock();
	return 0;
}


dgt_sint32 PccAgentCryptJob::unlockShare() throw(DgcExcept)
{
	if (lock() != 0) {
		DgcExcept* e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"job_id[%lld] lock failed while unlockShare[ELF:%u][NSL:%d]\n",JobID,ELF,NSL);
			delete e;
		}
		return 0;
	}
	if (NSL > 0) NSL--;
	unlock();
	return 0;
}

dgt_sint32 PccAgentCryptJob::start(dgt_uint8 job_type,dgt_uint8 job_status,dgt_sint32 file_queue_size,dgt_sint32 collecting_interval) throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"CryptJob Library Version test\n");
	//DgcWorker::PLOG.tprintf(0,"CryptJob Library Version [%d][%d][%d]\n",getBogoModule()->msGetMajorVersion(), getBogoModule()->msGetMinorVersion(), getBogoModule()->msGetPatchVersion());
	Repository.setJobType(job_type);

	// initialize file queue
	if (file_queue_size > 0) {
		if (Repository.fileQueue().initializeQueue(file_queue_size) == 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"initializeQueue failed : queue_size[%d]",file_queue_size)),0);
		}
		if (Repository.migrationFileQueue().initializeQueue(file_queue_size) == 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"initializeMigrationQueue failed : queue_size[%d]",file_queue_size)),0);
		}
	}
	// initialize fail file queue
	if (FailFileQueueSize > 0) {
		if (Repository.failFileQueue().initializeQueue(FailFileQueueSize) == 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"initializeFailQueue failed : queue_size[%d]",FailFileQueueSize)),0);
		}
	}
	if (NullityFileQueueSize > 0) {
		if (Repository.nullityFileQueue().initializeQueue(NullityFileQueueSize) == 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"initializeNullityQueue failed : queue_size[%d]",NullityFileQueueSize)),0);
		}
	}

	// start a collector
	if (Collector) {
		Collector->askStop();
		while (Collector->isAlive()) napAtick();
		delete Collector;
	}
	Collector = new PccCryptTargetCollector(Repository,collecting_interval,job_status);
	if (Collector->start(1)) {
		ATHROWnR(DgcError(SPOS,"start collector failed"),-1);
	}
	return 0;
}


dgt_sint32 PccAgentCryptJob::stop() throw(DgcExcept)
{
	Repository.dirPool().allPause();
	if (Collector) Collector->askStop();
	return 0;
}
