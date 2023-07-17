/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptMir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 add debug code by shson
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptTargetCollector.h"


PccCryptTargetCollector::PccCryptTargetCollector(PccJobRepository& repository,dgt_sint32 collecting_interval,dgt_uint8 job_status)
	: Repository(repository),CollectingInterval(collecting_interval ? collecting_interval:COLLECT_INTERVAL), JobStatus(job_status), StopFlag(0)
{
	IsCollected = 0;
}


PccCryptTargetCollector::~PccCryptTargetCollector()
{
}


dgt_void PccCryptTargetCollector::in() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"collector[%u] starts.\n",tid());
}


dgt_sint32 PccCryptTargetCollector::run() throw(DgcExcept)
{
	if (StopFlag) return 1;
	PccCryptDir*	crypt_dir = 0;
	if (JobStatus == PCC_STATUS_TYPE_RUN) {
		dgt_sint32 collect_flag=0;
		if (Repository.schedule().isWorkingTime()) collect_flag=1;
		for(dgt_sint32 i=0; i<Repository.dirPool().numDirs() && (crypt_dir=Repository.dirPool().getCryptDir(i)); i++) {
			if (crypt_dir->status() == PCC_STATUS_TYPE_DELETED) {
				if (Repository.dirPool().dropCryptDir(crypt_dir->dirID()) < 0) {
					DgcExcept* e=EXCEPTnC;
					DgcWorker::PLOG.tprintf(0,*e,"PccCryptDir[%lld:%s]::dropCryptDir Failed\n",crypt_dir->dirID(),crypt_dir->srcDir());
					delete e;
				}
				if (Repository.dirPool().numDirs() == 0) break;
			}
			if (crypt_dir->status() == PCC_STATUS_TYPE_DELETED || crypt_dir->status() == PCC_STATUS_TYPE_PAUSE) continue;
			if (Repository.getJobType() == PCC_AGENT_TYPE_DETECT_JOB) crypt_dir->dirRule()->version = 2;
			if (crypt_dir->filter() < 0) {
				DgcExcept* e=EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"PccCryptDir[%lld:%s]::filter:\n",crypt_dir->dirID(),crypt_dir->srcDir());
				delete e;
			}
		}
		if (Repository.getJobType() == PCC_AGENT_TYPE_TEMPORARY_JOB && collect_flag ==1) return 1;
		if (Repository.getJobType() == PCC_AGENT_TYPE_DETECT_JOB && collect_flag ==1) {
			JobStatus = PCC_STATUS_TYPE_PAUSE;
			return 1;
		}
	}
	for(dgt_sint32 i = 0 ; i < CollectingInterval ; i++) {
		if (StopFlag) return 1;
		for(dgt_sint32 i=0; i<Repository.dirPool().numDirs() && (crypt_dir=Repository.dirPool().getCryptDir(i)); i++) {
			if (crypt_dir->status() == PCC_STATUS_TYPE_DELETED) {
				if (Repository.dirPool().dropCryptDir(crypt_dir->dirID()) < 0) {
					DgcExcept* e=EXCEPTnC;
					DgcWorker::PLOG.tprintf(0,*e,"PccCryptDir[%lld:%s]::dropCryptDir Failed\n",crypt_dir->dirID(),crypt_dir->srcDir());
					delete e;
				}
				if (Repository.dirPool().numDirs() == 0) break;
			} //if (crypt_dir->status() == PCC_STATUS_TYPE_DELETED) end
		} //for(dgt_sint32 i=0; i<Repository.dirPool().numDirs() && (crypt_dir=Repository.dirPool().getCryptDir(i)); i++) end
		sleep(1);
	} //for(dgt_sint32 i = 0 ; i < CollectingInterval ; i++) end
	return 0;
}


dgt_void PccCryptTargetCollector::out() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"collector[%u] ends.\n",tid());
}

