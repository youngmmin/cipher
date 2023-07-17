/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptTargetCollector
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_TARGET_COLLECTOR_H
#define PCC_CRYPT_TARGET_COLLECTOR_H

#include "DgcWorker.h"
#include "PccJobRepository.h"

class PccCryptTargetCollector : public DgcWorker {
  private:
	static const dgt_sint32	COLLECT_INTERVAL = 10;
	PccJobRepository&	Repository;
	dgt_sint32		CollectingInterval;
	dgt_uint8		IsCollected;
	dgt_uint8		JobStatus;
	dgt_uint8		StopFlag;
  protected:
	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  public:
	PccCryptTargetCollector(PccJobRepository& repository,dgt_sint32 collecting_interval,dgt_uint8 job_status=PCC_STATUS_TYPE_RUN);
	virtual ~PccCryptTargetCollector();

	inline dgt_void setJobStatus(dgt_uint8 job_status) { JobStatus = job_status; };
	inline dgt_void setCollectingInterval(dgt_sint32 itv) { CollectingInterval = itv; };

	inline dgt_uint8 jobStatus() { return JobStatus; };
	inline dgt_void askStop() { StopFlag = 1; };
};

#endif
