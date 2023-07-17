/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration and definition
 *   Classes            :       PccJobRepository
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_JOB_REPOSITORY_H
#define PCC_JOB_REPOSITORY_H

#include "PccAgentMsg.h"
#include "PccCryptZonePool.h"
#include "PccCryptSchedule.h"
#include "PccCryptTargetFileQueue.h"
#include "PccCryptDirPool.h"

class PccJobRepository : public DgcObject {
  private:
	PccCryptTargetFileQueue		FileQueue;
	PccCryptTargetFileQueue		FailFileQueue;
	PccCryptTargetFileQueue		NullityFileQueue;
	PccCryptTargetFileQueue		MigrationFileQueue;
	PccCryptZonePool		ZonePool;
	PccCryptSchedule		Schedule;
	PccCryptDirPool			DirPool;
	dgt_sint32			JobType;
	dgt_sint32			TraceLevel;
  protected:
  public:
	PccJobRepository(dgt_sint32 trace_level = 0);
	virtual ~PccJobRepository();
	inline PccCryptTargetFileQueue& fileQueue() { return FileQueue; };
	inline PccCryptTargetFileQueue& failFileQueue() { return FailFileQueue; };
	inline PccCryptTargetFileQueue& nullityFileQueue() { return NullityFileQueue; };
	inline PccCryptTargetFileQueue& migrationFileQueue() { return MigrationFileQueue; };
	inline dgt_void setJobType(dgt_sint32 job_type) { JobType = job_type; };
	inline dgt_sint32 getJobType() { return JobType; };
	inline PccCryptZonePool& zonePool() { return ZonePool; };
	inline PccCryptSchedule& schedule() { return Schedule; };
	inline PccCryptDirPool& dirPool() { return DirPool; };
};

#endif

