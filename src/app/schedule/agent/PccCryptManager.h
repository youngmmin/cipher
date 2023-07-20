/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptManager
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_MANAGER_H
#define PCC_CRYPT_MANAGER_H

#include "DgcWorker.h"
#include "PccAgentCryptJobPool.h"
#include "PccCorePool.h"
#include "PccFileCryptor.h"

class PccCryptManager : public DgcWorker {
  private:
	static const dgt_sint32		MAX_PARAM_LEN = 10240;
	static const dgt_sint32		MAX_GET_CORE_TRY = 10;
	static const dgt_sint32		NO_TARGET_SLEEP = 3;
	PccAgentCryptJobPool& 	JobPool;
	PccCorePool&			CorePool;
	dgt_sint32			SessionID;
	dgt_schar*			CryptParams;
	dgt_schar*			OutFileName;
	dgt_sint32			OutFileNameLen;
	dgt_sint32			WorkStage;
	dgt_sint32			StopFlag;
	dgt_sint32			AgentMode;
	dgt_schar*			EncColName;
	dgt_schar*			HeaderFlag;
	dgt_sint32			BufferSize;
	dgt_sint32			EncryptFlag;
	dgt_sint64			EncFileCnt;
	dgt_sint32			ManagerID;
	dgt_sint32			TargetFileFlag;
	dgt_sint32			start_flag;

	PccCryptTargetFile	TargetFile;
	PccFileCryptor*		Cryptor;
	dgt_sint32 buildStreamParam(PccCryptTargetFile& tf, PccAgentCryptJob* curr_job);
	dgt_sint32 buildParam(PccCryptTargetFile& tf, PccAgentCryptJob* curr_job, dgt_sint32 threads=0, dgt_sint32 migration_flag = 0); // return the number of cores when success
  protected:
	dgt_sint32 fileCryption(PccAgentCryptJob* curr_job) throw(DgcExcept);
	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  public:
	PccCryptManager(PccAgentCryptJobPool& job_pool,PccCorePool& core_pool, dgt_sint32 manager_id, dgt_sint32 agent_mode=0,dgt_schar* enc_col_name=0, dgt_schar* header_flag=0,dgt_sint32 buffer_size=0);
	virtual ~PccCryptManager();
	dgt_sint32 workStage() { return WorkStage; }
	dgt_void askStop() { StopFlag = 1; }
	dgt_sint32 stopFlag() { return StopFlag; }
};

#endif
