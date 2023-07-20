/*******************************************************************
 *   File Type          :       class declaration and definition
 *   Classes            :       PccFileCipherService
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 29
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CIPHER_AGENT_SERVICE_H
#define PCC_CIPHER_AGENT_SERVICE_H

#include "PccCipherAgentSvrSessionPool.h"

class PccCipherAgentService : public DgcWorker {
  private:
	static const dgt_sint32 INIT_MANAGERS = 10; 

	PccAgentCryptJobPool		JobPool;
	PccCipherAgentSvrSessionPool	SessionPool;
	PccAgentRepository			Repository;
	PccCipherAgentSvrSession*	CurrSession;
	PccAgentCryptJob*			CryptJob;
	dgt_sint32					NumManagers;
	dgt_sint32					NoSessionSleepCount;
	dgt_sint32					CommandMode;
	dgt_schar*					UdsListenAddr;
	dgt_uint8					StopFlag;
	dgt_sint32					AgentMode;
	dgt_schar*					EncColName;
	dgt_schar*					HeaderFlag;
	dgt_sint32					BufferSize;
	
	// added by mjkim 19.05.31 for file pattern detecting
	dgt_sint64					MaxDetection;
	dgt_sint32					BinarySkipFlag;

	// added by ihjin 181118 for fp masking ai machine
	dgt_float32					Threshold;
	dgt_schar*					BogonetLibName;
	dgt_schar*					BogonetLibPath;
	dgt_schar*					MsMachinePath;

	dgt_void openLogStream(const dgt_schar* log_file_path);
	dgt_sint32 setConf(PccAgentCryptJob* job,DgcBgrammer* bg) throw(DgcExcept);
		
	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  protected:
  public:
	PccCipherAgentService();
	virtual ~PccCipherAgentService();

	inline dgt_void askStop() { StopFlag = 1; };
	inline const dgt_schar* udsListenAddr() { return UdsListenAddr; };
	inline dgt_sint32 commandMode() { return CommandMode; }
	inline dgt_sint64 agentID() { return JobPool.agentID(); };
	inline PccAgentCryptJobPool* jobPool() { return &JobPool; };
	dgt_sint32 initialize(
			dgt_sint64 agent_id,
			dgt_schar* uds_listen_dir,
			dgt_schar* log_dir,
			dgt_sint32 max_target_files,
			dgt_sint32 max_use_cores,
			dgt_sint32 init_managers,
			dgt_sint32 collect_interval,
			dgt_sint32 no_sess_sleep_conunt,
			dgt_sint32 trace_level,
			dgt_sint32 num_sessions,
			dgt_schar* primary_sess_ip,
			dgt_uint16 primary_sess_port,
			dgt_schar* secondary_sess_ip=0,
			dgt_uint16 secondary_sess_port=0) throw(DgcExcept);
	dgt_sint32 initialize(const dgt_schar* conf_file_path, dgt_sint64 agent_id = 0) throw(DgcExcept);

	dgt_void getCryptAgentStatus(pcct_agent_status* status);

};

#endif
