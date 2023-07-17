/*******************************************************************
 *   File Type          :       class declaration and definition
 *   Classes            :       PccCipherAgentManager
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 9. 27
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CIPHER_AGENT_MANAGER_H
#define PCC_CIPHER_AGENT_MANAGER_H

#include "DgcWorker.h"
#include "DgcSigManager.h"
#include "DgcBgmrList.h"
#include "DgcDbNet.h"
#include "DgcDgMsgStream.h"
#include "DgcSqlClient.h"
#include "PccAgentMsg.h"

typedef struct {
	dgt_sint64	agent_id;
	dgt_sint64	pid;
	dgt_uint8	monitoring_flag;
	dgt_uint8	agent_type;
} pcamt_agent_list;

typedef struct {
	dgt_sint32	max_target_files;
	dgt_sint32	max_use_cores;
	dgt_sint32	init_managers;
	dgt_sint32	collect_interval;
	dgt_sint32	no_sess_sleep_conunt;
	dgt_sint32	trace_level;
	dgt_sint32	num_sessions;
	dgt_uint16	primary_sess_port;
	dgt_uint16	secondary_sess_port;
	dgt_schar	primary_sess_ip[65];
	dgt_schar	secondary_sess_ip[65];
} pcamt_agent_param;

class PccCipherAgentManager : public DgcWorker {
  private:
	static const dgt_uint8	MAX_AGENTS = 10;
	static const dgt_sint32 SOHA_CONN_TIMEOUT = 5;
	static const dgt_schar	SOHA_CONN_STRING[];
	static const dgt_schar	CRYPT_AGENT_CONN_STRING[];
	static const dgt_schar	CLIENT_AGENT_CONN_STRING[];

	static const dgt_uint8	STEP_INIT					= 0;
	static const dgt_uint8	STEP_START_AGENT				= 1;
	static const dgt_uint8	STEP_CHECK_AGENT_IS_STARTING			= 2;
	static const dgt_uint8	STEP_MONITOR_AGENT				= 3;
	static const dgt_uint8	STEP_END					= 4;

	static const dgt_uint8	SOHA_CONN_STATUS_NONE			= 0;
	static const dgt_uint8	SOHA_CONN_STATUS_CONNECTED		= 1;
	static const dgt_uint8	SOHA_CONN_STATUS_BROKEN			= 2;

	DgcSqlClient			SohaClient;
	dgt_sint64			EncTgtSysID;
	pcamt_agent_list		AgentList[MAX_AGENTS]; // agent_id list
	dgt_uint8			NumAgents;
//	pcamt_agent_param	CryptAgentParam;
	dgt_schar*			CryptAgentBinPath;
	dgt_schar*			ClientAgentBinPath;
	dgt_schar*			UdsListenDir;
	dgt_schar*			UdsListenAddr;
	dgt_schar*			LogFileDir;
	const dgt_schar*	ConfFilePath;

	dgt_schar			PrimarySohaSvc[33];
	dgt_schar			PrimarySohaConnIP[65];
	dgt_uint16			PrimarySohaConnPort;
	dgt_schar			SecondarySohaSvc[33];
	dgt_schar			SecondarySohaConnIP[65];
	dgt_uint16			SecondarySohaConnPort;

	dgt_uint8			StopFlag;
	dgt_uint8			RunStep;
	dgt_uint8			SohaConnStatus;

	dgt_void openLogStream(const dgt_schar* log_file_path);

	dgt_sint32 connectMaster() throw(DgcExcept);
	dgt_sint32 getAgentList() throw(DgcExcept);
	dgt_sint32 sendAlertDeadProcess(dgt_sint64 pid, dgt_uint8 agent_type) throw(DgcExcept);
	dgt_sint32 execvCryptAgent(dgt_sint64 agent_id, dgt_uint8 agent_type, const dgt_schar* cmd) throw(DgcExcept);
	dgt_sint64 getCryptAgentPID(dgt_sint64 agent_id, dgt_uint8 agent_type) throw(DgcExcept);

	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  protected:
  public:
	PccCipherAgentManager();
	virtual ~PccCipherAgentManager();

	inline dgt_void askStop() { StopFlag = 1; };
	inline const dgt_sint64 encTgtSysID() { return EncTgtSysID; };
	inline const dgt_schar* udsListenAddr() { return UdsListenAddr; };
	inline pcamt_agent_list* agentList(dgt_sint32 idx) { return &AgentList[idx]; };

	dgt_sint32 initialize(const dgt_schar* conf_file_path) throw(DgcExcept);

	dgt_void getCryptManagerStatus(pcct_manager_status* status);
};



#endif
