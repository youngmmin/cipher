/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaKeySvrSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 9
 *   Description        :       petra cipher key server session pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaKeySvrSessionPool.h"

//dgt_sint32	PcaKeySvrSessionPool::TraceLevel=0;
dgt_sint32      PcaKeySvrSessionPool::ThreadSessionCheckInterval=PcaKeySvrSessionPool::PKSSP_THRD_SESS_CHECK_INTERVAL;
dgt_sint32      PcaKeySvrSessionPool::ThreadSessionCleanInterval=PcaKeySvrSessionPool::PKSSP_THRD_SESS_CLEAN_INTERVAL;
dgt_sint32      PcaKeySvrSessionPool::ThreadSessionMaxSleep=PcaKeySvrSessionPool::PKSSP_THRD_SESS_MAX_SLEEP;
dgt_sint32      PcaKeySvrSessionPool::NumSharedSession = 10;
dgt_sint32      PcaKeySvrSessionPool::MaxPrivateSession = PcaKeySvrSessionPool::PKSSP_MAX_PRIVATE_SESSION;
dgt_uint32      PcaKeySvrSessionPool::RuleEffectiveTime = 0;
dgt_sint64      PcaKeySvrSessionPool::VlColID = 0;
dgt_sint32      PcaKeySvrSessionPool::VlLength = 0;
dgt_sint32      PcaKeySvrSessionPool::VlEncLength = 0;
PccFileMemMap*  PcaKeySvrSessionPool::TraceMemMap = 0;

PcaKeySvrSessionPool::PcaKeySvrSessionPool()
#ifndef WIN32
	: EncryptLocalFlag(PKSSP_DEFAULT_ELF),
	  DecryptLocalFlag(PKSSP_DEFAULT_DLF),
	  NewSqlInterval(0),
	  CurrNumSessions(0),
	  NumStarveSessions(0),
	  IpProbPos(0),
          MacProbIpPos(0),
          MacProbPos(0),
	  DoubleEncCheck(0),
          TrailerFlag(1),
	  ApiMode(0),
	  OpMode(0),
	  OltpLogMode(0),
          UdpPort1(0),
          ClientDatagram1(DgcSockDatagram::DGC_DGRAM_CLIENT,3,3),
          UdpBindFlag(0),
	  UdpPort2(0),
          ClientDatagram2(DgcSockDatagram::DGC_DGRAM_CLIENT,3,3),
          UdpBindFlag2(0)
#else
	: EncryptLocalFlag(PKSSP_DEFAULT_ELF),
          DecryptLocalFlag(PKSSP_DEFAULT_DLF),
          NewSqlInterval(0),
          CurrNumSessions(0),
          NumStarveSessions(0),
          IpProbPos(0),
          MacProbIpPos(0),
          MacProbPos(0),
          DoubleEncCheck(0),
          TrailerFlag(1),
          ApiMode(0),
          OpMode(0)
#endif
{
	DgcSpinLock::unlock(&PoolLatch);
	memset(SessionTable, 0, sizeof(SessionTable));
	for(dgt_sint32 i=0; i<PKSSP_MAX_STARVE_SESSIONS; i++) { StarvingQueue[i].degree = 0; StarvingQueue[i].svr_session = 0; }
	memset(SharedSessionIP,0,65);
	memset(SharedSessionUID,0,33);
	memset(SharedSessionProgram,0,129);
	memset(DefaultEncColName,0,129);
	memset(IpProbCmdPath,0,129);
        memset(IpProbCmdArgs,0,129);
	memset(MacProbCmdPath,0,129);
        memset(MacProbCmdArgs,0,129);
	memset(CharSet,0,33);
        memset(InstanceName,0,33);
        memset(DbName,0,33);
//        strncpy(CharSet,"UTF-8",5);
#ifndef WIN32
	memset(UdpHost1,0,65);
	memset(UdpHost2,0,65);
#endif
	memset(KeyInfoFilePath,0,516);
	DecryptFailSrcRtnFlag = 0;
	//TraceLevel = 0;
	KcmvpMode = 0;
	TraceMemMap = 0;
}


PcaKeySvrSessionPool::~PcaKeySvrSessionPool()
{
	for(dgt_sint32 i=0; i<CurrNumSessions; i++) delete SessionTable[i];
}


#include "PcaNameValuePair.h"
#include "PcaKeySvrSessionSoha.h"
#ifndef WIN32
#include "PcaKcmvpModule.h"
#endif


dgt_sint32 PcaKeySvrSessionPool::initialize(dgt_schar* conf_file_path,const dgt_schar* credentials_pw, dgt_sint32 stand_alone_flag)
{
	dgt_sint32		keysvr_sessions=0;
	PcaNameValuePair	nvp;
	dgt_sint32		rtn=0;

	if ((rtn=nvp.parseFromFile(conf_file_path=PcaKeySvrSession::findConfPath(conf_file_path)))) {
		if (stand_alone_flag == 0) logging(rtn, nvp.errMsg());
        } else {
		dgt_sint32  conf_file_path_len = strlen(conf_file_path);
		dgt_schar*  trace_conf_file_path = new dgt_schar[conf_file_path_len + 15]; //added by shson 20200212 for realtime tracelevel setting
		memset(trace_conf_file_path, 0, conf_file_path_len + 15);
		dgt_schar*	log_file_path = nvp.getValue("log_file_path");
		dgt_uint32      no_log_interval = 0;
                dgt_schar*      val=0;
                if ((val=nvp.getValue("same_err_no_log_interval"))) no_log_interval=strtol(val,0,10);
                PcaLogger::initialize(log_file_path, no_log_interval);
		//added by shson 20200212 for realtime tracelevel setting
#ifndef WIN32
		//extract ConfPath
		for (dgt_sint32 i = 0; i < strlen(conf_file_path); i++)
		{
			if (*(conf_file_path + conf_file_path_len - i) == '/') {
				i--; // for include '/'
				strncpy(trace_conf_file_path, conf_file_path, conf_file_path_len - i);
				break;
			} 
		}
#else
		strcpy(trace_conf_file_path,"C:\\Program Files\\SINSIWAY\\Petra\\api\\");
#endif
		strcat(trace_conf_file_path, "PetraTrace.conf");
		if (!TraceMemMap) TraceMemMap = new PccFileMemMap;
		if (TraceMemMap && TraceMemMap->isLoaded() == 0 && TraceMemMap->load(trace_conf_file_path, 1, 0) < 0) {
			DgcExcept* e = EXCEPTnC; if (e) delete e;
			rtn = -66101;
			logging("error code : %d TraceMemMap load failed [%s]", rtn, trace_conf_file_path);
		}
		delete trace_conf_file_path;
		//if ((val=nvp.getValue("trace_level"))) TraceLevel = strtol(val,0,10);
		if ((val=nvp.getValue("encrypt_local_flag"))) EncryptLocalFlag = strtol(val,0,10);
		if ((val=nvp.getValue("decrypt_local_flag"))) DecryptLocalFlag = strtol(val,0,10);
		//if ((val=nvp.getValue("new_sql_interval"))) NewSqlInterval = strtol(val,0,10);
		if ((val=nvp.getValue("keysvr.sessions"))) keysvr_sessions = strtol(val,0,10);
		if ((val=nvp.getValue("num_shared_session"))) NumSharedSession=strtol(val,0,10);
		if ((val=nvp.getValue("shared_session_ip"))) strncpy(SharedSessionIP,val,64);
		if ((val=nvp.getValue("shared_session_uid"))) strncpy(SharedSessionUID,val,32);
		if ((val=nvp.getValue("shared_session_program"))) strncpy(SharedSessionProgram,val,128);
		if ((val=nvp.getValue("max_private_session"))) MaxPrivateSession=strtol(val,0,10);
		if ((val=nvp.getValue("default_enc_col_name"))) strncpy(DefaultEncColName,val,128);
		if ((val=nvp.getValue("ip_prob_cmd_path"))) strncpy(IpProbCmdPath,val,128);
                if ((val=nvp.getValue("ip_prob_cmd_args"))) strncpy(IpProbCmdArgs,val,128);
                if ((val=nvp.getValue("ip_prob_pos"))) IpProbPos=strtol(val,0,10);
		if ((val=nvp.getValue("mac_prob_cmd_path"))) strncpy(MacProbCmdPath,val,128);
                if ((val=nvp.getValue("mac_prob_cmd_args"))) strncpy(MacProbCmdArgs,val,128);
                if ((val=nvp.getValue("mac_prob_ip_pos"))) MacProbIpPos=strtol(val,0,10);
                if ((val=nvp.getValue("mac_prob_pos"))) MacProbPos=strtol(val,0,10);
		if ((val=nvp.getValue("thread_session_check_interval"))) ThreadSessionCheckInterval=strtol(val,0,10);
                if ((val=nvp.getValue("thread_session_clean_interval"))) ThreadSessionCleanInterval=strtol(val,0,10);
                if ((val=nvp.getValue("thread_session_max_sleep"))) ThreadSessionMaxSleep=strtol(val,0,10);
		if ((val=nvp.getValue("char_set"))) strncpy(CharSet,val,32);
                if ((val=nvp.getValue("instance_name"))) strncpy(InstanceName,val,32);
                if ((val=nvp.getValue("db_name"))) strncpy(DbName,val,32);
		if ((val=nvp.getValue("double_enc_check")) && strncasecmp("yes",val,3) == 0) DoubleEncCheck=1;
                if ((val=nvp.getValue("trailer_flag"))) TrailerFlag=strtol(val,0,10);
		if ((val=nvp.getValue("rule_effective_time"))) RuleEffectiveTime=strtol(val,0,10);
                if ((val=nvp.getValue("api_mode"))) ApiMode=strtol(val,0,10);
                if ((val=nvp.getValue("op_mode"))) OpMode=strtol(val,0,10);
#ifndef WIN32
		if ((val=nvp.getValue("oltp_log_mode"))) OltpLogMode=(dgt_uint8)strtol(val,0,10);
		if ((val=nvp.getValue("udp_host1"))) strncpy(UdpHost1,val,64);
		if ((val=nvp.getValue("udp_port1"))) UdpPort1=(dgt_uint16)strtol(val,0,10);
		if ((val=nvp.getValue("udp_host2"))) strncpy(UdpHost2,val,64);
		if ((val=nvp.getValue("udp_port2"))) UdpPort2=(dgt_uint16)strtol(val,0,10);
#endif
                if ((val=nvp.getValue("vl_col_id"))) VlColID=strtol(val,0,10);
                if ((val=nvp.getValue("vl_length"))) VlLength=strtol(val,0,10);
                if ((val=nvp.getValue("vl_enc_length"))) VlEncLength=strtol(val,0,10);

#if 1 // added by chchung 2017.6.11 for adding system level standalone mode
                if ((val=nvp.getValue("key_info_file"))) {
			strncpy(KeyInfoFilePath,val,512);
			if (*KeyInfoFilePath) stand_alone_flag = 1;
		}
#endif
#if 1 // added by chchung 2017.6.20 for allowing optional decrypting error handling
                if ((val=nvp.getValue("decrypt_fail_src_rtn")) && strncasecmp(val,"yes",3) == 0) DecryptFailSrcRtnFlag = 1;
#endif

#if 1 // added by chchung 2017.12.06 for allowing System Name & Syatem IP
                if ((val=nvp.getValue("system_name"))) {
                        memset(SystemName,0,65);
                        strncpy(SystemName,val,64);
                }
                if ((val=nvp.getValue("system_ip"))) {
                        memset(SystemIp,0,65);
                        strncpy(SystemIp,val,64);
                }
#endif
                if ((val=nvp.getValue("kcmvp_mode"))) KcmvpMode=strtol(val,0,10);


if (traceLevel() > 0) {
	logging("stand_alone_flag => [%d]",stand_alone_flag);
	//logging("trace_level => [%u]",TraceLevel);
	logging("configuration file[%s] parsed.",conf_file_path ? conf_file_path:"");
	logging("log_file_path => [%s]",log_file_path ? log_file_path:"");
	logging("encrypt_local_flag => [%d]",EncryptLocalFlag);
	logging("decrypt_local_flag => [%d]",DecryptLocalFlag);
	logging("new_sql_interval => [%lld]",NewSqlInterval);
	logging("same_err_no_log_interval => [%u]",no_log_interval);
	logging("keysvr.sessions => [%u]",keysvr_sessions);
	logging("num_shared_session => [%u]",NumSharedSession);
	logging("shared_session_ip => [%s]",SharedSessionIP);
	logging("shared_session_uid => [%s]",SharedSessionUID);
	logging("shared_session_program => [%s]",SharedSessionProgram);
	logging("max_private_session => [%d]",MaxPrivateSession);
	logging("default_enc_col_name => [%s]",DefaultEncColName);
	logging("ip_prob_cmd_path => [%s]",IpProbCmdPath);
        logging("ip_prob_cmd_args => [%s]",IpProbCmdArgs);
        logging("ip_prob_pos => [%d]",IpProbPos);
	logging("mac_prob_cmd_path => [%s]",MacProbCmdPath);
        logging("mac_prob_cmd_args => [%s]",MacProbCmdArgs);
        logging("mac_prob_ip_pos => [%d]",MacProbIpPos);
        logging("mac_prob_pos => [%d]",MacProbPos);
	logging("thread_session_check_interval => [%d]",ThreadSessionCheckInterval);
        logging("thread_session_clean_interval => [%d]",ThreadSessionCleanInterval);
        logging("thread_session_max_sleep => [%d]",ThreadSessionMaxSleep);
	logging("char_set => [%s]",CharSet);
        logging("instance_name => [%s]",InstanceName);
        logging("db_name => [%s]",DbName);
	logging("double_enc_check => [%d]",DoubleEncCheck);
        logging("trailer_flag=> [%d]",TrailerFlag);
        logging("rule_effective_time=> [%d]",RuleEffectiveTime);
	logging("api_mode=> [%d]",ApiMode);
	logging("op_mode=> [%d]",OpMode);
	logging("key_info_file=> [%s]",KeyInfoFilePath);
	logging("decrypt_fail_src_rtn=> [%d]",DecryptFailSrcRtnFlag);
	logging("system_name=> [%s]",SystemName);
	logging("system_ip=> [%s]",SystemIp);
	logging("kcmvp_mode=> [%d]",KcmvpMode);
}
	}
	if (stand_alone_flag == 0) {
		if (keysvr_sessions == 0) keysvr_sessions=1;
		for(dgt_sint32 i=0; i<keysvr_sessions; i++) {
			SessionTable[CurrNumSessions++] = new PcaKeySvrSessionSoha();
		}
if (traceLevel() > 0) logging("%d key server sessions created",CurrNumSessions);

#if 1 // modified by chchung 2015.9.13 for adding test mode
		for(dgt_sint32 i=0; OpMode < PCI_OP_NO_PULL_NO_PUSH && i < CurrNumSessions; i++) {
#else
		for(dgt_sint32 i=0; i<CurrNumSessions; i++) {
#endif
			dgt_sint32	tmp_rtn=0;
			if ((tmp_rtn=SessionTable[i]->initialize(credentials_pw))) logging(tmp_rtn,SessionTable[i]->errMsg());
		}
if (traceLevel() > 0) logging("%d key server sessions initialized",CurrNumSessions);
	}
#ifndef WIN32
        if (KcmvpMode) {
                PcaKcmvpModule klib_module;
                dgt_sint32 tmp_rtn=klib_module.initializeModule();
                if (tmp_rtn) logging("KCMVP KLIB module loading failed[%d] \n", tmp_rtn);
                return tmp_rtn;
        }
#endif
	return rtn;
}
