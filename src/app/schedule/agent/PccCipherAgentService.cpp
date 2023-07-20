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
#if 0
#define DEBUG
#endif

#include "PccCipherAgentService.h"

PccCipherAgentService::PccCipherAgentService()
	: Repository(JobPool)
{
	CurrSession = 0;
	CryptJob = 0;
	NumManagers = 0;
	NoSessionSleepCount = 0;
	UdsListenAddr = 0;
	StopFlag = 0;
	AgentMode = 0;
	EncColName = 0;
	HeaderFlag = 0;
	BufferSize = 0;
}


PccCipherAgentService::~PccCipherAgentService()
{
	if (UdsListenAddr) delete UdsListenAddr;
	if (EncColName) delete EncColName;
	if (HeaderFlag) delete HeaderFlag;
}


dgt_void PccCipherAgentService::openLogStream(const dgt_schar* log_file_path)
{
	for (;DgcWorker::PLOG.logStream() == 0;) {
		DgcFileStream* fs = new DgcFileStream(log_file_path,O_CREAT|O_APPEND|O_WRONLY,0666);
		if (EXCEPT) {
			delete EXCEPTnC;
			fs = 0;
		}
		if (fs) {
			DgcWorker::PLOG.setLog(10,DGC_TRUE,new DgcBufferStream(fs,1));
			break;
		}
		fs = new DgcFileStream("/tmp/cipher_agent.log",O_CREAT|O_APPEND|O_WRONLY,0666);
		if (EXCEPT) {
			delete EXCEPTnC;
			fs = 0;
		}
		if (fs) {
			DgcWorker::PLOG.setLog(10,DGC_TRUE,new DgcBufferStream(fs,1));
			break;
		}
		fs = new DgcFileStream(0,1);
		DgcWorker::PLOG.setLog(10,DGC_TRUE,new DgcBufferStream(fs,1));
		break;
    	}
}

dgt_sint32 PccCipherAgentService::setConf(PccAgentCryptJob *job, DgcBgrammer *bg) throw(DgcExcept)
{
	dgt_sint32 trace_level = 0;
	dgt_sint64 agent_id = 0;
	dgt_sint32 file_queue_size = 0;
	dgt_sint32 fail_file_queue_size = 0;
	dgt_sint32 nullity_file_queue_size = 0;
	dgt_sint32 max_use_cores = 0;
	dgt_sint32 collect_interval = 0;
	dgt_schar *val;

	if ((val = bg->getValue("agent.id"))){
		agent_id = dg_strtoll(val, 0, 10);
	}	
	else {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE, new DgcError(SPOS, "agent.id not defined[%s]", bg->getText())), -1);
	}

	if (JobPool.agentID() == 0)
		JobPool.setAgentID(agent_id);
	
	if ((val = bg->getValue("agent.log_file_path"))){
		openLogStream(val);
	}	
	else {
		openLogStream("/var/tmp/.petra/pcp_crypt_agent.log");
	}

	if ((val = bg->getValue("agent.max_target_files")))
	{
		file_queue_size = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		file_queue_size = 0;
	}
	JobPool.setFileQueueSize(file_queue_size);

	if ((val = bg->getValue("agent.max_fail_files")))
	{
		fail_file_queue_size = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		fail_file_queue_size = 0;
	}
	JobPool.setFailFileQueueSize(fail_file_queue_size);

	if ((val = bg->getValue("agent.max_nullity_files")))
	{
		nullity_file_queue_size = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		nullity_file_queue_size = 0;
	}
	JobPool.setNullityFileQueueSize(nullity_file_queue_size);

	if ((val = bg->getValue("agent.max_use_cores")))
	{
		max_use_cores = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		max_use_cores = 4;
	}
	Repository.corePool().setCores(max_use_cores);

	if ((val = bg->getValue("agent.init_managers")))
	{
		NumManagers = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		NumManagers = 1;
	}

	if ((val = bg->getValue("agent.no_session_sleep_count")))
	{
		NoSessionSleepCount = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		NoSessionSleepCount = 5;
	}

	if ((val = bg->getValue("agent.collecting_interval")))
	{
		collect_interval = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		collect_interval = 10;
	}
	JobPool.setCollectInterval(collect_interval);

	if ((val = bg->getValue("agent.trace_level")))
	{
		trace_level = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		trace_level = 0;
	}
	JobPool.setTraceLevel(trace_level);

	// for unix domain socket stream
	if ((val = bg->getValue("agent.uds_listen_addr")))
	{
		dgt_sint32 addr_len = dg_strlen(val) + 100;
		UdsListenAddr = new dgt_schar[addr_len];
		sprintf(UdsListenAddr, "%s/pcp_crypt_agent_%lld.s", val, JobPool.agentID());
	}
	else
	{
		UdsListenAddr = new dgt_schar[129];
		sprintf(UdsListenAddr, "/var/tmp/.petra/pcp_crypt_agent_%lld.s", JobPool.agentID());
	}
	// added by mwpark 18.10.03
	// for performance test
	// agent_mode = 0: default
	//              1: private session & controlling file owner
	//              2: no bgrammer, key, header flag, buffer_size (config_file)
	if ((val = bg->getValue("agent.mode")))
	{
		AgentMode = (dgt_sint32)dg_strtoll(val, 0, 10);
	}
	else
	{
		AgentMode = 0;
	}

	if (AgentMode >= 2)
	{
		if ((val = bg->getValue("agent.enc_col_name")))
		{
			EncColName = new dgt_schar[128];
			memset(EncColName, 0, 128);
			memcpy(EncColName, val, strlen(val));
		}
		if ((val = bg->getValue("agent.header_flag")))
		{
			HeaderFlag = new dgt_schar[128];
			memset(HeaderFlag, 0, 128);
			memcpy(HeaderFlag, val, strlen(val));
		}
		if ((val = bg->getValue("agent.buffer_size")))
		{
			BufferSize = (dgt_sint32)dg_strtoll(val, 0, 10);
		}
	}

	return 0;
}

dgt_void PccCipherAgentService::in() throw(DgcExcept)
{
	// start managers
	if (Repository.managerPool().addManagers(NumManagers>0 ? NumManagers : INIT_MANAGERS, AgentMode, EncColName, HeaderFlag, BufferSize) < 0) {
		DgcExcept*	e=EXCEPTnC;
		while(Repository.managerPool().numManagers() > 0) {
			Repository.managerPool().stopManagers(0);
			sleep(3);
			if (Repository.managerPool().cleanManagers(1) < 0) {
				DgcExcept* e=EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"cleanManagers failed:\n");
				delete e;
			}
		}
		RTHROW(e,DgcError(SPOS,"addManagers failed"));
	}

	DgcWorker::PLOG.tprintf(0,"agent[%lld] service starts\n",JobPool.agentID());
}


dgt_sint32 PccCipherAgentService::run() throw(DgcExcept)
{
	if (StopFlag) return 1;
	//check session connection and reconnection about broken session
	dgt_sint32 rtn = 0;
		if ((rtn=SessionPool.cleanBrokenSessions()) < 0) {
			DgcExcept* e = EXCEPTnC;
			if (e) {
				DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] cleanBrokenSessions failed :\n",JobPool.agentID());
				delete e;
			}
		}
		if (rtn) DgcWorker::PLOG.tprintf(0,"broken session count : [%d]\n",rtn);
		if (SessionPool.startNewSessions(JobPool,NoSessionSleepCount) < 0) {
			DgcExcept* e = EXCEPTnC;
			if (e) {
				DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] startNewSessions Failed :\n",JobPool.agentID());
				delete e;
			}
		}
	sleep(NoSessionSleepCount);
	return 0;
}


dgt_void PccCipherAgentService::out() throw(DgcExcept)
{
	dgt_sint32 stop_cnt = 0;
	if (SessionPool.stopSessions()) {
		DgcExcept*  e = EXCEPTnC;
		DgcWorker::PLOG.tprintf(0,*e,"stopSessions failed:");
		delete e;
	}
	while (stop_cnt < Repository.managerPool().numManagers()) {
		stop_cnt += Repository.managerPool().stopManagers(0);
		sleep(1);
	}
	if (Repository.managerPool().cleanManagers(1) < 0) {
		DgcExcept*  e = EXCEPTnC;
		DgcWorker::PLOG.tprintf(0,*e,"cleanManagers failed:");
		delete e;
	}
	if (CryptJob) {
		CryptJob->unlockShare();
		if (JobPool.dropJob(CryptJob->jobID()) < 0) {
			DgcExcept*  e = EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"dropJob[%lld] failed:",CryptJob->jobID());
			delete e;
		}
	} else CryptJob = 0;

	DgcWorker::PLOG.tprintf(0,"agent[%lld] service ends.\n",JobPool.agentID());
}


dgt_sint32 PccCipherAgentService::initialize(
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
		dgt_schar* secondary_sess_ip,
		dgt_uint16 secondary_sess_port) throw(DgcExcept)
{
	// create job (job_id == 0) to executing PccGetDirEntryStmt
	if ((CryptJob=JobPool.newJob(0)) == 0) ATHROWnR(DgcError(SPOS,"newJob failed"),-1);
	if (CryptJob->lockShare() < 0) ATHROWnR(DgcError(SPOS,"lockShare job_id[%lld] failed",CryptJob->jobID()),-1);

	if (agent_id == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"agent.id not defined")),-1);
	}

	dgt_sint32 path_len = dg_strlen(log_dir) + 30;
	dgt_schar* log_file_path = new dgt_schar[path_len];
	sprintf(log_file_path,"%s/cipher_agent.log",log_dir);
	openLogStream(log_file_path);
	delete log_file_path;

	JobPool.setAgentID(agent_id);
	JobPool.setFileQueueSize(max_target_files);
	Repository.corePool().setCores(max_use_cores);
	NumManagers = init_managers;
	JobPool.setCollectInterval(collect_interval);
	NoSessionSleepCount = no_sess_sleep_conunt;
	JobPool.setTraceLevel(trace_level);

	// for unix domain socket stream
	dgt_sint32 addr_len = dg_strlen(uds_listen_dir) + 100;
	UdsListenAddr = new dgt_schar[addr_len];
	sprintf(UdsListenAddr,"%s/pcp_crypt_agent_%lld.s",uds_listen_dir,agent_id);

	if (SessionPool.initialize(num_sessions, primary_sess_ip,primary_sess_port,secondary_sess_ip,secondary_sess_port) < 0){
		ATHROWnR(DgcError(SPOS,"initialize session_pool failed"),-1);
	}
	return 0;
}


dgt_sint32 PccCipherAgentService::initialize(const dgt_schar* conf_file_path, dgt_sint64 agent_id) throw(DgcExcept)
{
	DgcBgmrList	params(conf_file_path);
	ATHROWnR(DgcError(SPOS,"parse[%s] failed",conf_file_path),-1);
	DgcBgrammer*    bg = 0;

	// create job (job_id == 0) to executing PccGetDirEntryStmt
	if ((CryptJob=JobPool.newJob(0)) == 0) ATHROWnR(DgcError(SPOS,"newJob failed"),-1);
	if (CryptJob->lockShare() < 0) ATHROWnR(DgcError(SPOS,"lockShare job_id[%lld] failed",CryptJob->jobID()),-1);

	if (agent_id) JobPool.setAgentID(agent_id);
	while((bg=params.getNext())) {
		if (setConf(CryptJob,bg) < 0) ATHROWnR(DgcError(SPOS,"setParams failed"),-1);
	}
	
	return 0;
}


dgt_void PccCipherAgentService::getCryptAgentStatus(pcct_agent_status* status)
{
	if (status) {
		status->agent_id = agentID();
		status->agent_pid = (dgt_sint64)getpid();
		status->max_target_files = JobPool.fileQueueSize();
		status->max_use_cores = Repository.corePool().totalCores();
		status->num_managers = Repository.managerPool().numManagers();
		status->num_jobs = JobPool.numJobs();
	}
}


#include "revision.h"
#include "DgcSigManager.h"

void help_message()
{
	printf("Usage: pcp_crypt_agent [OPTIONS] <start|stop|status>\n");
	printf("\n Examples:\n");
	printf("    pcp_crypt_agent start\t\t\t\t# start the agent using agent.conf\n");
	printf("    pcp_crypt_agent -c agent2.conf -i 377 start\t\t# start the agent using agent2.conf and agent_id 377\n");
	printf("    pcp_crypt_agent -c agent2.conf -i 377 stop\t\t# stop the agent using agent2.conf and agent_id 377\n");
	printf("    pcp_crypt_agent -c agent2.conf -i 377 -v status\t# display the agent's detailed status using agent2.conf and agent_id 377\n");

	printf("\n Options:\n");
	printf("    -h\t display this help and exit\n");
	printf("    -c\t set configure file path [default: agent.conf]\n");
	printf("    -i\t use specified agent_id (overrides -c options) \n");
	printf("    -v\t display detailed agent job status (with status command)\n");
}

int main(dgt_sint32 argc,dgt_schar** argv)
{
	dgt_sint32 verbose_flag = 0;
	dgt_sint64 agent_id = 0;
	dgt_schar conf_file_path[2048];
	memset(conf_file_path, 0, sizeof(conf_file_path));

	if (argc < 2) {
		printf("revision : %d\n",cipher_revision());
//		printf("usage: pcp_crypt_agent <conf file path> <start|stop|status> [agent_id]\n");
		help_message();
		return -1;
	}
	
	dgt_schar	ch;
	while ((ch = dg_getopt(argc, argv, "hvc:i:")) != (dgt_schar)EOF)
	{
		switch (ch)
		{
			case 'h':
				help_message();
				return 0;
			case 'v':
				verbose_flag = 1;
				break;
			case 'c':
				memcpy(conf_file_path, optarg, strlen(optarg));
				break;
			case 'i':
				agent_id = dg_strtoll(optarg, 0, 10);
				break;
			case '?':
				help_message();
				return -1;
		}
	}
	if (!strlen(conf_file_path)) sprintf(conf_file_path, "agent.conf");
	
	dgt_schar* cmd = 0;
	dgt_sint32 remain_param = argc - optind;
	if (remain_param == 1) {	
		cmd = argv[optind];
	} else if (remain_param == 2) {	// for compatibility; pcp_crypt_agent <conf file path> <start|stop|staus>
		sprintf(conf_file_path, argv[optind]);
		cmd = argv[optind+1];
	} else if (remain_param == 3) { // fro compatibility; pcp_crypt_agent <conf file path> <start|stop|status> [agent_id]
		sprintf(conf_file_path, argv[optind]);
		cmd = argv[optind+1];
		agent_id = dg_strtoll(argv[optind+2], 0, 10);
	} else {
		printf("command <start|stop|status> is not entered or there are too many arguments\n");
		help_message();
		exit(100);
	}

	PccCipherAgentService*	agent_service = new PccCipherAgentService();
	
	if (agent_service->initialize(conf_file_path, agent_id) < 0)
	{
		DgcExcept *e = EXCEPTnC;
		e->print();
		DgcWorker::PLOG.tprintf(0, *e, "initialize[%s] failed:\n", conf_file_path);
		delete e;
		printf("initialize[%s] failed.\n", conf_file_path);
		return -2;
	}

	if (strcasecmp(cmd,"start")) {
		DgcExcept* msg_e = 0;
		// set msg_type
		if (!strcasecmp(cmd,"stop")) {
			msg_e = new DgcExcept(PCC_AGENT_UDS_MSG_TYPE_STOP,0);
		} else if(!strcasecmp(cmd,"status")) {
			if (!verbose_flag) {
				msg_e = new DgcExcept(PCC_AGENT_UDS_MSG_TYPE_STATUS,0);
			} else {
				msg_e = new DgcExcept(PCC_AGENT_UDS_MSG_TYPE_DETAIL_STATUS,0);
			}
		} else {
			printf("invalid command [%s], it should be <start|stop|status>\n",cmd);
			help_message();
			exit(100);
		}

		DgcUnixClient client_stream;
		if (client_stream.connectServer(agent_service->udsListenAddr(),10) < 0) {
			printf("agent_service[%lld] connectServer[%s] failed:\n",agent_service->agentID(),agent_service->udsListenAddr());
			DgcExcept*  e = EXCEPTnC;
			if (e) {
				e->print();
				delete e;
			}
			return -3;
		}
		// connect server
		DgcSession	session;
		session.setSessType(DGC_MSB,DGC_NUM_TYPE,(dgt_uint8*)DGC_TYPE_LENGTH,(dgt_uint8*)DGC_TYPE_STRIDE);
		DgcPacketStream pkt_stream(&session,&client_stream);
		DgcDgMsgStream  msg_stream(&session,&pkt_stream);

		DgcMsgDgiExt result_ext;
		result_ext.putExcept(msg_e);
		if (msg_stream.sendMessage(&result_ext) != 0) {
			DgcExcept* e = EXCEPTnC;
			if (e) {
				e->print();
				delete e;
			}
		}
		if (msg_e) delete msg_e;

		// recv result
		DgcMessage*	msg = 0;
		if (!strcasecmp(cmd,"stop")) {
			for (;;) {
				if (msg_stream.recvMessage(10) <= 0) {
					DgcExcept*	e = EXCEPTnC;
					if (e) {
						e->print();
						delete e;
					} else {
						printf("recvMessage[result_msg] time out\n");
					}
					exit(101);
				}
				if((msg=msg_stream.currMsg())->opi() != DGIEXT) {
					printf("not DGIEXT message[%d]\n",msg->opi());
					exit(102);
				}
				DgcMsgDgiExt* ext = (DgcMsgDgiExt*)msg;
				DgcExcept* result_e = ext?ext->getExcept():0;
				if (!result_e) {
					printf("stop agent_service[%lld] failed : [unknown error]\n",agent_service->agentID());
					break;
				}
				if (result_e->classid() == 0 && result_e->errCode() == 0) {
					printf("agent_service[%lld] stopped by command.\n",agent_service->agentID());
					break;
				} else if (result_e->classid() && result_e->errCode()) {
					result_e->print();
					printf("stop agent_service[%lld] failed.\n",agent_service->agentID());
					break;
				} else {
					printf("waiting[%d] until agent_service[%lld] stopped...\n",result_e->errCode(),agent_service->agentID());
				}
			}
		} else if(!strcasecmp(cmd,"status")) {
			if (msg_stream.recvMessage(10) <= 0) {
				DgcExcept*	e = EXCEPTnC;
				if (e) {
					e->print();
					delete e;
				} else {
					printf("recvMessage[status_msg] time out\n");
				}
				exit(103);
			}
			if((msg=msg_stream.currMsg())->opi() != PTDGILETTER) {
				printf("not PTDGILETTER message[%d]\n",msg->opi());
				exit(104);
			}
			PtMsgDgiLetter* letter = (PtMsgDgiLetter*)msg;
			printf("%s\n",letter->getBody());

			dgt_sint32 num_jobs = (dgt_sint32)dg_strtoll(letter->getPs(),0,10);
			if (num_jobs > 1) {
				for (dgt_sint32 i=0; i<num_jobs; i++) {
					if (msg_stream.recvMessage(10) <= 0) {
						DgcExcept*	e = EXCEPTnC;
						if (e) {
							e->print();
							delete e;
						} else {
							printf("recvMessage[job_status_msg] time out\n");
						}
						exit(103);
					}
					if((msg=msg_stream.currMsg())->opi() != PTDGILETTER) {
						printf("not PTDGILETTER message[%d]\n",msg->opi());
						exit(104);
					}
					letter = (PtMsgDgiLetter*)msg;
					printf("- %s\n",letter->getBody());
					if (verbose_flag) {
						dgt_sint32 num_dirs = (dgt_sint32)dg_strtoll(letter->getPs(),0,10);
						if (num_dirs > 0) {
							for (dgt_sint32 j=0; j<num_dirs; j++) {
								if (msg_stream.recvMessage(10) <= 0) {
									DgcExcept*	e = EXCEPTnC;
									if (e) {
										e->print();
										delete e;
									} else {
										printf("recvMessage[job_status_msg] time out\n");
									}
									exit(103);
								}
								if((msg=msg_stream.currMsg())->opi() != PTDGILETTER) {
									printf("not PTDGILETTER message[%d]\n",msg->opi());
									exit(104);
								}
								letter = (PtMsgDgiLetter*)msg;
								printf("    - %s\n",letter->getBody());
							}
						}
					}
				}
			}
			printf("\n");
		}

		exit(1);
	}

	/* start command begins */

	// 1. be a background process and group leader
	pid_t pid;
	dg_signal(SIGCHLD, SIG_IGN);
	if ((pid = fork()) < 0)
	{
		DgcExcept *e = EXCEPTnC;
		if (e)
		{
			e->print();
			DgcWorker::PLOG.tprintf(0, *e, "fork failed:\n");
			delete e;
		}
		else
		{
			DgcWorker::PLOG.tprintf(0, "fork failed: [unknown error]\n");
		}
		return -3;
	}
	// 2. parent exits and child is to be a deamon
	if (pid != 0)
		exit(0);
	// 3. be a group leader
	setsid();
	// 4. catch and set all catchable signals
	DgcSigManager::p()->regDefault();

	// 5. start unix server

	DgcUnixServer server_stream(5, 5);
	if (server_stream.listenServer(agent_service->udsListenAddr()) == 0)
	{
		DgcExcept *e = EXCEPTnC;
		if (e)
		{
			e->print();
			DgcWorker::PLOG.tprintf(0, *e, "agent_service[%lld] listenServer[%s] failed:\n", agent_service->agentID(), agent_service->udsListenAddr());
			delete e;
		}
		else
		{
			DgcWorker::PLOG.tprintf(0, "agent_service[%lld] listenServer[%s] failed: [unknown error]\n", agent_service->agentID(), agent_service->udsListenAddr());
		}
		return -4;
	}

	// 6. start agent_service
	agent_service->wa()->ThreadID = pthread_self();
	// DgcWorker::entry((dgt_void*)agent_service);
	if (agent_service->start() < 0)
	{
		DgcExcept *e = EXCEPTnC;
		if (e)
		{
			e->print();
			DgcWorker::PLOG.tprintf(0, *e, "starting agent_service[%lld] failed:\n", agent_service->agentID());
			delete e;
		}
		delete agent_service;
		return -5;
	}

	printf("- pcp_crypt_agent[%lld]'s starting.\n", agent_service->agentID());
	//
	// 7. wait & serve
	// msg_type : 1 - stop, 2- status
	//
	DgcSession session;
	session.setSessType(DGC_MSB, DGC_NUM_TYPE, (dgt_uint8 *)DGC_TYPE_LENGTH, (dgt_uint8 *)DGC_TYPE_STRIDE);

	while (1)
	{
		DgcCommStream *stream = 0;
		if ((stream = (DgcCommStream *)server_stream.acceptConnection(5)))
		{
			DgcPacketStream pkt_stream(&session, stream);
			DgcDgMsgStream msg_stream(&session, &pkt_stream);
			// recv msg_type
			if (msg_stream.recvMessage(10) <= 0)
			{
				DgcExcept *e = EXCEPTnC;
				if (e)
				{
					DgcWorker::PLOG.tprintf(0, *e, "recvMessage[msg_type] failed:\n");
					delete e;
				}
				else
				{
					DgcWorker::PLOG.tprintf(0, "recvMessage[msg_type] timeout.\n");
				}
				continue;
			}
			DgcMessage *msg = 0;
			if ((msg = msg_stream.currMsg())->opi() != DGIEXT)
			{
				DgcWorker::PLOG.tprintf(0, "not msg_type message[%d]\n", msg->opi());
				continue;
			}
			DgcMsgDgiExt *ext = (DgcMsgDgiExt *)msg;
			dgt_uint16 msg_type = ext->getExcept()->classid();
			msg_stream.resetIBuf();

			// check msg_type
			if (msg_type == PCC_AGENT_UDS_MSG_TYPE_STOP)
			{
				DgcExcept *result_e = 0;
				DgcMsgDgiExt result_ext;

				// askStop to terminate crypt_managers normal
				// for preventing from creating damaged encryption file
				agent_service->askStop();
				napAtick();
				// wake up workers
				agent_service->sendSignal(SIGUSR2);

				result_e = new DgcExcept(0, 0);
				result_ext.putExcept(result_e);
				dgt_sint32 wait_time = 0;
				while (agent_service->isAlive())
				{
					DgcWorker::PLOG.tprintf(0, "agent_service[%lld] : waiting until stoppd \n", agent_service->agentID());
					if (wait_time > 300)
					{
						if (agent_service->stop() < 0)
						{
							if (result_e)
								delete result_e;
							DgcExcept *e = EXCEPTnC;
							DgcWorker::PLOG.tprintf(0, *e, "agent_service[%lld] : stop failed:\n", agent_service->agentID());
							delete e;
							exit(-1);
						}
					}
					result_e->setErrCode(++wait_time);
					if (msg_stream.sendMessage(&result_ext) != 0)
					{
						DgcExcept *e = EXCEPTnC;
						if (e)
						{
							DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
							delete e;
						}
					}
					sleep(1);
				}
				// send success msg
				result_e->setErrCode(0);

				if (msg_stream.sendMessage(&result_ext) != 0)
				{
					DgcExcept *e = EXCEPTnC;
					if (e)
					{
						DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
						delete e;
					}
				}
				if (result_e && !result_e->errCode())
				{
					delete result_e;
					break; // terminate while loop for exit
				}
				if (result_e)
					delete result_e;
			}
			else if (msg_type == PCC_AGENT_UDS_MSG_TYPE_STATUS || msg_type == PCC_AGENT_UDS_MSG_TYPE_DETAIL_STATUS)
			{
				// send status msg
				pcct_agent_status agent_status;
				agent_service->getCryptAgentStatus(&agent_status);
				dgt_schar body[257];
				dgt_schar ps[65];
				sprintf(body, "agent_id[%lld] pid[%lld] max_target_files[%d] max_use_cores[%d] num_managers[%d] num_jobs[%d]",
						agent_status.agent_id,
						agent_status.agent_pid,
						agent_status.max_target_files,
						agent_status.max_use_cores,
						agent_status.num_managers,
						agent_status.num_jobs);
				PtMsgDgiLetter status_msg;
				status_msg.setBody(body);
				sprintf(ps, "%d", agent_status.num_jobs);
				status_msg.setPs(ps);
				if (msg_stream.sendMessage(&status_msg) != 0)
				{
					DgcExcept *e = EXCEPTnC;
					if (e)
					{
						DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
						delete e;
					}
				}

				if (agent_status.num_jobs > 1)
				{
					dgt_schar *job_body = new dgt_schar[512];
					PtMsgDgiLetter job_status_msg;
					for (dgt_sint32 i = 0; i < agent_status.num_jobs; i++)
					{
						PccAgentCryptJob *curr_job = agent_service->jobPool()->jobByIdx(i);
						dgt_sint64 job_id = 0;
						dgt_sint32 job_type = 0;
						dgt_uint8 job_status = 0;
						dgt_sint32 num_dirs = 0;
						if (curr_job)
						{
							job_id = curr_job->jobID();
							job_type = curr_job->repository().getJobType();
							job_status = curr_job->collector() ? curr_job->collector()->jobStatus() : 0;
							num_dirs = curr_job->repository().dirPool().numDirs();
						}
						sprintf(job_body, "job_id[%lld] job_type[%d] job_status[%u] num_dirs[%d]", job_id, job_type, job_status, num_dirs);
						job_status_msg.setBody(job_body);
						sprintf(ps, "%d", num_dirs);
						job_status_msg.setPs(ps);
						if (msg_stream.sendMessage(&job_status_msg) != 0)
						{
							DgcExcept *e = EXCEPTnC;
							if (e)
							{
								DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
								delete e;
							}
						}
						if (msg_type == PCC_AGENT_UDS_MSG_TYPE_DETAIL_STATUS)
						{
							if (num_dirs > 0)
							{
								dgt_schar *dir_body = new dgt_schar[4098];
								PtMsgDgiLetter dir_status_msg;
								for (dgt_sint32 j = 0; j < num_dirs; j++)
								{
									PccCryptDir *curr_dir = curr_job->repository().dirPool().getCryptDir(j);
									dgt_sint64 dir_id = 0;
									dgt_schar *src_dir = 0;
									dgt_schar *dst_dir = 0;
									dgt_sint32 dir_status = 0;
									if (curr_dir)
									{
										dir_id = curr_dir->dirID();
										src_dir = (dgt_schar *)curr_dir->srcDir();
										dst_dir = (dgt_schar *)curr_dir->dstDir();
										dir_status = curr_dir->status();
									}
									sprintf(dir_body, "dir_id[%lld] dir_status[%d] src_dir[%s] dst_dir[%s]", dir_id, dir_status, src_dir, dst_dir);
									dir_status_msg.setBody(dir_body);
									if (msg_stream.sendMessage(&dir_status_msg) != 0)
									{
										DgcExcept *e = EXCEPTnC;
										if (e)
										{
											DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
											delete e;
										}
									}
								}
								if (dir_body)
									delete dir_body;
							}
						}
					}
					if (job_body)
						delete job_body;
				}
			}
			else if (msg_type == PCC_AGENT_UDS_MSG_TYPE_GET_PID)
			{
				// send pid
				pcct_agent_status agent_status;
				agent_service->getCryptAgentStatus(&agent_status);
				dgt_schar body[33];
				sprintf(body, "%lld", agent_status.agent_pid);
				PtMsgDgiLetter status_msg;
				status_msg.setBody(body);
				if (msg_stream.sendMessage(&status_msg) != 0)
				{
					DgcExcept *e = EXCEPTnC;
					if (e)
					{
						DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
						delete e;
					}
				}
			}
			else
			{
				DgcWorker::PLOG.tprintf(0, "agent_service[%lld] invalid msg[%u] :\n", agent_service->agentID(), msg_type);
			}
		}
		napAtick();
	}

	printf("- pcp_crypt_agent[%lld] stopped\n", agent_service->agentID());
	delete agent_service;
	return 0;
}
