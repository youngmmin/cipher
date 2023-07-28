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
#if 0
#define DEBUG
#endif

#include "PccCipherAgentManager.h"

const dgt_schar PccCipherAgentManager::SOHA_CONN_STRING[] =
    "(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)(SID=%s)(CONN_TIMEOUT=%d)(IN_"
    "TIMEOUT=%d)(OUT_TIMEOUT=%d))";

const dgt_schar PccCipherAgentManager::CRYPT_AGENT_CONN_STRING[] =
    "%s/pcp_crypt_agent_%lld.s";

const dgt_schar PccCipherAgentManager::CLIENT_AGENT_CONN_STRING[] =
    "%s/pcp_client_agent_%lld.s";

PccCipherAgentManager::PccCipherAgentManager()
    : SohaClient(50), EncTgtSysID(0) {
    for (dgt_uint8 i = 0; i < MAX_AGENTS; i++)
        memset(&AgentList[i], 0, sizeof(pcamt_agent_list));
    NumAgents = 0;
    //	memset(&CryptAgentParam,0,sizeof(pcamt_agent_param));
    CryptAgentBinPath = 0;
    ClientAgentBinPath = 0;
    UdsListenDir = 0;
    UdsListenAddr = 0;
    LogFileDir = 0;

    memset(PrimarySohaSvc, 0, 33);
    memset(SecondarySohaSvc, 0, 33);
    memset(PrimarySohaConnIP, 0, 65);
    memset(SecondarySohaConnIP, 0, 65);
    PrimarySohaConnPort = 0;
    SecondarySohaConnPort = 0;

    StopFlag = 0;
    RunStep = STEP_INIT;
    SohaConnStatus = SOHA_CONN_STATUS_NONE;
}

PccCipherAgentManager::~PccCipherAgentManager() {
    if (CryptAgentBinPath) delete CryptAgentBinPath;
    if (ClientAgentBinPath) delete ClientAgentBinPath;
    if (UdsListenDir) delete UdsListenDir;
    if (UdsListenAddr) delete UdsListenAddr;
    if (LogFileDir) delete LogFileDir;
}

dgt_void PccCipherAgentManager::openLogStream(const dgt_schar* log_file_path) {
    for (; DgcWorker::PLOG.logStream() == 0;) {
        DgcFileStream* fs = new DgcFileStream(
            log_file_path, O_CREAT | O_APPEND | O_WRONLY, 0666);
        if (EXCEPT) {
            delete EXCEPTnC;
            fs = 0;
        }
        if (fs) {
            DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
            break;
        }
        fs = new DgcFileStream(0, 1);
        DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
        break;
    }
}

dgt_sint32 PccCipherAgentManager::connectMaster() throw(DgcExcept) {
    if (SohaConnStatus == SOHA_CONN_STATUS_CONNECTED) return 0;
    dgt_schar* conn_string = new dgt_schar[512];
    memset(conn_string, 0, 512);
    dg_sprintf(conn_string, SOHA_CONN_STRING, PrimarySohaConnIP,
               PrimarySohaConnPort, PrimarySohaSvc, SOHA_CONN_TIMEOUT,
               SOHA_CONN_TIMEOUT, SOHA_CONN_TIMEOUT);
    if (SohaClient.connectDB(conn_string, "dgadmin", "petra@one1", "attach",
                             "pcp_crypt_manager") < 0) {
        // connect secondary
        if (*SecondarySohaConnIP && SecondarySohaConnPort) {
            DgcExcept* e = EXCEPTnC;
            DgcWorker::PLOG.tprintf(
                0, *e, "connectDB to primary[%s:%u:%s]failed\n",
                PrimarySohaConnIP, PrimarySohaConnPort, PrimarySohaSvc);
            delete e;
            DgcWorker::PLOG.tprintf(0, "try connectDB to secondary\n");

            dg_sprintf(conn_string, SOHA_CONN_STRING, SecondarySohaConnIP,
                       SecondarySohaConnPort, SecondarySohaSvc,
                       SOHA_CONN_TIMEOUT, SOHA_CONN_TIMEOUT, SOHA_CONN_TIMEOUT);
            if (SohaClient.connectDB(conn_string, "dgadmin", "petra@one1",
                                     "attach", "pcp_crypt_manager") < 0) {
                if (conn_string) delete conn_string;
                ATHROWnR(
                    DgcError(SPOS, "connectDB to secondary[%s:%u:%s] failed",
                             SecondarySohaConnIP, SecondarySohaConnPort,
                             SecondarySohaSvc),
                    -1);
            }
        } else {
            if (conn_string) delete conn_string;
            ATHROWnR(
                DgcError(SPOS, "connectDB[%s:%u:%s]failed\n", PrimarySohaConnIP,
                         PrimarySohaConnPort, PrimarySohaSvc),
                -1);
        }
    }
    if (conn_string) delete conn_string;
    SohaConnStatus = SOHA_CONN_STATUS_CONNECTED;
    return 0;
}

dgt_sint32 PccCipherAgentManager::getAgentList() throw(DgcExcept) {
    if (connectMaster() < 0) {
        SohaConnStatus = SOHA_CONN_STATUS_BROKEN;
        ATHROWnR(DgcError(SPOS, "connectMaster failed"), -1);
    }
    dgt_schar sql_text[129];
    sprintf(sql_text,
            "select agent_id from pfct_agent where enc_tgt_sys_id=%lld",
            EncTgtSysID);
    if (SohaClient.execute(sql_text) < 0) {
        SohaConnStatus = SOHA_CONN_STATUS_BROKEN;
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    }

    dgt_sint32 frows = 0;
    if ((frows = SohaClient.fetch()) < 0) {
        SohaConnStatus = SOHA_CONN_STATUS_BROKEN;
        ATHROWnR(DgcError(SPOS, "fetch failed"), -1);
    }

    DgcMemRows* rtn_rows = SohaClient.returnRows();
    if (rtn_rows == 0) {
        THROWnR(DgcDbNetExcept(
                    DGC_EC_DN_INVALID_ST,
                    new DgcError(SPOS,
                                 "no agent_id pfct_agent.enc_tgt_sys_id[%lld]",
                                 EncTgtSysID)),
                -1);
    }
    // added by shson for client_tool 2018.05.24
    // pfct_agent table is modifed
    typedef struct {
        dgt_sint64 agent_id;
    } pcamt_agent_info;

    pcamt_agent_info* agent_info;
    while (rtn_rows->next() && rtn_rows->data() &&
           (agent_info = (pcamt_agent_info*)rtn_rows->data())) {
        AgentList[NumAgents].agent_id = agent_info->agent_id;
        NumAgents++;
    }
    return 0;
}

dgt_sint32 PccCipherAgentManager::sendAlertDeadProcess(dgt_sint64 pid) throw(
    DgcExcept) {
    if (connectMaster() < 0) {
        SohaConnStatus = SOHA_CONN_STATUS_BROKEN;
        ATHROWnR(DgcError(SPOS, "connectMaster failed"), -1);
    }
    dgt_schar sql_text[257];
    sprintf(sql_text,
            "select * from pfc_alert_dead_process(%lld,%lld,'pcp_crypt_agent')",
            EncTgtSysID, pid);
    if (SohaClient.execute(sql_text) < 0) {
        SohaConnStatus = SOHA_CONN_STATUS_BROKEN;
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    }
    return 0;
}

dgt_sint32 PccCipherAgentManager::execvCryptAgent(
    dgt_sint64 agent_id, const dgt_schar* cmd) throw(DgcExcept) {
    pid_t pid = 0;
    errno = 0;
    const dgt_schar* proc_path = CryptAgentBinPath;
    if ((pid = fork()) < 0) {
        THROWnR(
            DgcOsExcept(
                errno,
                new DgcError(SPOS, "fork for program[soha_mgr_start] failed")),
            -1);
    }
    if (pid == 0) {
        if (fork() != 0) {
            exit(0);
        }
        setsid();
        dgt_schar v_agent_id[20];
        sprintf(v_agent_id, "%lld", agent_id);

        dgt_schar* prog_name = 0;
        prog_name = (dgt_schar*)"pcp_crypt_agent";

        // pcp_crypt_agent -c <conf_file_path> -i <agent_id> <start|stop>
        dgt_schar* args[7] = {prog_name,
                              (dgt_schar*)"-c",
                              (dgt_schar*)ConfFilePath,
                              (dgt_schar*)"-i",
                              v_agent_id,
                              (dgt_schar*)cmd,
                              NULL};
        execv(proc_path, args);
        DgcWorker::PLOG.tprintf(0, "execv[%s] failed due to [%s].\n", proc_path,
                                strerror(errno));
        exit(errno);
    }
    dgt_sint32 status;
    waitpid(pid, &status, 0);
    return 0;
}

dgt_sint64 PccCipherAgentManager::getCryptAgentPID(dgt_sint64 agent_id) throw(
    DgcExcept) {
    dgt_sint32 addr_len = dg_strlen(UdsListenDir) + 100;
    dgt_schar agent_uds_addr[addr_len];
    sprintf(agent_uds_addr, CRYPT_AGENT_CONN_STRING, UdsListenDir, agent_id);

    // connect server
    DgcUnixClient client_stream;
    if (client_stream.connectServer(agent_uds_addr, 10) < 0) {
        ATHROWnR(DgcError(SPOS,
                          "connectServer to agent_service[%lld]:[%s] failed:\n",
                          agent_id, agent_uds_addr),
                 -1);
    }

    DgcSession session;
    session.setSessType(DGC_MSB, DGC_NUM_TYPE, (dgt_uint8*)DGC_TYPE_LENGTH,
                        (dgt_uint8*)DGC_TYPE_STRIDE);
    DgcPacketStream pkt_stream(&session, &client_stream);
    DgcDgMsgStream msg_stream(&session, &pkt_stream);

    // send message
    DgcExcept msg_e(PCC_AGENT_UDS_MSG_TYPE_GET_PID, 0);
    DgcMsgDgiExt result_ext;
    result_ext.putExcept(&msg_e);
    if (msg_stream.sendMessage(&result_ext) != 0) {
        ATHROWnR(
            DgcError(SPOS, "sendMessage to agent_service[%lld]:[%s] failed:\n",
                     agent_id, agent_uds_addr),
            -1);
    }

    // recv message
    DgcMessage* msg = 0;
    if (msg_stream.recvMessage(10) <= 0) {
        ATHROWnR(DgcError(SPOS,
                          "recvMessage from agent_service[%lld]:[%s] failed:\n",
                          agent_id, agent_uds_addr),
                 -1);
    }
    if ((msg = msg_stream.currMsg())->opi() != PTDGILETTER) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "not PTDGILETTER message[%d]\n",
                                        msg->opi())),
            -1);
    }
    PtMsgDgiLetter* letter = (PtMsgDgiLetter*)msg;
    dgt_sint64 agent_pid = (dgt_sint64)dg_strtoll(letter->getBody(), 0, 10);

    client_stream.closeStream();
    return agent_pid;
}

dgt_void PccCipherAgentManager::in() throw(DgcExcept) {
    // connect to master
    if (connectMaster() < 0) ATHROW(DgcError(SPOS, "connectMaster failed"));

    // get agent_id
    if (getAgentList() < 0) ATHROW(DgcError(SPOS, "getAgentList failed"));

    if (NumAgents > 0) {
        DgcWorker::PLOG.tprintf(0, "agent_manager[%lld] starts\n", EncTgtSysID);
        RunStep = STEP_START_AGENT;
    } else {
        DgcWorker::PLOG.tprintf(
            0, "agent_manager[%lld] has no pcp_crypt_agent to monitor\n",
            EncTgtSysID);
    }
}

dgt_sint32 PccCipherAgentManager::run() throw(DgcExcept) {
    if (StopFlag) return 1;
    switch (RunStep) {
        case STEP_START_AGENT: {
            // start agents
            for (dgt_uint8 i = 0; i < NumAgents; i++) {
                if (execvCryptAgent(AgentList[i].agent_id, "start") < 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        PLOG.tprintf(
                            0, *e,
                            "agent_manager[%lld] : restarting agent[%lld] "
                            "failed\n",
                            EncTgtSysID, AgentList[i].agent_id);
                        delete e;
                    }
                }
            }
            RunStep = STEP_CHECK_AGENT_IS_STARTING;
            break;
        }
        case STEP_CHECK_AGENT_IS_STARTING: {
            DgcWorker::PLOG.tprintf(
                0, "agent_manager[%lld]: waiting for agents to be ready \n",
                EncTgtSysID, NumAgents);
            // check agents pid to determine monitoring
            dgt_sint64 agent_pid = 0;
            dgt_uint8 list_idx = 0;
            dgt_uint8 max_retry_cnt = 10;
            dgt_uint8 retry_cnt = 0;
            dgt_uint8 num_monitor_proc = 0;
            while (list_idx < NumAgents) {
                if ((agent_pid =
                         getCryptAgentPID(AgentList[list_idx].agent_id)) < 0) {
                    if (retry_cnt++ < max_retry_cnt) {
                        delete EXCEPTnC;
                        sleep(1);
                        continue;
                    } else {
                        DgcExcept* e = EXCEPTnC;
                        if (e) {
                            DgcWorker::PLOG.tprintf(
                                0, *e,
                                "agent_manager[%lld]: getCryptAgentPID[%lld] "
                                "failed\n",
                                EncTgtSysID, AgentList[list_idx].agent_id);
                            delete e;
                        }
                    }
                } else {
                    if (agent_pid > 0) {
                        AgentList[list_idx].pid = agent_pid;
                        AgentList[list_idx].monitoring_flag = 1;
                        num_monitor_proc++;
                        DgcWorker::PLOG.tprintf(0,
                                                "agent_manager[%lld]: start "
                                                "the agents[%lld] pid[%lld]\n",
                                                EncTgtSysID,
                                                AgentList[list_idx].agent_id,
                                                AgentList[list_idx].pid);
                    }
                }
                list_idx++;
                retry_cnt = 0;
            }
            if (num_monitor_proc == 0)
                RunStep = STEP_END;
            else
                RunStep = STEP_MONITOR_AGENT;
            break;
        }
        case STEP_MONITOR_AGENT: {
            for (dgt_uint8 i = 0; i < NumAgents; i++) {
                if (AgentList[i].pid > 0 && AgentList[i].monitoring_flag) {
                    // monitoring agent status
                    if (kill((pid_t)AgentList[i].pid, 0) != 0 &&
                        errno == ESRCH) {  // find a dead process
                        DgcWorker::PLOG.tprintf(0,
                                                "agent_manager[%lld] : found "
                                                "dead agent[%lld:%lld]\n",
                                                EncTgtSysID,
                                                AgentList[i].agent_id,
                                                AgentList[i].pid);
                        // send alert
                        if (sendAlertDeadProcess(AgentList[i].pid) < 0) {
                            DgcExcept* e = EXCEPTnC;
                            if (e) {
                                DgcWorker::PLOG.tprintf(
                                    0, *e,
                                    "agent_manager[%lld] : send alert "
                                    "agent[%lld:%lld] failed\n",
                                    EncTgtSysID, AgentList[i].agent_id,
                                    AgentList[i].pid);
                                delete e;
                            }
                        }

                        // unlink agent's unix domain socket file
                        dgt_sint32 addr_len = dg_strlen(UdsListenDir) + 100;
                        dgt_schar agent_uds_addr[addr_len];
                        sprintf(agent_uds_addr, CRYPT_AGENT_CONN_STRING,
                                UdsListenDir, AgentList[i].agent_id);
                        unlink(agent_uds_addr);

                        // restarting process
                        if (execvCryptAgent(AgentList[i].agent_id, "start") <
                            0) {
                            DgcExcept* e = EXCEPTnC;
                            if (e) {
                                DgcWorker::PLOG.tprintf(
                                    0, *e,
                                    "agent_manager[%lld] : restarting "
                                    "agent[%lld] failed\n",
                                    EncTgtSysID, AgentList[i].agent_id);
                                delete e;
                            }
                            AgentList[i].monitoring_flag = 0;
                            continue;
                        }
                        // check agents pid
                        dgt_sint64 agent_pid = 0;
                        dgt_uint8 max_retry_cnt = 10;
                        dgt_uint8 retry_cnt = 0;
                        while ((agent_pid = getCryptAgentPID(
                                    AgentList[i].agent_id)) < 0) {
                            if (retry_cnt++ >= max_retry_cnt) {
                                DgcExcept* e = EXCEPTnC;
                                if (e) {
                                    DgcWorker::PLOG.tprintf(
                                        0, *e,
                                        "agent_manager[%lld] : "
                                        "getCryptAgentPID[%lld] failed\n",
                                        EncTgtSysID, AgentList[i].agent_id);
                                    delete e;
                                }
                                AgentList[i].monitoring_flag = 0;
                                break;
                            }
                            delete EXCEPTnC;
                            sleep(1);
                        }
                        if (agent_pid > 0) {
                            AgentList[i].pid = agent_pid;
                            AgentList[i].monitoring_flag = 1;
                            DgcWorker::PLOG.tprintf(
                                0,
                                "agent_manager[%lld] : restart "
                                "agent[%lld:%lld]\n",
                                EncTgtSysID, AgentList[i].agent_id,
                                AgentList[i].pid);
                        }
                    }
                }
            }
            sleep(1);
            break;
        }
        default: {
            return 1;  // end run()
            break;
        }
    }
    return 0;
}

dgt_void PccCipherAgentManager::out() throw(DgcExcept) {
    if (!StopFlag) {
        printf(
            "pcp_crypt_manager[%lld]'s has terminated unexpectedly.\nFor more "
            "details, please check the '%s/pcp_crypt_manager.log' file.\n",
            encTgtSysID(), LogFileDir);
    }

    for (dgt_uint8 i = 0; i < NumAgents; i++) {
        if (execvCryptAgent(AgentList[i].agent_id, "stop") < 0)
            ATHROW(DgcError(SPOS, "startCryptAgent failed"));
    }

    // disconnect from master
    if (SohaClient.disconnectDB() < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(0, *e, "disconnectDB failed.\n");
            delete e;
        }
    }

    // wait until agents stopped
    dgt_uint8 list_idx = 0;
    dgt_sint32 rtn = 0;
    while (list_idx < NumAgents) {
        if (AgentList[list_idx].pid > 0 &&
            AgentList[list_idx].monitoring_flag) {
            if ((rtn = kill((pid_t)AgentList[list_idx].pid, 0)) == 0) {
                // the process is not terminated yet
                DgcWorker::PLOG.tprintf(0,
                                        "agent_manager[%lld] : waiting until "
                                        "agent[%lld:%lld] stopped.\n",
                                        EncTgtSysID,
                                        AgentList[list_idx].agent_id,
                                        AgentList[list_idx].pid);
                sleep(3);
                continue;
            }
        }
        list_idx++;
    }

    DgcWorker::PLOG.tprintf(0, "agent_manager[%lld] ends.\n", EncTgtSysID);
}

dgt_sint32 PccCipherAgentManager::initialize(
    const dgt_schar* conf_file_path) throw(DgcExcept) {
    ConfFilePath = conf_file_path;
    DgcBgmrList params(conf_file_path);
    ATHROWnR(DgcError(SPOS, "parse[%s] failed", conf_file_path), -1);
    DgcBgrammer* bg = 0;
    dgt_schar* val = 0;
    while ((bg = params.getNext())) {
        if (bg->getNode("manager")) {
            if ((val = bg->getValue("manager.enc_tgt_sys_id")))
                EncTgtSysID = dg_strtoll(val, 0, 10);

            // pcp_crypt_agent binary file path
            if ((val = bg->getValue("manager.agent_bin_path"))) {
                dgt_sint32 len = dg_strlen(val);
                CryptAgentBinPath = new dgt_schar[len + 1];
                memset(CryptAgentBinPath, 0, len + 1);
                strcpy(CryptAgentBinPath, val);
            } else {
                CryptAgentBinPath = new dgt_schar[65];
                memset(CryptAgentBinPath, 0, 65);
                strcpy(CryptAgentBinPath, "./pcp_crypt_agent");
            }

            // for unix domain socket stream
            if ((val = bg->getValue("manager.uds_listen_dir"))) {
                dgt_sint32 len = dg_strlen(val);
                UdsListenDir = new dgt_schar[len + 1];
                memset(UdsListenDir, 0, len + 1);
                strcpy(UdsListenDir, val);
            } else {
                UdsListenDir = new dgt_schar[129];
                memset(UdsListenDir, 0, 129);
                strcpy(UdsListenDir, "/var/tmp/.petra");
            }
            dgt_sint32 addr_len = dg_strlen(UdsListenDir);
            UdsListenAddr = new dgt_schar[addr_len + 100];
            sprintf(UdsListenAddr, "%s/pcp_crypt_manager_%lld.s", UdsListenDir,
                    EncTgtSysID);

            if ((val = bg->getValue("manager.log_file_dir"))) {
                dgt_sint32 len = dg_strlen(val);
                LogFileDir = new dgt_schar[len + 1];
                memset(LogFileDir, 0, len + 1);
                strcpy(LogFileDir, val);
            } else {
                LogFileDir = new dgt_schar[129];
                memset(LogFileDir, 0, 129);
                strcpy(LogFileDir, "/var/tmp/.petra");
            }
            dgt_schar* log_file_path = 0;
            log_file_path = new dgt_schar[dg_strlen(LogFileDir) + 100];
            if (log_file_path) {
                sprintf(log_file_path, "%s/pcp_crypt_manager.log", LogFileDir);
                openLogStream(log_file_path);
                delete log_file_path;
            }

            if ((val = bg->getValue("manager.soha.primary.svc")))
                strcpy(PrimarySohaSvc, val);
            if ((val = bg->getValue("manager.soha.secondary.svc")))
                strcpy(SecondarySohaSvc, val);
            if ((val = bg->getValue("manager.soha.primary.ip")))
                strcpy(PrimarySohaConnIP, val);
            if ((val = bg->getValue("manager.soha.secondary.ip")))
                strcpy(SecondarySohaConnIP, val);
            if ((val = bg->getValue("manager.soha.primary.dgnet_port")))
                PrimarySohaConnPort = (dgt_uint16)dg_strtoll(val, 0, 10);
            if ((val = bg->getValue("manager.soha.secondary.dgnet_port")))
                SecondarySohaConnPort = (dgt_uint16)dg_strtoll(val, 0, 10);
        }
    }

    return 0;
}

dgt_void PccCipherAgentManager::getCryptManagerStatus(
    pcct_manager_status* status) {
    if (status) {
        status->manager_id = encTgtSysID();
        status->manager_pid = (dgt_sint64)getpid();
        status->num_agents = NumAgents;
        status->soha_conn_status = SohaConnStatus;
        memcpy(status->primary_soha_svc, PrimarySohaSvc,
               sizeof(PrimarySohaSvc));
        memcpy(status->primary_soha_ip, PrimarySohaConnIP,
               sizeof(PrimarySohaConnIP));
        status->primary_soha_port = PrimarySohaConnPort;
        memcpy(status->secondary_soha_svc, SecondarySohaSvc,
               sizeof(SecondarySohaSvc));
        memcpy(status->secondary_soha_ip, SecondarySohaConnIP,
               sizeof(SecondarySohaConnIP));
        status->secondary_soha_port = SecondarySohaConnPort;
    }
}

void help_message() {
    printf("Usage: pcp_crypt_manager [OPTIONS] <start|stop|status>\n");
    printf("\n Examples:\n");
    printf(
        "    pcp_crypt_manager start\t\t\t\t# start the manager using "
        "manager.conf\n");
    printf(
        "    pcp_crypt_manager -c manager2.conf start\t\t# start the manager "
        "using manager2.conf \n");
    printf(
        "    pcp_crypt_manager -c manager2.conf stop\t\t# stop the manager "
        "using manager2.conf \n");
    printf(
        "    pcp_crypt_manager -c manager2.conf -v status\t# display the "
        "manager's detailed status using manager2.conf \n");

    printf("\n Options:\n");
    printf("    -h\t display this help and exit\n");
    printf("    -c\t set configure file path [default: manager.conf]\n");
    printf(
        "    -v\t display detailed manager agent status (with status "
        "command)\n");
}

int main(dgt_sint32 argc, dgt_schar** argv) {
    dgt_sint32 verbose_flag = 0;
    dgt_schar conf_file_path[2048];
    memset(conf_file_path, 0, sizeof(conf_file_path));

    if (argc < 2) {
        //		printf("usage: pcp_crypt_manager <conf_file_path>
        //<start|stop|status> [all(default) | crypt_agent | client_agent]\n");
        help_message();
        return -1;
    }

    dgt_schar ch;
    while ((ch = dg_getopt(argc, argv, "hvc:")) != (dgt_schar)EOF) {
        switch (ch) {
            case 'h':
                help_message();
                return 0;
            case 'v':
                verbose_flag = 1;
                break;
            case 'c':
                memcpy(conf_file_path, optarg, strlen(optarg));
                break;
            case '?':
                help_message();
                return -1;
        }
    }
    if (!strlen(conf_file_path)) sprintf(conf_file_path, "manager.conf");

    dgt_schar* cmd = 0;
    dgt_sint32 remain_param = argc - optind;
    if (remain_param == 1) {
        cmd = argv[optind];
    } else if (remain_param == 2 ||
               remain_param ==
                   3) {  // for compatibility; pcp_crypt_manager <conf file
                         // path> <start|stop|staus> [all(default] | crypt_agent
                         // | client_agent]
        sprintf(conf_file_path, argv[optind]);
        cmd = argv[optind + 1];
    } else {
        printf(
            "command <start|stop|status> is not entered or there are too many "
            "arguments\n");
        help_message();
        exit(100);
    }

    PccCipherAgentManager* agent_manager = new PccCipherAgentManager();
    if (agent_manager->initialize(conf_file_path) < 0) {
        DgcExcept* e = EXCEPTnC;
        e->print();
        DgcWorker::PLOG.tprintf(0, *e, "initialize[%s] failed:\n",
                                conf_file_path);
        delete e;
        printf("initialize[%s] failed.\n", conf_file_path);
        return -2;
    }
    if (strcasecmp(cmd, "start")) {
        DgcExcept* msg_e = 0;
        // set msg_type
        if (!strcasecmp(cmd, "stop")) {
            msg_e = new DgcExcept(PCC_MANAGER_UDS_MSG_TYPE_STOP, 0);
        } else if (!strcasecmp(cmd, "status")) {
            msg_e = new DgcExcept(PCC_MANAGER_UDS_MSG_TYPE_STATUS, 0);
        } else {
            printf("invalid command [%s], it should be <start|stop|status>\n",
                   cmd);
            help_message();
            exit(100);
        }
        DgcUnixClient client_stream;
        if (client_stream.connectServer(agent_manager->udsListenAddr(), 10) <
            0) {
            printf("agent_manager[%lld] connectServer[%s] failed:\n",
                   agent_manager->encTgtSysID(),
                   agent_manager->udsListenAddr());
            DgcExcept* e = EXCEPTnC;
            if (e) {
                e->print();
                delete e;
            }
            return 3;
        }
        // connect server
        DgcSession session;
        session.setSessType(DGC_MSB, DGC_NUM_TYPE, (dgt_uint8*)DGC_TYPE_LENGTH,
                            (dgt_uint8*)DGC_TYPE_STRIDE);
        DgcPacketStream pkt_stream(&session, &client_stream);
        DgcDgMsgStream msg_stream(&session, &pkt_stream);

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
        DgcMessage* msg = 0;
        if (!strcasecmp(cmd, "stop")) {
            for (;;) {
                if (msg_stream.recvMessage(5) <= 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        e->print();
                        delete e;
                    } else {
                        printf("recvMessage[result_msg] time out\n");
                    }
                    exit(101);
                }
                if ((msg = msg_stream.currMsg())->opi() != DGIEXT) {
                    printf("not DGIEXT message[%d]\n", msg->opi());
                    exit(102);
                }
                DgcMsgDgiExt* ext = (DgcMsgDgiExt*)msg;
                DgcExcept* result_e = ext ? ext->getExcept() : 0;
                if (!result_e) {
                    printf(
                        "stop agent_manager[%lld] failed : [unknown error]\n",
                        agent_manager->encTgtSysID());
                    break;
                }
                if (result_e->classid() == 0 && result_e->errCode() == 0) {
                    printf("agent_manager[%lld] stopped by command.\n",
                           agent_manager->encTgtSysID());
                    break;
                } else if (result_e->classid() && result_e->errCode()) {
                    result_e->print();
                    printf("stop agent_manager[%lld] failed.\n",
                           agent_manager->encTgtSysID());
                    break;
                } else {
                    // do nothing
                    // printf("waiting[%d] until agent_manager[%lld]
                    // stopped...\n",result_e->errCode(),agent_manager->encTgtSysID());
                }
            }
        } else if (!strcasecmp(cmd, "status")) {
            if (msg_stream.recvMessage(10) <= 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    e->print();
                    delete e;
                } else {
                    printf("recvMessage[result_msg] time out\n");
                }
                exit(103);
            }
            if ((msg = msg_stream.currMsg())->opi() != PTDGILETTER) {
                printf("not DGIEXT message[%d]\n", msg->opi());
                exit(104);
            }
            PtMsgDgiLetter* letter = (PtMsgDgiLetter*)msg;
            printf("%s\n", letter->getBody());

            dgt_sint32 num_agents =
                (dgt_sint32)dg_strtoll(letter->getPs(), 0, 10);
            if (num_agents > 0) {
                for (dgt_sint32 i = 0; i < num_agents; i++) {
                    if (msg_stream.recvMessage(10) <= 0) {
                        DgcExcept* e = EXCEPTnC;
                        if (e) {
                            e->print();
                            delete e;
                        } else {
                            printf("recvMessage[agent_status_msg] time out\n");
                        }
                        exit(103);
                    }
                    if ((msg = msg_stream.currMsg())->opi() != PTDGILETTER) {
                        printf("not PTDGILETTER message[%d]\n", msg->opi());
                        exit(104);
                    }
                    letter = (PtMsgDgiLetter*)msg;
                    if (verbose_flag) printf("%s\n", letter->getBody());
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
    if ((pid = fork()) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            e->print();
            DgcWorker::PLOG.tprintf(0, *e, "fork failed:\n");
            delete e;
        } else {
            DgcWorker::PLOG.tprintf(0, "fork failed: [unknown error]\n");
        }
        return 3;
    }
    // 2. parent exits and child is to be a deamon
    if (pid != 0) exit(0);
    // 3. be a group leader
    setsid();
    // 4. catch and set all catchable signals
    DgcSigManager::p()->regDefault();
    // 5. start unix server
    DgcUnixServer server_stream(5, 5);
    if (server_stream.listenServer(agent_manager->udsListenAddr()) == 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            e->print();
            DgcWorker::PLOG.tprintf(
                0, *e, "agent_manager[%lld] listenServer[%s] failed:\n",
                agent_manager->encTgtSysID(), agent_manager->udsListenAddr());
            delete e;
        } else {
            DgcWorker::PLOG.tprintf(0,
                                    "agent_manager[%lld] listenServer[%s] "
                                    "failed: [unknown error]\n",
                                    agent_manager->encTgtSysID(),
                                    agent_manager->udsListenAddr());
        }
        return 4;
    }

    // 6. start manager
    agent_manager->wa()->ThreadID = pthread_self();
    if (agent_manager->start() < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            e->print();
            DgcWorker::PLOG.tprintf(0, *e,
                                    "starting agent_manager[%lld] failed:\n",
                                    agent_manager->encTgtSysID());
            delete e;
        }
        delete agent_manager;
        return 5;
    }

    printf("\npcp_crypt_manager[%lld]'s starting.\n",
           agent_manager->encTgtSysID());

    //
    // 7. wait & serve
    // msg_type : 1 - stop, 2- status
    //
    DgcSession session;
    session.setSessType(DGC_MSB, DGC_NUM_TYPE, (dgt_uint8*)DGC_TYPE_LENGTH,
                        (dgt_uint8*)DGC_TYPE_STRIDE);

    while (1) {
        DgcCommStream* stream = 0;
        if ((stream = (DgcCommStream*)server_stream.acceptConnection(5))) {
            DgcPacketStream pkt_stream(&session, stream);
            DgcDgMsgStream msg_stream(&session, &pkt_stream);
            // recv msg_type
            if (msg_stream.recvMessage() <= 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    DgcWorker::PLOG.tprintf(0, *e,
                                            "recvMessage[msg_type] failed:\n");
                    delete e;
                } else {
                    DgcWorker::PLOG.tprintf(0,
                                            "recvMessage[msg_type] timeout.\n");
                }
                continue;
            }
            DgcMessage* msg = 0;
            if ((msg = msg_stream.currMsg())->opi() != DGIEXT) {
                DgcWorker::PLOG.tprintf(0, "not msg_type message[%d]\n",
                                        msg->opi());
                continue;
            }
            DgcMsgDgiExt* ext = (DgcMsgDgiExt*)msg;
            dgt_uint16 msg_type = ext->getExcept()->classid();
            msg_stream.resetIBuf();

            // check msg_type
            if (msg_type == PCC_MANAGER_UDS_MSG_TYPE_STOP) {
                DgcExcept* result_e = 0;
                DgcMsgDgiExt result_ext;

                // askStop to terminate crypt_managers normal
                // for preventing from creating damaged encryption file
                agent_manager->askStop();

                result_e = new DgcExcept(0, 0);
                result_ext.putExcept(result_e);
                dgt_sint32 wait_time = 0;
                while (agent_manager->isAlive()) {
                    if (wait_time > 300) {
                        if (agent_manager->stop() < 0) {
                            if (result_e) delete result_e;
                            DgcExcept* e = EXCEPTnC;
                            DgcWorker::PLOG.tprintf(
                                0, *e, "agent_manager[%lld] : stop failed:\n",
                                agent_manager->encTgtSysID());
                            delete e;
                            exit(-1);
                        }
                    }
                    result_e->setErrCode(++wait_time);
                    if (msg_stream.sendMessage(&result_ext) != 0) {
                        DgcExcept* e = EXCEPTnC;
                        if (e) {
                            DgcWorker::PLOG.tprintf(0, *e,
                                                    "sendMessage failed:\n");
                            delete e;
                        }
                    }
                    sleep(1);
                }
                delete agent_manager;
                // send success msg
                result_e->setErrCode(0);
                if (msg_stream.sendMessage(&result_ext) != 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
                        delete e;
                    }
                }
                if (result_e && !result_e->errCode()) {
                    delete result_e;
                    break;  // terminate while loop for exit
                }
                if (result_e) delete result_e;
            } else if (msg_type == PCC_MANAGER_UDS_MSG_TYPE_STATUS) {
                // send status msg
                pcct_manager_status manager_status;
                agent_manager->getCryptManagerStatus(&manager_status);
                dgt_schar body[513];
                dgt_schar ps[65];
                sprintf(body,
                        "manager[%lld] pid[%lld] num_agents[%d] "
                        "soha_conn_status[%d] primary_soha_conn[%s:%d/%s] "
                        "secondary_soha_conn[%s:%d/%s]",
                        manager_status.manager_id, manager_status.manager_pid,
                        manager_status.num_agents,
                        manager_status.soha_conn_status,
                        manager_status.primary_soha_ip,
                        manager_status.primary_soha_port,
                        manager_status.primary_soha_svc,
                        manager_status.secondary_soha_ip,
                        manager_status.secondary_soha_port,
                        manager_status.secondary_soha_svc);
                PtMsgDgiLetter status_msg;
                status_msg.setBody(body);
                sprintf(ps, "%d", manager_status.num_agents);
                status_msg.setPs(ps);
                if (msg_stream.sendMessage(&status_msg) != 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(0, *e, "sendMessage failed:\n");
                        delete e;
                    }
                }

                if (manager_status.num_agents > 0) {
                    dgt_schar* agent_body = new dgt_schar[512];
                    PtMsgDgiLetter agent_status_msg;
                    for (dgt_sint32 i = 0; i < manager_status.num_agents; i++) {
                        pcamt_agent_list* agent_list =
                            agent_manager->agentList(i);
                        dgt_sint64 agent_id = 0;
                        dgt_sint64 agent_pid = 0;
                        dgt_uint8 monitoring_flag = 0;
                        if (agent_list) {
                            agent_id = agent_list->agent_id;
                            agent_pid = agent_list->pid;
                            monitoring_flag = agent_list->monitoring_flag;
                        }
                        sprintf(
                            agent_body,
                            "- agent_id[%lld] pid[%lld] monitoring_flag[%u]",
                            agent_id, agent_pid, monitoring_flag);
                        agent_status_msg.setBody(agent_body);
                        if (msg_stream.sendMessage(&agent_status_msg) != 0) {
                            DgcExcept* e = EXCEPTnC;
                            if (e) {
                                DgcWorker::PLOG.tprintf(
                                    0, *e, "sendMessage failed:\n");
                                delete e;
                            }
                        }
                    }
                    if (agent_body) delete agent_body;
                }
            } else {
                DgcWorker::PLOG.tprintf(
                    0, "agent_manager[%lld] invalid msg[%u] :\n",
                    agent_manager->encTgtSysID(), msg_type);
            }
        }
        if (!agent_manager->isAlive()) {
            DgcWorker::PLOG.tprintf(0,
                                    "pcp_crypt_manager stopped cause "
                                    "agent_manager[%lld] is not alive\n",
                                    agent_manager->encTgtSysID());
            break;
        }
        napAtick();
    }

    // pcp_crypt_manager stopped
    return 0;
}
