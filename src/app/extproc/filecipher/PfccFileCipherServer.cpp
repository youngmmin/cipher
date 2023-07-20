/*******************************************************************
 *   File Type          :       external server definition
 *   Classes            :       PfccFileCipherFactory
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 05. 24
 *   Description        :       file cipher external procedure server
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "DgcBgmrList.h"
#include "DgcDgRepository.h"
#include "DgcProcedureServer.h"
// write proceduer header that will be add at under area
#include "PfccAgentProcSvr.h"
#include "PfccAlertDeadProcess.h"
#include "PfccCryptFile.h"
#include "PfccCryptStatCollector.h"
#include "PfccDeleteCryptStat.h"
#include "PfccGetAgentStat.h"
#include "PfccGetDirCryptStat.h"
#include "PfccGetFileInfo.h"
#include "PfccGetStreamStat.h"
#include "PfccGetTargetList.h"
#include "PfccHasAgentSession.h"
#include "PfccRecollectCryptDir.h"
#include "PfccRemoveFile.h"
#include "PfccSetAgentParam.h"
#include "PfccSyncTable.h"
#include "PfccValidationFile.h"
#include "PfccVerifyCryptParam.h"
#include "PfccVerifyExpr.h"

#if 1  // added by chchung 2018.7.17 for PCFS
#include "PfccPcfsGetList.h"
#include "PfccPcfsGetStat.h"
#include "PfccPcfsMount.h"
#endif

#if 1
#include "PfccGetDetectInfo.h"
#include "PfccGetDetectStat.h"
#include "PfccVerifyDetectInfo.h"
#endif

class PfccFileCipherFactory : public DgcExtProcFactory {
   private:
    PfccAgentListener* AgentListener;
    PfccCryptStatCollector* CryptStatCollector;

   protected:
   public:
    PfccFileCipherFactory();
    virtual ~PfccFileCipherFactory();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 finalize() throw(DgcExcept);
};

PfccFileCipherFactory::PfccFileCipherFactory()
    : DgcExtProcFactory(/* num_service_handler=2,max_statement=100,max_procedure=1000,max_resource=100
                         */
                        50,
                        200, 1000, 100) {
    AgentListener = 0;
    CryptStatCollector = 0;
}

PfccFileCipherFactory::~PfccFileCipherFactory() {
    // if (AgentListener) delete AgentListener;
    if (AgentListener && AgentListener->isAlive()) AgentListener->stop();
    if (CryptStatCollector && CryptStatCollector->isAlive())
        CryptStatCollector->stop();
}

dgt_sint32 PfccFileCipherFactory::initialize() throw(DgcExcept) {
    DgcDbProcess::sess()->setDatabaseUser(DGC_SYS_OWNER);

    dgt_sint32 in_timeout = 10;   // agent default input timeout
    dgt_sint32 out_timeout = 10;  // agent default output timeout
    dgt_schar listen_ip[65];
    memset(listen_ip, 0, 65);
    dgt_uint16 listen_port = 0;
    dgt_schar* soha_home = dg_getenv("SOHA_HOME");
    if (!soha_home) {
        printf("$SOHA_HOME is not set\n.");
        exit(1);
    }

    dgt_schar listener_conf_file[255];
    dg_memset(listener_conf_file, 0, 255);
    dg_sprintf(listener_conf_file, "%s/config/listener.list", soha_home);
    DgcBgmrList listen_info_list(listener_conf_file);
    ATHROWnR(DgcError(SPOS, "parsing listener.list failed", listener_conf_file),
             -1);

    DgcBgrammer* listen_info = 0;
    while ((listen_info = listen_info_list.getNext()) != 0) {
        dgt_schar* val = 0;
        if ((val = listen_info->getValue("listen.client_type")) != 0 &&
            !(dg_strcmp(val, "pfcc_proc_svr"))) {
            if ((val = listen_info->getValue("listen.host")) != 0)
                dg_strncpy(listen_ip, val, 64);
            if ((val = listen_info->getValue("listen.port")) != 0)
                listen_port = (dgt_uint16)strtol(val, 0, 10);
            if ((val = listen_info->getValue("listen.in_timeout")) != 0)
                in_timeout = strtol(val, 0, 10);
            if ((val = listen_info->getValue("listen.out_timeout")) != 0)
                out_timeout = strtol(val, 0, 10);
        }
    }

    // in, out time is not in use nowadays but they are necessary
    if (!in_timeout) in_timeout = 10;
    if (!out_timeout) out_timeout = 10;

    dgt_worker* wa = DgcDbProcess::db().getWorker(DgcDbProcess::sess());
    if (wa == 0) {
        ATHROWnR(DgcError(SPOS, "getWorker failed"), -1);
    }
    wa->PID = DgcDbProcess::pa().pid;
    wa->LWID = wa->WID;

    AgentListener = new PfccAgentListener(wa, listen_ip, listen_port);
    if (AgentListener->start(0) < 0) {
        ATHROWnR(DgcError(SPOS, "agent_listener start failed"), -1);
    }

    // added by shson 18.03.07
    // this worker collect crypt_stat as from agent
#if 1
    dgt_sint32 collecting_interval = 0;
    dgt_uint8 start_flag = 0;
    dgt_dg_sys_param* param = 0;
    param = DgcDbProcess::db().getSysParam("CRYPT_STAT_COLLECTOR");
    if (param == 0) {
        delete EXCEPTnC;
    } else {
        collecting_interval = param->val_number;
        start_flag = (strncmp(param->val_string, "yes", 3) == 0) ? 1 : 0;
    }

    if (start_flag) {
        wa = DgcDbProcess::db().getWorker(DgcDbProcess::sess());
        if (wa == 0) {
            ATHROWnR(DgcError(SPOS, "getWorker failed"), -1);
        }
        wa->PID = DgcDbProcess::pa().pid;
        wa->LWID = wa->WID;
        CryptStatCollector =
            new PfccCryptStatCollector(wa, AgentListener, collecting_interval);
        if (CryptStatCollector->start() < 0) {
            ATHROWnR(DgcError(SPOS, "CryptStatCollector start failed"), -1);
        }
    }
#endif

    // retigster procedures to communcate with agent
    if (addProcedure(new PfccGetFileInfo("PFC_GET_FILE_INFO", AgentListener)) !=
        0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(
            new PfccGetAgentStat("PFC_GET_AGENT_STAT", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(new PfccGetDirCryptStat("PFC_GET_DIR_CRYPT_STAT",
                                             AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(
            new PfccSetAgentParam("PFC_SET_AGENT_PARAM", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(new PfccCryptFile("PFC_CRYPT_FILE", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(new PfccRemoveFile("PFC_REMOVE_FILE", AgentListener)) !=
        0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    // added by shson 2018.03.27
    if (addProcedure(
            new PfccGetTargetList("PFC_GET_TARGET_LIST", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
#if 1
    if (addProcedure(new PfccRecollectCryptDir("PFC_RECOLLECT_CRYPT_DIR",
                                               AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    if (addProcedure(new PfccValidationFile("PFC_VALIDATION_FILE",
                                            AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
#endif
    // normal procedure
    if (addProcedure(new PfccAlertDeadProcess("PFC_ALERT_DEAD_PROCESS")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccDeleteCryptStat("PFC_DELETE_CRYPT_STAT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccSyncTable("PFC_SYNC_TABLE")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccVerifyCryptParam("PFC_VERIFY_CRYPT_PARAM")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccVerifyExpr("PFC_VERIFY_EXPR")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

#if 1  // added by chchung 2018.7.17 for PCFS
    if (addProcedure(new PfccPcfsGetList("PFC_PCFS_GET_LIST", AgentListener)) !=
        0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccPcfsMount("PFC_PCFS_MOUNT", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccPcfsGetStat("PFC_PCFS_GET_STAT", AgentListener)) !=
        0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
#endif

#if 1  // added by mjkim 2019.05.22 for pattern detect
    if (addProcedure(new PfccGetDetectStat("PFC_GET_DETECT_STAT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(
            new PfccGetDetectInfo("PFC_GET_DETECT_INFO", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccVerifyDetectInfo("PFC_VERIFY_DETECT_INFO",
                                              AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
#endif
    if (addProcedure(
            new PfccGetStreamStat("PFC_GET_STREAM_STAT", AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PfccHasAgentSession("PFC_HAS_AGENT_SESSION",
                                             AgentListener)) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }

    return 0;
}

dgt_sint32 PfccFileCipherFactory::finalize() throw(DgcExcept) { return 0; }

dgt_void initServerFactory() {
    static PfccFileCipherFactory FileCipherFactory;  // create a SyncMgrFactory
    DgcProcServer::initFactory(
        &FileCipherFactory);  // register the SyncMgrFactory with the Procedure
                              // Server
}
