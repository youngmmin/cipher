/*
 * ext_main.cpp
 *
 * procedure server main function
 *
 */
#include "DgcProcedureServer.h"

#if defined(aix6) || defined(aix5) || defined(aix4)
#include <sys/dr.h>
void sig_handler(int signo) {
    if (signo == SIGRECONFIG) {
        int rc = 0;
        dr_info_t dr_info;
        if (rc = dr_reconfig(DR_QUERY, &dr_info)) {
        } else if (dr_info.post) {
            rc = dr_reconfig(DR_RECONFIG_DONE, &dr_info);
        } else {
            rc = dr_reconfig(DR_RECONFIG_DONE, &dr_info);
        }
    }
}
#endif

extern dgt_void initServerFactory();

int main(dgt_sint32 argc, dgt_schar** argv) {
    initServerFactory();
    //
    // *********************************************************
    // 1. process initialization: being a demon and a log open.
    // *********************************************************
    //
    dgt_uint32 ppid = getpid();
    if (DgcDbProcess::initialize(DGC_WT_PROC_SERVER, argv[0], 1, 1) != 0) {
        EXCEPT->print();
        exit(1);
    }
    dg_signal(SIGCHLD, SIG_IGN);
#if defined(aix6) || defined(aix5) || defined(aix4)
    dg_signal(SIGRECONFIG, sig_handler);
#endif

    //
    // ************************************************************
    // 2. database attach: attach the defiened repository database
    //    and enroll this process into the database.
    // ************************************************************
    //
    dgt_schar* svc_name = dg_getenv("SOHA_SVC");
    if (svc_name == 0) {
        DgcWorker::PLOG.tprintf(0, "SOHA_SVC not defined.\n");
        exit(1);
    }
    if (DgcDbProcess::openDatabase(svc_name, DGC_LD_ATTACH) != 0) {
        DgcExcept* e = EXCEPTnC;
        DgcWorker::PLOG.tprintf(
            0, *e, "attachDatabase[%s] failed due to the below:\n", svc_name);
        delete e;
        exit(1);
    }
    DgcDbProcess::sess()->setDbUser(DGC_SYS_OWNER);
    if (argc > 2 && argv[2] && *argv[2])
        dg_strcpy(DgcDbProcess::pa().owner, argv[2]);
    else
        dg_strcpy(DgcDbProcess::pa().owner, DGC_SYS_OWNER);

    //
    // *******************************************************************
    // 3. register the leader worker "DgcDgInlineRelayServer" with the database
    // *******************************************************************
    //
    dgt_worker* wa = DgcDbProcess::db().getWorker(DgcDbProcess::sess());
    if (wa == 0) {
        DgcExcept* e = EXCEPTnC;
        DgcWorker::PLOG.tprintf(0, *e, "getWorker failed due to the below:\n");
        delete e;
        DgcDbProcess::closeDatabase();
        exit(1);
    }
    wa->PID = DgcDbProcess::pa().pid;
    wa->LWID = wa->WID;
    DgcProcServer::p()->replaceWA(wa);
    if (argc > 2 && argv[2] && *argv[2])
        DgcProcServer::p()->setOwner(argv[2]);
    else
        DgcProcServer::p()->setOwner(DGC_SYS_OWNER);
    DgcProcServer::p()->setParentPID(ppid);
    if (DgcProcServer::p()->start() != 0) {
        DgcExcept* e = EXCEPTnC;
        DgcWorker::PLOG.tprintf(
            0, *e, "start[proc_server] failed due to the below:\n");
        delete e;
        DgcProcServer::p()->restoreWA();
        DgcDbProcess::db().removeWorker(wa);
        DgcDbProcess::closeDatabase();
    } else {
        DgcDbProcess::monitorProcess();
    }
    pthread_exit(0);
}
