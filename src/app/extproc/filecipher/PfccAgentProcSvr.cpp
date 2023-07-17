/*******************************************************************
 *   File Type          :       main file
 *   Classes            :       PccAgentProcSvr
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PfccAgentProcSvr.h"

PfccAgentSessChecker::PfccAgentSessChecker(dgt_worker* wa, PfccAgentSessionPool& agent_sess_pool)
	: DgcDbWorker(DGC_WT_CIPHER_AGENT_PROC_SVR,"agent_sess_checker",wa), AgentSessPool(agent_sess_pool), StopFlag(0)
{

}


PfccAgentSessChecker::~PfccAgentSessChecker()
{

}


dgt_void PfccAgentSessChecker::in() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"agent_sess_checker starts.\n");
}


dgt_sint32 PfccAgentSessChecker::run() throw(DgcExcept)
{
	// check sessions's connection
	PfccAgentSession* session = 0;
	for(dgt_sint32 i=0; i<PFCC_MAX_AGENT_SESS_NUM; i++) {
		session = AgentSessPool.getSessionIdx(i);
		if (session) {
			if (session->isBroken()) {
				AgentSessPool.removeSession(session);
				continue;
			} 
#if 0
			else if (session->checkConn() < 0) {
				DgcExcept* e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] session[%d] is broken.\n",session->agentID(),session->sessID());
					delete e;
				}
				AgentSessPool.removeSession(session);
				continue;
			} else {
				AgentSessPool.returnSession(session);
			}
#endif
			AgentSessPool.returnSession(session);
		}
	}
	for (dgt_sint32 i = 0; i < CHECK_INTERVAL ; i++) {
	if (StopFlag) return 1;
	sleep(1);
	}
	return 0;
}


dgt_void PfccAgentSessChecker::out() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"agent_sess_checker ends.\n");
}


PfccAgentListener::PfccAgentListener(dgt_worker* wa, const dgt_schar* ip,dgt_uint16 port)
	: DgcDbWorker(DGC_WT_CIPHER_AGENT_PROC_SVR,"pfcc_proc_svr",wa), ListenPort(port),CommServer(20,20)
{
	memset(ListenIP,0,129);
	strncpy(ListenIP,ip,128);
	AgentSessChecker = 0;
}


PfccAgentListener::~PfccAgentListener()
{
}


dgt_void PfccAgentListener::in() throw(DgcExcept)
{
	CommServer.listenServer(ListenIP,ListenPort);
	ATHROW(DgcError(SPOS,"listenServer failed"));

	dgt_worker*	wa = DgcDbProcess::db().getWorker(DgcDbProcess::sess());
	if (wa == 0) {
		ATHROW(DgcError(SPOS,"getWorker failed"));
	}
	wa->PID = DgcDbProcess::pa().pid;
	wa->LWID = this->lwid();
	AgentSessChecker = new PfccAgentSessChecker(wa,AgentSessPool);
	if (AgentSessChecker->start() != 0) {
		DgcExcept*	e = EXCEPTnC;
		AgentSessChecker->restoreWA();
		DgcDbProcess::db().removeWorker(wa);
		RTHROW(e,DgcError(SPOS,"AgentSessChecker start failed"));
	}

	DgcWorker::PLOG.tprintf(0,"listener is starting at[%s:%u].\n",ListenIP,ListenPort);
}


dgt_sint32 PfccAgentListener::run() throw(DgcExcept)
{
	DgcCommStream*	stream=0;
	if ((stream=(DgcCommStream*)CommServer.acceptConnection(1))) {
		PfccAgentSession*	session = new PfccAgentSession();
		if (session->connect(stream) < 0) {
			DgcExcept*	e = EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"connect failed:\n");
			delete e;
			delete session;
		} else {
			if (AgentSessPool.addSession(session) < 0) {
				DgcExcept* e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"addSession failed:\n");
					delete e;
				}
				delete session;
			}
		}
	}

	DgcExcept*	e = EXCEPTnC;
	if (e) {
		DgcWorker::PLOG.tprintf(0,*e,"exception while listener is running to the below:\n");
		delete e;
	}
	return 0;
}


dgt_void PfccAgentListener::out() throw(DgcExcept)
{
	AgentSessChecker->askStop();
	while (AgentSessChecker->isAlive()) napAtick();
	if (AgentSessChecker && AgentSessChecker->isAlive()) AgentSessChecker->stop();
	DgcWorker::PLOG.tprintf(0,"listener is stopped.\n");
}

