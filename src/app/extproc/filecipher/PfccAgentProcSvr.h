/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccAgentProcSvr
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_AGENT_PROC_SVR_H
#define PFCC_AGENT_PROC_SVR_H

#include "DgcDbWorker.h"
#include "PfccAgentSessionPool.h"

class PfccAgentSessChecker : public DgcDbWorker {
  private:
	static const dgt_sint32 CHECK_INTERVAL = 60;

	PfccAgentSessionPool&	AgentSessPool;
	dgt_uint8       		StopFlag;
	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  protected:
  public:
	PfccAgentSessChecker(dgt_worker* wa, PfccAgentSessionPool& agent_sess_pool);
	virtual ~PfccAgentSessChecker();
	inline dgt_void askStop() { StopFlag = 1; };
};

class PfccAgentListener : public DgcDbWorker {
  private:
	dgt_schar		ListenIP[129];
	dgt_uint16		ListenPort;
	DgcSockServer		CommServer;
	PfccAgentSessionPool	AgentSessPool;
	PfccAgentSessChecker* 	AgentSessChecker;


	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  protected:
  public:
	PfccAgentListener(dgt_worker* wa,const dgt_schar* ip,dgt_uint16 port);
	virtual ~PfccAgentListener();
	inline PfccAgentSessionPool& agentSessPool() { return AgentSessPool; };
};

#endif
