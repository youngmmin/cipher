/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PfccAgentSessionPool
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 2. 2
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_AGENT_SESSION_POOL_H
#define PFCC_AGENT_SESSION_POOL_H


#include "DgcSohaConnection.h"
#include "PccAgentMsg.h"
#include "PfccAgentParamBuilder.h"

static const dgt_sint32	PFCC_MAX_AGENT_SESS_NUM 			= 4096;

class PfccSohaConnection : public DgcSohaConnection {
  private:
  protected:
  public:
	PfccSohaConnection();
	virtual ~PfccSohaConnection();
	dgt_sint32 checkConnection() throw(DgcExcept);
};

class PfccAgentSession : public DgcObject {
  private:
	pcct_get_agent_info	AgentInfo;
	dgt_uint32		AgentIpAddr;  // src ip
	PfccSohaConnection	Connection;
	dgt_uint8		UseFlag;
	dgt_uint8		BrokenFlag;
	dgt_sint32 getAgentInfo() throw(DgcExcept);
	dgt_sint32 setInitParams() throw(DgcExcept);
  protected:
  public:
	PfccAgentSession();
	virtual ~PfccAgentSession();
	inline dgt_sint64 agentID() { return AgentInfo.agent_id; }
	inline dgt_sint32 sessID() { return AgentInfo.sess_id; }
	inline dgt_uint32 agentIpAddr() { return AgentIpAddr; }
	inline dgt_uint8 isUsing() { if (UseFlag) return 1; return 0; };
	inline dgt_void setUseFlag() { UseFlag = 1; };
	inline dgt_void unsetUseFlag() { UseFlag = 0; };
	inline dgt_uint8 isBroken() { if (BrokenFlag) return 1; return 0; };
	inline dgt_void setBrokenFlag() { BrokenFlag = 1; };
	inline dgt_void unsetBrokenFlag() { BrokenFlag = 0; };

	inline DgcCliStmt* getStmt() throw(DgcExcept) { return Connection.getStmt(); }
	inline dgt_sint32 checkConn() throw(DgcExcept) { return Connection.checkConnection(); }
	dgt_sint32 connect(DgcCommStream* stream) throw(DgcExcept);
};

class PfccAgentSessionPool : public DgcObject {
  private:
	PfccAgentSession*	AgentSess[PFCC_MAX_AGENT_SESS_NUM];
	dgt_slock			Lock;

	inline dgt_sint8 lock() { return DgcSpinLock::lock(&Lock); };
	inline dgt_void unlock() { DgcSpinLock::unlock(&Lock); };
  protected:
  public:
	PfccAgentSessionPool();
	virtual ~PfccAgentSessionPool();

	dgt_sint32 addSession(PfccAgentSession* session) throw(DgcExcept);
	dgt_void removeSession(PfccAgentSession* session);
	PfccAgentSession* getSession(dgt_sint64 agent_id);
	PfccAgentSession* getSessionIdx(dgt_sint32 idx);
	dgt_void returnSession(PfccAgentSession* session);
};

#endif
