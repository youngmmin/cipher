/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccCipherAgentSvrSessionPool
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 10. 24
 *   Description        :       agent statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CIPHER_AGENT_SVR_SESSION_POOL_H
#define PCC_CIPHER_AGENT_SVR_SESSION_POOL_H

#include "PccCipherAgentSvrSession.h"

class PccCipherAgentSvrSessionPool : public DgcObject {
  private:
	static const dgt_sint32		MAX_NUM_AGENT_SVR_SESS	=	5;
	//
	//(sess_info=(primary=(ip=)(port=))(secondary=(ip=)(port=)))
	//
	dgt_schar			PrimaryIP[257];
	dgt_uint16			PrimaryPort;
	dgt_schar			SecondaryIP[257];
	dgt_uint16			SecondaryPort;
	PccCipherAgentSvrSession*	AgentSvrSession[MAX_NUM_AGENT_SVR_SESS];
	dgt_sint32			NumAgentSvrSess;
  protected:
  public:
	PccCipherAgentSvrSessionPool();
	virtual ~PccCipherAgentSvrSessionPool();

	dgt_sint32 numAgentSvrSess() { return NumAgentSvrSess; } 

	dgt_sint32 startSessions(PccAgentCryptJobPool& job_pool, dgt_sint32 no_sess_sleep_cnt) throw(DgcExcept);
	dgt_sint32 stopSessions() throw(DgcExcept);
	dgt_sint32 cleanBrokenSessions() throw(DgcExcept);
	dgt_sint32 startNewSessions(PccAgentCryptJobPool& job_pool, dgt_sint32 no_sess_sleep_cnt) throw(DgcExcept);

	dgt_sint32 initialize(dgt_sint32 num_sessions, dgt_schar* p_ip, dgt_uint16 p_port, dgt_schar* s_ip=0, dgt_uint16 s_port=0) throw(DgcExcept);
	dgt_sint32 initialize(DgcBgrammer* sess_info) throw(DgcExcept);

};

#endif
