/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetAgentStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccGetAgentStat.h"

PfccGetAgentStat::PfccGetAgentStat(const dgt_schar* name, PfccAgentListener* agent_listener)
	: PfccAgentProcedure(name,agent_listener)
{
	CliStmt=0;
}


PfccGetAgentStat::~PfccGetAgentStat()
{
	if (CliStmt) delete CliStmt;
}


DgcExtProcedure* PfccGetAgentStat::clone()
{
	return new PfccGetAgentStat(procName(),AgentListener);
}


dgt_sint32 PfccGetAgentStat::initialize() throw(DgcExcept)
{
	return 0; 
}


dgt_sint32 PfccGetAgentStat::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pfcc_get_agent_stat_in* stat_in = (pfcc_get_agent_stat_in*) BindRows->data();
	if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
	AgentSession = AgentListener->agentSessPool().getSession(stat_in->agent_id);
	if (AgentSession == 0) {
		THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] has no available session\n",stat_in->agent_id)),-1);
	}
	dgt_schar	sql_text[256]={0,};
	sprintf(sql_text,"getCryptStat");
	if (CliStmt) {
		delete CliStmt;
		CliStmt=0;
	}
	CliStmt = AgentSession->getStmt();
	ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
	if (CliStmt->open(sql_text,strlen(sql_text))) {
		AgentSession->setBrokenFlag();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"open failed"),-1);
	}

	DgcMemRows	bind_vars(1);
	bind_vars.addAttr(DGC_SB8,0,"job_id");
	bind_vars.add();
	bind_vars.rewind();
	bind_vars.next();
	*(dgt_sint64*)bind_vars.data()=stat_in->job_id;

	if (CliStmt->execute(500,&bind_vars) < 0) {
		AgentSession->setBrokenFlag();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
	}
	dgt_sint32	frows = CliStmt->fetch(500);
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = CliStmt->returnRows();
		if (rtn_rows) {
			rtn_rows->rewind();
			while(rtn_rows->next()) {
				pcct_crypt_stat* stat = (pcct_crypt_stat*)rtn_rows->data();
				ReturnRows->add();
				ReturnRows->next();
				if (ReturnRows->data()) {
					memcpy(ReturnRows->data(),stat,sizeof(pcct_crypt_stat));
				}
			}
		}
	}
	ReturnRows->rewind();
	return 0;
}

dgt_sint32 PfccGetAgentStat::fetch() throw(DgcExcept)
{
	if (CliStmt->check() < 0) ATHROWnR(DgcError(SPOS,"client stamt check failed"),-1);
	dgt_sint32      frows = CliStmt->fetch(500);
	if (frows < 0) {
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*      e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*     rtn_rows = CliStmt->returnRows();
		if (rtn_rows) {
			if (rtn_rows->numRows() == 0) {
				CliStmt->close();
			} else {
				while(rtn_rows->next()) {
					pcct_crypt_stat* stat = (pcct_crypt_stat*)rtn_rows->data();
					ReturnRows->add();
					ReturnRows->next();
					if (ReturnRows->data()) {
						memcpy(ReturnRows->data(),stat,sizeof(pcct_crypt_stat));
					}
				}
				ReturnRows->rewind();
			}
		}
	}
	if (CliStmt->status() == DgcCliStmt::DGC_CS_ST_FEND) { //fetch end
		CliStmt->close();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
	}

	return 0;
}

