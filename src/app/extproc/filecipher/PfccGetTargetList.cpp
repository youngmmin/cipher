/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetTargetList
 *   Implementor        :       sonsuhun
 *   Create Date        :       2018. 03. 27
 *   Description        :       get target file list in file queue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccGetTargetList.h"

PfccGetTargetList::PfccGetTargetList(const dgt_schar* name, PfccAgentListener* agent_listener)
	: PfccAgentProcedure(name,agent_listener)
{
	CliStmt=0;
}


PfccGetTargetList::~PfccGetTargetList()
{
	if (CliStmt) delete CliStmt;
}


DgcExtProcedure* PfccGetTargetList::clone()
{
	return new PfccGetTargetList(procName(),AgentListener);
}


dgt_sint32 PfccGetTargetList::initialize() throw(DgcExcept)
{
	return 0; 
}


dgt_sint32 PfccGetTargetList::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pcct_target_list_in* param_in = (pcct_target_list_in*)BindRows->data();
	AgentSession = AgentListener->agentSessPool().getSession(param_in->agent_id);
	if (AgentSession == 0) {
		THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] has no available session\n",param_in->agent_id)),-1);
	}
	dgt_schar	sql_text[256]={0,};
	sprintf(sql_text,"getTargetList");
	CliStmt = AgentSession->getStmt();
	ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
	if (CliStmt->open(sql_text,strlen(sql_text))) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e=EXCEPTnC;
		delete CliStmt;
		RTHROWnR(e,DgcError(SPOS,"open failed"),-1);
	}

	DgcMemRows	bind_vars(3);
	bind_vars.addAttr(DGC_SB8,0,"agent_id");
	bind_vars.addAttr(DGC_SB8,0,"job_id");
	bind_vars.addAttr(DGC_UB1,0,"target_type");
	bind_vars.reset();
	bind_vars.add();
	bind_vars.next();
	memcpy(bind_vars.data(), param_in, sizeof(pcct_target_list_in));  

	bind_vars.rewind();
	if (CliStmt->execute(1,&bind_vars) < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e=EXCEPTnC;
		delete CliStmt;
		CliStmt = 0;
		RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
	}
#if 1
	dgt_sint32	frows = CliStmt->fetch(100);
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = CliStmt->returnRows();
		if (rtn_rows) {
			rtn_rows->rewind();
			while(rtn_rows->next()) {
				pcct_target_list_out* target_list_out = (pcct_target_list_out*)rtn_rows->data();
				target_list_out->job_id = param_in->job_id;
				ReturnRows->add();
				ReturnRows->next();
				if (ReturnRows->data()) {
					memcpy(ReturnRows->data(),target_list_out,sizeof(pcct_target_list_out));
				}
			}
		}
	}
#endif
	ReturnRows->rewind();
	return 0;
}

dgt_sint32 PfccGetTargetList::fetch() throw(DgcExcept)
{
	if (CliStmt->check() < 0) ATHROWnR(DgcError(SPOS,"client stamt check failed"),-1);
#if 1
	pcct_target_list_in* param_in = (pcct_target_list_in*)BindRows->data();
	dgt_sint32	frows = CliStmt->fetch(100);
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = CliStmt->returnRows();
		if (rtn_rows) {
			if (rtn_rows->numRows() == 0) {
				CliStmt->close();
			} else {
				while(rtn_rows->next()) {
					pcct_target_list_out* target_list_out = (pcct_target_list_out*)rtn_rows->data();
					target_list_out->job_id = param_in->job_id;
					ReturnRows->add();
					ReturnRows->next();
					if (ReturnRows->data()) {
						memcpy(ReturnRows->data(),target_list_out,sizeof(pcct_target_list_out));
					}
				}
				ReturnRows->rewind();
			}
		}
	}
#endif
	return 0;

}
