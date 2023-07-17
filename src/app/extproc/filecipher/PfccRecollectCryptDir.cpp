/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccRecollectCryptDir
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccRecollectCryptDir.h"
#include "DgcSqlHandle.h"
#include "DgcDgConstType.h"
#include "PfccAgentProcSvr.h"

PfccRecollectCryptDir::PfccRecollectCryptDir(const dgt_schar* name, PfccAgentListener* agent_listener)
	: PfccAgentProcedure(name,agent_listener)
{
}


PfccRecollectCryptDir::~PfccRecollectCryptDir()
{
}


DgcExtProcedure* PfccRecollectCryptDir::clone()
{
	return new PfccRecollectCryptDir(procName(),AgentListener);
}


dgt_sint32 PfccRecollectCryptDir::initialize() throw(DgcExcept)
{
	return 0; 
}


dgt_sint32 PfccRecollectCryptDir::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pcct_recollect_crypt_dir_in* param_in = (pcct_recollect_crypt_dir_in*) BindRows->data();

	// 1. build bind values
	DgcMemRows	bind_vars(3);
	bind_vars.addAttr(DGC_SB8,0,"agent_id");
	bind_vars.addAttr(DGC_SB8,0,"job_id");
	bind_vars.addAttr(DGC_SB8,0,"dir_id");
	bind_vars.reset();
	bind_vars.add();
	bind_vars.next();
	memcpy(bind_vars.data(), param_in, sizeof(pcct_recollect_crypt_dir_in));  

	// 2. execute stmt
	if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
	AgentSession = AgentListener->agentSessPool().getSession(param_in->agent_id);
	if (AgentSession == 0) {
		THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] has no available session\n",param_in->agent_id)),-1);
	}

	dgt_schar	sql_text[256]={0,};
	sprintf(sql_text,"getRecollectCryptDir");
	DgcCliStmt*	cli_stmt = AgentSession->getStmt();
	ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
	if (cli_stmt->open(sql_text,strlen(sql_text))) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e=EXCEPTnC;
		delete cli_stmt;
		RTHROWnR(e,DgcError(SPOS,"open failed"),-1);
	}

	bind_vars.rewind();
	if (cli_stmt->execute(10,&bind_vars) < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e=EXCEPTnC;
		delete cli_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
	}

	// 4. get return code
	dgt_sint32 frows = cli_stmt->fetch();
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e = EXCEPTnC;
		delete cli_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = cli_stmt->returnRows();
		if (rtn_rows) {
			rtn_rows->rewind();
			if(rtn_rows->next()) {
				pcct_recollect_crypt_dir_out* recollect_out = (pcct_recollect_crypt_dir_out*)rtn_rows->data();
				ReturnRows->add();
				ReturnRows->next();
//pr_debug("%*.*s %lld %lld %lld %lld %u %u %u\n",32,32,de->name,de->file_id,de->dir_id,de->zone_id,de->file_size,de->last_update,de->type,de->encrypt_flag);
				pcct_recollect_crypt_dir_out* result_out = 0;
				result_out = (pcct_recollect_crypt_dir_out*)ReturnRows->data();
				if (result_out) {
					result_out->rtn_code = recollect_out->rtn_code;
					if (result_out->rtn_code) {
						dgt_sint32 err_msg_len = dg_strlen(recollect_out->error_message);
						strncpy(result_out->error_message,recollect_out->error_message,err_msg_len>1024?1024:err_msg_len);
					} else {
						strcpy(result_out->error_message,"success");
					}
				}
			}
		}
	}
	delete cli_stmt;
	ReturnRows->rewind();
	return 0;
}

