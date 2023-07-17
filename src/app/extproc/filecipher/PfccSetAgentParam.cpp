/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccSetAgentParam
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccSetAgentParam.h"
#include "DgcSqlHandle.h"
#include "DgcDgConstType.h"
#include "PfccAgentProcSvr.h"
#include "PcaCharSetCnvt.h"

PfccSetAgentParam::PfccSetAgentParam(const dgt_schar* name, PfccAgentListener* agent_listener)
	: PfccAgentProcedure(name,agent_listener)
{
}


PfccSetAgentParam::~PfccSetAgentParam()
{
}


DgcExtProcedure* PfccSetAgentParam::clone()
{
	return new PfccSetAgentParam(procName(),AgentListener);
}


dgt_sint32 PfccSetAgentParam::initialize() throw(DgcExcept)
{
	return 0; 
}


dgt_sint32 PfccSetAgentParam::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pfct_set_agent_param_in* param_in = (pfct_set_agent_param_in*) BindRows->data();

	dgt_sint64 last_update = 0;
	dgt_sint64 agent_last_update = 0;
	dgt_sint64 schedule_id = 0;
	dgt_sint32 max_target_files = 0;
	dgt_sint32 collecting_interval = 0;
	dgt_uint8 job_type = 0;
	dgt_uint8 status = 0;

	// 1. get enc_job
	DgcTableSegment* enc_job_tab = PetraTableHandler->getTable("pfct_enc_job");
	if (!enc_job_tab) ATHROWnR(DgcError(SPOS,"getTable[pfct_enc_job] failed"),-1);
	DgcIndexSegment* enc_job_idx = PetraTableHandler->getIndex("pfct_enc_job_idx1");
	if (!enc_job_idx) ATHROWnR(DgcError(SPOS,"getIndex[pfct_enc_job_idx1] failed"),-1);

	pfct_type_enc_job job_rows;
	memset(&job_rows,0,sizeof(pfct_type_enc_job));
	job_rows.enc_job_id = param_in->job_id;

	DgcRowList job_row_list(enc_job_tab);
	job_row_list.reset();
	if (enc_job_idx->find((dgt_uint8*)&job_rows,job_row_list,1) < 0) {
		ATHROWnR(DgcError(SPOS,"enc_job_idx search failed"),-1);
	}

	if (job_row_list.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"pfct_enc_job[%lld] data not found",param_in->job_id)),-1);
	job_row_list.rewind();

	pfct_type_enc_job* enc_job = 0;
	if (job_row_list.next() && (enc_job=(pfct_type_enc_job*)job_row_list.data())) {
		last_update = enc_job->last_update;
		agent_last_update = enc_job->agent_last_update;
		schedule_id = enc_job->schedule_date_id;
		max_target_files = enc_job->max_target_files;
		collecting_interval = enc_job->collecting_interval;
		status = enc_job->status;
		job_type = enc_job->job_type;
	}

	dgt_uint32 agent_param_size = 0;
//agent_last_update = last_update -1; //for debuging
	// check last_update to decide executing setParams
	if (agent_last_update < last_update) {
		// 2. build param
		PfccAgentParamBuilder param_builder(param_in->agent_id);
		if (param_builder.buildAgentParams(param_in->job_id,schedule_id) < 0) {
			ATHROWnR(DgcError(SPOS,"buildAgentParams failed"),-1);
		}

		agent_param_size = param_builder.agentParamSize();
pr_debug("agent_param_size[%u]\n",param_builder.agentParamSize());
pr_debug("agent_param[%s]\n",param_builder.agentParam());

	//3. charset converting check
	dgt_sint32	convert_flag = 0;
	dgt_schar agent_charset[65];
	memset(agent_charset,0,sizeof(agent_charset));
	dgt_sint32 rtn = 0;
	DgcSqlHandle sql_handle(DgcDbProcess::sess()); // for select charset from pfct_agent
	dgt_void* rtn_row = 0; // for sql_handle
	dgt_schar sel_text[256];
	memset(sel_text,0,256);
	sprintf(sel_text,
			"select char_set "
			"from pfct_agent "
			"where agent_id = %lld "
			,param_in->agent_id);

	if (sql_handle.execute(sel_text,dg_strlen(sel_text)) < 0) {
		AgentSession->setBrokenFlag();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*	e = EXCEPTnC;
		//if (cli_stmt) delete cli_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
	}

	if (!(rtn = sql_handle.fetch(rtn_row)) && rtn_row) { 
		//fetch success
		strncpy(agent_charset, (dgt_schar*)rtn_row, strlen((dgt_schar*)rtn_row));
		if (strlen(agent_charset) && 
				((strncasecmp(agent_charset,"EUC-KR",sizeof("EUC-KR")) == 0) ||
				(strncasecmp(agent_charset,"CP949",sizeof("CP949")) == 0))) //need converting 
			convert_flag = 1;
	}
	//4. agent param charconv
	dgt_schar*	conv_agent_param = new dgt_schar[agent_param_size];
	memset(conv_agent_param,0,agent_param_size);
	if (convert_flag) {
		PcaCharSetCnvt * charset = new PcaCharSetCnvt(agent_charset,"UTF-8");
		rtn = charset->convert(param_builder.agentParam(),agent_param_size,conv_agent_param,agent_param_size);
		if (rtn < 0) {
			if (charset) delete charset;
			charset = 0;
			if (conv_agent_param) delete conv_agent_param;
			conv_agent_param = 0;
		THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] char conversion failed: param [%s]\n",param_in->agent_id,param_builder.agentParam())),-1);
		}
		agent_param_size = rtn;
		if (charset) delete charset;
		charset = 0;
	} else memcpy(conv_agent_param, param_builder.agentParam(), agent_param_size);

//printf("conv_agent_param [%s], agent_param_size [%d], strlen(conv_agent_param) [%d] rtn [%d] \n",conv_agent_param,agent_param_size,strlen(conv_agent_param),rtn);

		// 5. build bind values
		DgcMemRows	bind_vars(7);
		bind_vars.addAttr(DGC_SB8,0,"job_id");
		bind_vars.addAttr(DGC_SB8,0,"last_update");
		bind_vars.addAttr(DGC_SB4,0,"max_target_files");
		bind_vars.addAttr(DGC_SB4,0,"collecting_interval");
		bind_vars.addAttr(DGC_UB1,0,"job_type");
		bind_vars.addAttr(DGC_UB1,0,"status");
		bind_vars.addAttr(DGC_SCHR,1025,"params");
		bind_vars.reset();

		dgt_sint32 offset = 0;
		dgt_sint32 remain = (dgt_sint32)agent_param_size;
		pcct_set_params* set_params = 0;
		while (remain > 0) {
			bind_vars.add();
			bind_vars.next();
			set_params = (pcct_set_params*)bind_vars.data();
			if (!set_params) continue;
			set_params->job_id = param_in->job_id;
			set_params->last_update = last_update;
			set_params->max_target_files = max_target_files;
			set_params->collecting_interval = collecting_interval;
			set_params->job_type = job_type;
			set_params->status = status;

			if (remain >= 1024) {
				memcpy(set_params->data,conv_agent_param+offset,1024);
				offset += 1024;
				remain -= 1024;
			} else {
				memcpy(set_params->data,conv_agent_param+offset,remain);
				offset += remain;
				remain = 0;
			}
		}
		if (conv_agent_param) delete conv_agent_param;
		conv_agent_param = 0;

		// 6. execute stmt
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		AgentSession = AgentListener->agentSessPool().getSession(param_in->agent_id);
		if (AgentSession == 0) {
			THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] has no available session\n",param_in->agent_id)),-1);
		}

		dgt_schar	sql_text[256]={0,};
		sprintf(sql_text,"setParams");
		DgcCliStmt*	cli_stmt = AgentSession->getStmt();
		ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
		if (cli_stmt->open(sql_text,strlen(sql_text))) {
			AgentSession->setBrokenFlag();
			if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
			DgcExcept*	e=EXCEPTnC;
			delete cli_stmt;
			RTHROWnR(e,DgcError(SPOS,"open failed"),-1);
		}
	
		bind_vars.rewind();
		if (cli_stmt->execute(10,&bind_vars) < 0) {
			AgentSession->setBrokenFlag();
			if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
			DgcExcept*	e=EXCEPTnC;
			delete cli_stmt;
			RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
		}
		delete cli_stmt;

		// 7. update agent_last_update
		if (enc_job) {
			enc_job->agent_last_update = last_update;
			if (enc_job_tab->pinUpdate(job_row_list) < 0) ATHROWnR(DgcError(SPOS,"pinUpdate failed"),-1);
			job_row_list.rewind();
			if (enc_job_tab->updateCommit(DgcDbProcess::sess(),job_row_list) < 0) {
				ATHROWnR(DgcError(SPOS,"updateCommit failed"), -1);
			}
		}
	}

	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	memcpy(ReturnRows->data(),&agent_param_size,sizeof(dgt_uint32));
	ReturnRows->rewind();
	return 0;
}

