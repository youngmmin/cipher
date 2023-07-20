/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetStreamStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2019. 07. 05
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccGetStreamStat.h"

PfccGetStreamStat::PfccGetStreamStat(const dgt_schar* name,
                                     PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {}

PfccGetStreamStat::~PfccGetStreamStat() {}

DgcExtProcedure* PfccGetStreamStat::clone() {
    return new PfccGetStreamStat(procName(), AgentListener);
}

dgt_sint32 PfccGetStreamStat::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccGetStreamStat::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pcct_get_stream_stat_in* param_in =
        (pcct_get_stream_stat_in*)BindRows->data();
    AgentSession =
        AgentListener->agentSessPool().getSession(param_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 param_in->agent_id)),
                -1);
    }
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "getStreamStat");
    DgcCliStmt* cli_stmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        // delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }

    DgcMemRows bind_vars(5);
    bind_vars.addAttr(DGC_SB8, 0, "agent_id");
    bind_vars.addAttr(DGC_SB8, 0, "job_id");
    bind_vars.addAttr(DGC_SB8, 0, "file_id");
    bind_vars.addAttr(DGC_SB4, 0, "file_type");
    bind_vars.addAttr(DGC_SB4, 0, "file_count");
    bind_vars.reset();
    bind_vars.add();
    bind_vars.next();
    memcpy(bind_vars.data(), param_in, sizeof(pcct_get_stream_stat_in));

    bind_vars.rewind();
    if (cli_stmt->execute(1, &bind_vars) < 0) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        // delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }
#if 1
    dgt_sint32 frows = cli_stmt->fetch(100);
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            while (rtn_rows->next()) {
                pcct_get_stream_stat_out* get_stream_stat_out =
                    (pcct_get_stream_stat_out*)rtn_rows->data();
                get_stream_stat_out->job_id = param_in->job_id;
                ReturnRows->add();
                ReturnRows->next();
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), get_stream_stat_out,
                           sizeof(pcct_get_stream_stat_out));
                }
            }
        }
    }
#endif
    ReturnRows->rewind();
    if (cli_stmt) delete cli_stmt;
    cli_stmt = 0;
    return 0;
}

#if 0
dgt_sint32 PfccGetStreamStat::fetch() throw(DgcExcept)
{
	if (cli_stmt->check() < 0) ATHROWnR(DgcError(SPOS,"client stamt check failed"),-1);
	pcct_get_stream_stat_out* param_in = (pcct_get_stream_stat_out*)BindRows->data();
	dgt_sint32	frows = cli_stmt->fetch(100);
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = cli_stmt->returnRows();
		if (rtn_rows) {
			if (rtn_rows->numRows() == 0) {
				cli_stmt->close();
			} else {
				while(rtn_rows->next()) {
					pcct_get_stream_stat_out* get_stream_stat_out = (pcct_get_stream_stat_out*)rtn_rows->data();
					get_stream_stat_out->job_id = param_in->job_id;
					ReturnRows->add();
					ReturnRows->next();
					if (ReturnRows->data()) {
						memcpy(ReturnRows->data(),get_stream_stat_out,sizeof(pcct_get_stream_stat_out));
					}
				}
				ReturnRows->rewind();
			}
		}
	}
	return 0;

}
#endif
