/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetFileInfo
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 05. 24
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccGetFileInfo.h"

#include "PcaCharSetCnvt.h"

PfccGetFileInfo::PfccGetFileInfo(const dgt_schar* name,
                                 PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    pr_debug("new procedure!\n");
}

PfccGetFileInfo::~PfccGetFileInfo() { pr_debug("delete procedure!\n"); }

DgcExtProcedure* PfccGetFileInfo::clone() {
    return new PfccGetFileInfo(procName(), AgentListener);
}

dgt_sint32 PfccGetFileInfo::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccGetFileInfo::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    // 1. get agent session
    pfcc_get_file_info_in* info_in = (pfcc_get_file_info_in*)BindRows->data();
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession = AgentListener->agentSessPool().getSession(info_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 info_in->agent_id)),
                -1);
    }
    // 2. get agent statement
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "getDirEntry");

    DgcCliStmt* cli_stmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    // 3. open
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }
    // 4. prepare bind data
    DgcMemRows bind_vars(3);
    bind_vars.addAttr(DGC_SCHR, 1024, "dir_path");
    bind_vars.addAttr(DGC_SB8, 0, "offset");
    bind_vars.addAttr(DGC_SB4, 0, "fetch_count");
    bind_vars.reset();
    bind_vars.add();
    bind_vars.next();
    pcct_dir_entry_in* dir_entry_in = (pcct_dir_entry_in*)bind_vars.data();
    strncpy(dir_entry_in->dir_path, info_in->dir_path,
            strlen(info_in->dir_path));
    dir_entry_in->offset = info_in->offset;
    dir_entry_in->fetch_count = info_in->fetch_count;

    // 5. charset converting check
    dgt_sint32 convert_flag = 0;
    dgt_schar agent_charset[65];
    memset(agent_charset, 0, sizeof(agent_charset));
    dgt_sint32 rtn = 0;
    DgcSqlHandle sql_handle(
        DgcDbProcess::sess());  // for select charset from pfct_agent
    dgt_void* rtn_row = 0;      // for sql_handle
    dgt_schar sel_text[256];
    memset(sel_text, 0, 256);
    sprintf(sel_text,
            "select char_set "
            "from pfct_agent "
            "where agent_id = %lld ",
            info_in->agent_id);

    if (sql_handle.execute(sel_text, dg_strlen(sel_text)) < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }

    if (!(rtn = sql_handle.fetch(rtn_row)) && rtn_row) {
        // fetch success
        strncpy(agent_charset, (dgt_schar*)rtn_row,
                strlen((dgt_schar*)rtn_row));
        if (strlen(agent_charset) &&
            ((strncasecmp(agent_charset, "EUC-KR", sizeof("EUC-KR")) == 0) ||
             (strncasecmp(agent_charset, "CP949", sizeof("CP949")) ==
              0)))  // need converting
            convert_flag = 1;
    }

    // added by shson charconv
    PcaCharSetCnvt* charset = new PcaCharSetCnvt(agent_charset, "UTF-8");
    dgt_schar conv_name[1024];
    if (convert_flag) {
        pr_debug("before dir_entry_in->dir_path [%s], dir_path_len [%d]\n",
                 dir_entry_in->dir_path, strlen(dir_entry_in->dir_path));

        memset(conv_name, 0, 1024);
        rtn = charset->convert(dir_entry_in->dir_path,
                               strlen(dir_entry_in->dir_path), conv_name, 1024);
        if (rtn > 0) {
            memset(dir_entry_in->dir_path, 0, sizeof(dir_entry_in->dir_path));
            memcpy(dir_entry_in->dir_path, conv_name,
                   sizeof(dir_entry_in->dir_path));
        }
        // for fetch - when fetch, file_name must be converting to utf-8
        charset->setCharSet("UTF-8", agent_charset);
    }

    pr_debug(
        "dir_entry_in->dir_path [%s], strlen(dir_entry_in->dir_path) [%d], "
        "dir_entry_in->offset [%lld] dir_entry_in->fetch_count [%d] "
        "converting_flag [%d]\n",
        dir_entry_in->dir_path, strlen(dir_entry_in->dir_path),
        dir_entry_in->offset, dir_entry_in->fetch_count, convert_flag);

    // 6. execute
    bind_vars.rewind();
    if (cli_stmt->execute(info_in->fetch_count, &bind_vars) < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        if (charset) delete charset;
        charset = 0;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }

    //
    // 7. first fetching
    //
    dgt_sint32 frows = cli_stmt->fetch(info_in->fetch_count);
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        if (charset) delete charset;
        charset = 0;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        pr_debug("first fetch start\n");
        ReturnRows->reset();
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            while (rtn_rows->next()) {
                pcct_dir_entry* de = (pcct_dir_entry*)rtn_rows->data();
                // 8. fetch file name converting
                if (convert_flag) {
                    memset(conv_name, 0, 1024);
                    rtn = charset->convert(de->name, strlen(de->name),
                                           conv_name, 1024);
                    if (rtn > 0) {
                        memset(de->name, 0, strlen(de->name));
                        memcpy(de->name, conv_name, strlen(conv_name));
                    }
                }
                ReturnRows->add();
                ReturnRows->next();
                // pr_debug("%*.*s %lld %lld %lld %lld %u %u
                // %u\n",32,32,de->name,de->file_id,de->dir_id,de->zone_id,de->file_size,de->last_update,de->type,de->encrypt_flag);
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), de, sizeof(pcct_dir_entry));
                }
            }
        }
    }

    ReturnRows->rewind();
    if (charset) delete charset;
    if (cli_stmt) delete cli_stmt;
    cli_stmt = 0;
    return 0;
}
#if 0
dgt_sint32 PfccGetFileInfo::fetch() throw(DgcExcept)
{
pr_debug("fetch start\n");

	if (cli_stmt->check() < 0) ATHROWnR(DgcError(SPOS,"client stamt check failed"),-1);
	dgt_sint32	frows = cli_stmt->fetch(500);
	if (frows < 0) {
		AgentSession->setBrokenFlag();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
		DgcExcept*	e = EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	} else {
		ReturnRows->reset();
		DgcMemRows*	rtn_rows = cli_stmt->returnRows();
		if (rtn_rows) {
			if (rtn_rows->numRows() == 0) {
pr_debug("fetch rtn_rows->numRows() [%d]\n",rtn_rows->numRows());
				cli_stmt->close();
			} else {
				while(rtn_rows->next()) {
					pcct_dir_entry* de = (pcct_dir_entry*)rtn_rows->data();
					ReturnRows->add();
					ReturnRows->next();
//pr_debug("%*.*s %lld %lld %lld %lld %u %u %u\n",32,32,de->name,de->file_id,de->dir_id,de->zone_id,de->file_size,de->last_update,de->type,de->encrypt_flag);
					if (ReturnRows->data()) {
						memcpy(ReturnRows->data(),de,sizeof(pcct_dir_entry));
					}
				}
				ReturnRows->rewind();
			}
		}
	}
pr_debug("first fetch cli_stmt->status() [%d]\n",cli_stmt->status());
	if (cli_stmt->status() == Dgccli_stmt::DGC_CS_ST_FEND) { //fetch end
		cli_stmt->close();
		if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
	}

	return 0;
}
#endif
