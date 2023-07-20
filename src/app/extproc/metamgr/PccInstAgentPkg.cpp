/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccInstAgentPkg
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 03. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccInstAgentPkg.h"

#include "DgcOracleConnection.h"

PccInstAgentPkg::PccInstAgentPkg(const dgt_schar* name)
    : PccMetaProcedure(name) {}

PccInstAgentPkg::~PccInstAgentPkg() {}

DgcExtProcedure* PccInstAgentPkg::clone() {
    return new PccInstAgentPkg(procName());
}

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pc_type_inst_agent_pkg_out;

dgt_sint32 PccInstAgentPkg::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (!(InRow = (pc_type_inst_agent_pkg_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }

    pc_type_inst_agent_pkg_out out_param;
    memset(&out_param, 0, sizeof(pc_type_inst_agent_pkg_out));

    //
    // get the agent row
    //
    dgt_schar sql_text[1024];
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "select * from pct_db_agent where db_agent_id=%lld",
            InRow->db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pct_type_db_agent* ta;
    if ((ta = (pct_type_db_agent*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    pct_type_db_agent agent;
    memcpy(&agent, ta, sizeof(pct_type_db_agent));
    delete sql_stmt;

    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select max(step_no) from pct_script where enc_tab_id=%lld",
            InRow->db_agent_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_sint16* max_step_tmp = 0;
    dgt_sint16 max_step = 0;
    if ((max_step_tmp = (dgt_sint16*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    memcpy(&max_step, max_step_tmp, sizeof(dgt_sint16));
    delete sql_stmt;
    //
    // build the ScriptBuilder
    //
    PccScriptBuilder* cipher_builder =
        getScriptBuilder(InRow->db_agent_id, PCC_ID_TYPE_AGENT);
    if (!cipher_builder) {
        ATHROWnR(DgcError(SPOS, "getScriptBuilder failed."), -1);
    }
    //
    // run pkg install script
    //
    dgt_sint16 exe_counter = 0;
    dgt_sint16 step_no = agent.curr_install_step;
    if (agent.curr_install_stmt == 0) {
        agent.curr_install_stmt = 1;
    }
    dgt_sint16 stmt_no = agent.curr_install_stmt;
    dgt_sint32 rtn = 0;
    DgcExcept* e = 0;
    for (; step_no >= 2 && step_no <= max_step; step_no++) {
        for (; (rtn = cipher_builder->getScript(InRow->db_agent_id, 0, step_no,
                                                stmt_no)) > 0;
             stmt_no++) {
            if (cipher_builder->runScript(cipher_builder->scriptText())) break;
            DgcWorker::PLOG.tprintf(0, "SQL[%s]\n",
                                    cipher_builder->scriptText());
            exe_counter++;
            DgcWorker::PLOG.tprintf(0, "script[%d:%d] executed.\n", step_no,
                                    stmt_no);
        }
        e = EXCEPTnC;
        //
        // update installation fail step
        //
        if (e) {
            agent.curr_install_stmt = stmt_no;
            sprintf(sql_text,
                    "update pct_db_agent "
                    "set(curr_install_step,curr_install_stmt,inst_step,last_"
                    "update)=(%d,%d,-4,nextLastUpdate('PCT_DB_AGENT', %lld, "
                    "2)) where db_agent_id=%lld",
                    step_no, stmt_no, InRow->db_agent_id, InRow->db_agent_id);
            sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
            if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
            delete sql_stmt;
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            memset(ReturnRows->data(), 0, ReturnRows->rowSize());
            sprintf(out_param.result_msg, "[%.500s]%s",
                    cipher_builder->scriptText(), (dgt_schar*)err->message());
            out_param.result_code = -1 * (step_no - 1);
            memcpy(ReturnRows->data(), &out_param,
                   sizeof(pc_type_inst_agent_pkg_out));
            ReturnRows->rewind();
            delete cipher_builder;
            delete e;
            return 0;
        }
        stmt_no = 1;
    }
    //
    // update installation success step
    //
    sprintf(
        sql_text,
        "update pct_db_agent "
        "set(curr_install_step,curr_install_stmt,inst_step,last_update)=(%d,0,"
        "4,nextLastUpdate('PCT_DB_AGENT', %lld, 2)) where db_agent_id=%lld",
        step_no, InRow->db_agent_id, InRow->db_agent_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
    delete sql_stmt;

    //
    // db charset update(pct_db_agent table)
    //
    if (cipher_builder->setCharset(InRow->db_agent_id) < 0) {
        delete cipher_builder;
        e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    delete cipher_builder;
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    memset(ReturnRows->data(), 0, ReturnRows->rowSize());
    sprintf(out_param.result_msg, "%s",
            (dgt_schar*)"Package Created Successfully");
    out_param.result_code = 0;
    memcpy(ReturnRows->data(), &out_param, sizeof(pc_type_inst_agent_pkg_out));
    ReturnRows->rewind();
    return 0;
}
