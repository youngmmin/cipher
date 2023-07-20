/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccInstAgentUser
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 03. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccInstAgentUser.h"

#include "DgcOracleConnection.h"

PccInstAgentUser::PccInstAgentUser(const dgt_schar* name)
    : PccMetaProcedure(name) {}

PccInstAgentUser::~PccInstAgentUser() {}

DgcExtProcedure* PccInstAgentUser::clone() {
    return new PccInstAgentUser(procName());
}

typedef struct {
    dgt_schar instance_name[33];
    dgt_schar listen_ip[256];
    dgt_uint16 listen_port;
    dgt_uint8 db_type;
} pc_type_connect_db;

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pc_type_inst_agent_user_out;

dgt_sint32 PccInstAgentUser::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (!(InRow = (pc_type_inst_agent_user_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pc_type_inst_agent_user_out out_param;
    memset(&out_param, 0, sizeof(pc_type_inst_agent_user_out));

    //
    // get dbms_type
    //
    dgt_schar sql_text[1024];
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select a.db_type "
            "from pt_db_instance a, pct_db_agent b "
            "where a.instance_id = b.instance_id "
            "and   b.db_agent_id  = %lld",
            InRow->db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_uint8* ptr_db_type = 0;
    dgt_uint8 db_type = 0;
    if ((ptr_db_type = (dgt_uint8*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    db_type = *ptr_db_type;
    delete sql_stmt;

    switch (db_type) {
        case 11:  // oracle
        case 12:  // mssql, sqlserver
        case 21:  // edb, postgresql
            break;
        default:
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            memset(ReturnRows->data(), 0, ReturnRows->rowSize());
            sprintf(out_param.result_msg, "%s",
                    (dgt_schar*)"not Supported dbms type\n");
            out_param.result_code = 0;
            memcpy(ReturnRows->data(), &out_param,
                   sizeof(pc_type_inst_agent_user_out));
            ReturnRows->rewind();
            return 0;
    }

    //
    // get the agent row
    //
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "select * from pct_db_agent where db_agent_id=%lld",
            InRow->db_agent_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
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
    delete EXCEPTnC;
    delete sql_stmt;

    //
    // check DB(sys connect, duplicate user check)
    //
    PccScriptBuilder* cipher_builder =
        getScriptBuilder(InRow->db_agent_id, PCC_ID_TYPE_AGENT);
    if (!cipher_builder) {
        ATHROWnR(DgcError(SPOS, "getScriptBuilder failed."), -1);
    }
    if (agent.curr_install_step == 0 && agent.curr_install_stmt <= 1) {
        if (InRow->inst_mode == 0) {
            if (cipher_builder->checkDB(InRow->db_agent_id, InRow->sys_uid,
                                        InRow->sys_passwd, InRow->agent_uid,
                                        ReturnRows) < 0) {
                DgcExcept* e = EXCEPTnC;
                delete cipher_builder;
                if (e) {
                    RTHROWnR(e,
                             DgcError(SPOS, "PccInstAgentUser CheckDB failed"),
                             -1);
                }
                return 0;
            }
        }
        //
        // delete old scripts
        //
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "delete pct_script where enc_tab_id=%lld",
                InRow->db_agent_id);
        sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            delete cipher_builder;
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "delete failed."), -1);
        }
        delete sql_stmt;
        //
        // build new scripts
        //
        if (cipher_builder->buildInstallScript(
                InRow->db_agent_id, InRow->agent_uid, InRow->agent_passwd,
                InRow->soha_home) < 0) {
            delete cipher_builder;
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "buildInstallScript failed"), -1);
            }
            return 0;
        }
    }
    if (InRow->inst_mode == 1) {
        delete cipher_builder;
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        memset(ReturnRows->data(), 0, ReturnRows->rowSize());
        sprintf(out_param.result_msg, "%s",
                (dgt_schar*)"User Install Script Created Successfully");
        out_param.result_code = 0;
        ReturnRows->rewind();
        return 0;
    }

    //
    // create the oracle connection as system user
    //
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select a.instance_name, c.listen_ip, c.listen_port, a.db_type "
            "from pt_db_instance a, pct_db_agent b, pt_listen_addr c, "
            "pt_listen_service d, pt_database e "
            "where a.instance_id = b.instance_id "
            "and   a.instance_id = d.instance_id "
            "and   d.listen_addr_id  = c.listen_addr_id "
            "and   b.db_id = e.db_id "
            "and   b.db_agent_id  = %lld",
            InRow->db_agent_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_connect_db* tmp;
    pc_type_connect_db conDb;
    if ((tmp = (pc_type_connect_db*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    memcpy(&conDb, tmp, sizeof(pc_type_connect_db));
    delete sql_stmt;

    pc_type_inst_agent_user_out out;
    DgcOracleConnection* conn = 0;
    memset(&out, 0, sizeof(pc_type_inst_agent_user_out));
    if (conDb.db_type == 11) {
        dgt_schar conn_string[1024];
        memset(conn_string, 0, 1024);
        sprintf(conn_string,
                "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)("
                "PORT=%d)))"
                "(CONNECT_DATA=(SERVER=DEDICATED)(SID=%s)))",
                conDb.listen_ip, conDb.listen_port, conDb.instance_name);
        conn = new DgcOracleConnection();
        const dgt_schar* priv = 0;
        if (!strcasecmp(InRow->sys_uid, "sys")) priv = "SYSDBA";
        if (conn->connect(conn_string, nul, InRow->sys_uid, InRow->sys_passwd,
                          priv) != 0) {
            DgcExcept* e = EXCEPTnC;
            delete conn;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
            }
        }
    }
    //
    // if inst_mode = 0 then run script
    //
    dgt_sint16 exe_counter = 0;
    dgt_sint16 step_no = agent.curr_install_step;
    ;
    if (agent.curr_install_stmt == 0) {
        agent.curr_install_stmt = 1;
    }
    dgt_sint16 stmt_no = agent.curr_install_stmt;
    dgt_sint32 rtn = 0;
    DgcExcept* e = 0;
    if (agent.curr_install_step <= 1) {
        //
        // get a script builder for running sys owner scripts
        //
        for (; (rtn = cipher_builder->getScript(InRow->db_agent_id, 0, step_no,
                                                stmt_no)) > 0;
             stmt_no++) {
            if (cipher_builder->runScript(cipher_builder->scriptText(), conn))
                break;
            exe_counter++;
            DgcWorker::PLOG.tprintf(0, "script[%d:%d] executed.\n", step_no,
                                    stmt_no);
        }
        e = EXCEPTnC;
        //
        // update installation step
        //
        if (e) {
            agent.curr_install_stmt = stmt_no;
            sprintf(sql_text,
                    "update pct_db_agent "
                    "set(curr_install_stmt,inst_step,last_update)=(%d,-1,"
                    "nextLastUpdate('PCT_DB_AGENT', %lld, 2)) where "
                    "db_agent_id=%lld",
                    stmt_no, InRow->db_agent_id, InRow->db_agent_id);
        } else {
            if ((rtn = cipher_builder->getScript(InRow->db_agent_id, 0, 1, 1)) >
                0) {
                cipher_builder->runScript(cipher_builder->scriptText(), conn);
                delete EXCEPTnC;
            }
            delete cipher_builder;
            agent.curr_install_step = 2;
            agent.curr_install_stmt = 0;
            sprintf(sql_text,
                    "update pct_db_agent "
                    "set(curr_install_step,curr_install_stmt,inst_step,last_"
                    "update)=(2,0,1,nextLastUpdate('PCT_DB_AGENT', %lld, 2)) "
                    "where db_agent_id=%lld",
                    InRow->db_agent_id, InRow->db_agent_id);
        }
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
        delete sql_stmt;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            memset(ReturnRows->data(), 0, ReturnRows->rowSize());
            sprintf(out_param.result_msg, "[%.500s]%s",
                    cipher_builder->scriptText(), (dgt_schar*)err->message());
            out_param.result_code = -3;
            memcpy(ReturnRows->data(), &out_param,
                   sizeof(pc_type_inst_agent_user_out));
            ReturnRows->rewind();
            delete cipher_builder;
            delete e;
            delete conn;
            return 0;
        }
    }
    delete conn;
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    memset(ReturnRows->data(), 0, ReturnRows->rowSize());
    sprintf(out_param.result_msg, "%s",
            (dgt_schar*)"User Created Successfully");
    out_param.result_code = 0;
    memcpy(ReturnRows->data(), &out_param, sizeof(pc_type_inst_agent_user_out));
    ReturnRows->rewind();
    return 0;
}
