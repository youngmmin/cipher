/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccDropAgent
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 03. 25
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccDropAgent.h"
#include "DgcOracleConnection.h"


PccDropAgent::PccDropAgent(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccDropAgent::~PccDropAgent()
{
}


DgcExtProcedure* PccDropAgent::clone()
{
	return new PccDropAgent(procName());
}

typedef struct {
        dgt_schar       instance_name[33];
        dgt_schar       listen_ip[256];
        dgt_uint16      listen_port;
	dgt_uint8	db_type;
} pc_type_connect_db;

typedef struct {
        dgt_sint32      result_code;
        dgt_schar       result_msg[1024];
} pc_type_drop_agent_out;


dgt_sint32 PccDropAgent::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	if (!(InRow=(pc_type_drop_agent_in*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	pc_type_drop_agent_out out_param;
	memset(&out_param,0,sizeof(pc_type_drop_agent_out));

        PccScriptBuilder*       cipher_builder=getScriptBuilder(InRow->service_id,PCC_ID_TYPE_AGENT);
        if (!cipher_builder) {
                ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
        }
        //
        // get the agent row
        //
	dgt_schar sql_text[1024];
	memset(sql_text,0,1024);
        sprintf(sql_text,"select * from pct_db_agent where service_id=%lld",InRow->service_id);
        DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        pct_type_db_agent*  ta;
        if ((ta=(pct_type_db_agent*)sql_stmt->fetch()) == 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
        }
        pct_type_db_agent   agent;
        memcpy(&agent, ta, sizeof(pct_type_db_agent));
        delete sql_stmt;

	//
	// create the oracle connection as system user
	//
        memset(sql_text,0,1024);
        sprintf(sql_text,"select a.instance_name, c.listen_ip, c.listen_port, e.db_type "
                         "from pt_db_instance a, pct_db_agent b, pt_listen_addr c, pt_db_service d, pt_database e "
                         "where a.instance_id = b.instance_id "
                         "and   a.instance_id = d.instance_id "
                         "and   d.service_id  = c.service_id "
                         "and   d.db_id = e.db_id "
                         "and   b.service_id  = %lld",InRow->service_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        pc_type_connect_db*  tmp;
        pc_type_connect_db   conDb;
        if ((tmp=(pc_type_connect_db*)sql_stmt->fetch()) == 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
        }
        memcpy(&conDb, tmp, sizeof(pc_type_connect_db));
        delete sql_stmt;

        pc_type_drop_agent_out out;
        DgcCliConnection* conn=0;
        memset(&out,0,sizeof(pc_type_drop_agent_out));
        if (conDb.db_type == 1) {
		conn=new DgcOracleConnection();
                dgt_schar       conn_string[1024];
                memset(conn_string,0,1024);
                sprintf(conn_string,
                        "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)))"
                        "(CONNECT_DATA=(SERVER=DEDICATED)(SID=%s)))",
                        conDb.listen_ip,
                        conDb.listen_port,
                        conDb.instance_name);
                const dgt_schar*      priv=0;
                if (!strcasecmp(InRow->sys_uid,"sys")) priv="SYSDBA";
                if (conn->connect(conn_string, nul, InRow->sys_uid, InRow->sys_passwd, priv) != 0) {
                        DgcExcept*      e=EXCEPTnC;
			delete conn;
                        if (e) {
		                DgcError*       err=e->getErr();
                		while(err->next()) err=err->next();
		                ReturnRows->reset();
		                ReturnRows->add();
                		ReturnRows->next();
		                memset(ReturnRows->data(),0,ReturnRows->rowSize());
                		sprintf(out_param.result_msg,"%s",(dgt_schar*)err->message());
		                out_param.result_code=-1;
                		memcpy(ReturnRows->data(),&out_param,sizeof(pc_type_drop_agent_out));
		                ReturnRows->rewind();
				return 0;
                        }
		}
	}
        //
        // run script
        //
        dgt_sint16      exe_counter=0;
        dgt_sint16      step_no=0;
        dgt_sint16      stmt_no=0;
        dgt_sint32      rtn=0;
        DgcExcept*      e=0;
        if (agent.inst_step >= 4) {
                //
                // get a script builder for running sys owner scripts
                //
                for(stmt_no=0; (rtn=cipher_builder->getScript(InRow->service_id, 0, -2, stmt_no+1)) > 0; stmt_no++) {
                        if (cipher_builder->runScript(cipher_builder->scriptText(),conn)) break;
                        exe_counter++;
                        DgcWorker::PLOG.tprintf(0,"script[%d:%d] executed.\n",step_no,stmt_no);
                }
                delete EXCEPTnC;
	}
	for(stmt_no=0; (rtn=cipher_builder->getScript(InRow->service_id, 0, -1, stmt_no+1)) > 0; stmt_no++) {
		if (cipher_builder->runScript(cipher_builder->scriptText(),conn)) break;
		exe_counter++;
		DgcWorker::PLOG.tprintf(0,"script[%d:%d] executed.\n",step_no,stmt_no);
	}
	e=EXCEPTnC;
        if (e) {
        	DgcError*       err=e->getErr();
	        while(err->next()) err=err->next();
		ReturnRows->reset();
		ReturnRows->add();
		ReturnRows->next();
		memset(ReturnRows->data(),0,ReturnRows->rowSize());
		sprintf(out_param.result_msg,"[%.500s]%s",cipher_builder->scriptText(),(dgt_schar*)err->message());
		out_param.result_code=-1;
		memcpy(ReturnRows->data(),&out_param,sizeof(pc_type_drop_agent_out));
		ReturnRows->rewind();
        	delete cipher_builder;
		delete e;
		delete conn;
		return 0;
        }
	delete conn;
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        memset(ReturnRows->data(),0,ReturnRows->rowSize());
        sprintf(out_param.result_msg,"%s",(dgt_schar*)"User Droped Successfully");
        out_param.result_code=0;
        memcpy(ReturnRows->data(),&out_param,sizeof(pc_type_drop_agent_out));
        ReturnRows->rewind();
        return 0;
}
