/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccGenScript2
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccGenScript2.h"
#include "PccOraScriptBuilder.h"


PccGenScript2::PccGenScript2(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccGenScript2::~PccGenScript2()
{
}


DgcExtProcedure* PccGenScript2::clone()
{
	return new PccGenScript2(procName());
}

typedef struct {
        dgt_uint8       dbms_type;
        dgt_schar       schema_link[33];
        dgt_schar       db_version[33];
} pc_type_schema_info;


dgt_sint32 PccGenScript2::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	enc_tab_id;
	if (!(enc_tab_id=(dgt_sint64*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
        dgt_schar       sql_text[256];
        sprintf(sql_text,"select d.db_type, c.admin_link, d.db_version "
                         " from pct_enc_table a, pct_enc_schema b, pct_db_agent c, pt_db_instance d "
                         " where a.enc_tab_id = %lld and a.schema_id = b.schema_id and b.db_id = c.db_id and c.instance_id = d.instance_id",*enc_tab_id);
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),0);
        }
        pc_type_schema_info*    tmp_ptr;
        if ((tmp_ptr=(pc_type_schema_info*)sql_stmt->fetch()) == 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"schema not found by id[%lld]",*enc_tab_id),0);
        }
        pc_type_schema_info     schema_info;
        memcpy(&schema_info, tmp_ptr, sizeof(schema_info));
        delete sql_stmt;
        PccOraScriptBuilder*       script_builder=0;
        script_builder=new PccOraScriptBuilder(Database, Session, schema_info.schema_link);
	//
	// delete old scripts
	//
	memset(sql_text,0,256);
	sprintf(sql_text,"delete pct_script where enc_tab_id=%lld and step_no = 2 and stmt_no >=20000",*enc_tab_id);
	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"delete failed."),-1);
	}
	delete sql_stmt;
	//
	// build new scripts
	//
	if (script_builder->buildScript2(*enc_tab_id,0)) {
		DgcExcept*	e=EXCEPTnC;
		delete script_builder;
		RTHROWnR(e,DgcError(SPOS,"buildScript failed"),-1);
	}
	delete script_builder;


	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	memset(ReturnRows->data(),0,ReturnRows->rowSize());
        sprintf((dgt_schar*)ReturnRows->data(),"scripts generated.");
        ReturnRows->rewind();
	return 0;
}
