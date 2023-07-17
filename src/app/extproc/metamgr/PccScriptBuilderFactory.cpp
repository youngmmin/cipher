/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccScriptBuilderFactory
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 2. 29
 *   Description        :       script builder factory
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccScriptBuilderFactory.h"


PccScriptBuilderFactory* PccScriptBuilderFactory::Factory=0;


PccScriptBuilderFactory::PccScriptBuilderFactory()
{
}


PccScriptBuilderFactory::~PccScriptBuilderFactory()
{
}


typedef struct {
	dgt_uint8	dbms_type;
	dgt_schar	schema_link[33];
	dgt_schar	db_version[33];
} pc_type_schema_info;


#include "PccOraScriptBuilder.h"
#include "PccTdsScriptBuilder.h"
#include "PccTds2000ScriptBuilder.h"
#include "PccMyScriptBuilder.h"
#include "PccTiberoScriptBuilder.h"
#ifdef linux
#include "PccPostgresScriptBuilder.h"
#endif

PccScriptBuilder* PccScriptBuilderFactory::scriptBuilder(DgcDatabase* db,DgcSession* sess,dgt_sint64 id,dgt_uint8 id_type) throw(DgcExcept)
{
	dgt_schar	sql_text[256];
	if (id_type == PCC_ID_TYPE_AGENT) {
		sprintf(sql_text,"select b.db_type, a.admin_link, b.db_version"
		        " from pct_db_agent a, pt_db_instance b"
		        " where a.db_agent_id = %lld"
		        "   and a.instance_id = b.instance_id", id);
	} else if (id_type == PCC_ID_TYPE_TABLE) {
		sprintf(sql_text,"select d.db_type, c.admin_link, d.db_version "
		        " from pct_enc_table a, pct_enc_schema b, pct_db_agent c, pt_db_instance d "
		        " where a.enc_tab_id = %lld and a.schema_id = b.schema_id and b.db_id = c.db_id and c.instance_id = d.instance_id",id);
	} else {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid id type[%d]",id_type)),0);
	}
	DgcSqlStmt*	sql_stmt=db->getStmt(sess,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),0);
	}
	pc_type_schema_info*	tmp_ptr;
	if ((tmp_ptr=(pc_type_schema_info*)sql_stmt->fetch()) == 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"schema not found by id[%lld]",id),0);
	}
	pc_type_schema_info	schema_info;
	memcpy(&schema_info, tmp_ptr, sizeof(schema_info));
	delete sql_stmt;
	PccScriptBuilder*       script_builder=0;
	if (schema_info.dbms_type == 11) {
		script_builder=new PccOraScriptBuilder(db, sess, schema_info.schema_link);
	} else if (schema_info.dbms_type == DGC_DB_TYPE_TDS) {
		if (!strncasecmp(schema_info.db_version,"2000",32)) {
			script_builder=new PccTds2000ScriptBuilder(db, sess, schema_info.schema_link);
		} else {
			script_builder=new PccTdsScriptBuilder(db, sess, schema_info.schema_link);
		}
	} else if (schema_info.dbms_type == DGC_DB_TYPE_TIBERO) {
		script_builder=new PccTiberoScriptBuilder(db, sess, schema_info.schema_link);
	} else if (schema_info.dbms_type == 4) {
		script_builder=new PccOraScriptBuilder(db, sess, schema_info.schema_link);
	} else if (schema_info.dbms_type == 5) {
		script_builder=new PccOraScriptBuilder(db, sess, schema_info.schema_link);
	} else if (schema_info.dbms_type == DGC_DB_TYPE_MYSQL) {
		script_builder=new PccMyScriptBuilder(db, sess, schema_info.schema_link);
#ifdef linux
	} else if (schema_info.dbms_type == DGC_DB_TYPE_POSTGRESQL) {
		script_builder=new PccPostgresScriptBuilder(db, sess, schema_info.schema_link);
#endif
	} else {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"unsupported dbms type[%s]",schema_info.dbms_type)),0);
	}
	return script_builder;
}
