/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccMyScriptBuilder
 *   Implementor        :       mwpark
 *   Create Date        :       2012. 04. 10
 *   Description        :       build tdscle script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_MYSQL_SCRIPT_BUILDER_H
#define PCC_MYSQL_SCRIPT_BUILDER_H

#include "PccScriptBuilder.h"
#include "DgcMysqlConnection.h"

class PccMyScriptBuilder : public PccScriptBuilder {
  private:
	dgt_schar  Fname[256];
	DgcMemRows PrivSqlRows;
	DgcMemRows PrivSqlRows2;
	DgcMemRows PkSqlRows;
	DgcMemRows FkSqlRows;
	DgcMemRows IdxSqlRows;
	DgcMemRows IdxColRows; // for non enc column`s unique index (double view except rowid)
	DgcMemRows DefFkDropSqlRows;

	dgt_sint32 step1() throw(DgcExcept);
	dgt_sint32 step2() throw(DgcExcept);
	dgt_sint32 reverse_step1() throw(DgcExcept);
	dgt_sint32 reverse_step2() throw(DgcExcept);
	dgt_sint32 insteadOfTrigger(dgt_sint8 is_final=0) throw(DgcExcept);
	//
	// TabInfo-> getting the table info and setting the parallel degree,IsPkFk,SchemaName
	//
	dgt_sint32 preparePrivInfo() throw(DgcExcept);
	//
	// IdxInfo-> create the all indexs`s org,enc drop create script
	//
	dgt_sint32 prepareIdxInfo() throw(DgcExcept);
	dgt_sint32 prepareCtInfo() throw(DgcExcept);
	dgt_sint32 prepareCt2Info() throw(DgcExcept);

  protected:
  public:
	PccMyScriptBuilder(DgcDatabase* db,DgcSession* sess,dgt_schar* schema_link);
	virtual ~PccMyScriptBuilder();

	dgt_schar* getFname(dgt_sint64 enc_col_id,dgt_uint8 fun_type) throw(DgcExcept);

	virtual dgt_sint32 checkDB(dgt_sint64 db_agent_id,dgt_schar* sys_uid,dgt_schar* sys_pass,dgt_schar* agent_uid,DgcMemRows* rtn_rows) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 setCharset(dgt_sint64 db_agent_id) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 agentTest(dgt_sint64 db_agent_id,DgcMemRows* rtn_rows) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 agentTableTest(dgt_sint64 db_agent_id,DgcMemRows* rtn_rows) throw(DgcExcept) { return 0; };

	virtual DgcCliConnection* connect(dgt_schar* uid=0,dgt_schar* pw=0) throw(DgcExcept);
	virtual dgt_sint32 getTablespace(DgcMemRows* rtn_rows) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 buildScript(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept);
	virtual dgt_sint32 buildScriptMig(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 migInsertSql(dgt_sint64 it_tab_id, dgt_uint8 gen_flag=0) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 buildScriptAddCol(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 buildScriptColAdmin(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 runVerifyMig(dgt_sint64, pct_type_verify_job*) throw(DgcExcept) { return 0; };
	virtual dgt_sint32 buildInstallScript(dgt_sint64 agent_id,dgt_schar* agent_uid,dgt_schar* agent_pass,dgt_schar* soha_home) throw(DgcExcept) { return 0; };
};

#endif
