/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtPutExtKey
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 03. 04
 *   Description        :       KRED put ext key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtPutExtKey.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "DgcDatabaseLink.h"


PccKredStmtPutExtKey::PccKredStmtPutExtKey(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",1);
        SelectListDef->addAttr(DGC_SB4,0,"result");
}


PccKredStmtPutExtKey::~PccKredStmtPutExtKey()
{
}


dgt_sint32 PccKredStmtPutExtKey::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	pc_type_put_ext_key_in* key_in = (pc_type_put_ext_key_in*)mrows->data();
	dgt_schar sql_text[512];
	memset(sql_text,0,512);
	dg_sprintf(sql_text,"select soha_link from ppmt_product where product_id = 0");
	DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(Session, sql_text, strlen(sql_text));
	DgcExcept* e=0;
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%s] failed.",sql_text),-1);
	}
	dgt_schar* link_name;
	if ((link_name=(dgt_schar*)sql_stmt->fetch())) {
		DgcDatabaseLink dblink(link_name);
		DgcCliStmt* cli_stmt=dblink.getStmt();
		if (cli_stmt == 0) {
			e=EXCEPTnC;
			RTHROWnR(e,DgcError(SPOS,"master connect failed.",sql_text),-1);
		}
		dgt_schar sql_text[512];
		memset(sql_text,0,512);
		sprintf(sql_text,"select * from PCP_CREATE_EXT_KEY('%s','%s',%u)",key_in->key_name, key_in->key, key_in->format_no);
		if (cli_stmt->execute(sql_text,strlen(sql_text)) < 0) {
			e=EXCEPTnC;
			delete cli_stmt;
			RTHROWnR(e,DgcError(SPOS,"master sql[%s] execute failed",sql_text),-1);
		}
		e=EXCEPTnC;
		delete cli_stmt;
	}
	e=EXCEPTnC;
	delete e;
	delete sql_stmt;
	IsExecuted=1;
	NumRtnRows=0;
	Result=1;
	return 0;
}


dgt_uint8* PccKredStmtPutExtKey::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&Result;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
