/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtEncCount
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 12. 13
 *   Description        :       KRED enc count statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtEncCount.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"


PccKredStmtEncCount::PccKredStmtEncCount(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0), Result(0)
{
	SelectListDef=new DgcClass("select_list",1);
	SelectListDef->addAttr(DGC_SB4,0,"result");
}


PccKredStmtEncCount::~PccKredStmtEncCount()
{
}

dgt_sint32 PccKredStmtEncCount::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{

	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	pc_type_enc_count_in*	brow = (pc_type_enc_count_in*)mrows->data();
	//
	// get encryption column info
	//
	dgt_schar	sql_text[1024];
	memset(sql_text,0,1024);
	dg_sprintf(sql_text, "select c.job_id "
			     "from pct_enc_column a, pct_enc_table b, pct_job c "
			     "where a.enc_tab_id = b.enc_tab_id "
			     "and   b.enc_tab_id = c.enc_tab_id "
			     "and   a.enc_col_id=%lld", brow->enc_col_id);
	DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	DgcExcept*	e=0;
	dgt_uint8*		tmp_row;
	dgt_sint64		job_id=0;
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		delete EXCEPTnC;
		delete sql_stmt;
//		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->enc_col_id),-1);
	} else {
		if ((tmp_row=sql_stmt->fetch()) == 0) {
			delete EXCEPTnC;
			delete sql_stmt;
//			RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->enc_col_id),-1);
		} else {
			memcpy(&job_id, tmp_row, sizeof(dgt_sint64));
			delete sql_stmt;
		}
	}
	//
	// insert enc count into pct_job table
	//
	if (job_id) {
		memset(sql_text,0,1024);
        	dg_sprintf(sql_text, "insert into pct_worker(job_id,PROCESSED_ROWS) values(%lld,%lld)",job_id,brow->enc_count);
	        DgcSqlStmt*     sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        	DgcExcept*      e=0;
        	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
	                delete EXCEPTnC;
        	        delete sql_stmt;
		}
        }
	IsExecuted = 1;
	NumRtnRows = 0;
	Result = 1;
	return 0;
}


dgt_uint8* PccKredStmtEncCount::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&Result;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}

