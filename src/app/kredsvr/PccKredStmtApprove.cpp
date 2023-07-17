/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtApprove
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtApprove.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"


PccKredStmtApprove::PccKredStmtApprove(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0), Result(0)
{
	SelectListDef=new DgcClass("select_list",1);
        SelectListDef->addAttr(DGC_SB4,0,"result");
}


PccKredStmtApprove::~PccKredStmtApprove()
{
}


dgt_sint32 PccKredStmtApprove::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	pc_type_approve_in*	brow = (pc_type_approve_in*)mrows->data();
	//
	// get encryption column info
	//
	dgt_schar	sql_text[512];
	dg_sprintf(sql_text, "select * from pct_enc_column where enc_col_id=%lld", brow->enc_col_id);
	DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	DgcExcept*	e=0;
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->enc_col_id),-1);
	}
	pct_type_enc_column	enc_col;
	dgt_uint8*		tmp_row;
	if ((tmp_row=sql_stmt->fetch()) == 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->enc_col_id),-1);
	}
	memcpy(&enc_col, tmp_row, sizeof(enc_col));
	delete sql_stmt;
	//
	// get session user info
	//
	dg_sprintf(sql_text,"select * from pt_sess_user where psu_id=%lld", brow->user_sid);
	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	e=0;
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->user_sid),-1);
	}
	pt_type_sess_user	sess_user;
	if ((tmp_row=sql_stmt->fetch()) == 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->user_sid),-1);
	}
	memcpy(&sess_user, tmp_row, sizeof(sess_user));
	delete sql_stmt;

	IsExecuted = 1;
	NumRtnRows = 0;
	Result = 1;
	return 0;
}


dgt_uint8* PccKredStmtApprove::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&Result;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
