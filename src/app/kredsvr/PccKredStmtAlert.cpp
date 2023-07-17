/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtAlert
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtAlert.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "PccAlertControl.h"


PccKredStmtAlert::PccKredStmtAlert(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0), Result(0)
{
	SelectListDef=new DgcClass("select_list",1);
	SelectListDef->addAttr(DGC_SB4,0,"result");
}


PccKredStmtAlert::~PccKredStmtAlert()
{
}

typedef struct {
        dgt_schar       db_name[33];
	dgt_schar       schema_name[33];
	dgt_schar       table_name[33];
	dgt_schar       column_name[33];
} pc_type_enc_col;

typedef struct {
	dgt_sint64 level_id;
	dgt_uint32 alert_count;
} level_type;

dgt_sint32 PccKredStmtAlert::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{

	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	pc_type_alert_in*	brow = (pc_type_alert_in*)mrows->data();
	//
	// get encryption column info
	//
	dgt_schar	sql_text[1024];
	memset(sql_text,0,1024);
	dg_sprintf(sql_text, "select c.db_id "
			     "from pct_enc_column a, pct_enc_table b, pct_enc_schema c "
			     "where a.enc_tab_id = b.enc_tab_id "
			     "and   b.schema_id = c.schema_id "
			     "and   a.enc_col_id=%lld", brow->enc_col_id);
	DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	DgcExcept*	e=0;
	dgt_uint8*		tmp_row;
	dgt_sint64		db_id=0;
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
			memcpy(&db_id, tmp_row, sizeof(dgt_sint64));
			delete sql_stmt;
		}
	}
	//
	// get session user info
	//
	memset(sql_text,0,1024);
	dg_sprintf(sql_text,"select * from pt_sess_user where psu_id=%lld", brow->user_sid);
	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	e=0;
	pt_type_sess_user	sess_user;
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		delete EXCEPTnC;
		delete sql_stmt;
//		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->user_sid),-1);
	} else { 
		if ((tmp_row=sql_stmt->fetch()) == 0) {
			delete EXCEPTnC;
			delete sql_stmt;
//			RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->user_sid),-1);
		} else {
			memcpy(&sess_user, tmp_row, sizeof(sess_user));
			delete sql_stmt;
		}
	}

	//
	// get security level id (when op_code = 3)
	//
	if (brow->op_type == 3) {
		memset(sql_text,0,1024);
	        dg_sprintf(sql_text,"select level_id, level_count from pct_alert_level where level_count<=%lld order by level_count desc", brow->dec_count);
        	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	        e=0;
        	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
	                delete EXCEPTnC;
        	        delete sql_stmt;
//                	RTHROWnR(e,DgcError(SPOS,"execute[security_level query] failed."),-1);
	        } else {
		        if ((tmp_row=sql_stmt->fetch()) == 0) {
        		        delete EXCEPTnC;
                		delete sql_stmt;
//	                	RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->user_sid),-1);
	        	} else {

				level_type tmp_level;
				memset(&tmp_level,0,sizeof(level_type));
				memcpy(&tmp_level,tmp_row,sizeof(level_type));
				brow->level_id=tmp_level.level_id;
        			delete sql_stmt;
			}
		}
	}

	pt_sess_stat	sess_stat;
	memset(&sess_stat,0,sizeof(pt_sess_stat));
	sess_stat.current_dbid=db_id;
	sess_stat.psu_id=brow->user_sid;
        dgt_session     sess_info;
        memset(&sess_info,0,sizeof(dgt_session));
        sess_info.user=&sess_user;
	sess_info.stat=&sess_stat;
        DgcSession      cipher_session(&sess_info);
	PccAlertControl	alert_ctl(cipher_session);
	if (brow->op_type == 1) {
		// encrypt alert
		alert_ctl.encReject(brow);
	} else if (brow->op_type == 2) {
		// decrypt alert
		alert_ctl.decReject(brow);
	} else if (brow->op_type == 3) {
		// too many decrypt alert
		alert_ctl.tooManyDec(brow);
	}
	IsExecuted = 1;
	NumRtnRows = 0;
	Result = 1;
	//
	// for cipher alerting
	// brow->op_type             /* 1 -> encrypt no priv, 2 -> decrypt no priv, 3 -> too many decrypt */
#if 0
	dgt_schar desc[1025];
	memset(desc,0,1025);
	dgt_schar protocol[4];
	memset(protocol,0,4);
	if (sess_user.access_protocol == 1) sprintf(protocol,"BEQ");
	else if (sess_user.access_protocol == 2) sprintf(protocol,"IPC");
	else sprintf(protocol,"TCP");
	if (brow->op_type == 1) {
		sprintf(desc,"PSU_ID[%lld],IP[%s],MAC[%s],DB_USER[%s],OS_USER[%s],PROGRAM[%s],PROTOCOL[%s]"
			     " => [%s.(%s).%s.%s.%s] Rejected Encrypt Request",
			     sess_user.psu_id, sess_user.client_ip, sess_user.client_mac, sess_user.db_sess_user,
			     sess_user.os_user, sess_user.client_program, protocol,
			     enc_col.db_name, enc_col.owner_name,  enc_col.schema_name, enc_col.table_name, enc_col.column_name);
#if 0
		if (DgcAlertQueue::p()->sendAlert(DgcDbProcess::sess(), 0, DGC_ALT_EVNT_RER, 0,0,0,desc)) {
			e=EXCEPTnC;
			RTHROWnR(e,DgcError(SPOS,"send Alert[%lld] failed",brow->user_sid),-1);
		}
#endif
	} else if (brow->op_type == 2) {
		sprintf(desc,"PSU_ID[%lld],IP[%s],MAC[%s],DB_USER[%s],OS_USER[%s],PROGRAM[%s],PROTOCOL[%s]"
                             " => [%s.(%s).%s.%s.%s] Rejected Decrypt Request",
                             sess_user.psu_id, sess_user.client_ip, sess_user.client_mac, sess_user.db_sess_user,
                             sess_user.os_user, sess_user.client_program, protocol,
                             enc_col.db_name, enc_col.owner_name, enc_col.schema_name, enc_col.table_name, enc_col.column_name);
#if 0
                if (DgcAlertQueue::p()->sendAlert(DgcDbProcess::sess(), 0, DGC_ALT_EVNT_RDR, 0,0,0,desc)) {
			e=EXCEPTnC;
			RTHROWnR(e,DgcError(SPOS,"send Alert[%lld] failed",brow->user_sid),-1);
		}
#endif
	} else {
		sprintf(desc,"PSU_ID[%lld],IP[%s],MAC[%s],DB_USER[%s],OS_USER[%s],PROGRAM[%s],PROTOCOL[%s]"
                             " => [%s.(%s).%s.%s.%s] Too Much Decrypt Request",
                             sess_user.psu_id, sess_user.client_ip, sess_user.client_mac, sess_user.db_sess_user,
                             sess_user.os_user, sess_user.client_program, protocol,
                             enc_col.db_name, enc_col.owner_name, enc_col.schema_name, enc_col.table_name, enc_col.column_name);
#if 0
                if (DgcAlertQueue::p()->sendAlert(DgcDbProcess::sess(), 0, DGC_ALT_EVNT_TMDR, 0,0,0,desc)) {
			e=EXCEPTnC;
			RTHROWnR(e,DgcError(SPOS,"send Alert[%lld] failed",brow->user_sid),-1);
		}
#endif
	}
#endif
	return 0;
}


dgt_uint8* PccKredStmtAlert::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&Result;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}

