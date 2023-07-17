/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetPriv
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetPriv.h"
#include "PciCryptoIf.h"
#include "PciMsgTypes.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"

PccKredStmtGetPriv::PccKredStmtGetPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
        SelectListDef=new DgcClass("select_list",16);
        SelectListDef->addAttr(DGC_SB8,0,"key_id");
        SelectListDef->addAttr(DGC_UB4,0,"max_col_len");
        SelectListDef->addAttr(DGC_UB4,0,"dec_alt_threshold");
        SelectListDef->addAttr(DGC_UB4,0,"dec_masking_threshold");
        SelectListDef->addAttr(DGC_UB1,0,"enc_priv");
        SelectListDef->addAttr(DGC_UB1,0,"dec_priv");
        SelectListDef->addAttr(DGC_UB1,0,"enc_no_priv_alert");
        SelectListDef->addAttr(DGC_UB1,0,"dec_no_priv_alert");
        SelectListDef->addAttr(DGC_UB1,0,"auth_fail_enc_priv");
        SelectListDef->addAttr(DGC_UB1,0,"auth_fail_dec_priv");
        SelectListDef->addAttr(DGC_UB1,0,"enc_audit_flag");
        SelectListDef->addAttr(DGC_UB1,0,"dec_audit_flag");
        SelectListDef->addAttr(DGC_UB1,0,"col_type");
        SelectListDef->addAttr(DGC_UB1,0,"ophuek_flag");
        SelectListDef->addAttr(DGC_UB1,0,"multibyte_flag");
        SelectListDef->addAttr(DGC_ACHR,12,"week_map");
}


PccKredStmtGetPriv::~PccKredStmtGetPriv()
{
}


dgt_sint32 PccKredStmtGetPriv::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	pc_type_get_priv_in*	brow = (pc_type_get_priv_in*)mrows->data();
	memset(&PrivInfo, 0, sizeof(PrivInfo));

	//
        // get encrypt column info
        //
	DgcMemRows      v_bind(1);
        v_bind.addAttr(DGC_SB8,0,"enc_col_id");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1),&brow->enc_col_id, sizeof(dgt_sint64));
        v_bind.rewind();

	dgt_schar	sql_text[256];
        dg_sprintf(sql_text,"select * from pct_enc_column where enc_col_id=:1");
        DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        DgcExcept*	e=0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
                e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->enc_col_id),-1);
        }
	dgt_uint8*	enc_col_ptr;
        if ((enc_col_ptr=sql_stmt->fetch()) == 0) {
                e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",brow->enc_col_id),-1);
        }
        pct_type_enc_column	enc_col;
	memcpy(&enc_col, enc_col_ptr, sizeof(enc_col));
	PrivInfo.key_id = enc_col.key_id;
	if (enc_col.multi_byte_flag) PrivInfo.max_col_len = enc_col.data_length * 3;
        else PrivInfo.max_col_len = enc_col.data_length;
        if (strcasecmp(enc_col.data_type,"NUMBER") == 0) PrivInfo.col_type = PCI_SRC_TYPE_NUM;
        else if (strcasecmp(enc_col.data_type,"DATE") == 0) PrivInfo.col_type = PCI_SRC_TYPE_DATE;
        else if (strcasecmp(enc_col.data_type,"TIMESTAMP") == 0) PrivInfo.col_type = PCI_SRC_TYPE_DATE;
        else if (strcasecmp(enc_col.data_type,"RAW") == 0) PrivInfo.col_type = PCI_SRC_TYPE_RAW;
        else if (strcasecmp(enc_col.data_type,"CHAR") == 0) PrivInfo.col_type = PCI_SRC_TYPE_CHAR;
        else if (strcasecmp(enc_col.data_type,"NCHAR") == 0) PrivInfo.col_type = PCI_SRC_TYPE_CHAR;
        else PrivInfo.col_type = PCI_SRC_TYPE_VARCHAR;
        delete sql_stmt;
	PrivInfo.multibyte_flag = enc_col.multi_byte_flag;
#if 1 // added by chchung 2013.9.22 for adding test mode
	if (enc_col.curr_enc_step == 1) PrivInfo.ophuek_flag = 2;
#endif

        v_bind.rewind();
        memset(sql_text,0,256);
        dg_sprintf(sql_text,"select enc_col_id from pct_enc_index where enc_col_id=:1 and index_type =1");
        sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        e=0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
                e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",brow->enc_col_id),-1);
        }
        dgt_uint8*      idx_ptr;
        dgt_sint64      idx_count=0;
        if ((idx_ptr=sql_stmt->fetch()) == 0) {
                e=EXCEPTnC;
		delete e;
        } else {
	        memcpy(&idx_count,idx_ptr,sizeof(dgt_sint64));
	}

#if 1 // modified by chchung 2013.9.22 for adding test mode
        if (idx_count > 0) PrivInfo.ophuek_flag += 1;
#else
        if (idx_count > 0) PrivInfo.ophuek_flag = 1;
#endif
        delete sql_stmt;

	//
	// get privilege
	//
	pct_type_priv_request_hist	rqst_hist;
	memset(&rqst_hist, 0, sizeof(rqst_hist));
	if ((getPrivilege((pc_type_get_priv_in*)mrows->data(), &PrivInfo, &rqst_hist)) < 0) {
                ATHROWnR(DgcError(SPOS,"getPrivilege[%lld] failed.",brow->enc_col_id),-1);
	}
	IsExecuted=1;
	NumRtnRows=0;

	//
        // log privilege request history
        //
#if 0
        rqst_hist.user_sid = brow->user_sid;
        rqst_hist.enc_col_id = brow->enc_col_id;
        rqst_hist.request_date=dgtime(&rqst_hist.request_date);
        DgcTableSegment*        tab=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_PRIV_REQUEST_HIST_TEMP");
        if (tab == 0) {
                DgcExcept*      e=EXCEPTnC;
                if (e) {
                        DgcWorker::PLOG.tprintf(0,*e,"getTable[PCT_PRIV_REQUEST_HIST_TEMP] failed:\n");
                        delete e;
                } else {
                        DgcWorker::PLOG.tprintf(0,"Table[PCT_PRIV_REQUEST_HIST_TEMP] not found.\n");
                }
        } else {
                tab->unlockShare();
                DgcRowList      rows(tab);
                rows.reset();
                if (tab->pinInsert(DgcDbProcess::sess(),rows,1) != 0) {
                        DgcExcept*      e=EXCEPTnC;
                        DgcWorker::PLOG.tprintf(0,*e,"pinInsert[PCT_PRIV_REQUEST_HIST_TEMP] failed:\n");
                        delete e;
                } else {
                        rows.rewind();
                        rows.next();
                        memcpy(rows.data(), &rqst_hist, rows.rowSize());
                        rows.rewind();
                        if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
                                DgcExcept*      e=EXCEPTnC;
                                rows.rewind();
                                if (tab->pinRollback(rows)) delete EXCEPTnC;
                                DgcWorker::PLOG.tprintf(0,*e,"insertCommit[PCT_PRIV_REQUEST_HIST_TEMP] failed:\n");
                                delete e;
                        }
                }
        }
#endif
	return 0;
}


dgt_uint8* PccKredStmtGetPriv::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&PrivInfo;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
