/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetTrailer
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 03. 15
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetTrailer.h"
#include "PciKeyMgrIf.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"


PccKredStmtGetTrailer::PccKredStmtGetTrailer(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",2);
        SelectListDef->addAttr(DGC_UB1,0,"trailer_size");
        SelectListDef->addAttr(DGC_SCHR,7,"trailer_char");
}


PccKredStmtGetTrailer::~PccKredStmtGetTrailer()
{
}


dgt_sint32 PccKredStmtGetTrailer::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	//
	// get encrypt key info
	//
	pc_type_get_trailer_in* trailer_in = (pc_type_get_trailer_in*)mrows->data();
	dgt_schar sql_text[256];
	DgcMemRows      v_bind(1);
        v_bind.addAttr(DGC_SB8,0,"key_id");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1),&trailer_in->key_id,sizeof(dgt_sint64));
        v_bind.rewind();
	dg_sprintf(sql_text,"select trailer_size, trailer_char from PCT_ENCRYPT_KEY_TRAILER where key_id = :1");
	DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(Session, sql_text, strlen(sql_text));
	DgcExcept* e=0;
	if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%s] failed.",sql_text),-1);
	}
	typedef struct {
		dgt_uint8	trailer_size;
		dgt_schar	trailer_char[7];
	} trailer_type;
	trailer_type* trailer_tmp;
	if ((trailer_tmp=(trailer_type*)sql_stmt->fetch())) {
		TrailerInfo.trailer_size = trailer_tmp->trailer_size;
		memcpy(TrailerInfo.trailer_char,trailer_tmp->trailer_char,7);
	}
	e=EXCEPTnC;
	delete sql_stmt;
	if (e) {
		RTHROWnR(e,DgcError(SPOS,"fetch [%s] failed",sql_text),-1);
	}
	IsExecuted=1;
	NumRtnRows=0;
	return 0;
}


dgt_uint8* PccKredStmtGetTrailer::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&TrailerInfo;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
