/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetZoneId
 *   Implementor        :       shson
 *   Create Date        :       2018. 6. 1
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetZoneId.h"
#include "DgcDbProcess.h"


PccKredStmtGetZoneId::PccKredStmtGetZoneId(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",1);
        SelectListDef->addAttr(DGC_SB8,0,"zone_id");
}


PccKredStmtGetZoneId::~PccKredStmtGetZoneId()
{
}


dgt_sint32 PccKredStmtGetZoneId::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);
	//
	// parsing name
	//
	dgt_schar	zone_name[132];
	memset(zone_name, 0, 132);
	strncpy(zone_name, (dgt_schar*)mrows->data(), 131);
	dgt_schar	sql_text[1024];
		sprintf(sql_text,
			"select enc_zone_id from pfct_enc_zone "
			" where name = '%s' "
			"   and delete_flag = 0 ", zone_name);
		DgcSqlStmt*     sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	        DgcExcept*      e=0;
        	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
	                e=EXCEPTnC;
        	        delete sql_stmt;
	                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        	}
	        dgt_sint64*     tmp_id;
        	if ((tmp_id=(dgt_sint64*)sql_stmt->fetch()) == 0) {
	                //
        	        // name not found
                	//
	                ZoneID = -40201;
        	} else {
	                ZoneID = *tmp_id;
        	}
	        if ((tmp_id=(dgt_sint64*)sql_stmt->fetch())) {
        	        //
                	// ambiguous name
	                //
        	        ZoneID = -40202;
	        }
		delete EXCEPTnC;
		delete sql_stmt;
	IsExecuted = 1;
	NumRtnRows = 0;
	return 0;
}


dgt_uint8* PccKredStmtGetZoneId::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&ZoneID;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
