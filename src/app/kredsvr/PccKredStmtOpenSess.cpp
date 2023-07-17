/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtOpenSess
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtOpenSess.h"
#include "PccKredSessionPool.h"
#include "PccAuthPrivilege.h"


#include "PtCharConv.h"


PccKredStmtOpenSess::PccKredStmtOpenSess(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",2);
	SelectListDef->addAttr(DGC_SB8,0,"user_sid");
	SelectListDef->addAttr(DGC_SB4,0,"auth_fail_code");
}


PccKredStmtOpenSess::~PccKredStmtOpenSess()
{
}


dgt_sint32 PccKredStmtOpenSess::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),0);
	}
	defineUserVars(mrows);
	pc_type_open_sess_in*	uinfo=(pc_type_open_sess_in*)mrows->data();


	if (uinfo->os_user && *uinfo->os_user) {
		PtCharConv         ConvCharset("UTF-8","EUC-KR");
		dgt_schar	outbuffer[33];
		memset(outbuffer,0,33);
		if (ConvCharset.convCharSet(uinfo->os_user, 33, outbuffer, 33) < 0) {
			delete EXCEPTnC;
			ConvCharset.reset("UTF-8","CP949");
			memset(outbuffer,0,33);
			if (ConvCharset.convCharSet(uinfo->os_user, 33, outbuffer, 33) < 0) {
                		delete EXCEPTnC;
	        	}
		}
		memset(uinfo->os_user,0,33);
		memcpy(uinfo->os_user,outbuffer,33);
	}
	if (uinfo->client_program && *uinfo->client_program) {
                PtCharConv         ConvCharset("UTF-8","EUC-KR");
                dgt_schar       outbuffer[128];
                memset(outbuffer,0,128);
                if (ConvCharset.convCharSet(uinfo->client_program, 128, outbuffer, 128) < 0) {
                        delete EXCEPTnC;
                        ConvCharset.reset("UTF-8","CP949");
                        memset(outbuffer,0,128);
                        if (ConvCharset.convCharSet(uinfo->client_program, 128, outbuffer, 128) < 0) {
                                delete EXCEPTnC;
                        }
                }
                memset(uinfo->client_program,0,128);
                memcpy(uinfo->client_program,outbuffer,128);
        }
 

	//
	// added by chchung 2012.11.1 for resolving local ip
	//
	if (strcasecmp(uinfo->client_ip,"local") == 0) strncpy(uinfo->client_ip,Session->clientCommIP(),64);

	dgt_sint64 user_sid=0;
	dgt_sint32 auth_fail_code=0;
	memset(&SessOut,0,sizeof(pc_type_open_sess_out));
	SessOut.user_sid=0;
	SessOut.auth_fail_code=0;
	if (!(user_sid=PccKredSessionPool::getUserSID(uinfo,&auth_fail_code))) {
		ATHROWnR(DgcError(SPOS,"getUserSID failed"),-1);
	}
	SessOut.user_sid=user_sid;
//	if (auth_fail_code == PAUC_AUTH_ERRCODE_CANCEL || auth_fail_code == PAUC_AUTH_ERRCODE_AUTH_FAIL) {
	if (auth_fail_code < 0) {
		SessOut.auth_fail_code=auth_fail_code;
	}
	IsExecuted=1;
	NumRtnRows=0;
	return 0;
}


dgt_uint8* PccKredStmtOpenSess::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&SessOut;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
}
