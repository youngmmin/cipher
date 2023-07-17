/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmt.h"
#include "PccKredSessionPool.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "PccUserGroup.h"
#include "PccEncPrivilege.h"
#include "PccDecPrivilege.h"
#include "PccDecCountPrivilege.h"


dgt_sint32 PccKredStmt::getPrivilege(pc_type_get_priv_in* priv_in,pc_type_get_priv_out* priv_out,pct_type_priv_request_hist* rqst_hist)
{
	pt_type_sess_user*	sess_user = PccKredSessionPool::getSessUser(priv_in->user_sid);
	if (sess_user == 0) {
		ATHROWnR(DgcError(SPOS,"getSessUser[%lld] failed.",priv_in->user_sid),-1);
	}

	dgt_session	sess_info;
	memset(&sess_info,0,sizeof(dgt_session));
	sess_info.user=sess_user;
	DgcSession	cipher_session(&sess_info);
	PccUserGroup	user_grp(cipher_session);
	if (user_grp.initialize() < 0) {
		ATHROWnR(DgcError(SPOS,"getPrivilege[PccUserGroup] initialize failed"),-1);
	}
	user_grp.resetUserGroup();
	user_grp.resetRole();
	PccEncPrivilege enc_priv(user_grp,priv_in->enc_col_id);
	PccDecPrivilege dec_priv(user_grp,priv_in->enc_col_id);
	PccDecCountPrivilege dec_count_priv(user_grp,priv_in->enc_col_id);
	if (enc_priv.initialize() < 0) {
		ATHROWnR(DgcError(SPOS,"getPrivilege[PccEncPrivilege] initialize failed"),-1);
	}
	if (dec_priv.initialize() < 0) {
		ATHROWnR(DgcError(SPOS,"getPrivilege[PccDecPrivilege] initialize failed"),-1);
	}
	if (dec_count_priv.initialize() < 0) {
		ATHROWnR(DgcError(SPOS,"getPrivilege[PccDecCountPrivilege] initialize failed"),-1);
	}
	enc_priv.reset();
	dec_priv.reset();
	dec_count_priv.reset();

	enc_priv.getEncControl(priv_out,rqst_hist);

	dec_priv.getDecControl(priv_out,rqst_hist);

	dec_count_priv.getDecCountControl(priv_out,rqst_hist);

	DgcExcept*	e=EXCEPTnC;
	if (e) {
		DgcWorker::PLOG.tprintf(0,*e,"privilege search for sid[%lld]-enc_col_id[%lld] failed:",priv_in->user_sid, priv_in->enc_col_id);
		RTHROWnR(e, DgcError(SPOS,"getPrivilege[%lld:%lld] failed.",priv_in->user_sid, priv_in->enc_col_id),-1);
	}

//DgcWorker::PLOG.tprintf(0,"-------------------- priv bmap => \n");
//for(dgt_sint32 i=0; i<50; i++){
//DgcWorker::PLOG.tprintf(0,"  [%02x]\n", priv_out->priv[i]);
//}

	return 0;
}


PccKredStmt::PccKredStmt(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: DgcSqlStmt(pdb, stmt_term, session), UserVarRows(0), SelectListDef(0), PrivStmt(0), TLOG(0)
{
}


PccKredStmt::~PccKredStmt()
{
	delete SelectListDef;
	delete UserVarRows;
	delete PrivStmt;
}


dgt_sint8 PccKredStmt::defineUserVars(DgcMemRows* mrows) throw(DgcLdbExcept)
{
	if (UserVarRows) delete UserVarRows;
	UserVarRows=mrows;
	return 0;
}


dgt_sint8 PccKredStmt::describe(DgcClass* def) throw(DgcLdbExcept)
{
	return 0;
}


DgcClass* PccKredStmt::fetchListDef() throw(DgcLdbExcept)
{
	if (SelectListDef == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"fetch row format not defined yet")),0);
	}
	return SelectListDef;
}

dgt_void PccKredStmt::dump(DgcBufferStream* bs)
{
}
