/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGetCredentials
 *   Implementor        :       jhpark
 *   Create Date        :       2012. 4. 1
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccGetCredentials.h"
#include "PcaCredentials.h"
#include "DgcBgmrList.h"

PccGetCredentials::PccGetCredentials(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccGetCredentials::~PccGetCredentials()
{
}


DgcExtProcedure* PccGetCredentials::clone()
{
	return new PccGetCredentials(procName());
}


dgt_sint32 PccGetCredentials::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	/*
	 * (credentials =
	 *		(svc = soha)
	 *		(user =	dgsysadmin)
	 *		(password = petra@one1)
	 *		(key = this_is_key)
	 *		(svc_home = /home/petra/soha)
	 *		(ip = 192.168.10.230)
	 *		(mac = DD-IF-AA-CF-06)
	 *		(instance = ORA10R2)
	 *		(db_name = ORA10R2)
	 *		(db_user = SCOTT)
	 *		(os_user = petra)
	 *		(program = jeus_v3.0)
	 *		(org_user = org_user)
	 * )
	 */
	dgt_schar*	param=(dgt_schar*)BindRows->data();
	if (*param == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"null input param.")),-1);
	}
	dgt_schar *svc,*user,*password,*key;
	svc=user=password=key=0;

	//	ATHROWnR(DgcError(SPOS,"getTable[PCT_KEY] failed"),-1);
	DgcBgmrList credentials_list(param,1);
	DgcBgrammer* credentials_info;

	PcaCredentials	pc;

	while((credentials_info=credentials_list.getNext()) != 0){
		dgt_schar* val=0;
		if ((val=credentials_info->getValue("credentials.svc")) != 0) svc=val;
		if ((val=credentials_info->getValue("credentials.user")) != 0) user=val;
		if ((val=credentials_info->getValue("credentials.password")) != 0) password=val;
		if ((val=credentials_info->getValue("credentials.key")) != 0) key=val;
		if ((val=credentials_info->getValue("credentials.svc_home")) != 0) pc.setSvcHome(val);
		if ((val=credentials_info->getValue("credentials.ip")) != 0) pc.setIP(val);
		if ((val=credentials_info->getValue("credentials.mac")) != 0) pc.setMAC(val);
		if ((val=credentials_info->getValue("credentials.instance")) != 0) pc.setInstanceName(val);
		if ((val=credentials_info->getValue("credentials.db_name")) != 0) pc.setDbName(val);
		if ((val=credentials_info->getValue("credentials.db_user")) != 0) pc.setDbUser(val);
		if ((val=credentials_info->getValue("credentials.os_user")) != 0) pc.setOsUser(val);
		if ((val=credentials_info->getValue("credentials.program")) != 0) pc.setProgram(val);
		if ((val=credentials_info->getValue("credentials.org_user")) != 0) pc.setOrgUserID(val);
	}

	dgt_sint32	rtn;
	rtn=pc.generate(svc,user,password,key);

	pc_get_credentials_ret ret;
	ret.errcode=rtn;
	if(rtn)	dg_sprintf((dgt_schar*)ret.result,pc.errMsg());
	else dg_sprintf((dgt_schar*)ret.result,pc.credentials());

	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;
	dg_memcpy(ReturnRows->data(), &ret, sizeof(pc_get_credentials_ret));
	ReturnRows->rewind();
	return 0;
}
