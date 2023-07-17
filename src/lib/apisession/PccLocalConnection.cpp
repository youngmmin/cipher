/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccLocalConnection
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 11. 27
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccLocalConnection.h"
#include "DgcSohaConnection.h"


PccLocalConnection::PccLocalConnection(dgt_uint16 in_timeout, dgt_uint16 out_timeout, dgt_uint32 max_open_cursors)
	: DgcCliConnectionImpl(max_open_cursors), Connection(0)
{
	InTimeOut=in_timeout;
	OutTimeOut=out_timeout;
}


PccLocalConnection::~PccLocalConnection()
{
   try {
	DgcExcept*	e=EXCEPTnC;
	if (disconnect() != 0 && EXCEPT != 0) delete EXCEPTnC;
	if (e) DgcExcept::ethrow(e);
   } catch (...) {
   }
}


dgt_sint8 PccLocalConnection::connect(
	dgt_schar*		shome,
	const dgt_schar*	sid,
	const dgt_schar*	uid,
	const dgt_schar*	pswd,
	const dgt_schar*	pname
	) throw(DgcExcept)
{
	if (status() == DGC_CON_ST_OPEN) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
			new DgcError(SPOS,"invalid status[%d] for connect, disconnect first",status())),-1);
	} else {
		setStatus(DGC_CON_ST_ERROR);
	}
	dgt_schar	cstring[256];
	dg_sprintf(cstring,"(address=(protocol=beq)(soha_home=%s)(soha_svc=%s)(svr_name=pcp_kredsvr)(in_timeout=%d)(out_timeout=%d)(db_name=%s))",shome,sid,InTimeOut,OutTimeOut,sid);
	Connection = new DgcSohaConnection(MaxOpenCursors);
	if (Connection->connect(cstring,sid,uid,pswd,pname) < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete Connection;
		Connection = 0;
		RTHROWnR(e,DgcError(SPOS,"connect failed"),-1);
	}
	setStatus(DGC_CON_ST_OPEN);
	return 0;
}


DgcCliStmt* PccLocalConnection::getStmt(dgt_uint8 mode) throw(DgcExcept)
{
	if (status() != DGC_CON_ST_OPEN) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
			 new DgcError(SPOS,"not connected, connect first")),0);
        }
	DgcCliStmt*	stmt = Connection->getStmt();
	if (stmt == 0) {
		ATHROWnR(DgcError(SPOS,"getStmt failed"),0);
	}
	return stmt;
}


dgt_sint8 PccLocalConnection::disconnect() throw(DgcExcept)
{
	delete Connection;
	Connection = 0;
	setStatus(DGC_CON_ST_CLOSE);
	return 0;
}


dgt_void PccLocalConnection::dump(DgcBufferStream* bs)
{
}
