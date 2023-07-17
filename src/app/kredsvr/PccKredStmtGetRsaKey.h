/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetRsaKey
 *   Implementor        :       mwpark
 *   Create Date        :       2019. 04. 30
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_RSA_KEY_H
#define DGC_KRED_STMT_GET_RSA_KEY_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"
#include "PccTableTypes.h"

class PccKredStmtGetRsaKey : public PccKredStmt {
  private:
	dgt_uint32		NumRtnRows;
	dgt_schar*		ResultParam;
	dgt_sint32 getKeyPriv(dgt_sint64 key_id, dgt_schar* ip);
  protected:
  public:
	PccKredStmtGetRsaKey(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetRsaKey();

	virtual dgt_sint32 execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8* fetch() throw(DgcLdbExcept,DgcPdbExcept);

};

#endif
