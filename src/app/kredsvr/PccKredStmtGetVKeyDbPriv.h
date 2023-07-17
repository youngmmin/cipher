/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetVKeyDbPriv
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 06. 21
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_VKEY_DB_PRIV_H
#define DGC_KRED_STMT_GET_VKEY_DB_PRIV_H

#include "PccKredStmtGetVKeyPriv.h"

class PccKredStmtGetVKeyDbPriv : public PccKredStmtGetVKeyPriv {
  private:
  protected:
  public:
	PccKredStmtGetVKeyDbPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetVKeyDbPriv();

	virtual dgt_sint32 execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
