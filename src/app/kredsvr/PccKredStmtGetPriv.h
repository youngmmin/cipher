/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetPriv
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_PRIV_H
#define DGC_KRED_STMT_GET_PRIV_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtGetPriv : public PccKredStmt {
  private:
	pc_type_get_priv_out	PrivInfo;
	dgt_uint32		NumRtnRows;
  protected:
  public:
	PccKredStmtGetPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetPriv();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
