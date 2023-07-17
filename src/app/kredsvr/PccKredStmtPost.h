/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtPosting
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 12. 15
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_POST_H
#define DGC_KRED_STMT_POST_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtPost : public PccKredStmt {
  private:
	dgt_uint32	NumRtnRows;
	dgt_sint32	Result;
  protected:
  public:
	PccKredStmtPost(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtPost();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
