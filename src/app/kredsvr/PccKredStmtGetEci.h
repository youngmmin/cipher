/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetEci
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_ECI_H
#define DGC_KRED_STMT_GET_ECI_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtGetEci : public PccKredStmt {
  private:
	dgt_sint64		EncColID;
	dgt_uint32		NumRtnRows;
  protected:
  public:
	PccKredStmtGetEci(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetEci();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
