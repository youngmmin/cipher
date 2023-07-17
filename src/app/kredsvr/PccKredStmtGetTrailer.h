/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetTrailer
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 03. 15
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_TRAILER_H
#define DGC_KRED_STMT_GET_TRaiLER_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtGetTrailer : public PccKredStmt {
  private:
	dgt_uint32		NumRtnRows;
	pc_type_get_trailer_out	TrailerInfo;
  protected:
  public:
	PccKredStmtGetTrailer(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetTrailer();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
