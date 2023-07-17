/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetZoneId
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_ZONE_ID_H
#define DGC_KRED_STMT_GET_ZONE_ID_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtGetZoneId : public PccKredStmt {
  private:
	dgt_sint64		ZoneID;
	dgt_uint32		NumRtnRows;
  protected:
  public:
	PccKredStmtGetZoneId(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetZoneId();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
