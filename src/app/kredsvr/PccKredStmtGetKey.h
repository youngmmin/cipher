/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_KEY_H
#define DGC_KRED_STMT_GET_KEY_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtGetKey : public PccKredStmt {
  private:
	pc_type_get_key_out	KeyInfo;
	dgt_uint32		NumRtnRows;
	dgt_sint32 getKeyPriv(dgt_sint64 key_id, dgt_schar* ip);
  protected:
  public:
	PccKredStmtGetKey(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetKey();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
