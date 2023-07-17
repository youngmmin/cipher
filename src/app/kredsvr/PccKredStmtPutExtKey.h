/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtPutExtKey
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 03. 04
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_PUT_EXT_KEY_H
#define DGC_KRED_STMT_PUT_EXT_KEY_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtPutExtKey : public PccKredStmt {
  private:
        pc_type_put_ext_key_in  key_in;
        dgt_uint32              NumRtnRows;
        dgt_sint32              Result;

  protected:
  public:
	PccKredStmtPutExtKey(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtPutExtKey();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
