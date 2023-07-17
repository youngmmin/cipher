/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredFileStmtLogRequest
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 02. 07
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_FILE_LOG_REQUEST_H
#define DGC_KRED_STMT_FILE_LOG_REQUEST_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"


class PccKredStmtFileLogRequest : public PccKredStmt {
  private:
	pc_type_file_request_in	RqstInfo;
	dgt_uint32		NumRtnRows;
	dgt_sint32		Result;
  protected:
  public:
	PccKredStmtFileLogRequest(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtFileLogRequest();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
