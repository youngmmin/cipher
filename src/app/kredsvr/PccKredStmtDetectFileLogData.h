/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtDetectFileLogData
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 29 
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_DETECT_FILE_LOG_DATA_H
#define DGC_KRED_STMT_DETECT_FILE_LOG_DATA_H


#include "PccKredStmt.h"
#include "PciMsgTypes.h"

typedef struct {
	dgt_sint64 job_id;
	dgt_sint64 dir_id;
	dgt_sint64 file_id;
	dgt_schar* file_name[2048];
	dgt_sint64 start_offset;
	dgt_sint64 end_offset;
	dgt_schar  expr[1024];
	dgt_schar  data[1024];
} pct_type_detect_data;

class PccKredStmtDetectFileLogData : public PccKredStmt {
  private:
	dgt_uint32		NumRtnRows;
	dgt_sint32		Result;
  protected:
  public:
	PccKredStmtDetectFileLogData(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtDetectFileLogData();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);
};


#endif
