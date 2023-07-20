/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredUserFileStmtLogRequest
 *   Implementor        :       shson
 *   Create Date        :       2018. 06. 19
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_USER_FILE_LOG_REQUEST_H
#define DGC_KRED_STMT_USER_FILE_LOG_REQUEST_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtUserFileLogRequest : public PccKredStmt {
   private:
    pc_type_user_file_request_in RqstInfo;
    dgt_uint32 NumRtnRows;
    dgt_sint32 Result;

   protected:
   public:
    PccKredStmtUserFileLogRequest(DgcPhyDatabase* pdb, DgcSession* session,
                                  DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtUserFileLogRequest();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
