/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtDetectFileGetRequest
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 29
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_DETECT_FILE_GET_REQUEST_H
#define DGC_KRED_STMT_DETECT_FILE_GET_REQUEST_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtDetectFileGetRequest : public PccKredStmt {
   private:
    DgcMemRows* RqstList;

   protected:
   public:
    PccKredStmtDetectFileGetRequest(DgcPhyDatabase* pdb, DgcSession* session,
                                    DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtDetectFileGetRequest();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
