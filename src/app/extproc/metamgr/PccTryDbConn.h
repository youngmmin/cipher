/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccTryDbConn
 *   Implementor        :       mwpark
 *   Create Date        :       2011. 11. 21
 *   Description        :       db connection test
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_TRY_DB_CONN_H
#define PCC_TRY_DB_CONN_H

#include "DgcOracleConnection.h"
#include "PccMetaProcedure.h"

class PccTryDbConn : public PccMetaProcedure {
   private:
   protected:
   public:
    PccTryDbConn(const dgt_schar* name);
    virtual ~PccTryDbConn();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
