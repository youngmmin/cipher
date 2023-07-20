/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccDeleteCryptStat
 *   Implementor        :       mjkim
 *   Create Date        :       2018. 07. 19
 *   Description        :       delete pfct_crypt_stat_temp table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_DELETE_CRYPT_STAT_H
#define PFCC_DELETE_CRYPT_STAT_H

#include "DgcExtProcedure.h"

typedef struct {
    dgt_sint64 dir_id;
} pfcc_delete_crypt_stat_in;

class PfccDeleteCryptStat : public DgcExtProcedure {
   private:
   protected:
   public:
    PfccDeleteCryptStat(const dgt_schar* name);
    virtual ~PfccDeleteCryptStat();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
