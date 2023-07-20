/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccDecrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       decrypt
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_DECRYPT_H
#define PCC_DECRYPT_H

#include "DgcExtProcedure.h"

class PccDecrypt : public DgcExtProcedure {
   private:
   protected:
   public:
    PccDecrypt(const dgt_schar* name);
    virtual ~PccDecrypt();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
