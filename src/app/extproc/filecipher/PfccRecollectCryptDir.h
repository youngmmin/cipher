/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccRecollectCryptDir
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_RECOLLECT_CRYPT_DIR_H
#define PFCC_RECOLLECT_CRYPT_DIR_H

#include "PfccAgentProcedure.h"

class PfccRecollectCryptDir : public PfccAgentProcedure {
   private:
   protected:
   public:
    PfccRecollectCryptDir(const dgt_schar* name,
                          PfccAgentListener* agent_listener);
    virtual ~PfccRecollectCryptDir();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
