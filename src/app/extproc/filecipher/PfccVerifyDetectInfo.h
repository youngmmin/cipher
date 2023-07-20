/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccVerifyDetectInfo
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 07. 12
 *   Description        :       verify detection file
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_VERIFY_DETECT_INFO_H
#define PFCC_VERIFY_DETECT_INFO_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 job_id;
    dgt_sint64 dir_id;
    dgt_sint64 file_id;
} pfcc_verify_detect_info_in;

class PfccVerifyDetectInfo : public PfccAgentProcedure {
   private:
   protected:
   public:
    PfccVerifyDetectInfo(const dgt_schar* name,
                         PfccAgentListener* agent_listener);
    virtual ~PfccVerifyDetectInfo();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
    //	virtual dgt_sint32 fetch() throw(DgcExpcet);
};

#endif
