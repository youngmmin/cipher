/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetDetectInfo
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_DETECT_INFO_H
#define PFCC_GET_DETECT_INFO_H

#include "DgcSqlHandle.h"
#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_schar file_name[2048];
    dgt_schar parameter[1024];
} pfcc_get_detect_info_in;

class PfccGetDetectInfo : public PfccAgentProcedure {
   private:
   protected:
   public:
    PfccGetDetectInfo(const dgt_schar* name, PfccAgentListener* agent_listener);
    virtual ~PfccGetDetectInfo();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
    //	virtual dgt_sint32 fetch() throw(DgcExpcet);
};

#endif
