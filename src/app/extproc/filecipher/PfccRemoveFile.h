/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccRemoveFile
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_REMOVE_FILE_H
#define PFCC_REMOVE_FILE_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_schar file_path[2049];
} pfct_remove_file_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar err_msg[1025];
} pfct_remove_file_out;

class PfccRemoveFile : public PfccAgentProcedure {
   private:
    static const dgt_schar CRYPTOR_PARAM_FORMAT[];

   protected:
   public:
    PfccRemoveFile(const dgt_schar* name, PfccAgentListener* agent_listener);
    virtual ~PfccRemoveFile();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
