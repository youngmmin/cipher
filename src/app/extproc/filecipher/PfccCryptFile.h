/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccCryptFile
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_CRYPT_FILE_H
#define PFCC_CRYPT_FILE_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 ptu_id;
    dgt_sint64 enc_zone_id;
    dgt_uint8 crypt_flag;
    dgt_schar client_ip[128];
    dgt_schar src_file[2049];
    dgt_schar dst_file[2049];
} pfct_crypt_file_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar err_msg[1025];
} pfct_crypt_file_out;

class PfccCryptFile : public PfccAgentProcedure {
   private:
    static const dgt_schar CRYPTOR_PARAM_FORMAT[];

   protected:
   public:
    PfccCryptFile(const dgt_schar* name, PfccAgentListener* agent_listener);
    virtual ~PfccCryptFile();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
