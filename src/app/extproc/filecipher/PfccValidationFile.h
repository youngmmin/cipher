/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccValidationFile
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_VALIDATION_FILE_H
#define PFCC_VALIDATION_FILE_H

#include "PfccAgentProcedure.h"

typedef struct {
	dgt_sint64 agent_id;
	dgt_sint64 ptu_id;
	dgt_schar client_ip[128];
	dgt_schar file_path[2049];
} pfct_validation_file_in;

typedef struct {
	dgt_sint32	rtn_code;
	dgt_schar	err_msg[1025];
} pfct_validation_file_out;

class PfccValidationFile : public PfccAgentProcedure {
  private:
	static const dgt_schar CRYPTOR_PARAM_FORMAT[];
  protected:
  public:
	PfccValidationFile(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccValidationFile();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
