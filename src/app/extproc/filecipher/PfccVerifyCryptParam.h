/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccVerifyCryptParam
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 01. 09
 *   Description        :       verify crypt paramter
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_VERIFY_CRYPT_PARAM_H
#define PFCC_VERIFY_CRYPT_PARAM_H

#include "DgcExtProcedure.h"

typedef struct {
	dgt_schar crypt_param[513];
} pfcc_verify_crypt_param_in;

typedef struct {
	dgt_sint32 rtn_code;
	dgt_schar err_msg[1025];
} pfcc_verify_crypt_param_out;

class PfccVerifyCryptParam : public DgcExtProcedure {
  private:
  protected:
	static const dgt_sint32 PFC_VRFY_ERR_INVALID_PARAM_FORMAT	= -1;
	static const dgt_sint32 PFC_VRFY_ERR_KEY_NAME_NOT_DEFINED	= -2;
	static const dgt_sint32 PFC_VRFY_ERR_KEY_COL_NOT_DEFINED	= -3;
	static const dgt_sint32 PFC_VRFY_ERR_KEY_COL_NOT_FOUND		= -4;
	static const dgt_sint32 PFC_VRFY_ERR_MODE_CRYPT_NOT_SUPPORTED	= -5;
	static const dgt_sint32 PFC_VRFY_ERR_REGULAR_NOT_DEFINED	= -6;
	static const dgt_sint32 PFC_VRFY_ERR_REGUALR_REGEX_ERROR	= -7;
  public:
	PfccVerifyCryptParam(const dgt_schar* name);
	virtual ~PfccVerifyCryptParam();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);

	dgt_sint32	checkKeyExists(const dgt_schar* key_name) throw(DgcExcept);
};


#endif
