/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetZoneParam
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 08. 08
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_ZONE_PARAM_H
#define DGC_KRED_STMT_GET_ZONE_PARAM_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"
#include "PccTableTypes.h"
#include "PvacTableType.h"
#include "PccDecPrivilege.h"

typedef struct {
	dgt_sint64 enc_zone_id;
	dgt_sint64 enc_col_id;
	dgt_sint64 pattern_id;
	dgt_uint16 column_no;
	dgt_schar enc_col_name[130];
} pct_kred_apb_get_col_key_out;

class PccKredStmtGetZoneParam : public PccKredStmt {
  private:
	static const dgt_uint32 PARAM_MIN_LEN						= 512;
	static const dgt_uint32 REGULAR_PARAM_MAX_LEN_PER_ROW		= 512;
	static const dgt_uint32 DELIMITER_PARAM_MAX_LEN_PER_ROW		= 256;
	static const dgt_uint32 FIXED_PARAM_MAX_LEN_PER_ROW			= 1024;

	static const dgt_schar DELIMITER_PARAM_FORMAT[];
	static const dgt_schar FIXED_PARAM_FORMAT[];

	dgt_uint32	NumRtnRows;
	dgt_schar*	ResultParam;

	dgt_uint32	KeyParamLen;
	dgt_uint32	RegularParamLen;
	dgt_uint32	DelimiterParamLen;
	dgt_uint32	FixedParamLen;

	dgt_schar*	KeyParam;
	dgt_schar*	RegularParam;
	dgt_schar*	DelimiterParam;
	dgt_schar*	FixedParam;

  protected:
  public:
	PccKredStmtGetZoneParam(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetZoneParam();

	virtual dgt_sint32 execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8* fetch() throw(DgcLdbExcept,DgcPdbExcept);

};

#endif
