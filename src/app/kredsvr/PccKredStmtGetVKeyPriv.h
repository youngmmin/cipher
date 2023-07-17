/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetVKeyPriv
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 06. 21
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_VKEY_PRIV_H
#define DGC_KRED_STMT_GET_VKEY_PRIV_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"
#include "PccTableTypes.h"
#include "PvacTableType.h"
#include "PccDecPrivilege.h"

class PccKredStmtGetVKeyPriv : public PccKredStmt {
  private:
	inline dgt_sint32 atoif(dgt_schar* p_ascii, dgt_sint32 p_len) {
		int i, j, jj;
		j = jj = 0;
		for (i = 0; i < p_len; i++) {
			for (j = 0; j < 10; j++)
				if (*(p_ascii + i) == ('0' + j))
					break;
			if (j < 10)
				jj = jj * 10 + j;
		}

		return (jj);
	}

	dgt_schar*	NameStr;
  protected:
	pct_type_enc_column		EncColumn;
	pc_type_get_vkey_priv_out	PrivInfo;
	dgt_uint32	NumRtnRows;

	dgt_sint32 getEncColumn(dgt_sint64 virtual_key_id, dgt_uint64 user_sid, dgt_uint8 crypt_type) throw(DgcExcept);
	dgt_sint32 matchTargetName(dgt_schar* target_name, dgt_sint64 cmp_name_id, dgt_uint8 case_sensitive=0) throw(DgcExcept);
  public:
	PccKredStmtGetVKeyPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtGetVKeyPriv();

	virtual dgt_sint32 execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept) = 0;
	virtual dgt_uint8* fetch() throw(DgcLdbExcept,DgcPdbExcept);

};

#endif
