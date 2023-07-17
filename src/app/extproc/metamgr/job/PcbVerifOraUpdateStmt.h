/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbVerifOraUpdateStmt
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 4. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_VERIF_ORA_UPDATE_STMT
#define PCB_VERIF_ORA_UPDATE_STMT


#include "PcbOracleConnection.h"
#include "PcbUpdateStmt.h"
#include "DgcSqlHandle.h"

typedef struct {
	dgt_uint8	dbms_type;
	dgt_schar	schema_link[33];
	dgt_schar	db_version[33];
} pct_verif_schema_info;

class PcbVerifOraUpdateStmt : public PcbUpdateStmt {
  private:
	PcbOracleConnection	Connection;
	DgcDbifCoreOciCursor*	UpdateStmt;
	dgt_sint64 		JobID;
	dgt_sint8		IsDefined;
  protected:
  public:
        PcbVerifOraUpdateStmt(dgt_sint64 job_id, PcbCipherTable* cipher_table,dgt_uint32 array_size=0);
        virtual ~PcbVerifOraUpdateStmt();

    	virtual dgt_sint32 initialize() throw(DgcExcept);
    	virtual dgt_sint32 update(PcbDataChunk* data_chunk) throw(DgcExcept);
    	virtual dgt_sint32 verifUpdate(dgt_uint32 partition_number) throw(DgcExcept);
};

#endif /* PCB_VERIF_ORA_UPDATE_STMT */
