/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbOracleUpdateStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_ORACLE_UPDATE_STMT_H
#define PCB_ORACLE_UPDATE_STMT_H


#include "PcbOracleConnection.h"
#include "PcbUpdateStmt.h"


class PcbOracleUpdateStmt : public PcbUpdateStmt {
  private:
	PcbOracleConnection	Connection;
	DgcDbifCoreOciCursor*	UpdateStmt;
	dgt_sint8		IsDefined; 
  protected:
  public:
        PcbOracleUpdateStmt(PcbCipherTable* cipher_table,dgt_uint32 array_size=0);
	virtual ~PcbOracleUpdateStmt();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 update(PcbDataChunk* data_chunk) throw(DgcExcept);
	virtual dgt_sint32 verifUpdate(dgt_uint32 partition_number) throw(DgcExcept);
};


#endif
