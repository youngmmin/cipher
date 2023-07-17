/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbOracleSelectStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_ORACLE_SELECT_STMT_H
#define PCB_ORACLE_SELECT_STMT_H


#include "PcbSelectStmt.h"
#include "PcbOracleConnection.h"


class PcbOracleSelectStmt : public PcbSelectStmt {
  private:
	PcbOracleConnection	Connection;
	DgcDbifCoreOciCursor*	SelectStmt;
  protected:
  public:
        PcbOracleSelectStmt(PcbCipherTable* cipher_table,dgt_uint32 array_size=0);
        virtual ~PcbOracleSelectStmt();

	virtual dgt_sint32 initialize(dgt_schar* where_clause=0) throw(DgcExcept);
	virtual dgt_sint32 fetch() throw(DgcExcept);
	virtual dgt_sint32 fetch(PcbDataChunk* data_chunk) throw(DgcExcept);
        virtual dgt_sint32 getFetchData(dgt_uint32 col_order,dgt_void** buf,dgt_sint16** ind,dgt_uint16** len) throw(DgcExcept);
};


#endif
