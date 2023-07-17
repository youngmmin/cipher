/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbStmtFactory
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbStmtFactory.h"


PcbStmtFactory*	PcbStmtFactory::StmtFactory=0;


PcbStmtFactory::PcbStmtFactory()
{
}


PcbStmtFactory::~PcbStmtFactory()
{
	delete StmtFactory;
}



#include "PcbOracleSelectStmt.h"

PcbSelectStmt* PcbStmtFactory::selectStmt(PcbCipherTable* cipher_table,dgt_uint32 array_size) throw(DgcExcept)
{
	PcbSelectStmt*	select_stmt=0;
	if (cipher_table->dbmsType() == 11) select_stmt=new PcbOracleSelectStmt(cipher_table,array_size);
	else THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"unsupport dbms type[%d]",cipher_table->dbmsType())),0);
	return select_stmt;
}


#include "PcbOracleUpdateStmt.h"

PcbUpdateStmt* PcbStmtFactory::updateStmt(PcbCipherTable* cipher_table,dgt_uint32 array_size) throw(DgcExcept)
{
	PcbUpdateStmt*	update_stmt=0;
	if (cipher_table->dbmsType() == 11) update_stmt=new PcbOracleUpdateStmt(cipher_table,array_size);
	else THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"unsupport dbms type[%d]",cipher_table->dbmsType())),0);
	return update_stmt;
}

#include "PcbVerifOraUpdateStmt.h"

PcbUpdateStmt* PcbStmtFactory::verifUpdateStmt(dgt_sint64 job_id, PcbCipherTable* cipher_table,dgt_uint32 array_size) throw(DgcExcept)
{
	PcbUpdateStmt*	update_stmt=0;
	if (cipher_table->dbmsType() == 11) update_stmt=new PcbVerifOraUpdateStmt(job_id,cipher_table,array_size);
	else THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"unsupport dbms type[%d]",cipher_table->dbmsType())),0);
	return update_stmt;
}
