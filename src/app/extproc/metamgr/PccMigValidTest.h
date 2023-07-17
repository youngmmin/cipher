/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccMigValidTest
 *   Implementor        :       Mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_MIG_VALID_TEST_H
#define PCC_MIG_VALID_TEST_H

#include "PccMetaProcedure.h"
#include "DgcDatabaseLink.h"

class PccMigValidTest : public PccMetaProcedure {
  private:
	DgcMemRows	ItTabRows; // target it tab rows
	DgcMemRows	DictItTabRows; // dictionary check success it tab rows
	DgcMemRows	ExpItTabRows; // expression check success it tab rows
	dgt_sint64	TargetTabID; // 0: all tables

	dgt_sint32	setItTabRows() throw(DgcExcept);
	dgt_sint32	validDicExist() throw(DgcExcept);
	dgt_sint32	validExpression() throw(DgcExcept);
	dgt_sint32	registMtTabInfo() throw(DgcExcept);
	dgt_sint32	registEncTabInfo() throw(DgcExcept);
	dgt_sint32	buildScript() throw(DgcExcept);
	dgt_sint32	updateStatus() throw(DgcExcept);
	dgt_sint32	clearLogTables() throw(DgcExcept);
	dgt_sint32	logging(dgt_sint64 it_tab_id, dgt_schar* err_msg) throw(DgcExcept);

  public:
	PccMigValidTest(const dgt_schar* name);
	virtual ~PccMigValidTest();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
