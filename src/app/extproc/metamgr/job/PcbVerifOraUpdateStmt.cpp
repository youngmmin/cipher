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
#include "PcbVerifOraUpdateStmt.h"
#include "DgcDbProcess.h"
#include "PccOraScriptBuilder.h"

PcbVerifOraUpdateStmt::PcbVerifOraUpdateStmt(dgt_sint64 job_id, PcbCipherTable* cipher_table,dgt_uint32 array_size)
	:PcbUpdateStmt(cipher_table,array_size),
	 UpdateStmt(0),
	 IsDefined(0)
{
	JobID=job_id;
}


PcbVerifOraUpdateStmt::~PcbVerifOraUpdateStmt()
{
	delete UpdateStmt;
	Connection.disconnect();
}


dgt_sint32 PcbVerifOraUpdateStmt::initialize() throw(DgcExcept)
{
	//
	// connect to oracle and alter session attributes for converting date type to char
	//
	if (Connection.connect(CipherTable->linkInfo())) {
		ATHROWnR(DgcError(SPOS,"connet failed"),-1);
	}

	DgcSession* sess=DgcDbProcess::sess();
	DgcSqlHandle SqlHandle(sess);
	dgt_schar soha_str[256];
	dgt_void* rtn_row=0;
	dgt_sint32 ret=0;
	pct_verif_schema_info* schema_info=0;

	sprintf(soha_str,"select e.db_type, d.admin_link, e.db_version "
			" from pct_enc_table a, pct_enc_schema b, pct_db_agent c, pt_database d "
			" where a.enc_tab_id = %lld and a.schema_id = b.schema_id and b.db_id = c.db_id and c.db_id = d.db_id",CipherTable->encTabId());
	if (SqlHandle.execute(soha_str) < 0) {
		ATHROWnR(DgcError(SPOS,"SqlHandle execute failed."),-1);
	}

	if((ret=SqlHandle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"SqlHandle fetch failed."),-1);
	}
	if(!rtn_row)
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no data found [enc_tab_id:%lld]",CipherTable->encTabId())),0);
	schema_info=(pct_verif_schema_info*)rtn_row;

	PccOraScriptBuilder* script_builder=new PccOraScriptBuilder(
			DgcDbProcess::dbPtr(),
			DgcDbProcess::sess(),
			schema_info->schema_link);
	if(script_builder->readyGetFname(CipherTable->encTabId()) < 0){
		ATHROWnR(DgcError(SPOS,"readyGetFname fetch failed."),-1);
	}

	//
	// build update sql text
	//
	dgt_uint16 num_columns=CipherTable->numColumns();
	dgt_uint16 num_indexes=CipherTable->numIndexes();
	SqlText=new dgt_schar[128 + num_columns*94];
	*SqlText=0;
	sprintf(SqlText,"update ");
	dg_strcat(SqlText, CipherTable->schemaName());
	dg_strcat(SqlText, ".");
	dg_strcat(SqlText, CipherTable->encTabName());
	dg_strcat(SqlText," set ");
	PcbCipherColumn*	cipher_column;
	for(dgt_uint16 cno=0; cno<num_columns && (cipher_column=CipherTable->cipherColumn(cno)); cno++) {
		dgt_schar	tmp[128];
		dg_sprintf(tmp,"%s=%s",cipher_column->encColName(),
				script_builder->getFname((char*)cipher_column->columnName(),1));
		dg_strcat(SqlText, tmp);
		if (cno+1 < num_columns) dg_strcat(SqlText, ","); // not the last
//DgcWorker::PLOG.tprintf(0,"PcbVerifOraUpdateStmt::initialize enc_col_id[%lld]\n",cipher_column->encColumnID());

	}

	//index column update
	PcbCipherColumn*	cipher_idx_column;
	for(dgt_uint16 idx_cno=num_columns; idx_cno<(num_columns+num_indexes) && (cipher_idx_column=CipherTable->cipherColumn(idx_cno)); idx_cno++) {
		//dgt_schar	tmp[128];
		//dg_sprintf(tmp,", %s_IDX=hextoraw(:%d)",cipher_idx_column->encColName(),idx_cno+1);
		//dgt_schar* tmp=cipher_idx_column->indexColName();
		dgt_schar default_idx_name[40];
		dg_sprintf(default_idx_name,"%s_IDX",cipher_idx_column->encColName());
		dgt_schar	tmp[128];
		dg_sprintf(tmp,", %s=%s",
				cipher_idx_column->indexColName()?
						cipher_idx_column->indexColName():default_idx_name,
						script_builder->getFname((char*)cipher_column->columnName(),3));
		dg_strcat(SqlText, tmp);
	}

	dg_strcat(SqlText, " where ROWID = chartorowid(:a)");
	UpdateStmt=Connection.getStmt(SqlText, num_columns+num_indexes+1, num_columns+1);
	if (UpdateStmt->declare(SqlText, ArraySize)) ATHROWnR(DgcError(SPOS,"declare[%s] failed",SqlText),-1);
	if (UpdateStmt->open()) ATHROWnR(DgcError(SPOS,"open[%s] failed",SqlText),-1);

//DgcWorker::PLOG.tprintf(0,"PcbVerifOraUpdateStmt::initialize [%s]\n",SqlText);

	delete script_builder;
	return 0;
}

dgt_sint32 PcbVerifOraUpdateStmt::update(PcbDataChunk* data_chunk) throw(DgcExcept)
{
	return 0;
}

dgt_sint32 PcbVerifOraUpdateStmt::verifUpdate(dgt_uint32 partition_number) throw(DgcExcept)
{
	dgt_sint32	rtn=0;
	dgt_schar	empty_string[1]={0,};
	//
	//define binding row_id
	//
	if (!IsDefined) {
		rtn=UpdateStmt->defineBind(0,empty_string,SQLT_CHR,33);
		if (rtn) ATHROWnR(DgcError(SPOS,"defineBind failed"),-1);
		IsDefined=1;
	}

	//
	// bind row_id
	//
	DgcSession* sess=DgcDbProcess::sess();
	DgcSqlHandle SqlHandle(sess);
	dgt_schar soha_str[128];
	dgt_void* rtn_row=0;
	dgt_sint32 ret=0;
	dgt_schar* row_id=0;

	dg_sprintf(soha_str,"select row_id from pct_verif_invalid_%lld::partition(%d)",JobID,partition_number);
	if (SqlHandle.execute(soha_str) < 0) {
		ATHROWnR(DgcError(SPOS,"SqlHandle execute failed."),-1);
	}
	dgt_uint32 rno=0;
	while (!(ret=SqlHandle.fetch(rtn_row)) && rtn_row) {
		row_id=(dgt_schar*)rtn_row;

		if (rno && rno%1000 == 0) {
			//
			// the max number setBind to execute at once is a 1000
			// execute
			//
			if (UpdateStmt->execute(rno)) {
				DgcExcept* e = EXCEPTnC;
				Connection.rollback();
				RTHROWnR(e, DgcError(SPOS,"execute failed"), -1);
			}
			//
			// commit
			//
			if (Connection.commit()) {
				ATHROWnR(DgcError(SPOS,"commit failed"), -1);
			}
			rno=0;
		}
		if (UpdateStmt->setBind(0, rno,
					row_id,
					dg_strlen(row_id),0)) {
			ATHROWnR(DgcError(SPOS,"setBind failed rno[%d]",rno),-1);
		}

		rno++;
	}
	if(ret < 0){
		ATHROWnR(DgcError(SPOS,"SqlHandle fetch failed."),-1);
	}

	//
	// update remaind data.
	//
	if (rno > 0) {
		//
		// execute
		//
		if (UpdateStmt->execute(rno)) {
			DgcExcept* e = EXCEPTnC;
			Connection.rollback();
			RTHROWnR(e, DgcError(SPOS,"execute failed"), -1);
		}
		//
		// commit
		//
		if (Connection.commit()) {
			ATHROWnR(DgcError(SPOS,"commit failed"), -1);
		}
		rno=0;
	}

	return rno;
}

