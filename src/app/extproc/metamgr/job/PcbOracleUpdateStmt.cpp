/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbOracleUpdateStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbOracleUpdateStmt.h"

PcbOracleUpdateStmt::PcbOracleUpdateStmt(PcbCipherTable* ciphet_table,
                                         dgt_uint32 array_size)
    : PcbUpdateStmt(ciphet_table, array_size), UpdateStmt(0), IsDefined(0) {}

PcbOracleUpdateStmt::~PcbOracleUpdateStmt() {
    delete UpdateStmt;
    Connection.disconnect();
}

dgt_sint32 PcbOracleUpdateStmt::initialize() throw(DgcExcept) {
    //
    // connect to oracle and alter session attributes for converting date type
    // to char
    //
    if (Connection.connect(CipherTable->linkInfo())) {
        ATHROWnR(DgcError(SPOS, "connet failed"), -1);
    }
    //
    // build update sql text
    //
    dgt_uint16 num_columns = CipherTable->numColumns();
    dgt_uint16 num_indexes = CipherTable->numIndexes();
    SqlText = new dgt_schar[128 + num_columns * 94];
    *SqlText = 0;
    sprintf(SqlText, "update ");
    dg_strcat(SqlText, CipherTable->schemaName());
    dg_strcat(SqlText, ".");
    if (CipherTable->encType() == 0)
        dg_strcat(SqlText, CipherTable->encTabName());
    else
        dg_strcat(SqlText, CipherTable->tableName());
    dg_strcat(SqlText, " set ");
    PcbCipherColumn* cipher_column;
    for (dgt_uint16 cno = 0;
         cno < num_columns && (cipher_column = CipherTable->cipherColumn(cno));
         cno++) {
        dgt_schar tmp[128];
        if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_NULLUPDATE) {
            dg_sprintf(tmp, "%s=NULL", cipher_column->columnName());
        } else if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT) {
            dg_sprintf(tmp, "%s=:%d", cipher_column->columnName(), cno + 1);
        } else {
            dg_sprintf(tmp, "%s=:%d", cipher_column->encColName(), cno + 1);
        }
        dg_strcat(SqlText, tmp);
        if (cno + 1 < num_columns) dg_strcat(SqlText, ",");  // not the last
    }

    // index column update
    PcbCipherColumn* cipher_idx_column;
    for (dgt_uint16 idx_cno = num_columns;
         idx_cno < (num_columns + num_indexes) &&
         (cipher_idx_column = CipherTable->cipherColumn(idx_cno));
         idx_cno++) {
        // dgt_schar	tmp[128];
        // dg_sprintf(tmp,",
        // %s_IDX=hextoraw(:%d)",cipher_idx_column->encColName(),idx_cno+1);
        // dgt_schar* tmp=cipher_idx_column->indexColName();
        dgt_schar default_idx_name[40];
        dg_sprintf(default_idx_name, "%s_IDX", cipher_idx_column->encColName());
        dgt_schar tmp[128];
        dg_sprintf(tmp, ", %s=hextoraw(:%d)",
                   cipher_idx_column->indexColName()
                       ? cipher_idx_column->indexColName()
                       : default_idx_name,
                   idx_cno + 1);
        dg_strcat(SqlText, tmp);
    }
    dg_strcat(SqlText, " where ROWID = chartorowid(:a)");
    UpdateStmt = Connection.getStmt(SqlText, num_columns + num_indexes + 1,
                                    num_columns + 1);
    if (UpdateStmt->declare(SqlText, ArraySize))
        ATHROWnR(DgcError(SPOS, "declare[%s] failed", SqlText), -1);
    if (UpdateStmt->open())
        ATHROWnR(DgcError(SPOS, "open[%s] failed", SqlText), -1);
    return 0;
}

dgt_sint32 PcbOracleUpdateStmt::update(PcbDataChunk* data_chunk) throw(
    DgcExcept) {
#if 0  // this should be moved to SelectStmt because cipher lib is not
       // thread-safe.
	//
	// ecrypting or decrypting
	//
	if (CipherTable->getDecryptFlag()==PCB_DECRYPT_FLAG_DECRYPT) {
		if (CipherTable->decrypt(data_chunk)) ATHROWnR(DgcError(SPOS,"decrypt failed"),-1);
	} else {
		if (CipherTable->encrypt(data_chunk)) ATHROWnR(DgcError(SPOS,"encrypt failed"),-1);
	}
#endif
    dgt_sint32 rtn = 0;
    dgt_uint16 rowid_cno = 0;
    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_NULLUPDATE) {
        rowid_cno = 0;
        //
        // define binding variables
        //
        if (!IsDefined) {
            rtn = UpdateStmt->defineBind(
                rowid_cno, "", SQLT_CHR,
                data_chunk->dataColumn(rowid_cno)->maxColLen());
            if (rtn) ATHROWnR(DgcError(SPOS, "defineBind failed"), -1);
            IsDefined = 1;
        }
    } else {
        rowid_cno = CipherTable->numColumns() + CipherTable->numIndexes();
        //
        // define binding variables
        //
        if (!IsDefined) {
            for (dgt_uint16 cno = 0; cno < CipherTable->numColumns(); cno++) {
                if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT) {
                    if (CipherTable->cipherColumn(cno)->colType() ==
                        PcbCipherColumn::PCB_COL_TYPE_BIN) {
                        rtn = UpdateStmt->defineBind(
                            cno, "", SQLT_BIN,
                            data_chunk->dataColumn(cno)->maxColLen());
                    } else {
                        rtn = UpdateStmt->defineBind(
                            cno, "", SQLT_CHR,
                            data_chunk->dataColumn(cno)->maxColLen());
                    }
                } else {
                    if (CipherTable->cipherColumn(cno)->isTextEncoded()) {
                        rtn = UpdateStmt->defineBind(
                            cno, "", SQLT_CHR,
                            data_chunk->dataColumn(cno)->maxEncColLen());
                    } else {
                        rtn = UpdateStmt->defineBind(
                            cno, "", SQLT_BIN,
                            data_chunk->dataColumn(cno)->maxEncColLen());
                    }
                }
                if (rtn) ATHROWnR(DgcError(SPOS, "defineBind failed"), -1);
                if (CipherTable->numIndexes() > 0) {
                    dgt_uint16 idx_cno =
                        CipherTable->cipherColumn(cno)->getIdxColumnOrder();
                    if (idx_cno >
                        0)  // rtn=UpdateStmt->defineBind(idx_cno,"",SQLT_CHR,data_chunk->dataColumn(idx_cno)->maxEncColLen());
                        rtn = UpdateStmt->defineBind(
                            idx_cno, "", SQLT_BIN,
                            data_chunk->dataColumn(idx_cno)->maxEncColLen());
                }
                if (rtn) ATHROWnR(DgcError(SPOS, "defineBind failed"), -1);
            }
            rtn = UpdateStmt->defineBind(
                rowid_cno, "", SQLT_CHR,
                data_chunk->dataColumn(rowid_cno)->maxColLen());
            if (rtn) ATHROWnR(DgcError(SPOS, "defineBind failed"), -1);
            IsDefined = 1;
        }
    }

    //
    // bind variables
    //
    for (dgt_uint32 rno = 0; rno < data_chunk->numRows(); rno++) {
        if (CipherTable->getDecryptFlag() != PCB_DECRYPT_FLAG_NULLUPDATE) {
            for (dgt_uint16 cno = 0; cno < CipherTable->numColumns(); cno++) {
                PcbDataColumn* data_column = data_chunk->dataColumn(cno);
                if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT) {
                    if (UpdateStmt->setBind(cno, rno, data_column->colData(rno),
                                            *data_column->colLen(rno), 0)) {
                        ATHROWnR(DgcError(SPOS, "setBind failed"), -1);
                    }
                } else {
                    if (UpdateStmt->setBind(cno, rno,
                                            data_column->encColData(rno),
                                            *data_column->encColLen(rno), 0)) {
                        ATHROWnR(DgcError(SPOS, "setBind failed"), -1);
                    }
                }
                if (CipherTable->numIndexes() > 0) {
                    dgt_uint16 idx_cno =
                        CipherTable->cipherColumn(cno)->getIdxColumnOrder();
                    if (idx_cno > 0) {
                        PcbDataColumn* idx_data_column =
                            data_chunk->dataColumn(idx_cno);
                        if (UpdateStmt->setBind(
                                idx_cno, rno, idx_data_column->encColData(rno),
                                *idx_data_column->encColLen(rno), 0)) {
                            ATHROWnR(DgcError(SPOS, "setBind failed"), -1);
                        }
                    }
                }
                if (rtn) ATHROWnR(DgcError(SPOS, "defineBind failed"), -1);
            }
        }
        if (UpdateStmt->setBind(
                rowid_cno, rno, data_chunk->dataColumn(rowid_cno)->colData(rno),
                *(data_chunk->dataColumn(rowid_cno)->colLen(rno)), 0)) {
            ATHROWnR(DgcError(SPOS, "setBind failed"), -1);
        }
    }

#if 0
dgt_uint16 dst_len=*(data_chunk->dataColumn(rowid_cno)->colLen(0));
DgcWorker::PLOG.tprintf(0,"###PcbOracleUpdateStmt::update\n");
DgcWorker::PLOG.tprintf(0,"encColLen[%d] output[",dst_len);
for(dgt_uint32 i=0; i<dst_len; i++) DgcWorker::PLOG.tprintf(0,"%c",*(data_chunk->dataColumn(rowid_cno)->colData(0)+i));
DgcWorker::PLOG.tprintf(0,"]\n");
#endif
    //
    // execute
    //

    if (UpdateStmt->execute(data_chunk->numRows())) {
        DgcExcept* e = EXCEPTnC;
        Connection.rollback();
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }

    //
    // commit
    //
    if (Connection.commit()) {
        ATHROWnR(DgcError(SPOS, "commit failed"), -1);
    }
    return 0;
}

dgt_sint32 PcbOracleUpdateStmt::verifUpdate(dgt_uint32 partition_number) throw(
    DgcExcept) {
    return 0;
}
