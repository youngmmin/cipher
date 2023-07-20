/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbOracleSelectStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbOracleSelectStmt.h"

#include "DgcDbProcess.h"

PcbOracleSelectStmt::PcbOracleSelectStmt(PcbCipherTable* cipher_table,
                                         dgt_uint32 array_size)
    : PcbSelectStmt(cipher_table, array_size), SelectStmt(0) {}

PcbOracleSelectStmt::~PcbOracleSelectStmt() {
    delete SelectStmt;
    Connection.disconnect();
}

dgt_sint32 PcbOracleSelectStmt::initialize(dgt_schar* where_clause) throw(
    DgcExcept) {
    //
    // connect to oracle and alter session attributes for converting date type
    // to char
    //
    if (Connection.connect(CipherTable->linkInfo())) {
        ATHROWnR(DgcError(SPOS, "connet failed"), -1);
    }
    //
    // select total rows
    //
    dgt_schar alter_txt[128];
    sprintf(alter_txt, "select total_rows from pct_job where enc_tab_id=%lld",
            CipherTable->encTabId());
    DgcDatabase* Database = DgcDbProcess::dbPtr();
    DgcSqlStmt* sql_stmt =
        Database->getStmt(DgcDbProcess::sess(), alter_txt, strlen(alter_txt));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_sint64* tc;
    if ((tc = (dgt_sint64*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    TotalRows = *tc;
    delete sql_stmt;

    if (TotalRows == 0) {
        if (CipherTable->encType() == 0)
            dg_sprintf(alter_txt,
                       "select num_rows from dba_tables where table_name = "
                       "upper('%s') and owner=upper('%s') ",
                       CipherTable->encTabName(), CipherTable->schemaName());
        else
            dg_sprintf(alter_txt,
                       "select num_rows from dba_tables where table_name = "
                       "upper('%s') and owner=upper('%s') ",
                       CipherTable->tableName(), CipherTable->schemaName());
        DgcDbifCoreOciCursor* count_stmt = Connection.getStmt(alter_txt, 0, 1);
        DgcExcept* e = 0;
        if (count_stmt->declare(alter_txt, 1))
            e = EXCEPTnC;
        else if (count_stmt->open())
            e = EXCEPTnC;
        else if (count_stmt->execute())
            e = EXCEPTnC;
        if (e) {
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute[%s] failed", alter_txt), -1);
        }
        count_stmt->defineResult(0, SQLT_CHR, 32);
        if (count_stmt->fetch() <= 0) {
            e = EXCEPTnC;
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "no fetched row")),
                    -1);
        }
        DgcDbifCoreOciData* oci_data = count_stmt->getReturnDataArea();
        TotalRows = dg_strtoll((dgt_schar*)oci_data->valp, 0, 10);
        if (count_stmt->close()) {
            e = EXCEPTnC;
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "close[%s] failed", alter_txt), -1);
        }
        delete count_stmt;
    }
    if (TotalRows == 0) {
        memset(alter_txt, 0, 128);
        if (CipherTable->encType() == 0)
            dg_sprintf(alter_txt, "select count(rowid) from %s.%s",
                       CipherTable->schemaName(), CipherTable->encTabName());
        else
            dg_sprintf(alter_txt, "select count(rowid) from %s.%s",
                       CipherTable->schemaName(), CipherTable->tableName());
        DgcDbifCoreOciCursor* count_stmt = Connection.getStmt(alter_txt, 0, 1);
        DgcExcept* e = 0;
        if (count_stmt->declare(alter_txt, 1))
            e = EXCEPTnC;
        else if (count_stmt->open())
            e = EXCEPTnC;
        else if (count_stmt->execute())
            e = EXCEPTnC;
        if (e) {
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute[%s] failed", alter_txt), -1);
        }
        count_stmt->defineResult(0, SQLT_CHR, 32);
        if (count_stmt->fetch() <= 0) {
            e = EXCEPTnC;
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "no fetched row")),
                    -1);
        }
        DgcDbifCoreOciData* oci_data = count_stmt->getReturnDataArea();
        TotalRows = dg_strtoll((dgt_schar*)oci_data->valp, 0, 10);
        if (count_stmt->close()) {
            e = EXCEPTnC;
            delete count_stmt;
            RTHROWnR(e, DgcError(SPOS, "close[%s] failed", alter_txt), -1);
        }
        delete count_stmt;
    }

    //
    // build select sql text
    //
    SqlText = new dgt_schar[128 + CipherTable->numColumns() * 94];
    *SqlText = 0;
    dgt_uint16 parallel_degree = CipherTable->getDbAgent()->parallel_degree;
    sprintf(SqlText, "select /*+ parallel(T %d) big */ ",
            parallel_degree ? parallel_degree : 2);
    PcbCipherColumn* cipher_column;
    if (CipherTable->getDecryptFlag() != PCB_DECRYPT_FLAG_NULLUPDATE) {
        for (dgt_uint16 cno = 0;
             cno < CipherTable->numColumns() &&
             (cipher_column = CipherTable->cipherColumn(cno));
             cno++) {
            if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT ||
                CipherTable->getDecryptFlag() ==
                    PCB_DECRYPT_FLAG_VERIFICATION) {
                dg_strcat(SqlText, cipher_column->encColName());
            } else {
                if (cipher_column->colType() >
                    PcbCipherColumn::PCB_COL_TYPE_CHR) {
                    dg_strcat(SqlText, "to_char(");
                    dg_strcat(SqlText, cipher_column->columnName());
                    dg_strcat(SqlText, ")");
                } else {
                    dg_strcat(SqlText, cipher_column->columnName());
                }
            }
            dg_strcat(SqlText, ",");  // not the last
        }
    }

    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_VERIFICATION) {
        //
        // get encrypted column
        //
        for (dgt_uint16 cno = 0;
             cno < CipherTable->numColumns() &&
             (cipher_column = CipherTable->cipherColumn(cno));
             cno++) {
            dg_strcat(SqlText, cipher_column->columnName());
            dg_strcat(SqlText, ",");
        }
    }

    dg_strcat(SqlText, " rowidtochar(ROWID) from ");
    dg_strcat(SqlText, CipherTable->schemaName());
    dg_strcat(SqlText, ".");
    if (CipherTable->encType() == 0)
        dg_strcat(SqlText, CipherTable->encTabName());
    else
        dg_strcat(SqlText, CipherTable->tableName());
    dg_strcat(SqlText, " T ");

    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_VERIFICATION) {
        //
        // build where clause
        //
        if (where_clause && *where_clause) {
            dg_strcat(SqlText, " where (");
            dg_strcat(SqlText, where_clause);
            dg_strcat(SqlText, ")");
        }
    } else {
        dg_strcat(SqlText, " where ");
        if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_NULLUPDATE) {
            for (dgt_uint16 cno = 0;
                 cno < CipherTable->numColumns() &&
                 (cipher_column = CipherTable->cipherColumn(cno));
                 cno++) {
                if (cno > 0) dg_strcat(SqlText, " or ");
                dg_strcat(SqlText, cipher_column->columnName());
                dg_strcat(SqlText, " is not null ");
            }
        } else {
            for (dgt_uint16 cno = 0;
                 cno < CipherTable->numColumns() &&
                 (cipher_column = CipherTable->cipherColumn(cno));
                 cno++) {
                if (cno > 0) dg_strcat(SqlText, " or ");
                if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT)
                    dg_strcat(SqlText, cipher_column->columnName());
                else
                    dg_strcat(SqlText, cipher_column->encColName());
                dg_strcat(SqlText, " is null ");
            }
        }
        //
        // build where clause
        //
        if (where_clause && *where_clause) {
            dg_strcat(SqlText, " and (");
            dg_strcat(SqlText, where_clause);
            dg_strcat(SqlText, ")");
        }
    }
    // DgcWorker::PLOG.tprintf(0,"175. PcbOracleSelectStmt::initialize ORA
    // select [%s]\n",SqlText);
    //
    // execute select sql
    //
    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_NULLUPDATE)
        SelectStmt =
            Connection.getStmt(SqlText, CipherTable->numColumns() + 1, 1);
    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_VERIFICATION)
        SelectStmt =
            Connection.getStmt(SqlText, CipherTable->numColumns() * 2 + 1,
                               CipherTable->numColumns() * 2 + 1);
    else
        SelectStmt = Connection.getStmt(
            SqlText, CipherTable->numColumns() + CipherTable->numIndexes() + 1,
            CipherTable->numColumns() + CipherTable->numIndexes() + 1);

    if (SelectStmt->declare(SqlText, ArraySize))
        ATHROWnR(DgcError(SPOS, "declare[%s] failed", SqlText), -1);
    if (SelectStmt->open())
        ATHROWnR(DgcError(SPOS, "open[%s] failed", SqlText), -1);
    if (SelectStmt->execute())
        ATHROWnR(DgcError(SPOS, "execute[%s] failed", SqlText), -1);

    //
    // get & set select list attributes
    //
    DgcDbifCoreOciColumn slist(SelectStmt);
    if (slist.describe())
        ATHROWnR(DgcError(SPOS, "describe[%s] failed", SqlText), -1);
    for (dgt_uint16 cno = 0; cno < slist.getCount(); cno++) {
        dgt_colattr* cattr = slist.getAttr(!cno);
        PcbCipherColumn* cipher_column = CipherTable->cipherColumn(cno);
        if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT ||
            CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_VERIFICATION) {
            if (!cipher_column ||
                (cipher_column && cipher_column->isTextEncoded())) {
                SelectStmt->defineResult(cno, SQLT_CHR, cattr->leng);
            } else {
                SelectStmt->defineResult(cno, SQLT_BIN, cattr->leng);
            }
        } else {
            if (cipher_column &&
                cipher_column->colType() == PcbCipherColumn::PCB_COL_TYPE_BIN) {
                SelectStmt->defineResult(cno, SQLT_BIN, cattr->leng);
            } else {
                SelectStmt->defineResult(cno, SQLT_CHR, cattr->leng);
            }
        }
        addFetchCol(cattr->name, cattr->leng);
    }
    return 0;
}

dgt_sint32 PcbOracleSelectStmt::fetch() throw(DgcExcept) {
    NumFetchedRows = SelectStmt->fetch();
    if (NumFetchedRows < 0) {
        if (EXCEPT->errCode() == 1002) {
            //
            // fetch out of sequence, which happens when trying to fetch at the
            // end of rows
            //
            delete EXCEPTnC;
            NumFetchedRows = 0;
        } else
            ATHROWnR(DgcError(SPOS, "fetch[%s] failed", SqlText ? SqlText : 0),
                     -1);
    }
    return NumFetchedRows;
}

dgt_sint32 PcbOracleSelectStmt::fetch(PcbDataChunk* data_chunk) throw(
    DgcExcept) {
    if (fetch() < 0) {
        ATHROWnR(DgcError(SPOS, "fetch failed"), -1);
    }
    if (NumFetchedRows > 0) {
        DgcDbifCoreOciData* oci_data = SelectStmt->getReturnDataArea();
        for (dgt_uint16 cno = 0; cno < NumFetchCols; cno++) {
            if ((CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT ||
                 CipherTable->getDecryptFlag() ==
                     PCB_DECRYPT_FLAG_VERIFICATION) &&
                cno < CipherTable->numColumns()) {
                data_chunk->dataColumn(cno)->putEncData(
                    NumFetchedRows, (dgt_schar*)(oci_data + cno)->valp,
                    (oci_data + cno)->indp, (oci_data + cno)->lenp);
            } else {
                if (cno == NumFetchCols - 1) {
                    if (CipherTable->getDecryptFlag() ==
                        PCB_DECRYPT_FLAG_NULLUPDATE)
                        data_chunk->dataColumn(cno)->putData(
                            NumFetchedRows, (dgt_schar*)(oci_data + cno)->valp,
                            (oci_data + cno)->indp, (oci_data + cno)->lenp);
                    else
                        data_chunk->dataColumn(cno + CipherTable->numIndexes())
                            ->putData(NumFetchedRows,
                                      (dgt_schar*)(oci_data + cno)->valp,
                                      (oci_data + cno)->indp,
                                      (oci_data + cno)->lenp);
                } else {
                    data_chunk->dataColumn(cno)->putData(
                        NumFetchedRows, (dgt_schar*)(oci_data + cno)->valp,
                        (oci_data + cno)->indp, (oci_data + cno)->lenp);
                }
            }
        }
    }
    //
    // ecrypting or decrypting
    //
    if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_DECRYPT ||
        CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_VERIFICATION) {
        if (CipherTable->decrypt(data_chunk))
            ATHROWnR(DgcError(SPOS, "decrypt failed"), -1);
    } else if (CipherTable->getDecryptFlag() == PCB_DECRYPT_FLAG_ENCRYPT) {
        if (CipherTable->encrypt(data_chunk))
            ATHROWnR(DgcError(SPOS, "encrypt failed"), -1);
    }
    return NumFetchedRows;
}

dgt_sint32 PcbOracleSelectStmt::getFetchData(
    dgt_uint32 col_order, dgt_void** buf, dgt_sint16** ind,
    dgt_uint16** len) throw(DgcExcept) {
    if (col_order == 0 || col_order > NumFetchCols) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "column[%d] out of range[%d]",
                                          col_order, NumFetchCols)),
                -1);
    }
    if (NumFetchedRows <= 0) {
        THROWnR(DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "no fetched rows or failed fetch[%d]",
                                 NumFetchedRows)),
                -1);
    }
    DgcDbifCoreOciData* oci_data = SelectStmt->getReturnDataArea();
    *buf = (oci_data + col_order - 1)->valp;
    *ind = (oci_data + col_order - 1)->indp;
    *len = (oci_data + col_order - 1)->lenp;
    return 0;
}
