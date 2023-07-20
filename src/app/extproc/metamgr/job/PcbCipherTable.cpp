/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbCipherTable
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbCipherTable.h"

#include "DgcDbProcess.h"

PcbCipherTable::PcbCipherTable(dgt_sint64 enc_table_id, dgt_uint8 decrypt_flag)
    : EncTableID(enc_table_id),
      DecryptFlag(decrypt_flag),
      SchemaLinkInfo(DgcDbProcess::db().pdb()),
      LinkInfo(0),
      NumColumns(0),
      NumIndexes(0) {
    for (dgt_uint32 i = 0; i < PCB_MAX_CIPHER_COLUMNS; i++)
        CipherColumns[i] = 0;
}

PcbCipherTable::~PcbCipherTable() {
    for (dgt_uint16 i = 0; i < NumColumns; i++) delete CipherColumns[i];
}

dgt_sint32 PcbCipherTable::initialize() throw(DgcExcept) {
    dgt_schar sql_txt[256] = {
        0,
    };
    //
    // get encrypt table info
    //
    sprintf(sql_txt, "select * from pct_enc_table where enc_tab_id=%lld",
            EncTableID);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(),
                                                      sql_txt, strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&EncTable, rowd, sizeof(EncTable));
        }
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e)
        RTHROWnR(e,
                 DgcError(SPOS, "PCT_ENC_TABLE[%lld] execute/fetch failed",
                          EncTableID),
                 -1);
    //
    // get encrypt schema info
    //
    sprintf(sql_txt,
            "select b.* from pct_enc_table a, pct_enc_schema b where "
            "a.schema_id=b.schema_id and a.enc_tab_id=%lld",
            EncTableID);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&EncSchema, rowd, sizeof(EncSchema));
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e)
        RTHROWnR(e,
                 DgcError(SPOS, "PCT_ENC_SCHEMA[%lld] execute/fetch failed",
                          EncTableID),
                 -1);
    //
    // get encrypt agent info
    //
    sprintf(sql_txt,
            "select c.* from pct_enc_table a, pct_enc_schema b, pt_database c "
            "where a.schema_id=b.schema_id and b.db_id = c.db_id and "
            "a.enc_tab_id=%lld",
            EncTableID);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&EncDatabase, rowd, sizeof(EncDatabase));
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e)
        RTHROWnR(
            e,
            DgcError(SPOS, "PCT_AGENT[%lld] execute/fetch failed", EncTableID),
            -1);

    // get parallel degree
    sprintf(sql_txt, "select * from pct_db_agent where db_id=%lld",
            EncDatabase.db_id);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&DbAgent, rowd, sizeof(DbAgent));
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e)
        RTHROWnR(
            e,
            DgcError(SPOS, "PCT_AGENT[%lld] execute/fetch failed", EncTableID),
            -1);
    //
    // get schema link info
    //
    if (!(LinkInfo = SchemaLinkInfo.getDatabaseLinkInfo(DbAgent.admin_link))) {
        ATHROWnR(DgcError(SPOS, "getDatabaseLinkInfo[%s] failed",
                          EncSchema.schema_name),
                 -1);
    }
    //
    // create CipherColumns
    //
    sprintf(sql_txt,
            "select enc_col_id from pct_enc_column where enc_tab_id=%lld and "
            "status =1",
            EncTableID);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_sint64* enc_col_id;
        while ((enc_col_id = (dgt_sint64*)sql_stmt->fetch())) {
            CipherColumns[NumColumns++] = new PcbCipherColumn(*enc_col_id);
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    if (e && e->errCode() != DGC_EC_PD_NOT_FOUND) {
        RTHROWnR(e,
                 DgcError(SPOS, "PCT_ENC_COLUMN[%lld] execute/fetch failed",
                          EncTableID),
                 -1);
    }
    delete e;
    //
    // initialize CipherColumns
    //
    dgt_sint32 rtn = 0;
    for (dgt_uint16 i = 0; i < NumColumns; i++) {
        if ((rtn = CipherColumns[i]->initialize()) < 0) {
            ATHROWnR(DgcError(SPOS, "CipherColumn[%u].initialize failed", i),
                     rtn);
        }
    }
    NumIndexes = 0;
    if (DecryptFlag != PCB_DECRYPT_FLAG_ENCRYPT) return 0;

    //
    // domain index search
    //

    memset(sql_txt, 0, 256);
    dgt_uint16 add_num_cols = NumColumns;
    for (dgt_uint16 i = 0; i < NumColumns; i++) {
        sprintf(sql_txt,
                "select enc_idx_id from pct_enc_index where index_type=1 and "
                "enc_col_id=%lld",
                CipherColumns[i]->encColumnID());
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                              strlen(sql_txt));
        if (!sql_stmt) {
            ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
        }
        if (sql_stmt->execute() >= 0) {
            dgt_sint64 enc_idx_id = 0;
            dgt_sint64* enc_idx_id_tmp = 0;
            while ((enc_idx_id_tmp = (dgt_sint64*)sql_stmt->fetch())) {
                CipherColumns[add_num_cols] =
                    new PcbCipherColumn(CipherColumns[i]->encColumnID());
                enc_idx_id = *enc_idx_id_tmp;
                NumIndexes++;
            }
            e = EXCEPTnC;
            delete sql_stmt;
            if (e && e->errCode() != DGC_EC_PD_NOT_FOUND) {
                RTHROWnR(
                    e,
                    DgcError(SPOS, "PCT_ENC_INDEX[%lld] execute/fetch failed",
                             CipherColumns[i]->encColumnID()),
                    -1);
            }
            delete e;
            //
            // initialize index column
            //
            dgt_sint32 rtn = 0;
            if (enc_idx_id > 0) {
                // printf("PcbCipherTable::initialize()
                // NumColumns[%d],NumIndexes[%d]\n",NumColumns,NumIndexes);
                rtn = CipherColumns[add_num_cols]->initializeIndexColumns(
                    CipherColumns[i]->getEncColumn(),
                    CipherColumns[i]->getEncKey(),
                    CipherColumns[i]->getCipherContext());
                if (rtn < 0)
                    ATHROWnR(
                        DgcError(
                            SPOS,
                            "CipherColumn[%u].initializeIndexColumns failed",
                            i),
                        rtn);
                CipherColumns[i]->setIdxColumnOrder(add_num_cols);
                add_num_cols++;
            }
        }
    }

    return 0;
}

dgt_sint32 PcbCipherTable::encrypt(PcbDataChunk* data_chunk) throw(DgcExcept) {
    dgt_uint16 num_columns = 0;
    if (DecryptFlag == PCB_DECRYPT_FLAG_VERIFICATION)
        num_columns = NumColumns * 2;
    else
        num_columns = NumColumns;
    if (data_chunk->numColumns() != num_columns + 1) {
        THROWnR(DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "the number of columns mismatch [%d:%d;",
                                 data_chunk->numColumns(), num_columns)),
                -1);
    }
    for (dgt_uint16 cno = 0; cno < NumColumns; cno++) {
        // printf("####PcbCipherTable::encrypt idx_cno[%d] columnName[%s]
        // \n",cno,CipherColumns[cno]->columnName());
        if (CipherColumns[cno]->encrypt(data_chunk->dataColumn(cno))) {
            ATHROWnR(DgcError(SPOS, "CipherColumn[%u].encrypt failed", cno),
                     -1);
        }
        dgt_uint16 idx_col_order = CipherColumns[cno]->getIdxColumnOrder();
        if (idx_col_order > 0) {
            // printf("#####PcbCipherTable::encrypt OPHUEK
            // idx_col_order[%d]\n",idx_col_order);
            if (CipherColumns[idx_col_order]->ophuek(
                    data_chunk->dataColumn(idx_col_order),
                    data_chunk->dataColumn(cno))) {
                ATHROWnR(DgcError(SPOS, "CipherColumn[%u].ophuek failed", cno),
                         -1);
            }
        }
    }
    return 0;
}

dgt_sint32 PcbCipherTable::decrypt(PcbDataChunk* data_chunk) throw(DgcExcept) {
    dgt_uint16 num_columns = 0;
    dgt_uint8 verify_flag = 0;
    if (DecryptFlag == PCB_DECRYPT_FLAG_VERIFICATION) {
        num_columns = NumColumns * 2;
        verify_flag = 1;
    } else {
        num_columns = NumColumns;
        verify_flag = 0;
    }
    if (data_chunk->numColumns() != num_columns + 1) {
        THROWnR(DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "the number of columns mismatch [%d:%d;",
                                 data_chunk->numColumns(), num_columns)),
                -1);
    }
    for (dgt_uint16 cno = 0; cno < NumColumns; cno++) {
        if (CipherColumns[cno]->decrypt(data_chunk->dataColumn(cno),
                                        verify_flag)) {
            ATHROWnR(DgcError(SPOS, "CipherColumn[%u].decrypt failed", cno),
                     -1);
        }
    }
    return 0;
}
