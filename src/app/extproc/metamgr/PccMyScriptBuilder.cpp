/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccMyScriptBuilder
 *   Implementor        :       mwpark
 *   Create Date        :       2012. 04. 10
 *   Description        :       tds script builder
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PccMyScriptBuilder.h"

#include "DgcLinkInfo.h"

extern void check_logger(const char* fmt, ...);

typedef struct {
    dgt_sint64 index_name;
    dgt_sint64 renamed_org_name;
    dgt_sint64 index_owner;
    dgt_uint8 uniqueness;
    dgt_sint64 target_tablespace;
    dgt_uint16 degree;
} pc_type_idx2;

typedef struct {
    dgt_sint64 schema_name;
    dgt_sint64 table_name;
    dgt_sint64 renamed_tab_name;
    dgt_sint64 column_name;
    dgt_sint64 renamed_col_name;
    dgt_sint64 constraint_name;
    dgt_sint64 renamed_constraint_name;
    dgt_uint8 status;
    dgt_uint32 position;
    dgt_uint8 constraint_type;
    dgt_sint64 ref_pk_owner;
    dgt_sint64 ref_pk_table;
    dgt_sint64 ref_pk_column;
    dgt_sint64 org_renamed_tab_name;
    dgt_uint8 enc_type;
    dgt_uint8 keep_org_tab_flag;
    dgt_uint8 generated;
} pc_type_pk_info;

typedef struct {
    dgt_sint64 ref_pk_owner;
    dgt_sint64 ref_pk_table;
    dgt_sint64 ref_pk_column;
    dgt_sint64 ref_pk_renamed_table;
    dgt_sint64 ref_pk_renamed_column;
    dgt_uint8 status;
} pc_type_pk_row;

typedef struct {
    dgt_schar table_name[130];
    dgt_schar renamed_tab_name[130];
    dgt_schar column_name[130];
    dgt_schar renamed_col_name[130];
} pc_type_check_row;

typedef struct {
    dgt_schar org1[512];
    dgt_schar org2[512];
    dgt_schar enc1[512];
    dgt_schar enc2[512];
} pc_type_check_sql;

typedef struct {
    dgt_schar org1[512];
    dgt_schar org2[512];
    dgt_schar enc1[512];
    dgt_schar enc2[512];
} pc_type_pk_fk_sql;

typedef struct {
    dgt_schar org1[512];
    dgt_schar org2[512];
    dgt_schar enc1[512];
    dgt_schar enc2[512];
} pkfk_sql;

dgt_sint32 PccMyScriptBuilder::step1() throw(DgcExcept) {
    //
    // rename the orignal table for create a view with the same name
    //
    pc_type_col_info* col_info;
    StepNo = 1;
    StmtNo = 1000;
    *TextBuf = 0;
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "alter table %s.%s rename %s.%s", SchemaName,
                TabInfo.table_name, SchemaName, TabInfo.renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // create view with original table name
    //
    *TextBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "create view %s.%s as select ", SchemaName,
                TabInfo.table_name);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last "," off
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // grant privilege
    //
    typedef struct {
        dgt_schar org1[1024];
        dgt_schar enc1[1024];
        dgt_schar enc2[1024];
    } privsql;
    privsql* privsql_type;
    PrivSqlRows2.rewind();
    while (PrivSqlRows2.next()) {
        privsql_type = (privsql*)PrivSqlRows2.data();
        *TextBuf = 0;
        strcat(TextBuf, privsql_type->enc2);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        strcat(TextBuf, privsql_type->enc1);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // alter table add column
    //
    StmtNo = 2000;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            dgt_sint32 enc_len = 0;
            if (!strcasecmp(col_info->data_type, "INT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "BIGINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "MEDIUMINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "SMALLINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DECIMAL"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DOUBLE"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "FLOAT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "TINYINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "HEXADECIMAL"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATETIME"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "DATE"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "TIME"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "TIMESTAMP"))
                enc_len += 14;
            else
                enc_len += col_info->data_length;
            PCI_Context ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type,
                            col_info->enc_mode, col_info->iv_type,
                            col_info->n2n_flag, 1, col_info->enc_start_pos,
                            col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                sprintf(TextBuf, "alter table %s.%s add %s varchar(%d)",
                        SchemaName, TabInfo.renamed_tab_name,
                        col_info->renamed_col_name, enc_len);
            } else {
                sprintf(TextBuf, "alter table %s.%s add %s varchar(%d)",
                        SchemaName, TabInfo.table_name,
                        col_info->renamed_col_name, enc_len);
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // dml view for when not using instead of trigger
    //
    *TextBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "create view %s.%s_upd as select ", SchemaName,
                TabInfo.table_name);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status > 0) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s %s_upd,", col_info->renamed_col_name,
                        col_info->col_name);
                strcat(TextBuf, TmpBuf);

                *TmpBuf = 0;
                sprintf(TmpBuf, "%s %s,", getFname(col_info->enc_col_id, 2),
                        col_info->col_name);
                if (col_info->cipher_type == 4) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", col_info->renamed_col_name,
                            col_info->col_name);
                }
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last "," off
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // dml view for when not using instead of trigger
    //
    *TextBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "create view %s.%s_ins as select ", SchemaName,
                TabInfo.table_name);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 1) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s %s,", col_info->renamed_col_name,
                        col_info->col_name);
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last "," off
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // encrypting data without exclusive access
    //
    StmtNo = 3000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "update %s.%s set", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TextBuf, "update %s.%s set", SchemaName, TabInfo.table_name);
    }
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\t%s=%s,", col_info->renamed_col_name,
                    getFname(col_info->enc_col_id, 1));
            strcat(TextBuf, TmpBuf);
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // create encryption column`s index
    //
    StmtNo = 6000;
    typedef struct {
        dgt_schar org1[512];
        dgt_schar org2[512];
        dgt_schar enc1[512];
        dgt_schar enc2[512];
    } idxsql;
    idxsql* idxsql_type;
    IdxSqlRows.rewind();
    while (IdxSqlRows.next()) {
        idxsql_type = (idxsql*)IdxSqlRows.data();
        *TextBuf = 0;
        sprintf(TextBuf, (dgt_schar*)idxsql_type->enc2);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, (dgt_schar*)idxsql_type->enc1);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // replace the view for the encrypted column to be used as the original
    // column
    //
    *TextBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "drop view %s.%s", SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "create view %s.%s as\n select ", SchemaName,
                TabInfo.table_name);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status > 0) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s %s,", getFname(col_info->enc_col_id, 2),
                        col_info->col_name);
                if (col_info->cipher_type == 4) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", col_info->renamed_col_name,
                            col_info->col_name);
                }
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
        if (insteadOfTrigger(0) < 0) {
            ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
        }
    }
    return 0;
}

dgt_sint32 PccMyScriptBuilder::step2() throw(DgcExcept) {
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 1000;
    StepNo = 2;
    //
    // drop enc table's dependency foreign key
    //
    DefFkDropSqlRows.rewind();
    typedef struct {
        dgt_schar org1[512];
        dgt_schar org2[512];
        dgt_schar enc1[512];
        dgt_schar enc2[512];
        dgt_schar enc3[512];
        dgt_schar enc4[512];
    } enc_table_fk;
    enc_table_fk* tmp_ptr = 0;
    while (DefFkDropSqlRows.next() &&
           (tmp_ptr = (enc_table_fk*)DefFkDropSqlRows.data())) {
        if (tmp_ptr->enc4 && strlen(tmp_ptr->enc4) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->enc4);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (tmp_ptr->enc3 && strlen(tmp_ptr->enc3) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->enc3);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (tmp_ptr->enc2 && strlen(tmp_ptr->enc2) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->enc2);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (tmp_ptr->enc1 && strlen(tmp_ptr->enc1) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->enc1);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // If Pk,Fk Working set table then pk,fk migration
    //
    StmtNo = 3000;
    pkfk_sql* sql_row;
    if (TabInfo.iot_type == 0) {
        PkSqlRows.rewind();
        while (PkSqlRows.next() && (sql_row = (pkfk_sql*)PkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                strcpy(TextBuf, sql_row->enc2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    if (IsPkFk == 1) {
        PkSqlRows.rewind();
        if (TabInfo.iot_type == 0) {
            while (PkSqlRows.next() &&
                   (sql_row = (pkfk_sql*)PkSqlRows.data())) {
                *TextBuf = 0;
                if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
                    strcpy(TextBuf, sql_row->enc1);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            }
        }
        FkSqlRows.rewind();
        while (FkSqlRows.next() && (sql_row = (pkfk_sql*)FkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
                strcpy(TextBuf, sql_row->enc1);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    //
    // replace the instead-of trigger for replacing the original column with the
    // encrypted column
    //
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0 && col_info->nullable_flag == 0) {
            dgt_sint32 enc_len = 0;
            if (!strcasecmp(col_info->data_type, "INT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "BIGINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "MEDIUMINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "SMALLINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DECIMAL"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DOUBLE"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "FLOAT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "TINYINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "HEXADECIMAL"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATETIME"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "DATE"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "TIME"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "TIMESTAMP"))
                enc_len += 14;
            else
                enc_len += col_info->data_length;
            PCI_Context ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type,
                            col_info->enc_mode, col_info->iv_type,
                            col_info->n2n_flag, 1, col_info->enc_start_pos,
                            col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                sprintf(TextBuf,
                        "alter table %s.%s modify %s varchar(%d) not null",
                        SchemaName, TabInfo.renamed_tab_name,
                        col_info->renamed_col_name, enc_len);
            } else {
                sprintf(TextBuf,
                        "alter table %s.%s modify %s varchar(%d) not null",
                        SchemaName, TabInfo.table_name,
                        col_info->renamed_col_name, enc_len);
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                if (!strcasecmp(col_info->data_type, "varchar") ||
                    !strcasecmp(col_info->data_type, "char")) {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s(%d) null",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, col_info->data_type,
                            col_info->data_length);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s null",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, col_info->data_type);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            } else {
                if (!strcasecmp(col_info->data_type, "varchar") ||
                    !strcasecmp(col_info->data_type, "char")) {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s(%d) null",
                            SchemaName, TabInfo.table_name, col_info->col_name,
                            col_info->data_type, col_info->data_length);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s null",
                            SchemaName, TabInfo.table_name, col_info->col_name,
                            col_info->data_type);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            }
        }
    }
    if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
        if (insteadOfTrigger(1) < 0) {
            ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
        }
    }
    //
    // drop original column
    //
    StmtNo = 5000;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                sprintf(TextBuf, "update %s.%s set %s = null", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name);
            } else {
                sprintf(TextBuf, "update %s.%s set %s = null", SchemaName,
                        TabInfo.table_name, col_info->col_name);
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    return 0;
}

dgt_sint32 PccMyScriptBuilder::reverse_step1() throw(DgcExcept) {
    //
    // drop view that has decrypttion column
    //
    StepNo = -1;
    StmtNo = -8000;
    //
    // drop trigger
    //
    if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
        *TextBuf = 0;
        sprintf(TextBuf, "drop trigger %s.%s_insert", SchemaName,
                TabInfo.view_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "drop trigger %s.%s_update", SchemaName,
                TabInfo.view_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // drop & create index
    //
    StmtNo = -6000;
    typedef struct {
        dgt_schar org1[512];
        dgt_schar org2[512];
        dgt_schar enc1[512];
        dgt_schar enc2[512];
    } idxsql;
    idxsql* idxsql_type;
    IdxSqlRows.rewind();
    while (IdxSqlRows.next()) {
        idxsql_type = (idxsql*)IdxSqlRows.data();
        *TextBuf = 0;
        sprintf(TextBuf, (dgt_schar*)idxsql_type->org2);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, (dgt_schar*)idxsql_type->org1);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // revoke privilege
    //
    StmtNo = -4000;
    typedef struct {
        dgt_schar org1[1024];
        dgt_schar enc1[1024];
        dgt_schar enc2[1024];
    } privsql;
    privsql* privsql_type;
    PrivSqlRows2.rewind();
    while (PrivSqlRows2.next()) {
        privsql_type = (privsql*)PrivSqlRows2.data();
        *TextBuf = 0;
        strcat(TextBuf, privsql_type->org1);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // drop view
    //
    StmtNo = -3000;
    if (TabInfo.enc_type == 0) {
        *TextBuf = 0;
        sprintf(TextBuf, "drop view %s.%s_upd", SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "drop view %s.%s_ins", SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "drop view %s.%s", SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // rename table
    //
    StmtNo = -2000;
    if (TabInfo.enc_type == 0) {
        *TextBuf = 0;
        sprintf(TextBuf, "alter table %s.%s rename %s.%s", SchemaName,
                TabInfo.renamed_tab_name, SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // remove encrypt column
    //
    StmtNo = -1000;
    pc_type_col_info* col_info;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            *TextBuf = 0;
            sprintf(TextBuf, "alter table %s.%s drop column %s", SchemaName,
                    TabInfo.table_name, col_info->renamed_col_name);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    return 0;
}

dgt_sint32 PccMyScriptBuilder::reverse_step2() throw(DgcExcept) {
    //
    // decrypting data without exclusive access
    //
    StepNo = -2;
    StmtNo = -4000;
    *TextBuf = 0;
    *TmpBuf = 0;
    pc_type_col_info* col_info;
    if (TabInfo.enc_type == 0) {
        sprintf(TextBuf, "update %s.%s set", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TextBuf, "update %s.%s set", SchemaName, TabInfo.table_name);
    }
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\t%s=%s,", col_info->col_name,
                    getFname(col_info->enc_col_id, 2));
            strcat(TextBuf, TmpBuf);
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // drop enc table's dependency foreign key
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = -2000;
    DefFkDropSqlRows.rewind();
    typedef struct {
        dgt_schar org1[512];
        dgt_schar org2[512];
        dgt_schar enc1[512];
        dgt_schar enc2[512];
    } enc_table_fk;
    enc_table_fk* tmp_ptr = 0;
    while (DefFkDropSqlRows.next() &&
           (tmp_ptr = (enc_table_fk*)DefFkDropSqlRows.data())) {
        if (tmp_ptr->org2 && strlen(tmp_ptr->org2) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->org2);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (tmp_ptr->org1 && strlen(tmp_ptr->org1) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, tmp_ptr->org1);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // If Pk,Fk Working set table then pk,fk migration
    // drop pk,uk , create pk,uk,fk
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    pkfk_sql* sql_row;
    if (IsPkFk == 1) {
        PkSqlRows.rewind();
        while (PkSqlRows.next() && (sql_row = (pkfk_sql*)PkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->org2 && strlen(sql_row->org2) > 2) {
                strcpy(TextBuf, sql_row->org2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    if (IsPkFk == 1) {
        PkSqlRows.rewind();
        while (PkSqlRows.next() && (sql_row = (pkfk_sql*)PkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->org1 && strlen(sql_row->org1) > 2) {
                strcpy(TextBuf, sql_row->org1);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    if (IsPkFk == 1) {
        FkSqlRows.rewind();
        while (FkSqlRows.next() && (sql_row = (pkfk_sql*)FkSqlRows.data())) {
            *TextBuf = 0;
            *TextBuf = 0;
            if (sql_row->org1 && strlen(sql_row->org1) > 2) {
                strcpy(TextBuf, sql_row->org1);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    //
    // nul,not null
    //
    StmtNo = -1000;
    *TextBuf = 0;
    *TmpBuf = 0;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0 && col_info->nullable_flag == 0) {
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                if (!strcasecmp(col_info->data_type, "varchar") ||
                    !strcasecmp(col_info->data_type, "char")) {
                    sprintf(TextBuf,
                            "alter table %s.%s modify %s %s(%d) not null",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, col_info->data_type,
                            col_info->data_length);
                    if (col_info->col_default) {
                        sprintf(TextBuf, "%s default '%s'", TextBuf,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    }
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s not null",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, col_info->data_type);
                    if (col_info->col_default) {
                        sprintf(TextBuf, "%s default %s", TextBuf,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    }
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            } else {  // ghlee : no use cipher view
                if (!strcasecmp(col_info->data_type, "varchar") ||
                    !strcasecmp(col_info->data_type, "char")) {
                    sprintf(TextBuf,
                            "alter table %s.%s modify %s %s(%d) not null",
                            SchemaName, TabInfo.table_name, col_info->col_name,
                            col_info->data_type, col_info->data_length);
                    if (col_info->col_default) {
                        sprintf(TextBuf, "%s default %s", TextBuf,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    }
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s %s not null",
                            SchemaName, TabInfo.table_name, col_info->col_name,
                            col_info->data_type);
                    if (col_info->col_default) {
                        sprintf(TextBuf, "%s default %s", TextBuf,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    }
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            }
        }
    }
    return 0;
}

dgt_sint32 PccMyScriptBuilder::insteadOfTrigger(dgt_sint8 is_final) throw(
    DgcExcept) {
    //
    // insert dml trigger
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    if (is_final) {
        sprintf(TextBuf, "drop trigger %s.%s_insert", SchemaName,
                TabInfo.view_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;

    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf,
                "create trigger %s.%s_insert\nbefore insert on %s\nfor each "
                "row\nbegin",
                SchemaName, TabInfo.view_trigger_name,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf,
                "create trigger %s.%s_insert\nbefore insert on %s\nfor each "
                "row\nbegin",
                SchemaName, TabInfo.view_trigger_name, TabInfo.table_name);
    }
    strcat(TextBuf, TmpBuf);
    *TmpBuf = 0;
    pc_type_col_info* col_info;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            if (is_final) {
                if (col_info->col_default) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\tset new.%s = "
                            "petra.pls_encrypt_b64(ifnull(new.%s,'%s'),%lld);",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(
                        TmpBuf,
                        "\n\tset new.%s = petra.pls_encrypt_b64(new.%s,%lld);",
                        col_info->renamed_col_name, col_info->renamed_col_name,
                        col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                if (col_info->col_default) {
                    *TmpBuf = 0;
                    sprintf(
                        TmpBuf, "\n\tset new.%s = ifnull(new.%s,'%s');",
                        col_info->col_name, col_info->renamed_col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\tset new.%s = "
                            "petra.pls_encrypt_b64(ifnull(new.%s,'%s'),%lld);",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n\tset new.%s = new.%s;",
                            col_info->col_name, col_info->renamed_col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(
                        TmpBuf,
                        "\n\tset new.%s = petra.pls_encrypt_b64(new.%s,%lld);",
                        col_info->renamed_col_name, col_info->renamed_col_name,
                        col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
    }
    *TmpBuf = 0;
    sprintf(TmpBuf, "\nend;");
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // update instead of trigger
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    if (is_final) {
        sprintf(TextBuf, "drop trigger %s.%s_update", SchemaName,
                TabInfo.view_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf,
                "create trigger %s.%s_update\nbefore update on %s\nfor each "
                "row\nbegin",
                SchemaName, TabInfo.view_trigger_name,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf,
                "create trigger %s.%s_update\nbefore update on %s\nfor each "
                "row\nbegin",
                SchemaName, TabInfo.view_trigger_name, TabInfo.table_name);
    }
    strcat(TextBuf, TmpBuf);
    *TmpBuf = 0;
    ColInfoRows.rewind();
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            if (is_final) {
                *TmpBuf = 0;
                sprintf(TmpBuf,
                        "\n\tif ifnull(old.%s,'petra_null') != "
                        "ifnull(new.%s,'petra_null') then",
                        col_info->renamed_col_name, col_info->renamed_col_name);
                strcat(TextBuf, TmpBuf);
                if (col_info->col_default) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\t\tset new.%s = "
                            "petra.pls_encrypt_b64(ifnull(new.%s,'%s'),%lld);"
                            "\n\tend if;",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\t\tset new.%s = "
                            "petra.pls_encrypt_b64(new.%s,%lld);\n\tend if;",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name, col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf,
                        "\n\tif ifnull(old.%s,'petra_null') != "
                        "ifnull(new.%s,'petra_null') then",
                        col_info->renamed_col_name, col_info->renamed_col_name);
                strcat(TextBuf, TmpBuf);
                if (col_info->col_default) {
                    *TmpBuf = 0;
                    sprintf(
                        TmpBuf, "\n\t\tset new.%s = ifnull(new.%s,'%s');",
                        col_info->col_name, col_info->renamed_col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\t\tset new.%s = "
                            "petra.pls_encrypt_b64(ifnull(new.%s,'%s'),%lld);"
                            "\n\tend if;",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n\t\tset new.%s = new.%s;",
                            col_info->col_name, col_info->renamed_col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf,
                            "\n\t\tset new.%s = "
                            "petra.pls_encrypt_b64(new.%s,%lld);\n\tend if;",
                            col_info->renamed_col_name,
                            col_info->renamed_col_name, col_info->enc_col_id);
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
    }
    *TmpBuf = 0;
    sprintf(TmpBuf, "\nend;");
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    return 0;
}

dgt_sint32 PccMyScriptBuilder::preparePrivInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    sprintf(sql_text, "select * from pct_enc_tab_priv where enc_tab_id=%lld ",
            TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }

    typedef struct {
        dgt_schar org1[1024];
        dgt_schar enc1[1024];
        dgt_schar enc2[1024];
    } privsql;
    privsql tmp_sql;
    memset(&tmp_sql, 0, sizeof(privsql));

    pct_type_enc_tab_priv* priv_info_tmp;
    PrivSqlRows.reset();
    PrivSqlRows2.reset();
    while ((priv_info_tmp = (pct_type_enc_tab_priv*)sql_stmt->fetch())) {
        dgt_schar privilege[128];
        dgt_schar privSql[1024];
        memset(privilege, 0, 128);
        memset(privSql, 0, 1024);
        dgt_sint64 sql_id = 0;
        if (priv_info_tmp->privilege == 1) {
            sprintf(privilege, "select");
        } else if (priv_info_tmp->privilege == 2) {
            sprintf(privilege, "insert");
        } else if (priv_info_tmp->privilege == 3) {
            sprintf(privilege, "update");
        } else if (priv_info_tmp->privilege == 4) {
            sprintf(privilege, "delete");
        }
        sprintf(privSql, "grant %s on %s.%s to %s", privilege, SchemaName,
                TabInfo.table_name, priv_info_tmp->grantee);
        sprintf(tmp_sql.enc2, "grant %s on %s.%s to %s", privilege, SchemaName,
                TabInfo.table_name, priv_info_tmp->grantee);
        PrivSqlRows.add();
        PrivSqlRows.next();
        memcpy(PrivSqlRows.data(), privSql, 1024);
        if (TabInfo.enc_type == 0) {
            memset(privSql, 0, 1024);
            sprintf(privSql, "grant %s on %s.%s to %s", privilege, SchemaName,
                    TabInfo.renamed_tab_name, priv_info_tmp->grantee);
            sprintf(tmp_sql.enc1, "grant %s on %s.%s to %s", privilege,
                    SchemaName, TabInfo.renamed_tab_name,
                    priv_info_tmp->grantee);
            sprintf(tmp_sql.org1, "revoke %s on %s.%s from %s", privilege,
                    SchemaName, TabInfo.renamed_tab_name,
                    priv_info_tmp->grantee);
            PrivSqlRows.add();
            PrivSqlRows.next();
            memcpy(PrivSqlRows.data(), privSql, 1024);
        }

        PrivSqlRows2.add();
        PrivSqlRows2.next();
        memcpy(PrivSqlRows2.data(), &tmp_sql, sizeof(privsql));
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        delete e;
    }
    PrivSqlRows2.rewind();
    PrivSqlRows.rewind();
    return 1;
}

dgt_sint32 PccMyScriptBuilder::prepareIdxInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048] = {
        0,
    };
    //
    // Unique Idx Column settting(non enc column) for double view except rowid
    //
    IdxColRows.reset();
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    //
    // Unique Idx Column settting(non enc column) for double view except rowid
    //
    IdxColRows.reset();
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select c.idx_name1 "
            "from "
            "( select a.index_name idx_name1,b.index_name idx_name2 "
            "from    pct_enc_col_index a, "
            "(select distinct index_name "
            "from   pct_enc_col_index "
            "where  status = 1 "
            "and    enc_tab_id= %lld) (+) b "
            "where  a.index_name = b.index_name "
            "and    a.enc_tab_id = %lld "
            "and    a.uniqueness = 1 ) c "
            "where   c.idx_name2 = 0",
            TabInfo.enc_tab_id, TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_sint64* idxname = 0;
    if ((idxname = (dgt_sint64*)sql_stmt->fetch())) {
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select c.column_name "
                "from "
                "( "
                "select b.column_name,a.column_position "
                "from pct_enc_col_index a, pct_enc_column b "
                "where a.enc_col_id = b.enc_col_id "
                "and   a.index_name = %lld "
                "and   a.enc_tab_id = %lld "
                "order by a.column_position "
                ") c",
                *idxname, TabInfo.enc_tab_id);
        DgcSqlStmt* idx_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (idx_stmt == 0 || idx_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete idx_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        dgt_schar* idxcol = 0;
        while ((idxcol = (dgt_schar*)idx_stmt->fetch())) {
            IdxColRows.add();
            IdxColRows.next();
            memcpy(IdxColRows.data(), idxcol, strlen(idxcol));
        }
        DgcExcept* e = EXCEPTnC;
        if (e) {
            delete e;
        }
        delete idx_stmt;
    }
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    delete sql_stmt;
    IdxColRows.rewind();

    //
    // Unique Idx enc Column settting (for $$ column unique index)
    //
    IdxSqlRows.reset();
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select distinct index_name "
            "from   pct_enc_col_index "
            "where  enc_tab_id = %lld "
            "and    status = 1 ",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    idxname = 0;
    while ((idxname = (dgt_sint64*)sql_stmt->fetch())) {
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select a.index_name, b.column_name , b.renamed_col_name, "
                "a.column_position, a.UNIQUENESS, a.index_type, a.status "
                "from pct_enc_col_index a, pct_enc_column b "
                "where a.enc_col_id = b.enc_col_id "
                "and   a.index_name = %lld "
                "and   a.enc_tab_id = %lld "
                "order by a.column_position ",
                *idxname, TabInfo.enc_tab_id);
        DgcSqlStmt* idx_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (idx_stmt == 0 || idx_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete idx_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        typedef struct {
            dgt_sint64 index_name;
            dgt_schar col_name[130];
            dgt_schar renamed_col_name[130];
            dgt_uint8 position;
            dgt_uint8 uniqueness;
            dgt_uint8 index_type;
            dgt_uint8 status;
        } idx_type;
        idx_type* idxcol = 0;
        typedef struct {
            dgt_schar org1[512];
            dgt_schar org2[512];
            dgt_schar enc1[512];
            dgt_schar enc2[512];
        } idxsql;
        idxsql tmp_sql;
        memset(&tmp_sql, 0, sizeof(idxsql));
        dgt_sint32 seq = 0;
        while ((idxcol = (idx_type*)idx_stmt->fetch())) {
            seq++;
            if (seq == 1) {
                if (idxcol->uniqueness) {
                    if (TabInfo.enc_type == 0) {
                        sprintf(tmp_sql.org1,
                                "create unique index %s on %s.%s(%s,",
                                PetraNamePool->getName(idxcol->index_name),
                                SchemaName, TabInfo.renamed_tab_name,
                                idxcol->col_name);
                    } else {
                        sprintf(
                            tmp_sql.org1, "create unique index %s on %s.%s(%s,",
                            PetraNamePool->getName(idxcol->index_name),
                            SchemaName, TabInfo.table_name, idxcol->col_name);
                    }
                    if (idxcol->status) {
                        if (TabInfo.enc_type == 0) {
                            sprintf(tmp_sql.enc1,
                                    "create unique index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.renamed_tab_name,
                                    idxcol->renamed_col_name);
                        } else {
                            sprintf(tmp_sql.enc1,
                                    "create unique index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.table_name,
                                    idxcol->renamed_col_name);
                        }
                    } else {
                        if (TabInfo.enc_type == 0) {
                            sprintf(tmp_sql.enc1,
                                    "create unique index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.renamed_tab_name,
                                    idxcol->col_name);
                        } else {
                            sprintf(tmp_sql.enc1,
                                    "create unique index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.table_name,
                                    idxcol->col_name);
                        }
                    }
                } else {
                    if (TabInfo.enc_type == 0) {
                        sprintf(tmp_sql.org1, "create index %s on %s.%s(%s,",
                                PetraNamePool->getName(idxcol->index_name),
                                SchemaName, TabInfo.renamed_tab_name,
                                idxcol->col_name);
                    } else {
                        sprintf(tmp_sql.org1, "create index %s on %s.%s(%s,",
                                PetraNamePool->getName(idxcol->index_name),
                                SchemaName, TabInfo.table_name,
                                idxcol->col_name);
                    }
                    if (idxcol->status) {
                        if (TabInfo.enc_type == 0) {
                            sprintf(tmp_sql.enc1,
                                    "create index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.renamed_tab_name,
                                    idxcol->renamed_col_name);
                        } else {
                            sprintf(tmp_sql.enc1,
                                    "create index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.table_name,
                                    idxcol->renamed_col_name);
                        }
                    } else {
                        if (TabInfo.enc_type == 0) {
                            sprintf(tmp_sql.enc1,
                                    "create index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.renamed_tab_name,
                                    idxcol->col_name);
                        } else {
                            sprintf(tmp_sql.enc1,
                                    "create index %s on %s.%s(%s,",
                                    PetraNamePool->getName(idxcol->index_name),
                                    SchemaName, TabInfo.table_name,
                                    idxcol->col_name);
                        }
                    }
                }
                if (TabInfo.enc_type == 0) {
                    sprintf(tmp_sql.org2, "alter table %s.%s drop index %s",
                            SchemaName, TabInfo.renamed_tab_name,
                            PetraNamePool->getName(idxcol->index_name));
                    sprintf(tmp_sql.enc2, "alter table %s.%s drop index %s",
                            SchemaName, TabInfo.renamed_tab_name,
                            PetraNamePool->getName(idxcol->index_name));
                } else {
                    sprintf(tmp_sql.org2, "alter table %s.%s drop index %s",
                            SchemaName, TabInfo.table_name,
                            PetraNamePool->getName(idxcol->index_name));
                    sprintf(tmp_sql.enc2, "alter table %s.%s drop index %s",
                            SchemaName, TabInfo.table_name,
                            PetraNamePool->getName(idxcol->index_name));
                }
            } else {
                strcat(tmp_sql.org1, idxcol->col_name);
                if (idxcol->status == 1) {
                    strcat(tmp_sql.enc1, idxcol->renamed_col_name);
                } else {
                    strcat(tmp_sql.enc1, idxcol->col_name);
                }
                strcat(tmp_sql.org1, ",");
                strcat(tmp_sql.enc1, ",");
            }
        }
        tmp_sql.org1[strlen(tmp_sql.org1) - 1] = ')';
        tmp_sql.enc1[strlen(tmp_sql.enc1) - 1] = ')';
        IdxSqlRows.add();
        IdxSqlRows.next();
        memcpy(IdxSqlRows.data(), &tmp_sql, sizeof(idxsql));
        DgcExcept* e = EXCEPTnC;
        if (e) {
            delete e;
        }
        delete idx_stmt;
    }
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
    delete sql_stmt;
    IdxSqlRows.rewind();

    return 1;
}

dgt_sint32 PccMyScriptBuilder::prepareCtInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    //
    // if IsPkFk =1 then pk,fk sql create
    //
    sprintf(sql_text,
            "select working_set_id "
            "from pct_working_set where enc_tab_id=%lld",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_sint64* working_set_id_tmp;
    dgt_sint64 working_set_id = 0;
    while ((working_set_id_tmp = (dgt_sint64*)sql_stmt->fetch())) {
        memcpy(&working_set_id, working_set_id_tmp, sizeof(dgt_sint64));
    }
    delete sql_stmt;
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    pc_type_pk_fk_sql pkfkSql;
    memset(&pkfkSql, 0, sizeof(pc_type_pk_fk_sql));
    FkSqlRows.reset();
    PkSqlRows.reset();

    //
    // pk sql create
    //
    sprintf(sql_text,
            "select distinct working_set_id,enc_tab_id "
            "from pct_working_set where working_set_id=%lld",
            working_set_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    typedef struct pc_type_working_set {
        dgt_sint64 working_set_id;
        dgt_sint64 enc_tab_id;
    } pc_type_working_set;
    pc_type_working_set* row_ptr;
    while ((row_ptr = (pc_type_working_set*)sql_stmt->fetch())) {
        memset(&pkfkSql, 0, sizeof(pc_type_pk_fk_sql));
        sprintf(sql_text,
                "select c.schema_name, c.table_name, c.renamed_tab_name, "
                "b.column_name, b.renamed_col_name, a.constraint_name, "
                "a.renamed_constraint_name, "
                "a.status, a.position, a.constraint_type, a.ref_pk_owner, "
                "a.ref_pk_table, a.ref_pk_column, c.org_renamed_tab_name, "
                "d.enc_type, d.keep_org_tab_flag, "
                "a.generated "
                "from ceea_enc_col_ct a, ceea_enc_column b, ceea_enc_table c, "
                "pct_enc_table d "
                "where a.enc_col_id = b.enc_col_id "
                "and   a.enc_tab_id = c.enc_tab_id "
                "and   c.enc_tab_id = d.enc_tab_id "
                "and   a.enc_tab_id=%lld "
                "and   (a.constraint_type=1 or a.constraint_type = 4) "
                "order by a.position",
                row_ptr->enc_tab_id);
        dgt_sint32 ispkfk_tab = 0;
        dgt_sint32 is_enc_column = 0;
        if (TabInfo.enc_tab_id == row_ptr->enc_tab_id) {
            ispkfk_tab = 1;
        }

        DgcSqlStmt* pk_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (pk_stmt == 0 || pk_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete pk_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        pc_type_pk_info* pk_row = 0;
        dgt_sint32 seq = 0;
        dgt_sint32 is_fetch = 0;
        while ((pk_row = (pc_type_pk_info*)pk_stmt->fetch())) {
            seq++;
            is_fetch = 1;
            if (pk_row->status == 1) {
                is_enc_column = 1;
            }
            if (seq == 1) {
                if (pk_row->enc_type == 0) {
                    if (pk_row->constraint_type == 1) {
                        if (ispkfk_tab) {
                            sprintf(
                                pkfkSql.org1,
                                "alter table %s.%s add constraint primary key(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->renamed_tab_name));
                            sprintf(
                                pkfkSql.enc1,
                                "alter table %s.%s add constraint primary key(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->renamed_tab_name));
                        } else {
                            if (IsPkFk) {
                                sprintf(pkfkSql.org1,
                                        "alter table %s.%s add constraint "
                                        "primary key(",
                                        PetraNamePool->getNameString(
                                            pk_row->schema_name),
                                        PetraNamePool->getNameString(
                                            pk_row->table_name));
                                sprintf(pkfkSql.enc1,
                                        "alter table %s.%s add constraint "
                                        "primary key(",
                                        PetraNamePool->getNameString(
                                            pk_row->schema_name),
                                        PetraNamePool->getNameString(
                                            pk_row->renamed_tab_name));
                            } else {
                                sprintf(pkfkSql.org1,
                                        "alter table %s.%s add constraint "
                                        "primary key(",
                                        PetraNamePool->getNameString(
                                            pk_row->schema_name),
                                        PetraNamePool->getNameString(
                                            pk_row->table_name));
                                sprintf(pkfkSql.enc1,
                                        "alter table %s.%s add constraint "
                                        "primary key(",
                                        PetraNamePool->getNameString(
                                            pk_row->schema_name),
                                        PetraNamePool->getNameString(
                                            pk_row->table_name));
                            }
                        }
                    } else {
                        if (ispkfk_tab) {
                            sprintf(
                                pkfkSql.org1,
                                "alter table %s.%s add constraint %s unique(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->renamed_tab_name),
                                PetraNamePool->getNameString(
                                    pk_row->constraint_name));
                            sprintf(
                                pkfkSql.enc1,
                                "alter table %s.%s add constraint %s unique(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->renamed_tab_name),
                                PetraNamePool->getNameString(
                                    pk_row->constraint_name));
                        } else {
                            sprintf(
                                pkfkSql.org1,
                                "alter table %s.%s add constraint %s unique(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->table_name),
                                PetraNamePool->getNameString(
                                    pk_row->constraint_name));
                            sprintf(
                                pkfkSql.enc1,
                                "alter table %s.%s add constraint %s unique(",
                                PetraNamePool->getNameString(
                                    pk_row->schema_name),
                                PetraNamePool->getNameString(
                                    pk_row->table_name),
                                PetraNamePool->getNameString(
                                    pk_row->constraint_name));
                        }
                    }
                } else {
                    if (pk_row->constraint_type == 1) {
                        sprintf(
                            pkfkSql.org1,
                            "alter table %s.%s add constraint primary key(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name));
                        sprintf(
                            pkfkSql.enc1,
                            "alter table %s.%s add constraint primary key(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name));
                    } else {
                        sprintf(
                            pkfkSql.org1,
                            "alter table %s.%s add constraint %s unique(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                        sprintf(
                            pkfkSql.enc1,
                            "alter table %s.%s add constraint %s unique(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                    }
                }
            }
            strcat(pkfkSql.org1,
                   PetraNamePool->getNameString(pk_row->column_name));
            strcat(pkfkSql.org1, ",");
            if (pk_row->status == 1) {
                strcat(pkfkSql.enc1,
                       PetraNamePool->getNameString(pk_row->renamed_col_name));
            } else {
                strcat(pkfkSql.enc1,
                       PetraNamePool->getNameString(pk_row->column_name));
            }
            strcat(pkfkSql.enc1, ",");

            if (ispkfk_tab) {
                if (pk_row->enc_type == 0) {
                    if (pk_row->constraint_type == 1) {
                        sprintf(
                            pkfkSql.org2, "alter table %s.%s drop primary key",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(
                                pk_row->renamed_tab_name));
                    } else {
                        sprintf(
                            pkfkSql.org2, "alter table %s.%s drop index %s",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(
                                pk_row->renamed_tab_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                    }
                } else {
                    if (pk_row->constraint_type == 1) {
                        sprintf(
                            pkfkSql.org2, "alter table %s.%s drop primary key",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name));
                    } else {
                        sprintf(
                            pkfkSql.org2, "alter table %s.%s drop index %s",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                    }
                }
            } else {
                if (pk_row->constraint_type == 1) {
                    sprintf(pkfkSql.org2, "alter table %s.%s drop primary key",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name));
                } else {
                    sprintf(
                        pkfkSql.org2, "alter table %s.%s drop index %s",
                        PetraNamePool->getNameString(pk_row->schema_name),
                        PetraNamePool->getNameString(pk_row->table_name),
                        PetraNamePool->getNameString(pk_row->constraint_name));
                }
            }
            if (TabInfo.enc_type == 0) {
                if (pk_row->constraint_type == 1) {
                    sprintf(
                        pkfkSql.enc2, "alter table %s.%s drop primary key",
                        PetraNamePool->getNameString(pk_row->schema_name),
                        PetraNamePool->getNameString(pk_row->renamed_tab_name));
                } else {
                    sprintf(
                        pkfkSql.enc2, "alter table %s.%s drop index %s",
                        PetraNamePool->getNameString(pk_row->schema_name),
                        PetraNamePool->getNameString(pk_row->renamed_tab_name),
                        PetraNamePool->getNameString(pk_row->constraint_name));
                }
            } else {
                if (pk_row->constraint_type == 1) {
                    sprintf(pkfkSql.enc2, "alter table %s.%s drop primary key",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name));
                } else {
                    sprintf(
                        pkfkSql.enc2, "alter table %s.%s drop index %s",
                        PetraNamePool->getNameString(pk_row->schema_name),
                        PetraNamePool->getNameString(pk_row->table_name),
                        PetraNamePool->getNameString(pk_row->constraint_name));
                }
            }
        }
        if (is_fetch && is_enc_column) {
            pkfkSql.org1[strlen(pkfkSql.org1) - 1] = ')';
            pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = ')';
            PkSqlRows.add();
            PkSqlRows.next();
            memcpy(PkSqlRows.data(), &pkfkSql, sizeof(pc_type_pk_fk_sql));
        }
        memset(&pkfkSql, 0, sizeof(pc_type_pk_fk_sql));
        sprintf(sql_text,
                "select distinct constraint_name "
                "from ceea_enc_col_ct "
                "where enc_tab_id = %lld "
                "and   status = 1 "
                "and   constraint_type=2 ",
                row_ptr->enc_tab_id);
        DgcSqlStmt* fk_sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (fk_sql_stmt == 0 || fk_sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete fk_sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        dgt_sint64* constraint_name_tmp = 0;
        dgt_sint64 constraint_name = 0;
        while ((constraint_name_tmp = (dgt_sint64*)fk_sql_stmt->fetch())) {
            memcpy(&constraint_name, constraint_name_tmp, sizeof(dgt_sint64));
            sprintf(sql_text,
                    "select c.schema_name, c.table_name, c.renamed_tab_name, "
                    "b.column_name, b.renamed_col_name, a.constraint_name, "
                    "a.renamed_constraint_name, a.status, a.position, "
                    "a.constraint_type, "
                    "a.ref_pk_owner, a.ref_pk_table, a.ref_pk_column, "
                    "c.org_renamed_tab_name, d.enc_type, d.keep_org_tab_flag, "
                    "a.generated "
                    "from ceea_enc_col_ct a, ceea_enc_column b, ceea_enc_table "
                    "c, pct_enc_table d "
                    "where a.enc_col_id = b.enc_col_id "
                    "and   a.enc_tab_id = c.enc_tab_id "
                    "and   c.enc_tab_id = d.enc_tab_id "
                    "and   a.enc_tab_id=%lld "
                    "and   a.constraint_name=%lld "
                    "order by a.position",
                    row_ptr->enc_tab_id, constraint_name);
            DgcSqlStmt* fk_stmt =
                Database->getStmt(Session, sql_text, strlen(sql_text));
            if (fk_stmt == 0 || fk_stmt->execute() < 0) {
                DgcExcept* e = EXCEPTnC;
                delete fk_stmt;
                RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
            }
            dgt_sint32 seq = 0;
            pc_type_pk_info* fk_row = 0;
            DgcMemRows pkrows(6);
            pkrows.addAttr(DGC_SB8, 0, "enc_tab_id");
            pkrows.addAttr(DGC_SCHR, 130, "OWNER");
            pkrows.addAttr(DGC_SCHR, 130, "TABLE");
            pkrows.addAttr(DGC_SCHR, 130, "COLUMNE");
            pkrows.addAttr(DGC_SCHR, 130, "rename_table");
            pkrows.addAttr(DGC_SCHR, 130, "rename_column");
            pkrows.addAttr(DGC_UB1, 0, "status");
            pkrows.reset();
            typedef struct {
                dgt_sint64 enc_tab_id;
                dgt_schar owner[130];
                dgt_schar table[130];
                dgt_schar column[130];
                dgt_schar renamed_table[130];
                dgt_schar renamed_column[130];
                dgt_uint8 status;
            } pk_tmp;
            pk_tmp pktmp;
            memset(&pktmp, 0, sizeof(pk_tmp));
            while ((fk_row = (pc_type_pk_info*)fk_stmt->fetch())) {
                seq++;
                if (seq == 1) {
                    if (fk_row->enc_type == 0) {
                        if (ispkfk_tab) {
                            sprintf(pkfkSql.org1,
                                    "alter table %s.%s add constraint %s "
                                    "foreign key(",
                                    PetraNamePool->getNameString(
                                        fk_row->schema_name),
                                    PetraNamePool->getNameString(
                                        fk_row->renamed_tab_name),
                                    PetraNamePool->getNameString(
                                        fk_row->constraint_name));
                            sprintf(pkfkSql.enc1,
                                    "alter table %s.%s add constraint %s "
                                    "foreign key(",
                                    PetraNamePool->getNameString(
                                        fk_row->schema_name),
                                    PetraNamePool->getNameString(
                                        fk_row->renamed_tab_name),
                                    PetraNamePool->getNameString(
                                        fk_row->constraint_name));
                        } else {
                            sprintf(pkfkSql.org1,
                                    "alter table %s.%s add constraint %s "
                                    "foreign key(",
                                    PetraNamePool->getNameString(
                                        fk_row->schema_name),
                                    PetraNamePool->getNameString(
                                        fk_row->table_name),
                                    PetraNamePool->getNameString(
                                        fk_row->constraint_name));
                            sprintf(pkfkSql.enc1,
                                    "alter table %s.%s add constraint %s "
                                    "foreign key(",
                                    PetraNamePool->getNameString(
                                        fk_row->schema_name),
                                    PetraNamePool->getNameString(
                                        fk_row->renamed_tab_name),
                                    PetraNamePool->getNameString(
                                        fk_row->constraint_name));
                        }
                    } else {
                        sprintf(
                            pkfkSql.org1,
                            "alter table %s.%s add constraint %s foreign key(",
                            PetraNamePool->getNameString(fk_row->schema_name),
                            PetraNamePool->getNameString(fk_row->table_name),
                            PetraNamePool->getNameString(
                                fk_row->constraint_name));
                        sprintf(
                            pkfkSql.enc1,
                            "alter table %s.%s add constraint %s foreign key(",
                            PetraNamePool->getNameString(fk_row->schema_name),
                            PetraNamePool->getNameString(fk_row->table_name),
                            PetraNamePool->getNameString(
                                fk_row->constraint_name));
                    }
                }
                strcat(pkfkSql.org1,
                       PetraNamePool->getNameString(fk_row->column_name));
                strcat(pkfkSql.org1, ",");
                if (fk_row->status == 1) {
                    strcat(pkfkSql.enc1, PetraNamePool->getNameString(
                                             fk_row->renamed_col_name));
                } else {
                    strcat(pkfkSql.enc1,
                           PetraNamePool->getNameString(fk_row->column_name));
                }
                strcat(pkfkSql.enc1, ",");
                pkrows.add();
                pkrows.next();
                dgt_schar sqltext[2048];
                memset(sqltext, 0, 2048);
                sprintf(sqltext,
                        "select a.enc_tab_id, "
                        " c.schema_name, "
                        " b.table_name, "
                        " a.column_name, "
                        " b.renamed_tab_name, "
                        " a.renamed_col_name "
                        "from   pct_enc_column a, pct_enc_table b, "
                        "pct_enc_schema c "
                        "where  a.enc_tab_id = b.enc_tab_id "
                        "  and  b.schema_id = c.schema_id "
                        "and  c.db_id = %lld "
                        "and  c.schema_name = '%s' "
                        "and  b.table_name =  '%s'",
                        Dbid,
                        PetraNamePool->getNameString(fk_row->ref_pk_owner),
                        PetraNamePool->getNameString(fk_row->ref_pk_table));
                DgcSqlStmt* sqlstmt =
                    Database->getStmt(Session, sqltext, strlen(sqltext));
                if (sqlstmt == 0 || sqlstmt->execute() < 0) {
                    DgcExcept* e = EXCEPTnC;
                    delete sqlstmt;
                    RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
                }
                typedef struct {
                    dgt_sint64 enc_tab_id;
                    dgt_schar schema_name[33];
                    dgt_schar table_name[130];
                    dgt_schar column_name[130];
                    dgt_schar renamed_tab_name[130];
                    dgt_schar renamed_col_name[130];
                } ref_pk_row;
                ref_pk_row* tmp_ptr = 0;
                if ((tmp_ptr = (ref_pk_row*)sqlstmt->fetch())) {
                    pktmp.enc_tab_id = tmp_ptr->enc_tab_id;
                    sprintf(pktmp.owner, tmp_ptr->schema_name);
                    sprintf(pktmp.table, tmp_ptr->table_name);
                    sprintf(pktmp.column, tmp_ptr->column_name);
                    if (TabInfo.enc_type == 0) {
                        sprintf(pktmp.renamed_table, tmp_ptr->renamed_tab_name);
                    } else {
                        sprintf(pktmp.renamed_table, tmp_ptr->table_name);
                    }
                    sprintf(pktmp.renamed_column, tmp_ptr->renamed_col_name);
                } else {
                    sprintf(pktmp.owner,
                            PetraNamePool->getNameString(fk_row->ref_pk_owner));
                    sprintf(pktmp.table, "%s",
                            PetraNamePool->getNameString(fk_row->ref_pk_table));
                    sprintf(
                        pktmp.column, "%s",
                        PetraNamePool->getNameString(fk_row->ref_pk_column));
                    if (TabInfo.enc_type == 0) {
                        sprintf(
                            pktmp.renamed_table, "%s$$",
                            PetraNamePool->getNameString(fk_row->ref_pk_table));
                    } else {
                        sprintf(
                            pktmp.renamed_table, "%s",
                            PetraNamePool->getNameString(fk_row->ref_pk_table));
                    }
                    sprintf(
                        pktmp.renamed_column, "%s$$",
                        PetraNamePool->getNameString(fk_row->ref_pk_column));
                }
                DgcExcept* e = EXCEPTnC;
                delete sqlstmt;
                dgt_schar stext[512];
                sprintf(stext,
                        "select count() from ceea_enc_column "
                        "where db_id=%lld "
                        "and schema_name=%lld "
                        "and table_name=%lld "
                        "and status = 1 ",
                        Dbid, fk_row->ref_pk_owner, fk_row->ref_pk_table);
                DgcSqlStmt* s_stmt =
                    Database->getStmt(Session, stext, strlen(stext));
                if (s_stmt == 0 || s_stmt->execute() < 0) {
                    DgcExcept* e = EXCEPTnC;
                    delete s_stmt;
                    RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
                }
                dgt_sint64* cnt_tmp;
                if ((cnt_tmp = (dgt_sint64*)s_stmt->fetch())) {
                    if (*cnt_tmp > 0) pktmp.status = 1;
                }
                e = EXCEPTnC;
                delete s_stmt;
                memcpy(pkrows.data(), &pktmp, sizeof(pktmp));
            }
            delete fk_stmt;
            pkrows.rewind();
            if (strlen(pkfkSql.enc1) > 0 || strlen(pkfkSql.org1) > 0) {
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = 0;
                pkfkSql.org1[strlen(pkfkSql.org1) - 1] = 0;
                strcat(pkfkSql.enc1, ") references ");
                strcat(pkfkSql.org1, ") references ");
                pk_tmp* pk_ptr = 0;
                seq = 0;
                while (pkrows.next()) {
                    seq++;
                    pk_ptr = (pk_tmp*)pkrows.data();
                    if (seq == 1) {
                        dgt_schar tmpbuf[128];
                        memset(tmpbuf, 0, 128);
                        if (pk_ptr->enc_tab_id == TabInfo.enc_tab_id) {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->renamed_table, pk_ptr->column);
                        } else {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->table, pk_ptr->column);
                        }
                        strcat(pkfkSql.org1, tmpbuf);
                        memset(tmpbuf, 0, 128);
                        if (pk_ptr->status == 1) {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->renamed_table,
                                    pk_ptr->renamed_column);
                        } else {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->table, pk_ptr->column);
                        }
                        strcat(pkfkSql.enc1, tmpbuf);
                    } else {
                        strcat(pkfkSql.org1, pk_ptr->column);
                        strcat(pkfkSql.org1, ",");
                        if (pk_ptr->status == 1) {
                            strcat(pkfkSql.enc1, pk_ptr->renamed_column);
                            strcat(pkfkSql.enc1, ",");
                        } else {
                            strcat(pkfkSql.enc1, pk_ptr->column);
                            strcat(pkfkSql.enc1, ",");
                        }
                    }
                }
                pkfkSql.org1[strlen(pkfkSql.org1) - 1] = ')';
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = ')';
                FkSqlRows.add();
                FkSqlRows.next();
                memcpy(FkSqlRows.data(), &pkfkSql, sizeof(pc_type_pk_fk_sql));
            }
        }
        delete fk_sql_stmt;
        e = EXCEPTnC;
        if (e) {
            delete e;
        }
    }
    delete sql_stmt;
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
    PkSqlRows.rewind();
    FkSqlRows.rewind();
    return 1;
}

typedef struct {
    dgt_sint64 constraint_name;
    dgt_sint64 schema_name;
    dgt_sint64 table_name;
    dgt_sint64 column_name;
    dgt_sint64 renamed_tab_name;
    dgt_sint64 ref_owner;
    dgt_sint64 ref_table;
    dgt_sint64 ref_column;
    dgt_sint32 position;
} pc_type_def_fksql2;

dgt_sint32 PccMyScriptBuilder::prepareCt2Info() throw(DgcExcept) {
    DefFkDropSqlRows.reset();  // enc table`s dependeny foreign key(drop)
    //
    // FkSql (non enc pk column <- non enc fk column)
    //
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select distinct constraint_name "
            "from ceea_col_ct a, ceea_table b "
            "where a.enc_tab_id = b.enc_tab_id "
            "and   b.db_id = %lld "
            "and   ref_pk_owner = getnameid('%s') "
            "and   ref_pk_table = getnameid('%s') "
            "and   constraint_type = 2",
            Dbid, SchemaName, TabInfo.table_name);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_sint64* const_name = 0;
    DgcExcept* e = 0;
    while ((const_name = (dgt_sint64*)sql_stmt->fetch())) {
        //
        // if dependecy fk is encryption table then table_name
        //
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select constraint_name from ceea_enc_col_ct where "
                "constraint_name = %lld",
                *const_name);
        DgcSqlStmt* searchStmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (searchStmt == 0 || searchStmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            delete searchStmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        dgt_sint64* tmp_result;
        typedef struct {
            dgt_schar org1[512];
            dgt_schar org2[512];
            dgt_schar enc1[512];
            dgt_schar enc2[512];
            dgt_schar enc3[512];
            dgt_schar enc4[512];
        } def_fk_enc_table;
        def_fk_enc_table def_enc_sql;
        dgt_sint32 enc_tab_flag = 0;
        if ((tmp_result = (dgt_sint64*)searchStmt->fetch())) {
            enc_tab_flag = 1;
        }
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select constraint_name, a.schema_name, a.table_name, "
                "b.column_name, d.renamed_tab_name, c.ref_pk_owner, "
                "c.ref_pk_table, c.ref_pk_column, c.position "
                "from   ceea_table a, "
                "ceea_column b, "
                "ceea_col_ct c, "
                "ceea_enc_table d "
                "where a.enc_tab_id = b.enc_tab_id "
                "and   b.enc_col_id = c.enc_col_id "
                "and   a.db_id = %lld "
                "and   c.constraint_name = %lld "
                "and c.enc_tab_id = d.enc_tab_id "
                "order by c.position",
                Dbid, *const_name);
        DgcSqlStmt* fkStmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (fkStmt == 0 || fkStmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            delete fkStmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        pc_type_def_fksql2* def_fksql = 0;
        dgt_sint32 fetch = 0;
        while ((def_fksql = (pc_type_def_fksql2*)fkStmt->fetch())) {
            fetch = 1;
            if (enc_tab_flag) {
                memset(&def_enc_sql, 0, sizeof(def_fk_enc_table));
                sprintf(
                    def_enc_sql.enc4, "alter table %s.%s drop foreign key %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->renamed_tab_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(
                    def_enc_sql.enc3, "alter table %s.%s drop index %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->renamed_tab_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(
                    def_enc_sql.enc2, "alter table %s.%s drop foreign key %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(
                    def_enc_sql.enc1, "alter table %s.%s drop index %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                if (TabInfo.enc_type == 0) {
                    sprintf(
                        def_enc_sql.org2,
                        "alter table %s.%s$$ drop foreign key %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                    sprintf(
                        def_enc_sql.org1, "alter table %s.%s$$ drop index %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                } else {
                    sprintf(
                        def_enc_sql.org2,
                        "alter table %s.%s drop foreign key %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                    sprintf(
                        def_enc_sql.org1, "alter table %s.%s drop index %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                }
            }
        }
        if (fetch == 1) {
            if (enc_tab_flag) {
                DefFkDropSqlRows.add();
                DefFkDropSqlRows.next();
                memcpy(DefFkDropSqlRows.data(), &def_enc_sql,
                       sizeof(def_fk_enc_table));
            }
        }
        delete fkStmt;
        e = EXCEPTnC;
        if (e) {
            delete e;
        }
    }
    delete sql_stmt;
    e = EXCEPTnC;
    if (e) {
        delete e;
    }

    DefFkDropSqlRows.rewind();
    return 1;
}

PccMyScriptBuilder::PccMyScriptBuilder(DgcDatabase* db, DgcSession* sess,
                                       dgt_schar* schema_link)
    : PccScriptBuilder(db, sess, schema_link),
      PrivSqlRows(1),
      PrivSqlRows2(3),
      PkSqlRows(4),
      FkSqlRows(4),
      IdxSqlRows(4),
      IdxColRows(1),
      DefFkDropSqlRows(6) {
    PrivSqlRows.addAttr(DGC_SCHR, 1024, "sql_text");

    PrivSqlRows2.addAttr(DGC_SCHR, 1024, "sql_text");
    PrivSqlRows2.addAttr(DGC_SCHR, 1024, "sql_text");
    PrivSqlRows2.addAttr(DGC_SCHR, 1024, "sql_text");

    PkSqlRows.addAttr(DGC_SCHR, 512, "org1");
    PkSqlRows.addAttr(DGC_SCHR, 512, "org2");
    PkSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    PkSqlRows.addAttr(DGC_SCHR, 512, "enc2");

    FkSqlRows.addAttr(DGC_SCHR, 512, "org1");
    FkSqlRows.addAttr(DGC_SCHR, 512, "org2");
    FkSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    FkSqlRows.addAttr(DGC_SCHR, 512, "enc2");

    IdxSqlRows.addAttr(DGC_SCHR, 512, "org1");
    IdxSqlRows.addAttr(DGC_SCHR, 512, "org2");
    IdxSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    IdxSqlRows.addAttr(DGC_SCHR, 512, "enc2");

    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "org1");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "org2");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc2");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc3");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc4");

    IdxColRows.addAttr(DGC_SCHR, 130, "col_name");
}

PccMyScriptBuilder::~PccMyScriptBuilder() {}

dgt_schar* PccMyScriptBuilder::getFname(dgt_sint64 enc_col_id,
                                        dgt_uint8 fun_type) throw(DgcExcept) {
    memset(Fname, 0, 256);
    ColInfoRows2.rewind();
    pc_type_col_info* col_info;
    //
    // fun_type : 1=encrypt function name
    //            2=decrypt function name
    //
    if (fun_type == 1) {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            if (col_info->enc_col_id == enc_col_id) {
                sprintf(Fname, "petra.pls_encrypt_b64(ifnull(%s,''),%lld)",
                        col_info->col_name, col_info->enc_col_id);
            }
        }
    } else if (fun_type == 2) {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            if (col_info->enc_col_id == enc_col_id) {
                if (TabInfo.cast_flag == 0) {
                    sprintf(Fname, "petra.pls_decrypt_b64(%s,%lld)",
                            col_info->renamed_col_name, col_info->enc_col_id);
                } else {
                    if (!strcasecmp(col_info->data_type, "date") ||
                        !strcasecmp(col_info->data_type, "datetime") ||
                        !strcasecmp(col_info->data_type, "time") ||
                        !strcasecmp(col_info->data_type, "timestamp")) {
                        sprintf(Fname,
                                "cast(petra.pls_decrypt_b64(%s,%lld) as date)",
                                col_info->renamed_col_name,
                                col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "smallint") ||
                               !strcasecmp(col_info->data_type, "int") ||
                               !strcasecmp(col_info->data_type, "tinyint") ||
                               !strcasecmp(col_info->data_type, "bigint") ||
                               !strcasecmp(col_info->data_type, "mediumint")) {
                        sprintf(
                            Fname,
                            "cast(petra.pls_decrypt_b64(%s,%lld) as SIGNED)",
                            col_info->renamed_col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "decimal") ||
                               !strcasecmp(col_info->data_type, "float") ||
                               !strcasecmp(col_info->data_type,
                                           "hexadecimal") ||
                               !strcasecmp(col_info->data_type, "double")) {
                        sprintf(
                            Fname,
                            "cast(petra.pls_decrypt_b64(%s,%lld) as DECIMAL)",
                            col_info->renamed_col_name, col_info->enc_col_id);
                    } else {
                        sprintf(
                            Fname,
                            "cast(petra.pls_decrypt_b64(%s,%lld) as char(%d))",
                            col_info->renamed_col_name, col_info->enc_col_id,
                            col_info->data_length);
                    }
                }
            }
        }
    }
    return Fname;
}

DgcCliConnection* PccMyScriptBuilder::connect(dgt_schar* uid,
                                              dgt_schar* pw) throw(DgcExcept) {
    DgcLinkInfo dblink(Database->pdb());
    pt_database_link_info* link_info = dblink.getDatabaseLinkInfo(SchemaLink);
    if (!link_info) {
        ATHROWnR(DgcError(SPOS, "getDatabaseLinkInfo failed"), 0);
    }
    if (!uid || *uid == 0) uid = link_info->user_name;
    if (!pw || *pw == 0) pw = link_info->passwd;
    DgcMysqlConnection* conn = new DgcMysqlConnection();
    dgt_schar port[6];
    memset(port, 0, 6);
    sprintf(port, "%d", link_info->port);
    if (conn->connect(port, link_info->host, uid, pw, link_info->db_name) !=
        0) {
        DgcExcept* e = EXCEPTnC;
        delete conn;
        RTHROWnR(e, DgcError(SPOS, "connect failed."), 0);
    }
    return conn;
}

dgt_sint32 PccMyScriptBuilder::buildScript(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    //
    // enc_type = 0 (view)
    // enc_type = 1 (non view)
    //
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (preparePrivInfo() < 0)
        ATHROWnR(DgcError(SPOS, "preparePrivInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCtInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCtInfo failed."), -1);

    //
    // for new table encryption mode (get Constraints)
    //
    if (prepareCt2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCt2Info failed."), -1);
    if (step1() < 0) ATHROWnR(DgcError(SPOS, "step1 failed."), -1);
    if (step2() < 0) ATHROWnR(DgcError(SPOS, "step2 failed."), -1);
    if (reverse_step1() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step1 failed."), -1);
    if (reverse_step2() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step2 failed."), -1);
    return 0;
}
