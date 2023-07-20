/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccSyncTable
 *   Implementor        :       mjkim
 *   Create Date        :       2018. 11. 06
 *   Description        :       sync tables
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PfccSyncTable.h"

#include "DgcMemRows.h"
#include "DgcSqlHandle.h"
#include "PcSyncIudLogInserter.h"

PfccSyncTable::PfccSyncTable(const dgt_schar* name) : DgcExtProcedure(name) {}

PfccSyncTable::~PfccSyncTable() {}

DgcExtProcedure* PfccSyncTable::clone() {
    return new PfccSyncTable(procName());
}

dgt_sint32 PfccSyncTable::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }

    param_in = (pfcc_sync_table_in*)BindRows->data();
    if (!param_in)
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);

    dgt_schar table[256] = {
        0,
    };
    for (dgt_uint32 i = 0; i < strlen(param_in->table_name); i++)
        table[i] = toupper(param_in->table_name[i]);

    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar sql_text[256] = {
        0,
    };
    dgt_void* rtn_row = 0;

    //
    // 1. find pfct_enc_job_id
    //
    DgcMemRows PkRows(1);
    PkRows.addAttr(DGC_SB8, 0, "ENC_JOB_ID");
    PkRows.reset();
    PkRows.add();
    PkRows.next();
    memcpy(PkRows.data(), &(param_in->artificial_id), sizeof(dgt_sint64));
    PkRows.rewind();

    DgcMemRows FkRows(1);
    FkRows.addAttr(DGC_SB8, 0, "ENC_JOB_ID");
    FkRows.reset();

    while (strcmp(table, "PFCT_ENC_JOB")) {
        // SCHEDULE_DATE_ID
        if (!strcmp(table, "PFCT_SCHEDULE_DATE")) {
            strcpy(table, "PFCT_ENC_JOB");
            sprintf(sql_text,
                    "select ENC_JOB_ID from PFCT_ENC_JOB where "
                    "SCHEDULE_DATE_ID = :1");
        } else if (!strcmp(table, "PFCT_WEEKLY_WORK_SCHEDULE")) {
            strcpy(table, "PFCT_SCHEDULE_DATE_ID");
            sprintf(sql_text,
                    "select SCHEDULE_DATE_ID from PFCT_WEEKLY_WORK_SCHEDULE "
                    "where WEEKLY_WORK_SCHEDULE_ID = :1");
        }
        // ENC_JOB_ID
        else if (!strcmp(table, "PFCT_ENC_JOB_TGT")) {
            strcpy(table, "PFCT_ENC_JOB");
            sprintf(sql_text,
                    "select ENC_JOB_ID from PFCT_ENC_JOB_TGT where "
                    "ENC_JOB_TGT_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_ZONE_DIR_RULE")) {
            strcpy(table, "PFCT_ENC_JOB_TGT");
            sprintf(sql_text,
                    "select ENC_JOB_TGT_ID from PFCT_ENC_ZONE_DIR_RULE where "
                    "DIR_RULE_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_ZONE_DIR_NAME_PTTN")) {
            strcpy(table, "PFCT_ENC_JOB_TGT");
            sprintf(sql_text,
                    "select ENC_JOB_TGT_ID from PFCT_ENC_ZONE_DIR_NAME_PTTN "
                    "where DIR_NAME_PTTN_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_ZONE_FILE_NAME_PTTN")) {
            strcpy(table, "PFCT_ENC_JOB_TGT");
            sprintf(sql_text,
                    "select ENC_JOB_TGT_ID from PFCT_ENC_ZONE_FILE_NAME_PTTN "
                    "where FILE_NAME_PTTN_ID = :1");
        }
        // ENC_ZONE_ID
        else if (!strcmp(table, "PFCT_ENC_ZONE")) {
            strcpy(table, "PFCT_ENC_JOB_TGT");
            sprintf(sql_text,
                    "select ENC_JOB_TGT_ID from PFCT_ENC_JOB_TGT where "
                    "ENC_ZONE_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_FIXED_FILE_FORMAT")) {
            strcpy(table, "PFCT_ENC_ZONE");
            sprintf(sql_text,
                    "select ENC_ZONE_ID from PFCT_ENC_FIXED_FILE_FORMAT where "
                    "FILE_FORMAT_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_DELI_FILE_FORMAT")) {
            strcpy(table, "PFCT_ENC_ZONE");
            sprintf(sql_text,
                    "select ENC_ZONE_ID from PFCT_ENC_DELI_FILE_FORMAT where "
                    "FILE_FORMAT_ID = :1");
        } else if (!strcmp(table, "PFCT_ENC_PTTN_FILE_FORMAT")) {
            strcpy(table, "PFCT_ENC_ZONE");
            sprintf(sql_text,
                    "select ENC_ZONE_ID from PFCT_ENC_PTTN_FILE_FORMAT where "
                    "FILE_FORMAT_ID = :1");
        }
        // COL_KEY_ID
        else if (!strcmp(table, "PFCT_ENC_ZONE_COL_KEY")) {
            strcpy(table, "PFCT_ENC_ZONE");
            sprintf(sql_text,
                    "select ENC_ZONE_ID from PFCT_ENC_ZONE_COL_KEY where "
                    "COL_KEY_ID = :1");
        } else if (!strcmp(table, "PFCT_PATTERN")) {
            strcpy(table, "PFCT_ENC_ZONE_COL_KEY");
            sprintf(sql_text,
                    "select COL_KEY_ID from PFCT_ENC_ZONE_COL_KEY where "
                    "PATTERN_ID = :1");
        } else if (!strcmp(table, "PFCT_PATTERN_EXPR")) {
            strcpy(table, "PFCT_PATTERN");
            sprintf(sql_text,
                    "select PATTERN_ID from PFCT_PATTERN_EXPR where "
                    "PATTERN_EXPR_ID = :1");
        }
        // NOT FOUND TABLE NAME
        else {
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "unsuported table name")),
                    -1);
        }

        // get foreign key
        FkRows.reset();
        if (sql_handle.execute(sql_text, 0, &PkRows) < 0)
            ATHROWnR(DgcError(SPOS, "execute failed"), -1);
        while (dgt_void* rtn_rows_ptr = sql_handle.fetch()) {
            FkRows.add();
            FkRows.next();
            memcpy(FkRows.data(), rtn_rows_ptr, sizeof(dgt_sint64));
        }
        if (EXCEPT) ATHROWnR(DgcError(SPOS, "fetch failed"), -1);
        FkRows.rewind();

        // set Primary key
        PkRows.reset();
        while (FkRows.next()) {
            PkRows.add();
            PkRows.next();
            memcpy(PkRows.data(), FkRows.data(), sizeof(dgt_sint64));
        }
        PkRows.rewind();
    }
    //
    // if delete_flag == 1, delete record
    //
    if (param_in->delete_flag == 1) {
        if (!strcmp(table, "PFCT_ENC_JOB")) {  // update status
            sprintf(sql_text,
                    "update PFCT_ENC_JOB set(STATUS, LAST_UPDATE)=(0, "
                    "nextLastUpdate('PFCT_ENC_JOB', %lld, %d)) where "
                    "ENC_JOB_ID = %lld",
                    param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_UPDATE,
                    param_in->artificial_id);
        } else if (!strcmp(table, "PFCT_SCHEDULE_DATE")) {
            sprintf(sql_text,
                    "delete PFCT_SCHEDULE_DATE where SCHEDULE_DATE_ID = %lld "
                    "and nextLastUpdate('PFCT_SCHEDULE_DATE', %lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_WEEKLY_WORK_SCHEDULE")) {
            sprintf(
                sql_text,
                "delete PFCT_WEEKLY_WORK_SCHEDULE where "
                "WEEKLY_WORK_SCHEDULE_ID = %lld and "
                "nextLastUpdate('PFCT_WEEKLY_WORK_SCHEDULE', %lld, %d) > 0 ",
                param_in->artificial_id, param_in->artificial_id,
                PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_JOB_TGT")) {  // update status
            sprintf(sql_text,
                    "update PFCT_ENC_JOB_TGT set(STATUS, LAST_UPDATE)=(0, "
                    "nextLastUpdate('PFCT_ENC_JOB_TGT', %lld, %d)) where "
                    "ENC_JOB_TGT_ID = %lld",
                    param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_UPDATE,
                    param_in->artificial_id);
        } else if (!strcmp(table, "PFCT_ENC_ZONE_DIR_RULE")) {
            sprintf(
                sql_text,
                "delete PFCT_ENC_ZONE_DIR_RULE where DIR_RULE_ID = %lld and "
                "nextLastUpdate('PFCT_ENC_ZONE_DIR_RULE', %lld, %d) > 0 ",
                param_in->artificial_id, param_in->artificial_id,
                PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_ZONE_DIR_NAME_PTTN")) {
            sprintf(sql_text,
                    "delete PFCT_ENC_ZONE_DIR_NAME_PTTN where DIR_NAME_PTTN_ID "
                    "= %lld and nextLastUpdate('PFCT_ENC_ZONE_DIR_NAME_PTTN', "
                    "%lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_ZONE_FILE_NAME_PTTN")) {
            sprintf(
                sql_text,
                "delete PFCT_ENC_ZONE_FILE_NAME_PTTN where FILE_NAME_PTTN_ID = "
                "%lld and nextLastUpdate('PFCT_ENC_ZONE_FILE_NAME_PTTN', %lld, "
                "%d) > 0 ",
                param_in->artificial_id, param_in->artificial_id,
                PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_ZONE")) {  // update delete_flag
            sprintf(sql_text,
                    "update PFCT_ENC_ZONE set(DELETE_FLAG, LAST_UPDATE)=(1, "
                    "nextLastUpdate('PFCT_ENC_ZONE', %lld, %d)) where "
                    "ENC_ZONE_ID = %lld",
                    param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_UPDATE,
                    param_in->artificial_id);
        } else if (!strcmp(table, "PFCT_ENC_FIXED_FILE_FORMAT")) {
            sprintf(sql_text,
                    "delete PFCT_ENC_FIXED_FILE_FORMAT where FILE_FORMAT_ID = "
                    "%lld and nextLastUpdate('PFCT_ENC_FIXED_FILE_FORMAT', "
                    "%lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_DELI_FILE_FORMAT")) {
            sprintf(sql_text,
                    "delete PFCT_ENC_DELI_FILE_FORMAT where FILE_FORMAT_ID = "
                    "%lld and nextLastUpdate('PFCT_ENC_DELI_FILE_FORMAT', "
                    "%lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_PTTN_FILE_FORMAT")) {
            sprintf(sql_text,
                    "delete PFCT_ENC_PTTN_FILE_FORMAT where FILE_FORMAT_ID = "
                    "%lld and nextLastUpdate('PFCT_ENC_PTTN_FILE_FORMAT', "
                    "%lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_ENC_ZONE_COL_KEY")) {
            sprintf(sql_text,
                    "delete PFCT_ENC_ZONE_COL_KEY where COL_KEY_ID = %lld and "
                    "nextLastUpdate('PFCT_ENC_ZONE_COL_KEY', %lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_PATTERN")) {
            sprintf(sql_text,
                    "delete PFCT_PATTERN where PATTERN_ID = %lld and "
                    "nextLastUpdate('PFCT_PATTERN', %lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else if (!strcmp(table, "PFCT_PATTERN_EXPR")) {
            sprintf(sql_text,
                    "delete PFCT_PATTERN_EXPR where PATTERN_EXPR_ID = %lld and "
                    "nextLastUpdate('PFCT_PATTERN_EXPR', %lld, %d) > 0 ",
                    param_in->artificial_id, param_in->artificial_id,
                    PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_DELETE);
        } else {
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "unsuported table name")),
                    -1);
        }
        if (sql_handle.execute(sql_text) < 0)
            ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    }

    //
    // 2. set last_update
    //
    sprintf(
        sql_text,
        "update PFCT_ENC_JOB set(LAST_UPDATE)=(nextLastUpdate('PFCT_ENC_JOB', "
        ":1, %d)) where ENC_JOB_ID = :1",
        PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_UPDATE);
    if (sql_handle.execute(sql_text, 0, &PkRows) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    PkRows.rewind();

    //
    // 3. get enc_job_id, agent_last_update
    //
    sprintf(sql_text,
            "select ENC_JOB_ID, AGENT_LAST_UPDATE from PFCT_ENC_JOB where "
            "ENC_JOB_ID = :1");
    if (sql_handle.execute(sql_text, 0, &PkRows) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    PkRows.rewind();

    ReturnRows->reset();
    while (dgt_void* rtn_rows_ptr = sql_handle.fetch()) {
        ReturnRows->add();
        ReturnRows->next();
        memcpy(ReturnRows->data(), (pfcc_sync_table_out*)rtn_rows_ptr,
               sizeof(pfcc_sync_table_out));
    }
    if (EXCEPT) ATHROWnR(DgcError(SPOS, "fetch failed"), -1);

    ReturnRows->rewind();
    return 0;
}
