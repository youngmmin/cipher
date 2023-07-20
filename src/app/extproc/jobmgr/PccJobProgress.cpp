/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccJobProgress
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 5. 6
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccJobProgress.h"

#include "DgcSqlHandle.h"
#include "PccTableTypes.h"

PccJobProgress::PccJobProgress(const dgt_schar* name) : DgcExtProcedure(name) {
    DatabaseLink = 0;
}

PccJobProgress::~PccJobProgress() {
    if (DatabaseLink) delete DatabaseLink;
}

DgcExtProcedure* PccJobProgress::clone() {
    return new PccJobProgress(procName());
}

typedef struct {
    dgt_schar db_link[33];
    dgt_schar owner[33];
} pc_type_conn_info;

dgt_sint32 PccJobProgress::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64 job_id = *(dgt_sint64*)BindRows->data();
    pct_type_job_progress_result progress_result;
    dg_memset(&progress_result, 0, sizeof(pct_type_job_progress_result));

    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    DgcSqlHandle SqlHandle(Session);
    dgt_schar* sel_str = 0;
    sel_str = new dgt_schar[512];
    *sel_str = 0;
    dg_sprintf(sel_str,
               "select j.curr_enc_step, "
               "j.curr_enc_stmt, "
               "j.curr_status, "
               "j.total_rows, "
               "t.enc_tab_id, "
               "t.init_enc_type "
               "from pct_job j, pct_enc_table t "
               "where j.enc_tab_id=t.enc_tab_id "
               "and j.job_id=%lld ",
               job_id);
    if (SqlHandle.execute(sel_str) < 0) {
        if (sel_str) delete sel_str;
        ATHROWnR(DgcError(SPOS, "SqlHandle execute failed."), -1);
    }
    if ((ret = SqlHandle.fetch(rtn_row)) < 0) {
        if (sel_str) delete sel_str;
        ATHROWnR(DgcError(SPOS, "SqlHandle fetch failed."), -1);
    }

    if (!rtn_row) {
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        *(ReturnRows->data()) = 0;
        progress_result.progress_status = -1;
        dg_sprintf(progress_result.remark, "job_id[%lld] not found.", job_id);
        dg_memcpy(ReturnRows->data(), &progress_result,
                  sizeof(pct_type_job_progress_result));
        ReturnRows->rewind();
        if (sel_str) delete sel_str;
        return 0;
    }

    pct_type_job_progress_curr_info* job_info =
        (pct_type_job_progress_curr_info*)rtn_row;
    if (!job_info->curr_status) {
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        *(ReturnRows->data()) = 0;
        progress_result.progress_status = -1;
        dg_sprintf(progress_result.remark,
                   "an encryption of job_id[%lld] not in progress.", job_id);
        dg_memcpy(ReturnRows->data(), &progress_result,
                  sizeof(pct_type_job_progress_result));
        ReturnRows->rewind();
        if (sel_str) delete sel_str;
        return 0;
    }
    dgt_uint8 init_enc_type = job_info->init_enc_type;
    progress_result.curr_enc_step = job_info->curr_enc_step;
    progress_result.curr_enc_stmt = job_info->curr_enc_stmt;
    progress_result.curr_status = job_info->curr_status;

    if (init_enc_type == 0) {
        //
        // encryption with a pcb_job
        //
        dgt_sint64 total_rows = 0;
        total_rows = job_info->total_rows;

        dg_memset(sel_str, 0, 512);
        rtn_row = 0;
        sprintf(sel_str,
                "select sum(processed_rows) "
                "from pct_job j, pct_worker w "
                "where j.job_id=w.job_id "
                "and j.process_id=w.process_id "
                "and w.assigned_role='updater' "
                "and j.job_id=%lld ",
                job_id);
        if (SqlHandle.execute(sel_str) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle execute failed."), -1);
        }
        if ((ret = SqlHandle.fetch(rtn_row)) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle fetch failed."), -1);
        }
        if (!rtn_row) {
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            *(ReturnRows->data()) = 0;
            progress_result.progress_status = -1;
            dg_sprintf(progress_result.remark, "a job_id[%lld] has no workers.",
                       job_id);
            dg_memcpy(ReturnRows->data(), &progress_result,
                      sizeof(pct_type_job_progress_result));
            ReturnRows->rewind();
            if (sel_str) delete sel_str;
            return 0;
        }
        dgt_sint64 processed_rows = *(dgt_sint64*)rtn_row;
        progress_result.progress_status = (dgt_float64)processed_rows /
                                          (dgt_float64)total_rows *
                                          (dgt_float64)100;

    } else if (init_enc_type == 1 || init_enc_type == 2) {
        //
        // encryption with a create table statement
        //
        dgt_sint64 enc_tab_id = job_info->enc_tab_id;
        dgt_sint64 org_table_size = 0;
        dgt_sint64 curr_table_size = 0;
        dgt_schar table_name[130];
        pct_type_enc_table enc_table;
        pc_type_conn_info con_info;
        memset(&con_info, 0, sizeof(pc_type_conn_info));

        // 1.get a dblink info and a schema
        dg_memset(sel_str, 0, 512);
        rtn_row = 0;
        sprintf(sel_str,
                "select c.admin_link, b.schema_name "
                " from pct_enc_table a, pct_enc_schema b, pct_db_agent c "
                " where a.enc_tab_id = %lld and a.schema_id = b.schema_id and "
                "b.db_id = c.db_id",
                enc_tab_id);
        if (SqlHandle.execute(sel_str) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle execute failed."), -1);
        }
        if ((ret = SqlHandle.fetch(rtn_row)) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle fetch failed."), -1);
        }
        if (!rtn_row) {
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            *(ReturnRows->data()) = 0;
            progress_result.progress_status = -1;
            dg_sprintf(progress_result.remark,
                       "no admin_link[%lld] in the table[PCT_DB_AGENT]",
                       enc_tab_id);
            dg_memcpy(ReturnRows->data(), &progress_result,
                      sizeof(pct_type_job_progress_result));
            ReturnRows->rewind();
            if (sel_str) delete sel_str;
            return 0;
        }
        memcpy(&con_info, (pc_type_conn_info*)rtn_row,
               sizeof(pc_type_conn_info));

        // 2.get a table info
        dg_memset(sel_str, 0, 512);
        rtn_row = 0;
        sprintf(sel_str, "select * from pct_enc_table where enc_tab_id=%lld ",
                enc_tab_id);

        if (SqlHandle.execute(sel_str) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle execute failed."), -1);
        }
        if ((ret = SqlHandle.fetch(rtn_row)) < 0) {
            if (sel_str) delete sel_str;
            ATHROWnR(DgcError(SPOS, "SqlHandle fetch failed."), -1);
        }
        if (!rtn_row) {
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            *(ReturnRows->data()) = 0;
            progress_result.progress_status = -1;
            dg_sprintf(progress_result.remark,
                       "no enc_tab_id[%lld] in the table[PCT_ENC_TABLE]",
                       enc_tab_id);
            dg_memcpy(ReturnRows->data(), &progress_result,
                      sizeof(pct_type_job_progress_result));
            ReturnRows->rewind();
            if (sel_str) delete sel_str;
            return 0;
        }
        dg_memcpy(&enc_table, rtn_row, sizeof(pct_type_enc_table));
        dg_strcpy(table_name, enc_table.renamed_tab_name);

        // 3.get current size of table
        if (DatabaseLink) delete DatabaseLink;
        DatabaseLink = new DgcDatabaseLink(con_info.db_link);

        switch (DatabaseLink->getDbType()) {
            case DGC_DB_TYPE_SOHA:
                if (sel_str) delete sel_str;
                THROWnR(DgcLdbExcept(
                            DGC_EC_LD_STMT_ERR,
                            new DgcError(SPOS,
                                         "[%s] db type is not in service yet.",
                                         con_info.db_link)),
                        -1);
                // Stmt = new CeeaSohaSqlStmt(DatabaseLink,TraceLevel);
                break;
            case DGC_DB_TYPE_ORACLE: {
                // get original table`s bytes
                dgt_schar* ora_str = 0;
                ora_str = new dgt_schar[256];
                *ora_str = 0;
                sprintf(ora_str,
                        "SELECT SUM(BYTES) BYTES "
                        "FROM DBA_SEGMENTS "
                        "WHERE OWNER='%s' "
                        "AND SEGMENT_NAME='%s' "
                        "AND SEGMENT_TYPE IN ('TABLE','TABLE "
                        "PARTITION','NESTED TABLE') "
                        "GROUP BY OWNER,SEGMENT_NAME ",
                        con_info.owner, enc_table.table_name);
                DgcCliStmt* ora_stmt = 0;
                ora_stmt = DatabaseLink->getStmt();
                if (!ora_stmt) {
                    if (sel_str) delete sel_str;
                    if (ora_str) delete ora_str;
                    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
                }
                if (ora_stmt->execute(ora_str, strlen(ora_str), 1) < 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (ora_stmt) delete ora_stmt;
                    if (sel_str) delete sel_str;
                    if (ora_str) delete ora_str;
                    RTHROWnR(e,
                             DgcError(SPOS, "execute[%*.*s] failed", 64, 64,
                                      ora_str),
                             -1);
                }
                DgcMemRows* rtn_rows = ora_stmt->returnRows();
                if (rtn_rows && rtn_rows->numRows() > 0) {
                    rtn_rows->rewind();
                    rtn_rows->next();
                    org_table_size =
                        dg_strtoll((dgt_schar*)rtn_rows->getColPtr(1), 0, 10);
                } else {
                    // no data found
                    progress_result.progress_status = -100;
                    dg_sprintf(progress_result.remark,
                               "no segment info[%s:%s] in oracle",
                               con_info.owner, enc_table.table_name);
                }
                if (ora_stmt) delete ora_stmt;
                if (ora_str) delete ora_str;

                ora_str = 0;
                ora_str = new dgt_schar[256];
                *ora_str = 0;
                sprintf(ora_str,
                        "SELECT SUM(BYTES) BYTES "
                        "FROM DBA_SEGMENTS "
                        "WHERE OWNER='%s' "
                        "AND SEGMENT_NAME='%s' "
                        "AND SEGMENT_TYPE IN ('TABLE','TABLE "
                        "PARTITION','NESTED TABLE') "
                        "GROUP BY OWNER,SEGMENT_NAME ",
                        con_info.owner, table_name);

                ora_stmt = 0;
                ora_stmt = DatabaseLink->getStmt();
                if (!ora_stmt) {
                    if (sel_str) delete sel_str;
                    if (ora_str) delete ora_str;
                    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
                }
                if (ora_stmt->execute(ora_str, strlen(ora_str), 1) < 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (ora_stmt) delete ora_stmt;
                    if (sel_str) delete sel_str;
                    if (ora_str) delete ora_str;
                    RTHROWnR(e,
                             DgcError(SPOS, "execute[%*.*s] failed", 64, 64,
                                      ora_str),
                             -1);
                }
                rtn_rows = ora_stmt->returnRows();
                if (rtn_rows && rtn_rows->numRows() > 0) {
                    rtn_rows->rewind();
                    rtn_rows->next();
                    curr_table_size =
                        dg_strtoll((dgt_schar*)rtn_rows->getColPtr(1), 0, 10);
                    progress_result.progress_status =
                        (dgt_float64)curr_table_size /
                        (dgt_float64)org_table_size * (dgt_float64)100;
                } else {
                    // no data found
                    progress_result.progress_status = -100;
                    dg_sprintf(progress_result.remark,
                               "no segment info[%s:%s] in oracle",
                               con_info.owner, table_name);
                }
                if (ora_stmt) delete ora_stmt;
                if (ora_str) delete ora_str;
                break;
            }
            case DGC_DB_TYPE_TDS:
                if (sel_str) delete sel_str;
                THROWnR(DgcLdbExcept(
                            DGC_EC_LD_STMT_ERR,
                            new DgcError(SPOS,
                                         "[%s] db type is not in service yet.",
                                         con_info.db_link)),
                        -1);
                // Stmt = new CeeaTdsSqlStmt(DatabaseLink,TraceLevel);
                break;
            case DGC_DB_TYPE_DB2:
                if (sel_str) delete sel_str;
                THROWnR(DgcLdbExcept(
                            DGC_EC_LD_STMT_ERR,
                            new DgcError(SPOS,
                                         "[%s] db type is not in service yet.",
                                         con_info.db_link)),
                        -1);
                // Stmt = new CeeaDb2SqlStmt(DatabaseLink,TraceLevel);
                break;
            case DGC_DB_TYPE_MYSQL:
                if (sel_str) delete sel_str;
                THROWnR(DgcLdbExcept(
                            DGC_EC_LD_STMT_ERR,
                            new DgcError(SPOS,
                                         "[%s] db type is not in service yet.",
                                         con_info.db_link)),
                        -1);
                // Stmt = new CeeaMysqlSqlStmt(DatabaseLink,TraceLevel);
                break;
            default:
                if (sel_str) delete sel_str;
                THROWnR(
                    DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "[%s] db type is invaild.",
                                              con_info.db_link)),
                    -1);
                break;
        }
    } else {
        //
        // invalid init_enc_type
        //
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        *(ReturnRows->data()) = 0;
        progress_result.progress_status = -10;
        dg_sprintf(progress_result.remark, "invalid init_enc_type[%d]",
                   init_enc_type);
        dg_memcpy(ReturnRows->data(), &progress_result,
                  sizeof(pct_type_job_progress_result));
        ReturnRows->rewind();
        if (sel_str) delete sel_str;
        return 0;
    }

    if (progress_result.curr_status == 20000)
        progress_result.progress_status = 100;
    // else if(progress_result.progress_status>100)
    // progress_result.progress_status=99.99;

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_memcpy(ReturnRows->data(), &progress_result,
              sizeof(pct_type_job_progress_result));
    ReturnRows->rewind();

    if (sel_str) delete sel_str;
    return 0;
}
