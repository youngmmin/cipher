/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccProcSessSqlText
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 3. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccProcSessSqlText.h"

#include "PccTableTypes.h"

PccProcSessSqlText::PccProcSessSqlText(const dgt_schar* name)
    : DgcExtProcedure(name) {
    DatabaseLink = 0;
}

PccProcSessSqlText::~PccProcSessSqlText() {
    if (DatabaseLink) delete DatabaseLink;
}

DgcExtProcedure* PccProcSessSqlText::clone() {
    return new PccProcSessSqlText(procName());
}

dgt_sint32 PccProcSessSqlText::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pct_sess_sql_text_param* param = (pct_sess_sql_text_param*)BindRows->data();

    if (DatabaseLink) delete DatabaseLink;
    DatabaseLink = new DgcDatabaseLink(param->dblink_name);

    // printf("sid[%lld], serial#[%lld]\n",param->sid,param->serial_no);
    dgt_schar sel_str[1024] = {
        0,
    };

    switch (DatabaseLink->getDbType()) {
        case DGC_DB_TYPE_SOHA:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 param->dblink_name)),
                -1);
            // Stmt = new CeeaSohaSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_ORACLE:
            sprintf(sel_str,
                    "SELECT /*+ ordered */sql_text, "
                    "piece "
                    "FROM v$session s, "
                    "v$sqltext_with_newlines t "
                    "WHERE s.sid = %lld "
                    "AND s.serial# = %lld "
                    "AND s.sql_address = t.address "
                    "AND s.sql_hash_value = t.hash_value "
                    "AND s.sql_hash_value <> 0 "
                    "UNION ALL "
                    "SELECT /*+ ordered */sql_text, "
                    "piece "
                    "FROM v$session s, "
                    "v$sqltext_with_newlines t "
                    "WHERE s.sid = %lld "
                    "AND s.serial# = %lld "
                    "AND s.prev_sql_addr = t.address "
                    "AND s.prev_hash_value = t.hash_value "
                    "AND s.sql_hash_value = 0 "
                    "ORDER BY piece",
                    param->sid, param->serial_no, param->sid, param->serial_no);
            break;
        case DGC_DB_TYPE_TDS:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 param->dblink_name)),
                -1);
            // Stmt = new CeeaTdsSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_DB2:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 param->dblink_name)),
                -1);
            // Stmt = new CeeaDb2SqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_MYSQL:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 param->dblink_name)),
                -1);
            // Stmt = new CeeaMysqlSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_TIBERO:
            sprintf(sel_str,
                    "select sql_text, piece "
                    "from   v$session s, v$sqltext_with_newlines t "
                    "where  s.sql_id = t.sql_id "
                    "and    s.sid=%lld "
                    "order by piece",
                    param->sid);
            break;
        default:
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "[%s] db type is invaild.",
                                              param->dblink_name)),
                    -1);
            break;
    }
    DgcCliStmt* sql_stmt = 0;
    sql_stmt = DatabaseLink->getStmt();
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }

    if (sql_stmt->execute(sel_str, strlen(sel_str), 1000) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute[%*.*s] failed", 64, 64, sel_str),
                 -1);
    }

    pct_type_sess_sql_text sess_sql_text_info;
    DgcMemRows* rtn_rows = sql_stmt->returnRows();
    while (rtn_rows && rtn_rows->numRows() > 0) {
        rtn_rows->rewind();
        ReturnRows->reset();
        while (rtn_rows->next()) {
            dg_memset(&sess_sql_text_info, 0, sizeof(pct_type_sess_sql_text));
            dgt_schar* tmp = 0;
            dgt_uint16 tmp_len = 0;
            tmp = (dgt_schar*)rtn_rows->getColPtr(1);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_sql_text_info.sql_text, tmp,
                           tmp_len > 64 ? 64 : tmp_len);
            sess_sql_text_info.piece =
                dg_strtoll((dgt_schar*)rtn_rows->getColPtr(2), 0, 10);

            ReturnRows->add();
            ReturnRows->next();
            dg_memcpy(ReturnRows->data(), &sess_sql_text_info,
                      sizeof(pct_type_sess_sql_text));
        }
        ReturnRows->rewind();
        rtn_rows->reset();
    }

    if (sql_stmt) delete sql_stmt;
    return 0;
}
