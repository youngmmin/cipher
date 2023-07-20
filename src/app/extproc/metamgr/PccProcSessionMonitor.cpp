/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccProcSessionMonitor
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 3. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccProcSessionMonitor.h"

#include "PccTableTypes.h"

PccProcSessionMonitor::PccProcSessionMonitor(const dgt_schar* name)
    : DgcExtProcedure(name) {
    DatabaseLink = 0;
}

PccProcSessionMonitor::~PccProcSessionMonitor() {
    if (DatabaseLink) delete DatabaseLink;
}

DgcExtProcedure* PccProcSessionMonitor::clone() {
    return new PccProcSessionMonitor(procName());
}

dgt_sint32 PccProcSessionMonitor::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_schar* dblink_name = (dgt_schar*)BindRows->data();
    if (DatabaseLink) delete DatabaseLink;
    DatabaseLink = new DgcDatabaseLink(dblink_name);

    dgt_schar sel_str[2048] = {
        0,
    };

    switch (DatabaseLink->getDbType()) {
        case DGC_DB_TYPE_SOHA:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 dblink_name)),
                -1);
            // Stmt = new CeeaSohaSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_ORACLE:
            sprintf(sel_str,
                    "SELECT SS.* FROM ("
                    "SELECT /*+ use_hash(s t) */nvl(s.username, decode(s.type, "
                    "'USER', decode(bgp.name, NULL,'UNDEFINED '))) username, "
                    "s.sid, "
                    "s.serial#, "
                    "s.paddr, "
                    "s.osuser, "
                    "act.name sql_type, "
                    "s.status, "
                    "decode(s.event, 'latch free', s.event || ' (' || l.name "
                    "|| ')', s.event) event, "
                    "s.machine, "
                    "s.module, "
                    "s.action, "
                    "s.program, "
                    "s.logon_time, "
                    "t.v1 session_logical_read "
                    "FROM v$session s, "
                    "( SELECT /*+ ORDERED USE_NL(n s) */st.sid, "
                    "NVL(SUM(decode(st.statistic#, 9, st.value)), 0) v1 "
                    "FROM v$statname n, "
                    "v$sesstat st "
                    "WHERE n.statistic# = st.statistic# "
                    "AND n.statistic# IN (9) "
                    "GROUP BY sid ) t, "
                    "sys.audit_actions act, "
                    "sys.v_$bgprocess bgp, "
                    "sys.v_$latchname l "
                    "WHERE s.sid = t.sid(+) "
                    "AND s.command = act.action(+) "
                    "AND s.paddr = bgp.paddr(+) "
                    "AND s.p2 = l.latch#(+) "
                    ") SS "
                    "WHERE SS.USERNAME IS NOT NULL ");
            break;
        case DGC_DB_TYPE_TDS:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 dblink_name)),
                -1);
            // Stmt = new CeeaTdsSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_DB2:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 dblink_name)),
                -1);
            // Stmt = new CeeaDb2SqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_MYSQL:
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "[%s] db type is not in service yet.",
                                 dblink_name)),
                -1);
            // Stmt = new CeeaMysqlSqlStmt(DatabaseLink,TraceLevel);
            break;
        case DGC_DB_TYPE_TIBERO:
            sprintf(sel_str,
                    "select schemaname, "
                    " sid, "
                    " serial#, "
                    " ipaddr, "
                    " osuser, "
                    " decode(command,1,'SELECT',2,'INSERT',3,'UPDATE',4,'"
                    "DELETE','CALL'), "
                    " status, "
                    " state, "
                    " machine, "
                    " module, "
                    " action, "
                    " prog_name, "
                    " logon_time, "
                    " 0 "
                    "from v$session ");
            break;

        default:
            THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                 new DgcError(SPOS, "[%s] db type is invaild.",
                                              dblink_name)),
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

    pct_type_session_monitor sess_mon_info;
    DgcMemRows* rtn_rows = sql_stmt->returnRows();
    while (rtn_rows && rtn_rows->numRows() > 0) {
        rtn_rows->rewind();
        ReturnRows->reset();
        while (rtn_rows->next()) {
            dg_memset(&sess_mon_info, 0, sizeof(pct_type_session_monitor));
            dgt_schar* tmp = 0;
            dgt_uint16 tmp_len = 0;
            tmp = (dgt_schar*)rtn_rows->getColPtr(1);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.username, tmp,
                           tmp_len > 33 ? 33 : tmp_len);
            sess_mon_info.sid =
                dg_strtoll((dgt_schar*)rtn_rows->getColPtr(2), 0, 10);
            sess_mon_info.serial_no =
                dg_strtoll((dgt_schar*)rtn_rows->getColPtr(3), 0, 10);
            tmp = (dgt_schar*)rtn_rows->getColPtr(4);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.paddr, tmp,
                           tmp_len > 33 ? 33 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(5);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.osuser, tmp,
                           tmp_len > 33 ? 33 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(6);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.sql_type, tmp,
                           tmp_len > 10 ? 10 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(7);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.status, tmp,
                           tmp_len > 20 ? 20 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(8);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.sess_event, tmp,
                           tmp_len > 100 ? 100 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(9);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.machine, tmp,
                           tmp_len > 50 ? 50 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(10);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.module, tmp,
                           tmp_len > 50 ? 50 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(11);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.action, tmp,
                           tmp_len > 30 ? 30 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(12);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.program, tmp,
                           tmp_len > 50 ? 50 : tmp_len);
            tmp = (dgt_schar*)rtn_rows->getColPtr(13);
            tmp_len = dg_strlen(tmp);
            if (tmp_len > 0)
                dg_strncpy(sess_mon_info.logon_time, tmp,
                           tmp_len > 30 ? 30 : tmp_len);
            sess_mon_info.session_logical_read =
                dg_strtoll((dgt_schar*)rtn_rows->getColPtr(14), 0, 10);

            ReturnRows->add();
            ReturnRows->next();
            dg_memcpy(ReturnRows->data(), &sess_mon_info,
                      sizeof(pct_type_session_monitor));
        }
        ReturnRows->rewind();
        rtn_rows->reset();
    }

    if (sql_stmt) delete sql_stmt;
    return 0;
}
