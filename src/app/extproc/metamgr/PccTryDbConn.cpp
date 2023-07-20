/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccTryDbConn
 *   Implementor        :       mwpark
 *   Create Date        :       2011. 11. 21
 *   Description        :       db connection test
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccTryDbConn.h"

#include "DgcConnectionMgr.h"
#include "DgcDbWorker.h"
#include "PccTableTypes.h"

PccTryDbConn::PccTryDbConn(const dgt_schar* name) : PccMetaProcedure(name) {}

PccTryDbConn::~PccTryDbConn() {}

DgcExtProcedure* PccTryDbConn::clone() { return new PccTryDbConn(procName()); }

typedef struct {
    dgt_sint32 dbms_type;
    dgt_schar ip_addr[256];
    dgt_sint32 port;
    dgt_schar db_name[33];
    dgt_schar instance_name[33];
    dgt_schar user[33];
    dgt_schar password[33];
} pc_type_try_db_conn_in;

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pc_type_try_db_conn_out;

dgt_sint32 PccTryDbConn::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pc_type_try_db_conn_in* in;
    if (!(in = (pc_type_try_db_conn_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }

    pc_type_try_db_conn_out out_param;
    memset(&out_param, 0, sizeof(pc_type_try_db_conn_out));

    dgt_schar conn_string[1024];
    memset(conn_string, 0, 1024);

    DgcCliConnection* conn = 0;
    DgcExcept* e = 0;

    for (;;) {
        if (in->dbms_type == DGC_DB_TYPE_ORACLE) {
            // oracle connection
            sprintf(conn_string,
                    "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=%"
                    "s)(PORT=%d)))"
                    "(CONNECT_DATA=(SERVER=DEDICATED)(SID=%s)))",
                    in->ip_addr, in->port, in->instance_name);
            conn = DgcConnectionMgr::conMgr().getConnection("oracle");
            if (!conn) break;

            if (conn->connect(conn_string, nul, in->user, in->password, 0) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_TDS) {
            // tds connection
            conn = DgcConnectionMgr::conMgr().getConnection("tds");
            if (!conn) break;

            dgt_schar host[512];
            memset(host, 0, 512);
            sprintf(host, "%s:%d", in->ip_addr, in->port);

            if (conn->connect(nul, host, in->user, in->password, in->db_name) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_SYBASEIQ ||
                   in->dbms_type == DGC_DB_TYPE_SYBASEASE) {
            // tds connection
            conn = DgcConnectionMgr::conMgr().getConnection("sybase");
            if (!conn) break;

            dgt_schar host[512];
            memset(host, 0, 512);
            sprintf(host, "%s:%d", in->ip_addr, in->port);

            if (conn->connect(nul, host, in->user, in->password, in->db_name) !=
                0) {
                e = EXCEPTnC;
            }
            break;
#ifdef linux
        } else if (in->dbms_type == DGC_DB_TYPE_INFORMIX) {
            // informix connection
            conn = DgcConnectionMgr::conMgr().getConnection("informix");
            if (!conn) break;

            sprintf(conn_string,
                    "host=%s;service=%d;database=%s;protocol=onsoctcp;server=%"
                    "s;uid=%s;pwd=%s;CLIENT_LOCALE=en_us.utf8",
                    in->ip_addr, in->port, in->db_name, in->instance_name,
                    in->user, in->password);

            if (conn->connect(conn_string, nul, in->user, in->password, nul) !=
                0) {
                e = EXCEPTnC;
            }
            break;
#endif
        } else if (in->dbms_type == DGC_DB_TYPE_DB2) {
            // db2 connection
            conn = DgcConnectionMgr::conMgr().getConnection("db2");
            if (!conn) break;

            sprintf(
                conn_string,
                "DATABASE=%s;HOSTNAME=%s;PORT=%d;UID=%s;PWD=%s;PROTOCOL=TCPIP;",
                in->db_name, in->ip_addr, in->port, in->user, in->password);

            if (conn->connect(conn_string, nul, in->user, in->password, nul) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_TIBERO) {
            // tibero connectgion
            conn = DgcConnectionMgr::conMgr().getConnection("tibero");
            if (!conn) break;

            sprintf(conn_string, "SERVER=%s;DB=%s;PORT=%d;UID=%s;PWD=%s;",
                    in->ip_addr, in->db_name, in->port, in->user, in->password);

            if (conn->connect(conn_string, nul, in->user, in->password, nul) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_ALTIBASE) {
            // altibase connection
            conn = DgcConnectionMgr::conMgr().getConnection("altibase");
            if (!conn) break;

            sprintf(conn_string,
                    "DSN=%s;UID=%s;PWD=%s;CONNTYPE=1;PORT_NO=%d;NLS_USE=UTF8;",
                    in->ip_addr, in->user, in->password, in->port);
            if (conn->connect(conn_string, nul, in->user, in->password, nul) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_MYSQL) {
            // mysql connection
#if 0  // deleted by jhpark 2020.09.17
			dgt_sys_param* param = 0;
			dgt_schar db_name[33] = {0, };
			if (((param=DgcDbWorker::getDgParam("DBLINK_CONN_INSTANCE")) == 0) || (param && param->val_number == 0)) {
				if (EXCEPT != 0) delete EXCEPTnC;
				strcpy(db_name, in->db_name);
			}
#endif
            conn = DgcConnectionMgr::conMgr().getConnection("mysql");
            if (!conn) break;

            sprintf(conn_string, "%d", in->port);
            if (conn->connect(conn_string, in->ip_addr, in->user, in->password,
                              in->db_name) != 0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_CUBRID) {
            // cubrid connection
            conn = DgcConnectionMgr::conMgr().getConnection("cubrid");
            if (!conn) break;

            sprintf(conn_string, "%d", in->port);
            if (conn->connect(conn_string, in->ip_addr, in->user, in->password,
                              in->db_name) != 0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_POSTGRESQL) {
            // postgresql connection
            conn = DgcConnectionMgr::conMgr().getConnection("postgres");
            if (!conn) break;

            sprintf(conn_string, "%d", in->port);
            if (conn->connect(conn_string, in->ip_addr, in->user, in->password,
                              in->db_name) != 0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_GOLDILOCKS) {
            // goldilocks connection
            conn = DgcConnectionMgr::conMgr().getConnection("goldilocks");
            if (!conn) break;

            sprintf(conn_string, "PROTOCOL=TCP;HOST=%s;PORT=%d;UID=%s;PWD=%s;",
                    in->ip_addr, in->port, in->user, in->password);
            if (conn->connect(conn_string, nul, in->user, in->password, nul) !=
                0) {
                e = EXCEPTnC;
            }
            break;
        } else if (in->dbms_type == DGC_DB_TYPE_TERADATA) {
            // teradata connection
            conn = DgcConnectionMgr::conMgr().getConnection("teradata");
            if (!conn) break;
            /*
            sprintf(conn_string, "DSN=399;UID=%s;PWD=%s;", in->user,
            in->password); if (conn->connect(conn_string, nul, in->user,
            in->password, nul) != 0) { e = EXCEPTnC;
            }
            */
            break;
        } else {
            // not supported dbms type
            ReturnRows->reset();
            ReturnRows->add();
            ReturnRows->next();
            memset(ReturnRows->data(), 0, ReturnRows->rowSize());
            sprintf(out_param.result_msg, "[not supported dbms_type[%d]]",
                    in->dbms_type);
            out_param.result_code = 0;
            memcpy(ReturnRows->data(), &out_param,
                   sizeof(pc_type_try_db_conn_out));
            ReturnRows->rewind();
            return 0;
        }

        break;
    }

    if (e) {
        DgcError* err = e->getErr();
        while (err->next()) err = err->next();
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        memset(ReturnRows->data(), 0, ReturnRows->rowSize());
        sprintf(out_param.result_msg, "[%.1024s]", (dgt_schar*)err->message());
        out_param.result_code = -1;
        memcpy(ReturnRows->data(), &out_param, sizeof(pc_type_try_db_conn_out));
        ReturnRows->rewind();
        if (conn) delete conn;
        delete e;

        return 0;
    }

    if (!conn) {
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        out_param.result_code = -1;
        sprintf(out_param.result_msg,
                "[connection was not allocated : db_type[%d]]", in->dbms_type);
        memcpy(ReturnRows->data(), &out_param, sizeof(pc_type_try_db_conn_out));
        ReturnRows->rewind();
    } else {
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        out_param.result_code = 0;
        sprintf(out_param.result_msg, "[%s]", "connenction success");
        memcpy(ReturnRows->data(), &out_param, sizeof(pc_type_try_db_conn_out));
        ReturnRows->rewind();
        delete conn;
    }

    return 0;
}
