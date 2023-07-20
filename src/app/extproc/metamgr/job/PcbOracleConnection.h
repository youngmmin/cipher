/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbOracleConnection
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_ORACLE_CONNECTION_H
#define PCB_ORACLE_CONNECTION_H

#include "DgcBgmrList.h"
#include "DgcDbProcess.h"
#include "DgcDbifCoreOci.h"
#include "DgcLinkInfo.h"
#include "DgcOracleConnection.h"

class PcbOracleConnection : public DgcObject {
   private:
    DgcDbifCoreOci Connection;

   protected:
   public:
    PcbOracleConnection() {
        dgt_schar* oracle_home = dg_getenv("ORACLE_HOME");
        if (!oracle_home) {
            dgt_schar* soha_home = dg_getenv("SOHA_HOME");
            if (soha_home && strlen(soha_home) > 2) {
                DgcBgmrList* libList;
                DgcBgrammer* libConfig;
                dgt_schar conf_file[512];
                memset(conf_file, 0, 512);
                sprintf(conf_file, "%s/config/dblib.list", soha_home);
                libList = new DgcBgmrList(conf_file);
                if (EXCEPT) {
                    delete EXCEPTnC;
                    delete libList;
                } else {
                    libConfig = libList->getNext();
                    if (libConfig) {
                        dgt_schar* home = libConfig->getValue("oracle.home");
                        dgt_schar* file = libConfig->getValue("oracle.file");
                        dgt_schar libpath[PATH_MAX];
                        dgt_schar oracle_home[PATH_MAX];
                        memset(libpath, 0, PATH_MAX);
                        memset(oracle_home, 0, PATH_MAX);
                        if (!strcasecmp(home, "default")) {
                            sprintf(libpath, "%s/dblib1/lib/%s", soha_home,
                                    file);
                            sprintf(oracle_home, "%s/dblib1", soha_home);
                            dg_setenv("ORACLE_HOME", oracle_home, 1);
                            Connection.loadLibrary(libpath);
                        } else {
                            sprintf(libpath, "%s/dblib2/oracle/lib/%s",
                                    soha_home, file);
                            sprintf(oracle_home, "%s/dblib2/oracle", soha_home);
                            dg_setenv("ORACLE_HOME", oracle_home, 1);
                            Connection.loadLibrary(libpath);
                        }
                    }
                }
            }
        }
    };

    inline dgt_sint32 connect(pt_database_link_info* link_info) throw(
        DgcExcept) {
        //
        // Setting the charset(NLS_LANG)
        //
        dgt_schar con_string[1024];
        memset(con_string, 0, 1024);
        sprintf(con_string,
                "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=%s)(HOST=%s)("
                "PORT=%d)))"
                "(CONNECT_DATA=(SERVER=%s)(SID=%s)))",
                link_info->ora_protocol, link_info->host, link_info->port,
                link_info->ora_svr_proc, link_info->ora_service);
        dgt_sys_param* libpath = DG_PARAM("ORACLE_SHLIB");
        DgcOracleConnection* conn = new DgcOracleConnection();
        if (conn->connect(con_string, nul, link_info->user_name,
                          link_info->passwd, 0) != 0) {
            delete conn;
            ATHROWnR(DgcError(SPOS, "connect failed"), -1);
        }
        const dgt_schar* sel_str =
            "select parameter, value from v$nls_parameters "
            "where parameter in ('NLS_LANGUAGE', 'NLS_TERRITORY', "
            "'NLS_CHARACTERSET')";
        DgcCliStmt* client_stmt = conn->getStmt();
        if (client_stmt == 0) {
            delete conn;
            ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
        }
        if (client_stmt->execute(sel_str, strlen(sel_str), 3) < 0) {
            delete client_stmt;
            delete conn;
            ATHROWnR(DgcError(SPOS, "CharSetStmt->execute failed"), -1);
        }
        DgcMemRows* rtn_rows = client_stmt->returnRows();
        dgt_schar* nls_language = 0;
        dgt_schar* nls_territory = 0;
        dgt_schar* nls_characterset = 0;
        while (rtn_rows && rtn_rows->numRows() > 0) {
            rtn_rows->rewind();
            while (rtn_rows->next()) {
                dgt_schar* col = (dgt_schar*)rtn_rows->getColPtr(1);
                if (strcasecmp(col, "NLS_LANGUAGE") == 0)
                    nls_language = (dgt_schar*)rtn_rows->getColPtr(2);
                else if (strcasecmp(col, "NLS_TERRITORY") == 0)
                    nls_territory = (dgt_schar*)rtn_rows->getColPtr(2);
                else if (strcasecmp(col, "NLS_CHARACTERSET") == 0)
                    nls_characterset = (dgt_schar*)rtn_rows->getColPtr(2);
            }
            rtn_rows->reset();
            if (client_stmt->fetch(3) < 0) {
                delete client_stmt;
                ATHROWnR(DgcError(SPOS, "CharSetStmt->fetch failed"), -1);
            }
        }
        delete client_stmt;
        if (nls_language && nls_territory && nls_territory) {
            dgt_schar c_val[256];
            // sprintf(c_val, "%s_%s.%s",nls_language, nls_territory,
            // nls_characterset);
            sprintf(c_val, "KORENA_KOREA.UTF8");
            dg_setenv("NLS_LANG", c_val, 1);
        }
        conn->disconnect();
        delete conn;

        memset(con_string, 0, 1024);
        sprintf(con_string,
                "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%u))("
                "CONNECT_DATA=(SERVER=DEDICATED)(SID=%s)))",
                link_info->host, link_info->port, link_info->ora_service);
        if (Connection.connect(link_info->user_name, link_info->passwd,
                               con_string, link_info->ora_privilege)) {
            ATHROWnR(DgcError(SPOS, "connet[%s] failed", con_string), -1);
        }
        dgt_schar alter_txt[128];
        dg_sprintf(alter_txt,
                   "alter session set NLS_DATE_FORMAT = 'YYYYMMDDHH24MISS'");
        DgcDbifCoreOciCursor alter_stmt(&Connection);
        if (alter_stmt.declare(alter_txt, 1))
            ATHROWnR(DgcError(SPOS, "declare[%s] failed", alter_txt), -1);
        if (alter_stmt.open())
            ATHROWnR(DgcError(SPOS, "open[%s] failed", alter_txt), -1);
        if (alter_stmt.execute())
            ATHROWnR(DgcError(SPOS, "execute[%s] failed", alter_txt), -1);
        if (alter_stmt.close())
            ATHROWnR(DgcError(SPOS, "close[%s] failed", alter_txt), -1);
        return 0;
    };

    inline DgcDbifCoreOciCursor* getStmt(const dgt_schar* sql_text,
                                         dgt_uint16 max_bind_cols,
                                         dgt_uint16 max_rtn_cols) {
        return new DgcDbifCoreOciCursor(&Connection, max_bind_cols,
                                        max_rtn_cols);
    };

    inline dgt_sint32 commit() throw(DgcExcept) {
        if (Connection.commit()) {
            ATHROWnR(DgcError(SPOS, "commit failed"), -1);
        }
        return 0;
    };

    inline dgt_sint32 rollback() throw(DgcExcept) {
        if (Connection.rollback()) {
            ATHROWnR(DgcError(SPOS, "rollback failed"), -1);
        }
        return 0;
    };

    inline dgt_void disconnect() throw(DgcExcept) { Connection.disconnect(); };
};

#endif
