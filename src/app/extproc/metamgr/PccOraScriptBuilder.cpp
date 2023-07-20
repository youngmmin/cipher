/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccOraScriptBuilder
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       oracle script builder
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccOraScriptBuilder.h"

#include "DgcLinkInfo.h"

extern void check_logger(const char* fmt, ...);

DgcCliConnection* PccOraScriptBuilder::connect(dgt_schar* uid,
                                               dgt_schar* pw) throw(DgcExcept) {
    //
    // getting the link_info
    //
    dgt_schar c_val[256];
    sprintf(c_val, "KOREAN_KOREA.UTF8");
    dg_setenv("NLS_LANG", c_val, 1);
    DgcLinkInfo dblink(Database->pdb());
    pt_database_link_info* link_info = dblink.getDatabaseLinkInfo(SchemaLink);
    if (!link_info) {
        ATHROWnR(DgcError(SPOS, "getDatabaseLinkInfo failed"), 0);
    }
    if (!uid || *uid == 0) uid = link_info->user_name;
    if (!pw || *pw == 0) pw = link_info->passwd;
    const dgt_schar* privilege = link_info->ora_privilege;
    if (!strcasecmp(uid, "sys")) privilege = "SYSDBA";
    dgt_schar conn_string[1024];
    //
    // Setting the charset(NLS_LANG)
    //
    memset(conn_string, 0, 1024);
    sprintf(
        conn_string,
        "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=%s)(HOST=%s)(PORT=%d)))"
        "(CONNECT_DATA=(SERVER=%s)(SID=%s)))",
        link_info->ora_protocol, link_info->host, link_info->port,
        link_info->ora_svr_proc, link_info->ora_service);
    DgcOracleConnection* conn = new DgcOracleConnection();
    if (conn->connect(conn_string, nul, uid, pw, privilege) != 0) {
        DgcExcept* e = EXCEPTnC;
        delete conn;
        RTHROWnR(e, DgcError(SPOS, "connect failed."), 0);
    }
    return conn;
#if 0
        dgt_schar  sel_str[1024];
        memset(sel_str,0,1024);
        sprintf(sel_str,"select parameter, value from v$nls_parameters "
                              "where parameter in ('NLS_LANGUAGE', 'NLS_TERRITORY', 'NLS_CHARACTERSET')");
        DgcCliStmt* client_stmt=conn->getStmt();
        if (client_stmt==0) {
                delete conn;
                ATHROWnR(DgcError(SPOS, "getStmt failed"), 0);
        }
        if (client_stmt->execute(sel_str,strlen(sel_str),10) < 0) {
                delete client_stmt;
                delete conn;
                DgcExcept*      e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"charSet failed."),0);
        }
        DgcMemRows*     rtn_rows=client_stmt->returnRows();
        dgt_schar* nls_language=0;
        dgt_schar* nls_territory=0;
        dgt_schar* nls_characterset=0;
        while(rtn_rows && rtn_rows->numRows() > 0)
        {
                rtn_rows->rewind();
                while(rtn_rows->next()) {
                        dgt_schar* col=(dgt_schar*)rtn_rows->getColPtr(1);
                        if (strcasecmp(col, "NLS_LANGUAGE")==0) nls_language=(dgt_schar*)rtn_rows->getColPtr(2);
                        else if (strcasecmp(col, "NLS_TERRITORY")==0) nls_territory=(dgt_schar*)rtn_rows->getColPtr(2);
                        else if (strcasecmp(col, "NLS_CHARACTERSET")==0) nls_characterset=(dgt_schar*)rtn_rows->getColPtr(2);
                }
                rtn_rows->reset();
                if (client_stmt->fetch(3) < 0) {
                        delete client_stmt;
                        delete conn;
                        DgcExcept*      e=EXCEPTnC;
                        RTHROWnR(e,DgcError(SPOS,"fetch failed."),0);
                }
        }
        delete client_stmt;
        if (nls_language && nls_territory && nls_territory) {
                dgt_schar c_val[256];
                //sprintf(c_val, "%s_%s.%s",nls_language, nls_territory,  nls_characterset);
                sprintf(c_val, "KOREAN_KOREA.UTF8");
                dg_setenv("NLS_LANG", c_val, 1);
        }
        conn->disconnect();
        delete conn;

        memset(conn_string,0,256);
        if (link_info->ora_tnsname[0]) {
                dg_strcpy(conn_string, link_info->ora_tnsname);
        } else {
                sprintf(conn_string,
                        "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=%s)(HOST=%s)(PORT=%d)))"
#if 0
                        "(CONNECT_DATA=(SERVER=%s)(SERVICE_NAME=%s)))",
#else
                        "(CONNECT_DATA=(SERVER=%s)(SID=%s)))",
#endif
                        link_info->ora_protocol,
                        link_info->host,
                        link_info->port,
                        link_info->ora_svr_proc,
                        link_info->ora_service);
        }
        DgcOracleConnection*    conn2=new DgcOracleConnection();
        if (conn2->connect(conn_string, nul, uid, pw, privilege) != 0) {
                DgcExcept*      e=EXCEPTnC;
                delete conn2;
                RTHROWnR(e,DgcError(SPOS,"connect failed."),0);
        }
        return conn2;
#endif
}

dgt_sint32 PccOraScriptBuilder::preparePrivInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    sprintf(sql_text,
            "select * from pct_enc_tab_priv "
            "where enc_tab_id=%lld ",
            TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pct_type_enc_tab_priv* priv_info_tmp;
    PrivSqlRows.reset();
    while ((priv_info_tmp = (pct_type_enc_tab_priv*)sql_stmt->fetch())) {
        dgt_schar privilege[128];
        dgt_schar GrantOption[128];
        dgt_schar privSql[1024];
        memset(privilege, 0, 128);
        memset(GrantOption, 0, 128);
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
        } else if (priv_info_tmp->privilege == 5) {
            sprintf(privilege, "select");
            sprintf(GrantOption, "with grant option");
        } else if (priv_info_tmp->privilege == 6) {
            sprintf(privilege, "insert");
            sprintf(GrantOption, "with grant option");
        } else if (priv_info_tmp->privilege == 7) {
            sprintf(privilege, "update");
            sprintf(GrantOption, "with grant option");
        } else if (priv_info_tmp->privilege == 8) {
            sprintf(privilege, "delete");
            sprintf(GrantOption, "with grant option");
        }
        sprintf(privSql, "grant %s on %s.%s to %s %s", privilege, SchemaName,
                TabInfo.table_name, priv_info_tmp->grantee, GrantOption);
        PrivSqlRows.add();
        PrivSqlRows.next();
        memcpy(PrivSqlRows.data(), privSql, 1024);
        if (TabInfo.enc_type == 0) {
            memset(privSql, 0, 1024);
            sprintf(privSql, "grant %s on %s.%s to %s %s", privilege,
                    SchemaName, TabInfo.renamed_tab_name,
                    priv_info_tmp->grantee, GrantOption);
            PrivSqlRows.add();
            PrivSqlRows.next();
            memcpy(PrivSqlRows.data(), privSql, 1024);
        }
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        delete e;
    }
    PrivSqlRows.rewind();
    return 1;
}

typedef struct {
    dgt_schar col_name[130];
    dgt_sint64 comments;
} pc_type_col_comment;

dgt_sint32 PccOraScriptBuilder::prepareCommentInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    sprintf(sql_text,
            "select getname(comments) from pct_enc_tab_comment "
            "where enc_tab_id=%lld ",
            TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    dgt_schar* comment_tmp;
    CommentInfoRows.reset();
    while ((comment_tmp = (dgt_schar*)sql_stmt->fetch())) {
        dgt_schar comment_sql[5000];
        memset(comment_sql, 0, 5000);
        CommentInfoRows.add();
        CommentInfoRows.next();
        memset(comment_sql, 0, 5000);
        sprintf(comment_sql, "COMMENT ON TABLE %s.%s IS '%s'", SchemaName,
                TabInfo.table_name, comment_tmp);
        memcpy(CommentInfoRows.data(), comment_sql, 5000);
        if (TabInfo.enc_type == 0) {
            CommentInfoRows.add();
            CommentInfoRows.next();
            memset(comment_sql, 0, 5000);
            sprintf(comment_sql, "COMMENT ON TABLE %s.%s IS '%s'", SchemaName,
                    TabInfo.renamed_tab_name, comment_tmp);
            memcpy(CommentInfoRows.data(), comment_sql, 5000);
        }
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        delete e;
    }
    sprintf(sql_text,
            "select b.column_name, a.comments "
            "from pct_enc_col_comment a, "
            "     pct_enc_column b "
            "where a.enc_col_id = b.enc_col_id "
            "and   a.enc_tab_id = %lld",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_col_comment* col_comment_tmp;
    while ((col_comment_tmp = (pc_type_col_comment*)sql_stmt->fetch())) {
        dgt_schar comment_sql[5000];
        memset(comment_sql, 0, 5000);
        sprintf(comment_sql, "COMMENT ON COLUMN %s.%s.%s IS '%s'", SchemaName,
                TabInfo.table_name, col_comment_tmp->col_name,
                PetraNamePool->getNameString(col_comment_tmp->comments));
        CommentInfoRows.add();
        CommentInfoRows.next();
        memcpy(CommentInfoRows.data(), comment_sql, 5000);
        if (TabInfo.enc_type == 0) {
            memset(comment_sql, 0, 5000);
            sprintf(comment_sql, "COMMENT ON COLUMN %s.%s.%s IS '%s'",
                    SchemaName, TabInfo.renamed_tab_name,
                    col_comment_tmp->col_name,
                    PetraNamePool->getNameString(col_comment_tmp->comments));
            CommentInfoRows.add();
            CommentInfoRows.next();
            memcpy(CommentInfoRows.data(), comment_sql, 5000);
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        delete e;
    }
    CommentInfoRows.rewind();
    return 1;
}

dgt_sint32 PccOraScriptBuilder::prepareObjInfo() throw(DgcExcept) {
    //
    // getting the dependency object in real time
    //
    dgt_schar soha_text[2048];
    memset(soha_text, 0, 2048);
    sprintf(soha_text, "delete pct_enc_tab_dep_obj where enc_tab_id=%lld",
            TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, soha_text, strlen(soha_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete sql_stmt;
    ObjSqlRows.reset();
    ObjTriggerSqlRows.reset();
    dgt_schar sql_text[2048];
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
    }
    sprintf(sql_text,
            "select /*+ no_merge */ "
            "distinct "
            "owner, "
            "name, "
            "type, "
            "level hlevel "
            "from dba_dependencies start with referenced_owner = upper('%s') "
            "and referenced_name = upper('%s') connect by referenced_owner = "
            "prior owner "
            "and referenced_name = prior name "
            "and referenced_type = prior type "
            "order by hlevel",
            SchemaName, TabInfo.table_name);
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    } else {
        DgcMemRows* rows = stmt->returnRows();
        while (rows && rows->numRows() > 0) {
            rows->rewind();
            while (rows->next()) {
                dgt_schar objSql[1024];
                memset(objSql, 0, 1024);
                dgt_schar owner[64];
                dgt_schar name[64];
                dgt_schar type[32];
                dgt_sint32 hlevel = 0;
                memset(owner, 0, 64);
                memset(name, 0, 64);
                memset(type, 0, 32);
                memcpy(owner, (dgt_schar*)rows->getColPtr(1), 64);
                memcpy(name, (dgt_schar*)rows->getColPtr(2), 64);
                memcpy(type, (dgt_schar*)rows->getColPtr(3), 32);
                hlevel = strtol((dgt_schar*)rows->getColPtr(4), 0, 10);
                if (!strcasecmp(type, "SYNONYM")) {
                    continue;
                }
                if (!strcasecmp(type, "PACKAGE BODY")) {
                    // modify for bug#136 in trac
                    // sprintf(objSql,"alter %s %s.%s compile body", type ,
                    // owner, name);
                    sprintf(objSql, "alter PACKAGE %s.%s compile body", owner,
                            name);
                } else {
                    sprintf(objSql, "alter %s %s.%s compile", type, owner,
                            name);
                }
                if (TabInfo.init_enc_type > 0) {
                    if (!getConnection()) {
                        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
                    }
                    if (!strcasecmp(type, "TRIGGER")) {
                        dgt_schar sql_text[1024];
                        memset(sql_text, 0, 1024);
                        sprintf(
                            sql_text,
                            "select DBMS_METADATA.GET_DDL('TRIGGER','%s','%s') "
                            "from dual",
                            name, owner);
                        DgcCliStmt* stmt = Connection->getStmt();
                        if (!stmt) {
                            ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
                        }
                        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
                            DgcExcept* e = EXCEPTnC;
                            delete stmt;
                            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
                        }
                        DgcMemRows* rows = stmt->returnRows();
                        rows->rewind();
                        dgt_schar* ddl_stmt_ptr = 0;
                        while (rows->next() &&
                               (ddl_stmt_ptr = (dgt_schar*)rows->data())) {
                            dgt_schar* tmp_ptr = (dgt_schar*)dg_strcasestr(
                                ddl_stmt_ptr, "ALTER");
                            if (tmp_ptr) {
                                memset(tmp_ptr, 0, strlen(tmp_ptr));
                                ObjTriggerSqlRows.add();
                                ObjTriggerSqlRows.next();
                                memcpy(ObjTriggerSqlRows.data(), ddl_stmt_ptr,
                                       strlen(ddl_stmt_ptr));
                            }
                        }
                        delete stmt;
                    }
                }
                ObjSqlRows.add();
                ObjSqlRows.next();
                memcpy(ObjSqlRows.data(), objSql, 1024);
                dgt_uint32 object_type = 0;
                if (!strcasecmp(type, "FUNCTION")) {
                    object_type = 1;
                } else if (!strcasecmp(type, "PROCEDURE")) {
                    object_type = 2;
                } else if (!strcasecmp(type, "TRIGGER")) {
                    object_type = 3;
                } else if (!strcasecmp(type, "PACKAGE")) {
                    object_type = 4;
                } else if (!strcasecmp(type, "PACKAGE BODY")) {
                    object_type = 5;
                } else if (!strcasecmp(type, "VIEW")) {
                    object_type = 6;
                } else if (!strcasecmp(type, "SYNONYM")) {
                    object_type = 7;
                }
                memset(soha_text, 0, 2048);
                sprintf(soha_text,
                        "insert into "
                        "pct_enc_tab_dep_obj(enc_tab_id,schema_name,object_"
                        "name,object_type) "
                        "values(%lld,getnameid('%s'),getnameid('%s'),%d)",
                        TabInfo.enc_tab_id, owner, name, object_type);
                DgcSqlStmt* sql_stmt =
                    Database->getStmt(Session, soha_text, strlen(soha_text));
                if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                    //	DgcExcept*      e=EXCEPTnC;
                    //	delete sql_stmt;
                    //	RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                    delete EXCEPTnC;
                }
                delete sql_stmt;
            }
            rows->reset();
            if (stmt->fetch(10) < 0) {
                stmt->close();
                delete EXCEPTnC;
                break;
            }
        }
    }
    delete stmt;
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    ObjSqlRows.rewind();
    ObjTriggerSqlRows.rewind();
    return 1;
}

typedef struct {
    dgt_sint64 enc_col_id;
    dgt_schar column_name[130];
    dgt_schar data_type[33];
    dgt_uint8 index_type;
    dgt_schar domain_index_name[130];
    dgt_schar fbi_index_name[130];
    dgt_schar normal_index_name[130];
    dgt_schar tablespace_name[130];
    dgt_uint8 normal_idx_flag;
    dgt_schar index_col_name[130];
} pc_type_index_row;

typedef struct {
    dgt_schar sql_text[512];
    dgt_schar normal_sql_text[512];
    dgt_schar sql_text2[512];
    dgt_schar normal_sql_text2[512];
    dgt_schar idx_col_idx1[512];
    dgt_schar idx_col_idx2[512];
} pc_type_petra_index;

dgt_sint32 PccOraScriptBuilder::prepareIdxInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    //
    // Petra Index sql create
    //
    dgt_schar idx_sql[512];
    dgt_schar normal_sql[512];
    dgt_schar idx_sql2[512];
    dgt_schar normal_sql2[512];
    dgt_schar idx_col_idx1[512];
    dgt_schar idx_col_idx2[512];
    memset(idx_sql, 0, 512);
    memset(normal_sql, 0, 512);
    memset(idx_sql2, 0, 512);
    memset(normal_sql2, 0, 512);
    memset(sql_text, 0, 2048);
    memset(idx_col_idx1, 0, 512);
    memset(idx_col_idx2, 0, 512);
    if (TabInfo.synonym_flag == 0) {
        sprintf(sql_text,
                "select a.enc_col_id, b.column_name, b.data_type, "
                "a.index_type, b.domain_index_name, b.fbi_index_name, "
                "b.normal_index_name, a.tablespace_name, a.normal_idx_flag, "
                "b.index_col_name "
                //", a.sql_text, a.normal_sql_text, a.sql_text2,
                //a.normal_sql_text2, a.normal_sql_text, a.normal_sql_text "
                "from pct_enc_index a, pct_enc_column b, pct_enc_table c "
                "where a.enc_col_id = b.enc_col_id "
                "and   b.enc_tab_id = c.enc_tab_id "
                "and   b.enc_tab_id = %lld",
                TabInfo.enc_tab_id);
    } else {
        sprintf(sql_text,
                "select d.key_id, b.column_name, b.data_type, a.index_type, "
                "b.domain_index_name, b.fbi_index_name, "
                "b.normal_index_name, a.tablespace_name, a.normal_idx_flag, "
                "b.index_col_name "
                "from pct_enc_index a, pct_enc_column b, pct_enc_table c, "
                "pct_encrypt_key d "
                "where a.enc_col_id = b.enc_col_id "
                "and   b.enc_tab_id = c.enc_tab_id "
                "and   b.key_id = d.key_id "
                "and   b.enc_tab_id = %lld",
                TabInfo.enc_tab_id);
    }
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_index_row* idx_info = 0;
    PetraIdxInfoRows.reset();
    while ((idx_info = (pc_type_index_row*)sql_stmt->fetch())) {
        memset(idx_sql, 0, 512);
        memset(normal_sql, 0, 512);
        memset(idx_sql2, 0, 512);
        memset(normal_sql2, 0, 512);
        memset(idx_col_idx1, 0, 512);
        memset(idx_col_idx2, 0, 512);
        if (idx_info->index_type == 1) {
            if (TabInfo.enc_type == 0 && idx_info->normal_idx_flag == 1) {
                // normal_idx_flag == 1 create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            } else if (TabInfo.enc_type == 1 &&
                       idx_info->normal_idx_flag == 1) {
                // normal_idx_flag == 1 create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            }
            // create domain index`s normal index
            // if copy table encryption && enc column has normal index
            // (position) do not create index because already generated normal
            // index column
            //
            // getting the index_name in table
            //
            dgt_schar sql_text[2048];
            memset(sql_text, 0, 2048);
            sprintf(sql_text,
                    "select count() from pct_enc_col_index where enc_col_id = "
                    "%lld and column_position=1",
                    idx_info->enc_col_id);
            DgcSqlStmt* count_stmt =
                Database->getStmt(Session, sql_text, strlen(sql_text));
            if (count_stmt == 0 || count_stmt->execute() < 0) {
                DgcExcept* e = EXCEPTnC;
                delete count_stmt;
                RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
            }
            dgt_sint64* count_tmp = 0;
            dgt_sint64 count = 0;
            if ((count_tmp = (dgt_sint64*)count_stmt->fetch())) {
                memcpy(&count, count_tmp, sizeof(dgt_sint64));
            }
            if (count == 0 && idx_info->normal_idx_flag == 1) {
                if (TabInfo.partitioned) {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging local",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            idx_info->tablespace_name, ParallelDegree);
                } else {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            idx_info->tablespace_name, ParallelDegree);
                }
                sprintf(idx_col_idx2, "alter index %s.%s parallel %d logging",
                        SchemaName, idx_info->fbi_index_name, TabInfo.degree);
            }
            delete count_stmt;
            delete EXCEPTnC;
        } else if (idx_info->index_type == 2) {
            if (TabInfo.enc_type == 0 && idx_info->normal_idx_flag == 1) {
                // create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX2_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX2_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            } else if (TabInfo.enc_type == 1 &&
                       idx_info->normal_idx_flag == 1) {
                // create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX2_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX2_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            }
            // create domain index`s fbi(PLS_OPHUEK_B64) index
            if (TabInfo.partitioned) {
                sprintf(
                    idx_col_idx1,
                    "create index %s.%s on %s.%s(PLS_OPHUEK_B64(%s,%lld,1)) "
                    "tablespace %s parallel %d nologging local",
                    SchemaName, idx_info->fbi_index_name, SchemaName,
                    TabInfo.renamed_tab_name, idx_info->column_name,
                    idx_info->enc_col_id, idx_info->tablespace_name,
                    ParallelDegree);
            } else {
                sprintf(
                    idx_col_idx1,
                    "create index %s.%s on %s.%s(PLS_OPHUEK_B64(%s,%lld,1)) "
                    "tablespace %s parallel %d nologging",
                    SchemaName, idx_info->fbi_index_name, SchemaName,
                    TabInfo.renamed_tab_name, idx_info->column_name,
                    idx_info->enc_col_id, idx_info->tablespace_name,
                    ParallelDegree);
            }
            sprintf(idx_col_idx2, "alter index %s.%s parallel %d logging",
                    SchemaName, idx_info->fbi_index_name, TabInfo.degree);
        } else if (idx_info->index_type == 0 && idx_info->normal_idx_flag) {
            //
            // create bubun encryption`s doamin index && normal index
            //
            if (TabInfo.enc_type == 0) {
                // normal_idx_flag == 1 create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            } else if (TabInfo.enc_type == 1) {
                // normal_idx_flag == 1 create the domain index
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX3_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            AgentName);
                }
            }
            // create domain index`s normal index
            // if copy table encryption && enc column has normal index
            // (position) do not create index because already generated normal
            // index column
            //
            // getting the index_name in table
            //
            dgt_schar sql_text[2048];
            memset(sql_text, 0, 2048);
            sprintf(sql_text,
                    "select count() from pct_enc_col_index where enc_col_id = "
                    "%lld and column_position=1",
                    idx_info->enc_col_id);
            DgcSqlStmt* count_stmt =
                Database->getStmt(Session, sql_text, strlen(sql_text));
            if (count_stmt == 0 || count_stmt->execute() < 0) {
                DgcExcept* e = EXCEPTnC;
                delete count_stmt;
                RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
            }
            dgt_sint64* count_tmp = 0;
            dgt_sint64 count = 0;
            if ((count_tmp = (dgt_sint64*)count_stmt->fetch())) {
                memcpy(&count, count_tmp, sizeof(dgt_sint64));
            }
            if (count == 0) {
                if (TabInfo.partitioned) {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging local",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            idx_info->tablespace_name, ParallelDegree);
                } else {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->column_name,
                            idx_info->tablespace_name, ParallelDegree);
                }
                sprintf(idx_col_idx2, "alter index %s.%s parallel %d logging",
                        SchemaName, idx_info->fbi_index_name, TabInfo.degree);
            }
            delete count_stmt;
            delete EXCEPTnC;
        }
        if (idx_info->index_type || idx_info->normal_idx_flag) {
            pc_type_petra_index pt_idx_info;
            memset(&pt_idx_info, 0, sizeof(pc_type_petra_index));
            strncpy(pt_idx_info.sql_text, idx_sql, strlen(idx_sql));
            strncpy(pt_idx_info.normal_sql_text, normal_sql,
                    strlen(normal_sql));
            strncpy(pt_idx_info.sql_text2, idx_sql2, strlen(idx_sql2));
            strncpy(pt_idx_info.normal_sql_text2, normal_sql2,
                    strlen(normal_sql2));
            strncpy(pt_idx_info.idx_col_idx1, idx_col_idx1,
                    strlen(idx_col_idx1));
            strncpy(pt_idx_info.idx_col_idx2, idx_col_idx2,
                    strlen(idx_col_idx2));
            PetraIdxInfoRows.add();
            PetraIdxInfoRows.next();
            memcpy(PetraIdxInfoRows.data(), &pt_idx_info,
                   sizeof(pc_type_petra_index));
        }
    }
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    delete sql_stmt;
    PetraIdxInfoRows.rewind();
    //
    // Unique Idx Column settting(non enc column) for double view except rowid
    //
    IdxColRows.reset();
    memset(sql_text, 0, 2048);
    // modified by shson 2018.12.18 for except unique index
    // unique index is nullable so when update dml executing
    // occur problem
#if 0
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
"where   c.idx_name2 = 0",TabInfo.enc_tab_id,TabInfo.enc_tab_id);
#else
    sprintf(
        sql_text,
        "select c.idx_name1 "
        "from "
        "( select a.index_name idx_name1,b.index_name idx_name2 ,a.enc_col_id "
        "from    pct_enc_col_index a, "
        "(select distinct index_name "
        "from   pct_enc_col_index "
        "where  status = 1 "
        "and    enc_tab_id= %lld) (+) b "
        "where  a.index_name = b.index_name "
        "and    a.enc_tab_id = %lld "
        "and    a.uniqueness = 1 ) c , pct_enc_col_ct d "
        "where  c.enc_col_id = d.enc_col_id "
        "and   	d.constraint_type = 1 "
        "and   c.idx_name2 = 0 ",
        TabInfo.enc_tab_id, TabInfo.enc_tab_id);
#endif
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
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
        e = EXCEPTnC;
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
    IdxColRows.rewind();
    //
    // Unique Idx Column settting2 (for transaction trigger)
    //
#if 1
    TranIdxColRows.reset();
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select distinct index_name "
            "from   pct_enc_col_index "
            "where  enc_tab_id = %lld "
            "and    uniqueness = 1 ",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    idxname = 0;
    if ((idxname = (dgt_sint64*)sql_stmt->fetch())) {
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select c.column_name "
                "from "
                "( "
                "select b.column_name column_name, a.column_position "
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
            TranIdxColRows.add();
            TranIdxColRows.next();
            memcpy(TranIdxColRows.data(), idxcol, strlen(idxcol));
        }
        e = EXCEPTnC;
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
    TranIdxColRows.rewind();
#endif
    return 1;
}

typedef struct {
    dgt_sint64 index_name;
    dgt_sint64 renamed_org_name;
    dgt_sint64 index_owner;
    dgt_uint8 uniqueness;
    dgt_sint64 target_tablespace;
    dgt_uint16 degree;
    dgt_uint8 logging;
} pc_type_idx2;

dgt_sint32 PccOraScriptBuilder::prepareIdx2Info() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    IdxSqlRows2.reset();
    IdxSqlRows3.reset();
    IdxSqlRows4.reset();
    IdxSqlRows5.reset();
    IdxSqlRows6.reset();
    //
    // getting the index_name in table
    //
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select distinct "
            "index_name,renamed_org_name1,index_owner,uniqueness,target_"
            "tablespace_name,degree,logging "
            "from  pct_enc_col_index "
            "where enc_tab_id = %lld "
            "order by uniqueness desc",
            TabInfo.enc_tab_id);
    DgcSqlStmt* idx_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (idx_stmt == 0 || idx_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete idx_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_idx2* idx_tmp = 0;
    while ((idx_tmp = (pc_type_idx2*)idx_stmt->fetch())) {
        //
        // getting the index creation sql text
        //
        memset(sql_text, 0, 2048);
        if (!getConnection()) {
            ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
        }
        if (TabInfo.partitioned == 0) {
            sprintf(sql_text,
                    "declare "
                    "begin "
                    "dbms_metadata.set_transform_param(dbms_metadata.session_"
                    "transform,'TABLESPACE',TRUE); "
                    //    "dbms_metadata.set_transform_param(dbms_metadata.session_transform,'SEGMENT_ATTRIBUTES',FALSE);
                    //    "
                    "end;");
        } else {
            sprintf(sql_text,
                    "declare "
                    "begin "
                    "dbms_metadata.set_transform_param(dbms_metadata.session_"
                    "transform,'TABLESPACE',TRUE); "
                    "end;");
        }
        DgcCliStmt* stmt = Connection->getStmt();
        if (!stmt) {
            ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
        }
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        sprintf(sql_text,
                "select dbms_metadata.get_ddl('INDEX','%s','%s') from dual",
                PetraNamePool->getNameString(idx_tmp->index_name),
                PetraNamePool->getNameString(idx_tmp->index_owner));
        stmt = Connection->getStmt();
        if (!stmt) {
            ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
        }
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        DgcMemRows* rows = stmt->returnRows();
        rows->rewind();
        dgt_schar* ddl_stmt_ptr = 0;
        dgt_schar idx_sql[50000];
        dgt_schar idx_sql2[2048];
        dgt_schar idx_sql3[50000];
        memset(idx_sql, 0, 50000);
        memset(idx_sql2, 0, 2048);
        memset(idx_sql3, 0, 50000);
        if (idx_tmp->uniqueness == 1) {
            sprintf(idx_sql, "CREATE UNIQUE INDEX %s.%s ON %s.%s ",
                    PetraNamePool->getNameString(idx_tmp->index_owner),
                    PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                    SchemaName, TabInfo.renamed_tab_name);
            sprintf(idx_sql3, "CREATE UNIQUE INDEX %s.%s ON %s.%s_%lld ",
                    PetraNamePool->getNameString(idx_tmp->index_owner),
                    PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                    SchemaName, "petra", TabInfo.enc_tab_id);
        } else {
            sprintf(idx_sql, "CREATE INDEX %s.%s ON %s.%s ",
                    PetraNamePool->getNameString(idx_tmp->index_owner),
                    PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                    SchemaName, TabInfo.renamed_tab_name);
            sprintf(idx_sql3, "CREATE INDEX %s.%s ON %s.%s_%lld ",
                    PetraNamePool->getNameString(idx_tmp->index_owner),
                    PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                    SchemaName, "petra", TabInfo.enc_tab_id);
        }
        while (rows->next() && (ddl_stmt_ptr = (dgt_schar*)rows->data())) {
            dgt_schar tabname[130];
            memset(tabname, 0, 130);
            sprintf(tabname, "\"%s\"", TabInfo.table_name);
            dgt_schar* tmp = strstr(ddl_stmt_ptr, tabname);
            if (tmp) {
                dgt_uint32 i = 0;
                for (i = 0; i < strlen(tabname); i++) {
                    tmp++;
                }
            }
            strcat(idx_sql, tmp);
            strcat(idx_sql3, tmp);
            if (TabInfo.partitioned == 0) {
                //               	        strcat(idx_sql," TABLESPACE  ");
                //                      	strcat(idx_sql,PetraNamePool->getNameString(idx_tmp->target_tablespace));
                //				strcat(idx_sql," NOLOGGING ");
                //                             strcat(idx_sql3," TABLESPACE  ");
                //                             strcat(idx_sql3,PetraNamePool->getNameString(idx_tmp->target_tablespace));
                //				strcat(idx_sql3," NOLOGGING ");
                if (idx_tmp->logging) {
                    strcat(idx_sql, " NOLOGGING ");
                    strcat(idx_sql3, " NOLOGGING ");
                }
            }
            if (idx_tmp->degree == 1) {
                dgt_schar degree[50];
                memset(degree, 0, 50);
                sprintf(degree, " PARALLEL %d ", ParallelDegree);
                strcat(idx_sql, degree);
                strcat(idx_sql3, degree);
            }
            IdxSqlRows2.add();
            IdxSqlRows2.next();
            memcpy(IdxSqlRows2.data(), idx_sql, strlen(idx_sql));
            IdxSqlRows6.add();
            IdxSqlRows6.next();
            memcpy(IdxSqlRows6.data(), idx_sql3, strlen(idx_sql3));
        }
        sprintf(idx_sql2, "ALTER INDEX %s.%s PARALLEL %d LOGGING",
                PetraNamePool->getNameString(idx_tmp->index_owner),
                PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                idx_tmp->degree);
        IdxSqlRows3.add();
        IdxSqlRows3.next();
        memcpy(IdxSqlRows3.data(), idx_sql2, strlen(idx_sql2));

        dgt_schar idx_sql4[512];
        memset(idx_sql4, 0, 512);
        sprintf(idx_sql4, "ALTER INDEX %s.%s rename to %s",
                PetraNamePool->getNameString(idx_tmp->index_owner),
                PetraNamePool->getNameString(idx_tmp->renamed_org_name),
                PetraNamePool->getNameString(idx_tmp->index_name));
        IdxSqlRows4.add();
        IdxSqlRows4.next();
        memcpy(IdxSqlRows4.data(), idx_sql4, strlen(idx_sql4));

        dgt_schar idx_sql5[512];
        memset(idx_sql5, 0, 512);
        sprintf(idx_sql5, "ALTER INDEX %s.%s rename to %s_org",
                PetraNamePool->getNameString(idx_tmp->index_owner),
                PetraNamePool->getNameString(idx_tmp->index_name),
                PetraNamePool->getNameString(idx_tmp->index_name));
        IdxSqlRows5.add();
        IdxSqlRows5.next();
        memcpy(IdxSqlRows5.data(), idx_sql5, strlen(idx_sql5));

        delete stmt;
    }
    delete idx_stmt;
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    IdxSqlRows2.rewind();
    IdxSqlRows3.rewind();
    IdxSqlRows4.rewind();
    IdxSqlRows5.rewind();
    IdxSqlRows6.rewind();
    return 1;
}

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
    dgt_schar org3[512];
    dgt_schar org4[512];
} pc_type_pk_fk_sql;

dgt_sint32 PccOraScriptBuilder::prepareCtInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    CheckSqlRows.reset();
    //
    // Not Null Encryption Column`s check constraint sql create
    //
    sprintf(sql_text,
            "select "
            "c.table_name,c.renamed_tab_name,b.column_name,b.renamed_col_name "
            "from pct_enc_col_ct a, pct_enc_column b, pct_enc_table c "
            "where a.enc_col_id = b.enc_col_id "
            "and   b.enc_tab_id = c.enc_tab_id "
            "and   a.enc_tab_id=%lld "
            "and   getname(a.search_condition) like '%%IS NOT NULL%%' ",
            TabInfo.enc_tab_id);
    //"and   a.status = 1",TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_check_row* check_row_tmp;
    pc_type_check_sql check_sql;
    memset(&check_sql, 0, sizeof(pc_type_check_sql));
    while ((check_row_tmp = (pc_type_check_row*)sql_stmt->fetch())) {
        CheckSqlRows.add();
        CheckSqlRows.next();
        if (TabInfo.enc_type == 0) {
            if (TabInfo.init_enc_type >= 1) {
                sprintf(check_sql.org1,
                        "alter table %s.petra_%lld modify %s not null",
                        SchemaName, TabInfo.enc_tab_id,
                        check_row_tmp->column_name);
                sprintf(check_sql.enc1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
            } else {
                sprintf(check_sql.org1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
                sprintf(check_sql.org2, "alter table %s.%s modify %s null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
                sprintf(check_sql.enc1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
                sprintf(check_sql.enc2, "alter table %s.%s modify %s null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
            }
        } else {
            if (TabInfo.init_enc_type >= 1) {
                sprintf(check_sql.org1,
                        "alter table %s.petra_%lld modify %s not null",
                        SchemaName, TabInfo.enc_tab_id,
                        check_row_tmp->column_name);
                sprintf(check_sql.enc1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.renamed_tab_name,
                        check_row_tmp->column_name);
            } else {
                sprintf(check_sql.org1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.table_name,
                        check_row_tmp->column_name);
                sprintf(check_sql.org2, "alter table %s.%s modify %s null",
                        SchemaName, TabInfo.table_name,
                        check_row_tmp->column_name);
                sprintf(check_sql.enc1, "alter table %s.%s modify %s not null",
                        SchemaName, TabInfo.table_name,
                        check_row_tmp->renamed_col_name);
                sprintf(check_sql.enc2, "alter table %s.%s modify %s null",
                        SchemaName, TabInfo.table_name,
                        check_row_tmp->renamed_col_name);
            }
        }
        memcpy(CheckSqlRows.data(), &check_sql, sizeof(pc_type_check_sql));
    }
    delete sql_stmt;
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    CheckSqlRows.rewind();

    //
    // for using trigger (enc_column`s check constraint)
    //
    CheckTrgRows.reset();
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select a.search_condition, b.default "
            "from pct_enc_col_ct a, pct_enc_column b, pct_enc_table c "
            "where a.enc_col_id = b.enc_col_id "
            "and   b.enc_tab_id = c.enc_tab_id "
            "and   a.enc_tab_id = %lld "
            "and   a.status =1 "
            "and   getname(a.search_condition) != '' "
            "and   a.constraint_type =3",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    typedef struct {
        dgt_sint64 search_condition;
        dgt_sint64 default_val;
    } type_check;
    typedef struct {
        dgt_schar search_condition[4000];
        dgt_schar default_val[4000];
    } check_st;

    type_check* tmp_search = 0;
    check_st st_search;
    while ((tmp_search = (type_check*)sql_stmt->fetch())) {
        dgt_sint32 i = 0;
        memset(&st_search, 0, sizeof(check_st));
        dgt_schar tmp_st_con[4000];
        memset(tmp_st_con, 0, 4000);
        sprintf(tmp_st_con, "%s",
                PetraNamePool->getNameString(tmp_search->search_condition));
        sprintf(st_search.default_val, "%s",
                PetraNamePool->getNameString(tmp_search->default_val));
        //
        // modified by mwpark 2020.05.06
        // strcpy issue
        // Copy string
        // Copies the C string pointed by source into the array pointed by
        // destination, including the terminating null character.To avoid
        // overflows, the size of the array pointed by destination shall be long
        // enough to contain the same C string as source (including the
        // terminating null character), and should not overlap in memory with
        // source.
        //
#if 0
                while (st_search.search_condition[i]) {
                        if( st_search.search_condition[i] == '"' ) {
                                strcpy( st_search.search_condition+i, st_search.search_condition+i+1 );
                        }
                        i++;
                }
                DgcWorker::PLOG.tprintf(0,"st_search.search_condition[%s]\n",st_search.search_condition);
#else
        dgt_sint32 j = 0;
        while (tmp_st_con[i]) {
            if (tmp_st_con[i] == '"') {
            } else {
                st_search.search_condition[j] = tmp_st_con[i];
                j++;
            }
            i++;
        }
#endif
        CheckTrgRows.add();
        CheckTrgRows.next();
        memcpy(CheckTrgRows.data(), &st_search, sizeof(check_st));
    }

    delete sql_stmt;
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
    CheckTrgRows.rewind();
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
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
    pc_type_pk_fk_sql pkfkSql;
    memset(&pkfkSql, 0, sizeof(pc_type_pk_fk_sql));
    FkSqlRows.reset();
    PkSqlRows.reset();

    if (IsPkFk == 1) {
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
                    "d.enc_type, d.keep_org_tab_flag "
                    "from ceea_enc_col_ct a, ceea_enc_column b, ceea_enc_table "
                    "c, pct_enc_table d "
                    "where a.enc_col_id = b.enc_col_id "
                    "and   a.enc_tab_id = c.enc_tab_id "
                    "and   c.enc_tab_id = d.enc_tab_id "
                    "and   a.enc_tab_id=%lld "
                    "and   a.constraint_type=1 "
                    "order by a.position",
                    row_ptr->enc_tab_id);

            dgt_sint32 ispkfk_tab = 0;
            if (TabInfo.enc_tab_id == row_ptr->enc_tab_id) ispkfk_tab = 1;

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
                // pc_type_pk_row refpk;
                seq++;
                is_fetch = 1;
                if (seq == 1) {
#if 0
					sprintf(pkfkSql.org1,"alter table %s.%s rename constraint %s to %s"
							,PetraNamePool->getNameString(pk_row->schema_name)
							,PetraNamePool->getNameString(pk_row->table_name)
							,PetraNamePool->getNameString(pk_row->constraint_name)
							,PetraNamePool->getNameString(pk_row->renamed_constraint_name));
					if (TabInfo.enc_type == 0) {
						sprintf(pkfkSql.org2,"alter table %s.%s rename constraint %s to %s"
							,PetraNamePool->getNameString(pk_row->schema_name)
							,PetraNamePool->getNameString(pk_row->renamed_tab_name)
							,PetraNamePool->getNameString(pk_row->constraint_name)
							,PetraNamePool->getNameString(pk_row->renamed_constraint_name));
					} else {
						sprintf(pkfkSql.org2,"alter table %s.%s rename constraint %s to %s"
							,PetraNamePool->getNameString(pk_row->schema_name)
							,PetraNamePool->getNameString(pk_row->table_name)
							,PetraNamePool->getNameString(pk_row->constraint_name)
							,PetraNamePool->getNameString(pk_row->renamed_constraint_name));
					}
#endif

                    if (pk_row->enc_type == 0) {
                        sprintf(
                            pkfkSql.enc1,
                            "alter table %s.%s add constraint %s primary key(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(
                                pk_row->renamed_tab_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                    } else {
                        sprintf(
                            pkfkSql.enc1,
                            "alter table %s.%s add constraint %s primary key(",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(pk_row->table_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name));
                    }
                    sprintf(
                        pkfkSql.org3,
                        "alter table %s.%s add constraint %s primary key(",
                        PetraNamePool->getNameString(pk_row->schema_name),
                        PetraNamePool->getNameString(pk_row->table_name),
                        PetraNamePool->getNameString(pk_row->constraint_name));
                    if (pk_row->keep_org_tab_flag) {
                        sprintf(
                            pkfkSql.enc2,
                            "alter table %s.%s rename constraint %s to %s",
                            PetraNamePool->getNameString(pk_row->schema_name),
                            PetraNamePool->getNameString(
                                pk_row->org_renamed_tab_name),
                            PetraNamePool->getNameString(
                                pk_row->constraint_name),
                            PetraNamePool->getNameString(
                                pk_row->renamed_constraint_name));
                    }
                }
                strcat(pkfkSql.org3,
                       PetraNamePool->getNameString(pk_row->column_name));
                strcat(pkfkSql.org3, ",");
                if (pk_row->status == 1) {
                    strcat(pkfkSql.enc1,
                           PetraNamePool->getNameString(pk_row->column_name));
                } else {
                    strcat(pkfkSql.enc1,
                           PetraNamePool->getNameString(pk_row->column_name));
                }
                strcat(pkfkSql.enc1, ",");
            }
            if (is_fetch) {
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = 0;
                pkfkSql.org3[strlen(pkfkSql.org3) - 1] = 0;
                strcat(pkfkSql.enc1, ")");
                strcat(pkfkSql.org3, ")");
                PkSqlRows.add();
                PkSqlRows.next();
                memcpy(PkSqlRows.data(), &pkfkSql, sizeof(pc_type_pk_fk_sql));
            }
            memset(&pkfkSql, 0, sizeof(pc_type_pk_fk_sql));
            sprintf(sql_text,
                    "select distinct constraint_name "
                    "from ceea_enc_col_ct "
                    "where enc_tab_id = %lld "
                    "and   constraint_type=2 "
                    //"and   status =1",row_ptr->enc_tab_id);
                    ,
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
                memcpy(&constraint_name, constraint_name_tmp,
                       sizeof(dgt_sint64));
                sprintf(
                    sql_text,
                    "select c.schema_name, c.table_name, c.renamed_tab_name, "
                    "b.column_name, b.renamed_col_name, a.constraint_name, "
                    "a.renamed_constraint_name, a.status, a.position, "
                    "a.constraint_type, "
                    "a.ref_pk_owner, a.ref_pk_table, a.ref_pk_column, "
                    "c.org_renamed_tab_name, d.enc_type, d.keep_org_tab_flag "
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
                pkrows.addAttr(DGC_SCHR, 130, "OWNER");
                pkrows.addAttr(DGC_SCHR, 130, "TABLE");
                pkrows.addAttr(DGC_SCHR, 130, "COLUMNE");
                pkrows.addAttr(DGC_SCHR, 130, "rename_table");
                pkrows.addAttr(DGC_SCHR, 130, "rename_column");
                pkrows.addAttr(DGC_UB1, 0, "status");
                pkrows.reset();
                typedef struct {
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
                            sprintf(pkfkSql.enc1,
                                    "alter table %s.%s add constraint %s "
                                    "foreign key(",
                                    PetraNamePool->getNameString(
                                        fk_row->schema_name),
                                    PetraNamePool->getNameString(
                                        fk_row->table_name),
                                    PetraNamePool->getNameString(
                                        fk_row->constraint_name));
                        }
                        sprintf(
                            pkfkSql.org3,
                            "alter table %s.%s add constraint %s foreign key(",
                            PetraNamePool->getNameString(fk_row->schema_name),
                            PetraNamePool->getNameString(fk_row->table_name),
                            PetraNamePool->getNameString(
                                fk_row->constraint_name));
                        if (fk_row->keep_org_tab_flag) {
                            sprintf(
                                pkfkSql.enc2,
                                "alter table %s.%s rename constraint %s to %s",
                                PetraNamePool->getNameString(
                                    fk_row->schema_name),
                                PetraNamePool->getNameString(
                                    fk_row->org_renamed_tab_name),
                                PetraNamePool->getNameString(
                                    fk_row->constraint_name),
                                PetraNamePool->getNameString(
                                    fk_row->renamed_constraint_name));
                        }
                    }
                    strcat(pkfkSql.org3,
                           PetraNamePool->getNameString(fk_row->column_name));
                    strcat(pkfkSql.org3, ",");
                    if (fk_row->status == 1) {
                        strcat(pkfkSql.enc1, PetraNamePool->getNameString(
                                                 fk_row->column_name));
                    } else {
                        strcat(pkfkSql.enc1, PetraNamePool->getNameString(
                                                 fk_row->column_name));
                    }
                    strcat(pkfkSql.enc1, ",");
                    pkrows.add();
                    pkrows.next();
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
                    dgt_schar stext[2048];
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
                    DgcExcept* e = EXCEPTnC;
                    delete s_stmt;
                    memcpy(pkrows.data(), &pktmp, sizeof(pktmp));
                }
                delete fk_stmt;
                pkrows.rewind();
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = 0;
                pkfkSql.org3[strlen(pkfkSql.org3) - 1] = 0;
                strcat(pkfkSql.enc1, ") references ");
                strcat(pkfkSql.org3, ") references ");
                pk_tmp* pk_ptr = 0;
                seq = 0;
                while (pkrows.next()) {
                    seq++;
                    pk_ptr = (pk_tmp*)pkrows.data();
                    if (seq == 1) {
                        dgt_schar tmpbuf[128];
                        memset(tmpbuf, 0, 128);
                        sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                pk_ptr->table, pk_ptr->column);
                        strcat(pkfkSql.org3, tmpbuf);
                        memset(tmpbuf, 0, 128);
                        if (pk_ptr->status == 1) {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->renamed_table, pk_ptr->column);
                        } else {
                            sprintf(tmpbuf, "%s.%s(%s,", pk_ptr->owner,
                                    pk_ptr->table, pk_ptr->column);
                        }
                        strcat(pkfkSql.enc1, tmpbuf);
                    } else {
                        strcat(pkfkSql.org3, pk_ptr->column);
                        strcat(pkfkSql.org3, ",");
                        if (pk_ptr->status == 1) {
                            strcat(pkfkSql.enc1, pk_ptr->column);
                            strcat(pkfkSql.enc1, ",");
                        } else {
                            strcat(pkfkSql.enc1, pk_ptr->column);
                            strcat(pkfkSql.enc1, ",");
                        }
                    }
                }
                pkfkSql.org3[strlen(pkfkSql.org3) - 1] = 0;
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = 0;
                // 22.02.08 added by mwpark
                // remove enable novalidate
                strcat(pkfkSql.org3, ")");
                strcat(pkfkSql.enc1, ")");
                FkSqlRows.add();
                FkSqlRows.next();
                memcpy(FkSqlRows.data(), &pkfkSql, sizeof(pc_type_pk_fk_sql));
            }
            delete fk_sql_stmt;
            e = EXCEPTnC;
            if (e) {
                delete e;
            }
        }
        delete sql_stmt;
        DgcExcept* e = EXCEPTnC;
        if (e) {
            delete e;
        }
    }
    PkSqlRows.rewind();
    FkSqlRows.rewind();
    return 1;
}

typedef struct {
    dgt_schar col_name[130];
    dgt_uint8 status;
    dgt_uint32 position;
    dgt_uint8 constraint_type;
    dgt_sint64 constraint_name;
    dgt_sint64 renamed_constraint_name;
} pc_type_pksql2;

typedef struct {
    dgt_schar col_name[130];
    dgt_sint64 ref_pk_owner;
    dgt_sint64 ref_pk_table;
    dgt_sint64 ref_pk_column;
    dgt_uint8 status;
    dgt_uint32 position;
    dgt_sint64 constraint_name;
    dgt_sint64 renamed_constraint_name;
} pc_type_fksql2;

typedef struct {
    dgt_schar col_name[130];
    dgt_schar renamed_col_name[130];
    dgt_schar search_condition[4000];
    dgt_uint8 status;
} pc_type_checksql2;

typedef struct {
    dgt_sint64 constraint_name;
    dgt_sint64 schema_name;
    dgt_sint64 table_name;
    dgt_sint64 column_name;
    dgt_sint64 ref_owner;
    dgt_sint64 ref_table;
    dgt_sint64 ref_column;
    dgt_sint32 position;
} pc_type_def_fksql2;

dgt_sint32 PccOraScriptBuilder::prepareCt2Info() throw(DgcExcept) {
    //
    // new table encryption mode (setting pksql,fksql,checksql)
    //
    DefFkDropSqlRows.reset();   // enc table`s dependeny foreign key(drop)
    DefFkDropSqlRows2.reset();  // non enc table`s dependeny foreign key(drop)
    DefFkCreSqlRows2
        .reset();  // non enc column`s dependeny foreign key in step2
    DefFkCreSqlRows3
        .reset();  // non enc column`s dependeny foreign key in reverse_step2

    //
    // pksql create
    //
#if 0
	dgt_schar sql_text[2048];
	memset(sql_text,0,2048);
	sprintf(sql_text,
"select b.column_name,b.status, a.position, a.constraint_type, a.constraint_name, a.renamed_constraint_name "
"from   pct_enc_col_ct a, pct_enc_column b "
"where  a.enc_col_id = b.enc_col_id "
"and    a.constraint_type =1 "
"and    a.enc_tab_id=%lld "
"order by a.position",TabInfo.enc_tab_id);
	DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	pc_type_pksql2* pksql2_tmp=0;
	dgt_sint32 fetch_count=0;
	dgt_sint32 enc_col_flag=0;
	dgt_schar rename_pksql[512];
	dgt_schar rename_pksql2[512];
	dgt_schar pksql[512];
	dgt_schar pksql2[512];
	memset(rename_pksql,0,512);
	memset(rename_pksql2,0,512);
	memset(pksql,0,512);
	memset(pksql2,0,512);

	dgt_sint32 seq=0;
	while ((pksql2_tmp=(pc_type_pksql2*)sql_stmt->fetch())) {
		if (pksql2_tmp->status == 1) {
			enc_col_flag=1;
		}
		if (seq == 0) {
			sprintf(rename_pksql,"alter table %s.%s rename constraint %s to %s",SchemaName,TabInfo.table_name,
											 PetraNamePool->getNameString(pksql2_tmp->constraint_name),
											 PetraNamePool->getNameString(pksql2_tmp->renamed_constraint_name)); 
			if (TabInfo.enc_type == 0) {
				sprintf(rename_pksql2,"alter table %s.%s rename constraint %s to %s",SchemaName,TabInfo.renamed_tab_name,
											PetraNamePool->getNameString(pksql2_tmp->constraint_name),
                                                                                        PetraNamePool->getNameString(pksql2_tmp->renamed_constraint_name)); 
			} else {
				sprintf(rename_pksql2,"alter table %s.%s rename constraint %s to %s",SchemaName,TabInfo.table_name,
											PetraNamePool->getNameString(pksql2_tmp->constraint_name),
                                                                                        PetraNamePool->getNameString(pksql2_tmp->renamed_constraint_name)); 
			}
			sprintf(pksql,"alter table %s.%s add constraint %s primary key(",SchemaName,TabInfo.renamed_tab_name,
											 PetraNamePool->getNameString(pksql2_tmp->constraint_name)); 
			sprintf(pksql2,"alter table %s.%s_%lld add constraint %s primary key(",SchemaName,"petra",TabInfo.enc_tab_id,
											 PetraNamePool->getNameString(pksql2_tmp->constraint_name)); 
		}
		fetch_count++;
		strcat(pksql,pksql2_tmp->col_name);
		strcat(pksql,",");
		strcat(pksql2,pksql2_tmp->col_name);
		strcat(pksql2,",");
		seq++;
	}
	delete sql_stmt;
	DgcExcept* e=EXCEPTnC;
	if (e) {
		delete e;
	}
	pksql[strlen(pksql)-1]=0;
	pksql2[strlen(pksql2)-1]=0;
	strcat(pksql,") enable novalidate");
	strcat(pksql2,") enable novalidate");
	if (enc_col_flag == 0) {
		if (fetch_count > 0) {
			PkSqlRows2.add();
			PkSqlRows2.next();
			memcpy(PkSqlRows2.data(),rename_pksql,strlen(rename_pksql));
			PkSqlRows2.add();
			PkSqlRows2.next();
			memcpy(PkSqlRows2.data(),pksql,strlen(pksql));
			PkSqlRows3.add();
                        PkSqlRows3.next();
                        memcpy(PkSqlRows3.data(),rename_pksql2,strlen(rename_pksql2));
			PkSqlRows3.add();
			PkSqlRows3.next();
			memcpy(PkSqlRows3.data(),pksql2,strlen(pksql2));
		}
	}
#endif
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
            dgt_schar enc_sql[512];
            dgt_schar org_sql[512];
        } def_fk_enc_table;
        def_fk_enc_table def_enc_sql;
        dgt_sint32 enc_tab_flag = 0;
        if ((tmp_result = (dgt_sint64*)searchStmt->fetch())) {
            enc_tab_flag = 1;
        }
        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select constraint_name, a.schema_name, a.table_name, "
                "b.column_name, c.ref_pk_owner, c.ref_pk_table, "
                "c.ref_pk_column, c.position "
                "from   ceea_table a, "
                "ceea_column b, "
                "ceea_col_ct c "
                "where a.enc_tab_id = b.enc_tab_id "
                "and   b.enc_col_id = c.enc_col_id "
                "and   a.db_id = %lld "
                "and   c.constraint_name = %lld "
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
        dgt_schar dropSql[512];
        dgt_schar createSql[512];
        dgt_schar createSql2[512];
        dgt_schar refSql[512];
        dgt_schar refSql2[512];
        dgt_schar pk_col[512];
        dgt_schar fk_col[512];
        memset(pk_col, 0, 512);
        memset(fk_col, 0, 512);
        memset(dropSql, 0, 512);
        dgt_sint32 fetch = 0;
        while ((def_fksql = (pc_type_def_fksql2*)fkStmt->fetch())) {
            fetch = 1;
            if (enc_tab_flag == 0) {
                memset(createSql, 0, 512);
                memset(createSql2, 0, 512);
                memset(dropSql, 0, 512);
                memset(refSql, 0, 512);
                memset(refSql2, 0, 512);
                sprintf(
                    dropSql, "alter table %s.%s drop constraint %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(
                    createSql,
                    "alter table %s.%s add constraint %s foreign key(",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(
                    createSql2,
                    "alter table %s.%s add constraint %s foreign key(",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                sprintf(refSql, " references %s.%s(", SchemaName,
                        TabInfo.renamed_tab_name);
                sprintf(refSql2, " references %s.%s(", SchemaName,
                        TabInfo.table_name);
                strcat(fk_col,
                       PetraNamePool->getNameString(def_fksql->column_name));
                strcat(fk_col, ",");
                strcat(pk_col,
                       PetraNamePool->getNameString(def_fksql->ref_column));
                strcat(pk_col, ",");
            } else {
                memset(&def_enc_sql, 0, sizeof(def_fk_enc_table));
                sprintf(
                    def_enc_sql.enc_sql, "alter table %s.%s drop constraint %s",
                    PetraNamePool->getNameString(def_fksql->schema_name),
                    PetraNamePool->getNameString(def_fksql->table_name),
                    PetraNamePool->getNameString(def_fksql->constraint_name));
                if (TabInfo.enc_type == 0) {
                    sprintf(
                        def_enc_sql.org_sql,
                        "alter table %s.%s$$ drop constraint %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                } else {
                    sprintf(
                        def_enc_sql.org_sql,
                        "alter table %s.%s drop constraint %s",
                        PetraNamePool->getNameString(def_fksql->schema_name),
                        PetraNamePool->getNameString(def_fksql->table_name),
                        PetraNamePool->getNameString(
                            def_fksql->constraint_name));
                }
            }
        }
        if (fetch == 1) {
            if (enc_tab_flag == 0) {
                DefFkDropSqlRows2.add();
                DefFkDropSqlRows2.next();
                memcpy(DefFkDropSqlRows2.data(), dropSql, strlen(dropSql));
                DefFkCreSqlRows2.add();
                DefFkCreSqlRows2.next();
                fk_col[strlen(fk_col) - 1] = ')';
                pk_col[strlen(pk_col) - 1] = ')';
                strcat(createSql, fk_col);
                strcat(createSql, refSql);
                strcat(createSql, pk_col);
                //				strcat(createSql," enable novalidate");
                memcpy(DefFkCreSqlRows2.data(), createSql, strlen(createSql));
                DefFkCreSqlRows3.add();
                DefFkCreSqlRows3.next();
                strcat(createSql2, fk_col);
                strcat(createSql2, refSql2);
                strcat(createSql2, pk_col);
                //				strcat(createSql2," enable novalidate");
                memcpy(DefFkCreSqlRows3.data(), createSql2, strlen(createSql2));
            } else {
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
    //
    // fksql create (if non encryption column is fk then create fksql)
    //
#if 0
	memset(sql_text,0,2048);
	sprintf(sql_text,
"select distinct constraint_name "
"from   pct_enc_col_ct "
"where  constraint_type =2 "
"and    enc_tab_id=%lld",TabInfo.enc_tab_id);
	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	const_name=0;
	dgt_sint32 enc_table_flag = 0;
	while ((const_name=(dgt_sint64*)sql_stmt->fetch())) {
                //
                // if dependecy fk is encryption table then table_name -> enc_table_name
                //
                memset(sql_text,0,2048);
                sprintf(sql_text,
"select ref_pk_owner,ref_pk_table,ref_pk_column "
"from pct_enc_col_ct a, pct_enc_schema b, pct_enc_table c , pct_enc_column d, pt_database e "
"where b.schema_id = c.schema_id "
"and   c.enc_tab_id = d.enc_tab_id "
"and   b.db_id = e.db_id "
"and   e.db_id = %lld "
"and   getname(a.ref_pk_owner) = b.schema_name "
"and   getname(a.ref_pk_table) = c.table_name "
"and   a.constraint_name = %lld",Dbid, *const_name);
                DgcSqlStmt* searchStmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                if (searchStmt == 0 || searchStmt->execute() < 0) {
                        DgcExcept*      e=EXCEPTnC;
                        delete sql_stmt;
                        delete searchStmt;
                        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                }
                dgt_sint64* tmp_result;
                if ((tmp_result=(dgt_sint64*)searchStmt->fetch())) {
			enc_table_flag=1;
                }


		memset(sql_text,0,2048);
		sprintf(sql_text,
"select b.column_name,a.ref_pk_owner,a.ref_pk_table,a.ref_pk_column,b.status,a.position, a.constraint_name, a.renamed_constraint_name "
"from   pct_enc_col_ct a, pct_enc_column b "
"where  a.enc_col_id = b.enc_col_id "
"and    a.enc_tab_id = %lld "
"and    constraint_name=%lld "
"order by a.position",TabInfo.enc_tab_id,*const_name);
		DgcSqlStmt* fk_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
		if (fk_stmt == 0 || fk_stmt->execute() < 0) {
			DgcExcept*      e=EXCEPTnC;
			delete fk_stmt;
			RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
		}
		dgt_schar rename_fksql[256];
		dgt_schar rename_fksql2[256];
		dgt_schar fksql[256];
		dgt_schar fksql2[256];
		dgt_schar refsql[256];
		dgt_schar refsql2[256];
		memset(rename_fksql,0,256);
		memset(rename_fksql2,0,256);
		memset(fksql,0,256);
		memset(fksql2,0,256);
		memset(refsql,0,256);
		memset(refsql2,0,256);
		sprintf(refsql," references ");
		sprintf(refsql2," references ");
		dgt_sint32 fetch_count=0;
		dgt_sint32 enc_col_flag=0;
		pc_type_fksql2* fksql2_tmp=0;
		dgt_sint32 seq=0;
		while ((fksql2_tmp=(pc_type_fksql2*)fk_stmt->fetch())) {
			if (fksql2_tmp->status == 1) {
				enc_col_flag=1;
			}
			if (seq == 0) {
#if 0
				sprintf(rename_fksql,"alter table %s.%s drop constraint %s", SchemaName,TabInfo.table_name,
											PetraNamePool->getNameString(fksql2_tmp->constraint_name));
				if (TabInfo.enc_type == 0) {
					sprintf(rename_fksql2,"alter table %s.%s drop constraint %s", SchemaName,TabInfo.renamed_tab_name,
											PetraNamePool->getNameString(fksql2_tmp->constraint_name));
				} else {
					sprintf(rename_fksql2,"alter table %s.%s drop constraint %s", SchemaName,TabInfo.table_name,
											PetraNamePool->getNameString(fksql2_tmp->constraint_name));
				}
#endif
				sprintf(fksql,"alter table %s.%s add constraint %s foreign key(",SchemaName,TabInfo.renamed_tab_name,
												 PetraNamePool->getNameString(fksql2_tmp->constraint_name));
				sprintf(fksql2,"alter table %s.%s_%lld add constraint %s foreign key(",SchemaName,"petra",TabInfo.enc_tab_id,
												 PetraNamePool->getNameString(fksql2_tmp->constraint_name));
			}
			fetch_count++;
			strcat(fksql,fksql2_tmp->col_name);
			strcat(fksql,",");
			strcat(fksql2,fksql2_tmp->col_name);
			strcat(fksql2,",");
			if (fetch_count == 1) {
				strcat(refsql,PetraNamePool->getNameString(fksql2_tmp->ref_pk_owner));
				strcat(refsql,".");
				strcat(refsql,PetraNamePool->getNameString(fksql2_tmp->ref_pk_table));
				if (enc_table_flag == 1) strcat(refsql,"$$(");
				else strcat(refsql,"(");
				strcat(refsql,PetraNamePool->getNameString(fksql2_tmp->ref_pk_column));
				strcat(refsql,",");
				strcat(refsql2,PetraNamePool->getNameString(fksql2_tmp->ref_pk_owner));
				strcat(refsql2,".");
				strcat(refsql2,PetraNamePool->getNameString(fksql2_tmp->ref_pk_table));
				strcat(refsql2,"(");
				strcat(refsql2,PetraNamePool->getNameString(fksql2_tmp->ref_pk_column));
				strcat(refsql2,",");
			} else {
				strcat(refsql,PetraNamePool->getNameString(fksql2_tmp->ref_pk_column));
				strcat(refsql,",");
				strcat(refsql2,PetraNamePool->getNameString(fksql2_tmp->ref_pk_column));
				strcat(refsql2,",");
			}
			seq++;
		}
		delete fk_stmt;
		e=EXCEPTnC;
		if (e) {
			delete e;
		}
		fksql[strlen(fksql)-1]=0;
		fksql2[strlen(fksql2)-1]=0;
		refsql[strlen(refsql)-1]=0;
		refsql2[strlen(refsql2)-1]=0;
		strcat(fksql,")");
		strcat(fksql2,")");
		strcat(refsql,")");
		strcat(refsql2,")");
		strcat(fksql,refsql);
		strcat(fksql2,refsql2);
		if (enc_col_flag == 0) {
			if (fetch_count > 0) {
				FkSqlRows2.add();
				FkSqlRows2.next();
				memcpy(FkSqlRows2.data(),rename_fksql,strlen(rename_fksql));
				FkSqlRows2.add();
				FkSqlRows2.next();
				memcpy(FkSqlRows2.data(),fksql,strlen(fksql));

				FkSqlRows3.add();
				FkSqlRows3.next();
				memcpy(FkSqlRows3.data(),rename_fksql2,strlen(rename_fksql2));
				FkSqlRows3.add();
				FkSqlRows3.next();
				memcpy(FkSqlRows3.data(),fksql2,strlen(fksql2));
			}
		}
	}
        delete sql_stmt;
        e=EXCEPTnC;
        if (e) {
                delete e;
        }
#endif

    //
    // unique constraint create (enc_column and non enc_column)
    //
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select distinct constraint_name "
            "from   pct_enc_col_ct "
            "where  constraint_type =4 "
            "and    enc_tab_id=%lld",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    const_name = 0;
    while ((const_name = (dgt_sint64*)sql_stmt->fetch())) {
        memset(sql_text, 0, 2048);
        sprintf(
            sql_text,
            "select b.column_name, b.renamed_col_name, b.status, a.position "
            "from   pct_enc_col_ct a, pct_enc_column b "
            "where  a.enc_col_id = b.enc_col_id "
            "and    a.enc_tab_id = %lld "
            "and    constraint_name = %lld "
            "order by a.position",
            TabInfo.enc_tab_id, *const_name);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        typedef struct {
            dgt_schar column_name[130];
            dgt_schar renamed_col_name[130];
            dgt_uint8 status;
            dgt_uint8 position;
        } uniq_type;
        uniq_type* uniq_tmp = 0;
        dgt_sint32 seq = 1;
        dgt_schar uniqueSql[512];
        dgt_schar uniqueSql2[512];
        memset(uniqueSql, 0, 512);
        memset(uniqueSql2, 0, 512);
        while ((uniq_tmp = (uniq_type*)sql_stmt->fetch())) {
            if (seq == 1) {
                if (uniq_tmp->status == 0) {
                    sprintf(uniqueSql, "alter table %s.%s add unique(%s",
                            SchemaName, TabInfo.renamed_tab_name,
                            uniq_tmp->column_name);
                    sprintf(uniqueSql2, "alter table %s.%s_%lld add unique(%s",
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            uniq_tmp->column_name);
                } else {
                    sprintf(uniqueSql, "alter table %s.%s add unique(%s",
                            SchemaName, TabInfo.renamed_tab_name,
                            uniq_tmp->column_name);
                    sprintf(uniqueSql2, "alter table %s.%s_%lld add unique(%s",
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            uniq_tmp->column_name);
                }
            } else {
                if (uniq_tmp->status == 0) {
                    strcat(uniqueSql, ", ");
                    strcat(uniqueSql, uniq_tmp->column_name);
                    strcat(uniqueSql2, ", ");
                    strcat(uniqueSql2, uniq_tmp->column_name);
                } else {
                    strcat(uniqueSql, ", ");
                    strcat(uniqueSql, uniq_tmp->column_name);
                    strcat(uniqueSql2, ", ");
                    strcat(uniqueSql2, uniq_tmp->column_name);
                }
            }
            seq++;
        }
        strcat(uniqueSql, ")");
        strcat(uniqueSql2, ")");
        UniqueSqlRows1.add();
        UniqueSqlRows1.next();
        memcpy(UniqueSqlRows1.data(), uniqueSql, strlen(uniqueSql));
        UniqueSqlRows2.add();
        UniqueSqlRows2.next();
        memcpy(UniqueSqlRows2.data(), uniqueSql2, strlen(uniqueSql2));
        delete sql_stmt;
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
    DefFkDropSqlRows2.rewind();
    DefFkCreSqlRows2.rewind();
    UniqueSqlRows1.rewind();
    UniqueSqlRows2.rewind();
    return 1;
}

typedef struct {
    dgt_schar create_sql_id[1024];
    dgt_schar drop_sql_id[1024];
} pc_type_synonym_sql;

dgt_sint32 PccOraScriptBuilder::prepareSynonymInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    sprintf(sql_text,
            "select * "
            "from pct_enc_synonym where enc_tab_id=%lld",
            TabInfo.enc_tab_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pct_type_enc_synonym* syn_info_tmp;
    SynonymSqlRows.reset();
    pc_type_synonym_sql syn_sql;
    while ((syn_info_tmp = (pct_type_enc_synonym*)sql_stmt->fetch())) {
        dgt_schar creSql[1024];
        dgt_schar dropSql[1024];
        memset(creSql, 0, 1024);
        memset(dropSql, 0, 1024);
        sprintf(creSql, "create synonym %s.\"%s\" for \"%s\".\"%s\"",
                PetraNamePool->getNameString(syn_info_tmp->owner),
                PetraNamePool->getNameString(syn_info_tmp->synonym_name),
                SchemaName, TabInfo.table_name);
        sprintf(dropSql, "drop synonym %s.\"%s\"",
                PetraNamePool->getNameString(syn_info_tmp->owner),
                PetraNamePool->getNameString(syn_info_tmp->synonym_name));
        memset(&syn_sql, 0, sizeof(pc_type_synonym_sql));
        memcpy(syn_sql.create_sql_id, creSql, 1024);
        memcpy(syn_sql.drop_sql_id, dropSql, 1024);
        SynonymSqlRows.add();
        SynonymSqlRows.next();
        memcpy(SynonymSqlRows.data(), &syn_sql, sizeof(pc_type_synonym_sql));
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    if (e) {
        delete e;
    }
    SynonymSqlRows.rewind();
    return 1;
}

dgt_schar* PccOraScriptBuilder::getFname(
    dgt_schar* col_name, dgt_uint8 fun_type,
    dgt_uint8 instead_of_trigger_flag) throw(DgcExcept) {
    memset(fname, 0, 256);
    ColInfoRows2.rewind();
    pc_type_col_info* col_info;
    //
    // fun_type : 1=encrypt function name
    //            2=decrypt function name
    //            3=ophuek function name
    //
    if (fun_type == 1) {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            if (!strcasecmp(col_info->col_name, col_name)) {
                //                        if (col_info->enc_col_id==enc_col_id)
                //                        {
                if (instead_of_trigger_flag) {
                    if (col_info->col_default) {
                        if (!strcasecmp(col_info->data_type, "date") ||
                            !strcasecmp(col_info->data_type, "timestamp")) {
                            sprintf(
                                fname,
                                "pls_encrypt_b64_id_date(nvl(:new.%s,%s),%lld)",
                                col_info->col_name,
                                PetraNamePool->getNameString(
                                    col_info->col_default),
                                col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "raw")) {
                            sprintf(
                                fname,
                                "pls_encrypt_b64_id_raw(nvl(:new.%s,%s),%lld)",
                                col_info->col_name,
                                PetraNamePool->getNameString(
                                    col_info->col_default),
                                col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "clob")) {
                            sprintf(fname, "pls_encrypt_clob(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "blob")) {
                            sprintf(fname, "pls_encrypt_blob(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "long")) {
                            sprintf(fname,
                                    "pls_encrypt_clob(nvl(:new.%s,%s),%lld)",
                                    col_info->col_name,
                                    PetraNamePool->getNameString(
                                        col_info->col_default),
                                    col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type,
                                               "long raw")) {
                            sprintf(fname,
                                    "pls_encrypt_blob(nvl(:new.%s,%s),%lld)",
                                    col_info->col_name,
                                    PetraNamePool->getNameString(
                                        col_info->col_default),
                                    col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "charm")) {
                            if (col_info->coupon_id) {
                                sprintf(fname,
                                        "pls_encrypt_cpn_id(nvl(trim(:new.%s),%"
                                        "s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "pls_encrypt_b64_id(nvl(trim(:new.%s),%"
                                        "s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type, "nchar")) {
                            if (col_info->coupon_id) {
                                sprintf(fname,
                                        "pls_encrypt_cpn_id(nvl(trim(:new.%s),%"
                                        "s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "pls_encrypt_b64_id_n(nvl(trim(:new.%s)"
                                        ",%s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type,
                                               "nvarchar2")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname,
                                    "pls_encrypt_cpn_id(nvl(:new.%s,%s),%lld)",
                                    col_info->col_name,
                                    PetraNamePool->getNameString(
                                        col_info->col_default),
                                    col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "pls_encrypt_b64_id_n(nvl(:new.%s,%s),%"
                                        "lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            }
                        } else {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname,
                                    "pls_encrypt_cpn_id(nvl(:new.%s,%s),%lld)",
                                    col_info->col_name,
                                    PetraNamePool->getNameString(
                                        col_info->col_default),
                                    col_info->enc_col_id);
                            } else {
                                sprintf(
                                    fname,
                                    "pls_encrypt_b64_id(nvl(:new.%s,%s),%lld)",
                                    col_info->col_name,
                                    PetraNamePool->getNameString(
                                        col_info->col_default),
                                    col_info->enc_col_id);
                            }
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "date") ||
                            !strcasecmp(col_info->data_type, "timestamp")) {
                            sprintf(fname,
                                    "pls_encrypt_b64_id_date(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "raw")) {
                            sprintf(fname,
                                    "pls_encrypt_b64_id_raw(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "clob")) {
                            sprintf(fname, "pls_encrypt_clob(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "blob")) {
                            sprintf(fname, "pls_encrypt_blob(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "long")) {
                            sprintf(fname, "pls_encrypt_clob(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type,
                                               "long raw")) {
                            sprintf(fname, "pls_encrypt_blob(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "charm")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname,
                                    "pls_encrypt_cpn_id(trim(:new.%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    fname,
                                    "pls_encrypt_b64_id(trim(:new.%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type, "nchar")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname,
                                    "pls_encrypt_cpn_id(trim(:new.%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    fname,
                                    "pls_encrypt_b64_id_n(trim(:new.%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type,
                                               "nvarchar2")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname, "pls_encrypt_cpn_id(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    fname, "pls_encrypt_b64_id_n(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            }
                        } else {
                            if (col_info->coupon_id) {
                                sprintf(
                                    fname, "pls_encrypt_cpn_id(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    fname, "pls_encrypt_b64_id(:new.%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            }
                        }
                    }
                } else {
                    if (!strcasecmp(col_info->data_type, "date") ||
                        !strcasecmp(col_info->data_type, "timestamp")) {
                        sprintf(fname, "pls_encrypt_b64_id_date(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "raw")) {
                        sprintf(fname, "pls_encrypt_b64_id_raw(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "clob")) {
                        sprintf(fname, "pls_encrypt_clob(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "blob")) {
                        sprintf(fname, "pls_encrypt_blob(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "long")) {
                        sprintf(fname, "pls_encrypt_clob(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "long raw")) {
                        sprintf(fname, "pls_encrypt_blob(%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "charm")) {
                        if (col_info->coupon_id) {
                            sprintf(fname, "pls_encrypt_cpn_id(trim(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname, "pls_encrypt_b64_id(trim(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else if (!strcasecmp(col_info->data_type, "nchar")) {
                        if (col_info->coupon_id) {
                            sprintf(fname, "pls_encrypt_cpn_id(trim(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname,
                                    "pls_encrypt_b64_id_n(trim(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else if (!strcasecmp(col_info->data_type, "nvarchar2")) {
                        if (col_info->coupon_id) {
                            sprintf(fname, "pls_encrypt_cpn_id(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname, "pls_encrypt_b64_id_n(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else {
                        if (col_info->coupon_id) {
                            sprintf(fname, "pls_encrypt_cpn_id(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname, "pls_encrypt_b64_id(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    }
                }
            }
        }
    } else if (fun_type == 2) {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            dgt_schar renamed_col_name[4000];
            memset(renamed_col_name, 0, 4000);
            strncpy(renamed_col_name, col_info->col_name,
                    strlen(col_info->col_name));
            if (!strcasecmp(col_info->col_name, col_name)) {
                // if (col_info->enc_col_id==enc_col_id) {
                if (col_info->normal_idx_flag == 1) {
                    if (!strcasecmp(col_info->data_type, "date") ||
                        !strcasecmp(col_info->data_type, "timestamp")) {
                        sprintf(fname, "pls_idx1_date(%s,%lld)",
                                renamed_col_name, col_info->enc_col_id);
                    } else if (!strcasecmp(col_info->data_type, "number")) {
                        sprintf(fname, "pls_idx1_num(%s,%lld)",
                                renamed_col_name, col_info->enc_col_id);
                    } else {
                        sprintf(fname, "pls_idx1_str(%s,%lld)",
                                renamed_col_name, col_info->enc_col_id);
                    }
                } else {
                    if (TabInfo.cast_flag == 0) {
                        if (!strcasecmp(col_info->data_type, "date") ||
                            !strcasecmp(col_info->data_type, "timestamp")) {
                            sprintf(fname, "pls_decrypt_b64_id_date(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "raw")) {
                            sprintf(fname, "pls_decrypt_b64_id_raw(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "clob") ||
                                   !strcasecmp(col_info->data_type, "long")) {
                            sprintf(fname, "pls_decrypt_clob(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "blob") ||
                                   !strcasecmp(col_info->data_type,
                                               "long raw")) {
                            sprintf(fname, "pls_decrypt_blob(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "number")) {
                            sprintf(fname, "pls_decrypt_b64_id_num(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else {
                            if (col_info->coupon_id) {
                                sprintf(fname, "pls_decrypt_cpn_id(%s,%lld)",
                                        renamed_col_name, col_info->enc_col_id);
                            } else {
                                sprintf(fname, "pls_decrypt_b64_id(%s,%lld)",
                                        renamed_col_name, col_info->enc_col_id);
                            }
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "number")) {
                            if (col_info->data_precision == 0) {
                                sprintf(
                                    fname,
                                    "cast(pls_decrypt_b64_id(%s,%lld) as %s)",
                                    renamed_col_name, col_info->enc_col_id,
                                    col_info->data_type);
                            } else {
                                sprintf(fname,
                                        "cast(pls_decrypt_b64_id(%s,%lld) as "
                                        "%s(%d,%d))",
                                        renamed_col_name, col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_precision,
                                        col_info->data_scale);
                            }
                        } else if (!strcasecmp(col_info->data_type, "char")) {
                            if (col_info->coupon_id) {
                                sprintf(fname,
                                        "cast(pls_decrypt_cpn_id(%s,%lld) as "
                                        "%s(%d))",
                                        renamed_col_name, col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_length);
                            } else {
                                sprintf(fname,
                                        "cast(pls_decrypt_b64_id(%s,%lld) as "
                                        "%s(%d))",
                                        renamed_col_name, col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_length);
                            }
                        } else if (!strcasecmp(col_info->data_type, "date")) {
                            sprintf(fname,
                                    "to_date(pls_decrypt_b64_id(%s,%lld),'"
                                    "YYYYMMDDHH24MISS')",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "raw")) {
                            sprintf(fname,
                                    "cast(pls_decrypt_b64_id_raw(%s,%lld) as "
                                    "%s(%d))",
                                    renamed_col_name, col_info->enc_col_id,
                                    col_info->data_type, col_info->data_length);
                        } else if (!strcasecmp(col_info->data_type, "clob") ||
                                   !strcasecmp(col_info->data_type, "long")) {
                            sprintf(fname, "pls_decrypt_clob(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else if (!strcasecmp(col_info->data_type, "blob") ||
                                   !strcasecmp(col_info->data_type,
                                               "long raw")) {
                            sprintf(fname, "pls_decrypt_blob(%s,%lld)",
                                    renamed_col_name, col_info->enc_col_id);
                        } else {
                            if (col_info->coupon_id) {
                                sprintf(fname,
                                        "cast(pls_decrypt_cpn_id(%s,%lld) as "
                                        "%s(%d))",
                                        renamed_col_name, col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_length);
                            } else {
                                sprintf(fname,
                                        "cast(pls_decrypt_b64_id(%s,%lld) as "
                                        "%s(%d))",
                                        renamed_col_name, col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_length);
                            }
                        }
                    }
                }
            }
        }
    } else {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            if (!strcasecmp(col_info->col_name, col_name)) {
                //	if (col_info->enc_col_id==enc_col_id) {
                if (instead_of_trigger_flag) {
                    if (col_info->col_default) {
                        sprintf(
                            fname, "PLS_OPHUEK_B64(nvl(:new.%s,%s),%lld,0)",
                            col_info->col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->enc_col_id);
                    } else {
                        sprintf(fname, "PLS_OPHUEK_B64(:new.%s,%lld,0)",
                                col_info->col_name, col_info->enc_col_id);
                    }
                } else {
                    sprintf(fname, "PLS_OPHUEK_B64(%s,%lld,0)",
                            col_info->col_name, col_info->enc_col_id);
                }
            }
        }
    }
    return fname;
}

#include "PciCryptoIf.h"

dgt_sint32 PccOraScriptBuilder::insteadOfTrigger(
    dgt_sint8 is_final, dgt_sint32 uniq_flag) throw(DgcExcept) {
    //
    // create a instead-of trigger for the view so for any DML on the view
    // to be reflected on the original table.
    // but the original column is still kepted for emergency recovery.
    //
    //
    // if TabInfo.org_col_name_flag = 1 then use dbms_sql
    // else update all columns
    //
    dgt_uint8 use_dbms_sql = TabInfo.org_col_name_flag;
    *TextBuf = 0;
    dgt_sint32 ver_flag = 1;
    //	if (!strcasecmp(DbVersion,"11g")) ver_flag=1;
    if (TabInfo.user_view_flag == 1 ||
        (TabInfo.double_flag && IdxColRows.numRows() == 0)) {
        sprintf(TextBuf,
                "create or replace trigger %s.%s\ninstead of insert or update "
                "on %s.%s for each row\ndeclare \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.first_view_name);
    } else {
        sprintf(TextBuf,
                "create or replace trigger %s.%s\ninstead of insert or update "
                "on %s.%s for each row\ndeclare \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.second_view_name);
    }

    *TmpBuf = 0;
    if (use_dbms_sql == 1) {
        sprintf(TmpBuf,
                "\n\t v_sql_main varchar2(30000) := null;"
                "\n\t v_sql_set varchar2(30000) := null;"
                "\n\t v_cursor pls_integer;"
                "\n\t v_ret pls_integer;\n");
        strcat(TextBuf, TmpBuf);
        if (TabInfo.keep_org_tab_flag == 2 && IdxColRows.numRows() > 0) {
            *TmpBuf = 0;
            sprintf(TmpBuf,
                    "\n\t v_sql_main2 varchar2(30000) := null;"
                    "\n\t v_sql_set2 varchar2(30000) := null;"
                    "\n\t v_cursor2 pls_integer;"
                    "\n\t v_ret2 pls_integer;\n");
            strcat(TextBuf, TmpBuf);
        }
    }
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    //
    // for 11g trigger (performance issue)
    //
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            *TmpBuf = 0;
            dgt_sint32 enc_len = 0;
            if (!strcasecmp(col_info->data_type, "NUMBER"))
                enc_len = (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATE") ||
                     !strcasecmp(col_info->data_type, "TIMESTAMP"))
                enc_len = 14;
            else if (col_info->multi_byte_flag)
                enc_len = col_info->data_length * 3;
            else
                enc_len = col_info->data_length;
            PCI_Context ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type,
                            col_info->enc_mode, col_info->iv_type,
                            col_info->n2n_flag, col_info->b64_txt_enc_flag,
                            col_info->enc_start_pos, col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            if (col_info->index_type == 1) {
                enc_len += PCI_ophuekLength(col_info->data_length,
                                            PCI_SRC_TYPE_CHAR, 1);
                enc_len += 4;
            }
            if (!strcasecmp(col_info->data_type, "NCHAR") ||
                !strcasecmp(col_info->data_type, "NVARCHAR2")) {
                enc_len = enc_len * 3;
            }
            if (!strcasecmp(col_info->data_type, "BLOB") ||
                !strcasecmp(col_info->data_type, "LONG RAW")) {
                sprintf(TmpBuf, "\t v_%s BLOB;\n", col_info->col_name);
            } else if (!strcasecmp(col_info->data_type, "CLOB") ||
                       !strcasecmp(col_info->data_type, "LONG")) {
                sprintf(TmpBuf, "\t v_%s CLOB;\n", col_info->col_name);
            } else {
                if (col_info->b64_txt_enc_flag &&
                    col_info->b64_txt_enc_flag != 4) {
                    sprintf(TmpBuf, "\t v_%s varchar2(%d);\n",
                            col_info->col_name, enc_len);
                } else {
                    sprintf(TmpBuf, "\t v_%s raw(%d);\n", col_info->col_name,
                            enc_len);
                }
            }
            strcat(TextBuf, TmpBuf);
        }
        *TmpBuf = 0;
        if (use_dbms_sql == 1) {
            sprintf(TmpBuf, "\t v_%d varchar2(1);\n", col_info->column_order);
            strcat(TextBuf, TmpBuf);
        }
    }
    strcat(TextBuf, "begin\n");
    //
    // for check constraint
    //
    CheckTrgRows.rewind();
    typedef struct {
        dgt_schar search_condition[4000];
        dgt_schar default_val[4000];
    } type_check;
    type_check* tmp_search = 0;
    while (CheckTrgRows.next() &&
           (tmp_search = (type_check*)CheckTrgRows.data())) {
        if (strlen(tmp_search->default_val) > 2 &&
            strstr(tmp_search->search_condition, "IS NOT NULL"))
            continue;
        *TmpBuf = 0;
        sprintf(TmpBuf, "\n if not ");
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "( :new.%s )", tmp_search->search_condition);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf,
                " then\n\t raise_application_error(-20001,'%s`s check "
                "constraint violated');\n end if;",
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
    }
    *TmpBuf = 0;
    sprintf(TmpBuf, "\n   if inserting then\n");
    strcat(TextBuf, TmpBuf);
    *TmpBuf = 0;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        *TmpBuf = 0;
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            sprintf(TmpBuf, "\t\t v_%s := %s;\n", col_info->col_name,
                    getFname(col_info->col_name, 1, 1));
            strcat(TextBuf, TmpBuf);
        }
    }
    //
    // dual sync mode (keep_org_tab_flag == 2)
    //
    if (TabInfo.keep_org_tab_flag == 2) {
        *TmpBuf = 0;
        sprintf(TmpBuf, "\tinsert into %s.%s(", SchemaName,
                TabInfo.org_renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ")\n\tvalues(");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->col_default) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "nvl(:new.%s,%s),", col_info->col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, ":new.%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(TmpBuf, ");\n");
        strcat(TextBuf, TmpBuf);
    }
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf, "\tinsert into %s.%s(", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf, "\tinsert into %s.%s(", SchemaName, TabInfo.table_name);
    }
    strcat(TextBuf, TmpBuf);

    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3 && is_final) continue;
        *TmpBuf = 0;
        sprintf(TmpBuf, "%s,", col_info->col_name);
        strcat(TextBuf, TmpBuf);
    }
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    strcat(TextBuf, ")\n\tvalues(");
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3 && is_final) continue;
        if (col_info->col_default) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "nvl(:new.%s,%s),", col_info->col_name,
                    PetraNamePool->getNameString(col_info->col_default));
            strcat(TextBuf, TmpBuf);
        } else {
            *TmpBuf = 0;
            sprintf(TmpBuf, ":new.%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
    }
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            dgt_sint32 idx_flag = col_info->index_type;
            *TmpBuf = 0;
            sprintf(TmpBuf, "v_%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    sprintf(TmpBuf, ");\n   elsif updating then");
    strcat(TextBuf, TmpBuf);

    if (use_dbms_sql == 1) {
        *TmpBuf = 0;
        if (TabInfo.enc_type == 0) {
            sprintf(TmpBuf, "\n\t\tv_sql_main := 'update %s.%s SET ';",
                    SchemaName, TabInfo.renamed_tab_name);
        } else {
            sprintf(TmpBuf, "\n\t\tv_sql_main := 'update %s.%s SET ';",
                    SchemaName, TabInfo.table_name);
        }
        strcat(TextBuf, TmpBuf);
        if (TabInfo.keep_org_tab_flag == 2 && IdxColRows.numRows() > 0) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\t\tv_sql_main2 := 'update %s.%s SET ';",
                    SchemaName, TabInfo.org_renamed_tab_name);
            strcat(TextBuf, TmpBuf);
        }
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3) continue;
            *TmpBuf = 0;
            if (TabInfo.keep_org_tab_flag == 2 && IdxColRows.numRows() > 0) {
                sprintf(TmpBuf,
                        "\n\t\tif updating('%s') then "
                        "\n\t\t\t v_%d := 'Y'; "
                        "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
                        "\n\t\t\t v_sql_set2 := v_sql_set2 || '%s=:d%d,';",
                        col_info->col_name, col_info->column_order,
                        col_info->col_name, col_info->column_order,
                        col_info->col_name, col_info->column_order);
            } else {
                sprintf(TmpBuf,
                        "\n\t\tif updating('%s') then "
                        "\n\t\t\t v_%d := 'Y'; "
                        "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';",
                        col_info->col_name, col_info->column_order,
                        col_info->col_name, col_info->column_order);
            }
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\t\tend if;");
            strcat(TextBuf, TmpBuf);
        }
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3) {
                *TmpBuf = 0;
                if (TabInfo.keep_org_tab_flag == 2 &&
                    IdxColRows.numRows() > 0) {
                    sprintf(TmpBuf,
                            "\n\t\tif updating('%s') then "
                            "\n\t\t\t v_%d := 'Y'; "
                            "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
                            "\n\t\t\t v_sql_set2 := v_sql_set2 || '%s=:d%d,';"
                            "\n\t\t\t v_%s := %s;",
                            col_info->col_name, col_info->column_order,
                            col_info->col_name, col_info->column_order,
                            col_info->col_name, col_info->column_order,
                            col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                } else {
                    sprintf(TmpBuf,
                            "\n\t\tif updating('%s') then "
                            "\n\t\t\t v_%d := 'Y'; "
                            "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
                            "\n\t\t\t v_%s := %s;",
                            col_info->col_name, col_info->column_order,
                            col_info->col_name, col_info->column_order,
                            col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                }
                strcat(TextBuf, TmpBuf);
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n\t\tend if;");
                strcat(TextBuf, TmpBuf);
            }
        }
        *TmpBuf = 0;
        if (TabInfo.double_flag && IdxColRows.numRows() == 0) {
            sprintf(
                TmpBuf,
                "\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, length(v_sql_set)-1 );"
                "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' WHERE ROWID "
                "= :r1';"
                "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, DBMS_SQL.NATIVE);");
        } else {
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                sprintf(TmpBuf,
                        "\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, "
                        "length(v_sql_set)-1 );"
                        "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' "
                        "WHERE ROWID = :r1';"
                        "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                        "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, "
                        "DBMS_SQL.NATIVE);");
            } else {
                dgt_schar* col_name = 0;
                dgt_sint32 seq = 0;
                dgt_schar where_clause[512];
                dgt_schar tmp_clause[128];
                memset(where_clause, 0, 512);
                memset(tmp_clause, 0, 128);
                while (IdxColRows.next() &&
                       (col_name = (dgt_schar*)IdxColRows.data())) {
                    seq++;
                    if (seq == 1) {
                        sprintf(tmp_clause, " WHERE %s = :r%d", col_name, seq);
                    } else {
                        sprintf(tmp_clause, " and %s = :r%d", col_name, seq);
                    }
                    strcat(where_clause, tmp_clause);
                }
                if (TabInfo.keep_org_tab_flag == 2 &&
                    IdxColRows.numRows() > 0) {
                    sprintf(
                        TmpBuf,
                        "\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, "
                        "length(v_sql_set)-1 );"
                        "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' %s';"
                        "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                        "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, "
                        "DBMS_SQL.NATIVE);"
                        "\n\t\tv_sql_set2 := SUBSTR(v_sql_set2, 1, "
                        "length(v_sql_set2)-1 );"
                        "\n\t\tv_sql_main2 := v_sql_main2 || v_sql_set2 || ' "
                        "%s';"
                        "\n\t\tv_cursor2 := DBMS_SQL.OPEN_CURSOR;"
                        "\n\t\tDBMS_SQL.PARSE(v_cursor2, v_sql_main2, "
                        "DBMS_SQL.NATIVE);",
                        where_clause, where_clause);
                } else {
                    sprintf(
                        TmpBuf,
                        "\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, "
                        "length(v_sql_set)-1 );"
                        "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' %s';"
                        "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                        "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, "
                        "DBMS_SQL.NATIVE);",
                        where_clause);
                }
            }
        }
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3) {
                if (TabInfo.keep_org_tab_flag == 2 &&
                    IdxColRows.numRows() > 0) {
                    if (col_info->col_default) {
                        sprintf(TmpBuf,
                                "\n\t\tIF V_%d = 'Y' THEN"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':d%d', v_%s);"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, "
                                "':d%d', nvl(:new.%s,%s));"
                                "\n\t\tEND IF;",
                                col_info->column_order, col_info->column_order,
                                col_info->col_name, col_info->column_order,
                                col_info->col_name,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    } else {
                        sprintf(TmpBuf,
                                "\n\t\tIF V_%d = 'Y' THEN"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':d%d', v_%s);"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, "
                                "':d%d', :new.%s);"
                                "\n\t\tEND IF;",
                                col_info->column_order, col_info->column_order,
                                col_info->col_name, col_info->column_order,
                                col_info->col_name);
                    }
                    strcat(TextBuf, TmpBuf);
                } else {
                    sprintf(
                        TmpBuf,
                        "\n\t\tIF V_%d = 'Y' THEN"
                        "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', v_%s);"
                        "\n\t\tEND IF;",
                        col_info->column_order, col_info->column_order,
                        col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                if (col_info->col_default) {
                    if (TabInfo.keep_org_tab_flag == 2 &&
                        IdxColRows.numRows() > 0) {
                        sprintf(
                            TmpBuf,
                            "\n\t\tIF V_%d = 'Y' THEN"
                            "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', "
                            "nvl(:new.%s,%s));"
                            "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, ':d%d', "
                            "nvl(:new.%s,%s));"
                            "\n\t\tEND IF;",
                            col_info->column_order, col_info->column_order,
                            col_info->col_name,
                            PetraNamePool->getNameString(col_info->col_default),
                            col_info->column_order, col_info->col_name,
                            PetraNamePool->getNameString(
                                col_info->col_default));
                    } else {
                        sprintf(TmpBuf,
                                "\n\t\tIF V_%d = 'Y' THEN"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':d%d', nvl(:new.%s,%s));"
                                "\n\t\tEND IF;",
                                col_info->column_order, col_info->column_order,
                                col_info->col_name,
                                PetraNamePool->getNameString(
                                    col_info->col_default));
                    }
                } else {
                    if (TabInfo.keep_org_tab_flag == 2 &&
                        IdxColRows.numRows() > 0) {
                        sprintf(TmpBuf,
                                "\n\t\tIF V_%d = 'Y' THEN"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':d%d', :new.%s);"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, "
                                "':d%d', :new.%s);"
                                "\n\t\tEND IF;",
                                col_info->column_order, col_info->column_order,
                                col_info->col_name, col_info->column_order,
                                col_info->col_name);
                    } else {
                        sprintf(TmpBuf,
                                "\n\t\tIF V_%d = 'Y' THEN"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':d%d', :new.%s);"
                                "\n\t\tEND IF;",
                                col_info->column_order, col_info->column_order,
                                col_info->col_name);
                    }
                }
                strcat(TextBuf, TmpBuf);
            }
        }
        *TmpBuf = 0;
        if (TabInfo.double_flag && IdxColRows.numRows() == 0) {
            sprintf(
                TmpBuf,
                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':r1', :old.row_id);");
            strcat(TextBuf, TmpBuf);
        } else {
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                sprintf(TmpBuf,
                        "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':r1', "
                        ":old.row_id);");
                strcat(TextBuf, TmpBuf);
            } else {
                dgt_schar* col_name = 0;
                dgt_sint32 seq = 0;
                while (IdxColRows.next() &&
                       (col_name = (dgt_schar*)IdxColRows.data())) {
                    seq++;
                    if (TabInfo.keep_org_tab_flag == 2 &&
                        IdxColRows.numRows() > 0) {
                        sprintf(TmpBuf,
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':r%d', :old.%s);"
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, "
                                "':r%d', :old.%s);",
                                seq, col_name, seq, col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        sprintf(TmpBuf,
                                "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, "
                                "':r%d', :old.%s);",
                                seq, col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                }
            }
        }
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\n\t\tv_ret := DBMS_SQL.EXECUTE (v_cursor);"
                "\n\t\tDBMS_SQL.CLOSE_CURSOR (v_cursor);");
        strcat(TextBuf, TmpBuf);
        if (TabInfo.keep_org_tab_flag == 2 && IdxColRows.numRows() > 0) {
            *TmpBuf = 0;
            sprintf(TmpBuf,
                    "\n\t\tv_ret2 := DBMS_SQL.EXECUTE (v_cursor2);"
                    "\n\t\tDBMS_SQL.CLOSE_CURSOR (v_cursor2);");
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf, "\n\tend if;\nend;");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3) {
                sprintf(TmpBuf, "\n\t v_%s := %s;", col_info->col_name,
                        getFname(col_info->col_name, 1, 1));
                strcat(TextBuf, TmpBuf);
            }
            *TmpBuf = 0;
        }
        *TmpBuf = 0;
        if (TabInfo.enc_type == 0) {
            sprintf(TmpBuf, "\n\tupdate %s.%s set\n", SchemaName,
                    TabInfo.renamed_tab_name);
        } else {
            sprintf(TmpBuf, "\n\tupdate %s.%s set\n", SchemaName,
                    TabInfo.table_name);
        }
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3 && is_final)
                continue;
            *TmpBuf = 0;
            if (col_info->col_default) {
                sprintf(TmpBuf, "\n\t\t%s=nvl(:new.%s,%s),", col_info->col_name,
                        col_info->col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "\n\t\t%s=:new.%s,", col_info->col_name,
                        col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 5) continue;
            if (col_info->status >= 1 && col_info->status < 3) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n\t\t%s=v_%s,", col_info->col_name,
                        col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, "\n      where ");
        *TmpBuf = 0;
        if (TabInfo.double_flag && IdxColRows.numRows() == 0) {
            strcat(TextBuf, "rowid = :old.row_id");
        } else {
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf, "rowid = :old.row_id");
            } else {
                dgt_schar* col_name = 0;
                dgt_sint32 seq = 0;
                while (IdxColRows.next() &&
                       (col_name = (dgt_schar*)IdxColRows.data())) {
                    seq++;
                    *TmpBuf = 0;
                    if (seq == 1) {
                        sprintf(TmpBuf, "%s = :old.%s ", col_name, col_name);
                    } else {
                        sprintf(TmpBuf, "\n\t and %s = :old.%s", col_name,
                                col_name);
                    }
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        strcat(TextBuf, ";");
        *TmpBuf = 0;
        if (TabInfo.keep_org_tab_flag == 2 && IdxColRows.numRows() > 0) {
            sprintf(TmpBuf, "\n\tupdate %s.%s set\n", SchemaName,
                    TabInfo.org_renamed_tab_name);
            strcat(TextBuf, TmpBuf);
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                if (col_info->status == 5) continue;
                *TmpBuf = 0;
                if (col_info->col_default) {
                    sprintf(
                        TmpBuf, "\n\t\t%s=nvl(:new.%s,%s),", col_info->col_name,
                        col_info->col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                    strcat(TextBuf, TmpBuf);
                } else {
                    sprintf(TmpBuf, "\n\t\t%s=:new.%s,", col_info->col_name,
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            strcat(TextBuf, "\n      where ");
            *TmpBuf = 0;
            IdxColRows.rewind();
            dgt_schar* col_name = 0;
            dgt_sint32 seq = 0;
            while (IdxColRows.next() &&
                   (col_name = (dgt_schar*)IdxColRows.data())) {
                seq++;
                *TmpBuf = 0;
                if (seq == 1) {
                    sprintf(TmpBuf, "%s = :old.%s ", col_name, col_name);
                } else {
                    sprintf(TmpBuf, "\n\t and %s = :old.%s", col_name,
                            col_name);
                }
                strcat(TextBuf, TmpBuf);
            }
            strcat(TextBuf, ";");
        }
        strcat(TextBuf, "\n   end if;\nend;\n");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    return 0;
}

typedef struct {
    dgt_schar org1[512];
    dgt_schar org2[512];
    dgt_schar enc1[512];
    dgt_schar enc2[512];
    dgt_schar org3[512];
    dgt_schar org4[512];
} pkfk_sql;

dgt_sint32 PccOraScriptBuilder::step1() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //
    // create the copy table (same as original table)
    //
    pc_type_col_info* col_info;
    StepNo = 1;
    StmtNo = 1000;
    *TextBuf = 0;
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
    }
    if (TabInfo.partitioned == 1) {
        sprintf(sql_text,
                "declare "
                "begin "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'CONSTRAINTS',FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'REF_CONSTRAINTS', FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'SEGMENT_ATTRIBUTES',TRUE); "
                "end;");
    } else {
        sprintf(sql_text,
                "declare "
                "begin "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'CONSTRAINTS',FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'REF_CONSTRAINTS', FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'TABLESPACE',TRUE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'SEGMENT_ATTRIBUTES',TRUE); "
                "end;");
    }
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;
    sprintf(sql_text,
            "select dbms_metadata.get_ddl('TABLE','%s','%s') from dual",
            TabInfo.table_name, SchemaName);
    stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcMemRows* rows = stmt->returnRows();
    rows->rewind();
    dgt_schar* ddl_stmt_ptr = 0;
    while (rows->next() && (ddl_stmt_ptr = (dgt_schar*)rows->data())) {
        strcpy(TmpBuf, ddl_stmt_ptr);
        sprintf(TextBuf, "CREATE TABLE %s.%s ", SchemaName,
                TabInfo.renamed_tab_name);
        dgt_schar table_name[130];
        memset(table_name, 0, 130);
        sprintf(table_name, "\"%s\"", TabInfo.table_name);
        dgt_schar* tmp = strstr(TmpBuf, table_name);
        if (tmp) {
            dgt_uint32 i = 0;
            for (i = 0; i < strlen(table_name); i++) {
                tmp++;
            }
        }
        strcat(TextBuf, tmp);
#if 0
		if (TabInfo.partitioned == 0) {
			*TmpBuf=0;
			sprintf(TmpBuf," TABLESPACE %s",TabInfo.target_tablespace_name);
			strcat(TextBuf,TmpBuf);
		}
#endif
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    delete stmt;
#if 1
    *TextBuf = 0;
    ColInfoRows.rewind();
    dgt_sint32 lob_flag = 0;
    dgt_sint32 long_flag = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                lob_flag = 1;
            }
            if (!strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW")) {
                long_flag = 1;
            }
        }
    }
#endif
    //
    // alter table modify column
    //
    StmtNo = 2000;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            dgt_sint32 enc_len = 0;
            if (!strcasecmp(col_info->data_type, "NUMBER"))
                enc_len = (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATE") ||
                     !strcasecmp(col_info->data_type, "TIMESTAMP"))
                enc_len = 14;
            else if (col_info->multi_byte_flag)
                enc_len = col_info->data_length * 3;
            else
                enc_len = col_info->data_length;
            PCI_Context ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type,
                            col_info->enc_mode, col_info->iv_type,
                            col_info->n2n_flag, col_info->b64_txt_enc_flag,
                            col_info->enc_start_pos, col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            if (col_info->index_type == 1) {
                enc_len += PCI_ophuekLength(col_info->data_length,
                                            PCI_SRC_TYPE_CHAR, 1);
                // add trailer length
                enc_len += 4;
            }
            if (!strcasecmp(col_info->data_type, "NVARCHAR2") ||
                !strcasecmp(col_info->data_type, "NCHAR")) {
                enc_len = enc_len * 3;
            }
            *TextBuf = 0;
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                // sprintf(TextBuf,"alter table %s.%s modify %s BLOB",
                // SchemaName, TabInfo.renamed_tab_name, col_info->col_name);
            } else if (!strcasecmp(col_info->data_type, "LONG RAW")) {
                sprintf(TextBuf, "alter table %s.%s modify %s BLOB", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name);
            } else if (!strcasecmp(col_info->data_type, "LONG")) {
                sprintf(TextBuf, "alter table %s.%s modify %s CLOB", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name);
            } else {
                if (col_info->b64_txt_enc_flag &&
                    col_info->b64_txt_enc_flag != 4) {
                    sprintf(TextBuf, "alter table %s.%s modify %s varchar2(%d)",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, enc_len);
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s raw(%d)",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name, enc_len);
                }
            }
            if (*TextBuf && saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }

            *TextBuf = 0;
        } else {
            *TextBuf = 0;
            if (TabInfo.enc_type == 0) {
                if (!strcasecmp(col_info->data_type, "LONG")) {
                    sprintf(TextBuf, "alter table %s.%s modify %s clob",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                } else if (!strcasecmp(col_info->data_type, "LONG RAW")) {
                    sprintf(TextBuf, "alter table %s.%s modify %s blob",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            }
        }
    }
    //
    // Create the Transaction table
    //
#if 1
    if (TabInfo.tran_trg_flag == 1 && TranIdxColRows.numRows() > 0) {
        StmtNo = 4000;
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(
            TextBuf,
            "CREATE TABLE %s.%s as select 1 petra_id, '          ' petra_type, "
            "alias.* from %s.%s alias where 1=0",
            AgentName, TabInfo.tran_tab_name, SchemaName, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "create index %s.tran_%lld_idx on %s.%s(petra_id)",
                AgentName, TabInfo.enc_tab_id, AgentName,
                TabInfo.tran_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        //
        // Create the Transcation Trigger
        //
        StmtNo = 5000;
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE TRIGGER %s.%s \n"
                "after insert or update or delete on %s.%s for each row \n"
                "begin \n"
                "\tif inserting then \n"
                "\t\tinsert into %s.%s(PETRA_ID,PETRA_TYPE,",
                AgentName, TabInfo.tab_trigger_name, SchemaName,
                TabInfo.table_name, AgentName, TabInfo.tran_tab_name);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ")");
        strcat(TextBuf, " values(tr_table_id.nextval, 'INSERT',");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, ":new.%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ");\n");
        strcat(TextBuf, "\telsif updating then \n");
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\tinsert into %s.%s(PETRA_ID,PETRA_TYPE,", AgentName,
                TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ")");
        strcat(TextBuf, " values(tr_table_id.nextval, 'UPDATE_OLD',");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, ":old.%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ");\n");
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\tinsert into %s.%s(PETRA_ID,PETRA_TYPE,", AgentName,
                TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ")");
        strcat(TextBuf, " values(tr_table_id.nextval, 'UPDATE_NEW',");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, ":new.%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ");\n");
        strcat(TextBuf, "\telsif deleting then \n");
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\tinsert into %s.%s(PETRA_ID,PETRA_TYPE,", AgentName,
                TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ")");
        strcat(TextBuf, " values(tr_table_id.nextval, 'DELETE',");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            sprintf(TmpBuf, ":old.%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ");\n");
        strcat(TextBuf, "\tend if;\n");
        strcat(TextBuf, "end;");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
#endif
    //
    // initial encrpytion(parallel insert)
    //
    if (lob_flag == 0) {
        *TextBuf = 0;
        sprintf(TextBuf, "ALTER SESSION FORCE PARALLEL DML");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "ALTER TABLE %s.%s nologging", SchemaName,
                TabInfo.renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    StmtNo = 6000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (lob_flag == 1) {
        ColInfoRows.rewind();
        sprintf(TmpBuf, "insert into %s.%s( ", SchemaName,
                TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 1) {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ") \nselect ");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW")) {
                sprintf(TmpBuf, "to_lob(%s),", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            } else {
                if (col_info->status == 1) {
                    sprintf(TmpBuf, "%s,", getFname(col_info->col_name, 1));
                    strcat(TextBuf, TmpBuf);
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.table_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "commit");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else if (TabInfo.partitioned == 1) {
        sprintf(sql_text,
                "select subobject_name from dba_objects "
                "where object_type = 'TABLE PARTITION' "
                " and owner = upper('%s') "
                " and object_name = upper('%s') "
                " and subobject_name is not null ",
                SchemaName, TabInfo.table_name);
        stmt = Connection->getStmt();
        if (!stmt) {
            ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
        }
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        DgcMemRows* rows = stmt->returnRows();
        rows->rewind();
        dgt_schar* part_name = 0;
        while (rows->next() && (part_name = (dgt_schar*)rows->data())) {
            *TextBuf = 0;
            *TmpBuf = 0;
            ColInfoRows.rewind();
            sprintf(
                TmpBuf,
                "insert /*+ APPEND PARALLEL(%s,%d) */ into %s.%s partition(%s) "
                "%s \n select /*+ FULL(%s) PARALLEL(%s,%d) */ ",
                TabInfo.renamed_tab_name, ParallelDegree, SchemaName,
                TabInfo.renamed_tab_name, part_name, TabInfo.renamed_tab_name,
                TabInfo.table_name, TabInfo.table_name, ParallelDegree);
            strcat(TextBuf, TmpBuf);
            dgt_sint32 count_fun_use_flag = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                if (col_info->status == 1) {
                    *TmpBuf = 0;
                    if (count_fun_use_flag == 0) {
                        if (!strcasecmp(col_info->data_type, "CHARM")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    TmpBuf, "PLS_ENCRYPT_CPN_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    TmpBuf, "PLS_ENCRYPT_B64_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                                count_fun_use_flag = 1;
                            }
                        } else if (!strcasecmp(col_info->data_type,
                                               "VARCHAR") ||
                                   !strcasecmp(col_info->data_type,
                                               "VARCHAR2")) {
                            if (col_info->coupon_id) {
                                sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            } else {
                                sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                                count_fun_use_flag = 1;
                            }
                        } else if (!strcasecmp(col_info->data_type, "LONG") ||
                                   !strcasecmp(col_info->data_type,
                                               "LONG RAW")) {
                            sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                        } else {
                            sprintf(TmpBuf, getFname(col_info->col_name, 1));
                        }
                    } else if (col_info->iv_type == 2) {
                        if (!strcasecmp(col_info->data_type, "CHARM")) {
                            if (col_info->coupon_id) {
                                sprintf(
                                    TmpBuf, "PLS_ENCRYPT_CPN_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            } else {
                                sprintf(
                                    TmpBuf, "PLS_ENCRYPT_B64_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type,
                                               "VARCHAR") ||
                                   !strcasecmp(col_info->data_type,
                                               "VARCHAR2")) {
                            if (col_info->coupon_id) {
                                sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            } else {
                                sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            }
                        } else if (!strcasecmp(col_info->data_type, "LONG") ||
                                   !strcasecmp(col_info->data_type,
                                               "LONG RAW")) {
                            sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                        } else {
                            sprintf(TmpBuf, getFname(col_info->col_name, 1));
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "LONG") ||
                            !strcasecmp(col_info->data_type, "LONG RAW")) {
                            sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                        } else {
                            sprintf(TmpBuf, getFname(col_info->col_name, 1));
                        }
                    }
                    strcat(TmpBuf, ",");
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    if (!strcasecmp(col_info->data_type, "LONG") ||
                        !strcasecmp(col_info->data_type, "LONG RAW")) {
                        sprintf(TmpBuf, "to_lob(%s),", col_info->col_name);
                    } else {
                        sprintf(TmpBuf, "%s,", col_info->col_name);
                    }
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            *TmpBuf = 0;
            sprintf(TmpBuf, " from %s.%s partition(%s) %s", SchemaName,
                    TabInfo.table_name, part_name, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "commit");
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    } else {
        ColInfoRows.rewind();
        sprintf(TmpBuf,
                "insert /*+ APPEND PARALLEL(%s,%d) */ into %s.%s \n select /*+ "
                "FULL(%s) PARALLEL(%s,%d) */ ",
                TabInfo.renamed_tab_name, ParallelDegree, SchemaName,
                TabInfo.renamed_tab_name, TabInfo.table_name,
                TabInfo.table_name, ParallelDegree);
        strcat(TextBuf, TmpBuf);
        dgt_sint32 count_fun_use_flag = 0;
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 1) {
                *TmpBuf = 0;
                if (count_fun_use_flag == 0) {
                    if (!strcasecmp(col_info->data_type, "CHARM")) {
                        if (col_info->coupon_id) {
                            sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            count_fun_use_flag = 1;
                        }
                    } else if (!strcasecmp(col_info->data_type, "VARCHAR") ||
                               !strcasecmp(col_info->data_type, "VARCHAR2")) {
                        if (col_info->coupon_id) {
                            sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                            count_fun_use_flag = 1;
                        }
                    } else if (!strcasecmp(col_info->data_type, "LONG") ||
                               !strcasecmp(col_info->data_type, "LONG RAW")) {
                        sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                    } else {
                        sprintf(TmpBuf, getFname(col_info->col_name, 1));
                    }
                } else if (col_info->iv_type == 2) {
                    if (!strcasecmp(col_info->data_type, "CHARM")) {
                        if (col_info->coupon_id) {
                            sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(TRIM(%s),%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else if (!strcasecmp(col_info->data_type, "VARCHAR") ||
                               !strcasecmp(col_info->data_type, "VARCHAR2")) {
                        if (col_info->coupon_id) {
                            sprintf(TmpBuf, "PLS_ENCRYPT_CPN_ID(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(TmpBuf, "PLS_ENCRYPT_B64_ID(%s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else if (!strcasecmp(col_info->data_type, "LONG") ||
                               !strcasecmp(col_info->data_type, "LONG RAW")) {
                        sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                    } else {
                        sprintf(TmpBuf, getFname(col_info->col_name, 1));
                    }
                } else {
                    if (!strcasecmp(col_info->data_type, "LONG") ||
                        !strcasecmp(col_info->data_type, "LONG RAW")) {
                        sprintf(TmpBuf, "to_lob(%s)", col_info->col_name);
                    } else {
                        sprintf(TmpBuf, getFname(col_info->col_name, 1));
                    }
                }
                strcat(TmpBuf, ",");
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                if (!strcasecmp(col_info->data_type, "LONG") ||
                    !strcasecmp(col_info->data_type, "LONG RAW")) {
                    sprintf(TmpBuf, "to_lob(%s),", col_info->col_name);
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                }
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.table_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        sprintf(TextBuf, "commit");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;
    sprintf(TextBuf, "ALTER SESSION DISABLE PARALLEL DML");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    *TextBuf = 0;
    sprintf(TextBuf, "ALTER TABLE %s.%s logging", SchemaName,
            TabInfo.renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    if (long_flag == 1) {
        sprintf(TextBuf, "declare\n   urows number := 0;\n   v_rowid rowid;\n");
        *TmpBuf = 0;
        if (TabInfo.enc_type == 0) {
            sprintf(TmpBuf, "   cursor c1 is\n      select rowid from %s.%s",
                    SchemaName, TabInfo.renamed_tab_name);
        } else {
            sprintf(TmpBuf, "   cursor c1 is\n      select rowid from %s.%s",
                    SchemaName, TabInfo.table_name);
        }
        strcat(TextBuf, TmpBuf);
        strcat(TextBuf,
               ";\nbegin\n   open c1;\n   loop\n\tfetch c1 into "
               "v_rowid;\n\texit when c1%NOTFOUND;\n");
        *TmpBuf = 0;
        if (TabInfo.enc_type == 0) {
            sprintf(TmpBuf, "\tupdate %s.%s set", SchemaName,
                    TabInfo.renamed_tab_name);
        } else {
            sprintf(TmpBuf, "\tupdate %s.%s set", SchemaName,
                    TabInfo.table_name);
        }
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 1 &&
                (!strcasecmp(col_info->data_type, "LONG") ||
                 !strcasecmp(col_info->data_type, "LONG RAW"))) {
                dgt_sint32 idx_flag = col_info->index_type;
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n\t\t%s=%s,", col_info->col_name,
                        getFname(col_info->col_name, 1));
                strcat(TextBuf, TmpBuf);
                *TmpBuf = 0;
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(
            TmpBuf,
            "\n\t where rowid = v_rowid;\n\turows := urows + 1;\n\tif ((urows mod %u) = 0) then\n\t\tcommit;\n\tend if;\n   end loop; \
                                \n   commit;\nend;\n",
            1000);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // Create the table`s original index
    //
    StmtNo = 7000;
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows2.rewind();
    IdxSqlRows3.rewind();
    dgt_schar* idx_sql = 0;
    while (IdxSqlRows2.next() && (idx_sql = (dgt_schar*)IdxSqlRows2.data())) {
        if (idx_sql && strlen(idx_sql) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    while (IdxSqlRows3.next() && (idx_sql = (dgt_schar*)IdxSqlRows3.data())) {
        if (idx_sql && strlen(idx_sql) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // rename enc column name
    //
    StmtNo = 8000;
#if 0
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                if (col_info->status == 1) {
                        *TextBuf=0;
                        sprintf(TextBuf,"alter table %s.%s rename column %s to %s",
                                        SchemaName, TabInfo.renamed_tab_name, col_info->col_name, col_info->renamed_col_name);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }
#endif
    //
    // index creation script if index_flag is on
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 9000;
    PetraIdxInfoRows.rewind();
    pc_type_petra_index* pt_idx_info;
    *TextBuf = 0;
    while (PetraIdxInfoRows.next() &&
           (pt_idx_info = (pc_type_petra_index*)PetraIdxInfoRows.data())) {
        *TextBuf = 0;
        if (pt_idx_info->sql_text && strlen(pt_idx_info->sql_text) > 2) {
            *TextBuf = 0;
            sprintf(TextBuf, "%s", pt_idx_info->sql_text);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "%s", pt_idx_info->sql_text2);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (pt_idx_info->normal_sql_text &&
            strlen(pt_idx_info->normal_sql_text) > 2) {
            *TextBuf = 0;
            sprintf(TextBuf, "%s", pt_idx_info->normal_sql_text);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "%s", pt_idx_info->normal_sql_text2);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        if (pt_idx_info->idx_col_idx1 &&
            strlen(pt_idx_info->idx_col_idx1) > 2) {
            sprintf(TextBuf, "%s", pt_idx_info->idx_col_idx1);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "%s", pt_idx_info->idx_col_idx2);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // creating Transaction Logging apply procedure
    //
#if 1
    if (TabInfo.tran_trg_flag == 1 && TranIdxColRows.numRows() > 0) {
        StmtNo = 11000;
        *TextBuf = 0;
        *TmpBuf = 0;
        ColInfoRows.rewind();
        sprintf(
            TextBuf,
            "create or replace procedure %s.proc1_%lld\n"
            "is\n\tcursor tr_table_cursor is \n\t\tselect petra_id,petra_type,",
            AgentName, TabInfo.enc_tab_id);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            if (col_info->status == 1)
                sprintf(TmpBuf, "%s %s,", getFname(col_info->col_name, 1),
                        col_info->col_name);
            else
                sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
#if 0
		ColInfoRows.rewind();
		while (ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        if (col_info->status == 1 && col_info->index_type == 2) {
                        	*TmpBuf=0;
				sprintf(TmpBuf,"%s %s,",getFname(col_info->col_name,3),col_info->index_col_name);
	                        strcat(TextBuf,TmpBuf);
			}
                }
#endif
        TextBuf[strlen(TextBuf) - 1] = 0;
        *TmpBuf = 0;
        sprintf(TmpBuf, " from %s.%s order by petra_id asc;\n", AgentName,
                TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "LONG")) continue;
            if (col_info->status == 0)
                sprintf(TmpBuf, "\tv_%s %s.%s.%s%%TYPE;\n", col_info->col_name,
                        AgentName, TabInfo.tran_tab_name, col_info->col_name);
            else if (col_info->status == 1) {
                dgt_sint32 enc_len = 0;
                if (!strcasecmp(col_info->data_type, "NUMBER"))
                    enc_len = (col_info->data_precision + 2);
                else if (!strcasecmp(col_info->data_type, "DATE") ||
                         !strcasecmp(col_info->data_type, "TIMESTAMP"))
                    enc_len = 14;
                else if (col_info->multi_byte_flag)
                    enc_len = col_info->data_length * 3;
                else
                    enc_len = col_info->data_length;
                PCI_Context ctx;
                PCI_initContext(&ctx, 0, col_info->key_size,
                                col_info->cipher_type, col_info->enc_mode,
                                col_info->iv_type, col_info->n2n_flag,
                                col_info->b64_txt_enc_flag,
                                col_info->enc_start_pos, col_info->enc_length);
                enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
                if (col_info->index_type == 1) {
                    enc_len += PCI_ophuekLength(col_info->data_length,
                                                PCI_SRC_TYPE_CHAR, 1);
                    enc_len += 4;
                }
                if (!strcasecmp(col_info->data_type, "NCHAR") ||
                    !strcasecmp(col_info->data_type, "NVARCHAR2")) {
                    enc_len = enc_len * 3;
                }
                if (!strcasecmp(col_info->data_type, "CLOB") ||
                    !strcasecmp(col_info->data_type, "BLOB")) {
                    sprintf(TmpBuf, "\tv_%s BLOB;\n", col_info->col_name);
                } else {
                    if (col_info->b64_txt_enc_flag &&
                        col_info->b64_txt_enc_flag != 4) {
                        sprintf(TmpBuf, "\tv_%s varchar2(%d);\n",
                                col_info->col_name, enc_len);
                    } else {
                        sprintf(TmpBuf, "\tv_%s raw(%d);\n", col_info->col_name,
                                enc_len);
                    }
                }
            }
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf,
               "begin\n\tfor v_value in tr_table_cursor loop\n\t\tif "
               "v_value.petra_type = 'INSERT' then\n");
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\t\tinsert into %s.%s(", SchemaName,
                TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            if (col_info->status == 1)
                sprintf(TmpBuf, "%s,", col_info->col_name);
            else
                sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ") values(");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            if (col_info->status == 1) {
                sprintf(TmpBuf, "v_value.%s,", col_info->col_name);
            } else {
                sprintf(TmpBuf, "v_value.%s,", col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ");\n");
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\t\t\tdelete %s.%s where petra_id = v_value.petra_id;\n",
                AgentName, TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\telsif v_value.petra_type = 'UPDATE_OLD' then\n");
        strcat(TextBuf, TmpBuf);
        TranIdxColRows.rewind();
        if (TranIdxColRows.numRows() > 0) {
            dgt_schar* col_name = 0;
            while (TranIdxColRows.next() &&
                   (col_name = (dgt_schar*)TranIdxColRows.data())) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\t\t\tv_%s :=v_value.%s;\n", col_name,
                        col_name);
                strcat(TextBuf, TmpBuf);
            }
        } else {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (!strcasecmp(col_info->data_type, "LONG")) continue;
                if (col_info->status == 1) {
                    sprintf(TmpBuf,
                            "\t\t\tv_%s := nvl(v_value.%s,'=p=e=t=r=a=');\n",
                            col_info->col_name, col_info->col_name);
                } else {
                    sprintf(TmpBuf,
                            "\t\t\tv_%s := nvl(v_value.%s,'=p=e=t=r=a=');\n",
                            col_info->col_name, col_info->col_name);
                }
                strcat(TextBuf, TmpBuf);
            }
        }
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\t\t\tdelete %s.%s where petra_id = v_value.petra_id;\n",
                AgentName, TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\telsif v_value.petra_type = 'UPDATE_NEW' then\n");
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\t\tupdate %s.%s set ", SchemaName,
                TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 0 &&
                !strcasecmp(col_info->data_type, "LONG"))
                continue;
            if (col_info->status == 1) {
                sprintf(TmpBuf, " %s = v_value.%s,", col_info->col_name,
                        col_info->col_name);
            } else {
                sprintf(TmpBuf, " %s = v_value.%s,", col_info->col_name,
                        col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, " where ");
        TranIdxColRows.rewind();
        if (TranIdxColRows.numRows() > 0) {
            dgt_schar* col_name = 0;
            dgt_sint32 seq = 0;
            while (TranIdxColRows.next() &&
                   (col_name = (dgt_schar*)TranIdxColRows.data())) {
                *TmpBuf = 0;
                seq++;
                if (seq == 1) {
                    sprintf(TmpBuf, " %s = v_%s ", col_name, col_name);
                } else {
                    sprintf(TmpBuf, " and %s = v_%s ", col_name, col_name);
                }
                strcat(TextBuf, TmpBuf);
            }
        } else {
            ColInfoRows.rewind();
            dgt_sint32 seq = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                seq++;
                if (!strcasecmp(col_info->data_type, "LONG")) continue;
                if (seq == 1) {
                    if (!strcasecmp(col_info->data_type, "CLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),v_"
                                    "%s) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),v_"
                                    "%s) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else if (!strcasecmp(col_info->data_type, "BLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf, " %s = v_%s ", col_info->col_name,
                                    col_info->col_name);
                        } else {
                            sprintf(TmpBuf, " %s = v_%s ", col_info->col_name,
                                    col_info->col_name);
                        }
                    } else {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf, " nvl(%s,'=p=e=t=r=a=') = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf, " nvl(%s,'=p=e=t=r=a=') = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        }
                    }
                } else {
                    if (!strcasecmp(col_info->data_type, "CLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " and "
                                    "dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),v_%"
                                    "s) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " and "
                                    "dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),v_%"
                                    "s) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else if (!strcasecmp(col_info->data_type, "BLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf, " and %s = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf, " and %s = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " and nvl(%s,'=p=e=t=r=a=') = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " and nvl(%s,'=p=e=t=r=a=') = v_%s ",
                                    col_info->col_name, col_info->col_name);
                        }
                    }
                }
                strcat(TextBuf, TmpBuf);
            }
        }
        strcat(TextBuf, ";\n");
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\t\t\tdelete %s.%s where petra_id = v_value.petra_id;\n",
                AgentName, TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\telsif v_value.petra_type = 'DELETE' then\n");
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\t\t\tdelete %s.%s where ", SchemaName,
                TabInfo.renamed_tab_name);
        strcat(TextBuf, TmpBuf);
        TranIdxColRows.rewind();
        if (TranIdxColRows.numRows() > 0) {
            dgt_schar* col_name = 0;
            dgt_sint32 seq = 0;
            while (TranIdxColRows.next() &&
                   (col_name = (dgt_schar*)TranIdxColRows.data())) {
                *TmpBuf = 0;
                seq++;
                if (seq == 1) {
                    sprintf(TmpBuf, " %s = v_value.%s ", col_name, col_name);
                } else {
                    sprintf(TmpBuf, " and %s = v_value.%s ", col_name,
                            col_name);
                }
                strcat(TextBuf, TmpBuf);
            }
        } else {
            ColInfoRows.rewind();
            dgt_sint32 seq = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (!strcasecmp(col_info->data_type, "LONG")) continue;
                seq++;
                if (seq == 1) {
                    if (!strcasecmp(col_info->data_type, "CLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),"
                                    "nvl(v_value.%s,'=p=e=t=r=a=')) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),"
                                    "nvl(v_value.%s,'=p=e=t=r=a=')) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else if (!strcasecmp(col_info->data_type, "BLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf, " %s = v_value.%s ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf, " %s = v_value.%s ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " nvl(%s,'=p=e=t=r=a=') = "
                                    "nvl(v_value.%s,'=p=e=t=r=a=') ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " nvl(%s,'=p=e=t=r=a=') = "
                                    "nvl(v_value.%s,'=p=e=t=r=a=') ",
                                    col_info->col_name, col_info->col_name);
                        }
                    }
                } else {
                    if (!strcasecmp(col_info->data_type, "CLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " and "
                                    "dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),"
                                    "nvl(v_value.%s,'=p=e=t=r=a=')) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " and "
                                    "dbms_lob.compare(nvl(%s,'=p=e=t=r=a='),"
                                    "nvl(v_value.%s,'=p=e=t=r=a=')) = 0 ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else if (!strcasecmp(col_info->data_type, "BLOB")) {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf, " and %s = v_value.%s ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf, " and %s = v_value.%s ",
                                    col_info->col_name, col_info->col_name);
                        }
                    } else {
                        if (col_info->status == 1) {
                            sprintf(TmpBuf,
                                    " and nvl(%s,'=p=e=t=r=a=') = "
                                    "nvl(v_value.%s,'=p=e=t=r=a=') ",
                                    col_info->col_name, col_info->col_name);
                        } else {
                            sprintf(TmpBuf,
                                    " and nvl(%s,'=p=e=t=r=a=') = "
                                    "nvl(v_value.%s,'=p=e=t=r=a=') ",
                                    col_info->col_name, col_info->col_name);
                        }
                    }
                }
                strcat(TextBuf, TmpBuf);
            }
        }
        strcat(TextBuf, ";\n");
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\t\t\tdelete %s.%s where petra_id = v_value.petra_id;\n",
                AgentName, TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        strcat(TextBuf, "\t\tend if;\n");
        strcat(TextBuf, "\tend loop;\n");
        strcat(TextBuf, "end;");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf,
                "create or replace procedure %s.proc2_%lld\nis\n\tv_cnt "
                "number;\nbegin\n\tloop\n",
                AgentName, TabInfo.enc_tab_id);
        sprintf(TmpBuf, "\t\tselect count(rowid) into v_cnt from %s.%s;\n",
                AgentName, TabInfo.tran_tab_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(
            TmpBuf,
            "\t\t%s.proc1_%lld;\n\texit when(v_cnt <= 0);\n\tend loop;\nend;",
            AgentName, TabInfo.enc_tab_id);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
#endif
    //
    // create the unique constraint
    //
    StmtNo = 12000;
    *TextBuf = 0;
    *TmpBuf = 0;
    UniqueSqlRows1.rewind();
    dgt_schar* unisql = 0;
    while (UniqueSqlRows1.next() &&
           (unisql = (dgt_schar*)UniqueSqlRows1.data())) {
        if (unisql && strlen(unisql) > 2) {
            strcpy(TextBuf, unisql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // If not null check constraint exist drop and create
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 15000;
    CheckSqlRows.rewind();
    pc_type_check_sql* check_sql = 0;
    while (CheckSqlRows.next() &&
           (check_sql = (pc_type_check_sql*)CheckSqlRows.data())) {
        *TextBuf = 0;
        if (check_sql->enc1 && strlen(check_sql->enc1) > 2) {
            strcpy(TextBuf, check_sql->enc1);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    return 0;
}

dgt_sint32 PccOraScriptBuilder::step2() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //

    //
    // Create the Constraint non enc_column(PK,Dependency Fk,Check)
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 1000;
    StepNo = 2;
    DefFkDropSqlRows2.rewind();
    dgt_schar* fkdropsql = 0;
    while (DefFkDropSqlRows2.next() &&
           (fkdropsql = (dgt_schar*)DefFkDropSqlRows2.data())) {
        if (fkdropsql && strlen(fkdropsql) > 2) {
            strcpy(TextBuf, fkdropsql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    if (TabInfo.keep_org_tab_flag == 0) {
        DefFkDropSqlRows.rewind();
        typedef struct {
            dgt_schar enc_sql[512];
            dgt_schar org_sql[512];
        } enc_table_fk;
        enc_table_fk* tmp_ptr = 0;
        StmtNo = 2000;
        while (DefFkDropSqlRows.next() &&
               (tmp_ptr = (enc_table_fk*)DefFkDropSqlRows.data())) {
            if (tmp_ptr->enc_sql && strlen(tmp_ptr->enc_sql) > 2) {
                strcpy(TextBuf, tmp_ptr->enc_sql);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    *TextBuf = 0;
    *TmpBuf = 0;
#if 0
        DefFkCreSqlRows2.rewind();
        dgt_schar* fkcresql=0;
	StmtNo=3000;
        while (DefFkCreSqlRows2.next() && (fkcresql=(dgt_schar*)DefFkCreSqlRows2.data())) {
                if (fkcresql && strlen(fkcresql) > 2) {
                        strcpy(TextBuf,fkcresql);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }
#endif

    //
    // If Pk,Fk Working set table then pk,fk migration
    //
#if 0
	*TextBuf=0;
        *TmpBuf=0;
        StmtNo=4000;
        pkfk_sql* sql_row;
        PkSqlRows.rewind();
        FkSqlRows.rewind();
        if (IsPkFk == 1) {
                PkSqlRows.rewind();
                FkSqlRows.rewind();
		if (TabInfo.iot_type == 0) {
                        while (PkSqlRows.next() && (sql_row=(pkfk_sql*)PkSqlRows.data())) {
                                *TextBuf=0;
                                if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                                        strcpy(TextBuf,sql_row->enc2);
                                        if (saveSqlText() < 0) {
                                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                        }
                                }
                        }
                }
                while (FkSqlRows.next() && (sql_row=(pkfk_sql*)FkSqlRows.data())) {
                        *TextBuf=0;
                        if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                                strcpy(TextBuf,sql_row->enc2);
                                if (saveSqlText() < 0) {
                                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                }
                        }
                }

                PkSqlRows.rewind();
                FkSqlRows.rewind();
		if (TabInfo.iot_type == 0) { 
	                while (PkSqlRows.next() && (sql_row=(pkfk_sql*)PkSqlRows.data())) {
        	                *TextBuf=0;
                	        if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
                        	        strcpy(TextBuf,sql_row->enc1);
                                	if (saveSqlText() < 0) {
                                        	ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	                                }
        	                }
                	}
		}
                while (FkSqlRows.next() && (sql_row=(pkfk_sql*)FkSqlRows.data())) {
                        *TextBuf=0;
                        if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
                                strcpy(TextBuf,sql_row->enc1);
                                if (saveSqlText() < 0) {
                                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                }
                        }
                }
        }
#endif
    //
    // Transaction Logging apply to encryption table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 5000;
    if (TabInfo.tran_trg_flag == 1 && TranIdxColRows.numRows() > 0) {
        dgt_sint32 loop;
        for (loop = 0; loop < 2; loop++) {
            *TextBuf = 0;
            *TmpBuf = 0;
            sprintf(TextBuf,
                    "declare \n"
                    "begin \n"
                    "     %s.proc2_%lld; \n"
                    "     commit;\n"
                    "end;",
                    AgentName, TabInfo.enc_tab_id);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop trigger %s.%s", AgentName,
                TabInfo.tab_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        if (!strcasecmp(DbVersion, "9i"))
            sprintf(TextBuf, "drop table %s.%s", AgentName,
                    TabInfo.tran_tab_name);
        else
            sprintf(TextBuf, "drop table %s.%s purge", AgentName,
                    TabInfo.tran_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop procedure %s.proc1_%lld", AgentName,
                TabInfo.enc_tab_id);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop procedure %s.proc2_%lld", AgentName,
                TabInfo.enc_tab_id);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }

    //
    // rename orginal table
    //
    StmtNo = 6000;
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "alter table %s.%s rename to %s", SchemaName,
            TabInfo.table_name, TabInfo.org_renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // rename enc column name -> original column name
    //
#if 0
        StmtNo=4500;
        pc_type_col_info*       col_info;
        if (TabInfo.org_col_name_flag == 1) {
                ColInfoRows.rewind();
                while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        if (col_info->status == 1) {
                                *TextBuf=0;
                                if (TabInfo.enc_type == 0) {
                                        sprintf(TextBuf,"alter table %s.%s rename column %s to %s",
                                                        SchemaName, TabInfo.renamed_tab_name, col_info->renamed_col_name, col_info->col_name);
                                        if (saveSqlText() < 0) {
                                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                        }
                                } else {
                                        sprintf(TextBuf,"alter table %s.%s rename column %s to %s",
                                                        SchemaName, TabInfo.table_name, col_info->renamed_col_name, col_info->col_name);
                                        if (saveSqlText() < 0) {
                                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                        }
                                }
                        }
                }
        }
#endif

    //
    // create view or rename encryption table -> original table name
    //
    StmtNo = 7000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.first_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                    TabInfo.renamed_tab_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
            TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last ";" off
            *TmpBuf = 0;
            sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.first_view_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf, ",rowid row_id");
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    } else {
        sprintf(TextBuf, "alter table %s.%s rename to %s", SchemaName,
                TabInfo.renamed_tab_name, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    StmtNo = 8000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type != 0 && TabInfo.user_view_flag == 1) {
        sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                SchemaName, TabInfo.first_view_name);
        ColInfoRows.rewind();
        pc_type_col_info* col_info = 0;
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 1) {
                if (col_info->cipher_type == 4) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", col_info->col_name,
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", getFname(col_info->col_name, 2),
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        IdxColRows.rewind();
        if (IdxColRows.numRows() == 0) {
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            TextBuf[strlen(TextBuf) - 1] = 0;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // if plugin view -> create the instead of trigger
    // if dml_trg_flag=yes -> view + dml trigger(must modify update,insert sql`s
    // tablename ex: insert into table -> insert into table$$
    //
    *TmpBuf = 0;
    *TextBuf = 0;
    StmtNo = 9000;
    if (TabInfo.dml_trg_flag == 1) {
        dgt_sint32 ver_flag = 0;
        if (!strcasecmp(DbVersion, "11g")) ver_flag = 1;
        if (TabInfo.enc_type == 0) {
            sprintf(TextBuf,
                    "create or replace trigger %s.%s\nbefore insert or update "
                    "on %s.%s for each row\ndeclare \n",
                    SchemaName, TabInfo.view_trigger_name, SchemaName,
                    TabInfo.renamed_tab_name);
        } else {
            sprintf(TextBuf,
                    "create or replace trigger %s.%s\nbefore insert or update "
                    "on %s.%s for each row\ndeclare \n",
                    SchemaName, TabInfo.view_trigger_name, SchemaName,
                    TabInfo.table_name);
        }
        ColInfoRows.rewind();
        pc_type_col_info* col_info;
        //
        // for 11g trigger (performance issue)
        //
        if (ver_flag) {
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                if (col_info->status == 1) {
                    *TmpBuf = 0;
                    dgt_sint32 enc_len = 0;
                    if (!strcasecmp(col_info->data_type, "NUMBER"))
                        enc_len = (col_info->data_precision + 2);
                    else if (!strcasecmp(col_info->data_type, "DATE") ||
                             !strcasecmp(col_info->data_type, "TIMESTAMP"))
                        enc_len = 14;
                    else if (col_info->multi_byte_flag)
                        enc_len = col_info->data_length * 3;
                    else
                        enc_len = col_info->data_length;
                    PCI_Context ctx;
                    PCI_initContext(
                        &ctx, 0, col_info->key_size, col_info->cipher_type,
                        col_info->enc_mode, col_info->iv_type,
                        col_info->n2n_flag, col_info->b64_txt_enc_flag,
                        col_info->enc_start_pos, col_info->enc_length);
                    enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
                    if (col_info->index_type == 1) {
                        enc_len += PCI_ophuekLength(col_info->data_length,
                                                    PCI_SRC_TYPE_CHAR, 1);
                        enc_len += 4;
                    }
                    if (!strcasecmp(col_info->data_type, "NCHAR") ||
                        !strcasecmp(col_info->data_type, "NVARCHAR2")) {
                        enc_len = enc_len * 3;
                    }
                    if (!strcasecmp(col_info->data_type, "CLOB") ||
                        !strcasecmp(col_info->data_type, "BLOB")) {
                        sprintf(TmpBuf, "\t v_%s BLOB;\n", col_info->col_name);
                    } else {
                        if (col_info->b64_txt_enc_flag &&
                            col_info->b64_txt_enc_flag != 4) {
                            sprintf(TmpBuf, "\t v_%s varchar2(%d);\n",
                                    col_info->col_name, enc_len);
                        } else {
                            sprintf(TmpBuf, "\t v_%s raw(%d);\n",
                                    col_info->col_name, enc_len);
                        }
                    }
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        strcat(TextBuf, "begin\n");
        //
        // for check constraint
        //
        CheckTrgRows.rewind();
        typedef struct {
            dgt_schar search_condition[4000];
            dgt_schar default_val[4000];
        } type_check;
        type_check* tmp_search = 0;
        while (CheckTrgRows.next() &&
               (tmp_search = (type_check*)CheckTrgRows.data())) {
            if (strlen(tmp_search->default_val) > 2 &&
                strstr(tmp_search->search_condition, "IS NOT NULL"))
                continue;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n if not ");
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf, "( :new.%s )", tmp_search->search_condition);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf,
                    " then\n\t raise_application_error(-20001,'%s`s check "
                    "constraint violated');\n end if;\n",
                    TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
        }
        *TmpBuf = 0;
#if 1
        sprintf(TmpBuf, "\tif inserting then\n");
        strcat(TextBuf, TmpBuf);
#endif
        if (ver_flag) {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t v_%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t :new.%s := v_%s;\n",
                            col_info->col_name, col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
        } else {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t :new.%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        *TmpBuf = 0;
#if 1
        sprintf(TmpBuf, "\telsif updating then\n");
        strcat(TextBuf, TmpBuf);
        if (ver_flag) {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    sprintf(TmpBuf, "\t\t if updating('%s') then\n",
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t v_%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t :new.%s := v_%s;\n",
                            col_info->col_name, col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    strcat(TextBuf, "\t\t end if;\n");
                }
            }
        } else {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    sprintf(TmpBuf, "\t\t if updating('%s') then\n",
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t :new.%s := %s;\n",
                            col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    strcat(TextBuf, "\t\t end if;\n");
                }
            }
        }
        strcat(TextBuf, "\tend if;\n");
#endif
        strcat(TextBuf, "\n end;\n");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
            if (insteadOfTrigger(1)) {
                ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
            }
        }
    }
    //
    // grant privilege
    //
    StmtNo = 11000;
    *TextBuf = 0;
    *TmpBuf = 0;
    PrivSqlRows.rewind();
    if (TabInfo.grant_flag) {
        while (PrivSqlRows.next()) {
            *TextBuf = 0;
            strcat(TextBuf, (dgt_schar*)PrivSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // synonym recreate
    //
    StmtNo = 12000;
    *TextBuf = 0;
    *TmpBuf = 0;
    pc_type_synonym_sql* syn_info_tmp;
    SynonymSqlRows.rewind();
    if (SynonymSqlRows.next() &&
        (syn_info_tmp = (pc_type_synonym_sql*)SynonymSqlRows.data())) {
        if (syn_info_tmp->drop_sql_id) {
            strcpy(TextBuf, syn_info_tmp->drop_sql_id);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        *TextBuf = 0;
        if (syn_info_tmp->create_sql_id && *syn_info_tmp->create_sql_id) {
            strcpy(TextBuf, syn_info_tmp->create_sql_id);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // create comment
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 13000;
    CommentInfoRows.rewind();
    dgt_schar* comment_sql;
    while (CommentInfoRows.next() &&
           (comment_sql = (dgt_schar*)CommentInfoRows.data())) {
        *TextBuf = 0;
        if (comment_sql && strlen(comment_sql) > 2) {
            strcpy(TextBuf, comment_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // Drop The Original table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 14000;
    if (TabInfo.keep_org_tab_flag >= 1) {
        IdxSqlRows5.rewind();
        dgt_schar* rename_idx = 0;
        while (IdxSqlRows5.next() &&
               (rename_idx = (dgt_schar*)IdxSqlRows5.data())) {
            if (rename_idx && strlen(rename_idx) > 2) {
                *TextBuf = 0;
                strcpy(TextBuf, rename_idx);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    } else {
        if (!strcasecmp(DbVersion, "9i"))
            sprintf(TextBuf, "drop table %s.%s", SchemaName,
                    TabInfo.org_renamed_tab_name);
        else
            sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                    TabInfo.org_renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }

    //
    // If Pk,Fk Working set table then pk,fk migration
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 15000;
    pkfk_sql* sql_row;
    PkSqlRows.rewind();
    FkSqlRows.rewind();
    if (IsPkFk == 1) {
        PkSqlRows.rewind();
        FkSqlRows.rewind();
        if (TabInfo.iot_type == 0) {
            while (PkSqlRows.next() &&
                   (sql_row = (pkfk_sql*)PkSqlRows.data())) {
                *TextBuf = 0;
                if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                    strcpy(TextBuf, sql_row->enc2);
                    if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                    }
                }
            }
        }
        while (FkSqlRows.next() && (sql_row = (pkfk_sql*)FkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                strcpy(TextBuf, sql_row->enc2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }

        PkSqlRows.rewind();
        FkSqlRows.rewind();
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
    *TextBuf = 0;
    *TmpBuf = 0;
    DefFkCreSqlRows2.rewind();
    dgt_schar* fkcresql = 0;
    while (DefFkCreSqlRows2.next() &&
           (fkcresql = (dgt_schar*)DefFkCreSqlRows2.data())) {
        if (fkcresql && strlen(fkcresql) > 2) {
            strcpy(TextBuf, fkcresql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // rename renamed index name -> orginal index name
    //
#if 1
    StmtNo = 16000;
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows4.rewind();
    dgt_schar* rename_idx = 0;
    while (IdxSqlRows4.next() &&
           (rename_idx = (dgt_schar*)IdxSqlRows4.data())) {
        if (rename_idx && strlen(rename_idx) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, rename_idx);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
#endif
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo = 17000;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjTriggerSqlRows.next()) {
            *TextBuf = 0;
            sprintf(TextBuf, (dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo = 18000;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjSqlRows.next()) {
            *TextBuf = 0;
            strcat(TextBuf, (dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // keep_org_tab_flag  == 1
    // for supporting manual script(restore and instead of trigger)
    //
    if (TabInfo.keep_org_tab_flag >= 1) {
        StepNo = 10;
        StmtNo = -10;
        // restore flag
        *TextBuf = 0;
        *TmpBuf = 0;
        if (TabInfo.enc_type == 0) {
            *TextBuf = 0;
            sprintf(TextBuf, "drop view %s.%s", SchemaName,
                    TabInfo.second_view_name);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
                *TextBuf = 0;
                sprintf(TextBuf, "drop view %s.%s", SchemaName,
                        TabInfo.first_view_name);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        } else {
            if (!strcasecmp(DbVersion, "9i"))
                sprintf(TextBuf, "drop table %s.%s", SchemaName,
                        TabInfo.table_name);
            else
                sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                        TabInfo.table_name);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "alter table %s.%s rename to %s", SchemaName,
                TabInfo.org_renamed_tab_name, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        //
        //  encrypt completion script(modify instead of trigger)
        //
        StepNo = 10;
        StmtNo = 0;
        if (TabInfo.keep_org_tab_flag == 2) {
            TabInfo.keep_org_tab_flag = 0;
            if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
                if (insteadOfTrigger(1)) {
                    ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
                }
            }
        }
        *TmpBuf = 0;
        *TextBuf = 0;
        if (!strcasecmp(DbVersion, "9i"))
            sprintf(TextBuf, "drop table %s.%s", SchemaName,
                    TabInfo.org_renamed_tab_name);
        else
            sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                    TabInfo.org_renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }

    return 0;
}

dgt_sint32 PccOraScriptBuilder::reverse_step1() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //
    //
    StepNo = -1;
    StmtNo = -11000;
    if (TabInfo.tran_trg_flag == 1 && TranIdxColRows.numRows() > 0) {
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop trigger %s.%s", AgentName,
                TabInfo.tab_trigger_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        if (!strcasecmp(DbVersion, "9i"))
            sprintf(TextBuf, "drop table %s.%s", AgentName,
                    TabInfo.tran_tab_name);
        else
            sprintf(TextBuf, "drop table %s.%s purge", AgentName,
                    TabInfo.tran_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop procedure %s.proc1_%lld", AgentName,
                TabInfo.enc_tab_id);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "drop procedure %s.proc2_%lld", AgentName,
                TabInfo.enc_tab_id);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    //
    // drop enc table & rename original table
    //
    StmtNo = -1000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (!strcasecmp(DbVersion, "9i")) {
        sprintf(TextBuf, "drop table %s.%s", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                TabInfo.renamed_tab_name);
    }
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    if (!strcasecmp(DbVersion, "9i"))
        sprintf(TextBuf, "drop table %s.%s", SchemaName,
                TabInfo.org_renamed_tab_name);
    else
        sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                TabInfo.org_renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    return 0;
}

dgt_sint32 PccOraScriptBuilder::reverse_step2() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //
    // create the copy table (same as original table)
    //
    StepNo = -2;
    StmtNo = -17000;
    *TextBuf = 0;
    *TmpBuf = 0;
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
    }
    if (TabInfo.partitioned == 1) {
        sprintf(sql_text,
                "declare "
                "begin "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'CONSTRAINTS',FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'REF_CONSTRAINTS', FALSE); "
                "end;");
    } else {
        sprintf(sql_text,
                "declare "
                "begin "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'CONSTRAINTS',FALSE); "
                "dbms_metadata.set_transform_param(dbms_metadata.session_"
                "transform,'REF_CONSTRAINTS', FALSE); "
                //    "dbms_metadata.set_transform_param(dbms_metadata.session_transform,'TABLESPACE',FALSE);
                //    "
                "end;");
    }
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;
    sprintf(sql_text,
            "select dbms_metadata.get_ddl('TABLE','%s','%s') from dual",
            TabInfo.table_name, SchemaName);
    stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcMemRows* rows = stmt->returnRows();
    rows->rewind();
    dgt_schar* ddl_stmt_ptr = 0;
    while (rows->next() && (ddl_stmt_ptr = (dgt_schar*)rows->data())) {
        strcpy(TmpBuf, ddl_stmt_ptr);
        sprintf(TextBuf, "CREATE TABLE %s.%s_%lld ", SchemaName, "petra",
                TabInfo.enc_tab_id);
        dgt_schar table_name[130];
        memset(table_name, 0, 130);
        sprintf(table_name, "\"%s\"", TabInfo.table_name);
        dgt_schar* tmp = strstr(TmpBuf, table_name);
        if (tmp) {
            dgt_uint32 i = 0;
            for (i = 0; i < strlen(table_name); i++) {
                tmp++;
            }
        }
        strcat(TextBuf, tmp);
#if 0
                if (TabInfo.partitioned == 0) {
                        *TmpBuf=0;
                        sprintf(TmpBuf," TABLESPACE %s",TabInfo.target_tablespace_name);
                        strcat(TextBuf,TmpBuf);
                }
#endif
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    delete stmt;
    *TextBuf = 0;
    ColInfoRows.rewind();
    pc_type_col_info* col_info = 0;
    dgt_sint32 lob_flag = 0;
    dgt_sint32 long_flag = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                lob_flag = 1;
            }
            if (!strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW")) {
                long_flag = 1;
            }
        }
    }
#if 0
        if (lob_flag == 0) {
		if (TabInfo.enc_type == 0) {
	                sprintf(TextBuf,"alter table %s.%s parallel %d",SchemaName, TabInfo.renamed_tab_name, ParallelDegree);
        	        if (saveSqlText() < 0) {
                	        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	                }
		} else {
	                sprintf(TextBuf,"alter table %s.%s parallel %d",SchemaName, TabInfo.table_name, ParallelDegree);
        	        if (saveSqlText() < 0) {
                	        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	                }
		}
        }
#endif
    // insert decryption (parallel insert)
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    if (lob_flag == 1) {
        ColInfoRows.rewind();
        sprintf(TmpBuf, "insert into %s.%s_%lld( ", SchemaName, "petra",
                TabInfo.enc_tab_id);
        strcat(TextBuf, TmpBuf);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ") \nselect ");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 1) {
                sprintf(TmpBuf, "%s,", getFname(col_info->col_name, 2));
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
    } else {
        *TextBuf = 0;
        sprintf(TextBuf, "ALTER SESSION FORCE PARALLEL DML");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        *TextBuf = 0;
        ColInfoRows.rewind();
        if (TabInfo.enc_type == 0) {
            sprintf(TmpBuf,
                    "insert /*+ APPEND PARALLEL(petra_%lld,%d) */ into "
                    "%s.%s_%lld \n select /*+ FULL(%s) PARALLEL(%s,%d) */ ",
                    TabInfo.enc_tab_id, ParallelDegree, SchemaName, "petra",
                    TabInfo.enc_tab_id, TabInfo.renamed_tab_name,
                    TabInfo.renamed_tab_name, ParallelDegree);
        } else {
            sprintf(TmpBuf,
                    "insert /*+ APPEND PARALLEL(petra_%lld,%d) */ into "
                    "%s.%s_%lld \n select /*+ FULL(%s) PARALLEL(%s,%d) */ ",
                    TabInfo.enc_tab_id, ParallelDegree, SchemaName, "petra",
                    TabInfo.enc_tab_id, TabInfo.table_name, TabInfo.table_name,
                    ParallelDegree);
        }
        strcat(TextBuf, TmpBuf);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status == 1) {
                *TmpBuf = 0;
                sprintf(TmpBuf, getFname(col_info->col_name, 2));
                strcat(TmpBuf, ",");
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.renamed_tab_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.table_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    sprintf(TextBuf, "ALTER SESSION DISABLE PARALLEL DML");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
#if 0
        if (long_flag ==1) {
                sprintf(TextBuf,"declare\n   urows number := 0;\n   v_rowid rowid;\n");
                *TmpBuf=0;
                sprintf(TmpBuf,"   cursor c1 is\n      select rowid from %s.%s_%lld\n       where",SchemaName,"petra",TabInfo.enc_tab_id); 
                strcat(TextBuf,TmpBuf);
                ColInfoRows.rewind();
                for(dgt_uint16 i=0; ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data());) {
                        if (col_info->status == 1) {
                                *TmpBuf=0;
                                if (i++ == 0) sprintf(TmpBuf," %s is null", col_info->col_name);
                                else sprintf(TmpBuf," or %s is null", col_info->col_name);
                                strcat(TextBuf,TmpBuf);
                        }
                }
                strcat(TextBuf,";\nbegin\n   open c1;\n   loop\n\tfetch c1 into v_rowid;\n\texit when c1%NOTFOUND;\n");
                *TmpBuf=0;
                sprintf(TmpBuf,"\tupdate %s.%s_%lld set",SchemaName,"petra" ,TabInfo.enc_tab_id);
                strcat(TextBuf,TmpBuf);
                ColInfoRows.rewind();
                while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        if (col_info->status == 1 && (!strcasecmp(col_info->data_type, "LONG") || !strcasecmp(col_info->data_type, "LONG RAW"))) {
                                *TmpBuf=0;
                                sprintf(TmpBuf,"\n\t\t%s=%s,", col_info->col_name, getFname(col_info->col_name,2));
                                strcat(TextBuf,TmpBuf);
                        }
                }
                TextBuf[strlen(TextBuf)-1]=0;
                *TmpBuf=0;
                sprintf(TmpBuf,"\n\t where rowid = v_rowid;\n\turows := urows + 1;\n\tif ((urows mod %u) = 0) then\n\t\tcommit;\n\tend if;\n   end loop; \
                                \n   commit;\nend;\n", 1000);
                strcat(TextBuf,TmpBuf);
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
        }
#endif
    //
    // rename enc column name -> original column name
    //
#if 0
        *TextBuf=0;
        *TmpBuf=0;
        col_info=0;
        if (TabInfo.org_col_name_flag == 1) {
                ColInfoRows.rewind();
                while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        if (col_info->status == 1) {
                                *TextBuf=0;
                                if (TabInfo.enc_type == 0) {
                                        sprintf(TextBuf,"alter table %s.%s rename column %s to %s",
                                                        SchemaName, TabInfo.renamed_tab_name, col_info->col_name, col_info->renamed_col_name);
                                        if (saveSqlText() < 0) {
                                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                        }
                                } else {
                                        sprintf(TextBuf,"alter table %s.%s rename column %s to %s",
                                                        SchemaName, TabInfo.table_name, col_info->col_name, col_info->renamed_col_name);
                                        if (saveSqlText() < 0) {
                                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                        }
                                }
                        }
                }
        }
#endif

    //
    // Create the table`s original index
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows6.rewind();
    IdxSqlRows3.rewind();
    dgt_schar* idx_sql = 0;
    while (IdxSqlRows6.next() && (idx_sql = (dgt_schar*)IdxSqlRows6.data())) {
        if (idx_sql && strlen(idx_sql) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    while (IdxSqlRows3.next() && (idx_sql = (dgt_schar*)IdxSqlRows3.data())) {
        if (idx_sql && strlen(idx_sql) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // make unique constraint
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    UniqueSqlRows2.rewind();
    dgt_schar* unisql = 0;
    while (UniqueSqlRows2.next() &&
           (unisql = (dgt_schar*)UniqueSqlRows2.data())) {
        if (unisql && strlen(unisql) > 2) {
            strcpy(TextBuf, unisql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // If not null check constraint exist drop and create
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    CheckSqlRows.rewind();
    pc_type_check_sql* check_sql = 0;
    while (CheckSqlRows.next() &&
           (check_sql = (pc_type_check_sql*)CheckSqlRows.data())) {
        *TextBuf = 0;
        if (check_sql->org1 && strlen(check_sql->org1) > 2) {
            strcpy(TextBuf, check_sql->org1);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // Create the Constraint (Pk,Fk,Check)
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    dgt_schar* pksql = 0;
    StmtNo = -2000;
    DefFkDropSqlRows2.rewind();
    dgt_schar* fkdropsql = 0;
    while (DefFkDropSqlRows2.next() &&
           (fkdropsql = (dgt_schar*)DefFkDropSqlRows2.data())) {
        if (fkdropsql && strlen(fkdropsql) > 2) {
            strcpy(TextBuf, fkdropsql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    DefFkDropSqlRows.rewind();
    typedef struct {
        dgt_schar enc_sql[512];
        dgt_schar org_sql[512];
    } enc_table_fk;
    enc_table_fk* tmp_ptr = 0;
    while (DefFkDropSqlRows.next() &&
           (tmp_ptr = (enc_table_fk*)DefFkDropSqlRows.data())) {
        if (tmp_ptr->org_sql && strlen(tmp_ptr->org_sql) > 2) {
            strcpy(TextBuf, tmp_ptr->org_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = -1000;
#if 0
        DefFkCreSqlRows3.rewind();
        dgt_schar* fkcresql=0;
        while (DefFkCreSqlRows3.next() && (fkcresql=(dgt_schar*)DefFkCreSqlRows3.data())) {
                if (fkcresql && strlen(fkcresql) > 2) {
                        strcpy(TextBuf,fkcresql);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }
#endif
    //
    // drop enc table & rename original table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
#if 0
		sprintf(TextBuf,"drop table %s.%s",SchemaName,TabInfo.renamed_tab_name);
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
#endif
        *TextBuf = 0;
        sprintf(TextBuf, "drop view %s.%s", SchemaName,
                TabInfo.second_view_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            *TextBuf = 0;
            sprintf(TextBuf, "drop view %s.%s", SchemaName,
                    TabInfo.first_view_name);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    } else {
#if 1
        sprintf(TextBuf, "alter table %s.%s rename to %s", SchemaName,
                TabInfo.table_name, TabInfo.renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
#endif
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "alter table %s.%s_%lld rename to %s", SchemaName, "petra",
            TabInfo.enc_tab_id, TabInfo.table_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // grant privilege
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    PrivSqlRows.rewind();
    if (TabInfo.grant_flag) {
        while (PrivSqlRows.next()) {
            *TextBuf = 0;
            strcat(TextBuf, (dgt_schar*)PrivSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // synonym recreate
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    pc_type_synonym_sql* syn_info_tmp;
    SynonymSqlRows.rewind();
    if (SynonymSqlRows.next() &&
        (syn_info_tmp = (pc_type_synonym_sql*)SynonymSqlRows.data())) {
        if (syn_info_tmp->drop_sql_id && *syn_info_tmp->drop_sql_id) {
            strcpy(TextBuf, syn_info_tmp->drop_sql_id);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
        *TextBuf = 0;
        if (syn_info_tmp->create_sql_id && *syn_info_tmp->create_sql_id) {
            strcpy(TextBuf, syn_info_tmp->create_sql_id);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // create comment
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    CommentInfoRows.rewind();
    dgt_schar* comment_sql;
    while (CommentInfoRows.next() &&
           (comment_sql = (dgt_schar*)CommentInfoRows.data())) {
        *TextBuf = 0;
        if (comment_sql && strlen(comment_sql) > 2) {
            strcpy(TextBuf, comment_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjTriggerSqlRows.next()) {
            *TextBuf = 0;
            sprintf(TextBuf, (dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // encrypt tables`s dependency object complie script
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjSqlRows.next()) {
            *TextBuf = 0;
            strcat(TextBuf, (dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // drop enc table & rename original table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    if (!strcasecmp(DbVersion, "9i")) {
        sprintf(TextBuf, "drop table %s.%s", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TextBuf, "drop table %s.%s purge", SchemaName,
                TabInfo.renamed_tab_name);
    }
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    //
    // If Pk,Fk Working set table then pk,fk migration
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    pkfk_sql* sql_row;
    PkSqlRows.rewind();
    FkSqlRows.rewind();
    if (IsPkFk == 1) {
        while (PkSqlRows.next() && (sql_row = (pkfk_sql*)PkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->org3 && strlen(sql_row->org3) > 2) {
                strcpy(TextBuf, sql_row->org3);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
        while (FkSqlRows.next() && (sql_row = (pkfk_sql*)FkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->org3 && strlen(sql_row->org3) > 2) {
                strcpy(TextBuf, sql_row->org3);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    DefFkCreSqlRows3.rewind();
    dgt_schar* fkcresql = 0;
    while (DefFkCreSqlRows3.next() &&
           (fkcresql = (dgt_schar*)DefFkCreSqlRows3.data())) {
        if (fkcresql && strlen(fkcresql) > 2) {
            strcpy(TextBuf, fkcresql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // rename renamed index name -> orginal index name
    //
#if 1
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows4.rewind();
    dgt_schar* rename_idx = 0;
    while (IdxSqlRows4.next() &&
           (rename_idx = (dgt_schar*)IdxSqlRows4.data())) {
        if (rename_idx && strlen(rename_idx) > 2) {
            *TextBuf = 0;
            strcpy(TextBuf, rename_idx);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
#endif

    return 0;
}

dgt_sint32 PccOraScriptBuilder::addColStep() throw(DgcExcept) {
    //
    // alter table modify column
    //
    StepNo = 3;
    StmtNo = 1000;
    *TextBuf = 0;
    *TmpBuf = 0;
    ColInfoRows.rewind();
    pc_type_col_info* col_info = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            dgt_sint32 enc_len = 0;
            if (!strcasecmp(col_info->data_type, "NUMBER"))
                enc_len = (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATE") ||
                     !strcasecmp(col_info->data_type, "TIMESTAMP"))
                enc_len = 14;
            else if (col_info->multi_byte_flag)
                enc_len = col_info->data_length * 3;
            else
                enc_len = col_info->data_length;
            PCI_Context ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type,
                            col_info->enc_mode, col_info->iv_type,
                            col_info->n2n_flag, col_info->b64_txt_enc_flag,
                            col_info->enc_start_pos, col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            if (col_info->index_type == 1) {
                enc_len += PCI_ophuekLength(col_info->data_length,
                                            PCI_SRC_TYPE_CHAR, 1);
                enc_len += 4;
            }
            if (!strcasecmp(col_info->data_type, "NCHAR") ||
                !strcasecmp(col_info->data_type, "NVARCHAR2")) {
                enc_len = enc_len * 3;
            }
            *TextBuf = 0;
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                if (TabInfo.enc_type == 0) {
                    sprintf(TextBuf, "alter table %s.%s modify %s BLOB",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name);
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s BLOB",
                            SchemaName, TabInfo.table_name, col_info->col_name);
                }
            } else if (!strcasecmp(col_info->data_type, "LONG") ||
                       !strcasecmp(col_info->data_type, "LONG RAW")) {
                if (TabInfo.enc_type == 0) {
                    sprintf(TextBuf, "alter table %s.%s modify %s BLOB",
                            SchemaName, TabInfo.renamed_tab_name,
                            col_info->col_name);
                } else {
                    sprintf(TextBuf, "alter table %s.%s modify %s BLOB",
                            SchemaName, TabInfo.table_name, col_info->col_name);
                }
            } else {
                if (col_info->b64_txt_enc_flag &&
                    col_info->b64_txt_enc_flag != 4) {
                    if (TabInfo.enc_type == 0) {
                        sprintf(TextBuf,
                                "alter table %s.%s modify %s varchar2(%d)",
                                SchemaName, TabInfo.renamed_tab_name,
                                col_info->col_name, enc_len);
                    } else {
                        sprintf(TextBuf,
                                "alter table %s.%s modify %s varchar2(%d)",
                                SchemaName, TabInfo.table_name,
                                col_info->col_name, enc_len);
                    }
                } else {
                    if (TabInfo.enc_type == 0) {
                        sprintf(TextBuf, "alter table %s.%s modify %s raw(%d)",
                                SchemaName, TabInfo.renamed_tab_name,
                                col_info->col_name, enc_len);
                    } else {
                        sprintf(TextBuf, "alter table %s.%s modify %s raw(%d)",
                                SchemaName, TabInfo.table_name,
                                col_info->col_name, enc_len);
                    }
                }
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // encrypting data without exclusive access
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 2000;
    sprintf(TextBuf, "declare\n   urows number := 0;\n   v_rowid rowid;\n");
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "number")) {
                if (col_info->data_precision == 0) {
                    sprintf(TmpBuf, "   v_%s %s;\n", col_info->col_name,
                            col_info->data_type);
                } else {
                    sprintf(TmpBuf, "   v_%s %s(%d,%d);\n", col_info->col_name,
                            col_info->data_type, col_info->data_precision,
                            col_info->data_scale);
                }
            } else if (!strcasecmp(col_info->data_type, "date")) {
                sprintf(TmpBuf, "   v_%s %s;\n", col_info->col_name,
                        col_info->data_type);
            } else if (!strcasecmp(col_info->data_type, "raw")) {
                sprintf(TmpBuf, "   v_%s %s(%u);\n", col_info->col_name,
                        col_info->data_type, col_info->data_length);
            } else {
                sprintf(TmpBuf, "   v_%s varchar2(%u);\n", col_info->col_name,
                        col_info->data_length);
            }
            strcat(TextBuf, TmpBuf);
        }
    }
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf, "   cursor c1 is\n      select rowid from %s.%s;\n",
                SchemaName, TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf, "   cursor c1 is\n      select rowid from %s.%s;\n",
                SchemaName, TabInfo.table_name);
    }
    strcat(TextBuf, TmpBuf);
    strcat(TextBuf,
           "\nbegin\n   open c1;\n   loop\n\tfetch c1 into v_rowid;\n\texit "
           "when c1%NOTFOUND;\n");
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf, "\tupdate %s.%s set", SchemaName,
                TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf, "\tupdate %s.%s set", SchemaName, TabInfo.table_name);
    }
    strcat(TextBuf, TmpBuf);
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            dgt_sint32 idx_flag = col_info->index_type;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\t\t%s=%s,", col_info->col_name,
                    getFname(col_info->col_name, 1));
            strcat(TextBuf, TmpBuf);
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    sprintf(
        TmpBuf,
        "\n\t where rowid = v_rowid;\n\turows := urows + 1;\n\tif ((urows mod %u) = 0) then\n\t\tcommit;\n\tend if;\n   end loop; \
                        \n   commit;\nend;\n",
        1000);
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 3000;
    if (TabInfo.enc_type == 0) {
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.first_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status >= 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                    TabInfo.renamed_tab_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
            TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last ";" off
            *TmpBuf = 0;
            sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.first_view_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status >= 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf, ",rowid row_id");
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    //
    // if plugin view -> create the instead of trigger
    // if dml trigger use -> create the before of trigger
    //#646 issue fix by shson 2019.01.04
    *TmpBuf = 0;
    *TextBuf = 0;
    StmtNo = 4000;
    if (TabInfo.dml_trg_flag == 1) {
        dgt_sint32 ver_flag = 0;
        if (!strcasecmp(DbVersion, "11g")) ver_flag = 1;
        if (TabInfo.enc_type == 0) {
            sprintf(TextBuf,
                    "create or replace trigger %s.%s\nbefore insert or update "
                    "on %s.%s for each row\ndeclare \n",
                    SchemaName, TabInfo.view_trigger_name, SchemaName,
                    TabInfo.renamed_tab_name);
        } else {
            sprintf(TextBuf,
                    "create or replace trigger %s.%s\nbefore insert or update "
                    "on %s.%s for each row\ndeclare \n",
                    SchemaName, TabInfo.view_trigger_name, SchemaName,
                    TabInfo.table_name);
        }
        ColInfoRows.rewind();
        pc_type_col_info* col_info;
        //
        // for 11g trigger (performance issue)
        //
        if (ver_flag) {
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                if (col_info->status == 1 || col_info->status == 2) {
                    *TmpBuf = 0;
                    dgt_sint32 enc_len = 0;
                    if (!strcasecmp(col_info->data_type, "NUMBER"))
                        enc_len = (col_info->data_precision + 2);
                    else if (!strcasecmp(col_info->data_type, "DATE") ||
                             !strcasecmp(col_info->data_type, "TIMESTAMP"))
                        enc_len = 14;
                    else if (col_info->multi_byte_flag)
                        enc_len = col_info->data_length * 3;
                    else
                        enc_len = col_info->data_length;
                    PCI_Context ctx;
                    PCI_initContext(
                        &ctx, 0, col_info->key_size, col_info->cipher_type,
                        col_info->enc_mode, col_info->iv_type,
                        col_info->n2n_flag, col_info->b64_txt_enc_flag,
                        col_info->enc_start_pos, col_info->enc_length);
                    enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
                    if (col_info->index_type == 1) {
                        enc_len += PCI_ophuekLength(col_info->data_length,
                                                    PCI_SRC_TYPE_CHAR, 1);
                        enc_len += 4;
                    }
                    if (!strcasecmp(col_info->data_type, "NCHAR") ||
                        !strcasecmp(col_info->data_type, "NVARCHAR2")) {
                        enc_len = enc_len * 3;
                    }
                    if (!strcasecmp(col_info->data_type, "CLOB") ||
                        !strcasecmp(col_info->data_type, "BLOB")) {
                        sprintf(TmpBuf, "\t v_%s BLOB;\n", col_info->col_name);
                    } else {
                        if (col_info->b64_txt_enc_flag &&
                            col_info->b64_txt_enc_flag != 4) {
                            sprintf(TmpBuf, "\t v_%s varchar2(%d);\n",
                                    col_info->col_name, enc_len);
                        } else {
                            sprintf(TmpBuf, "\t v_%s raw(%d);\n",
                                    col_info->col_name, enc_len);
                        }
                    }
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        strcat(TextBuf, "begin\n");
        //
        // for check constraint
        //
        CheckTrgRows.rewind();
        typedef struct {
            dgt_schar search_condition[4000];
            dgt_schar default_val[4000];
        } type_check;
        type_check* tmp_search = 0;
        while (CheckTrgRows.next() &&
               (tmp_search = (type_check*)CheckTrgRows.data())) {
            if (strlen(tmp_search->default_val) > 2 &&
                strstr(tmp_search->search_condition, "IS NOT NULL"))
                continue;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n if not ");
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf, "( :new.%s )", tmp_search->search_condition);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf,
                    " then\n\t raise_application_error(-20001,'%s`s check "
                    "constraint violated');\n end if;\n",
                    TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
        }
        *TmpBuf = 0;
#if 1
        sprintf(TmpBuf, "\tif inserting then\n");
        strcat(TextBuf, TmpBuf);
#endif
        if (ver_flag) {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1 || col_info->status == 2) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t v_%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t :new.%s := v_%s;\n",
                            col_info->col_name, col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
        } else {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1 || col_info->status == 2) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t :new.%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                }
            }
        }
        *TmpBuf = 0;
#if 1
        sprintf(TmpBuf, "\telsif updating then\n");
        strcat(TextBuf, TmpBuf);
        if (ver_flag) {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1 || col_info->status == 2) {
                    sprintf(TmpBuf, "\t\t if updating('%s') then\n",
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t v_%s := %s;\n", col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t :new.%s := v_%s;\n",
                            col_info->col_name, col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    strcat(TextBuf, "\t\t end if;\n");
                }
            }
        } else {
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1 || col_info->status == 2) {
                    sprintf(TmpBuf, "\t\t if updating('%s') then\n",
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\t\t\t :new.%s := %s;\n",
                            col_info->col_name,
                            getFname(col_info->col_name, 1, 1));
                    strcat(TextBuf, TmpBuf);
                    *TmpBuf = 0;
                    strcat(TextBuf, "\t\t end if;\n");
                }
            }
        }
        strcat(TextBuf, "\tend if;\n");
#endif
        strcat(TextBuf, "\n end;\n");
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
            if (insteadOfTrigger(1)) {
                ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
            }
        }
    }

    //
    // Petra Index sql create
    //
    dgt_schar idx_sql[512];
    dgt_schar normal_sql[512];
    dgt_schar idx_sql2[512];
    dgt_schar normal_sql2[512];
    dgt_schar idx_col_idx1[512];
    dgt_schar idx_col_idx2[512];
    dgt_schar sql_text[2048];
    memset(idx_sql, 0, 512);
    memset(normal_sql, 0, 512);
    memset(idx_sql2, 0, 512);
    memset(normal_sql2, 0, 512);
    memset(sql_text, 0, 2048);
    memset(idx_col_idx1, 0, 512);
    memset(idx_col_idx2, 0, 512);
    StmtNo = 5000;
    *TmpBuf = 0;
    *TextBuf = 0;
    if (TabInfo.synonym_flag == 0) {
        sprintf(sql_text,
                "select a.enc_col_id, b.renamed_col_name, b.data_type, "
                "a.index_type, b.domain_index_name, b.fbi_index_name, "
                "b.normal_index_name, a.tablespace_name, a.normal_idx_flag, "
                "b.column_name "
                "from pct_enc_index a, pct_enc_column b, pct_enc_table c "
                "where a.enc_col_id = b.enc_col_id "
                "and   b.enc_tab_id = c.enc_tab_id "
                "and   b.enc_tab_id = %lld "
                "and   b.status = 2",
                TabInfo.enc_tab_id);
    } else {
        sprintf(sql_text,
                "select d.key_id, b.renamed_col_name, b.data_type, "
                "a.index_type, b.domain_index_name, b.fbi_index_name, "
                "b.normal_index_name, a.tablespace_name, a.normal_idx_flag, "
                "b.column_name "
                "from pct_enc_index a, pct_enc_column b, pct_enc_table c, "
                "pct_encrypt_key d "
                "where a.enc_col_id = b.enc_col_id "
                "and   b.enc_tab_id = c.enc_tab_id "
                "and   b.key_id = d.key_id "
                "and   b.enc_tab_id = %lld "
                "and   b.status = 2",
                TabInfo.enc_tab_id);
    }

    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_index_row* idx_info = 0;
    while ((idx_info = (pc_type_index_row*)sql_stmt->fetch())) {
        if (idx_info->index_type == 1) {
            if (TabInfo.enc_type == 0 && idx_info->normal_idx_flag == 1) {
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->index_col_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->index_col_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->index_col_name,
                            AgentName);
                }
            } else if (TabInfo.enc_type == 1 &&
                       idx_info->normal_idx_flag == 1) {
                if (!strcasecmp(idx_info->data_type, "NUMBER")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP2",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.table_name, idx_info->index_col_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type, "DATE") ||
                           !strcasecmp(idx_info->data_type, "TIMESTAMP")) {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP3",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.table_name, idx_info->index_col_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,
                            "create index %s.%s on %s.%s(%s) indextype is "
                            "%s.PC_IDX1_TYP1",
                            SchemaName, idx_info->domain_index_name, SchemaName,
                            TabInfo.table_name, idx_info->index_col_name,
                            AgentName);
                }
            }
            sprintf(TextBuf, idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;

            // create domain index`s normal index
            // if copy table encryption && enc column has normal index
            // (position) do not create index because already generated normal
            // index column
            //
            // getting the index_name in table
            //
            dgt_schar sql_text[2048];
            memset(sql_text, 0, 2048);
            sprintf(sql_text,
                    "select count() from pct_enc_col_index where enc_col_id = "
                    "%lld and column_position=1",
                    idx_info->enc_col_id);
            DgcSqlStmt* count_stmt =
                Database->getStmt(Session, sql_text, strlen(sql_text));
            if (count_stmt == 0 || count_stmt->execute() < 0) {
                DgcExcept* e = EXCEPTnC;
                delete count_stmt;
                RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
            }
            dgt_sint64* count_tmp = 0;
            dgt_sint64 count = 0;
            if ((count_tmp = (dgt_sint64*)count_stmt->fetch())) {
                memcpy(&count, count_tmp, sizeof(dgt_sint64));
            }
            if (count == 0) {
                if (TabInfo.partitioned) {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging local",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->index_col_name,
                            idx_info->tablespace_name, ParallelDegree);
                } else {
                    sprintf(idx_col_idx1,
                            "create index %s.%s on %s.%s(%s) tablespace %s "
                            "parallel %d nologging",
                            SchemaName, idx_info->fbi_index_name, SchemaName,
                            TabInfo.renamed_tab_name, idx_info->index_col_name,
                            idx_info->tablespace_name, ParallelDegree);
                }
                sprintf(TextBuf, idx_col_idx1);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
                *TextBuf = 0;
                sprintf(idx_col_idx2, "alter index %s.%s parallel %d logging",
                        SchemaName, idx_info->fbi_index_name, TabInfo.degree);
                sprintf(TextBuf, idx_col_idx2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
                *TextBuf = 0;
            }
            delete count_stmt;
            delete EXCEPTnC;
        }
    }
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    delete sql_stmt;
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo = 6000;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjTriggerSqlRows.next()) {
            *TextBuf = 0;
            sprintf(TextBuf, (dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo = 7000;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while (ObjSqlRows.next()) {
            *TextBuf = 0;
            strcat(TextBuf, (dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // create comment
    //
    *TextBuf = 0;
    StmtNo = 7800;
    CommentInfoRows.rewind();
    dgt_schar* comment_sql;
    while (CommentInfoRows.next() &&
           (comment_sql = (dgt_schar*)CommentInfoRows.data())) {
        *TextBuf = 0;
        if (comment_sql && strlen(comment_sql) > 2) {
            strcpy(TextBuf, comment_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // for finish sign step
    //
    StmtNo = 8000;
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    //
    // insert decryption (parallel insert)
    //
    dgt_sint32 lobFlag = 0;
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                lobFlag = 1;
            }
        }
    }
    if (lobFlag == 1) {
        StepNo = -2;
        StmtNo = -14999;
    } else {
        StepNo = -2;
        StmtNo = -14998;
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    if (lobFlag == 1) {
        ColInfoRows.rewind();
        sprintf(TmpBuf, "insert into %s.%s_%lld( ", SchemaName, "petra",
                TabInfo.enc_tab_id);
        strcat(TextBuf, TmpBuf);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status >= 1) {
                sprintf(TmpBuf, "%s,", col_info->renamed_col_name);
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf) - 1] = 0;
        strcat(TextBuf, ") \nselect ");
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW")) {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
    } else {
        ColInfoRows.rewind();
        sprintf(TmpBuf,
                "insert into %s.%s_%lld \n select /*+ PARALLEL(%s,%d) */ ",
                SchemaName, "petra", TabInfo.enc_tab_id, TabInfo.table_name,
                ParallelDegree);
        strcat(TextBuf, TmpBuf);
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status >= 1) {
                *TmpBuf = 0;
                sprintf(TmpBuf, getFname(col_info->col_name, 2));
                strcat(TmpBuf, ",");
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.renamed_tab_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        sprintf(TmpBuf, " from %s.%s %s", SchemaName, TabInfo.table_name,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    return 0;
}

PccOraScriptBuilder::PccOraScriptBuilder(DgcDatabase* db, DgcSession* sess,
                                         dgt_schar* schema_link)
    : PccScriptBuilder(db, sess, schema_link),
      PrivSqlRows(1),
      ObjSqlRows(1),
      ObjTriggerSqlRows(1),
      CheckSqlRows(4),
      SynonymSqlRows(2),
      CommentInfoRows(1),
      PetraIdxInfoRows(6),
      PkSqlRows(6),
      FkSqlRows(6),
      IdxSqlRows2(1),
      IdxSqlRows3(1),
      IdxSqlRows4(1),
      IdxSqlRows5(1),
      IdxSqlRows6(1),
      IdxColRows(1),
      TranIdxColRows(1),
      DefFkDropSqlRows(2),
      DefFkDropSqlRows2(1),
      DefFkCreSqlRows2(1),
      DefFkCreSqlRows3(1),
      CheckTrgRows(2),
      UniqueSqlRows1(1),
      UniqueSqlRows2(1) {
    PrivSqlRows.addAttr(DGC_SCHR, 1024, "sql_text");
    ObjSqlRows.addAttr(DGC_SCHR, 1024, "sql_text");
    ObjTriggerSqlRows.addAttr(DGC_SCHR, 50000, "sql_text");

    CheckSqlRows.addAttr(DGC_SCHR, 512, "org1");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "org2");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "enc2");

    SynonymSqlRows.addAttr(DGC_SCHR, 1024, "create_sql_id");
    SynonymSqlRows.addAttr(DGC_SCHR, 1024, "drop_sql_id");

    CommentInfoRows.addAttr(DGC_SCHR, 5000, "sql_id");

#if 0
        PetraIdxInfoRows.addAttr(DGC_SB8,0,"enc_col_id");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"renamed_col_name");
        PetraIdxInfoRows.addAttr(DGC_SCHR,33,"data_type");
        PetraIdxInfoRows.addAttr(DGC_UB1,0,"index_type");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"domain_index_name");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"fbi_index_name");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"normal_index_name");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"tablespace_name");
        PetraIdxInfoRows.addAttr(DGC_UB1,0,"normal_idx_flag");
        PetraIdxInfoRows.addAttr(DGC_SCHR,130,"index_col_name");
#endif
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "sql_text");
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "normal_sql_text");
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "sql_text2");
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "normal_sql_text2");
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "idx_col_idx1");
    PetraIdxInfoRows.addAttr(DGC_SCHR, 512, "idx_col_idx2");

    PkSqlRows.addAttr(DGC_SCHR, 512, "org1");
    PkSqlRows.addAttr(DGC_SCHR, 512, "org2");
    PkSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    PkSqlRows.addAttr(DGC_SCHR, 512, "enc2");
    PkSqlRows.addAttr(DGC_SCHR, 512, "org3");
    PkSqlRows.addAttr(DGC_SCHR, 512, "org4");

    FkSqlRows.addAttr(DGC_SCHR, 512, "org1");
    FkSqlRows.addAttr(DGC_SCHR, 512, "org2");
    FkSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    FkSqlRows.addAttr(DGC_SCHR, 512, "enc2");
    FkSqlRows.addAttr(DGC_SCHR, 512, "org3");
    FkSqlRows.addAttr(DGC_SCHR, 512, "org4");

    IdxSqlRows2.addAttr(DGC_SCHR, 30000, "sql_id");
    IdxSqlRows3.addAttr(DGC_SCHR, 30000, "sql_id");

    IdxSqlRows4.addAttr(DGC_SCHR, 512, "sql_id");
    IdxSqlRows5.addAttr(DGC_SCHR, 512, "sql_id");
    IdxSqlRows6.addAttr(DGC_SCHR, 30000, "sql_id");

    IdxColRows.addAttr(DGC_SCHR, 130, "col_name");
    TranIdxColRows.addAttr(DGC_SCHR, 130, "col_name");

    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc_sql");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "org_sql");

    DefFkDropSqlRows2.addAttr(DGC_SCHR, 512, "sql_id");
    DefFkCreSqlRows2.addAttr(DGC_SCHR, 512, "sql_id");
    DefFkCreSqlRows3.addAttr(DGC_SCHR, 512, "sql_id");

    CheckTrgRows.addAttr(DGC_SCHR, 4000, "search_condition");
    CheckTrgRows.addAttr(DGC_SCHR, 4000, "default_value");

    UniqueSqlRows1.addAttr(DGC_SCHR, 512, "sql_iq");
    UniqueSqlRows2.addAttr(DGC_SCHR, 512, "sql_iq");
}

PccOraScriptBuilder::~PccOraScriptBuilder() {}

dgt_sint32 PccOraScriptBuilder::getTablespace(DgcMemRows* rtn_rows) throw(
    DgcExcept) {
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
    }
    dgt_schar sql_text[256];
    sprintf(sql_text,
            "select tablespace_name, 1 relation from dba_tablespaces ");
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        Connection->disconnect();
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcAttr* attr = rtn_rows->attr();
    DgcMemRows* rows = stmt->returnRows();
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            rtn_rows->add();
            rtn_rows->next();
            for (dgt_uint32 i = 0; i < rtn_rows->numCols(); i++) {
                dgt_sint32 rtn = rows->getColData(i + 1, (attr + i)->type(),
                                                  (attr + i)->length(),
                                                  rtn_rows->getColPtr(i + 1));
                if (rtn) {
                    DgcExcept* e = EXCEPTnC;
                    delete stmt;
                    Connection->disconnect();
                    RTHROWnR(e, DgcError(SPOS, "getColData failed."), -1);
                }
            }
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;
    Connection->disconnect();
    rtn_rows->rewind();
    return 0;
}

typedef struct {
    dgt_uint8 enc_type;
    dgt_uint8 init_enc_type;
} pc_type_enc_type;

dgt_sint32 PccOraScriptBuilder::buildScript(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    //
    // enc_type = 0 (view)
    // enc_type = 1 (non view)
    //

    VersionNo = version_no;
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (preparePrivInfo() < 0)
        ATHROWnR(DgcError(SPOS, "preparePrivInfo failed."), -1);
    if (prepareObjInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareObjInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCommentInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareSynonymInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareSynonymInfo failed."), -1);
    if (prepareCtInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCtInfo failed."), -1);

    //
    // for new table encryption mode (get Constraints)
    //
    if (prepareCt2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCt2Info failed."), -1);
    if (prepareIdx2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCt2Info failed."), -1);
    if (step1() < 0) ATHROWnR(DgcError(SPOS, "step1_ins failed."), -1);
    if (step2() < 0) ATHROWnR(DgcError(SPOS, "step2_ins failed."), -1);
    if (reverse_step1() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step1_ins failed."), -1);
    if (reverse_step2() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step2_ins failed."), -1);
    return 0;
}

dgt_sint32 PccOraScriptBuilder::buildScript2(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    //
    // enc_type = 0 (view)
    // enc_type = 1 (non view)
    //

    VersionNo = version_no;
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCtInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCtInfo failed."), -1);
    if (prepareCt2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCt2Info failed."), -1);

    //
    // create view or rename encryption table -> original table name
    //
    StepNo = 2;
    StmtNo = 20000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.first_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                    TabInfo.renamed_tab_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
            TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last ";" off
            *TmpBuf = 0;
            sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.first_view_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf, ",rowid row_id");
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type != 0 && TabInfo.user_view_flag == 1) {
        sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                SchemaName, TabInfo.first_view_name);
        ColInfoRows.rewind();
        pc_type_col_info* col_info = 0;
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 1) {
                if (col_info->cipher_type == 4) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", col_info->col_name,
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", getFname(col_info->col_name, 2),
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        IdxColRows.rewind();
        if (IdxColRows.numRows() == 0) {
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            TextBuf[strlen(TextBuf) - 1] = 0;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
        if (insteadOfTrigger(1)) {
            ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
        }
    }
    return 0;
}

#include "DgcSqlHandle.h"

dgt_sint32 PccOraScriptBuilder::buildScriptMig(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    VersionNo = version_no;
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    DgcSqlHandle sql_handle(Session);
    dgt_schar sql_text[1024];
    //
    // get it_tab_id
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    dgt_sint64 it_tab_id = 0;
    dgt_sint32 analy_percent = 0;
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select distinct it_tab_id, analy_percent "
            "from   pct_mt_table "
            "where  enc_tab_id = %lld",
            enc_tab_id);
    if (sql_handle.execute(sql_text) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
        }
    }
    typedef struct {
        dgt_sint64 it_tab_id;
        dgt_sint32 analy_percent;
    } target_it_tab;
    dgt_void* rtn_row_ptr = 0;
    while (1) {
        if (sql_handle.fetch(rtn_row_ptr) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"), -1);
            }
        } else if (rtn_row_ptr) {
            it_tab_id = ((target_it_tab*)rtn_row_ptr)->it_tab_id;
            analy_percent = ((target_it_tab*)rtn_row_ptr)->analy_percent;
        } else {
            break;
        }
    }
    if (it_tab_id == 0) {
        ATHROWnR(DgcError(SPOS, "PCT_MT_TABLE.IT_TAB_ID not found."), -1);
    }
    //
    // get index information
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    DgcMemRows disableIdxSqlRows(1);
    disableIdxSqlRows.addAttr(DGC_SCHR, 512, "sql");
    DgcMemRows enableIdxSqlRows(1);
    enableIdxSqlRows.addAttr(DGC_SCHR, 512, "sql");
    disableIdxSqlRows.reset();
    enableIdxSqlRows.reset();
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select distinct a.index_name "
            "from   ceea_col_index a, "
            " ceea_table b "
            "where a.enc_tab_id = b.enc_tab_id "
            "and   a.UNIQUENESS = 0 "
            "and   b.db_id = %lld "
            "and   b.schema_name = getnameid('%s') "
            "and   b.table_name = getnameid('%s')",
            Dbid, SchemaName, TabInfo.table_name);
    if (sql_handle.execute(sql_text) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
        }
    }
    rtn_row_ptr = 0;
    while (1) {
        if (sql_handle.fetch(rtn_row_ptr) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"), -1);
            }
        } else if (rtn_row_ptr) {
            disableIdxSqlRows.add();
            disableIdxSqlRows.next();
            enableIdxSqlRows.add();
            enableIdxSqlRows.next();
            sprintf(TextBuf, "ALTER INDEX %s.%s unusable", SchemaName,
                    PetraNamePool->getNameString(*(dgt_sint64*)rtn_row_ptr));
            memcpy(disableIdxSqlRows.data(), TextBuf, strlen(TextBuf));
            sprintf(TextBuf, "ALTER INDEX %s.%s rebuild", SchemaName,
                    PetraNamePool->getNameString(*(dgt_sint64*)rtn_row_ptr));
            memcpy(enableIdxSqlRows.data(), TextBuf, strlen(TextBuf));
        } else {
            break;
        }
    }
    disableIdxSqlRows.rewind();
    enableIdxSqlRows.rewind();
    //
    // step 1 : disable index -> data migration -> enable index
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StepNo = 1;
    StmtNo = 1000;
    if (disableIdxSqlRows.next()) {
        *TextBuf = 0;
        memcpy(TextBuf, (dgt_schar*)disableIdxSqlRows.data(), 512);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    StmtNo = 2000;
    *TextBuf = 0;
    sprintf(TextBuf, "ALTER SESSION FORCE PARALLEL DML");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    if (migInsertSql(it_tab_id, 1) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "create MigrationInsertSql failed"), -1);
        }
    } else {
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    *TextBuf = 0;
    sprintf(TextBuf, "COMMIT");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    sprintf(TextBuf, "ALTER SESSION DISABLE PARALLEL DML");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    StmtNo = 3000;
    if (enableIdxSqlRows.next()) {
        *TextBuf = 0;
        memcpy(TextBuf, (dgt_schar*)enableIdxSqlRows.data(), 512);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    StmtNo = 4000;
    *TextBuf = 0;
    if (analy_percent > 0) {
        sprintf(TextBuf,
                "ANALYZE TABLE %s.%s ESTIMATE STATISTICS SAMPLE %d PERCENT",
                SchemaName, TabInfo.table_name, analy_percent);
    } else {
        sprintf(TextBuf, "ANALYZE TABLE %s.%s COMPUTE STATISTICS", SchemaName,
                TabInfo.table_name);
    }
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // step -1 : truncate table
    //
    StepNo = -1;
    StmtNo = -1;
    *TextBuf = 0;
    sprintf(TextBuf, "TRUNCATE TABLE %s.%s", SchemaName, TabInfo.table_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    return 0;
}

dgt_sint32 PccOraScriptBuilder::runVerifyMig(
    dgt_sint64 enc_tab_id, pct_type_verify_job* job_row_ptr) throw(DgcExcept) {
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    DgcSqlHandle sql_handle(Session);
    dgt_schar sql_text[1024];
    //
    // get it_tab_id
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    dgt_sint64 it_tab_id = 0;
    dgt_sint32 analy_percent = 0;
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "select distinct it_tab_id, analy_percent "
            "from   pct_mt_table "
            "where  enc_tab_id = %lld",
            enc_tab_id);
    if (sql_handle.execute(sql_text) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
        }
    }
    typedef struct {
        dgt_sint64 it_tab_id;
        dgt_sint32 analy_percent;
    } target_it_tab;
    dgt_void* rtn_row_ptr = 0;
    while (1) {
        if (sql_handle.fetch(rtn_row_ptr) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"), -1);
            }
        } else if (rtn_row_ptr) {
            it_tab_id = ((target_it_tab*)rtn_row_ptr)->it_tab_id;
            analy_percent = ((target_it_tab*)rtn_row_ptr)->analy_percent;
        } else {
            break;
        }
    }
    if (it_tab_id == 0) {
        ATHROWnR(DgcError(SPOS, "PCT_MT_TABLE.IT_TAB_ID not found."), -1);
    }
    //
    // verify row cnt
    //
    if (job_row_ptr->verify_mode == 0 || job_row_ptr->verify_mode == 1 ||
        job_row_ptr->verify_mode == 3) {
        //
        // count target table`s row count
        //
        *TextBuf = 0;
        sprintf(TextBuf, "select count(rowid) from %s.%s", SchemaName,
                TabInfo.table_name);
        DgcMemRows rtn_row(1);
        rtn_row.addAttr(DGC_UB4, 0, "count");
        rtn_row.reset();
        if (runVerifyScript(TextBuf, &rtn_row) < 0)
            ATHROWnR(DgcError(SPOS, "runVerifyScript[%s] failed.", TextBuf),
                     -1);
        dgt_uint32 target_tab_cnt = 0;
        dgt_uint32 src_tab_cnt = 0;
        rtn_row.rewind();
        rtn_row.next();
        target_tab_cnt = *(dgt_uint32*)rtn_row.data();

        if (migInsertSql(it_tab_id, 2) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "create MigrationInsertSql failed"),
                         -1);
            }
        } else {
            rtn_row.reset();
            if (runVerifyScript(TextBuf, &rtn_row) < 0)
                ATHROWnR(DgcError(SPOS, "runVerifyScript[%s] failed.", TextBuf),
                         -1);
            rtn_row.rewind();
            rtn_row.next();
            src_tab_cnt = *(dgt_uint32*)rtn_row.data();
        }
        if (target_tab_cnt != src_tab_cnt) {
            job_row_ptr->row_verify_cnt_result = -1;
            dgt_schar sql_text[512];
            sprintf(sql_text,
                    "insert into PCT_VERIFY_JOB_ROW_CNT_RESULT "
                    "values(%lld,%d,%d)",
                    job_row_ptr->verify_job_id, target_tab_cnt, src_tab_cnt);
            DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                DgcDbProcess::sess(), sql_text, strlen(sql_text));
            if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
            delete sql_stmt;
        } else {
            job_row_ptr->row_verify_cnt_result = 1;
        }
    }
    //
    // verify data
    //
    if (job_row_ptr->verify_mode == 0 || job_row_ptr->verify_mode == 2 ||
        job_row_ptr->verify_mode == 3) {
        if (IdxColRows.numRows() == 0) {
            job_row_ptr->data_verify_result = -1;
            sprintf(job_row_ptr->curr_err_msg,
                    "not found primary key or unique(non enc column)");
            return 0;
        }
        if (migInsertSql(it_tab_id, 3) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "create MigrationInsertSql failed"),
                         -1);
            }
        } else {
            DgcMemRows rtn_row(2);
            rtn_row.addAttr(DGC_SCHR, 16384, "TARGET_DATA");
            rtn_row.addAttr(DGC_SCHR, 16384, "SRC_DATA");
            rtn_row.reset();
            if (runVerifyScript(TextBuf, &rtn_row) < 0)
                ATHROWnR(DgcError(SPOS, "runVerifyScript[%s] failed.", TextBuf),
                         -1);
            rtn_row.rewind();
            typedef struct {
                dgt_schar target_data[16384];
                dgt_schar src_data[16384];
            } rtn_data;
            rtn_data* tmp_row_ptr = 0;
            if (rtn_row.numRows()) {
                job_row_ptr->data_verify_result = -1;
                while (rtn_row.next()) {
                    tmp_row_ptr = (rtn_data*)rtn_row.data();
                    dgt_sint64 target_name_id =
                        PetraNamePool->getNameID(tmp_row_ptr->target_data);
                    dgt_sint64 src_name_id =
                        PetraNamePool->getNameID(tmp_row_ptr->src_data);
                    dgt_schar sql_text[512];
                    sprintf(sql_text,
                            "insert into PCT_VERIFY_JOB_DATA_RESULT "
                            "values(%lld,%lld,%lld)",
                            job_row_ptr->verify_job_id, target_name_id,
                            src_name_id);
                    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(
                        DgcDbProcess::sess(), sql_text, strlen(sql_text));
                    if (sql_stmt == 0 || sql_stmt->execute() < 0)
                        delete EXCEPTnC;
                    delete sql_stmt;
                }
            } else {
                job_row_ptr->data_verify_result = 1;
            }
        }
    }
    return 0;
}

dgt_sint32 PccOraScriptBuilder::migInsertSql(
    dgt_sint64 it_tab_id, dgt_uint8 gen_flag) throw(DgcExcept) {
    //
    // gen_flag == 0 (syntax test)
    // gen_flag == 1 (migration insert script)
    // gen_flag == 2 (verify row count script)
    // gen_flag == 3 (verify data script)
    //
    if (!ScriptText) ScriptText = new dgt_schar[PCC_MAX_SCRIPT_LEN];
    *ScriptText = 0;
    DgcSqlHandle sql_handle(Session);
    dgt_schar sql_text[1024];
    memset(sql_text, 0, 1024);
    dgt_schar insert_part[2048] = {
        0,
    };
    dgt_schar insert_select_part[2048] = {
        0,
    };
    dgt_schar select_m_list[24000] = {
        0,
    };
    dgt_schar select_s_list[24000] = {
        0,
    };
    dgt_schar from_part[1024] = {
        0,
    };
    dgt_schar join_part[1024] = {
        0,
    };
    dgt_schar where_part[1024] = {
        0,
    };

    //
    // insert_part, insert_select_part
    // join_clause, where_clause
    //
    typedef struct {
        dgt_sint64 enc_col_id;
        dgt_sint64 schema_name;
        dgt_sint64 table_name;
        dgt_sint64 column_name;
        dgt_sint64 map_col_id;
        dgt_sint64 col_expression;
        dgt_sint64 key_id;
        dgt_sint64 join_clause;
        dgt_sint64 where_clause;
        dgt_sint32 column_order;
    } insert_st;
    insert_st* insert_st_tmp = 0;
    if (gen_flag == 0) {
        //
        // for validation test
        //
        sprintf(sql_text,
                "select b.it_col_id, "
                "	a.schema_name, "
                " a.table_name, "
                " b.column_name, "
                " b.map_col_id, "
                " b.col_expression, "
                " b.key_id, "
                " a.join_clause, "
                " a.where_clause, "
                " b.column_order "
                "from   PCT_IT_TABLE a, "
                " PCT_IT_COLUMN b "
                "where  a.IT_TAB_ID = b.IT_TAB_ID "
                "and    a.IT_TAB_ID = %lld "
                "order by column_order",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                insert_st_tmp = (insert_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(join_part, " %s ",
                            PetraNamePool->getNameString(
                                insert_st_tmp->join_clause));
                    sprintf(where_part, " %s ",
                            PetraNamePool->getNameString(
                                insert_st_tmp->where_clause));
                    sprintf(
                        insert_part, "INSERT INTO %s.%s \n( %s,",
                        PetraNamePool->getNameString(
                            insert_st_tmp->schema_name),
                        PetraNamePool->getNameString(insert_st_tmp->table_name),
                        PetraNamePool->getNameString(
                            insert_st_tmp->column_name));
                    if (insert_st_tmp->key_id > 0) {
                        sprintf(insert_select_part,
                                "\nSELECT \n pls_encrypt_b64_id(%s,1),",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                    } else {
                        sprintf(insert_select_part, "\nSELECT \n %s,",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n  %s,",
                            PetraNamePool->getNameString(
                                insert_st_tmp->column_name));
                    strcat(insert_part, TmpBuf);
                    if (insert_st_tmp->key_id > 0) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n  pls_encrypt_b64_id(%s,1),",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                        strcat(insert_select_part, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n  %s,",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                        strcat(insert_select_part, TmpBuf);
                    }
                }

            } else {
                break;
            }
            seq++;
        }
        insert_part[strlen(insert_part) - 1] = 0;
        insert_select_part[strlen(insert_select_part) - 1] = 0;
        strcat(insert_part, "\n)");
        strcat(insert_select_part, "\nfrom");
        delete EXCEPTnC;
    } else {
        //
        // for generate script
        //
        sprintf(sql_text,
                "select b.enc_col_id, "
                " a.schema_name, "
                " a.table_name, "
                " b.column_name, "
                " b.map_col_id, "
                " b.col_expression, "
                " b.key_id, "
                " a.join_clause, "
                " a.where_clause, "
                " b.column_order "
                "from   PCT_MT_TABLE a, "
                " PCT_MT_COLUMN b "
                "where  a.IT_TAB_ID = b.IT_TAB_ID "
                "and    a.IT_TAB_ID = %lld "
                "order by column_order",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                insert_st_tmp = (insert_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(join_part, " %s ",
                            PetraNamePool->getNameString(
                                insert_st_tmp->join_clause));
                    sprintf(where_part, " %s ",
                            PetraNamePool->getNameString(
                                insert_st_tmp->where_clause));
                    sprintf(
                        insert_part,
                        "INSERT /*+ APPEND PARALLEL(%s,%d) */ INTO %s.%s \n( "
                        "%s,",
                        PetraNamePool->getNameString(insert_st_tmp->table_name),
                        ParallelDegree,
                        PetraNamePool->getNameString(
                            insert_st_tmp->schema_name),
                        PetraNamePool->getNameString(insert_st_tmp->table_name),
                        PetraNamePool->getNameString(
                            insert_st_tmp->column_name));
                    if (insert_st_tmp->key_id > 0) {
                        sprintf(insert_select_part, "\nSELECT \n %s,",
                                getFname(PetraNamePool->getNameString(
                                             insert_st_tmp->column_name),
                                         1));
                    } else {
                        sprintf(insert_select_part, "\nSELECT \n %s,",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n  %s,",
                            PetraNamePool->getNameString(
                                insert_st_tmp->column_name));
                    strcat(insert_part, TmpBuf);
                    if (insert_st_tmp->key_id > 0) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n  %s,",
                                getFname(PetraNamePool->getNameString(
                                             insert_st_tmp->column_name),
                                         1));
                        strcat(insert_select_part, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n  %s,",
                                PetraNamePool->getNameString(
                                    insert_st_tmp->column_name));
                        strcat(insert_select_part, TmpBuf);
                    }
                }

            } else {
                break;
            }
            seq++;
        }
        insert_part[strlen(insert_part) - 1] = 0;
        insert_select_part[strlen(insert_select_part) - 1] = 0;
        strcat(insert_part, "\n)");
        strcat(insert_select_part, "\nfrom");
        delete EXCEPTnC;
    }
    //
    // select_list
    //
    typedef struct {
        dgt_sint64 column_name;
        dgt_sint64 col_expression;
        dgt_sint64 alias_name;
        dgt_sint64 t_alias_name;
        dgt_sint32 column_order;
    } select_list_st;
    select_list_st* select_list_tmp = 0;
    if (gen_flag == 0) {
        //
        // only validation test
        //
        sprintf(sql_text,
                "select   b.column_name, "
                " a.col_expression, "
                " a.column_name, "
                " c.alias_name, "
                " a.column_order "
                "from pct_it_column a, "
                " pct_is_column b, "
                " pct_is_table  c  "
                "where   a.it_tab_id = b.it_tab_id "
                "and     b.is_tab_id = c.is_tab_id "
                "and     a.it_tab_id = %lld "
                "and     a.map_col_id = b.is_col_id "
                "order   by a.column_order",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                select_list_tmp = (select_list_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(select_m_list, "\n\t(SELECT %s,",
                            PetraNamePool->getNameString(
                                select_list_tmp->alias_name));
                    if (select_list_tmp->col_expression) {
                        sprintf(select_s_list, "\n\t\t(SELECT %s %s,",
                                PetraNamePool->getNameString(
                                    select_list_tmp->col_expression),
                                PetraNamePool->getNameString(
                                    select_list_tmp->alias_name));
                    } else {
                        if (select_list_tmp->t_alias_name) {
                            sprintf(select_s_list, "\n\t\t(SELECT %s.%s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->t_alias_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                        } else {
                            sprintf(select_s_list, "\n\t\t(SELECT %s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                        }
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n\t        %s,",
                            PetraNamePool->getNameString(
                                select_list_tmp->alias_name));
                    strcat(select_m_list, TmpBuf);
                    if (select_list_tmp->col_expression) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n\t\t        %s %s,",
                                PetraNamePool->getNameString(
                                    select_list_tmp->col_expression),
                                PetraNamePool->getNameString(
                                    select_list_tmp->alias_name));
                        strcat(select_s_list, TmpBuf);
                    } else {
                        if (select_list_tmp->t_alias_name) {
                            *TmpBuf = 0;
                            sprintf(TmpBuf, "\n\t\t        %s.%s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->t_alias_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                            strcat(select_s_list, TmpBuf);
                        } else {
                            *TmpBuf = 0;
                            sprintf(TmpBuf, "\n\t\t        %s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                            strcat(select_s_list, TmpBuf);
                        }
                    }
                }
            } else {
                break;
            }
            seq++;
        }
        select_m_list[strlen(select_m_list) - 1] = 0;
        select_s_list[strlen(select_s_list) - 1] = 0;
        strcat(select_m_list, "\n\tFROM");
        delete EXCEPTnC;
    } else {
        //
        // for generate script
        //
        sprintf(sql_text,
                "select   b.column_name, "
                " a.col_expression, "
                " a.column_name, "
                " c.alias_name, "
                " a.column_order "
                "from pct_mt_column a, "
                " pct_ms_column b, "
                " pct_ms_table  c  "
                "where   a.it_tab_id = b.it_tab_id "
                "and     b.enc_tab_id = c.enc_tab_id "
                "and     a.it_tab_id = %lld "
                "and     a.map_col_id = b.enc_col_id "
                "order   by a.column_order",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                select_list_tmp = (select_list_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(select_m_list, "\n\t(SELECT %s,",
                            PetraNamePool->getNameString(
                                select_list_tmp->alias_name));
                    if (select_list_tmp->col_expression) {
                        sprintf(select_s_list, "\n\t\t(SELECT %s %s,",
                                PetraNamePool->getNameString(
                                    select_list_tmp->col_expression),
                                PetraNamePool->getNameString(
                                    select_list_tmp->alias_name));
                    } else {
                        if (select_list_tmp->t_alias_name) {
                            sprintf(select_s_list, "\n\t\t(SELECT %s.%s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->t_alias_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                        } else {
                            sprintf(select_s_list, "\n\t\t(SELECT %s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                        }
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "\n\t        %s,",
                            PetraNamePool->getNameString(
                                select_list_tmp->alias_name));
                    strcat(select_m_list, TmpBuf);
                    if (select_list_tmp->col_expression) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "\n\t\t        %s %s,",
                                PetraNamePool->getNameString(
                                    select_list_tmp->col_expression),
                                PetraNamePool->getNameString(
                                    select_list_tmp->alias_name));
                        strcat(select_s_list, TmpBuf);
                    } else {
                        if (select_list_tmp->t_alias_name) {
                            *TmpBuf = 0;
                            sprintf(TmpBuf, "\n\t\t        %s.%s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->t_alias_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                            strcat(select_s_list, TmpBuf);
                        } else {
                            *TmpBuf = 0;
                            sprintf(TmpBuf, "\n\t\t        %s %s,",
                                    PetraNamePool->getNameString(
                                        select_list_tmp->column_name),
                                    PetraNamePool->getNameString(
                                        select_list_tmp->alias_name));
                            strcat(select_s_list, TmpBuf);
                        }
                    }
                }
            } else {
                break;
            }
            seq++;
        }
        select_m_list[strlen(select_m_list) - 1] = 0;
        select_s_list[strlen(select_s_list) - 1] = 0;
        strcat(select_m_list, "\n\tFROM");
        delete EXCEPTnC;
    }
    //
    // from part
    //
    typedef struct {
        dgt_sint64 schema_name;
        dgt_sint64 table_name;
        dgt_sint64 alias_name;
        dgt_sint64 dblink_name;
    } from_st;
    from_st* from_tmp = 0;
    if (gen_flag == 0) {
        //
        // only validation test
        //
        sprintf(sql_text,
                "select  schema_name, "
                " table_name, "
                " alias_name, "
                " dblink_name "
                "from    pct_is_table "
                "where   it_tab_id = %lld",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                from_tmp = (from_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(from_part, "\n\t\tFROM %s.%s",
                            PetraNamePool->getNameString(from_tmp->schema_name),
                            PetraNamePool->getNameString(from_tmp->table_name));
                    if (from_tmp->dblink_name) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "@%s ",
                                PetraNamePool->getNameString(
                                    from_tmp->dblink_name));
                        strcat(from_part, TmpBuf);
                    }
                    if (from_tmp->alias_name) {
                        *TmpBuf = 0;
                        sprintf(
                            TmpBuf, " %s,",
                            PetraNamePool->getNameString(from_tmp->alias_name));
                        strcat(from_part, TmpBuf);
                    } else {
                        strcat(from_part, ",");
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, " %s.%s",
                            PetraNamePool->getNameString(from_tmp->schema_name),
                            PetraNamePool->getNameString(from_tmp->table_name));
                    strcat(from_part, TmpBuf);
                    if (from_tmp->dblink_name) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "@%s ",
                                PetraNamePool->getNameString(
                                    from_tmp->dblink_name));
                        strcat(from_part, TmpBuf);
                    }
                    if (from_tmp->alias_name) {
                        *TmpBuf = 0;
                        sprintf(
                            TmpBuf, " %s,",
                            PetraNamePool->getNameString(from_tmp->alias_name));
                        strcat(from_part, TmpBuf);
                    } else {
                        strcat(from_part, ",");
                    }
                }
            } else {
                break;
            }
            seq++;
        }
        from_part[strlen(from_part) - 1] = 0;
        delete EXCEPTnC;
    } else {
        //
        // for generate script
        //
        sprintf(sql_text,
                "select  schema_name, "
                " table_name, "
                " alias_name, "
                " dblink_name "
                "from    pct_ms_table "
                "where   it_tab_id = %lld",
                it_tab_id);
        if (sql_handle.execute(sql_text) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                RTHROWnR(e, DgcError(SPOS, "sql_handle execute Failed"), -1);
            }
        }
        dgt_void* rtn_row_ptr = 0;
        dgt_sint32 seq = 1;
        while (1) {
            if (sql_handle.fetch(rtn_row_ptr) < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    RTHROWnR(e, DgcError(SPOS, "sql_handle execute failed"),
                             -1);
                }
            } else if (rtn_row_ptr) {
                from_tmp = (from_st*)rtn_row_ptr;
                if (seq == 1) {
                    sprintf(from_part, "\n\t\tFROM %s.%s",
                            PetraNamePool->getNameString(from_tmp->schema_name),
                            PetraNamePool->getNameString(from_tmp->table_name));
                    if (from_tmp->dblink_name) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "@%s ",
                                PetraNamePool->getNameString(
                                    from_tmp->dblink_name));
                        strcat(from_part, TmpBuf);
                    }
                    if (from_tmp->alias_name) {
                        *TmpBuf = 0;
                        sprintf(
                            TmpBuf, " %s,",
                            PetraNamePool->getNameString(from_tmp->alias_name));
                        strcat(from_part, TmpBuf);
                    } else {
                        strcat(from_part, ",");
                    }
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, " %s.%s",
                            PetraNamePool->getNameString(from_tmp->schema_name),
                            PetraNamePool->getNameString(from_tmp->table_name));
                    strcat(from_part, TmpBuf);
                    if (from_tmp->dblink_name) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "@%s ",
                                PetraNamePool->getNameString(
                                    from_tmp->dblink_name));
                        strcat(from_part, TmpBuf);
                    }
                    if (from_tmp->alias_name) {
                        *TmpBuf = 0;
                        sprintf(
                            TmpBuf, " %s,",
                            PetraNamePool->getNameString(from_tmp->alias_name));
                        strcat(from_part, TmpBuf);
                    } else {
                        strcat(from_part, ",");
                    }
                }
            } else {
                break;
            }
            seq++;
        }
        from_part[strlen(from_part) - 1] = 0;
        delete EXCEPTnC;
    }

    //
    // merge part sql into scriptText Buf
    //
    if (gen_flag == 0) {
        sprintf(ScriptText, "explain plan for \n");
        strcat(ScriptText, insert_part);
        strcat(ScriptText, insert_select_part);
        strcat(ScriptText, select_m_list);
        strcat(ScriptText, select_s_list);
        strcat(ScriptText, from_part);
        if (strlen(join_part) > 0) {
            strcat(ScriptText, "\n\t\t");
            strcat(ScriptText, join_part);
        }
        strcat(ScriptText, " )");
        if (strlen(where_part) > 0) {
            strcat(ScriptText, "\n\t");
            strcat(ScriptText, where_part);
        }
        strcat(ScriptText, ")");
    } else if (gen_flag == 1) {
        *TextBuf = 0;
        strcat(TextBuf, insert_part);
        strcat(TextBuf, insert_select_part);
        strcat(TextBuf, select_m_list);
        strcat(TextBuf, select_s_list);
        strcat(TextBuf, from_part);
        if (strlen(join_part) > 0) {
            strcat(TextBuf, "\n\t\t");
            strcat(TextBuf, join_part);
        }
        strcat(TextBuf, " )");
        if (strlen(where_part) > 0) {
            strcat(TextBuf, "\n\t");
            strcat(TextBuf, where_part);
        }
        strcat(TextBuf, " )");
    } else if (gen_flag == 2) {
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "select count(*) from \n");
        strcat(TextBuf, select_s_list);
        strcat(TextBuf, from_part);
        if (strlen(join_part) > 0) {
            strcat(TextBuf, "\n\t\t");
            strcat(TextBuf, join_part);
        }
        strcat(TextBuf, " )");
        if (strlen(where_part) > 0) {
            strcat(TextBuf, "\n\t");
            strcat(TextBuf, where_part);
        }
    } else if (gen_flag == 3) {
        *TextBuf = 0;
        *TmpBuf = 0;
        sprintf(TextBuf, "select ");
        pc_type_col_info* col_info = 0;
        dgt_sint32 seq = 0;
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                continue;
            }
            seq++;
            if (col_info->status == 1) {
                *TmpBuf = 0;
                if (seq == 1)
                    sprintf(TmpBuf, " pls_decrypt_b64_id(target_tab.%s,%lld) ",
                            col_info->col_name, col_info->enc_col_id);
                else
                    sprintf(
                        TmpBuf,
                        " || ' | ' || pls_decrypt_b64_id(target_tab.%s,%lld) ",
                        col_info->col_name, col_info->enc_col_id);
            } else {
                *TmpBuf = 0;
                if (seq == 1)
                    sprintf(TmpBuf, "target_tab.%s ", col_info->col_name);
                else
                    sprintf(TmpBuf, " || ' | ' || target_tab.%s ",
                            col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf, TmpBuf);
        strcat(TextBuf, ",");
        seq = 0;
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                continue;
            }
            seq++;
            *TmpBuf = 0;
            if (seq == 1)
                sprintf(TmpBuf, "src_tab.%s ", col_info->col_name);
            else
                sprintf(TmpBuf, " || ' | ' || src_tab.%s ", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf, "\nfrom %s.%s target_tab full outer join ", SchemaName,
                TabInfo.table_name);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        strcat(TmpBuf, select_m_list);
        strcat(TmpBuf, select_s_list);
        strcat(TmpBuf, from_part);
        if (strlen(join_part) > 0) {
            strcat(TmpBuf, "\n\t\t");
            strcat(TmpBuf, join_part);
        }
        strcat(TmpBuf, " )");
        if (strlen(where_part) > 0) {
            strcat(TmpBuf, "\n\t");
            strcat(TmpBuf, where_part);
        }
        strcat(TmpBuf, " ) src_tab ");
        strcat(TmpBuf, "\n on ");
        strcat(TextBuf, TmpBuf);
        IdxColRows.rewind();
        dgt_schar* col_name = 0;
        seq = 0;
        while (IdxColRows.next() &&
               (col_name = (dgt_schar*)IdxColRows.data())) {
            seq++;
            *TmpBuf = 0;
            if (seq == 1) {
                sprintf(TmpBuf, "target_tab.%s = src_tab.%s ", col_name,
                        col_name);
            } else {
                sprintf(TmpBuf, "\n\t and target_tab.%s = src_tab.%s", col_name,
                        col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf, "\nwhere ");
        IdxColRows.rewind();
        if (IdxColRows.next() && (col_name = (dgt_schar*)IdxColRows.data())) {
            *TmpBuf = 0;
            sprintf(TmpBuf, " target_tab.%s is null \n", col_name);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
            sprintf(TmpBuf, " or src_tab.%s is null \n", col_name);
            strcat(TextBuf, TmpBuf);
        }
        ColInfoRows.rewind();
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "LONG") ||
                !strcasecmp(col_info->data_type, "LONG RAW") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                continue;
            }
            if (col_info->status == 1) {
                *TmpBuf = 0;
                sprintf(
                    TmpBuf,
                    " or pls_decrypt_b64_id(target_tab.%s,%lld) != src_tab.%s ",
                    col_info->col_name, col_info->enc_col_id,
                    col_info->col_name);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, " or target_tab.%s != src_tab.%s ",
                        col_info->col_name, col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
        strcat(TextBuf, TmpBuf);
    }
    DgcWorker::PLOG.tprintf(0, "[%s]\n", TextBuf);

    return 0;
}

dgt_sint32 PccOraScriptBuilder::buildScriptAddCol(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    VersionNo = version_no;
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCommentInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    dgt_sint32 lobFlag = 0;
    ColInfoRows.rewind();
    pc_type_col_info* col_info = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            *TmpBuf = 0;
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                !strcasecmp(col_info->data_type, "BLOB")) {
                lobFlag = 1;
            }
        }
    }
    //
    // delete old scripts
    //
    dgt_schar sql_text[256];
    if (lobFlag == 1) {
        sprintf(sql_text,
                "delete pct_script where enc_tab_id=%lld and step_no=-2 and "
                "stmt_no=-14998",
                enc_tab_id);
    } else {
        sprintf(sql_text,
                "delete pct_script where enc_tab_id=%lld and step_no=-2 and "
                "stmt_no=-14997",
                enc_tab_id);
    }
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "delete failed."), -1);
    }
    delete sql_stmt;
    //
    // for new table encryption mode (get Constraints)
    //
    if (TabInfo.init_enc_type == 0) {
        //
        // add column initial encryption
        //
    } else if (TabInfo.init_enc_type >= 1) {
        //
        // new table initial encryption
        //
        if (addColStep() < 0)
            ATHROWnR(DgcError(SPOS, "addColStep failed."), -1);
    }
    return 0;
}

dgt_sint32 PccOraScriptBuilder::buildScriptColAdmin(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    VersionNo = version_no;
    if (prepareTabInfo(enc_tab_id) < 0)
        ATHROWnR(DgcError(SPOS, "prepareTabInfo failed."), -1);
    if (prepareColInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareColInfo failed."), -1);
    if (prepareIdxInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCommentInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);

    //
    // alter table add, modify, drop column
    //
    StepNo = 3;
    StmtNo = 1000;
    *TextBuf = 0;
    *TmpBuf = 0;
    ColInfoRows.rewind();
    pc_type_col_info* col_info = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 3) {
            //
            // add column
            //
            if (TabInfo.enc_type == 0) {
                // view table
                sprintf(TextBuf, "alter table %s.%s add %s %s", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        col_info->data_type);
                if (col_info->data_length > 0) {
                    sprintf(TmpBuf, "(%d)", col_info->data_length);
                    strcat(TextBuf, TmpBuf);
                } else if (col_info->data_precision > 0) {
                    if (col_info->data_scale > 0) {
                        sprintf(TmpBuf, "(%d,%d)", col_info->data_precision,
                                col_info->data_scale);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        sprintf(TmpBuf, "(%d)", col_info->data_precision);
                        strcat(TextBuf, TmpBuf);
                    }
                }
                if (col_info->nullable_flag == 0) {
                    sprintf(TmpBuf, " not null");
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                // non view table
                sprintf(TextBuf, "alter table %s.%s add %s %s", SchemaName,
                        TabInfo.table_name, col_info->col_name,
                        col_info->data_type);
                if (col_info->data_length > 0) {
                    sprintf(TmpBuf, "(%d)", col_info->data_length);
                    strcat(TextBuf, TmpBuf);
                } else if (col_info->data_precision > 0) {
                    if (col_info->data_scale > 0) {
                        sprintf(TmpBuf, "(%d,%d)", col_info->data_precision,
                                col_info->data_scale);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        sprintf(TmpBuf, "(%d)", col_info->data_precision);
                        strcat(TextBuf, TmpBuf);
                    }
                }
                if (col_info->nullable_flag == 0) {
                    sprintf(TmpBuf, " not null");
                    strcat(TextBuf, TmpBuf);
                }
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else if (col_info->status == 4) {
            //
            // modify column
            //
            if (TabInfo.enc_type == 0) {
                // view table
                sprintf(TextBuf, "alter table %s.%s modify %s %s", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        col_info->data_type);
                if (col_info->data_length > 0) {
                    sprintf(TmpBuf, "(%d)", col_info->data_length);
                    strcat(TextBuf, TmpBuf);
                }
                if (col_info->nullable_flag == 0) {
                    sprintf(TmpBuf, " not null");
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                // non view table
                sprintf(TextBuf, "alter table %s.%s modify %s %s", SchemaName,
                        TabInfo.table_name, col_info->col_name,
                        col_info->data_type);
                if (col_info->data_length > 0) {
                    sprintf(TmpBuf, "(%d)", col_info->data_length);
                    strcat(TextBuf, TmpBuf);
                }
                if (col_info->nullable_flag == 0) {
                    sprintf(TmpBuf, " not null");
                    strcat(TextBuf, TmpBuf);
                }
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else if (col_info->status == 5) {
            //
            // drop column
            //
            if (TabInfo.enc_type == 0) {
                // view table
                sprintf(TextBuf, "alter table %s.%s drop column %s", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name);
            } else {
                // non view table
                sprintf(TextBuf, "alter table %s.%s drop column %s", SchemaName,
                        TabInfo.table_name, col_info->col_name);
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    StmtNo = 2000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.first_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 5) continue;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                    TabInfo.renamed_tab_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
            *TextBuf = 0;
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 5) continue;
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
            TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last ";" off
            *TmpBuf = 0;
            sprintf(TmpBuf, " from %s.%s", SchemaName, TabInfo.first_view_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                    SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info = 0;
            while (ColInfoRows.next() &&
                   (col_info = (pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf = 0;
                if (col_info->status == 5) continue;
                if (col_info->status == 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,", col_info->col_name,
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    } else {
                        *TmpBuf = 0;
                        sprintf(TmpBuf, "%s %s,",
                                getFname(col_info->col_name, 2),
                                col_info->col_name);
                        strcat(TextBuf, TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf, "%s,", col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf) - 1] = 0;
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf, ",rowid row_id");
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "\n   from %s.%s", SchemaName,
                        TabInfo.renamed_tab_name);
                strcat(TextBuf, TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
                }
            }
        }
    }
    StmtNo = 3000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type != 0 && TabInfo.user_view_flag == 1) {
        sprintf(TextBuf, "create or replace view %s.%s as\n select ",
                SchemaName, TabInfo.first_view_name);
        ColInfoRows.rewind();
        pc_type_col_info* col_info = 0;
        while (ColInfoRows.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf = 0;
            if (col_info->status == 5) continue;
            if (col_info->status == 1) {
                if (col_info->cipher_type == 4) {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", col_info->col_name,
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                } else {
                    *TmpBuf = 0;
                    sprintf(TmpBuf, "%s %s,", getFname(col_info->col_name, 2),
                            col_info->col_name);
                    strcat(TextBuf, TmpBuf);
                }
            } else {
                sprintf(TmpBuf, "%s,", col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }
        }
        IdxColRows.rewind();
        if (IdxColRows.numRows() == 0) {
            strcat(TextBuf, "rowid row_id");
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        } else {
            TextBuf[strlen(TextBuf) - 1] = 0;
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n   from %s.%s", SchemaName, TabInfo.table_name);
            strcat(TextBuf, TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    *TmpBuf = 0;
    *TextBuf = 0;
    StmtNo = 4000;
    if (TabInfo.dml_trg_flag == 1) {
        //#645 issue fix by shson 2019.01.04
        // not define column status
        // dml trigger is created when added column status is 1
        // this case status is 3 or 4 or 5
#if 0 /*{{{*/
                dgt_sint32 ver_flag=0;
                if (!strcasecmp(DbVersion,"11g")) ver_flag=1;
                sprintf(TextBuf,"create or replace trigger %s.%s\nbefore insert or update on %s.%s for each row\ndeclare \n",
                                SchemaName,TabInfo.view_trigger_name, SchemaName, TabInfo.renamed_tab_name);
                ColInfoRows.rewind();
                pc_type_col_info*       col_info;
                //
                // for 11g trigger (performance issue)
                //
                if (ver_flag) {
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
				if (col_info->status == 5) continue;
                                if (col_info->status == 1) {
                                        *TmpBuf=0;
                                        dgt_sint32      enc_len = 0;
                                        if (!strcasecmp(col_info->data_type,"NUMBER")) enc_len = (col_info->data_precision + 2);
                                        else if (!strcasecmp(col_info->data_type,"DATE") ||
                                                 !strcasecmp(col_info->data_type,"TIMESTAMP")) enc_len = 14;
                                        else if (col_info->multi_byte_flag) enc_len = col_info->data_length * 3;
                                        else enc_len = col_info->data_length;
                                        PCI_Context     ctx;
                                        PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type, col_info->enc_mode,
                                                        col_info->iv_type, col_info->n2n_flag, col_info->b64_txt_enc_flag,
                                                        col_info->enc_start_pos, col_info->enc_length);
                                        enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
                                        if (col_info->index_type == 1) {
                                                enc_len += PCI_ophuekLength(col_info->data_length,PCI_SRC_TYPE_CHAR,1);
                                                enc_len += 4;
                                        }
                                        if (!strcasecmp(col_info->data_type,"CLOB") ||
                                            !strcasecmp(col_info->data_type,"BLOB")) {
                                                sprintf(TmpBuf,"\t v_%s BLOB;\n", col_info->col_name);
                                        } else {
                                                if (col_info->b64_txt_enc_flag && col_info->b64_txt_enc_flag != 4) {
                                                        sprintf(TmpBuf,"\t v_%s varchar2(%d);\n", col_info->col_name, enc_len);
                                                } else {
                                                        sprintf(TmpBuf,"\t v_%s raw(%d);\n", col_info->col_name, enc_len);
                                                }
                                        }
                                        strcat(TextBuf,TmpBuf);
                                }
                        }
                }
                strcat(TextBuf,"begin\n");
                //
                // for check constraint
                //
                CheckTrgRows.rewind();
                typedef struct {
                        dgt_schar       search_condition[4000];
                        dgt_schar       default_val[4000];
                } type_check;
                type_check*    tmp_search=0;
                while(CheckTrgRows.next() && (tmp_search=(type_check*)CheckTrgRows.data())) {
                        if (strlen(tmp_search->default_val) > 2 && strstr(tmp_search->search_condition,"IS NOT NULL")) continue;
                        *TmpBuf=0;
                        sprintf(TmpBuf,"\n if not ");
                        strcat(TextBuf,TmpBuf);
                        *TmpBuf=0;
                        sprintf(TmpBuf,"( :new.%s )",tmp_search->search_condition);
                        strcat(TextBuf,TmpBuf);
                        *TmpBuf=0;
                        sprintf(TmpBuf," then\n\t raise_application_error(-20001,'%s`s check constraint violated');\n end if;",
                                        TabInfo.table_name);
                        strcat(TextBuf,TmpBuf);
                }
                *TmpBuf=0;
                if (ver_flag) {
                        ColInfoRows.rewind();
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                                *TmpBuf=0;
				if (col_info->status == 5) continue;
                                if (col_info->status == 1) {
                                        sprintf(TmpBuf,"\t\t if updating('%s') then\n", col_info->col_name);
                                        strcat(TextBuf,TmpBuf);
                                        *TmpBuf=0;
                                        sprintf(TmpBuf,"\t\t v_%s := %s;\n",col_info->col_name,getFname(col_info->col_name,1,1));
                                        strcat(TextBuf,TmpBuf);
                                        *TmpBuf=0;
                                        sprintf(TmpBuf,"\t\t :new.%s := v_%s;\n",col_info->col_name, col_info->col_name);
                                        strcat(TextBuf,TmpBuf);
                                        *TmpBuf=0;
                                        strcat(TextBuf,"\t\t end if;\n");
                                }
                        }
                } else {
                        ColInfoRows.rewind();
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                                *TmpBuf=0;
				if (col_info->status == 5) continue;
                                if (col_info->status == 1) {
                                        sprintf(TmpBuf,"\t\t if updating('%s') then\n", col_info->col_name);
                                        strcat(TextBuf,TmpBuf);
                                        *TmpBuf=0;
                                        sprintf(TmpBuf,"\t\t :new.%s := %s;\n",col_info->col_name,getFname(col_info->col_name,1,1));
                                        strcat(TextBuf,TmpBuf);
                                        *TmpBuf=0;
                                        strcat(TextBuf,"\t\t end if;\n");
                                }
                        }
                }
                strcat(TextBuf,"\t end;\n");
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
#endif /*}}}*/
    } else {
        if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
            if (insteadOfTrigger(1)) {
                ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
            }
        }
    }
    //
    // create comment
    //
    *TextBuf = 0;
    StmtNo = 5000;
    CommentInfoRows.rewind();
    dgt_schar* comment_sql;
    while (CommentInfoRows.next() &&
           (comment_sql = (dgt_schar*)CommentInfoRows.data())) {
        *TextBuf = 0;
        if (comment_sql && strlen(comment_sql) > 2) {
            strcpy(TextBuf, comment_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

    //
    // for cipher job update status = 0 stmtno = 8001
    //
    StmtNo = 8000;
    *TextBuf = 0;
    sprintf(TextBuf, "commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    return 0;
}

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pc_type_inst_agent_user_out;

typedef struct {
    dgt_schar instance_name[33];
    dgt_schar listen_ip[256];
    dgt_uint16 listen_port;
    dgt_uint8 db_type;
} pc_type_connect_db;

dgt_sint32 PccOraScriptBuilder::checkDB(dgt_sint64 db_agent_id,
                                        dgt_schar* sys_uid, dgt_schar* sys_pass,
                                        dgt_schar* agent_uid,
                                        DgcMemRows* rtn_rows) throw(DgcExcept) {
    //
    // Connecting test for sys user
    //
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select a.instance_name, c.listen_ip, c.listen_port, e.db_type "
            "from pt_db_instance a, pct_db_agent b, pt_listen_addr c, "
            "pt_listen_service d, pt_database e "
            "where a.instance_id = b.instance_id "
            "and   a.instance_id = d.instance_id "
            "and   d.listen_addr_id  = c.listen_addr_id "
            "and   b.db_id = e.db_id "
            "and   b.db_agent_id  = %lld",
            db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_connect_db* tmp;
    pc_type_connect_db conDb;
    if ((tmp = (pc_type_connect_db*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    memcpy(&conDb, tmp, sizeof(pc_type_connect_db));
    delete EXCEPTnC;
    delete sql_stmt;

    pc_type_inst_agent_user_out out;
    DgcOracleConnection* conn = 0;
    memset(&out, 0, sizeof(pc_type_inst_agent_user_out));
    if (conDb.db_type == 11) {
        dgt_schar conn_string[1024];
        memset(conn_string, 0, 1024);
        sprintf(conn_string,
                "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)("
                "PORT=%d)))"
                "(CONNECT_DATA=(SERVER=DEDICATED)(SID=%s)))",
                conDb.listen_ip, conDb.listen_port, conDb.instance_name);
        conn = new DgcOracleConnection();
        const dgt_schar* priv = 0;
        if (!strcasecmp(sys_uid, "sys")) priv = "SYSDBA";
        if (conn->connect(conn_string, nul, sys_uid, sys_pass, priv) != 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcError* err = e->getErr();
                while (err->next()) err = err->next();
                sprintf(out.result_msg, "%s", (dgt_schar*)err->message());
                out.result_code = -1;
            }
            delete conn;
            delete e;
            rtn_rows->reset();
            rtn_rows->add();
            rtn_rows->next();
            memset(rtn_rows->data(), 0, rtn_rows->rowSize());
            memcpy(rtn_rows->data(), &out, sizeof(pc_type_inst_agent_user_out));
            rtn_rows->rewind();
            return -1;
        }
    }
    //
    // Agent User duplicate check
    //
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select count(*) from dba_users where username = upper('%s')",
            agent_uid);
    DgcCliStmt* stmt = conn->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        delete conn;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcMemRows* rows = stmt->returnRows();
    dgt_sint32 count = 0;
    if (rows && rows->numRows() > 0) {
        if (rows->next()) {
            count = strtol((dgt_schar*)rows->data(), 0, 10);
        }
    }
    delete stmt;
    delete conn;
    if (count > 0) {
        rtn_rows->reset();
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        sprintf(out.result_msg, "duplicate user name");
        out.result_code = -2;
        memcpy(rtn_rows->data(), &out, sizeof(pc_type_inst_agent_user_out));
        rtn_rows->rewind();
        return -1;
    }
    return 0;
}

dgt_sint32 PccOraScriptBuilder::setCharset(dgt_sint64 db_agent_id) throw(
    DgcExcept) {
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS, "getConnection failed."), -1);
    }
    dgt_schar sql_text[256];
    sprintf(sql_text,
            "select value$ from sys.props$ where name = 'NLS_LANGUAGE' or name "
            "= 'NLS_TERRITORY' or name = 'NLS_CHARACTERSET'");
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        Connection->disconnect();
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcMemRows* rows = stmt->returnRows();
    dgt_schar nls_char[128];
    memset(nls_char, 0, 128);
    dgt_sint32 seq = 0;
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            if (seq == 0) {
                strcat(nls_char, (dgt_schar*)rows->data());
                strcat(nls_char, "_");
            } else {
                strcat(nls_char, (dgt_schar*)rows->data());
                strcat(nls_char, ".");
            }
            seq++;
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;

    *(nls_char + strlen(nls_char) - 1) = 0;
    memset(sql_text, 0, 256);
    sprintf(sql_text,
            "update pct_db_agent "
            "set(nls_lang,last_update)=('%s',nextLastUpdate('PCT_DB_AGENT', "
            "%lld, 2)) where db_agent_id=%lld",
            nls_char, db_agent_id, db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete sql_stmt;
    Connection->disconnect();
    return 0;
}

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pc_type_agent_test_out;

dgt_sint32 PccOraScriptBuilder::agentTest(
    dgt_sint64 db_agent_id, DgcMemRows* rtn_rows) throw(DgcExcept) {
    pc_type_agent_test_out out;
    memset(&out, 0, sizeof(pc_type_agent_test_out));
    if (!getConnection()) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out.result_msg, "%s", (dgt_schar*)err->message());
            out.result_code = 0;
        }
        rtn_rows->reset();
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out, sizeof(pc_type_agent_test_out));
        rtn_rows->rewind();
        delete e;
        return -1;
    }
    dgt_schar sql_text[256];
    memset(sql_text, 0, 256);
    sprintf(sql_text, "select pls_encrypt_b64_id('AGENT_TEST',1) from dual");
    DgcCliStmt* stmt = Connection->getStmt();
    if (!stmt) {
        Connection->disconnect();
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out.result_msg, "%s", (dgt_schar*)err->message());
            if (strstr(out.result_msg, "00904")) {
                out.result_code = 0;
            } else if (strstr(out.result_msg, "29540")) {
                out.result_code = 1;
            } else if (strstr(out.result_msg, "29541")) {
                out.result_code = 2;
            } else if (strstr(out.result_msg, "PcaOracle")) {
                out.result_code = 3;
            } else if (strstr(out.result_msg, "ExceptionInInitializerError")) {
                out.result_code = 4;
            } else if (strstr(out.result_msg, "03113")) {
                out.result_code = 5;
            } else {
                out.result_code = 6;
            }
        }
        delete e;
        delete stmt;
        rtn_rows->reset();
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out, sizeof(pc_type_agent_test_out));
        rtn_rows->rewind();
        Connection->disconnect();
        return -1;
    }
    DgcMemRows* rows = stmt->returnRows();
    dgt_schar enc_data[128];
    memset(enc_data, 0, 128);
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            memcpy(enc_data, rows->data(), 128);
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;

    memset(sql_text, 0, 256);
    sprintf(sql_text,
            "update pct_db_agent "
            "set(inst_step,last_update)=(5,nextLastUpdate('PCT_DB_AGENT', "
            "%lld, 2)) where db_agent_id=%lld",
            db_agent_id, db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete sql_stmt;
    Connection->disconnect();
    return 0;
}

typedef struct {
    dgt_uint16 parallel_degree;
    dgt_sint8 domain_index;
    dgt_sint8 data_type;
    dgt_sint8 algorithm;
    dgt_schar result_msg[1024];
} pc_type_agent_table_test_out;

dgt_sint32 PccOraScriptBuilder::agentTableTest(
    dgt_sint64 db_agent_id, DgcMemRows* rtn_rows) throw(DgcExcept) {
    pc_type_agent_table_test_out out_param;
    memset(&out_param, 0, sizeof(pc_type_agent_table_test_out));
    if (!getConnection()) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
            out_param.parallel_degree = 0;
            out_param.domain_index = -1;
            out_param.data_type = -1;
            out_param.algorithm = -1;
        }
        delete e;
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out_param,
               sizeof(pc_type_agent_table_test_out));
        rtn_rows->rewind();
        return 0;
    }
    dgt_schar sql_text[1024];

    //
    // drop the table
    //
    DgcCliStmt* stmt = Connection->getStmt();
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE ALGO_TABLE PURGE");
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        delete EXCEPTnC;
    }
    delete stmt;

    stmt = Connection->getStmt();
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE BASE_TABLE PURGE");
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        delete EXCEPTnC;
    }
    delete stmt;

    stmt = Connection->getStmt();
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE PARALLEL_TABLE PURGE");
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        delete EXCEPTnC;
    }
    delete stmt;

    stmt = Connection->getStmt();
    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE DATA_TYPE_TABLE PURGE");
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        delete EXCEPTnC;
    }
    delete stmt;

    //
    // find the optimal parallel dgree
    //
    sprintf(sql_text, "select value from v$parameter where name = 'cpu_count'");
    stmt = Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed."), -1);
    }
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    DgcMemRows* rows = stmt->returnRows();
    dgt_sint32 cpu_count = 0;
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            dgt_schar* tmp = (dgt_schar*)rows->getColPtr(1);
            cpu_count = strtol(tmp, 0, 10);
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;

    if (cpu_count > 1) {
        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "CREATE TABLE BASE_TABLE "
                "(	DATA1 NUMBER,"
                "DATA2 VARCHAR(15)"
                ")");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;

        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "INSERT INTO BASE_TABLE "
                "SELECT LEVEL "
                ",TO_CHAR(LEVEL,'FM0000000000000') "
                "FROM DUAL "
                "CONNECT BY LEVEL <= 300000");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;

        memset(sql_text, 0, 1024);
        sprintf(sql_text, "commit");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;

        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "CREATE TABLE PARALLEL_TABLE "
                "(  DATA1 VARCHAR(30), "
                "   DATA2 VARCHAR(30) )");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        //
        // calculate the elasped time
        // first time : cpu_count
        // second time : cpu_count / 2
        // third time : cpu_count / 2 + ceil(cpu_count/4)
        //
        struct timeval startTime;
        struct timeval currTime;
        dgt_sint64 lapse_time = 0;
        dgt_sint64 cmp_time = 0;
        //
        // first time
        //
        gettimeofday(&startTime, 0);
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "ALTER SESSION FORCE PARALLEL DML");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "insert /*+ APPEND PARALLEL(PARALLEL_TABLE,%d) */ into "
                "PARALLEL_TABLE "
                "SELECT /*+ FULL(BASE_TABLE) PARALLEL(BASE_TABLE,%d) */ "
                "PLS_ENCRYPT_B64_ID(DATA1,1) , "
                "PLS_ENCRYPT_B64_ID(DATA2,1) "
                "FROM BASE_TABLE",
                cpu_count, cpu_count);
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcError* err = e->getErr();
                while (err->next()) err = err->next();
                sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
                out_param.parallel_degree = 0;
                out_param.domain_index = -1;
                out_param.data_type = -1;
                out_param.algorithm = -1;
            }
            delete e;
            rtn_rows->add();
            rtn_rows->next();
            memset(rtn_rows->data(), 0, rtn_rows->rowSize());
            memcpy(rtn_rows->data(), &out_param,
                   sizeof(pc_type_agent_table_test_out));
            rtn_rows->rewind();
            delete stmt;
            Connection->disconnect();
            return 0;
        }
        delete stmt;
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "commit");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        gettimeofday(&currTime, 0);
        if (currTime.tv_sec == startTime.tv_sec) {
            lapse_time = currTime.tv_usec - startTime.tv_usec;
        } else {
            lapse_time =
                (dgt_sint64)(currTime.tv_sec - startTime.tv_sec) * 1000000 +
                currTime.tv_usec - startTime.tv_usec;
        }
        cmp_time = lapse_time;
        out_param.parallel_degree = cpu_count;
        //
        // second time
        //
        gettimeofday(&startTime, 0);
        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "insert /*+ APPEND PARALLEL(PARALLEL_TABLE,%d) */  into "
                "PARALLEL_TABLE "
                "SELECT /*+ FULL(BASE_TABLE) PARALLEL(BASE_TABLE,%d) */ "
                "PLS_ENCRYPT_B64_ID(DATA1,1) , "
                "PLS_ENCRYPT_B64_ID(DATA2,1) "
                "FROM BASE_TABLE",
                cpu_count / 2, cpu_count / 2);
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcError* err = e->getErr();
                while (err->next()) err = err->next();
                sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
                out_param.parallel_degree = 0;
                out_param.domain_index = -1;
                out_param.data_type = -1;
                out_param.algorithm = -1;
            }
            delete e;
            rtn_rows->add();
            rtn_rows->next();
            memset(rtn_rows->data(), 0, rtn_rows->rowSize());
            memcpy(rtn_rows->data(), &out_param,
                   sizeof(pc_type_agent_table_test_out));
            rtn_rows->rewind();
            delete stmt;
            Connection->disconnect();
            return 0;
        }
        delete stmt;
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "commit");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        gettimeofday(&currTime, 0);
        if (currTime.tv_sec == startTime.tv_sec) {
            lapse_time = currTime.tv_usec - startTime.tv_usec;
        } else {
            lapse_time =
                (dgt_sint64)(currTime.tv_sec - startTime.tv_sec) * 1000000 +
                currTime.tv_usec - startTime.tv_usec;
        }
        if (cmp_time > lapse_time) {
            cmp_time = lapse_time;
            out_param.parallel_degree = cpu_count / 2;
        }
        //
        // third time
        //
        gettimeofday(&startTime, 0);
        memset(sql_text, 0, 1024);
        sprintf(sql_text,
                "insert /*+ APPEND PARALLEL(PARALLEL_TABLE,%d) */ into "
                "PARALLEL_TABLE "
                "SELECT /*+ FULL(BASE_TABLE) PARALLEL(BASE_TABLE,%d) */ "
                "PLS_ENCRYPT_B64_ID(DATA1,1) , "
                "PLS_ENCRYPT_B64_ID(DATA2,1) "
                "FROM BASE_TABLE",
                (dgt_sint32)cpu_count / 2 + (dgt_sint32)ceil(cpu_count / 4),
                (dgt_sint32)cpu_count / 2 + (dgt_sint32)ceil(cpu_count / 4));
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcError* err = e->getErr();
                while (err->next()) err = err->next();
                sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
                out_param.parallel_degree = 0;
                out_param.domain_index = -1;
                out_param.data_type = -1;
                out_param.algorithm = -1;
            }
            delete e;
            rtn_rows->add();
            rtn_rows->next();
            memset(rtn_rows->data(), 0, rtn_rows->rowSize());
            memcpy(rtn_rows->data(), &out_param,
                   sizeof(pc_type_agent_table_test_out));
            rtn_rows->rewind();
            Connection->disconnect();
            delete stmt;
            return 0;
        }
        delete stmt;
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "commit");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        gettimeofday(&currTime, 0);
        if (currTime.tv_sec == startTime.tv_sec) {
            lapse_time = currTime.tv_usec - startTime.tv_usec;
        } else {
            lapse_time =
                (dgt_sint64)(currTime.tv_sec - startTime.tv_sec) * 1000000 +
                currTime.tv_usec - startTime.tv_usec;
        }
        if (cmp_time > lapse_time) {
            cmp_time = lapse_time;
            out_param.parallel_degree =
                (dgt_sint16)cpu_count / 2 + (dgt_sint16)ceil(cpu_count / 4);
            if (out_param.parallel_degree > 2)
                out_param.parallel_degree = out_param.parallel_degree - 1;
        }

        memset(sql_text, 0, 1024);
        sprintf(sql_text, "DROP TABLE BASE_TABLE PURGE");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;

        memset(sql_text, 0, 1024);
        sprintf(sql_text, "DROP TABLE PARALLEL_TABLE PURGE");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;
        memset(sql_text, 0, 1024);
        sprintf(sql_text, "ALTER SESSION DISABLE PARALLEL DML");
        stmt = Connection->getStmt();
        if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete stmt;

        memset(sql_text, 0, 256);
        sprintf(sql_text,
                "update pct_db_agent "
                "set(parallel_degree,last_update)=(%d,nextLastUpdate('PCT_DB_"
                "AGENT', %lld, 2)) where db_agent_id=%lld",
                out_param.parallel_degree, db_agent_id, db_agent_id);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete sql_stmt;
    } else {
        out_param.parallel_degree = 1;
        memset(sql_text, 0, 256);
        sprintf(sql_text,
                "update pct_db_agent "
                "set(parallel_degree,last_update)=(%d,nextLastUpdate('PCT_DB_"
                "AGENT', %lld, 2)) where db_agent_id=%lld",
                out_param.parallel_degree, db_agent_id, db_agent_id);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        delete sql_stmt;
    }

    //
    // data type encryption test
    //
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "CREATE TABLE BASE_TABLE "
            "(  NUMBER_TYPE	NUMBER(13) "
            " ,VARCHAR_TYPE	VARCHAR2(13) "
            " ,DATE_TYPE     DATE "
            " ,LOB_TYPE	    CLOB "
            " ,RAW_TYPE      RAW(13))");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "INSERT INTO BASE_TABLE "
            "SELECT 1,'NAME'||ROUND(DBMS_RANDOM.VALUE(1, 10000)) "
            ",SYSDATE "
            ",TO_CHAR('FM0000000000000000') "
            ",UTL_RAW.CAST_TO_RAW('FM0000') "
            "FROM DUAL");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "CREATE TABLE DATA_TYPE_TABLE "
            "(  NUMBER_TYPE	VARCHAR2(30) "
            " ,VARCHAR_TYPE	VARCHAR2(30) "
            " ,DATE_TYPE     VARCHAR2(30) "
            " ,LOB_TYPE	    CLOB "
            " ,RAW_TYPE      VARCHAR2(30))");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "INSERT INTO DATA_TYPE_TABLE "
            "SELECT PLS_ENCRYPT_B64_ID(NUMBER_TYPE,1), "
            "PLS_ENCRYPT_B64_ID(VARCHAR_TYPE,1), "
            "PLS_ENCRYPT_B64_ID_DATE(DATE_TYPE,1), "
            "PLS_ENCRYPT_CLOB(LOB_TYPE,1), "
            "PLS_ENCRYPT_B64_ID_RAW(RAW_TYPE,1) "
            "FROM BASE_TABLE");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
            out_param.data_type = -1;
            out_param.algorithm = -1;
            out_param.domain_index = -1;
        }
        delete e;
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out_param,
               sizeof(pc_type_agent_table_test_out));
        rtn_rows->rewind();
        delete stmt;
        Connection->disconnect();
        return 0;
    }
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "SELECT COUNT(*) "
            "FROM BASE_TABLE A, DATA_TYPE_TABLE B "
            "WHERE A.NUMBER_TYPE != PLS_DECRYPT_B64_ID(B.NUMBER_TYPE,1) "
            "OR    A.VARCHAR_TYPE != PLS_DECRYPT_B64_ID(B.VARCHAR_TYPE,1) "
            "OR    A.DATE_TYPE != PLS_DECRYPT_B64_ID_DATE(B.DATE_TYPE,1) "
            "OR    dbms_lob.compare(A.LOB_TYPE,PLS_DECRYPT_CLOB(B.LOB_TYPE,1)) "
            "!= 0 "
            "OR    A.RAW_TYPE != PLS_DECRYPT_B64_ID_RAW(B.RAW_TYPE,1) ");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
            out_param.data_type = -1;
            out_param.algorithm = -1;
            out_param.domain_index = -1;
        }
        delete e;
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out_param,
               sizeof(pc_type_agent_table_test_out));
        rtn_rows->rewind();
        delete stmt;
        Connection->disconnect();
        return 0;
    }
    rows = stmt->returnRows();
    dgt_sint32 success_flag = -1;
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            dgt_schar* tmp = (dgt_schar*)rows->getColPtr(1);
            success_flag = strtol(tmp, 0, 10);
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;
    out_param.data_type = success_flag;

    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE DATA_TYPE_TABLE PURGE");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;

    //
    // algorithm test
    //
    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "CREATE TABLE ALGO_TABLE "
            "(  AES_COL VARCHAR2(30) "
            "  ,ARIA_COL VARCHAR2(30) "
            "  ,SEED_COL VARCHAR2(30) "
            "  ,SHA_COL  VARCHAR2(45))");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;

    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "INSERT INTO ALGO_TABLE "
            "SELECT PLS_ENCRYPT_B64_ID(VARCHAR_TYPE,1), "
            "PLS_ENCRYPT_B64_ID(VARCHAR_TYPE,2), "
            "PLS_ENCRYPT_B64_ID(VARCHAR_TYPE,3), "
            "PLS_ENCRYPT_B64_ID(VARCHAR_TYPE,4) "
            "FROM BASE_TABLE ");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
            out_param.algorithm = -1;
            out_param.domain_index = -1;
        }
        delete e;
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out_param,
               sizeof(pc_type_agent_table_test_out));
        rtn_rows->rewind();
        delete stmt;
        Connection->disconnect();
        return 0;
    }
    delete stmt;

    memset(sql_text, 0, 1024);
    sprintf(sql_text,
            "SELECT COUNT(*) "
            "FROM BASE_TABLE A, ALGO_TABLE B "
            "WHERE A.VARCHAR_TYPE != PLS_DECRYPT_B64_ID(B.AES_COL,1) "
            "OR    A.VARCHAR_TYPE != PLS_DECRYPT_B64_ID(B.ARIA_COL,2) "
            "OR    A.VARCHAR_TYPE != PLS_DECRYPT_B64_ID(B.SEED_COL,3)");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcError* err = e->getErr();
            while (err->next()) err = err->next();
            sprintf(out_param.result_msg, "%s", (dgt_schar*)err->message());
            out_param.algorithm = -1;
            out_param.domain_index = -1;
        }
        delete e;
        rtn_rows->add();
        rtn_rows->next();
        memset(rtn_rows->data(), 0, rtn_rows->rowSize());
        memcpy(rtn_rows->data(), &out_param,
               sizeof(pc_type_agent_table_test_out));
        rtn_rows->rewind();
        delete stmt;
        Connection->disconnect();
        return 0;
    }
    rows = stmt->returnRows();
    success_flag = -1;
    while (rows && rows->numRows() > 0) {
        while (rows->next()) {
            dgt_schar* tmp = (dgt_schar*)rows->getColPtr(1);
            success_flag = strtol(tmp, 0, 10);
        }
        rows->reset();
        if (stmt->fetch(10) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            Connection->disconnect();
            RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
        }
    }
    delete stmt;
    out_param.algorithm = success_flag;

    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE ALGO_TABLE PURGE");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;

    memset(sql_text, 0, 1024);
    sprintf(sql_text, "DROP TABLE BASE_TABLE PURGE");
    stmt = Connection->getStmt();
    if (stmt->execute(sql_text, strlen(sql_text), 10) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete stmt;

    //
    // domain index test
    //
    out_param.domain_index = 0;

    //
    // update the current inst_step = 6(sample table test success) in
    // pct_db_agent table
    //
    memset(sql_text, 0, 256);
    sprintf(sql_text,
            "update pct_db_agent "
            "set(inst_step,last_update)=(6,nextLastUpdate('PCT_DB_AGENT', "
            "%lld, 2)) where db_agent_id=%lld",
            db_agent_id, db_agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        Connection->disconnect();
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    delete sql_stmt;
    Connection->disconnect();

    strcpy(out_param.result_msg, "Sample Table Test Successfully");
    rtn_rows->add();
    rtn_rows->next();
    memset(rtn_rows->data(), 0, rtn_rows->rowSize());
    memcpy(rtn_rows->data(), &out_param, sizeof(pc_type_agent_table_test_out));
    return 0;
}

typedef struct {
    dgt_uint8 os_type;
    dgt_schar db_version[33];
} pc_type_install_script;

dgt_sint32 PccOraScriptBuilder::buildInstallScript(
    dgt_sint64 agent_id, dgt_schar* agent_uid, dgt_schar* agent_pass,
    dgt_schar* soha_home) throw(DgcExcept) {
    TabInfo.enc_tab_id = agent_id;
    //
    // get system os type, oracle version
    //
    dgt_schar sql_text[1024];
    memset(sql_text, 0, 1024);
    sprintf(
        sql_text,
        "select  a.os_type, b.db_version "
        "from	pt_system a, pt_db_instance b, pct_db_agent c, pt_database d "
        "where   b.instance_id = c.instance_id "
        "and     a.system_id = b.system_id "
        "and     d.db_id = c.db_id "
        "and     c.db_agent_id = %lld",
        agent_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_install_script* tmp;
    if ((tmp = (pc_type_install_script*)sql_stmt->fetch()) == 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    }
    pc_type_install_script is;
    memcpy(&is, tmp, sizeof(pc_type_install_script));
    delete EXCEPTnC;
    delete sql_stmt;

    //
    // system owner's scripts
    //
    delete TextBuf;
    TextBuf = new dgt_schar[64000];
    VersionNo = 0;
    StepNo = 0;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf, "CREATE USER %s IDENTIFIED BY %s", agent_uid, agent_pass);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CONNECT, RESOURCE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT unlimited tablespace TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY VIEW TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY TRIGGER TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE PUBLIC SYNONYM TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY SYNONYM TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT SELECT ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT SELECT ANY DICTIONARY TO  %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT SELECT_CATALOG_ROLE TO  %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ALTER ANY PROCEDURE TO  %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ALTER ANY TRIGGER TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ALTER ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP ANY TRIGGER TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP ANY INDEX TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP ANY VIEW TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP ANY SYNONYM TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DROP PUBLIC SYNONYM TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ALTER ANY INDEX TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY INDEX TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ANALYZE ANY TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
#if 0
	*TextBuf=0;
	sprintf(TextBuf, "GRANT EXECUTE ON DBMS_RLS TO %s", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
#endif
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT MERGE any VIEW TO PUBLIC");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT QUERY REWRITE TO PUBLIC");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY DIRECTORY TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY INDEXTYPE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY OPERATOR TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT UPDATE ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT INSERT ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT DELETE ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT COMMENT ANY TABLE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT CREATE ANY TYPE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT EXECUTE ON DBMS_UTILITY TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT EXECUTE ON DBMS_SQL TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT GRANT ANY OBJECT PRIVILEGE TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "GRANT ALTER ANY materialized view TO %s", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    StepNo = 1;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "declare\n"
        "    v_seq number;\n"
        "begin\n"
        "    select seq into v_seq from dba_java_policy where GRANTEE = "
        "'PUBLIC' and TYPE_NAME like "
        "'%soracle.aurora.rdbms.security.PolicyTablePermission%s';\n"
        "    dbms_java.disable_permission(v_seq);\n"
        "    dbms_java.grant_permission( upper('%s'), "
        "'SYS:java.lang.RuntimePermission', 'loadLibrary.PcaOracle', '' );\n"
        "    dbms_java.enable_permission(v_seq);\n"
        "end; \n/",
        "%", "%", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    //
    // cipher owner's scripts
    //

    //
    // Step2 = JVM Installation Check
    //
    StepNo = 2;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf, "SELECT NAME FROM DBA_JAVA_POLICY WHERE ROWNUM=1");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    //
    // Step3 = Java Class File Loading
    //
    StepNo = 3;
    StmtNo = 0;
    *TextBuf = 0;
    if (is.os_type != 7) {
        //
        // in case of os type unix
        //
        if (!strcasecmp(is.db_version, "8i")) {
            sprintf(TextBuf,
                    "CREATE OR REPLACE DIRECTORY petra_dir AS "
                    "'%s/lib/cipher/oracle_class/8i/unix'",
                    soha_home);
            if (saveSqlText() < 0)
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        } else {
            sprintf(TextBuf,
                    "CREATE OR REPLACE DIRECTORY petra_dir AS "
                    "'%s/lib/cipher/oracle_class/9i_above/unix'",
                    soha_home);
            if (saveSqlText() < 0)
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    } else {
        //
        // in case of os type windows
        //
#if 1
        if (!strcasecmp(is.db_version, "8i")) {
            sprintf(TextBuf,
                    "CREATE OR REPLACE DIRECTORY petra_dir AS 'C:\\Program "
                    "Files\\SINSIWAY\\Petra\\api'");
            if (saveSqlText() < 0)
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        } else {
            sprintf(TextBuf,
                    "CREATE OR REPLACE DIRECTORY petra_dir AS 'C:\\Program "
                    "Files\\SINSIWAY\\Petra\\api'");
            if (saveSqlText() < 0)
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
#endif
    }
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE JAVA CLASS USING BFILE (petra_dir , "
            "'PcaOracle.class')");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    //
    // Step 4 = Create Enc/Dec Function
    //
    StepNo = 4;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_RAW "
            "(DATA IN VARCHAR2) "
            "RETURN RAW  parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[]) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_RAW_NM "
        "(DATA IN VARCHAR2, ECN VARCHAR2) "
        "RETURN RAW  parallel_enable deterministic IS "
        "LANGUAGE JAVA "
        "NAME 'PcaOracle.EXT_ENC_BB(byte[],java.lang.String) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_RAW_ID "
            "(DATA IN VARCHAR2, ENC_COL_ID NUMBER) "
            "RETURN RAW  parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_RAW_ID_RAW "
            "(DATA IN RAW, ENC_COL_ID NUMBER) "
            "RETURN RAW  parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_RAW_ID_DATE "
            "(DATA IN DATE, ENC_COL_ID NUMBER)"
            "RETURN RAW parallel_enable deterministic IS "
            "BEGIN "
            "RETURN "
            "PLS_ENCRYPT_RAW_ID(TO_CHAR(DATA,'YYYYMMDDHH24MISS'),ENC_COL_ID);"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW "
            "(DATA IN RAW) "
            "RETURN VARCHAR2 parallel_enable deterministic  IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[]) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW_NM "
        "(DATA IN RAW, ECN VARCHAR2) "
        "RETURN VARCHAR2 parallel_enable deterministic IS "
        "LANGUAGE JAVA "
        "NAME 'PcaOracle.EXT_DEC_BB(byte[],java.lang.String) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW_ID "
            "(DATA IN RAW, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW_ID_RAW "
            "(DATA IN RAW, ENC_COL_ID NUMBER) "
            "RETURN RAW parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW_ID_DATE "
            "(DATA IN RAW,ENC_COL_ID NUMBER) "
            "RETURN DATE parallel_enable deterministic IS "
            "BEGIN "
            "RETURN "
            "TO_DATE(PLS_DECRYPT_RAW_ID(DATA,ENC_COL_ID),'YYYYMMDDHH24MISS');"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_RAW_ID_NUM "
            "(DATA IN RAW,ENC_COL_ID NUMBER) "
            "RETURN NUMBER parallel_enable deterministic IS "
            "BEGIN "
            "RETURN PLS_DECRYPT_RAW_ID(DATA,ENC_COL_ID);"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64 "
            "(DATA IN VARCHAR2) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[]) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_NM "
        "(DATA IN VARCHAR2, ECN VARCHAR2) "
        "RETURN VARCHAR2 parallel_enable deterministic IS "
        "LANGUAGE JAVA "
        "NAME 'PcaOracle.EXT_ENC_BB(byte[],java.lang.String) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_ID "
            "(DATA IN VARCHAR2, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_ID_C "
            "(DATA IN VARCHAR2, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB_C(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_ID_N "
            "(DATA IN VARCHAR2, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "BEGIN "
            "RETURN pls_encrypt_b64_id( data , enc_col_id); "
            "end;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_CPN_ID "
            "(DATA IN VARCHAR2, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_CPN(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_ID_RAW "
            "(DATA IN RAW, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2  parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_B64_ID_DATE "
            "(DATA IN DATE, ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "BEGIN "
            "RETURN "
            "PLS_ENCRYPT_B64_ID(TO_CHAR(DATA,'YYYYMMDDHH24MISS'),ENC_COL_ID);"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64 "
            "(DATA IN VARCHAR2) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[]) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64_NM "
        "(DATA IN VARCHAR2, ECN VARCHAR2) "
        "RETURN VARCHAR2 parallel_enable deterministic IS "
        "LANGUAGE JAVA "
        "NAME 'PcaOracle.EXT_DEC_BB(byte[],java.lang.String) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64_ID "
            "(DATA IN VARCHAR2,ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_CPN_ID "
            "(DATA IN VARCHAR2,ENC_COL_ID NUMBER) "
            "RETURN VARCHAR2 parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_CPN(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64_ID_RAW "
            "(DATA IN VARCHAR2,ENC_COL_ID NUMBER) "
            "RETURN RAW parallel_enable deterministic IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BB(byte[],int) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64_ID_DATE "
            "(DATA IN VARCHAR2,ENC_COL_ID NUMBER) "
            "RETURN DATE parallel_enable deterministic IS "
            "BEGIN "
            "RETURN "
            "TO_DATE(PLS_DECRYPT_B64_ID(DATA,ENC_COL_ID),'YYYYMMDDHH24MISS');"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_B64_ID_NUM "
            "(DATA IN VARCHAR2,ENC_COL_ID NUMBER)"
            "RETURN NUMBER parallel_enable deterministic IS "
            "BEGIN "
            "RETURN PLS_DECRYPT_B64_ID(DATA,ENC_COL_ID);"
            "END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_CLOB_M "
            "(DATA IN BLOB,ENC_COL_ID NUMBER) "
            "RETURN CLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_CLOB(oracle.sql.BLOB,int) return "
            "oracle.sql.CLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_CLOB_M_NM "
            "(DATA IN BLOB, ECN VARCHAR2) "
            "RETURN CLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_CLOB(oracle.sql.BLOB,java.lang.String) "
            "return oracle.sql.CLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_CLOB(DATA IN "
            "CLOB,ENC_COL_ID NUMBER) "
            "RETURN CLOB parallel_enable deterministic IS "
            " v_blob blob; "
            " v_srcPos number := 1; "
            " v_dstPos number := 1; "
            " v_warning number; "
            " v_langContext number := DBMS_LOB.default_lang_ctx; "
            " v_nullcheck varchar2(100) := '==null=='; "
            "BEGIN "
            " IF dbms_lob.compare(nvl(DATA,'==null=='),v_nullcheck) = 0  then "
            "   return PLS_ENCRYPT_B64_ID(null, ENC_COL_ID); "
            " END IF; "
            " DBMS_LOB.CreateTemporary( v_blob, true ); "
            " DBMS_LOB.ConvertToBlob(v_blob, DATA, DBMS_LOB.GetLength(DATA), "
            "v_dstPos, v_srcPos, DBMS_LOB.default_csid, v_langContext, "
            "v_warning ); "
            " return PLS_ENCRYPT_CLOB_M(v_blob, ENC_COL_ID); "
            " END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_CLOB_NM(DATA IN CLOB,ECN "
            "VARCHAR2) "
            "RETURN CLOB parallel_enable deterministic IS "
            " v_blob blob; "
            " v_srcPos number := 1; "
            " v_dstPos number := 1; "
            " v_warning number; "
            " v_langContext number := DBMS_LOB.default_lang_ctx; "
            " v_nullcheck varchar2(100) := '==null=='; "
            "BEGIN "
            " IF dbms_lob.compare(nvl(DATA,'==null=='),v_nullcheck) = 0  then "
            "   return PLS_ENCRYPT_B64_NM(null, ECN); "
            " END IF; "
            " DBMS_LOB.CreateTemporary( v_blob, true ); "
            " DBMS_LOB.ConvertToBlob(v_blob, DATA, DBMS_LOB.GetLength(DATA), "
            "v_dstPos, v_srcPos, DBMS_LOB.default_csid, v_langContext, "
            "v_warning ); "
            " return PLS_ENCRYPT_CLOB_M_NM(v_blob, ECN); "
            " END;");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_CLOB "
            "(DATA IN CLOB,ENC_COL_ID NUMBER) "
            "RETURN CLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_CLOB(oracle.sql.CLOB,int) return "
            "oracle.sql.CLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_CLOB_NM "
            "(DATA IN CLOB,ECN VARCHAR2) "
            "RETURN CLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_CLOB(oracle.sql.CLOB,java.lang.String) "
            "return oracle.sql.CLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_BLOB "
            "(DATA IN BLOB,ENC_COL_ID NUMBER) "
            "RETURN BLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BLOB(oracle.sql.BLOB,int) return "
            "oracle.sql.BLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_ENCRYPT_BLOB_NM "
            "(DATA IN BLOB,ECN VARCHAR2) "
            "RETURN BLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_ENC_BLOB(oracle.sql.BLOB,java.lang.String) "
            "return oracle.sql.BLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_BLOB "
            "(DATA IN BLOB,ENC_COL_ID NUMBER) "
            "RETURN BLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BLOB(oracle.sql.BLOB,int) return "
            "oracle.sql.BLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_DECRYPT_BLOB_NM "
            "(DATA IN BLOB,ECN VARCHAR2) "
            "RETURN BLOB parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_DEC_BLOB(oracle.sql.BLOB,java.lang.String) "
            "return oracle.sql.BLOB';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "CREATE OR REPLACE FUNCTION PLS_LCR "
            "(tablename varchar2,object varchar2) "
            "RETURN VARCHAR2 parallel_enable IS "
            "LANGUAGE JAVA "
            "NAME 'PcaOracle.EXT_LCR(byte[],byte[]) return byte[]';");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    //
    // Step 5 = Grant Execute on Function to PULBIC
    //
    StepNo = 5;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_RAW_NM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_RAW_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_ENCRYPT_RAW_ID_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_ENCRYPT_RAW_ID_DATE TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_RAW_NM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_RAW_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_RAW_ID_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_RAW_ID_DATE TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_RAW_ID_NUM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_B64 TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_B64_NM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_B64_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_ENCRYPT_B64_ID_C TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_ENCRYPT_B64_ID_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_ENCRYPT_B64_ID_DATE TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_B64 TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_B64_NM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_B64_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_B64_ID_RAW TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_B64_ID_DATE TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(
        TextBuf,
        "GRANT EXECUTE ON PLS_DECRYPT_B64_ID_NUM TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_CLOB TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_CLOB_M TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_BLOB TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_CLOB TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_BLOB TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_ENCRYPT_CPN_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf,
            "GRANT EXECUTE ON PLS_DECRYPT_CPN_ID TO PUBLIC WITH GRANT OPTION");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

#if 0
	*TextBuf=0; sprintf(TextBuf,"GRANT EXECUTE ON PLS_LCR TO PUBLIC WITH GRANT OPTION");
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
#endif

    *TextBuf = 0;
    sprintf(
        TextBuf,
        "create sequence tr_table_id increment by 1 start with 1 cache 10000");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    //
    // Step 6 = Create Function Synonym
    //
    StepNo = 6;
    StmtNo = 0;
    if (!strcasecmp(is.db_version, "8i")) {
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_RAW FOR %s.PLS_ENCRYPT_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_RAW_NM FOR "
                "%s.PLS_ENCRYPT_RAW_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID FOR "
                "%s.PLS_ENCRYPT_RAW_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_RAW FOR "
                "%s.PLS_ENCRYPT_RAW_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_DATE FOR "
                "%s.PLS_ENCRYPT_RAW_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW FOR %s.PLS_DECRYPT_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW_NM FOR "
                "%s.PLS_DECRYPT_RAW_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID FOR "
                "%s.PLS_DECRYPT_RAW_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_RAW FOR "
                "%s.PLS_DECRYPT_RAW_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_DATE FOR "
                "%s.PLS_DECRYPT_RAW_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_NUM FOR "
                "%s.PLS_DECRYPT_RAW_ID_NUM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64 FOR %s.PLS_ENCRYPT_B64",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_NM FOR "
                "%s.PLS_ENCRYPT_B64_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID FOR "
                "%s.PLS_ENCRYPT_B64_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_C FOR "
                "%s.PLS_ENCRYPT_B64_ID_C",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_N FOR "
                "%s.PLS_ENCRYPT_B64_ID_N",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_RAW FOR "
                "%s.PLS_ENCRYPT_B64_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_DATE FOR "
                "%s.PLS_ENCRYPT_B64_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64 FOR %s.PLS_DECRYPT_B64",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64_NM FOR "
                "%s.PLS_DECRYPT_B64_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64_ID FOR "
                "%s.PLS_DECRYPT_B64_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_RAW FOR "
                "%s.PLS_DECRYPT_B64_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_DATE FOR "
                "%s.PLS_DECRYPT_B64_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_NUM FOR "
                "%s.PLS_DECRYPT_B64_ID_NUM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE PUBLIC SYNONYM PLS_ENCRYPT_CLOB FOR %s.PLS_ENCRYPT_CLOB",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_CLOB_M FOR "
                "%s.PLS_ENCRYPT_CLOB_M",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE PUBLIC SYNONYM PLS_ENCRYPT_BLOB FOR %s.PLS_ENCRYPT_BLOB",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE PUBLIC SYNONYM PLS_DECRYPT_CLOB FOR %s.PLS_DECRYPT_CLOB",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE PUBLIC SYNONYM PLS_DECRYPT_BLOB FOR %s.PLS_DECRYPT_BLOB",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf, "CREATE PUBLIC SYNONYM PLS_LCR FOR %s.PLS_LCR",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_ENCRYPT_CPN_ID FOR "
                "%s.PLS_ENCRYPT_CPN_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE PUBLIC SYNONYM PLS_DECRYPT_CPN_ID FOR "
                "%s.PLS_DECRYPT_CPN_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    } else {
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_RAW FOR "
                "%s.PLS_ENCRYPT_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_RAW_NM FOR "
                "%s.PLS_ENCRYPT_RAW_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID FOR "
                "%s.PLS_ENCRYPT_RAW_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_RAW FOR "
                "%s.PLS_ENCRYPT_RAW_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_DATE FOR "
                "%s.PLS_ENCRYPT_RAW_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW FOR "
                "%s.PLS_DECRYPT_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW_NM FOR "
                "%s.PLS_DECRYPT_RAW_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID FOR "
                "%s.PLS_DECRYPT_RAW_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_RAW FOR "
                "%s.PLS_DECRYPT_RAW_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_DATE FOR "
                "%s.PLS_DECRYPT_RAW_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_NUM FOR "
                "%s.PLS_DECRYPT_RAW_ID_NUM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64 FOR "
                "%s.PLS_ENCRYPT_B64",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_NM FOR "
                "%s.PLS_ENCRYPT_B64_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID FOR "
                "%s.PLS_ENCRYPT_B64_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_C FOR "
                "%s.PLS_ENCRYPT_B64_ID_C",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_N FOR "
                "%s.PLS_ENCRYPT_B64_ID_N",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_RAW FOR "
                "%s.PLS_ENCRYPT_B64_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_DATE FOR "
                "%s.PLS_ENCRYPT_B64_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64 FOR "
                "%s.PLS_DECRYPT_B64",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64_NM FOR "
                "%s.PLS_DECRYPT_B64_NM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64_ID FOR "
                "%s.PLS_DECRYPT_B64_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_RAW FOR "
                "%s.PLS_DECRYPT_B64_ID_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_DATE FOR "
                "%s.PLS_DECRYPT_B64_ID_DATE",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_B64_ID_NUM FOR "
                "%s.PLS_DECRYPT_B64_ID_NUM",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_CLOB FOR "
                "%s.PLS_ENCRYPT_CLOB",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_CLOB_M FOR "
                "%s.PLS_ENCRYPT_CLOB_M",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_BLOB FOR "
                "%s.PLS_ENCRYPT_BLOB",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_CLOB FOR "
                "%s.PLS_DECRYPT_CLOB",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_BLOB FOR "
                "%s.PLS_DECRYPT_BLOB",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_LCR FOR %s.PLS_LCR",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_ENCRYPT_CPN_ID FOR "
                "%s.PLS_ENCRYPT_CPN_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_DECRYPT_CPN_ID FOR "
                "%s.PLS_DECRYPT_CPN_ID",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    //
    // Step 7 = Create Domain Index Type
    //
    StepNo = 7;
    StmtNo = 0;
    if (strcasecmp(is.db_version, "8i")) {
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE FUNCTION PLS_OPHUEK_RAW "
                "(DATA IN  RAW , ENC_COL_ID IN NUMBER, SRC_ENC_FLAG IN NUMBER) "
                "RETURN VARCHAR2 parallel_enable deterministic IS "
                "LANGUAGE JAVA "
                "NAME 'PcaOracle.EXT_OPHUEK(byte[],int,int) return byte[]';");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE FUNCTION PLS_OPHUEK_B64 "
                "(DATA IN  VARCHAR2 , ENC_COL_ID IN NUMBER, SRC_ENC_FLAG IN "
                "NUMBER) "
                "RETURN VARCHAR2 parallel_enable deterministic IS "
                "LANGUAGE JAVA "
                "NAME 'PcaOracle.EXT_OPHUEK(byte[],int,int) return byte[]';");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "GRANT EXECUTE ON PLS_OPHUEK_RAW TO PUBLIC WITH GRANT OPTION");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "GRANT EXECUTE ON PLS_OPHUEK_B64 TO PUBLIC WITH GRANT OPTION");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_OPHUEK_RAW FOR "
                "%s.PLS_OPHUEK_RAW",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM PLS_OPHUEK_B64 FOR "
                "%s.PLS_OPHUEK_B64",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create operator pls_idx1_str "
                "binding (varchar2,number) "
                "return varchar2 using pls_decrypt_b64_id");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create operator pls_idx1_num "
                "binding (varchar2,number) "
                "return number using pls_decrypt_b64_id_num");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create operator pls_idx1_date "
                "binding (varchar2,number) "
                "return date using pls_decrypt_b64_id_date");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pls_idx1_str to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pls_idx1_num to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pls_idx1_date to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
#if 1
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE OR REPLACE PUBLIC SYNONYM pls_idx1_str FOR %s.pls_idx1_str",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
#else
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE OR REPLACE PUBLIC SYNONYM pls_idx1_num FOR %s.pls_idx1_num",
            agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "CREATE OR REPLACE PUBLIC SYNONYM pls_idx1_date FOR "
                "%s.pls_idx1_date",
                agent_uid);
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
#endif
        sprintf(TextBuf,
                "create or replace package DgCipherIndex$Const \n"
                "is \n"
                "ShowDebugInfo  constant boolean := false;\n"
                "UnknownType    constant integer := 0;\n"
                "Varchar2Type   constant integer := 1;\n"
                "NumberType     constant integer := 2;\n"
                "Success        constant integer := 0;\n"
                "Failed         constant integer := -1;\n"
                "end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "grant execute on DgCipherIndex$Const to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type DgCipherIndex$LikeExprInfo as object\n"
                "(\n"
                "exprString    varchar2(4000),\n"
                "allMarkPos    sys.ODCINumberList,\n"
                "singleMarkPos sys.ODCINumberList,\n"
                "constructor function DgCipherIndex$LikeExprInfo\n"
                "(expr varchar2)\n"
                "return self as result\n"
                ");");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type body DgCipherIndex$LikeExprInfo\n"
                "is\n"
                "constructor function DgCipherIndex$LikeExprInfo\n"
                "(expr varchar2)\n"
                "return self as result\n"
                "is\n"
                "aPos integer;\n"
                "sPos integer;\n"
                "next integer := 1;\n"
                "begin\n"
                "self.exprString := expr;\n"
                "self.allMarkPos := sys.ODCINumberList();\n"
                "self.singleMarkPos := sys.ODCINumberList();\n"
                "loop\n"
                "aPos := instr(self.exprString, '%%', 1, next);\n"
                "sPos := instr(self.exprString, '_', 1, next);\n"
                "exit when aPos = 0 and sPos = 0;\n"
                "if aPos != 0 then\n"
                "self.allMarkPos.extend;\n"
                "self.allMarkPos(next) := aPos;\n"
                "end if;\n"
                "if sPos != 0 then\n"
                "self.singleMarkPos.extend;\n"
                "self.singleMarkPos(next) := sPos;\n"
                "end if;\n"
                "next := next + 1;\n"
                "end loop;\n"
                "return;\n"
                "end DgCipherIndex$LikeExprInfo;\n"
                "end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type DgCipherIndex$QueryInfo as object\n"
                "(\n"
                "cursorNo        number,\n"
                "howMany         number,\n"
                "colType         number,\n"
                "operatorList    sys.ODCIVarchar2List,\n"
                "bindValueList   sys.ODCIVarchar2List,\n"
                "placeHolderList sys.ODCIVarchar2List,\n"
                "likeExprInfo    DgCipherIndex$LikeExprInfo,\n"
                "constructor function DgCipherIndex$QueryInfo\n"
                "return self as result,\n"
                "constructor function DgCipherIndex$QueryInfo\n"
                "(pr sys.ODCIPredInfo, strt varchar2, stop varchar2)\n"
                "return self as result\n"
                ")\n"
                "not final;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body DgCipherIndex$QueryInfo\n"
            "is\n"
            "constructor function DgCipherIndex$QueryInfo\n"
            "return self as result\n"
            "is\n"
            "begin\n"
            "cursorNo := 0;\n"
            "howMany := 0;\n"
            "colType := DgCipherIndex$Const.UnknownType;\n"
            "operatorList := sys.ODCIVarchar2List();\n"
            "bindValueList := sys.ODCIVarchar2List();\n"
            "placeHolderList := sys.ODCIVarchar2List();\n"
            "return;\n"
            "end DgCipherIndex$QueryInfo;\n"
            "constructor function DgCipherIndex$QueryInfo\n"
            "(pr sys.ODCIPredInfo, strt varchar2, stop varchar2)\n"
            "return self as result\n"
            "is\n"
            "begin\n"
            "cursorNo := 0;\n"
            "howMany := 0;\n"
            "colType := DgCipherIndex$Const.UnknownType;\n"
            "operatorList := sys.ODCIVarchar2List();\n"
            "bindValueList := sys.ODCIVarchar2List();\n"
            "placeHolderList := sys.ODCIVarchar2List();\n"
            "self.operatorList.extend;\n"
            "self.bindValueList.extend;\n"
            "if bitand(pr.Flags, ODCIConst.PredPrefixMatch) <> 0 then\n"
            "self.operatorList(1) := 'like';\n"
            "self.bindValueList(1) := strt;\n"
            "self.likeExprInfo := DgCipherIndex$LikeExprInfo(strt);\n"
            "elsif bitand(pr.Flags, ODCIConst.PredExactMatch) <> 0 then\n"
            "self.operatorList(1) := '=';\n"
            "self.bindValueList(1) := strt;\n"
            "elsif bitand(pr.Flags, ODCIConst.PredIncludeStart) <> 0 and\n"
            "bitand(pr.Flags, ODCIConst.PredIncludeStop) <> 0 then\n"
            "self.operatorList.extend;\n"
            "self.operatorList(1) := 'between';\n"
            "self.operatorList(2) := 'and';\n"
            "self.bindValueList.extend;\n"
            "self.bindValueList(1) := strt;\n"
            "self.bindValueList(2) := stop;\n"
            "elsif bitand(pr.Flags, ODCIConst.PredIncludeStart) <> 0 and\n"
            "stop is NULL then\n"
            "self.operatorList(1) := '>=';\n"
            "self.bindValueList(1) := strt;\n"
            "elsif bitand(pr.Flags, ODCIConst.PredIncludeStart) <> 0 and\n"
            "stop is NOT NULL then\n"
            "self.operatorList.extend;\n"
            "self.bindValueList.extend;\n"
            "self.operatorList(1) := '>=';\n"
            "self.bindValueList(1) := strt;\n"
            "self.operatorList(2) := '<';\n"
            "self.bindValueList(2) := stop;\n"
            "elsif bitand(pr.Flags, ODCIConst.PredIncludeStop) <> 0 and\n"
            "strt is NULL then\n"
            "self.operatorList(1) := '<=';\n"
            "self.bindValueList(1) := stop;\n"
            "elsif bitand(pr.Flags, ODCIConst.PredIncludeStop) <> 0 and\n"
            "stop is NOT NULL then\n"
            "self.operatorList.extend;\n"
            "self.bindValueList.extend;\n"
            "self.operatorList(1) := '<=';\n"
            "self.bindValueList(1) := stop;\n"
            "self.operatorList(2) := '>';\n"
            "self.bindValueList(2) := strt;\n"
            "else\n"
            "if length(strt) > 0 and stop is NULL then\n"
            "self.operatorList(1) := '>';\n"
            "self.bindValueList(1) := strt;\n"
            "elsif length(stop) > 0 and strt is NULL then\n"
            "self.operatorList(1) := '<';\n"
            "self.bindValueList(1) := stop;\n"
            "else\n"
            "self.operatorList.extend;\n"
            "self.bindValueList.extend;\n"
            "self.operatorList(1) := '>';\n"
            "self.bindValueList(1) := strt;\n"
            "self.operatorList(2) := '<';\n"
            "self.bindValueList(2) := stop;\n"
            "end if;\n"
            "end if;\n"
            "if pr.ObjectName = upper('DgCipherIndex$NumberOperator') then\n"
            "self.colType := DgCipherIndex$Const.NumberType;\n"
            "else\n"
            "self.colType := DgCipherIndex$Const.Varchar2Type;\n"
            "end if;\n"
            "for i in self.bindValueList.First .. self.bindValueList.Last "
            "loop\n"
            "self.placeHolderList.extend;\n"
            "self.placeHolderList(i) := ':v' || i; \n"
            "end loop;\n"
            "return;\n"
            "end DgCipherIndex$QueryInfo;\n"
            "end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type DgCipherIndex$PrimaryIndex as object\n"
                "(\n"
                "queryInfo DgCipherIndex$QueryInfo,\n"
                "indexInfo sys.ODCIIndexInfo,\n"
                "constructor function DgCipherIndex$PrimaryIndex\n"
                "(ia  sys.ODCIIndexInfo,\n"
                "env sys.ODCIEnv)\n"
                "return self as result,\n"
                "member procedure initQuery\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex,\n"
                "pr   sys.ODCIPredInfo,\n"
                "qi   sys.ODCIQueryInfo,\n"
                "strt varchar2,\n"
                "stop varchar2),\n"
                "member function getQueryStatement\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex,\n"
                "cipherId number)\n"
                "return varchar2,\n"
                "member function startIndex\n"
                "(self in out DgCipherIndex$PrimaryIndex,\n"
                "cipherId    number,\n"
                "strt        varchar2,\n"
                "stop        varchar2)\n"
                "return number,\n"
                "member function fetchIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex,\n"
                "nrows       number,\n"
                "rids OUT    sys.ODCIRidList)\n"
                "return number,\n"
                "member function closeIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex)\n"
                "return number\n"
                ")\n"
                "not final;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body DgCipherIndex$PrimaryIndex\n"
            "is\nconstructor function DgCipherIndex$PrimaryIndex\n(ia  "
            "sys.ODCIIndexInfo,env sys.ODCIEnv)\n"
            "return self as result\n"
            "is\nbegin\n"
            "self.indexInfo := ia;\nreturn;\nend DgCipherIndex$PrimaryIndex;\n"
            "member function startIndex(self in out "
            "DgCipherIndex$PrimaryIndex,cipherId number,strt varchar2,stop "
            "varchar2) return number\n"
            "is\ni number; cnum integer; stmt varchar2(4000);\n"
            "bvList sys.ODCIVarchar2List;\nbegin\n"
            "stmt := self.getQueryStatement(cipherId);\n"
            "cnum := dbms_sql.open_cursor;\n"
            "dbms_sql.parse(cnum, stmt, dbms_sql.native);\n"
            "bvList := self.queryInfo.bindValueList;\n"
            "for i in bvList.First .. bvList.Last loop\n"
            "dbms_sql.bind_variable(cnum, 'v' || i, bvList(i));\n"
            "end loop;\n"
            "self.queryInfo.cursorNo := cnum;\n"
            "self.queryInfo.howMany := 0;\n"
            "return DgCipherIndex$Const.Success;\n"
            "exception when OTHERS then dbms_sql.close_cursor(cnum); return "
            "DgCipherIndex$Const.Failed; end startIndex;\n"
            "member function fetchIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex,nrows number,rids OUT "
            "sys.ODCIRidList)\n"
            "return number\nis\n"
            "i number; cnum integer;fetched number;\n"
            "rlist   sys.ODCIRidList := sys.ODCIRidList();\n"
            "rid_tab dbms_sql.varchar2_table;\n"
            "begin\n cnum := self.queryInfo.CursorNo;\n if "
            "self.queryInfo.HowMany = 0 then\n"
            "i := dbms_sql.execute(cnum);\n end if;\n "
            "dbms_sql.define_array(cnum, 1, rid_tab, nrows, 1);\n"
            "fetched := dbms_sql.fetch_rows(cnum);\n if fetched = nrows then\n "
            "rlist.extend(fetched);\n"
            "else\n rlist.extend(fetched + 1);\n end if;\n "
            "dbms_sql.column_value(cnum, 1, rid_tab);\n for i in 1..fetched "
            "loop\n"
            "rlist(i) := rid_tab(i);\n end loop;\n self.queryInfo.HowMany := "
            "self.queryInfo.HowMany + fetched;\n rids := rlist;\n"
            "return DgCipherIndex$Const.Success;\n end fetchIndex;\n"
            "member function closeIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex) return number\n"
            "is\n begin\n if self.queryInfo.cursorNo != 0 then\n "
            "dbms_sql.close_cursor(self.queryInfo.cursorNo);\n"
            "end if;\n return DgCipherIndex$Const.Success;\n end closeIndex;\n"
            "member procedure initQuery(self IN OUT "
            "DgCipherIndex$PrimaryIndex,pr   sys.ODCIPredInfo,qi   "
            "sys.ODCIQueryInfo,\n"
            "strt varchar2,stop varchar2)\nis\nbegin\n"
            "self.queryInfo := DgCipherIndex$QueryInfo(pr, strt, stop);\n end "
            "initQuery;\n"
            "member function getQueryStatement (self in out "
            "DgCipherIndex$PrimaryIndex, cipherId number) return varchar2\n"
            "is\nstmt varchar2(4000);\nwhereClause varchar2(4000);\n opList "
            "sys.ODCIVarchar2List;\n"
            "phList      sys.ODCIVarchar2List; indexedColName varchar2(4000);  "
            "begin\n"
            "opList := self.queryInfo.operatorList; phList := "
            "self.queryInfo.placeHolderList;\n"
            "declare func varchar2(4000); begin indexedColName := "
            "self.indexInfo.indexCols(1).colname;\n"
            "whereClause := 'where ' || indexedColName || ' ';\n if opList(1) "
            "= 'between' then\n whereClause := whereClause || "
            "opList(1) || ' ' || 'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || "
            "cipherId || ') ' || opList(2) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(2) || ',' || cipherId || ')'; "
            "elsif opList(1) = 'like' then if "
            "(self.queryInfo.likeExprInfo.allMarkPos.count > 0 and "
            "self.queryInfo.likeExprInfo.allMarkPos(1) != 1) then declare "
            "bindStr varchar2(4000); bindStr2 varchar2(4000); lastChr "
            "varchar2(10); "
            "strLen  number; whileCount number; begin bindStr := "
            "replace(self.queryInfo.bindValueList(1),'%%',''); strLen := "
            "length(bindStr); "
            "lastChr := substr(bindStr, strLen, 1); if strLen = 1 then "
            "bindStr2 := chr(ascii(lastChr) + 1); else "
            "bindStr2 := substr(bindStr, 1, strLen - 1) || chr(ascii(lastChr) "
            "+ 1); end if; "
            "self.queryInfo.bindValueList.extend(1); "
            "self.queryInfo.bindValueList(1) := bindStr; "
            "self.queryInfo.bindValueList(2) := bindStr2; "
            "whereClause := 'where ' || indexedColName || ' >= "
            "PLS_ENCRYPT_B64_ID(:v1,' || cipherId || ')' || ' and ' || "
            "indexedColName || "
            "' < PLS_ENCRYPT_B64_ID(:v2,' || cipherId || ')'; end; elsif "
            "(self.queryInfo.likeExprInfo.singleMarkPos.count > 0 and "
            "self.queryInfo.likeExprInfo.singleMarkPos(1) != 1) then declare "
            "bindStr varchar2(4000); bindStr2 varchar2(4000); "
            "lastChr varchar2(10); strLen  number; blanktmp varchar2(100); "
            "whileCount number; begin bindStr := "
            "replace(self.queryInfo.bindValueList(1),'_',' '); "
            "bindStr2 := replace(self.queryInfo.bindValueList(1),'_','');  "
            "strLen := length(bindStr2); lastChr := substr(bindStr2, strLen, "
            "1); "
            "if strLen = 1 then bindStr2 := chr(ascii(lastChr) + 1); else "
            "bindStr2 := substr(bindStr2, 1, strLen - 1) || chr(ascii(lastChr) "
            "+ 1); "
            "end if; for i in "
            "1..self.queryInfo.likeExprInfo.singleMarkPos.count loop bindStr2 "
            ":= bindStr2 || ' '; "
            "end loop; self.queryInfo.bindValueList.extend(1); "
            "self.queryInfo.bindValueList(1) := bindStr; "
            "self.queryInfo.bindValueList(2) := bindStr2; "
            "whereClause := 'where ' || indexedColName || ' >= "
            "PLS_ENCRYPT_B64_ID(:v1,' || cipherId || ')' || ' and ' || "
            "indexedColName || "
            "' < PLS_ENCRYPT_B64_ID(:v2,' || cipherId || ')'; end;\n "
            "else whereClause := whereClause || opList(1) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || cipherId || ')';\n "
            "end if; elsif opList.last = 1 then if opList(1) = '=' then "
            "whereClause := whereClause || "
            "opList(1) || ' ' || 'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || "
            "cipherId || ')'; else whereClause := whereClause || opList(1) || "
            "' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || cipherId || ')'; end "
            "if; else whereClause := whereClause || opList(1) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || cipherId || ')' || ' "
            "and ' || indexedColName || ' ' || opList(2) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(2) || ',' || cipherId || ')'; "
            "end if; end; stmt := 'select /*+ first_rows index(a) */ rowid,a.* "
            "' || 'from ' || self.indexInfo.indexCols(1).tableSchema || '.' || "
            " self.indexInfo.indexCols(1).tableName || ' a ' || "
            "whereClause ; return stmt; end getQueryStatement; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type pc_index_impl as object\n"
                "(primaryIndex   DgCipherIndex$PrimaryIndex, static function "
                "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
                "return number,\n"
                "static function ODCIIndexCreate(\n"
                "ia       sys.ODCIIndexInfo,\n"
                "params   varchar2,\n"
                "env      sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDrop(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexAlter(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "parms IN OUT varchar2,\n"
                "alter_option number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexTruncate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexInsert(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDelete(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexUpdate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexStart(\n"
                "sctx IN OUT  pc_index_impl,\n"
                "ia           sys.ODCIIndexInfo,\n"
                "pr           sys.ODCIPredInfo,\n"
                "qi           sys.ODCIQueryInfo,\n"
                "strt         varchar2,\n"
                "stop         varchar2,\n"
                "cipherId     number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexFetch(\n"
                "self IN OUT  pc_index_impl,\n"
                "nrows        number,\n"
                "rids OUT     sys.ODCIRidList,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexClose(\n"
                "self IN OUT  pc_index_impl,\n"
                "env sys.ODCIEnv)\n"
                "return number\n"
                ");");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body pc_index_impl is static function "
            "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
            "return number is begin ifclist := "
            "sys.ODCIObjectList(sys.ODCIObject('SYS','ODCIINDEX2')); return "
            "ODCIConst.Success; end ODCIGetInterfaces;\n"
            "static function ODCIIndexCreate(ia       sys.ODCIIndexInfo,params "
            "  varchar2,env      sys.ODCIEnv) return number is "
            "E_INDEX_EXIST_OBJ exception;\n"
            "pragma exception_init(E_INDEX_EXIST_OBJ, -955); begin begin "
            "return ODCIConst.Success; exception when E_INDEX_EXIST_OBJ then "
            "NULL;\n"
            "when OTHERS then raise_application_error(-20900,'Error creating "
            "base index ' || ' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack);\n"
            "end; end ODCIIndexCreate; static function ODCIIndexDrop(ia  "
            "sys.ODCIIndexInfo,env sys.ODCIEnv) return number is "
            "E_INDEX_NOT_EXIST exception;\n"
            "E_TABLE_NOT_EXIST exception; pragma "
            "exception_init(E_INDEX_NOT_EXIST, -01418); pragma "
            "exception_init(E_TABLE_NOT_EXIST, -00942); begin\n"
            "return ODCIConst.Success; exception when E_TABLE_NOT_EXIST then "
            "NULL; when OTHERS then raise_application_error(-20901,'Error "
            "dropping base index ' ||\n"
            "' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack); end ODCIIndexDrop;\n"
            "static function ODCIIndexAlter(ia sys.ODCIIndexInfo, parms IN OUT "
            "varchar2, alter_option number, env sys.ODCIEnv) return number is "
            "begin\n"
            "return ODCIConst.Success; end ODCIIndexAlter; static function "
            "ODCIIndexTruncate(ia  sys.ODCIIndexInfo,env sys.ODCIEnv) return "
            "number\n"
            "is begin return ODCIConst.Success; end ODCIIndexTruncate; static "
            "function ODCIIndexInsert(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,\n"
            "newval varchar2, env    sys.ODCIEnv) return number is begin "
            "return 0; end ODCIIndexInsert;\n"
            "static function ODCIIndexDelete(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,oldval varchar2,env    sys.ODCIEnv) return number is "
            "begin return 0;\n"
            "end ODCIIndexDelete; static function ODCIIndexUpdate(ia     "
            "sys.ODCIIndexInfo,rid    varchar2,oldval varchar2,newval "
            "varchar2,env    sys.ODCIEnv)\n"
            "return number is begin return 0; end ODCIIndexUpdate;\n"
            "static function ODCIIndexStart(sctx IN OUT pc_index_impl,ia "
            "sys.ODCIIndexInfo,pr sys.ODCIPredInfo,qi sys.ODCIQueryInfo,strt "
            "varchar2,\n"
            "stop varchar2,cipherId number,env sys.ODCIEnv) return number is "
            "ret       number; primaryIndex  DgCipherIndex$PrimaryIndex; "
            "begin\n"
            "primaryIndex := DgCipherIndex$PrimaryIndex(ia, env); "
            "primaryIndex.initQuery(pr, qi, strt, stop); ret := "
            "primaryIndex.startIndex(cipherId,strt,stop);\n"
            "sctx := pc_index_impl(primaryIndex); return ODCIConst.Success; "
            "exception when OTHERS then raise; end ODCIIndexStart; member "
            "function ODCIIndexFetch(\n"
            "self IN OUT pc_index_impl, nrows       number, rids OUT    "
            "sys.ODCIRidList, env         sys.ODCIEnv) return number\n"
            "is ret     number; begin ret := "
            "self.primaryIndex.fetchIndex(nrows, rids); return "
            "ODCIConst.Success; end ODCIIndexFetch; member function "
            "ODCIIndexClose(\n"
            "self IN OUT pc_index_impl, env sys.ODCIEnv) return number is ret "
            "number; begin ret := self.primaryIndex.closeIndex; return "
            "ODCIConst.Success;\n"
            "end ODCIIndexClose; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx1_typ1 "
                "for pls_idx1_str(varchar2,number) using pc_index_impl");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx1_typ2 "
                "for pls_idx1_num(varchar2,number) using pc_index_impl");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx1_typ3 "
                "for pls_idx1_date(varchar2,number) using pc_index_impl");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx1_typ1 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx1_typ2 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx1_typ3 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        //
        // create petra domain index type2(add column)
        //
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type DgCipherIndex$PrimaryIndex2 as object\n"
                "(\n"
                "queryInfo DgCipherIndex$QueryInfo,\n"
                "indexInfo sys.ODCIIndexInfo,\n"
                "constructor function DgCipherIndex$PrimaryIndex2\n"
                "(ia  sys.ODCIIndexInfo,\n"
                "env sys.ODCIEnv)\n"
                "return self as result,\n"
                "member procedure initQuery\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex2,\n"
                "pr   sys.ODCIPredInfo,\n"
                "qi   sys.ODCIQueryInfo,\n"
                "strt varchar2,\n"
                "stop varchar2),\n"
                "member function getQueryStatement\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex2,\n"
                "cipherId number)\n"
                "return varchar2,\n"
                "member function startIndex\n"
                "(self in out DgCipherIndex$PrimaryIndex2,\n"
                "cipherId    number,\n"
                "strt        varchar2,\n"
                "stop        varchar2)\n"
                "return number,\n"
                "member function fetchIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex2,\n"
                "nrows       number,\n"
                "rids OUT    sys.ODCIRidList)\n"
                "return number,\n"
                "member function closeIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex2)\n"
                "return number\n"
                ")\n"
                "not final;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body DgCipherIndex$PrimaryIndex2\n"
            "is\nconstructor function DgCipherIndex$PrimaryIndex2\n(ia  "
            "sys.ODCIIndexInfo,env sys.ODCIEnv)\n"
            "return self as result\n"
            "is\nbegin\n"
            "self.indexInfo := ia;\nreturn;\nend DgCipherIndex$PrimaryIndex2;\n"
            "member function startIndex(self in out "
            "DgCipherIndex$PrimaryIndex2,cipherId number,strt varchar2,stop "
            "varchar2) return number\n"
            "is\ni number; cnum integer; stmt varchar2(4000);\n"
            "bvList sys.ODCIVarchar2List;\nbegin\n"
            "stmt := self.getQueryStatement(cipherId);\n"
            "cnum := dbms_sql.open_cursor;\n"
            "dbms_sql.parse(cnum, stmt, dbms_sql.native);\n"
            "bvList := self.queryInfo.bindValueList;\n"
            "for i in bvList.First .. bvList.Last loop\n"
            "dbms_sql.bind_variable(cnum, 'v' || i, bvList(i));\n"
            "end loop;\n"
            "self.queryInfo.cursorNo := cnum;\n"
            "self.queryInfo.howMany := 0;\n"
            "return DgCipherIndex$Const.Success;\n"
            "exception when OTHERS then dbms_sql.close_cursor(cnum); return "
            "DgCipherIndex$Const.Failed; end startIndex;\n"
            "member function fetchIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex2,nrows number,rids OUT "
            "sys.ODCIRidList)\n"
            "return number\nis\n"
            "i number; cnum integer;fetched number;\n"
            "rlist   sys.ODCIRidList := sys.ODCIRidList();\n"
            "rid_tab dbms_sql.varchar2_table;\n"
            "begin\n cnum := self.queryInfo.CursorNo;\n if "
            "self.queryInfo.HowMany = 0 then\n"
            "i := dbms_sql.execute(cnum);\n end if;\n "
            "dbms_sql.define_array(cnum, 1, rid_tab, nrows, 1);\n"
            "fetched := dbms_sql.fetch_rows(cnum);\n if fetched = nrows then\n "
            "rlist.extend(fetched);\n"
            "else\n rlist.extend(fetched + 1);\n end if;\n "
            "dbms_sql.column_value(cnum, 1, rid_tab);\n for i in 1..fetched "
            "loop\n"
            "rlist(i) := rid_tab(i);\n end loop;\n self.queryInfo.HowMany := "
            "self.queryInfo.HowMany + fetched;\n rids := rlist;\n"
            "return DgCipherIndex$Const.Success;\n end fetchIndex;\n"
            "member function closeIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex2) return number\n"
            "is\n begin\n if self.queryInfo.cursorNo != 0 then\n "
            "dbms_sql.close_cursor(self.queryInfo.cursorNo);\n"
            "end if;\n return DgCipherIndex$Const.Success;\n end closeIndex;\n"
            "member procedure initQuery(self IN OUT "
            "DgCipherIndex$PrimaryIndex2,pr   sys.ODCIPredInfo,qi   "
            "sys.ODCIQueryInfo,\n"
            "strt varchar2,stop varchar2)\nis\nbegin\n"
            "self.queryInfo := DgCipherIndex$QueryInfo(pr, strt, stop);\n end "
            "initQuery;\n"
            "member function getQueryStatement(self in out "
            "DgCipherIndex$PrimaryIndex2,cipherId number)\n"
            "return varchar2\nis\nstmt        varchar2(4000);\nwhereClause "
            "varchar2(4000);\nopList      sys.ODCIVarchar2List;\n"
            "phList sys.ODCIVarchar2List;\n indexedColName varchar2(4000);\n "
            "begin\n"
            "opList := self.queryInfo.operatorList;\n phList := "
            "self.queryInfo.placeHolderList;\n"
            "declare\n func varchar2(4000);\n begin\n indexedColName := "
            "self.indexInfo.indexCols(1).colname;\n"
            "whereClause := ' where PLS_OPHUEK_B64(' || indexedColName || ',' "
            "|| cipherId || ',1) ';\n"
            "if opList(1) = 'between' then\n whereClause := whereClause || "
            "opList(1) || ' ' || 'PLS_OPHUEK_B64(' || phList(1) || ',' || "
            "cipherId || ',0) ' ||\n"
            "opList(2) || ' ' || 'PLS_OPHUEK_B64(' || phList(2) || ',' || "
            "cipherId || ',0)';\n"
            "elsif opList(1) = 'like' then if "
            "(self.queryInfo.likeExprInfo.allMarkPos.count > 0 and "
            "self.queryInfo.likeExprInfo.allMarkPos(1) != 1) then\n"
            "declare bindStr varchar2(4000); bindStr2 varchar2(4000); lastChr "
            "varchar2(10); strLen  number; whileCount number;\n"
            "begin\n bindStr := "
            "replace(self.queryInfo.bindValueList(1),'%%',''); strLen := "
            "length(bindStr); lastChr := substr(bindStr, strLen, 1);\n"
            "if strLen = 1 then\n bindStr2 := chr(ascii(lastChr) + 1);\n "
            "else\n bindStr2 := substr(bindStr, 1, strLen - 1) || "
            "chr(ascii(lastChr) + 1);\n"
            "end if;\n self.queryInfo.bindValueList.extend(1);\n "
            "self.queryInfo.bindValueList(1) := bindStr;\n "
            "self.queryInfo.bindValueList(2) := bindStr2;\n"
            "whereClause := 'where ' || 'PLS_OPHUEK_B64(' || indexedColName || "
            "',' || cipherId || ',1) ' || ' >= PLS_OPHUEK_B64(:v1,' || "
            "cipherId || ',0)' || ' and ' || 'PLS_OPHUEK_B64(' || "
            "indexedColName || ',' || cipherId || ',1) ' ||\n"
            "' < PLS_OPHUEK_B64(:v2,' || cipherId || ',0)';\nend; \n elsif "
            "(self.queryInfo.likeExprInfo.singleMarkPos.count > 0 and\n"
            "self.queryInfo.likeExprInfo.singleMarkPos(1) != 1) then\n declare "
            "bindStr varchar2(4000); bindStr2 varchar2(4000); lastChr "
            "varchar2(10);\n"
            "strLen  number; blanktmp varchar2(100); whileCount number;\n "
            "begin\n"
            "bindStr := replace(self.queryInfo.bindValueList(1),'_',' ');\n "
            "bindStr2 := replace(self.queryInfo.bindValueList(1),'_','');\n"
            "strLen := length(bindStr2);\n lastChr := substr(bindStr2, strLen, "
            "1); if strLen = 1 then bindStr2 := chr(ascii(lastChr) + 1);\n"
            "else bindStr2 := substr(bindStr2, 1, strLen - 1) || "
            "chr(ascii(lastChr) + 1); end if; for i in "
            "1..self.queryInfo.likeExprInfo.singleMarkPos.count loop\n"
            "bindStr2 := bindStr2 || ' ';\n end loop; "
            "self.queryInfo.bindValueList.extend(1); "
            "self.queryInfo.bindValueList(1) := bindStr;\n"
            "self.queryInfo.bindValueList(2) := bindStr2; whereClause := "
            "'where ' || 'PLS_OPHUEK_B64(' || indexedColName || ',' || "
            "cipherId || ',1) ' || ' >= PLS_OPHUEK_B64(:v1,' || cipherId || "
            "',0)' ||\n"
            "' and ' || 'PLS_OPHUEK_B64(' || indexedColName || ',' || cipherId "
            "|| ',1) ' || ' < PLS_OPHUEK_B64(:v2,' || cipherId || ',0)'; "
            "end;\n "
            "else whereClause := whereClause || opList(1) || ' ' || "
            "'PLS_OPHUEK_B64(' || phList(1) || ',' || cipherId || ',0)';\n end "
            "if;\n "
            "elsif opList.last = 1 then if opList(1) = '=' then whereClause := "
            "whereClause || opList(1) || ' ' || \n"
            "'PLS_OPHUEK_B64(' || phList(1) || ',' || cipherId || ',0)'; else "
            "whereClause := whereClause || opList(1) || ' ' ||\n"
            "'PLS_OPHUEK_B64(' || phList(1) || ',' || cipherId || ',0)'; end "
            "if; else whereClause := whereClause || opList(1) || ' ' ||\n"
            "'PLS_OPHUEK_B64(' || phList(1) || ',' || cipherId || ',0)' || ' "
            "and ' || 'PLS_OPHUEK_B64(' || indexedColName || ',' || cipherId "
            "|| ',1) ' || opList(2) || ' ' || 'PLS_OPHUEK_B64(' || phList(2) "
            "|| ',' || cipherId || ',0)';\n"
            "end if; end; stmt := 'select /*+ first_rows index(a) */ rowid,a.* "
            "' || 'from ' || self.indexInfo.indexCols(1).tableSchema || '.' "
            "||\n"
            "self.indexInfo.indexCols(1).tableName || ' a ' || whereClause ; "
            "return stmt; end getQueryStatement; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type pc_index_impl2 as object\n"
                "(primaryIndex   DgCipherIndex$PrimaryIndex2, static function "
                "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
                "return number,\n"
                "static function ODCIIndexCreate(\n"
                "ia       sys.ODCIIndexInfo,\n"
                "params   varchar2,\n"
                "env      sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDrop(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexAlter(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "parms IN OUT varchar2,\n"
                "alter_option number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexTruncate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexInsert(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDelete(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexUpdate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexStart(\n"
                "sctx IN OUT  pc_index_impl2,\n"
                "ia           sys.ODCIIndexInfo,\n"
                "pr           sys.ODCIPredInfo,\n"
                "qi           sys.ODCIQueryInfo,\n"
                "strt         varchar2,\n"
                "stop         varchar2,\n"
                "cipherId     number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexFetch(\n"
                "self IN OUT  pc_index_impl2,\n"
                "nrows        number,\n"
                "rids OUT     sys.ODCIRidList,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexClose(\n"
                "self IN OUT  pc_index_impl2,\n"
                "env sys.ODCIEnv)\n"
                "return number\n"
                ");");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body pc_index_impl2 is static function "
            "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
            "return number is begin ifclist := "
            "sys.ODCIObjectList(sys.ODCIObject('SYS','ODCIINDEX2')); return "
            "ODCIConst.Success; end ODCIGetInterfaces;\n"
            "static function ODCIIndexCreate(ia       sys.ODCIIndexInfo,params "
            "  varchar2,env      sys.ODCIEnv) return number is "
            "E_INDEX_EXIST_OBJ exception;\n"
            "pragma exception_init(E_INDEX_EXIST_OBJ, -955); begin begin "
            "return ODCIConst.Success; exception when E_INDEX_EXIST_OBJ then "
            "NULL;\n"
            "when OTHERS then raise_application_error(-20900,'Error creating "
            "base index ' || ' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack);\n"
            "end; end ODCIIndexCreate; static function ODCIIndexDrop(ia  "
            "sys.ODCIIndexInfo,env sys.ODCIEnv) return number is "
            "E_INDEX_NOT_EXIST exception;\n"
            "E_TABLE_NOT_EXIST exception; pragma "
            "exception_init(E_INDEX_NOT_EXIST, -01418); pragma "
            "exception_init(E_TABLE_NOT_EXIST, -00942); begin\n"
            "return ODCIConst.Success; exception when E_TABLE_NOT_EXIST then "
            "NULL; when OTHERS then raise_application_error(-20901,'Error "
            "dropping base index ' ||\n"
            "' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack); end ODCIIndexDrop;\n"
            "static function ODCIIndexAlter(ia sys.ODCIIndexInfo, parms IN OUT "
            "varchar2, alter_option number, env sys.ODCIEnv) return number is "
            "begin\n"
            "return ODCIConst.Success; end ODCIIndexAlter; static function "
            "ODCIIndexTruncate(ia  sys.ODCIIndexInfo,env sys.ODCIEnv) return "
            "number\n"
            "is begin return ODCIConst.Success; end ODCIIndexTruncate; static "
            "function ODCIIndexInsert(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,\n"
            "newval varchar2, env    sys.ODCIEnv) return number is begin "
            "return 0; end ODCIIndexInsert;\n"
            "static function ODCIIndexDelete(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,oldval varchar2,env    sys.ODCIEnv) return number is "
            "begin return 0;\n"
            "end ODCIIndexDelete; static function ODCIIndexUpdate(ia     "
            "sys.ODCIIndexInfo,rid    varchar2,oldval varchar2,newval "
            "varchar2,env    sys.ODCIEnv)\n"
            "return number is begin return 0; end ODCIIndexUpdate;\n"
            "static function ODCIIndexStart(sctx IN OUT pc_index_impl2,ia "
            "sys.ODCIIndexInfo,pr sys.ODCIPredInfo,qi sys.ODCIQueryInfo,strt "
            "varchar2,\n"
            "stop varchar2,cipherId number,env sys.ODCIEnv) return number is "
            "ret       number; primaryIndex  DgCipherIndex$PrimaryIndex2; "
            "begin\n"
            "primaryIndex := DgCipherIndex$PrimaryIndex2(ia, env); "
            "primaryIndex.initQuery(pr, qi, strt, stop); ret := "
            "primaryIndex.startIndex(cipherId,strt,stop);\n"
            "sctx := pc_index_impl2(primaryIndex); return ODCIConst.Success; "
            "exception when OTHERS then raise; end ODCIIndexStart; member "
            "function ODCIIndexFetch(\n"
            "self IN OUT pc_index_impl2, nrows       number, rids OUT    "
            "sys.ODCIRidList, env         sys.ODCIEnv) return number\n"
            "is ret     number; begin ret := "
            "self.primaryIndex.fetchIndex(nrows, rids); return "
            "ODCIConst.Success; end ODCIIndexFetch; member function "
            "ODCIIndexClose(\n"
            "self IN OUT pc_index_impl2, env sys.ODCIEnv) return number is ret "
            "number; begin ret := self.primaryIndex.closeIndex; return "
            "ODCIConst.Success;\n"
            "end ODCIIndexClose; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx2_typ1 "
                "for pls_idx1_str(varchar2,number) using pc_index_impl2");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx2_typ2 "
                "for pls_idx1_num(varchar2,number) using pc_index_impl2");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx2_typ1 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx2_typ2 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        //
        // create domain index type3 (bubun encryption)
        //
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type DgCipherIndex$PrimaryIndex3 as object\n"
                "(\n"
                "queryInfo DgCipherIndex$QueryInfo,\n"
                "indexInfo sys.ODCIIndexInfo,\n"
                "constructor function DgCipherIndex$PrimaryIndex3\n"
                "(ia  sys.ODCIIndexInfo,\n"
                "env sys.ODCIEnv)\n"
                "return self as result,\n"
                "member procedure initQuery\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex3,\n"
                "pr   sys.ODCIPredInfo,\n"
                "qi   sys.ODCIQueryInfo,\n"
                "strt varchar2,\n"
                "stop varchar2),\n"
                "member function getQueryStatement\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex3,\n"
                "cipherId number)\n"
                "return varchar2,\n"
                "member function startIndex\n"
                "(self in out DgCipherIndex$PrimaryIndex3,\n"
                "cipherId    number,\n"
                "strt        varchar2,\n"
                "stop        varchar2)\n"
                "return number,\n"
                "member function fetchIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex3,\n"
                "nrows       number,\n"
                "rids OUT    sys.ODCIRidList)\n"
                "return number,\n"
                "member function closeIndex\n"
                "(self IN OUT DgCipherIndex$PrimaryIndex3)\n"
                "return number\n"
                ")\n"
                "not final;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(
            TextBuf,
            "CREATE OR REPLACE TYPE BODY PETRA.DgCipherIndex$PrimaryIndex3 is "
            "constructor function DgCipherIndex$PrimaryIndex3 (ia "
            "sys.ODCIIndexInfo, env sys.ODCIEnv) "
            " return self as result is begin self.indexInfo := ia; return; end "
            "DgCipherIndex$PrimaryIndex3; "
            " member function startIndex(self in out "
            "DgCipherIndex$PrimaryIndex3, cipherId number, strt varchar2, stop "
            "varchar2) "
            " return number "
            " is i number; cnum integer; stmt varchar2(4000); bvList "
            "sys.ODCIVarchar2List; begin stmt := "
            "self.getQueryStatement(cipherId); "
            " cnum := dbms_sql.open_cursor; dbms_sql.parse(cnum, stmt, "
            "dbms_sql.native); bvList := self.queryInfo.bindValueList; "
            " for i in bvList.First .. bvList.Last loop "
            "dbms_sql.bind_variable(cnum, 'v' || i, bvList(i)); end loop; "
            "self.queryInfo.cursorNo := cnum; "
            " self.queryInfo.howMany := 0; return DgCipherIndex$Const.Success; "
            "exception when OTHERS then dbms_sql.close_cursor(cnum); "
            " return DgCipherIndex$Const.Failed; end startIndex; "
            " member function fetchIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex3, nrows number, rids OUT "
            "sys.ODCIRidList) "
            " return number is i number; cnum integer; fetched number; rlist "
            "sys.ODCIRidList := sys.ODCIRidList(); rid_tab "
            "dbms_sql.varchar2_table; "
            " begin cnum := self.queryInfo.CursorNo; if self.queryInfo.HowMany "
            "= 0 then i := dbms_sql.execute(cnum); end if; "
            " dbms_sql.define_array(cnum, 1, rid_tab, nrows, 1); fetched := "
            "dbms_sql.fetch_rows(cnum); if fetched = nrows then "
            "rlist.extend(fetched); "
            " else rlist.extend(fetched + 1); end if; "
            "dbms_sql.column_value(cnum, 1, rid_tab); for i in 1..fetched loop "
            "rlist(i) := rid_tab(i); "
            " end loop; self.queryInfo.HowMany := self.queryInfo.HowMany + "
            "fetched; rids := rlist; return DgCipherIndex$Const.Success; "
            " end fetchIndex;"
            " member function closeIndex(self IN OUT "
            "DgCipherIndex$PrimaryIndex3) "
            " return number is begin if self.queryInfo.cursorNo != 0 then "
            "dbms_sql.close_cursor(self.queryInfo.cursorNo); "
            " end if; return DgCipherIndex$Const.Success; end closeIndex;"
            " member procedure initQuery(self IN OUT "
            "DgCipherIndex$PrimaryIndex3, pr sys.ODCIPredInfo, qi "
            "sys.ODCIQueryInfo, strt varchar2, stop varchar2) "
            " is begin self.queryInfo := DgCipherIndex$QueryInfo(pr, strt, "
            "stop); end initQuery; "
            " member function getQueryStatement (self in out "
            "DgCipherIndex$PrimaryIndex3, cipherId number) return varchar2 "
            " is stmt varchar2(4000); whereClause varchar2(4000); opList "
            "sys.ODCIVarchar2List; phList sys.ODCIVarchar2List; "
            " indexedColName varchar2(4000); func varchar2(4000); begin opList "
            ":= self.queryInfo.operatorList; phList := "
            "self.queryInfo.placeHolderList; "
            " indexedColName := self.indexInfo.indexCols(1).colname; "
            "whereClause := 'where ' || indexedColName || ' '; if opList(1) = "
            "'between' then "
            " whereClause := whereClause || opList(1) || ' ' || phList(1) || ' "
            "' || opList(2) || ' ' || phList(2); "
            " elsif opList(1) = 'like' then whereClause := whereClause || "
            "opList(1) || ' ' || phList(1); "
            " elsif opList.last = 1 then if opList(1) = '=' then "
            " whereClause := whereClause || opList(1) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || cipherId || ')'; "
            " else whereClause := whereClause || opList(1) || ' ' || "
            "phList(1); end if; else "
            " whereClause := whereClause || opList(1) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(1) || ',' || cipherId || ')' || ' "
            "and ' || indexedColName || ' ' || opList(2) || ' ' || "
            "'PLS_ENCRYPT_B64_ID(' || phList(2) || ',' || cipherId || ')'; "
            " end if; "
            "stmt := 'select /*+ first_rows index(a) */ rowid,a.* ' || 'from ' "
            "|| self.indexInfo.indexCols(1).tableSchema || '.' || "
            "self.indexInfo.indexCols(1).tableName || ' a ' || whereClause ; "
            " return stmt; end getQueryStatement; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace type pc_index_impl3 as object\n"
                "(primaryIndex   DgCipherIndex$PrimaryIndex3, static function "
                "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
                "return number,\n"
                "static function ODCIIndexCreate(\n"
                "ia       sys.ODCIIndexInfo,\n"
                "params   varchar2,\n"
                "env      sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDrop(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexAlter(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "parms IN OUT varchar2,\n"
                "alter_option number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexTruncate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexInsert(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexDelete(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexUpdate(\n"
                "ia           sys.ODCIIndexInfo,\n"
                "rid          varchar2,\n"
                "oldval       varchar2,\n"
                "newval       varchar2,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "static function ODCIIndexStart(\n"
                "sctx IN OUT  pc_index_impl3,\n"
                "ia           sys.ODCIIndexInfo,\n"
                "pr           sys.ODCIPredInfo,\n"
                "qi           sys.ODCIQueryInfo,\n"
                "strt         varchar2,\n"
                "stop         varchar2,\n"
                "cipherId     number,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexFetch(\n"
                "self IN OUT  pc_index_impl3,\n"
                "nrows        number,\n"
                "rids OUT     sys.ODCIRidList,\n"
                "env          sys.ODCIEnv)\n"
                "return number,\n"
                "member function ODCIIndexClose(\n"
                "self IN OUT  pc_index_impl3,\n"
                "env sys.ODCIEnv)\n"
                "return number\n"
                ");");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(
            TextBuf,
            "create or replace type body pc_index_impl3 is static function "
            "ODCIGetInterfaces(ifclist OUT sys.ODCIObjectList)\n"
            "return number is begin ifclist := "
            "sys.ODCIObjectList(sys.ODCIObject('SYS','ODCIINDEX2')); return "
            "ODCIConst.Success; end ODCIGetInterfaces;\n"
            "static function ODCIIndexCreate(ia       sys.ODCIIndexInfo,params "
            "  varchar2,env      sys.ODCIEnv) return number is "
            "E_INDEX_EXIST_OBJ exception;\n"
            "pragma exception_init(E_INDEX_EXIST_OBJ, -955); begin begin "
            "return ODCIConst.Success; exception when E_INDEX_EXIST_OBJ then "
            "NULL;\n"
            "when OTHERS then raise_application_error(-20900,'Error creating "
            "base index ' || ' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack);\n"
            "end; end ODCIIndexCreate; static function ODCIIndexDrop(ia  "
            "sys.ODCIIndexInfo,env sys.ODCIEnv) return number is "
            "E_INDEX_NOT_EXIST exception;\n"
            "E_TABLE_NOT_EXIST exception; pragma "
            "exception_init(E_INDEX_NOT_EXIST, -01418); pragma "
            "exception_init(E_TABLE_NOT_EXIST, -00942); begin\n"
            "return ODCIConst.Success; exception when E_TABLE_NOT_EXIST then "
            "NULL; when OTHERS then raise_application_error(-20901,'Error "
            "dropping base index ' ||\n"
            "' of the domain index' || chr(10) || "
            "dbms_utility.format_error_stack); end ODCIIndexDrop;\n"
            "static function ODCIIndexAlter(ia sys.ODCIIndexInfo, parms IN OUT "
            "varchar2, alter_option number, env sys.ODCIEnv) return number is "
            "begin\n"
            "return ODCIConst.Success; end ODCIIndexAlter; static function "
            "ODCIIndexTruncate(ia  sys.ODCIIndexInfo,env sys.ODCIEnv) return "
            "number\n"
            "is begin return ODCIConst.Success; end ODCIIndexTruncate; static "
            "function ODCIIndexInsert(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,\n"
            "newval varchar2, env    sys.ODCIEnv) return number is begin "
            "return 0; end ODCIIndexInsert;\n"
            "static function ODCIIndexDelete(ia     sys.ODCIIndexInfo,rid    "
            "varchar2,oldval varchar2,env    sys.ODCIEnv) return number is "
            "begin return 0;\n"
            "end ODCIIndexDelete; static function ODCIIndexUpdate(ia     "
            "sys.ODCIIndexInfo,rid    varchar2,oldval varchar2,newval "
            "varchar2,env    sys.ODCIEnv)\n"
            "return number is begin return 0; end ODCIIndexUpdate;\n"
            "static function ODCIIndexStart(sctx IN OUT pc_index_impl3,ia "
            "sys.ODCIIndexInfo,pr sys.ODCIPredInfo,qi sys.ODCIQueryInfo,strt "
            "varchar2,\n"
            "stop varchar2,cipherId number,env sys.ODCIEnv) return number is "
            "ret       number; primaryIndex  DgCipherIndex$PrimaryIndex3; "
            "begin\n"
            "primaryIndex := DgCipherIndex$PrimaryIndex3(ia, env); "
            "primaryIndex.initQuery(pr, qi, strt, stop); ret := "
            "primaryIndex.startIndex(cipherId,strt,stop);\n"
            "sctx := pc_index_impl3(primaryIndex); return ODCIConst.Success; "
            "exception when OTHERS then raise; end ODCIIndexStart; member "
            "function ODCIIndexFetch(\n"
            "self IN OUT pc_index_impl3, nrows       number, rids OUT    "
            "sys.ODCIRidList, env         sys.ODCIEnv) return number\n"
            "is ret     number; begin ret := "
            "self.primaryIndex.fetchIndex(nrows, rids); return "
            "ODCIConst.Success; end ODCIIndexFetch; member function "
            "ODCIIndexClose(\n"
            "self IN OUT pc_index_impl3, env sys.ODCIEnv) return number is ret "
            "number; begin ret := self.primaryIndex.closeIndex; return "
            "ODCIConst.Success;\n"
            "end ODCIIndexClose; end;");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx3_typ1 "
                "for pls_idx1_str(varchar2,number) using pc_index_impl3");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "create or replace indextype pc_idx3_typ2 "
                "for pls_idx1_num(varchar2,number) using pc_index_impl3");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx3_typ1 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        *TextBuf = 0;
        sprintf(TextBuf,
                "grant execute on pc_idx3_typ2 to public with grant option");
        if (saveSqlText() < 0)
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    //
    // Step -2 = DROP Synonym
    //
    StepNo = -2;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_RAW_NM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_RAW_ID_DATE");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW_NM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW_ID");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_DATE");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_RAW_ID_NUM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_B64");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_B64_NM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_B64_ID");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_B64_ID_DATE");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64_NM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64_ID");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64_ID_RAW");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64_ID_DATE");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_B64_ID_NUM");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_CLOB");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_ENCRYPT_BLOB");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_CLOB");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_DECRYPT_BLOB");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    *TextBuf = 0;
    sprintf(TextBuf, "DROP PUBLIC SYNONYM PLS_LCR");
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    //
    // DROP PETRA AGENT USER SQL SCRIPT
    //
    StepNo = -1;
    StmtNo = 0;
    *TextBuf = 0;
    sprintf(TextBuf, "DROP USER %s CASCADE", agent_uid);
    if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);

    return 0;
}
