/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccTds2000ScriptBuilder
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       oracle script builder
 *   Modification history
 *   date                    modification
 --------------------------------------------------------------------

 ********************************************************************/
#include "PccTds2000ScriptBuilder.h"

#include "DgcLinkInfo.h"

extern void check_logger(const char* fmt, ...);

DgcCliConnection* PccTds2000ScriptBuilder::connect(
    dgt_schar* uid, dgt_schar* pw) throw(DgcExcept) {
    //
    // getting the link_info
    //
    DgcLinkInfo dblink(Database->pdb());
    pt_database_link_info* link_info = dblink.getDatabaseLinkInfo(SchemaLink);
    if (!link_info) {
        ATHROWnR(DgcError(SPOS, "getDatabaseLinkInfo failed"), 0);
    }
    if (!uid || *uid == 0) uid = link_info->user_name;
    if (!pw || *pw == 0) pw = link_info->passwd;
    DgcTdsConnection* conn = new DgcTdsConnection();
    dgt_schar link_info_id[33];
    memset(link_info_id, 0, 33);
    sprintf(link_info_id, "%lld", link_info->link_info_id);
    if (conn->connect(nul, link_info_id, uid, pw, link_info->db_name) != 0) {
        DgcExcept* e = EXCEPTnC;
        delete conn;
        RTHROWnR(e, DgcError(SPOS, "connect failed."), 0);
    }
    return conn;
}

dgt_sint32 PccTds2000ScriptBuilder::preparePrivInfo() throw(DgcExcept) {
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
        PrivSqlRows.add();
        PrivSqlRows.next();
        memcpy(PrivSqlRows.data(), privSql, 1024);
        if (TabInfo.enc_type == 0) {
            memset(privSql, 0, 1024);
            sprintf(privSql, "grant %s on %s.%s to %s", privilege, SchemaName,
                    TabInfo.renamed_tab_name, priv_info_tmp->grantee);
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

dgt_sint32 PccTds2000ScriptBuilder::prepareCommentInfo() throw(DgcExcept) {
    return 1;
}

dgt_sint32 PccTds2000ScriptBuilder::prepareObjInfo() throw(DgcExcept) {
    //
    // getting the dependency object in real time
    //
#if 0 /*{{{*/
    dgt_schar soha_text[2048];
    memset(soha_text,0,2048);
    sprintf(soha_text,
            "delete pct_enc_tab_dep_obj where enc_tab_id=%lld",TabInfo.enc_tab_id);
    DgcSqlStmt*     sql_stmt=Database->getStmt(Session,soha_text,strlen(soha_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept*      e=EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
    }
    delete sql_stmt;
    ObjSqlRows.reset();
    ObjTriggerSqlRows.reset();
    dgt_schar       sql_text[2048];
    if (!getConnection()) {
        ATHROWnR(DgcError(SPOS,"getConnection failed."),-1);
    }
    sprintf(sql_text,
            "select /*+ no_merge */ "
            "distinct "
            "owner, "
            "name, "
            "type, "
            "level hlevel "
            "from dba_dependencies start with referenced_owner = upper('%s') "
            "and referenced_name = upper('%s') connect by referenced_owner = prior owner "
            "and referenced_name = prior name "
            "and referenced_type = prior type "
            "order by hlevel",SchemaName, TabInfo.table_name);
    DgcCliStmt*     stmt=Connection->getStmt();
    if (!stmt) {
        ATHROWnR(DgcError(SPOS,"getStmt failed."),-1);
    }
    if (stmt->execute(sql_text,strlen(sql_text),10) < 0) {
        DgcExcept*      e=EXCEPTnC;
        delete stmt;
        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
    }
    DgcMemRows*     rows=stmt->returnRows();
    rows->rewind();
    while(rows->next()) {
        dgt_schar objSql[1024];
        memset(objSql,0,1024);
        dgt_schar	owner[64];
        dgt_schar	name[64];
        dgt_schar	type[32];
        dgt_sint32	hlevel=0;
        memset(owner,0,64);
        memset(name,0,64);
        memset(type,0,32);
        memcpy(owner,(dgt_schar*)rows->getColPtr(1),64);
        memcpy(name,(dgt_schar*)rows->getColPtr(2),64);
        memcpy(type,(dgt_schar*)rows->getColPtr(3),32);
        hlevel=strtol((dgt_schar*)rows->getColPtr(4), 0, 10);
        if (!strcasecmp(type,"SYNONYM")) {
            continue;
        }
        if (!strcasecmp(type,"PACKAGE BODY")) {
            sprintf(objSql,"alter %s %s.%s compile body", type , owner, name);
        } else {
            sprintf(objSql,"alter %s %s.%s compile", type , owner, name);
        } 
        if (TabInfo.init_enc_type > 0) {
            if (!getConnection()) {
                ATHROWnR(DgcError(SPOS,"getConnection failed."),-1);
            }
            if (!strcasecmp(type,"TRIGGER")) {
                dgt_schar sql_text[1024];
                memset(sql_text,0,1024);
                sprintf(sql_text,
                        "select DBMS_METADATA.GET_DDL('TRIGGER','%s','%s') from dual",name,owner);
                DgcCliStmt*     stmt=Connection->getStmt();
                if (!stmt) {
                    ATHROWnR(DgcError(SPOS,"getStmt failed."),-1);
                }
                if (stmt->execute(sql_text,strlen(sql_text),10) < 0) {
                    DgcExcept*      e=EXCEPTnC;
                    delete stmt;
                    RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                }
                DgcMemRows*     rows=stmt->returnRows();
                rows->rewind();
                dgt_schar* ddl_stmt_ptr=0;
                while(rows->next() && (ddl_stmt_ptr=(dgt_schar*)rows->data())) {
                    dgt_schar* tmp_ptr=(dgt_schar*)dg_strcasestr(ddl_stmt_ptr,"ALTER");
                    if (tmp_ptr) {
                        memset(tmp_ptr,0,strlen(tmp_ptr));
                        ObjTriggerSqlRows.add();
                        ObjTriggerSqlRows.next();
                        memcpy(ObjTriggerSqlRows.data(), ddl_stmt_ptr, strlen(ddl_stmt_ptr));
                    }
                }
                delete stmt;
            }
        }
        ObjSqlRows.add();
        ObjSqlRows.next();
        memcpy(ObjSqlRows.data(), objSql, 1024);
        dgt_uint32	object_type=0;
        if (!strcasecmp(type,"FUNCTION")) {
            object_type=1;
        } else if (!strcasecmp(type,"PROCEDURE")) {
            object_type=2;
        } else if (!strcasecmp(type,"TRIGGER")) {
            object_type=3;
        } else if (!strcasecmp(type,"PACKAGE")) {
            object_type=4;
        } else if (!strcasecmp(type,"PACKAGE BODY")) {
            object_type=5;
        } else if (!strcasecmp(type,"VIEW")) {
            object_type=6;
        } else if (!strcasecmp(type,"SYNONYM")) {
            object_type=7;
        }  
        memset(soha_text,0,2048);
        sprintf(soha_text,
                "insert into pct_enc_tab_dep_obj(enc_tab_id,schema_name,object_name,object_type) values(%lld,getnameid('%s'),getnameid('%s'),%d)"
                ,TabInfo.enc_tab_id, owner, name, object_type );
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,soha_text,strlen(soha_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            //	DgcExcept*      e=EXCEPTnC;
            //	delete sql_stmt;
            //	RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
            delete EXCEPTnC;
        }
        delete sql_stmt;
    }
    delete stmt;
    DgcExcept*      e=EXCEPTnC;
    if (e) {
        delete e;
    }
    ObjSqlRows.rewind();
    ObjTriggerSqlRows.rewind();
#endif /*}}}*/
    return 1;
}

dgt_sint32 PccTds2000ScriptBuilder::prepareIdxInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    //
    // Unique Idx Column settting(non enc column) for double view except rowid
    //
    IdxColRows.reset();
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    dgt_sint32 is_identity = 0;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        *TmpBuf = 0;
        if (col_info->is_identity == 1) {
            is_identity = 1;
            IdxColRows.add();
            IdxColRows.next();
            memcpy(IdxColRows.data(), col_info->col_name,
                   strlen(col_info->col_name));
        }
    }
    if (is_identity == 0) {
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
    }
    IdxColRows.rewind();
    return 1;
}

typedef struct {
    dgt_sint64 index_name;
    dgt_sint64 renamed_org_name;
    dgt_sint64 index_owner;
    dgt_uint8 uniqueness;
    dgt_sint64 target_tablespace;
    dgt_uint16 degree;
} pc_type_idx2;

dgt_sint32 PccTds2000ScriptBuilder::prepareIdx2Info() throw(DgcExcept) {
    dgt_schar sql_text[2048];
    IdxSqlRows2.reset();
    IdxSqlRows4.reset();
    IdxSqlRows5.reset();
    IdxSqlRows6.reset();
    IdxSqlRows7.reset();
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
        dgt_schar idx_sql[30000];
        dgt_schar idx_sql2[2048];
        dgt_schar idx_sql3[30000];
        memset(idx_sql, 0, 30000);
        memset(idx_sql2, 0, 2048);
        memset(idx_sql3, 0, 30000);

        memset(sql_text, 0, 2048);
        sprintf(sql_text,
                "select a.index_name, a.renamed_org_name1, b.column_name , "
                "b.renamed_col_name, a.column_position, a.UNIQUENESS, "
                "a.index_type, a.status "
                "from pct_enc_col_index a, pct_enc_column b "
                "where a.enc_col_id = b.enc_col_id "
                "and   a.index_name = %lld "
                "and   a.enc_tab_id = %lld "
                "order by a.column_position ",
                idx_tmp->index_name, TabInfo.enc_tab_id);
        DgcSqlStmt* idx_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (idx_stmt == 0 || idx_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete idx_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
        }
        typedef struct {
            dgt_sint64 index_name;
            dgt_sint64 renamed_index_name;
            dgt_schar col_name[130];
            dgt_schar renamed_col_name[130];
            dgt_uint8 position;
            dgt_uint8 uniqueness;
            dgt_uint8 index_type;
            dgt_uint8 status;
        } idx_type;
        idx_type* idxcol = 0;
        dgt_sint32 seq = 0;
        while ((idxcol = (idx_type*)idx_stmt->fetch())) {
            seq++;
            if (seq == 1) {
                if (idxcol->uniqueness) {
                    if (idxcol->index_type == 1) {
                        sprintf(
                            idx_sql3,
                            "create unique clustered index %s on "
                            "%s.%s_%lld(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            idxcol->col_name);

                        sprintf(
                            idx_sql,
                            "create unique clustered index %s on %s.%s(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, TabInfo.renamed_tab_name,
                            idxcol->col_name);
                    } else {  // when unique and nonclustered index
                        sprintf(
                            idx_sql3,
                            "create unique nonclustered index %s on "
                            "%s.%s_%lld(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            idxcol->col_name);

                        sprintf(
                            idx_sql,
                            "create unique nonclustered index %s on %s.%s(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, TabInfo.renamed_tab_name,
                            idxcol->col_name);
                    }
                } else {  // non unuqueness
                    if (idxcol->index_type == 1) {
                        sprintf(
                            idx_sql3,
                            "create clustered index %s on %s.%s_%lld(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            idxcol->col_name);

                        sprintf(
                            idx_sql, "create clustered index %s on %s.%s(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, TabInfo.renamed_tab_name,
                            idxcol->col_name);
                    } else {  // non unuqueness and nonclustered index
                        sprintf(
                            idx_sql3,
                            "create nonclustered index %s on %s.%s_%lld(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, "petra", TabInfo.enc_tab_id,
                            idxcol->col_name);

                        sprintf(
                            idx_sql,
                            "create nonclustered index %s on %s.%s(%s,",
                            PetraNamePool->getName(idxcol->renamed_index_name),
                            SchemaName, TabInfo.renamed_tab_name,
                            idxcol->col_name);
                    }
                }
            } else {
                strcat(idx_sql3, idxcol->col_name);
                strcat(idx_sql, idxcol->col_name);
                strcat(idx_sql3, ",");
                strcat(idx_sql, ",");
            }
        }
        idx_sql3[strlen(idx_sql3) - 1] = ')';
        idx_sql[strlen(idx_sql) - 1] = ')';
        IdxSqlRows2.add();
        IdxSqlRows2.next();
        memcpy(IdxSqlRows2.data(), idx_sql, strlen(idx_sql));
        IdxSqlRows6.add();
        IdxSqlRows6.next();
        memcpy(IdxSqlRows6.data(), idx_sql3, strlen(idx_sql3));

        dgt_schar idx_sql4[512];
        memset(idx_sql4, 0, 512);
        sprintf(idx_sql4, "sp_rename '%s.%s' , '%s'", TabInfo.renamed_tab_name,
                PetraNamePool->getName(idx_tmp->renamed_org_name),
                PetraNamePool->getName(idx_tmp->index_name));
        IdxSqlRows4.add();
        IdxSqlRows4.next();
        memcpy(IdxSqlRows4.data(), idx_sql4, strlen(idx_sql4));

        // add renamed idx$$ -> orignal idx in reverse step2
        dgt_schar idx_sql7[512];
        memset(idx_sql7, 0, 512);
        sprintf(idx_sql7, "sp_rename '%s.%s' , '%s'", TabInfo.table_name,
                PetraNamePool->getName(idx_tmp->renamed_org_name),
                PetraNamePool->getName(idx_tmp->index_name));
        IdxSqlRows7.add();
        IdxSqlRows7.next();
        memcpy(IdxSqlRows7.data(), idx_sql7, strlen(idx_sql7));

        dgt_schar idx_sql5[512];
        memset(idx_sql5, 0, 512);
        sprintf(idx_sql5, "sp_rename '%s.%s' , '%s_org'", TabInfo.table_name,
                PetraNamePool->getName(idx_tmp->index_name),
                PetraNamePool->getName(idx_tmp->index_name));
        IdxSqlRows5.add();
        IdxSqlRows5.next();
        memcpy(IdxSqlRows5.data(), idx_sql5, strlen(idx_sql5));
    }
    delete idx_stmt;
    DgcExcept* e = EXCEPTnC;
    if (e) {
        delete e;
    }
    IdxSqlRows2.rewind();
    IdxSqlRows4.rewind();
    IdxSqlRows5.rewind();
    IdxSqlRows6.rewind();
    IdxSqlRows7.rewind();
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
    dgt_schar org3[512];
    dgt_schar org4[512];
} pc_type_pk_fk_sql;

dgt_sint32 PccTds2000ScriptBuilder::prepareCtInfo() throw(DgcExcept) {
    dgt_schar sql_text[2048];
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
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
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
        sprintf(st_search.search_condition, "%s",
                PetraNamePool->getNameString(tmp_search->search_condition));
        sprintf(st_search.default_val, "%s",
                PetraNamePool->getNameString(tmp_search->default_val));
        CheckTrgRows.add();
        CheckTrgRows.next();
        memcpy(CheckTrgRows.data(), &st_search, sizeof(check_st));
    }
    delete sql_stmt;
    DgcExcept* e = EXCEPTnC;
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
                    "d.enc_type, d.keep_org_tab_flag, "
                    "a.generated "
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
            dgt_sint32 is_enc_column = 0;
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
                strcat(pkfkSql.enc1, ") ");
                strcat(pkfkSql.org3, ") ");
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
                memcpy(&constraint_name, constraint_name_tmp,
                       sizeof(dgt_sint64));
                sprintf(
                    sql_text,
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
                dgt_uint8 cascade_flag = 0;
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
                    cascade_flag = fk_row->generated;
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
                pkfkSql.org1[strlen(pkfkSql.org1) - 1] = ')';
                pkfkSql.enc1[strlen(pkfkSql.enc1) - 1] = ')';
                if (cascade_flag == 1) {
                    strcat(pkfkSql.org3, " on delete cascade");
                    strcat(pkfkSql.enc1, " on delete cascade");
                } else if (cascade_flag == 2) {
                    strcat(pkfkSql.org3, " on update cascade");
                    strcat(pkfkSql.enc1, " on update cascade");
                } else if (cascade_flag == 3) {
                    strcat(pkfkSql.org3,
                           " on delete cascade on update cascade");
                    strcat(pkfkSql.enc1,
                           " on delete cascade on update cascade");
                }
#if 0
                pkfkSql.org3[strlen(pkfkSql.org3)-1]=0;
                pkfkSql.enc1[strlen(pkfkSql.enc1)-1]=0;
                strcat(pkfkSql.org3,") enable novalidate");
                strcat(pkfkSql.enc1,") enable novalidate");
#endif
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
    dgt_sint64 constraint_name;
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

dgt_sint32 PccTds2000ScriptBuilder::prepareCt2Info() throw(DgcExcept) {
    //
    // new table encryption mode (setting pksql,fksql,checksql)
    //
    DefFkDropSqlRows.reset();   // enc table`s dependeny foreign key(drop)
    DefFkDropSqlRows2.reset();  // non enc table`s dependeny foreign key(drop)
    DefFkCreSqlRows2
        .reset();  // non enc column`s dependeny foreign key in step2
    DefFkCreSqlRows3
        .reset();  // non enc column`s dependeny foreign key in reverse_step2

    CheckSqlRows2.reset();
    CheckSqlRows3.reset();
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
                memcpy(DefFkCreSqlRows2.data(), createSql, strlen(createSql));
                DefFkCreSqlRows3.add();
                DefFkCreSqlRows3.next();
                strcat(createSql2, fk_col);
                strcat(createSql2, refSql2);
                strcat(createSql2, pk_col);
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
    // checksql create (if non encryption column then create checksql)
    //
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select a.constraint_name, b.column_name, b.renamed_col_name, "
            "getname(a.search_condition), b.status "
            "from   pct_enc_col_ct a, pct_enc_column b "
            "where  a.enc_col_id = b.enc_col_id "
            "and    a.enc_tab_id = %lld "
            "and    b.status = 0 "
            "and    a.constraint_type=3 ",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pc_type_checksql2* checksql_tmp;
    while ((checksql_tmp = (pc_type_checksql2*)sql_stmt->fetch())) {
        dgt_schar checksql[512];
        memset(checksql, 0, 512);
        sprintf(checksql, "alter table %s.%s add constraint %s_enc check(%s)",
                SchemaName, TabInfo.renamed_tab_name,
                PetraNamePool->getName(checksql_tmp->constraint_name),
                checksql_tmp->search_condition);
        CheckSqlRows2.add();
        CheckSqlRows2.next();
        memcpy(CheckSqlRows2.data(), checksql, strlen(checksql));
    }
    delete sql_stmt;
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
    memset(sql_text, 0, 2048);
    sprintf(sql_text,
            "select a.constraint_name, b.column_name, b.renamed_col_name, "
            "getname(a.search_condition), b.status "
            "from   pct_enc_col_ct a, pct_enc_column b "
            "where  a.enc_col_id = b.enc_col_id "
            "and    a.enc_tab_id = %lld "
            "and    a.constraint_type=3 ",
            TabInfo.enc_tab_id);
    sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    while ((checksql_tmp = (pc_type_checksql2*)sql_stmt->fetch())) {
        dgt_schar checksql[512];
        memset(checksql, 0, 512);
        sprintf(checksql,
                "alter table %s.%s_%lld add constraint %s_org check (%s)",
                SchemaName, "petra", TabInfo.enc_tab_id,
                PetraNamePool->getName(checksql_tmp->constraint_name),
                checksql_tmp->search_condition);
        CheckSqlRows3.add();
        CheckSqlRows3.next();
        memcpy(CheckSqlRows3.data(), checksql, strlen(checksql));
    }
    delete sql_stmt;
    e = EXCEPTnC;
    if (e) {
        delete e;
    }
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
        sprintf(sql_text,
                "select a.constraint_name, b.column_name, b.renamed_col_name, "
                "b.status, a.position "
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
            dgt_uint64 constraint_name;
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
                sprintf(uniqueSql,
                        "alter table %s.%s add constraint %s_enc unique(%s",
                        SchemaName, TabInfo.renamed_tab_name,
                        PetraNamePool->getName(uniq_tmp->constraint_name),
                        uniq_tmp->column_name);
                sprintf(
                    uniqueSql2,
                    "alter table %s.%s_%lld add constraint %s_org unique(%s",
                    SchemaName, "petra", TabInfo.enc_tab_id,
                    PetraNamePool->getName(uniq_tmp->constraint_name),
                    uniq_tmp->column_name);
            } else {
                strcat(uniqueSql, ", ");
                strcat(uniqueSql, uniq_tmp->column_name);
                strcat(uniqueSql2, ", ");
                strcat(uniqueSql2, uniq_tmp->column_name);
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

    CheckSqlRows2.rewind();
    DefFkDropSqlRows.rewind();
    DefFkDropSqlRows2.rewind();
    DefFkCreSqlRows2.rewind();
    UniqueSqlRows1.rewind();
    UniqueSqlRows2.rewind();
    return 1;
}

dgt_schar* PccTds2000ScriptBuilder::getFname(
    dgt_sint64 enc_col_id, dgt_uint8 fun_type,
    dgt_uint8 instead_of_trigger_flag) throw(DgcExcept) {
    memset(fname, 0, 256);
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
                if (col_info->data_length <= 256) {
                    if (instead_of_trigger_flag) {
                        if (col_info->col_default) {
                            if (!strcasecmp(col_info->data_type, "image") ||
                                !strcasecmp(col_info->data_type, "varbinary") ||
                                !strcasecmp(col_info->data_type, "binary")) {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_bin_b64(@@"
                                        "spid,isnull(I.%s,%s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_b64(@@spid,"
                                        "isnull(I.%s,%s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            }
                        } else {
                            if (!strcasecmp(col_info->data_type, "image") ||
                                !strcasecmp(col_info->data_type, "varbinary") ||
                                !strcasecmp(col_info->data_type, "binary")) {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_bin_b64(@@"
                                        "spid,I.%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_b64(@@spid,I."
                                        "%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            }
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "image") ||
                            !strcasecmp(col_info->data_type, "varbinary") ||
                            !strcasecmp(col_info->data_type, "binary")) {
                            sprintf(fname,
                                    "master.petra.pls_encrypt_bin_b64(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(
                                fname,
                                "master.petra.pls_encrypt_b64(@@spid,%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                        }
                    }
                } else {
                    if (instead_of_trigger_flag) {
                        if (col_info->col_default) {
                            if (!strcasecmp(col_info->data_type, "image") ||
                                !strcasecmp(col_info->data_type, "varbinary") ||
                                !strcasecmp(col_info->data_type, "binary")) {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_bin_b64(@@"
                                        "spid,isnull(I.%s,%s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_b64_max(@@"
                                        "spid,isnull(I.%s,%s),%lld)",
                                        col_info->col_name,
                                        PetraNamePool->getNameString(
                                            col_info->col_default),
                                        col_info->enc_col_id);
                            }
                        } else {
                            if (!strcasecmp(col_info->data_type, "image") ||
                                !strcasecmp(col_info->data_type, "varbinary") ||
                                !strcasecmp(col_info->data_type, "binary")) {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_bin_b64(@@"
                                        "spid,I.%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            } else {
                                sprintf(fname,
                                        "master.petra.pls_encrypt_b64_max(@@"
                                        "spid,I.%s,%lld)",
                                        col_info->col_name,
                                        col_info->enc_col_id);
                            }
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "image") ||
                            !strcasecmp(col_info->data_type, "varbinary") ||
                            !strcasecmp(col_info->data_type, "binary")) {
                            sprintf(fname,
                                    "master.petra.pls_encrypt_bin_b64(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname,
                                    "master.petra.pls_encrypt_b64_max(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    }
                }
            }
        }
    } else if (fun_type == 2) {
        while (ColInfoRows2.next() &&
               (col_info = (pc_type_col_info*)ColInfoRows2.data())) {
            if (col_info->enc_col_id == enc_col_id) {
                if (col_info->data_length <= 256) {
                    if (TabInfo.cast_flag == 0) {
                        if (!strcasecmp(col_info->data_type, "image") ||
                            !strcasecmp(col_info->data_type, "varbinary") ||
                            !strcasecmp(col_info->data_type, "binary")) {
                            sprintf(fname,
                                    "master.petra.pls_decrypt_bin_b64(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(
                                fname,
                                "master.petra.pls_decrypt_b64(@@spid,%s,%lld)",
                                col_info->col_name, col_info->enc_col_id);
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "numeric")) {
                            if (col_info->data_precision == 0) {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_b64(@@"
                                        "spid,%s,%lld) as %s)",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type);
                            } else {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_b64(@@"
                                        "spid,%s,%lld) as %s(%d,%d))",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_precision,
                                        col_info->data_scale);
                            }
                        } else if (!strcasecmp(col_info->data_type, "date") ||
                                   !strcasecmp(col_info->data_type, "bigint") ||
                                   !strcasecmp(col_info->data_type,
                                               "smallint") ||
                                   !strcasecmp(col_info->data_type,
                                               "decimal") ||
                                   !strcasecmp(col_info->data_type,
                                               "smallmoney") ||
                                   !strcasecmp(col_info->data_type, "int") ||
                                   !strcasecmp(col_info->data_type,
                                               "tinyint") ||
                                   !strcasecmp(col_info->data_type, "bit") ||
                                   !strcasecmp(col_info->data_type, "money") ||
                                   !strcasecmp(col_info->data_type, "float") ||
                                   !strcasecmp(col_info->data_type, "real") ||
                                   !strcasecmp(col_info->data_type, "time") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetime") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetime2") ||
                                   !strcasecmp(col_info->data_type,
                                               "smalldatetime") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetimeoffset")) {
                            sprintf(fname,
                                    "cast(master.petra.pls_decrypt_b64(@@spid,%"
                                    "s,%lld) as %s)",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type);
                        } else if (!strcasecmp(col_info->data_type, "image") ||
                                   !strcasecmp(col_info->data_type,
                                               "varbinary") ||
                                   !strcasecmp(col_info->data_type, "binary")) {
                            if (col_info->data_length) {
                                sprintf(
                                    fname,
                                    "cast(master.petra.pls_decrypt_bin_b64(@@"
                                    "spid,%s,%lld) as %s(%d))",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type, col_info->data_length);
                            } else {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_bin_b64("
                                        "@@spid,%s,%lld) as %s)",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type);
                            }
                        } else {
                            sprintf(fname,
                                    "cast(master.petra.pls_decrypt_b64(@@spid,%"
                                    "s,%lld) as %s(%d))",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type, col_info->data_length);
                        }
                    }
                } else {
                    if (TabInfo.cast_flag == 0) {
                        if (!strcasecmp(col_info->data_type, "image") ||
                            !strcasecmp(col_info->data_type, "varbinary") ||
                            !strcasecmp(col_info->data_type, "binary")) {
                            sprintf(fname,
                                    "master.petra.pls_decrypt_bin_b64(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        } else {
                            sprintf(fname,
                                    "master.petra.pls_decrypt_b64_max(@@spid,%"
                                    "s,%lld)",
                                    col_info->col_name, col_info->enc_col_id);
                        }
                    } else {
                        if (!strcasecmp(col_info->data_type, "numeric")) {
                            if (col_info->data_precision == 0) {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_b64_max("
                                        "@@spid,%s,%lld) as %s)",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type);
                            } else {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_b64_max("
                                        "@@spid,%s,%lld) as %s(%d,%d))",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type,
                                        col_info->data_precision,
                                        col_info->data_scale);
                            }
                        } else if (!strcasecmp(col_info->data_type, "date") ||
                                   !strcasecmp(col_info->data_type, "bigint") ||
                                   !strcasecmp(col_info->data_type,
                                               "smallint") ||
                                   !strcasecmp(col_info->data_type,
                                               "decimal") ||
                                   !strcasecmp(col_info->data_type,
                                               "smallmoney") ||
                                   !strcasecmp(col_info->data_type, "int") ||
                                   !strcasecmp(col_info->data_type,
                                               "tinyint") ||
                                   !strcasecmp(col_info->data_type, "bit") ||
                                   !strcasecmp(col_info->data_type, "money") ||
                                   !strcasecmp(col_info->data_type, "float") ||
                                   !strcasecmp(col_info->data_type, "real") ||
                                   !strcasecmp(col_info->data_type, "time") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetime") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetime2") ||
                                   !strcasecmp(col_info->data_type,
                                               "smalldatetime") ||
                                   !strcasecmp(col_info->data_type,
                                               "datetimeoffset")) {
                            sprintf(fname,
                                    "cast(master.petra.pls_decrypt_b64_max(@@"
                                    "spid,%s,%lld) as %s)",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type);
                        } else if (!strcasecmp(col_info->data_type, "image") ||
                                   !strcasecmp(col_info->data_type,
                                               "varbinary") ||
                                   !strcasecmp(col_info->data_type, "binary")) {
                            if (col_info->data_length) {
                                sprintf(
                                    fname,
                                    "cast(master.petra.pls_decrypt_bin_b64(@@"
                                    "spid,%s,%lld) as %s(%d))",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type, col_info->data_length);
                            } else {
                                sprintf(fname,
                                        "cast(master.petra.pls_decrypt_bin_b64("
                                        "@@spid,%s,%lld) as %s)",
                                        col_info->col_name,
                                        col_info->enc_col_id,
                                        col_info->data_type);
                            }
                        } else {
                            sprintf(fname,
                                    "cast(master.petra.pls_decrypt_b64_max(@@"
                                    "spid,%s,%lld) as %s(%d))",
                                    col_info->col_name, col_info->enc_col_id,
                                    col_info->data_type, col_info->data_length);
                        }
                    }
                }
            }
        }
    }
    return fname;
}

#include "PciCryptoIf.h"

dgt_sint32 PccTds2000ScriptBuilder::insteadOfTrigger(
    dgt_sint8 is_final, dgt_sint32 uniq_flag) throw(DgcExcept) {
    //
    // create a instead-of trigger for the view so for any DML on the view
    // to be reflected on the original table.
    // but the original column is still kepted for emergency recovery.
    //
    *TextBuf = 0;
    if (!is_final) {
        sprintf(TextBuf, "create trigger ");
    } else {
        sprintf(TextBuf, "alter trigger ");
    }
    *TmpBuf = 0;
    if (TabInfo.user_view_flag == 1 || IdxColRows.numRows() == 0) {
        sprintf(TmpBuf, "%s.%s_I\non %s.%s\ninstead of insert\nas\nbegin \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.second_view_name);
    } else {
        sprintf(TmpBuf, "%s.%s_I\non %s.%s\ninstead of insert\nas\nbegin \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.second_view_name);
    }
    strcat(TextBuf, TmpBuf);
    strcat(TextBuf, "\n\tset nocount on;\n");

    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\tdeclare @v_%s int;\n", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        if (col_info->status > 0 && col_info->nullable_flag == 0) {
            *TmpBuf = 0;
            if (col_info->col_default == 0) {
                sprintf(TmpBuf,
                        "\n\tselect @v_%s = case when (%s is null) then 0 else "
                        "1 end from INSERTED\n",
                        col_info->col_name, col_info->col_name);
                strcat(TextBuf, TmpBuf);
                *TmpBuf = 0;
                sprintf(TmpBuf,
                        "\n\tif @v_%s = 0\n\tbegin RAISERROR ('%s not null "
                        "constraint violated',15,1,''); return;\n\tend\n",
                        col_info->col_name, col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
    }
    CheckTrgRows.rewind();
    typedef struct {
        dgt_schar search_condition[4000];
        dgt_schar default_val[4000];
    } type_check;
    type_check* tmp_search = 0;
    dgt_sint32 seq = 1;
    while (CheckTrgRows.next() &&
           (tmp_search = (type_check*)CheckTrgRows.data())) {
        *TmpBuf = 0;
        sprintf(TmpBuf, "\n\tdeclare @v_%d int;", seq);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\n\tselect @v_%d = case when (%s) then 0 else 1 end from "
                "INSERTED\n",
                seq, tmp_search->search_condition);
        strcat(TextBuf, TmpBuf);
        sprintf(TmpBuf,
                "\n\tif @v_%d = 0\n\tbegin RAISERROR ('%s check constraint "
                "violated',15,1,''); return;\n\tend\n",
                seq, tmp_search->search_condition);
        strcat(TextBuf, TmpBuf);
        seq++;
    }

    *TmpBuf = 0;
    sprintf(TmpBuf, "\n\tinsert into %s.%s(", SchemaName,
            TabInfo.renamed_tab_name);
    strcat(TextBuf, TmpBuf);
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        if (col_info->status >= 1 && col_info->status < 3 && is_final) continue;
        *TmpBuf = 0;
        sprintf(TmpBuf, "%s,", col_info->col_name);
        strcat(TextBuf, TmpBuf);
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    strcat(TextBuf, ")\n\tselect ");
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            if (col_info->col_default) {
                *TmpBuf = 0;
                sprintf(TmpBuf, "isnull(%s,%s),",
                        getFname(col_info->enc_col_id, 1, 1),
                        PetraNamePool->getNameString(col_info->col_default));
                strcat(TextBuf, TmpBuf);
            } else {
                *TmpBuf = 0;
                sprintf(TmpBuf, "%s,", getFname(col_info->enc_col_id, 1, 1));
                strcat(TextBuf, TmpBuf);
            }
        } else {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
        }
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    sprintf(TmpBuf, "\n\tfrom INSERTED I\nEND");
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    //
    // update trigger
    //
    *TextBuf = 0;
    if (!is_final) {
        sprintf(TextBuf, "create trigger ");
    } else {
        sprintf(TextBuf, "alter trigger ");
    }
    *TmpBuf = 0;
    if (TabInfo.user_view_flag == 1 ||
        (IdxColRows.numRows() == 0 && TabInfo.double_flag == 1)) {
        sprintf(TmpBuf, "%s.%s_U\non %s.%s\ninstead of update\nas\nbegin \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.first_view_name);
    } else {
        sprintf(TmpBuf, "%s.%s_U\non %s.%s\ninstead of update\nas\nbegin \n",
                SchemaName, TabInfo.view_trigger_name, SchemaName,
                TabInfo.second_view_name);
    }
    strcat(TextBuf, TmpBuf);
    strcat(TextBuf, "\n\tset nocount on;\n");

    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status > 0) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "\n\tdeclare @v_%s int;\n", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
        if (col_info->status > 0 && col_info->nullable_flag == 0) {
            *TmpBuf = 0;
            if (col_info->col_default == 0) {
                sprintf(TmpBuf,
                        "\n\tselect @v_%s = case when (%s is null) then 0 else "
                        "1 end from INSERTED\n",
                        col_info->col_name, col_info->col_name);
                strcat(TextBuf, TmpBuf);
                *TmpBuf = 0;
                sprintf(TmpBuf,
                        "\n\tif @v_%s = 0\n\tbegin RAISERROR ('%s not null "
                        "constraint violated',15,1,''); return;\n\tend\n",
                        col_info->col_name, col_info->col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
    }
    CheckTrgRows.rewind();
    seq = 1;
    while (CheckTrgRows.next() &&
           (tmp_search = (type_check*)CheckTrgRows.data())) {
        *TmpBuf = 0;
        sprintf(TmpBuf, "\n\tdeclare @v_%d int;", seq);
        strcat(TextBuf, TmpBuf);
        *TmpBuf = 0;
        sprintf(TmpBuf,
                "\n\tselect @v_%d = case when (%s) then 0 else 1 end from "
                "INSERTED\n",
                seq, tmp_search->search_condition);
        strcat(TextBuf, TmpBuf);
        sprintf(TmpBuf,
                "\n\tif @v_%d = 0\n\tbegin RAISERROR ('%s check constraint "
                "violated',15,1,''); return;\n\tend\n",
                seq, tmp_search->search_condition);
        strcat(TextBuf, TmpBuf);
        seq++;
    }

    *TmpBuf = 0;
    ColInfoRows.rewind();
    sprintf(TmpBuf, "\n\tupdate %s.%s set\n", SchemaName,
            TabInfo.renamed_tab_name);
    strcat(TextBuf, TmpBuf);
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            *TmpBuf = 0;
            if (col_info->col_default) {
                sprintf(TmpBuf, "\n\t\t%s.%s.%s=isnull(%s,%s),", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        getFname(col_info->enc_col_id, 1, 1),
                        PetraNamePool->getNameString(col_info->col_default));
                strcat(TextBuf, TmpBuf);
            } else {  // not dedault column
                sprintf(TmpBuf, "\n\t\t%s.%s.%s=%s,", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        getFname(col_info->enc_col_id, 1, 1));
                strcat(TextBuf, TmpBuf);
            }  // not default column end
        }      // when encrypt column end
        else   // when nomal column
        {
            *TmpBuf = 0;
            if (col_info->col_default) {
                sprintf(TmpBuf, "\n\t\t%s.%s.%s=isnull(I.%s,%s),", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        col_info->col_name,
                        PetraNamePool->getNameString(col_info->col_default));
                strcat(TextBuf, TmpBuf);
            } else {
                sprintf(TmpBuf, "\n\t\t%s.%s.%s=I.%s,", SchemaName,
                        TabInfo.renamed_tab_name, col_info->col_name,
                        col_info->col_name);
                strcat(TextBuf, TmpBuf);
            }

        }  // when nomal column  end
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    sprintf(TmpBuf, "\n\t\tfrom %s.%s R INNER JOIN INSERTED I", SchemaName,
            TabInfo.renamed_tab_name);
    strcat(TextBuf, TmpBuf);
    strcat(TextBuf, "\n\t\ton ");
    *TmpBuf = 0;
    if (IdxColRows.numRows() == 0) {
        strcat(TextBuf, "R.rowid = I.row_id");
    } else {
        IdxColRows.rewind();
        dgt_schar* col_name = 0;
        dgt_sint32 seq = 0;
        while (IdxColRows.next() &&
               (col_name = (dgt_schar*)IdxColRows.data())) {
            seq++;
            *TmpBuf = 0;
            if (seq == 1) {
                sprintf(TmpBuf, "R.%s = I.%s ", col_name, col_name);
            } else {
                sprintf(TmpBuf, "\n\t\t and R.%s = I.%s", col_name, col_name);
            }
            strcat(TextBuf, TmpBuf);
        }
    }
    strcat(TextBuf, "\nend");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
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

dgt_sint32 PccTds2000ScriptBuilder::step1() throw(DgcExcept) {
    //
    //    // new copy table encryption (non add column)
    //
    StepNo = 1;
    StmtNo = 1000;
    *TextBuf = 0;
    dgt_schar sql_text[2048];
    memset(sql_text, 0, 2048);
    // create the copy table (same as original table)
    sprintf(TextBuf, "create table %s.%s (", SchemaName,
            TabInfo.renamed_tab_name);
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        *TmpBuf = 0;
        if (col_info->data_length == 0)
            sprintf(TmpBuf, "%s %s ", col_info->col_name, col_info->data_type);
        else
            sprintf(TmpBuf, "%s %s(%d) ", col_info->col_name,
                    col_info->data_type, col_info->data_length);
        strcat(TextBuf, TmpBuf);

        if (col_info->is_identity == 1) strcat(TextBuf, "identity(1,1) ");

        if (col_info->nullable_flag == 0)
            strcat(TextBuf, "not null ,");
        else
            strcat(TextBuf, "null ,");
    }
    TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last "," off
    *TmpBuf = 0;
    if (IdxColRows.numRows() == 0) {
        sprintf(TmpBuf, ",rowid bigint identity(1,1))");
        strcat(TextBuf, TmpBuf);
    } else {
        sprintf(TmpBuf, ")");
        strcat(TextBuf, TmpBuf);
    }
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
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
            else if (!strcasecmp(col_info->data_type, "TINYINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "SMALLINT"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "NUMERIC"))
                enc_len += (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type, "DATETIME"))
                enc_len += 14;
            else if (!strcasecmp(col_info->data_type, "IMAGE"))
                enc_len += 2048;
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
            *TextBuf = 0;
            sprintf(TextBuf, "alter table %s.%s alter column %s nvarchar(%d)",
                    SchemaName, TabInfo.renamed_tab_name, col_info->col_name,
                    enc_len);
            if (col_info->nullable_flag == 0)
                strcat(TextBuf, " not null ");
            else
                strcat(TextBuf, " null ");
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }
    *TextBuf = 0;
    StmtNo = 3000;
    //
    // insert encrypt data
    //
    StmtNo = 6000;
    *TmpBuf = 0;
    sprintf(TmpBuf, "insert into %s.%s(", SchemaName, TabInfo.renamed_tab_name);
    strcat(TextBuf, TmpBuf);
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        *TmpBuf = 0;
        sprintf(TmpBuf, "%s,", col_info->col_name);
        strcat(TextBuf, TmpBuf);
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    strcat(TextBuf, ")\n\tselect ");
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        if (col_info->status >= 1 && col_info->status < 3) {
            *TmpBuf = 0;
            sprintf(TmpBuf, " %s,", getFname(col_info->enc_col_id, 1, 0));
            strcat(TextBuf, TmpBuf);
            *TmpBuf = 0;
        } else if (col_info->col_default) {
            *TmpBuf = 0;
            sprintf(TmpBuf, "isnull(%s,%s),", col_info->col_name,
                    PetraNamePool->getNameString(col_info->col_default));
            strcat(TextBuf, TmpBuf);
        } else {
            *TmpBuf = 0;
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
        }
    }
    ColInfoRows.rewind();
    TextBuf[strlen(TextBuf) - 1] = 0;
    *TmpBuf = 0;
    sprintf(TmpBuf, " from %s.%s ", SchemaName, TabInfo.table_name);
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
#if 0
    *TextBuf=0;
    sprintf(TextBuf,"commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
    }
#endif

    //
    // Create the table`s original index
    //
    StmtNo = 7000;
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows2.rewind();
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

    //
    // make check constraint that non encrypt column
    //
    StmtNo = 7500;
    *TextBuf = 0;
    *TmpBuf = 0;
    CheckSqlRows2.rewind();
    dgt_schar* cksql = 0;
    while (CheckSqlRows2.next() && (cksql = (dgt_schar*)CheckSqlRows2.data())) {
        if (cksql && strlen(cksql) > 2) {
            strcpy(TextBuf, cksql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
            }
        }
    }

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
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::step2() throw(DgcExcept) {
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

    //
    // rename orginal table
    //
    StmtNo = 6000;
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "sp_rename '%s.%s' , '%s'", SchemaName, TabInfo.table_name,
            TabInfo.org_renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }

    //
    // create view or rename encryption table -> original table name
    //
    StmtNo = 7000;
    *TextBuf = 0;
    *TmpBuf = 0;
    pc_type_col_info* col_info = 0;
    if (TabInfo.enc_type == 0) {
        if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
            sprintf(TextBuf, "create view %s.%s as\n select ", SchemaName,
                    TabInfo.first_view_name);
            ColInfoRows.rewind();
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
                                getFname(col_info->enc_col_id, 2),
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
            sprintf(TextBuf, "create view %s.%s as\n select ", SchemaName,
                    TabInfo.second_view_name);
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
            sprintf(TextBuf, "create view %s.%s as\n select ", SchemaName,
                    TabInfo.second_view_name);
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
                                getFname(col_info->enc_col_id, 2),
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
        sprintf(TextBuf, "sp_rename '%s.%s' , '%s'", SchemaName,
                TabInfo.renamed_tab_name, TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
    }
    StmtNo = 8000;
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type != 0 && TabInfo.user_view_flag == 1) {
        sprintf(TextBuf, "create view %s.%s as\n select ", SchemaName,
                TabInfo.first_view_name);
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
                    sprintf(TmpBuf, "%s %s,", getFname(col_info->enc_col_id, 2),
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
    *TextBuf = 0;
    *TmpBuf = 0;
    if (TabInfo.enc_type == 0) {
        if (insteadOfTrigger(0) < 0) {
            ATHROWnR(DgcError(SPOS, "insteadOfTigger failed."), -1);
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
    // Drop The Original table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    StmtNo = 14000;
    if (TabInfo.keep_org_tab_flag >= 1) {
#if 1
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
#endif
    } else {
        sprintf(TextBuf, "drop table %s.%s ", SchemaName,
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
        while (PkSqlRows.next() && (sql_row = (pkfk_sql*)PkSqlRows.data())) {
            *TextBuf = 0;
            if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
                strcpy(TextBuf, sql_row->enc2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
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
#if 0
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo=17000;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjTriggerSqlRows.next()) {
            *TextBuf=0;
            sprintf(TextBuf,(dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo=18000;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjSqlRows.next()) {
            *TextBuf=0;
            strcat(TextBuf,(dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }






    //
    // keep_org_tab_flag  == 1
    // for supporting manual script(restore and instead of trigger)
    //
    if (TabInfo.keep_org_tab_flag >= 1) {
        StepNo=10;
        StmtNo=-10;
        // restore flag
        *TextBuf=0;
        *TmpBuf=0;
        if (TabInfo.enc_type == 0) {
            *TextBuf=0;
            sprintf(TextBuf,"drop view %s.%s",SchemaName,TabInfo.second_view_name);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
            if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
                *TextBuf=0;
                sprintf(TextBuf,"drop view %s.%s",SchemaName,TabInfo.first_view_name);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
            }
        } 
        *TextBuf=0;
        *TmpBuf=0;
        sprintf(TextBuf,"alter table %s.%s rename to %s",SchemaName,TabInfo.org_renamed_tab_name,TabInfo.table_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        }
        //
        //  encrypt completion script(modify instead of trigger)
        //
        StepNo=10;
        StmtNo=0;
        if (TabInfo.keep_org_tab_flag == 2) {
            TabInfo.keep_org_tab_flag=0;
            if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
                if (insteadOfTrigger(1)) {
                    ATHROWnR(DgcError(SPOS,"insteadOfTigger failed."),-1);
                }
            }
        }
        *TmpBuf=0;
        *TextBuf=0;
        if (!strcasecmp(DbVersion,"9i")) sprintf(TextBuf,"drop table %s.%s",SchemaName,TabInfo.org_renamed_tab_name);
        else sprintf(TextBuf,"drop table %s.%s purge",SchemaName,TabInfo.org_renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        }
    }
#endif

    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::reverse_step1() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //
    //
    StepNo = -1;
    //
    // drop enc table & rename original table
    //
    StmtNo = -1000;
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "drop table %s.%s", SchemaName, TabInfo.renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "drop table %s.%s", SchemaName,
            TabInfo.org_renamed_tab_name);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::reverse_step2() throw(DgcExcept) {
    //
    // new copy table encryption (non add column)
    //
    // create the copy table (same as original table)
    //
    StepNo = -2;
    StmtNo = -17000;
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "CREATE TABLE %s.%s_%lld (", SchemaName, "petra",
            TabInfo.enc_tab_id);
    // here! create table script input, be original table
    ColInfoRows.rewind();
    pc_type_col_info* col_info;
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        *TmpBuf = 0;
        if (col_info->data_length == 0)
            sprintf(TmpBuf, "%s %s ", col_info->col_name, col_info->data_type);
        else
            sprintf(TmpBuf, "%s %s(%d) ", col_info->col_name,
                    col_info->data_type, col_info->data_length);
        strcat(TextBuf, TmpBuf);

        if (col_info->is_identity == 1) strcat(TextBuf, "identity(1,1) ");

        if (col_info->nullable_flag == 0)
            strcat(TextBuf, "not null ,");
        else
            strcat(TextBuf, "null ,");
    }
    TextBuf[strlen(TextBuf) - 1] = 0;  // cut the last "," off
    *TmpBuf = 0;
    sprintf(TmpBuf, ")");
    strcat(TextBuf, TmpBuf);
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
    }
    // insert decryption (parallel insert)
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    ColInfoRows.rewind();
    sprintf(TmpBuf, "insert into %s.%s_%lld( ", SchemaName, "petra",
            TabInfo.enc_tab_id);
    strcat(TextBuf, TmpBuf);
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        *TmpBuf = 0;
        sprintf(TmpBuf, "%s,", col_info->col_name);
        strcat(TextBuf, TmpBuf);
    }
    TextBuf[strlen(TextBuf) - 1] = 0;
    strcat(TextBuf, ") \nselect ");
    ColInfoRows.rewind();
    while (ColInfoRows.next() &&
           (col_info = (pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 5) continue;
        if (col_info->is_identity == 1) continue;
        *TmpBuf = 0;
        if (col_info->status == 1) {
            sprintf(TmpBuf, "%s,", getFname(col_info->enc_col_id, 2));
            strcat(TextBuf, TmpBuf);
        } else {
            sprintf(TmpBuf, "%s,", col_info->col_name);
            strcat(TextBuf, TmpBuf);
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
#if 0
    *TextBuf=0;
    sprintf(TextBuf,"commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
    }
#endif

    //
    // Create the table`s original index
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    IdxSqlRows6.rewind();
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
    // make check constraint
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    CheckSqlRows3.rewind();
    dgt_schar* cksql = 0;
    while (CheckSqlRows3.next() && (cksql = (dgt_schar*)CheckSqlRows3.data())) {
        if (cksql && strlen(cksql) > 2) {
            strcpy(TextBuf, cksql);
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
    //
    // drop enc table & rename original table
    //
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
#if 1
        sprintf(TextBuf, "sp_rename '%s.%s' , '%s'", SchemaName,
                TabInfo.table_name, TabInfo.renamed_tab_name);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS, "saveSqlText failed."), -1);
        }
#endif
    }
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "sp_rename '%s.%s_%lld' , '%s'", SchemaName, "petra",
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
#if 0 /*{{{*/
    //
    // encrypt tables`s dependency object complie script
    //
    *TextBuf=0;
    *TmpBuf=0;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjTriggerSqlRows.next()) {
            *TextBuf=0;
            sprintf(TextBuf,(dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    *TextBuf=0;
    *TmpBuf=0;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjSqlRows.next()) {
            *TextBuf=0;
            strcat(TextBuf,(dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }
#endif /*}}}*/

    //
    // drop enc table & rename original table
    //
    *TextBuf = 0;
    *TmpBuf = 0;
    sprintf(TextBuf, "drop table %s.%s", SchemaName, TabInfo.renamed_tab_name);
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
    IdxSqlRows7.rewind();
    dgt_schar* rename_idx = 0;
    while (IdxSqlRows7.next() &&
           (rename_idx = (dgt_schar*)IdxSqlRows7.data())) {
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

dgt_sint32 PccTds2000ScriptBuilder::addColStep() throw(DgcExcept) {
    //
    // alter table modify column
    //
#if 0 /*{{{*/
    StepNo=3;
    StmtNo=1000;
    *TextBuf=0;
    *TmpBuf=0;
    ColInfoRows.rewind();
    pc_type_col_info* col_info=0;
    while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            dgt_sint32      enc_len = 0;
            if (!strcasecmp(col_info->data_type,"NUMBER")) enc_len = (col_info->data_precision + 2);
            else if (!strcasecmp(col_info->data_type,"DATE") || !strcasecmp(col_info->data_type,"TIMESTAMP")) enc_len = 14;
            else if (col_info->multi_byte_flag) enc_len = col_info->data_length * 3;
            else enc_len = col_info->data_length;
            PCI_Context     ctx;
            PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type, col_info->enc_mode,
                    col_info->iv_type, col_info->n2n_flag, col_info->b64_txt_enc_flag,
                    col_info->enc_start_pos, col_info->enc_length);
            enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
            if (col_info->index_type == 1) {
                enc_len += PCI_ophuekLength(col_info->data_length, PCI_SRC_TYPE_CHAR, 1);
                enc_len += 4;
            }
            if (!strcasecmp(col_info->data_type,"NCHAR") ||
                    !strcasecmp(col_info->data_type,"NVARCHAR2")) {
                enc_len = enc_len * 3;
            }
            *TextBuf=0;
            if (!strcasecmp(col_info->data_type,"CLOB") ||  !strcasecmp(col_info->data_type,"BLOB")) {
                if (TabInfo.enc_type == 0) {
                    sprintf(TextBuf,"alter table %s.%s modify %s BLOB", SchemaName, TabInfo.renamed_tab_name, col_info->col_name);
                } else {
                    sprintf(TextBuf,"alter table %s.%s modify %s BLOB", SchemaName, TabInfo.table_name, col_info->col_name);
                }
            } else if (!strcasecmp(col_info->data_type,"LONG") || !strcasecmp(col_info->data_type,"LONG RAW")) {
                if (TabInfo.enc_type == 0) {
                    sprintf(TextBuf,"alter table %s.%s modify %s BLOB", SchemaName, TabInfo.renamed_tab_name, col_info->col_name);
                } else {
                    sprintf(TextBuf,"alter table %s.%s modify %s BLOB", SchemaName, TabInfo.table_name, col_info->col_name);
                }
            } else {
                if (col_info->b64_txt_enc_flag) {
                    if (TabInfo.enc_type == 0) {
                        sprintf(TextBuf,"alter table %s.%s modify %s varchar2(%d)",
                                SchemaName, TabInfo.renamed_tab_name, col_info->col_name, enc_len);
                    } else {
                        sprintf(TextBuf,"alter table %s.%s modify %s varchar2(%d)",
                                SchemaName, TabInfo.table_name, col_info->col_name, enc_len);
                    }
                } else {
                    if (TabInfo.enc_type == 0) {
                        sprintf(TextBuf,"alter table %s.%s modify %s raw(%d)",
                                SchemaName, TabInfo.renamed_tab_name, col_info->col_name, enc_len);
                    } else {
                        sprintf(TextBuf,"alter table %s.%s modify %s raw(%d)",
                                SchemaName, TabInfo.table_name, col_info->col_name, enc_len);
                    }
                }
            }
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }
    //
    // encrypting data without exclusive access
    //
    *TextBuf=0;
    *TmpBuf=0;
    StmtNo=2000;
    sprintf(TextBuf,"declare\n   urows number := 0;\n   v_rowid rowid;\n");
    ColInfoRows.rewind();
    while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            *TmpBuf=0;
            if (!strcasecmp(col_info->data_type,"number")) {
                if (col_info->data_precision == 0) {
                    sprintf(TmpBuf,"   v_%s %s;\n",col_info->col_name,col_info->data_type);
                } else {
                    sprintf(TmpBuf,"   v_%s %s(%d,%d);\n",col_info->col_name,col_info->data_type,
                            col_info->data_precision,col_info->data_scale);
                }
            } else if (!strcasecmp(col_info->data_type,"date")) {
                sprintf(TmpBuf,"   v_%s %s;\n",col_info->col_name,col_info->data_type);
            } else if (!strcasecmp(col_info->data_type,"raw")) {
                sprintf(TmpBuf,"   v_%s %s(%u);\n",col_info->col_name,col_info->data_type,col_info->data_length);
            } else {
                sprintf(TmpBuf,"   v_%s varchar2(%u);\n",col_info->col_name,col_info->data_length);
            }
            strcat(TextBuf,TmpBuf);
        }
    }
    *TmpBuf=0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf,"   cursor c1 is\n      select rowid from %s.%s;\n",SchemaName, TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf,"   cursor c1 is\n      select rowid from %s.%s;\n",SchemaName, TabInfo.table_name);
    }
    strcat(TextBuf,TmpBuf);
    strcat(TextBuf,"\nbegin\n   open c1;\n   loop\n\tfetch c1 into v_rowid;\n\texit when c1%NOTFOUND;\n");
    *TmpBuf=0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf,"\tupdate %s.%s set",SchemaName, TabInfo.renamed_tab_name);
    } else {
        sprintf(TmpBuf,"\tupdate %s.%s set",SchemaName, TabInfo.table_name);
    }
    strcat(TextBuf,TmpBuf);
    ColInfoRows.rewind();
    while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 2) {
            dgt_sint32 idx_flag=col_info->index_type;
            *TmpBuf=0;
            sprintf(TmpBuf,"\n\t\t%s=%s,",col_info->col_name,getFname(col_info->enc_col_id,1));
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
    *TextBuf=0;
    *TmpBuf=0;
    StmtNo=3000;
    if (TabInfo.enc_type == 0) {
        if (IdxColRows.numRows() == 0) {
            sprintf(TextBuf,"create or replace view %s.%s as\n select ",SchemaName,TabInfo.first_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info=0;
            while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf=0;
                if (col_info->status >= 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf=0;
                        sprintf(TmpBuf,"%s %s,",col_info->col_name, col_info->col_name);
                        strcat(TextBuf,TmpBuf);
                    } else {
                        *TmpBuf=0;
                        sprintf(TmpBuf,"%s %s,", getFname(col_info->enc_col_id,2),col_info->col_name);
                        strcat(TextBuf,TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf,"%s,",col_info->col_name);
                    strcat(TextBuf,TmpBuf);
                }
            }
            strcat(TextBuf,"rowid row_id");
            *TmpBuf=0;
            sprintf(TmpBuf,"\n   from %s.%s", SchemaName, TabInfo.renamed_tab_name);
            strcat(TextBuf,TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
            *TextBuf=0;
            sprintf(TextBuf,"create or replace view %s.%s as\n select ",SchemaName, TabInfo.second_view_name);
            ColInfoRows.rewind();
            while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf=0;
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
            }
            TextBuf[strlen(TextBuf)-1]=0;   // cut the last ";" off
            *TmpBuf=0;
            sprintf(TmpBuf," from %s.%s",SchemaName, TabInfo.first_view_name);
            strcat(TextBuf,TmpBuf);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        } else {
            sprintf(TextBuf,"create or replace view %s.%s as\n select ",SchemaName,TabInfo.second_view_name);
            ColInfoRows.rewind();
            pc_type_col_info* col_info=0;
            while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                *TmpBuf=0;
                if (col_info->status >= 1) {
                    if (col_info->cipher_type == 4) {
                        *TmpBuf=0;
                        sprintf(TmpBuf,"%s %s,",col_info->col_name, col_info->col_name);
                        strcat(TextBuf,TmpBuf);
                    } else {
                        *TmpBuf=0;
                        sprintf(TmpBuf,"%s %s,", getFname(col_info->enc_col_id,2), col_info->col_name);
                        strcat(TextBuf,TmpBuf);
                    }
                } else {
                    sprintf(TmpBuf,"%s,",col_info->col_name);
                    strcat(TextBuf,TmpBuf);
                }
            }
            TextBuf[strlen(TextBuf)-1]=0;
            IdxColRows.rewind();
            if (IdxColRows.numRows() == 0) {
                strcat(TextBuf,",rowid row_id");
                *TmpBuf=0;
                sprintf(TmpBuf,"\n   from %s.%s", SchemaName,TabInfo.renamed_tab_name);
                strcat(TextBuf,TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
            } else {
                *TmpBuf=0;
                sprintf(TmpBuf,"\n   from %s.%s", SchemaName,TabInfo.renamed_tab_name);
                strcat(TextBuf,TmpBuf);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
            }
        }
    }
    //
    // if plugin view -> create the instead of trigger
    //
    *TmpBuf=0;
    *TextBuf=0;
    StmtNo=4000;
    dgt_schar sql_text[2048];
    memset(sql_text,0,2048);
    sprintf(sql_text,"select count() from pct_enc_col_index where enc_tab_id = %lld and uniqueness=1 and column_position > 1",TabInfo.enc_tab_id);
    DgcSqlStmt* count_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
    if (count_stmt == 0 || count_stmt->execute() < 0) {
        DgcExcept*      e=EXCEPTnC;
        delete count_stmt;
        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
    }
    dgt_sint64* count_tmp=0;
    dgt_sint64  count=0;
    if ((count_tmp=(dgt_sint64*)count_stmt->fetch())) {
        memcpy(&count,count_tmp,sizeof(dgt_sint64));
    }
    delete count_stmt;
    dgt_sint32 uniq_idx_flag=0;
    if (count) {
        uniq_idx_flag=1;
    } else {
        memset(sql_text,0,2048);
        sprintf(sql_text,"select count() from pct_enc_col_ct where enc_tab_id = %lld and constraint_type=1 and position > 1",TabInfo.enc_tab_id);
        DgcSqlStmt* count_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (count_stmt == 0 || count_stmt->execute() < 0) {
            DgcExcept*      e=EXCEPTnC;
            delete count_stmt;
            RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64* count_tmp=0;
        if ((count_tmp=(dgt_sint64*)count_stmt->fetch())) {
            memcpy(&count,count_tmp,sizeof(dgt_sint64));
        }
        delete count_stmt;
        if (count) {
            uniq_idx_flag=1;
        }
    }
    if (TabInfo.user_view_flag == 1 || TabInfo.enc_type == 0) {
        if (insteadOfTrigger(1,uniq_idx_flag)) {
            ATHROWnR(DgcError(SPOS,"insteadOfTigger failed."),-1);
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
    memset(idx_sql,0,512);
    memset(normal_sql,0,512);
    memset(idx_sql2,0,512);
    memset(normal_sql2,0,512);
    memset(sql_text,0,2048);
    memset(idx_col_idx1,0,512);
    memset(idx_col_idx2,0,512);
    StmtNo=5000;
    *TmpBuf=0;
    *TextBuf=0;
    sprintf(sql_text,
            "select a.enc_col_id, b.renamed_col_name, b.data_type, a.index_type, b.domain_index_name, b.fbi_index_name, "
            "b.normal_index_name, a.tablespace_name, a.normal_idx_flag, b.column_name "
            "from pct_enc_index a, pct_enc_column b, pct_enc_table c "
            "where a.enc_col_id = b.enc_col_id "
            "and   b.enc_tab_id = c.enc_tab_id "
            "and   b.enc_tab_id = %lld"
            "and   b.status = 2",TabInfo.enc_tab_id);

    DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept*      e=EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
    }
    pc_type_index_row*  idx_info=0;
    while ((idx_info=(pc_type_index_row*)sql_stmt->fetch())) {
        if (idx_info->index_type == 1) {
            if (TabInfo.enc_type == 0 && idx_info->normal_idx_flag ==1) {
                if (!strcasecmp(idx_info->data_type,"NUMBER")) {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP2",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.renamed_tab_name,idx_info->index_col_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type,"DATE") || !strcasecmp(idx_info->data_type,"TIMESTAMP")) {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP3",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.renamed_tab_name,idx_info->index_col_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP1",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.renamed_tab_name,idx_info->index_col_name,
                            AgentName);
                }
            } else if (TabInfo.enc_type == 1 && idx_info->normal_idx_flag ==1){
                if (!strcasecmp(idx_info->data_type,"NUMBER")) {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP2",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.table_name,idx_info->index_col_name,
                            AgentName);
                } else if (!strcasecmp(idx_info->data_type,"DATE") || !strcasecmp(idx_info->data_type,"TIMESTAMP")) {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP3",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.table_name,idx_info->index_col_name,
                            AgentName);
                } else {
                    sprintf(idx_sql,"create index %s.%s on %s.%s(%s) indextype is %s.PC_IDX1_TYP1",
                            SchemaName,idx_info->domain_index_name,
                            SchemaName,TabInfo.table_name,idx_info->index_col_name,
                            AgentName);
                }
            }
            sprintf(TextBuf,idx_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
            *TextBuf=0;

            // create domain index`s normal index
            // if copy table encryption && enc column has normal index (position) do not create index
            // because already generated normal index column
            //
            // getting the index_name in table
            //
            dgt_schar sql_text[2048];
            memset(sql_text,0,2048);
            sprintf(sql_text,"select count() from pct_enc_col_index where enc_col_id = %lld and column_position=1",idx_info->enc_col_id);
            DgcSqlStmt* count_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
            if (count_stmt == 0 || count_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete count_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
            }
            dgt_sint64* count_tmp=0;
            dgt_sint64  count=0;
            if ((count_tmp=(dgt_sint64*)count_stmt->fetch())) {
                memcpy(&count,count_tmp,sizeof(dgt_sint64));
            }
            if (count == 0) {
                if (TabInfo.partitioned) {
                    sprintf(idx_col_idx1,"create index %s.%s on %s.%s(%s) tablespace %s parallel %d nologging local",
                            SchemaName,idx_info->fbi_index_name,
                            SchemaName,TabInfo.renamed_tab_name,
                            idx_info->index_col_name,idx_info->tablespace_name,
                            ParallelDegree);
                } else {
                    sprintf(idx_col_idx1,"create index %s.%s on %s.%s(%s) tablespace %s parallel %d nologging",
                            SchemaName,idx_info->fbi_index_name,
                            SchemaName,TabInfo.renamed_tab_name,
                            idx_info->index_col_name,idx_info->tablespace_name,
                            ParallelDegree);
                }
                sprintf(TextBuf,idx_col_idx1);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
                *TextBuf=0;
                sprintf(idx_col_idx2,"alter index %s.%s parallel %d logging",
                        SchemaName,idx_info->fbi_index_name,
                        TabInfo.degree);
                sprintf(TextBuf,idx_col_idx2);
                if (saveSqlText() < 0) {
                    ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
                *TextBuf=0;

            }
            delete count_stmt;
            delete EXCEPTnC;
        }
    }
    DgcExcept* e=EXCEPTnC;
    if (e) {
        delete e;
    }
    delete sql_stmt;
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo=6000;
    ObjTriggerSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjTriggerSqlRows.next()) {
            *TextBuf=0;
            sprintf(TextBuf,(dgt_schar*)ObjTriggerSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }
    //
    // encrypt tables`s dependency object complie script
    //
    StmtNo=7000;
    ObjSqlRows.rewind();
    if (TabInfo.obj_flag) {
        while(ObjSqlRows.next()) {
            *TextBuf=0;
            strcat(TextBuf,(dgt_schar*)ObjSqlRows.data());
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }

    //
    // create comment
    //
    *TextBuf=0;
    StmtNo=7800;
    CommentInfoRows.rewind();
    dgt_schar* comment_sql;
    while (CommentInfoRows.next() && (comment_sql=(dgt_schar*)CommentInfoRows.data())) {
        *TextBuf=0;
        if (comment_sql && strlen(comment_sql) > 2) {
            strcpy(TextBuf,comment_sql);
            if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
            }
        }
    }

    //
    // for finish sign step
    //
    StmtNo=8000;
    *TextBuf=0;
    sprintf(TextBuf,"commit");
    if (saveSqlText() < 0) {
        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
    }

    //
    // insert decryption (parallel insert)
    //
    dgt_sint32 lobFlag=0;
    ColInfoRows.rewind();
    while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
        if (col_info->status == 1) {
            *TmpBuf=0;
            if (!strcasecmp(col_info->data_type, "CLOB") ||
                    !strcasecmp(col_info->data_type, "BLOB")) {
                lobFlag=1;
            }
        }
    }
    if (lobFlag==1) {
        StepNo=-2;
        StmtNo=-14999;
    } else {
        StepNo=-2;
        StmtNo=-14998;
    }
    *TextBuf=0;
    *TmpBuf=0;
    if (lobFlag==1) {
        ColInfoRows.rewind();
        sprintf(TmpBuf,"insert into %s.%s_%lld( ",
                SchemaName,"petra",TabInfo.enc_tab_id);
        strcat(TextBuf,TmpBuf);
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf=0;
            if (col_info->status >= 1) {
                sprintf(TmpBuf,"%s,",col_info->renamed_col_name);
                strcat(TextBuf,TmpBuf);
            } else {
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
            }
        }
        TextBuf[strlen(TextBuf)-1]=0;
        strcat(TextBuf,") \nselect ");
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
            *TmpBuf=0;
            if (!strcasecmp(col_info->data_type,"LONG") || !strcasecmp(col_info->data_type,"LONG RAW")) {
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
            } else {
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
            }
        }
    } else {
        ColInfoRows.rewind();
        sprintf(TmpBuf,"insert into %s.%s_%lld \n select /*+ PARALLEL(%s,%d) */ ",
                SchemaName,"petra",TabInfo.enc_tab_id,TabInfo.table_name,ParallelDegree);
        strcat(TextBuf,TmpBuf);
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
            if (col_info->status >= 1) {
                *TmpBuf=0;
                sprintf(TmpBuf,getFname(col_info->enc_col_id,2));
                strcat(TmpBuf,",");
                strcat(TextBuf,TmpBuf);
            } else {
                *TmpBuf=0;
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
            }
        }
    }
    TextBuf[strlen(TextBuf)-1]=0;
    *TmpBuf=0;
    if (TabInfo.enc_type == 0) {
        sprintf(TmpBuf," from %s.%s %s",SchemaName,TabInfo.renamed_tab_name,TabInfo.table_name);
        strcat(TextBuf,TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        }
    } else {
        sprintf(TmpBuf," from %s.%s %s",SchemaName,TabInfo.table_name,TabInfo.table_name);
        strcat(TextBuf,TmpBuf);
        if (saveSqlText() < 0) {
            ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        }
    }
#endif /*}}}*/
    return 0;
}

PccTds2000ScriptBuilder::PccTds2000ScriptBuilder(DgcDatabase* db,
                                                 DgcSession* sess,
                                                 dgt_schar* schema_link)
    : PccScriptBuilder(db, sess, schema_link),
      PrivSqlRows(1),
      ObjSqlRows(1),
      ObjTriggerSqlRows(1),
      PkSqlRows(6),
      FkSqlRows(6),
      IdxColRows(1),
      CheckTrgRows(2),
      CheckSqlRows(4),
      CheckSqlRows2(1),
      CheckSqlRows3(1),
      DefFkDropSqlRows(2),
      DefFkDropSqlRows2(1),
      DefFkCreSqlRows2(1),
      DefFkCreSqlRows3(1),
      UniqueSqlRows1(1),
      UniqueSqlRows2(1),
      IdxSqlRows2(1),
      IdxSqlRows4(1),
      IdxSqlRows5(1),
      IdxSqlRows6(1),
      IdxSqlRows7(1) {
    PrivSqlRows.addAttr(DGC_SCHR, 1024, "sql_text");
    ObjSqlRows.addAttr(DGC_SCHR, 1024, "sql_text");
    ObjTriggerSqlRows.addAttr(DGC_SCHR, 30000, "sql_text");

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

    IdxColRows.addAttr(DGC_SCHR, 130, "col_name");
    CheckTrgRows.addAttr(DGC_SCHR, 4000, "search_condition");
    CheckTrgRows.addAttr(DGC_SCHR, 4000, "default_value");

    CheckSqlRows.addAttr(DGC_SCHR, 512, "org1");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "org2");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "enc1");
    CheckSqlRows.addAttr(DGC_SCHR, 512, "enc2");

    CheckSqlRows2.addAttr(DGC_SCHR, 512, "sql_id");
    CheckSqlRows3.addAttr(DGC_SCHR, 512, "sql_id");

    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "enc_sql");
    DefFkDropSqlRows.addAttr(DGC_SCHR, 512, "org_sql");

    DefFkDropSqlRows2.addAttr(DGC_SCHR, 512, "sql_id");
    DefFkCreSqlRows2.addAttr(DGC_SCHR, 512, "sql_id");
    DefFkCreSqlRows3.addAttr(DGC_SCHR, 512, "sql_id");

    UniqueSqlRows1.addAttr(DGC_SCHR, 512, "sql_iq");
    UniqueSqlRows2.addAttr(DGC_SCHR, 512, "sql_iq");
    IdxSqlRows2.addAttr(DGC_SCHR, 30000, "sql_id");
    IdxSqlRows4.addAttr(DGC_SCHR, 512, "sql_id");
    IdxSqlRows5.addAttr(DGC_SCHR, 512, "sql_id");
    IdxSqlRows6.addAttr(DGC_SCHR, 30000, "sql_id");
    IdxSqlRows7.addAttr(DGC_SCHR, 512, "sql_id");
}

PccTds2000ScriptBuilder::~PccTds2000ScriptBuilder() {}

dgt_sint32 PccTds2000ScriptBuilder::getTablespace(DgcMemRows* rtn_rows) throw(
    DgcExcept) {
    return 0;
}

typedef struct {
    dgt_uint8 enc_type;
    dgt_uint8 init_enc_type;
} pc_type_enc_type;

dgt_sint32 PccTds2000ScriptBuilder::buildScript(
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
    if (prepareCtInfo() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCtInfo failed."), -1);

    //
    // for new table encryption mode (get Constraints)
    //
    if (prepareIdx2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareIdxInfo failed."), -1);
    if (prepareCt2Info() < 0)
        ATHROWnR(DgcError(SPOS, "prepareCtInfo failed."), -1);

    if (step1() < 0) ATHROWnR(DgcError(SPOS, "step1_ins failed."), -1);
    if (step2() < 0) ATHROWnR(DgcError(SPOS, "step2_ins failed."), -1);
    if (reverse_step1() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step1_ins failed."), -1);
    if (reverse_step2() < 0)
        ATHROWnR(DgcError(SPOS, "reverse step2_ins failed."), -1);
    return 0;
}

#include "DgcSqlHandle.h"

dgt_sint32 PccTds2000ScriptBuilder::buildScriptMig(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::runVerifyMig(
    dgt_sint64 enc_tab_id, pct_type_verify_job* job_row_ptr) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::migInsertSql(
    dgt_sint64 it_tab_id, dgt_uint8 gen_flag) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::buildScriptAddCol(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
#if 1 /*{{{*/
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
#endif /*}}}*/
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::buildScriptColAdmin(
    dgt_sint64 enc_tab_id, dgt_uint16 version_no) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::checkDB(
    dgt_sint64 db_agent_id, dgt_schar* sys_uid, dgt_schar* sys_pass,
    dgt_schar* agent_uid, DgcMemRows* rtn_rows) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::setCharset(dgt_sint64 db_agent_id) throw(
    DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::agentTest(
    dgt_sint64 db_agent_id, DgcMemRows* rtn_rows) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::agentTableTest(
    dgt_sint64 db_agent_id, DgcMemRows* rtn_rows) throw(DgcExcept) {
    return 0;
}

dgt_sint32 PccTds2000ScriptBuilder::buildInstallScript(
    dgt_sint64 agent_id, dgt_schar* agent_uid, dgt_schar* agent_pass,
    dgt_schar* soha_home) throw(DgcExcept) {
    return 0;
}
