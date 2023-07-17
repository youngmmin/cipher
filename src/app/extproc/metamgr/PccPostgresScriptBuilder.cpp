/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccPostgresScriptBuilder
 *   Implementor        :       mjkim
 *   Create Date        :       2021. 06. 04
 *   Description        :       postgres script builder
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccPostgresScriptBuilder.h"
#include "DgcLinkInfo.h"

extern void check_logger(const char *fmt, ...);

DgcCliConnection* PccPostgresScriptBuilder::connect(dgt_schar* uid,dgt_schar* pw) throw(DgcExcept)
{
	//
	// getting the link_info
	//
	DgcLinkInfo		dblink(Database->pdb());
	pt_database_link_info*	link_info=dblink.getDatabaseLinkInfo(SchemaLink);
	if (!link_info) ATHROWnR(DgcError(SPOS,"getDatabaseLinkInfo failed"),0);

	dgt_schar conn_string[1024]={0};
	sprintf(conn_string,"%d", link_info->port);
	if (!uid || *uid == 0) uid=link_info->user_name;
	if (!pw || *pw == 0) pw=link_info->passwd;

	DgcPostgresConnection*	conn=new DgcPostgresConnection();
	if (conn->connect(conn_string, link_info->host, uid, pw, link_info->db_name) != 0) {
		DgcExcept*	e=EXCEPTnC;
		delete conn;
		RTHROWnR(e,DgcError(SPOS,"connect failed."),0);
	}
	return conn;
}

typedef struct {
	dgt_schar org1[1024];
	dgt_schar enc1[1024];
} pc_type_col_priv;

dgt_sint32 PccPostgresScriptBuilder::preparePrivInfo() throw(DgcExcept)
{
        dgt_schar       sql_text[2048];
        sprintf(sql_text,
"select * from pct_enc_tab_priv "
"where enc_tab_id=%lld ",TabInfo.enc_tab_id);
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        pct_type_enc_tab_priv*       priv_info_tmp;

	pc_type_col_priv privSql;
	memset(&privSql,0,sizeof(pc_type_col_priv));

        PrivSqlRows.reset();
        while ((priv_info_tmp=(pct_type_enc_tab_priv*)sql_stmt->fetch())) {
                dgt_schar privilege[128];
                memset(privilege,0,128);
		memset(&privSql,0,sizeof(pc_type_col_priv));
                dgt_sint64 sql_id=0;
                if (priv_info_tmp->privilege == 1) {
                        sprintf(privilege,"select");
                } else if (priv_info_tmp->privilege == 2) {
                        sprintf(privilege,"insert");
                } else if (priv_info_tmp->privilege == 3) {
                        sprintf(privilege,"update");
                } else if (priv_info_tmp->privilege == 4) {
                        sprintf(privilege,"delete");
                }
                sprintf(privSql.org1,"GRANT %s ON %s.%s TO %s", privilege, SchemaName, TabInfo.org_renamed_tab_name, priv_info_tmp->grantee);
		sprintf(privSql.enc1,"GRANT %s ON %s.%s TO %s", privilege, SchemaName, TabInfo.renamed_tab_name, priv_info_tmp->grantee);
                PrivSqlRows.add();
                PrivSqlRows.next();
		memcpy(PrivSqlRows.data(), &privSql, sizeof(pc_type_col_priv));
        }
        DgcExcept*      e=EXCEPTnC;
        delete sql_stmt;
        if (e) {
                delete e;
        }
        PrivSqlRows.rewind();
        return 1;
}

typedef struct {
	dgt_schar org1[5000];
	dgt_schar enc1[5000];
} pc_type_col_comment;

dgt_sint32 PccPostgresScriptBuilder::prepareCommentInfo() throw(DgcExcept)
{
        dgt_schar       sql_text[2048];
        sprintf(sql_text,"select getname(comments) from pct_enc_tab_comment where enc_tab_id=%lld ",TabInfo.enc_tab_id);
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_schar*       comment_tmp;
	CommentInfoRows.reset();

	pc_type_col_comment comments;
	memset(&comments,0,sizeof(pc_type_col_comment));

        while ((comment_tmp=(dgt_schar*)sql_stmt->fetch())) {
		CommentInfoRows.add();
		CommentInfoRows.next();
		memset(&comments,0,sizeof(pc_type_col_comment));
		sprintf(comments.org1,"COMMENT ON TABLE %s.%s IS '%s'", SchemaName, TabInfo.org_renamed_tab_name, comment_tmp);
		sprintf(comments.enc1,"COMMENT ON TABLE %s.%s IS '%s'", SchemaName, TabInfo.renamed_tab_name, comment_tmp);
               	memcpy(CommentInfoRows.data(), &comments , sizeof(pc_type_col_comment));
        }
        DgcExcept*      e=EXCEPTnC;
        delete sql_stmt;
        if (e) {
                delete e;
        }
	//
	// automatically set column comment by INCLUDING COMMENTS
	//
        CommentInfoRows.rewind();
        return 1;
}

typedef struct {
        dgt_sint64 enc_col_id;
	dgt_schar  column_name[130];
	dgt_schar  data_type[33];
	dgt_uint8  index_type;
	dgt_schar  domain_index_name[130];
	dgt_schar  fbi_index_name[130];
	dgt_schar  normal_index_name[130];
	dgt_schar  tablespace_name[130];
	dgt_uint8  normal_idx_flag;
	dgt_schar  index_col_name[130];
} pc_type_index_row;

typedef struct {
	dgt_schar	org1[512];
	dgt_schar	org2[512];
	dgt_schar	enc1[512];
	dgt_schar	enc2[512];
} idxsql;

dgt_sint32 PccPostgresScriptBuilder::prepareIdxInfo() throw(DgcExcept)
{
        dgt_schar       sql_text[2048];
        memset(sql_text,0,2048);
	//
	// Unique Idx Column settting(non enc column) for double view except rowid 
	//
	IdxColRows.reset();
	ColInfoRows.rewind();
	pc_type_col_info*       col_info;
	dgt_sint32 is_identity=0;
	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		*TmpBuf=0;
		if (col_info->is_identity == 1) {
			is_identity=1;
                        IdxColRows.add();
                        IdxColRows.next();
                        memcpy(IdxColRows.data(),col_info->col_name,strlen(col_info->col_name));
		}
	}
	if (is_identity == 0) {
        	memset(sql_text,0,2048);
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
        	DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        	        DgcExcept*      e=EXCEPTnC;
                	delete sql_stmt;
	                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        	}
	        dgt_sint64*       idxname=0;
        	if ((idxname=(dgt_sint64*)sql_stmt->fetch())) {
        		memset(sql_text,0,2048);
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
") c",*idxname,TabInfo.enc_tab_id);
			DgcSqlStmt* idx_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (idx_stmt == 0 || idx_stmt->execute() < 0) {
				DgcExcept*      e=EXCEPTnC;
                		delete idx_stmt;
				RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
			} 
			dgt_schar* idxcol=0;
			while ((idxcol=(dgt_schar*)idx_stmt->fetch())) {
				IdxColRows.add();
				IdxColRows.next();
				memcpy(IdxColRows.data(),idxcol,strlen(idxcol));
			}
			DgcExcept* e=EXCEPTnC;
			if (e) {
				delete e;
			}
			delete idx_stmt;
		}
		DgcExcept *e=EXCEPTnC;
		if (e) {
			delete e;
		}
		delete sql_stmt;
	}
	IdxColRows.rewind();
        //
        // Unique Idx Column settting2 (for transaction trigger)
        //
#if 1
        IdxSqlRows.reset();
        memset(sql_text,0,2048);
        sprintf(sql_text,
"select distinct index_name "
"from   pct_enc_col_index "
"where  enc_tab_id = %lld " ,TabInfo.enc_tab_id);
        DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64* idxname=0;
        while ((idxname=(dgt_sint64*)sql_stmt->fetch())) {
#if 1		
		// except pk
                memset(sql_text,0,2048);
                sprintf(sql_text,"select count() from pct_enc_col_ct where constraint_name = %lld ", *idxname);
                DgcSqlStmt* pk_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                if (pk_stmt == 0 || pk_stmt->execute() < 0) {
                        DgcExcept*      e=EXCEPTnC;
                        delete pk_stmt;
                        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                }
		dgt_sint64* count_tmp=0;
		dgt_sint64  count=0;
		if ((count_tmp=(dgt_sint64*)pk_stmt->fetch())) {
			memcpy(&count,count_tmp,sizeof(dgt_sint64));
		}
		delete pk_stmt;

		if (count > 0) continue;
#endif 
                memset(sql_text,0,2048);
                sprintf(sql_text,
"select a.index_name, b.column_name , b.renamed_col_name, a.column_position, a.UNIQUENESS, a.index_type, a.status "
"from pct_enc_col_index a, pct_enc_column b "
"where a.enc_col_id = b.enc_col_id "
"and   a.index_name = %lld "
"and   a.enc_tab_id = %lld "
"order by a.column_position ", *idxname, TabInfo.enc_tab_id);
                DgcSqlStmt* idx_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                if (idx_stmt == 0 || idx_stmt->execute() < 0) {
                       DgcExcept*      e=EXCEPTnC;
                        delete idx_stmt;
                        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
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
                idx_type* idxcol=0;
		idxsql	tmp_sql;
		memset(&tmp_sql,0,sizeof(idxsql));
		dgt_sint32	seq=0;
                while ((idxcol=(idx_type*)idx_stmt->fetch())) {
			seq++;
			if (seq == 1) {
				if (idxcol->uniqueness) {
					sprintf(tmp_sql.org1,"CREATE UNIQUE INDEX %s ON %s.%s(%s,",
							     PetraNamePool->getName(idxcol->index_name),SchemaName,
							     TabInfo.org_renamed_tab_name, idxcol->col_name);
					sprintf(tmp_sql.enc1,"CREATE UNIQUE INDEX %s ON %s.%s(%s,", 
							     PetraNamePool->getName(idxcol->index_name),SchemaName,
     							     TabInfo.renamed_tab_name ,idxcol->col_name);
				} else {
					sprintf(tmp_sql.org1,"CREATE INDEX %s ON %s.%s(%s,",
							     PetraNamePool->getName(idxcol->index_name),SchemaName,
							     TabInfo.org_renamed_tab_name, idxcol->col_name);
					sprintf(tmp_sql.enc1,"CREATE INDEX %s ON %s.%s(%s,", 
							     PetraNamePool->getName(idxcol->index_name),SchemaName,
							     TabInfo.renamed_tab_name ,idxcol->col_name);
				}
				sprintf(tmp_sql.org2,"DROP INDEX %s.%s", SchemaName, PetraNamePool->getName(idxcol->index_name));
				sprintf(tmp_sql.enc2,"DROP INDEX %s.%s", SchemaName, PetraNamePool->getName(idxcol->index_name));
			} else {
				strcat(tmp_sql.org1,idxcol->col_name);
				strcat(tmp_sql.org1,",");
				strcat(tmp_sql.enc1,idxcol->col_name);
				strcat(tmp_sql.enc1,",");
			}
                }
		tmp_sql.org1[strlen(tmp_sql.org1)-1]=')';
		tmp_sql.enc1[strlen(tmp_sql.enc1)-1]=')';
		IdxSqlRows.add();
		IdxSqlRows.next();
		memcpy(IdxSqlRows.data(),&tmp_sql,sizeof(idxsql));
                DgcExcept* e=EXCEPTnC;
                if (e) {
                        delete e;
                }
                delete idx_stmt;
        }
        DgcExcept* e=EXCEPTnC;
        if (e) {
                delete e;
        }
        delete sql_stmt;
	IdxSqlRows.rewind();
#endif
        return 1;
}

typedef struct {
	dgt_sint64 index_name;
	dgt_sint64 renamed_org_name;
	dgt_sint64 index_owner;
	dgt_uint8  uniqueness;
	dgt_sint64 target_tablespace;
	dgt_uint16 degree;
	dgt_uint8  logging;
} pc_type_idx2;

typedef struct {
	dgt_sint64 schema_name;
	dgt_sint64 table_name;
	dgt_sint64 renamed_tab_name;
	dgt_sint64 column_name;
	dgt_sint64 renamed_col_name;
	dgt_sint64 constraint_name;
	dgt_sint64 renamed_constraint_name;
	dgt_uint8  status;
	dgt_uint32 position;
	dgt_uint8  constraint_type;
	dgt_sint64 ref_pk_owner;
	dgt_sint64 ref_pk_table;
	dgt_sint64 ref_pk_column;
	dgt_sint64 org_renamed_tab_name;
	dgt_uint8  enc_type;
	dgt_uint8  keep_org_tab_flag;
	dgt_uint8  generated;
} pc_type_pk_info;

typedef struct {
        dgt_sint64 ref_pk_owner;
        dgt_sint64 ref_pk_table;
        dgt_sint64 ref_pk_column;
        dgt_sint64 ref_pk_renamed_table;
        dgt_sint64 ref_pk_renamed_column;
	dgt_uint8  status;
} pc_type_pk_row;

typedef struct {
        dgt_schar       org1[512];
        dgt_schar       org2[512];
        dgt_schar       enc1[512];
        dgt_schar       enc2[512];
} pc_type_pk_fk_sql;

dgt_sint32 PccPostgresScriptBuilder::prepareCtInfo() throw(DgcExcept)
{
	DgcExcept* e = 0;
        dgt_schar       sql_text[2048];
        DgcSqlStmt*	sql_stmt=0;
	//
	// for using trigger (enc_column`s check constraint)
	//
	CheckTrgRows.reset();
	memset(sql_text,0,2048);
        sprintf(sql_text,
"select a.search_condition, b.default "
"from pct_enc_col_ct a, pct_enc_column b, pct_enc_table c "
"where a.enc_col_id = b.enc_col_id "
"and   b.enc_tab_id = c.enc_tab_id "
"and   a.enc_tab_id = %lld "
// "and   a.status =1 "
"and   getname(a.search_condition) != '' "
"and   a.constraint_type =3",TabInfo.enc_tab_id);

        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        typedef struct {
                dgt_sint64       search_condition;
                dgt_sint64       default_val;
        } type_check;
	typedef struct {
                dgt_schar       search_condition[4000];
                dgt_schar       default_val[4000];
        } check_st;
	
        type_check*    tmp_search=0;
        check_st       st_search;
        while ((tmp_search=(type_check*)sql_stmt->fetch())) {
		dgt_sint32 i = 0;
		memset(&st_search,0,sizeof(check_st));
		sprintf(st_search.search_condition,"%s",PetraNamePool->getNameString(tmp_search->search_condition));
		sprintf(st_search.default_val,"%s",PetraNamePool->getNameString(tmp_search->default_val));
		while (st_search.search_condition[i]) {
			if( st_search.search_condition[i] == '"' )
			strcpy( st_search.search_condition+i, st_search.search_condition+i+1 );
			i++;
		}
                CheckTrgRows.add();
                CheckTrgRows.next();
                memcpy(CheckTrgRows.data(),&st_search,sizeof(check_st));
        }
        delete sql_stmt;
        e=EXCEPTnC;
        if (e) {
                delete e;
        }
        CheckTrgRows.rewind();
	//
	// if IsPkFk =1 then pk,fk sql create
	//
        sprintf(sql_text,
"select working_set_id "
"from pct_working_set where enc_tab_id=%lld",TabInfo.enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64*     working_set_id_tmp;
	dgt_sint64	working_set_id=0;
        while ((working_set_id_tmp=(dgt_sint64*)sql_stmt->fetch())) {
		memcpy(&working_set_id,working_set_id_tmp,sizeof(dgt_sint64));
	}
	delete sql_stmt;
	e=EXCEPTnC;
	if (e) {
		delete e;
	}
	pc_type_pk_fk_sql pkfkSql;
	memset(&pkfkSql,0,sizeof(pc_type_pk_fk_sql));
	FkSqlRows.reset();
	PkSqlRows.reset();

	if (IsPkFk == 1) {
		//
		// pk sql create
		//
        	sprintf(sql_text,
"select distinct working_set_id,enc_tab_id "
"from pct_working_set where working_set_id=%lld",working_set_id);
	        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
	                DgcExcept*      e=EXCEPTnC;
        	        delete sql_stmt;
                	RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	        }
		typedef struct pc_type_working_set {
			dgt_sint64	working_set_id;
			dgt_sint64	enc_tab_id;
		} pc_type_working_set;
        	pc_type_working_set*       row_ptr;
	        while ((row_ptr=(pc_type_working_set*)sql_stmt->fetch())) {
			memset(&pkfkSql,0,sizeof(pc_type_pk_fk_sql));
			sprintf(sql_text,
"select c.schema_name, c.table_name, c.renamed_tab_name, b.column_name, b.renamed_col_name, a.constraint_name, a.renamed_constraint_name, "
"a.status, a.position, a.constraint_type, a.ref_pk_owner, a.ref_pk_table, a.ref_pk_column, c.org_renamed_tab_name, d.enc_type, d.keep_org_tab_flag, "
"a.generated "
"from ceea_enc_col_ct a, ceea_enc_column b, ceea_enc_table c, pct_enc_table d "
"where a.enc_col_id = b.enc_col_id "
"and   a.enc_tab_id = c.enc_tab_id "
"and   c.enc_tab_id = d.enc_tab_id "
"and   a.enc_tab_id=%lld "
"and   a.constraint_type=1 "
"order by a.position",row_ptr->enc_tab_id);

			DgcSqlStmt* pk_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (pk_stmt == 0 || pk_stmt->execute() < 0) {
				DgcExcept*      e=EXCEPTnC;
				delete pk_stmt;
				RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
			}
			pc_type_pk_info* pk_row=0;
			dgt_sint32 seq=0;
			dgt_sint32 is_fetch=0;

			dgt_sint32 ispkfk_tab=0;
			dgt_sint32 is_enc_column=0;
			if (TabInfo.enc_tab_id == row_ptr->enc_tab_id) ispkfk_tab=1;
			while ((pk_row=(pc_type_pk_info*)pk_stmt->fetch())) {
				//pc_type_pk_row refpk;
				seq++;
				is_fetch=1;
				if (pk_row->status == 1) {
					is_enc_column=1;
				}
				if (seq == 1) {
					if (pk_row->enc_type == 0) {
						if (ispkfk_tab) {
							sprintf(pkfkSql.org2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s PRIMARY KEY("
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->org_renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.enc2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->org_renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s PRIMARY KEY("
									,PetraNamePool->getNameString(pk_row->schema_name)
       		        	                       	                ,PetraNamePool->getNameString(pk_row->renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
						} else {
							sprintf(pkfkSql.org2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s PRIMARY KEY("
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->table_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.enc2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(pk_row->schema_name)
									,PetraNamePool->getNameString(pk_row->org_renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
							sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s PRIMARY KEY("
									,PetraNamePool->getNameString(pk_row->schema_name)
       		        	                       	                ,PetraNamePool->getNameString(pk_row->renamed_tab_name)
									,PetraNamePool->getNameString(pk_row->constraint_name));
						}
					} else {
						sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s PRIMARY KEY("
								,PetraNamePool->getNameString(pk_row->schema_name)
								,PetraNamePool->getNameString(pk_row->table_name)
								,PetraNamePool->getNameString(pk_row->constraint_name));
					}
				}
				strcat(pkfkSql.org1,PetraNamePool->getNameString(pk_row->column_name));
				strcat(pkfkSql.org1,",");
				strcat(pkfkSql.enc1,PetraNamePool->getNameString(pk_row->column_name));
				strcat(pkfkSql.enc1,",");
			}
			if (is_fetch && is_enc_column) {
				pkfkSql.org1[strlen(pkfkSql.org1)-1]=')';
				pkfkSql.enc1[strlen(pkfkSql.enc1)-1]=')';
				PkSqlRows.add();
				PkSqlRows.next();
				memcpy(PkSqlRows.data(),&pkfkSql,sizeof(pc_type_pk_fk_sql));
			}
			memset(&pkfkSql,0,sizeof(pc_type_pk_fk_sql));
			sprintf(sql_text,
"select distinct constraint_name "
"from ceea_enc_col_ct "
"where enc_tab_id = %lld "
"and   constraint_type=2 "
//"and   status =1",row_ptr->enc_tab_id);
,row_ptr->enc_tab_id);
                        DgcSqlStmt* fk_sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                        if (fk_sql_stmt == 0 || fk_sql_stmt->execute() < 0) {
                        	DgcExcept*      e=EXCEPTnC;
                                delete fk_sql_stmt;
                                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                        }
                        dgt_sint64* constraint_name_tmp=0;
                        dgt_sint64  constraint_name=0;
			while ((constraint_name_tmp=(dgt_sint64*)fk_sql_stmt->fetch())) {
				memcpy(&constraint_name,constraint_name_tmp,sizeof(dgt_sint64));
				sprintf(sql_text,
"select c.schema_name, c.table_name, c.renamed_tab_name, b.column_name, b.renamed_col_name, a.constraint_name, "
"a.renamed_constraint_name, a.status, a.position, a.constraint_type, "
"a.ref_pk_owner, a.ref_pk_table, a.ref_pk_column, c.org_renamed_tab_name, d.enc_type, d.keep_org_tab_flag, "
"a.generated "
"from ceea_enc_col_ct a, ceea_enc_column b, ceea_enc_table c, pct_enc_table d "
"where a.enc_col_id = b.enc_col_id "
"and   a.enc_tab_id = c.enc_tab_id "
"and   a.enc_tab_id = d.enc_tab_id "
"and   a.enc_tab_id=%lld "
"and   a.constraint_name=%lld "
"order by a.position",row_ptr->enc_tab_id, constraint_name);
				DgcSqlStmt* fk_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
				if (fk_stmt == 0 || fk_stmt->execute() < 0) {
                	        	DgcExcept*      e=EXCEPTnC;
                                        delete fk_stmt;
                               	        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	                        }
        	                dgt_sint32 seq=0;
				dgt_uint8 cascade_flag=0;
				pc_type_pk_info* fk_row=0;
				DgcMemRows	pkrows(6);
				pkrows.addAttr(DGC_SCHR,130,"OWNER");
				pkrows.addAttr(DGC_SCHR,130,"TABLE");
				pkrows.addAttr(DGC_SCHR,130,"COLUMNE");
				pkrows.addAttr(DGC_SCHR,130,"rename_table");
				pkrows.addAttr(DGC_SCHR,130,"rename_column");
				pkrows.addAttr(DGC_UB1,0,"status");
				pkrows.reset();
				typedef struct {
					dgt_sint64	enc_tab_id;
					dgt_schar	owner[130];
					dgt_schar	table[130];
					dgt_schar	column[130];
					dgt_schar	renamed_table[130];
					dgt_schar	renamed_column[130];
					dgt_uint8	status;
				} pk_tmp;
				pk_tmp pktmp;
				memset(&pktmp,0,sizeof(pk_tmp));
                	        while ((fk_row=(pc_type_pk_info*)fk_stmt->fetch())) {
					seq++;
					cascade_flag=fk_row->generated;
					if (seq == 1) {
						if (fk_row->enc_type == 0) {
							if (ispkfk_tab) {
								sprintf(pkfkSql.enc2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
										,PetraNamePool->getNameString(fk_row->schema_name)
										,PetraNamePool->getNameString(fk_row->org_renamed_tab_name)
										,PetraNamePool->getNameString(fk_row->constraint_name));
								sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
                                        	                                ,PetraNamePool->getNameString(fk_row->schema_name)
                                                	                        ,PetraNamePool->getNameString(fk_row->renamed_tab_name)
                                                        	                ,PetraNamePool->getNameString(fk_row->constraint_name));
								sprintf(pkfkSql.org2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
										,PetraNamePool->getNameString(fk_row->schema_name)
										,PetraNamePool->getNameString(fk_row->renamed_tab_name)
										,PetraNamePool->getNameString(fk_row->constraint_name));
                                	                        sprintf(pkfkSql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
                                        	                                ,PetraNamePool->getNameString(fk_row->schema_name)
                                                	                        ,PetraNamePool->getNameString(fk_row->org_renamed_tab_name)
                                                        	                ,PetraNamePool->getNameString(fk_row->constraint_name));
							} else {
								sprintf(pkfkSql.enc2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
										,PetraNamePool->getNameString(fk_row->schema_name)
										,PetraNamePool->getNameString(fk_row->table_name)
										,PetraNamePool->getNameString(fk_row->constraint_name));
								sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
                                        	                                ,PetraNamePool->getNameString(fk_row->schema_name)
                                                	                        ,PetraNamePool->getNameString(fk_row->table_name)
                                                        	                ,PetraNamePool->getNameString(fk_row->constraint_name));
								sprintf(pkfkSql.org2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
										,PetraNamePool->getNameString(fk_row->schema_name)
										,PetraNamePool->getNameString(fk_row->table_name)
										,PetraNamePool->getNameString(fk_row->constraint_name));
                                	                        sprintf(pkfkSql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
                                        	                                ,PetraNamePool->getNameString(fk_row->schema_name)
                                                	                        ,PetraNamePool->getNameString(fk_row->org_renamed_tab_name)
                                                        	                ,PetraNamePool->getNameString(fk_row->constraint_name));
							}
						} else {
							sprintf(pkfkSql.enc2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(fk_row->schema_name)
									,PetraNamePool->getNameString(fk_row->table_name)
									,PetraNamePool->getNameString(fk_row->constraint_name));
			               		        sprintf(pkfkSql.enc1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
									,PetraNamePool->getNameString(fk_row->schema_name)
        		                	                        ,PetraNamePool->getNameString(fk_row->table_name)
									,PetraNamePool->getNameString(fk_row->constraint_name));
							sprintf(pkfkSql.org2,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
									,PetraNamePool->getNameString(fk_row->schema_name)
									,PetraNamePool->getNameString(fk_row->renamed_tab_name)
									,PetraNamePool->getNameString(fk_row->constraint_name));
							sprintf(pkfkSql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY("
        	                                        	        ,PetraNamePool->getNameString(fk_row->schema_name)
                	                                        	,PetraNamePool->getNameString(fk_row->table_name)
	                        	                                ,PetraNamePool->getNameString(fk_row->constraint_name));
						}
					}
                	                strcat(pkfkSql.org1,PetraNamePool->getNameString(fk_row->column_name));
                        	        strcat(pkfkSql.org1,",");
                	                strcat(pkfkSql.enc1,PetraNamePool->getNameString(fk_row->column_name));
                                	strcat(pkfkSql.enc1,",");
					pkrows.add();
					pkrows.next();
					dgt_schar	sqltext[2048];
					memset(sqltext,0,2048);
					sprintf(sqltext,
"select a.enc_tab_id, "
      " c.schema_name, "
      " b.table_name, "
      " a.column_name, "
      " b.renamed_tab_name, "
      " a.renamed_col_name "
"from   pct_enc_column a, pct_enc_table b, pct_enc_schema c "
"where  a.enc_tab_id = b.enc_tab_id "
"  and  b.schema_id = c.schema_id "
  "and  c.db_id = %lld "
  "and  c.schema_name = '%s' "
  "and  b.table_name =  '%s'",Dbid, PetraNamePool->getNameString(fk_row->ref_pk_owner), PetraNamePool->getNameString(fk_row->ref_pk_table));
					DgcSqlStmt*	sqlstmt=Database->getStmt(Session,sqltext,strlen(sqltext));
					if (sqlstmt == 0 || sqlstmt->execute() < 0) {
						DgcExcept*      e=EXCEPTnC;
				                delete sqlstmt;
				                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
				        }
				        typedef struct {
				                dgt_sint64       enc_tab_id;
						dgt_schar	 schema_name[33];
						dgt_schar	 table_name[130];
						dgt_schar	 column_name[130];
						dgt_schar	 renamed_tab_name[130];
						dgt_schar	 renamed_col_name[130];
				        } ref_pk_row;
        				ref_pk_row*    tmp_ptr=0;
        				if ((tmp_ptr=(ref_pk_row*)sqlstmt->fetch())) {
						pktmp.enc_tab_id=tmp_ptr->enc_tab_id;
						sprintf(pktmp.owner,tmp_ptr->schema_name);
						sprintf(pktmp.table,tmp_ptr->table_name);
						sprintf(pktmp.column,tmp_ptr->column_name);
						if (TabInfo.enc_type == 0) {
							sprintf(pktmp.renamed_table,tmp_ptr->renamed_tab_name);
						} else {
							sprintf(pktmp.renamed_table,tmp_ptr->table_name);
						}
						sprintf(pktmp.renamed_column,tmp_ptr->renamed_col_name);
					} else {
						sprintf(pktmp.owner,PetraNamePool->getNameString(fk_row->ref_pk_owner));
                                                sprintf(pktmp.table,"%s",PetraNamePool->getNameString(fk_row->ref_pk_table));
                                                sprintf(pktmp.column,"%s",PetraNamePool->getNameString(fk_row->ref_pk_column));
                                                if (TabInfo.enc_type == 0) {
                                                        sprintf(pktmp.renamed_table,"%s$$",PetraNamePool->getNameString(fk_row->ref_pk_table));
                                                } else {
                                                        sprintf(pktmp.renamed_table,"%s",PetraNamePool->getNameString(fk_row->ref_pk_table));
                                                }
                                                sprintf(pktmp.renamed_column,"%s$$",PetraNamePool->getNameString(fk_row->ref_pk_column));
					}
					DgcExcept*	e=EXCEPTnC;
					delete sqlstmt;
					dgt_schar stext[512];
					sprintf(stext,					
"select count() from ceea_enc_column "
"where db_id=%lld "
"and schema_name=%lld "
"and table_name=%lld "
"and status = 1 ",Dbid,fk_row->ref_pk_owner,fk_row->ref_pk_table);
				        DgcSqlStmt*     s_stmt=Database->getStmt(Session,stext,strlen(stext));
				        if (s_stmt == 0 || s_stmt->execute() < 0) {
				                DgcExcept*      e=EXCEPTnC;
				                delete s_stmt;
				                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
				        }
				        dgt_sint64*       cnt_tmp;
        				if ((cnt_tmp=(dgt_sint64*)s_stmt->fetch())) {
						if (*cnt_tmp > 0) pktmp.status=1;
				        }
				        e=EXCEPTnC;
				        delete s_stmt;
					memcpy(pkrows.data(),&pktmp,sizeof(pktmp));
				}
				delete fk_stmt;
				pkrows.rewind();
                	        pkfkSql.enc1[strlen(pkfkSql.enc1)-1]=0;
                        	pkfkSql.org1[strlen(pkfkSql.org1)-1]=0;
	                        strcat(pkfkSql.enc1,") REFERENCES ");
        	                strcat(pkfkSql.org1,") REFERENCES ");
				pk_tmp* pk_ptr=0;
				seq=0;
				while (pkrows.next()) {
					seq++;
					pk_ptr=(pk_tmp*)pkrows.data();
					if (seq == 1) {
						dgt_schar tmpbuf[128];
						memset(tmpbuf,0,128);
						if (pk_ptr->enc_tab_id == TabInfo.enc_tab_id) {
							sprintf(tmpbuf,"%s.%s(%s,",pk_ptr->owner,
        	               	                                                   pk_ptr->renamed_table,
                	               	                                           pk_ptr->column);
						} else {
							sprintf(tmpbuf,"%s.%s(%s,",pk_ptr->owner,
        	               	                                                   pk_ptr->table,
                	               	                                           pk_ptr->column);
						}
						strcat(pkfkSql.org1,tmpbuf);
						memset(tmpbuf,0,128);
						if (pk_ptr->status == 1) {
							sprintf(tmpbuf,"%s.%s(%s,",pk_ptr->owner, 
										   pk_ptr->renamed_table,
               	                	               	                       	   pk_ptr->column);
						} else {
							sprintf(tmpbuf,"%s.%s(%s,",pk_ptr->owner, 
										   pk_ptr->table,
               	                	               	                       	   pk_ptr->column);
						}
						strcat(pkfkSql.enc1,tmpbuf);
					} else {
						strcat(pkfkSql.org1,pk_ptr->column);
						strcat(pkfkSql.org1,",");
						strcat(pkfkSql.enc1,pk_ptr->column);
						strcat(pkfkSql.enc1,",");
					}
				}
				pkfkSql.org1[strlen(pkfkSql.org1)-1]=')';
				pkfkSql.enc1[strlen(pkfkSql.enc1)-1]=')';
				if (cascade_flag == 1) {
					strcat(pkfkSql.org1," ON DELETE CASCADE");
					strcat(pkfkSql.enc1," ON DELETE CASCADE");
				} else if (cascade_flag == 2) {
					strcat(pkfkSql.org1," ON UPDATE CASCADE");
					strcat(pkfkSql.enc1," ON UPDATE CASCADE");
				} else if (cascade_flag == 3) {
					strcat(pkfkSql.org1," ON DELETE CASCADE ON UPDATE CASCADE");
					strcat(pkfkSql.enc1," ON DELETE CASCADE ON UPDATE CASCADE");
				}
				FkSqlRows.add();
				FkSqlRows.next();
				memcpy(FkSqlRows.data(),&pkfkSql,sizeof(pc_type_pk_fk_sql));
			}
       			delete fk_sql_stmt;
                        e=EXCEPTnC;
                       	if (e) {
                        	delete e;
			}
        	}
        	delete sql_stmt;
	        DgcExcept*      e=EXCEPTnC;
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
        dgt_uint8  status;
        dgt_uint32 position;
        dgt_uint8  constraint_type;
        dgt_sint64 constraint_name;
        dgt_sint64 renamed_constraint_name;
} pc_type_pksql2;

typedef struct {
        dgt_schar col_name[130];
        dgt_sint64 ref_pk_owner;
        dgt_sint64 ref_pk_table;
        dgt_sint64 ref_pk_column;
        dgt_uint8  status;
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
	dgt_schar org1[1024];
	dgt_schar enc1[1024];
} pc_type_checksql;

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

dgt_sint32 PccPostgresScriptBuilder::prepareCt2Info() throw(DgcExcept)
{
        //
        // new table encryption mode (setting pksql,fksql,checksql)
        //
        DefFkDropSqlRows.reset(); // enc table`s dependeny foreign key(drop)
        DefFkDropSqlRows2.reset(); // non enc table`s dependeny foreign key(drop)
        DefFkCreSqlRows2.reset(); // non enc column`s dependeny foreign key in step2
        DefFkCreSqlRows3.reset(); // non enc column`s dependeny foreign key in reverse_step2
	DefTabDropSqlRows.reset(); // enc tbla`s depencdey table (drop)

        CheckSqlRows.reset();

        UniqueSqlRows1.reset();
        UniqueSqlRows2.reset();

        //
        // FkSql (non enc pk column <- non enc fk column)
        //
        dgt_schar sql_text[2048];
        memset(sql_text,0,2048);
        sprintf(sql_text,
"select distinct constraint_name "
"from ceea_col_ct a, ceea_table b "
"where a.enc_tab_id = b.enc_tab_id "
"and   b.db_id = %lld "
"and   ref_pk_owner = getnameid('%s') "
"and   ref_pk_table = getnameid('%s') "
"and   constraint_type = 2",Dbid, SchemaName, TabInfo.table_name);
        DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64* const_name=0;
        DgcExcept* e=0;
        while ((const_name=(dgt_sint64*)sql_stmt->fetch())) {
                //
                // if dependecy fk is encryption table then table_name
                //
                memset(sql_text,0,2048);
                sprintf(sql_text,
"select constraint_name from ceea_enc_col_ct where constraint_name = %lld",*const_name);
                DgcSqlStmt* searchStmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                if (searchStmt == 0 || searchStmt->execute() < 0) {
                        DgcExcept*      e=EXCEPTnC;
                        delete sql_stmt;
                        delete searchStmt;
                        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                }
                dgt_sint64* tmp_result;
                typedef struct {
                        dgt_schar       enc_sql[512];
                        dgt_schar       org_sql[512];
                } def_fk_enc_table;
                def_fk_enc_table def_enc_sql;
                dgt_sint32 enc_tab_flag =0;
                if ((tmp_result=(dgt_sint64*)searchStmt->fetch())) {
                        enc_tab_flag =1;
                }
                memset(sql_text,0,2048);
                sprintf(sql_text,
"select constraint_name, a.schema_name, a.table_name, b.column_name, c.ref_pk_owner, c.ref_pk_table, c.ref_pk_column, c.position "
"from   ceea_table a, "
       "ceea_column b, "
       "ceea_col_ct c "
"where a.enc_tab_id = b.enc_tab_id "
"and   b.enc_col_id = c.enc_col_id "
"and   a.db_id = %lld "
"and   c.constraint_name = %lld "
"order by c.position", Dbid, *const_name);
                DgcSqlStmt* fkStmt=Database->getStmt(Session,sql_text,strlen(sql_text));
                if (fkStmt == 0 || fkStmt->execute() < 0) {
                        DgcExcept*      e=EXCEPTnC;
                        delete sql_stmt;
                        delete fkStmt;
                        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
                }
                pc_type_def_fksql2* def_fksql=0;
                dgt_schar dropSql[512];
                dgt_schar createSql[512];
                dgt_schar createSql2[512];
                dgt_schar refSql[512];
                dgt_schar refSql2[512];
                dgt_schar pk_col[512];
                dgt_schar fk_col[512];
                memset(pk_col,0,512);
                memset(fk_col,0,512);
                memset(dropSql,0,512);
                dgt_sint32 fetch=0;
                while ((def_fksql=(pc_type_def_fksql2*)fkStmt->fetch())) {
                        fetch=1;
                        if (enc_tab_flag == 0) {
                                memset(createSql,0,512);
                                memset(createSql2,0,512);
                                memset(dropSql,0,512);
                                memset(refSql,0,512);
                                memset(refSql2,0,512);
                                sprintf(dropSql,"ALTER TABLE %s.%s DROP CONSTRAINT %s",
                                                PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                sprintf(createSql,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY(",
                                                PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                sprintf(createSql2,"ALTER TABLE %s.%s ADD CONSTRAINT %s FOREIGN KEY(",
                                                PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                sprintf(refSql," REFERENCES %s.%s(", SchemaName, TabInfo.renamed_tab_name);
                                sprintf(refSql2," REFERENCES %s.%s(", SchemaName, TabInfo.org_renamed_tab_name);
                                strcat(fk_col,PetraNamePool->getNameString(def_fksql->column_name));
                                strcat(fk_col,",");
                                strcat(pk_col,PetraNamePool->getNameString(def_fksql->ref_column));
                                strcat(pk_col,",");
                        } else {
                                memset(&def_enc_sql,0,sizeof(def_fk_enc_table));
                                sprintf(def_enc_sql.enc_sql,"ALTER TABLE %s.%s DROP CONSTRAINT %s",
						PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                if (TabInfo.enc_type == 0) {
                                        sprintf(def_enc_sql.org_sql,"ALTER TABLE %s.%s$$ DROP CONSTRAINT %s",
                                                PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                } else {
                                        sprintf(def_enc_sql.org_sql,"ALTER TABLE %s.%s DROP CONSTRAINT %s",
                                                PetraNamePool->getNameString(def_fksql->schema_name),
                                                PetraNamePool->getNameString(def_fksql->table_name),
                                                PetraNamePool->getNameString(def_fksql->constraint_name));
                                }
                        }

                }
                if (fetch == 1) {
                        if (enc_tab_flag == 0) {
                                DefFkDropSqlRows2.add();
                                DefFkDropSqlRows2.next();
                                memcpy(DefFkDropSqlRows2.data(),dropSql,strlen(dropSql));
                                DefFkCreSqlRows2.add();
                                DefFkCreSqlRows2.next();
                                fk_col[strlen(fk_col)-1]=')';
                                pk_col[strlen(pk_col)-1]=')';
                                strcat(createSql,fk_col);
                                strcat(createSql,refSql);
                                strcat(createSql,pk_col);
                                memcpy(DefFkCreSqlRows2.data(),createSql,strlen(createSql));
                                DefFkCreSqlRows3.add();
                                DefFkCreSqlRows3.next();
                                strcat(createSql2,fk_col);
                                strcat(createSql2,refSql2);
                                strcat(createSql2,pk_col);
                                memcpy(DefFkCreSqlRows3.data(),createSql2,strlen(createSql2));
                        } else {
                                DefFkDropSqlRows.add();
                                DefFkDropSqlRows.next();
                                memcpy(DefFkDropSqlRows.data(),&def_enc_sql,sizeof(def_fk_enc_table));
                        }
                }
                delete fkStmt;
                e=EXCEPTnC;
                if (e) {
                        delete e;
                }
        }
        delete sql_stmt;
        e=EXCEPTnC;
        if (e) {
                delete e;
        }
	//
	// drop dependecy table
	// 
	memset(sql_text,0,2048);
        sprintf(sql_text,
"select a.enc_tab_id, a.schema_name, a.table_name, a.renamed_tab_name, a.org_renamed_tab_name "
"from   ceea_enc_table a, "
       "(select distinct ref_pk_owner, ref_pk_table from pct_enc_col_ct where enc_tab_id = %lld and constraint_type=2) b "
"where a.schema_name = b.ref_pk_owner and a.table_name = b.ref_pk_table ",TabInfo.enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
	typedef struct pc_type_ref_table {
		dgt_sint64	enc_tab_id;
		dgt_sint64	schema_name;
		dgt_sint64	table_name;
		dgt_sint64	renamed_tab_name;
		dgt_sint64	org_renamed_tab_name;
	} pc_type_ref_table;
	pc_type_ref_table*	row_ptr;
	while ((row_ptr=(pc_type_ref_table*)sql_stmt->fetch())) {
                typedef struct {
                        dgt_schar       enc_sql[512];
                        dgt_schar       org_sql[512];
                } ref_table_sql;
                ref_table_sql refsql;
                memset(&refsql,0,sizeof(ref_table_sql));
		sprintf(refsql.enc_sql,"DROP TABLE %s.%s", 
					PetraNamePool->getNameString(row_ptr->schema_name),
					PetraNamePool->getNameString(row_ptr->org_renamed_tab_name));
		sprintf(refsql.org_sql,"DROP TABLE %s.%s", 
					PetraNamePool->getNameString(row_ptr->schema_name),
					PetraNamePool->getNameString(row_ptr->renamed_tab_name));
		DefTabDropSqlRows.add();
		DefTabDropSqlRows.next();
		memcpy(DefTabDropSqlRows.data(),&refsql,sizeof(ref_table_sql));
	}
        delete sql_stmt;
        e=EXCEPTnC;
        if (e) {
                delete e;
        }
	//
	// checksql create (if non encryption column then create checksql)
	// 
	memset(sql_text,0,2048);
        sprintf(sql_text,
"select a.constraint_name, b.column_name, b.renamed_col_name, getname(a.search_condition), b.status "
"from   pct_enc_col_ct a, pct_enc_column b "
"where  a.enc_col_id = b.enc_col_id "
"and    a.enc_tab_id = %lld "
"and    a.constraint_type=3 ",TabInfo.enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }

        pc_type_checksql2* checksql_tmp;
        while ((checksql_tmp=(pc_type_checksql2*)sql_stmt->fetch())) {
		pc_type_checksql checksql;
		memset(&checksql,0,sizeof(pc_type_checksql));
		sprintf(checksql.enc1,"ALTER TABLE %s.%s DROP CONSTRAINT %s"
				,SchemaName,TabInfo.renamed_tab_name,PetraNamePool->getName(checksql_tmp->constraint_name));
		sprintf(checksql.org1,"ALTER TABLE %s.%s ADD CONSTRAINT %s check %s"
				,SchemaName,TabInfo.org_renamed_tab_name,PetraNamePool->getName(checksql_tmp->constraint_name),checksql_tmp->search_condition);
                CheckSqlRows.add();
                CheckSqlRows.next();
                memcpy(CheckSqlRows.data(),&checksql,sizeof(pc_type_checksql));
        }
        delete sql_stmt;
        e=EXCEPTnC;
        if (e) {
                delete e;
        }
        //
        // unique constraint create (enc_column and non enc_column)
        //
        memset(sql_text,0,2048);
        sprintf(sql_text,
"select distinct constraint_name "
"from   pct_enc_col_ct "
"where  constraint_type =4 "
"and    enc_tab_id=%lld",TabInfo.enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        const_name=0;
        while ((const_name=(dgt_sint64*)sql_stmt->fetch())) {
                memset(sql_text,0,2048);
		sprintf(sql_text,
"select a.constraint_name, b.column_name, b.renamed_col_name, b.status, a.position "
"from   pct_enc_col_ct a, pct_enc_column b "
"where  a.enc_col_id = b.enc_col_id "
"and    a.enc_tab_id = %lld "
"and    constraint_name = %lld "
"order by a.position",TabInfo.enc_tab_id,*const_name);
		DgcSqlStmt* sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        	        DgcExcept*      e=EXCEPTnC;
	                delete sql_stmt;
        	        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	        }
		typedef struct {
			dgt_uint64  constraint_name;
			dgt_schar	column_name[130];
			dgt_schar	renamed_col_name[130];
			dgt_uint8	status;
			dgt_uint8	position;
		} uniq_type;
		uniq_type* uniq_tmp=0;
		dgt_sint32 seq=1;
		dgt_schar uniqueSql[512];
		dgt_schar uniqueSql2[512];
		memset(uniqueSql,0,512);
		memset(uniqueSql2,0,512);
		while ((uniq_tmp=(uniq_type*)sql_stmt->fetch())) {
			if (seq == 1) {
				if (uniq_tmp->status == 0) {
			                sprintf(uniqueSql,"ALTER TABLE %s.%s ADD UNIQUE(%s",SchemaName,TabInfo.renamed_tab_name,
        			                                                                          uniq_tmp->column_name);
               				sprintf(uniqueSql2,"ALTER TABLE %s.%s_%lld ADD UNIQUE(%s",SchemaName,"petra",TabInfo.enc_tab_id,
	                                                                                  uniq_tmp->column_name);
				} else {
		                	sprintf(uniqueSql,"ALTER TABLE %s.%s ADD UNIQUE(%s",SchemaName,TabInfo.renamed_tab_name,
	        		                                                                          uniq_tmp->column_name);
               				sprintf(uniqueSql2,"ALTER TABLE %s.%s_%lld ADD UNIQUE(%s",SchemaName,"petra",TabInfo.enc_tab_id,
	                                                                                  uniq_tmp->column_name);
				}
			} else {
				if (uniq_tmp->status == 0) {
                                        strcat(uniqueSql,", ");
                                        strcat(uniqueSql,uniq_tmp->column_name);
                                        strcat(uniqueSql2,", ");
                                        strcat(uniqueSql2,uniq_tmp->column_name);
                                } else {
                                        strcat(uniqueSql,", ");
                                        strcat(uniqueSql,uniq_tmp->column_name);
                                        strcat(uniqueSql2,", ");
                                        strcat(uniqueSql2,uniq_tmp->column_name);
                                }
			}
			seq++;
		}
		strcat(uniqueSql,")");
		strcat(uniqueSql2,")");
       	        UniqueSqlRows1.add();
               	UniqueSqlRows1.next();
                memcpy(UniqueSqlRows1.data(),uniqueSql,strlen(uniqueSql));
		UniqueSqlRows2.add();
		UniqueSqlRows2.next();
                memcpy(UniqueSqlRows2.data(),uniqueSql2,strlen(uniqueSql2));
		delete sql_stmt;
		e=EXCEPTnC;
		if (e) {
			delete e;
		}
	}
	delete sql_stmt;
	e=EXCEPTnC;
	if (e) {
		delete e;
	}

        CheckSqlRows.rewind();
        DefFkDropSqlRows.rewind();
        DefFkDropSqlRows2.rewind();
        DefFkCreSqlRows2.rewind();
        DefFkCreSqlRows3.rewind();
        DefTabDropSqlRows.rewind();
        UniqueSqlRows1.rewind();
        UniqueSqlRows2.rewind();
	return 1;
}

dgt_schar* PccPostgresScriptBuilder::getFname(dgt_sint64 enc_col_id,dgt_uint8 fun_type,dgt_uint8 instead_of_trigger_flag) throw(DgcExcept)
{
        memset(fname,0,512);
        ColInfoRows2.rewind();
        pc_type_col_info* col_info;

	DgcSqlStmt* sql_stmt=0;
        dgt_schar   sql_text[2048];

        //
        // fun_type : 1=encrypt function name
        //            2=decrypt function name
        //
	while (ColInfoRows2.next() && (col_info=(pc_type_col_info*)ColInfoRows2.data())) {
		if (col_info->enc_col_id!=enc_col_id) continue;
		
		// get enc_tab_name, enc_col_name
		memset(sql_text, 0, sizeof(sql_text));
		sprintf(sql_text,"select t.table_name, c.column_name from pct_enc_table t, pct_enc_column c "
				 "where c.enc_col_id = %lld and t.enc_tab_id = c.enc_tab_id",col_info->enc_col_id);
		sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
		if (sql_stmt == 0 || sql_stmt->execute() < 0) {
			delete sql_stmt;
			continue;
		}
		dgt_schar enc_name[260] = {0};
		typedef struct pc_type_enc_name {
			dgt_schar	tab_name[130];
			dgt_schar	col_name[130];
		} pc_type_enc_name;
		pc_type_enc_name*	row_ptr;
		if ((row_ptr=(pc_type_enc_name*)sql_stmt->fetch())) {
			sprintf(enc_name,"%s.%s", row_ptr->tab_name, row_ptr->col_name);
		}
		delete sql_stmt;

		// set fname 
		if (fun_type == 1) {
			if (instead_of_trigger_flag) {
				if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
					sprintf(fname,"pca_encrypt(coalesce(:new.%s,%s), '%s')", 
						col_info->col_name,PetraNamePool->getNameString(col_info->col_default), enc_name);
				} else {
					sprintf(fname,"pca_encrypt(:new.%s,'%s')",col_info->col_name,enc_name);	
				}
			} else {
				if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
					sprintf(fname,"pca_encrypt(coalesce(%s,%s), '%s')", 
						col_info->col_name,PetraNamePool->getNameString(col_info->col_default), enc_name);
				} else {
					sprintf(fname,"pca_encrypt(%s,'%s')",col_info->col_name,enc_name);	
				}
			}
		} else if (fun_type == 2) {
			if (TabInfo.cast_flag == 0) {
				sprintf(fname,"pca_decrypt(%s,'%s')",col_info->col_name,enc_name);
			} else {
				if (!strcasecmp(col_info->data_type,"numeric")) {
					dgt_schar type[128];
					memset(type,0,128);
					if (col_info->data_precision && col_info->data_scale) {
						sprintf(fname,"(%d,%d)", col_info->data_precision, col_info->data_scale);
					} else if (col_info->data_precision) {
						sprintf(fname,"(%d)", col_info->data_precision);
					}
					sprintf(fname,"cast(pca_decrypt(%s,'%s') as %s%.*s)", col_info->col_name, enc_name, col_info->data_type,
							(dgt_sint32)strlen(type), type);
				} else if (!strncasecmp(col_info->data_type,"time",4)) {
					sprintf(fname,"cast(pca_decrypt(%s,'%s') as %s)", col_info->col_name, enc_name, col_info->data_type);
				} else if (col_info->data_length) {
                                               sprintf(fname,"cast(pca_decrypt(%s,'%s') as %s(%d))",col_info->col_name, enc_name, col_info->data_type,
							col_info->data_length);
				} else {
                                               sprintf(fname,"cast(pca_decrypt(%s,'%s') as %s)",col_info->col_name, enc_name, col_info->data_type);
				}
			}
		}
       }
       return fname;
}


#include "PciCryptoIf.h"

dgt_sint32 PccPostgresScriptBuilder::insteadOfTrigger(dgt_sint8 is_final,dgt_sint32 uniq_flag) throw(DgcExcept)
{
        //
        // create a instead-of trigger for the view so for any DML on the view
        // to be reflected on the original table.
        // but the original column is still kepted for emergency recovery.
        //

	//
	// if TabInfo.org_col_name_flag = 1 then use dbms_sql
	// else update all columns
	//
	dgt_uint8 use_dbms_sql=TabInfo.org_col_name_flag;
        *TextBuf=0;
	*TmpBuf=0;
	if (TabInfo.user_view_flag == 1 || (TabInfo.double_flag && IdxColRows.numRows() == 0)) {
	        sprintf(TextBuf,"CREATE TRIGGER %s \nINSTEAD OF INSERT OR UPDATE ON %s.%s FOR EACH ROW \nDECLARE",
	                        TabInfo.view_trigger_name, SchemaName, TabInfo.first_view_name);
	} else {
	        sprintf(TextBuf,"CREATE TRIGGER %s \nINSTEAD OF INSERT OR UPDATE ON %s.%s FOR EACH ROW \nDECLARE",
	                        TabInfo.view_trigger_name, SchemaName, TabInfo.second_view_name);
	}

	*TmpBuf=0;
	if (use_dbms_sql == 1) {
		sprintf(TmpBuf,"\n\t v_sql_main varchar2(30000) := null;"
			       "\n\t v_sql_set varchar2(30000) := null;"
			       "\n\t v_cursor pls_integer;"
			       "\n\t v_ret pls_integer;\n");
		strcat(TextBuf,TmpBuf);
		if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
			*TmpBuf=0;
			sprintf(TmpBuf,"\n\t v_sql_main2 varchar2(30000) := null;"
	                               "\n\t v_sql_set2 varchar2(30000) := null;"
        	                       "\n\t v_cursor2 pls_integer;"
                	               "\n\t v_ret2 pls_integer;\n");
			strcat(TextBuf,TmpBuf);
		}
	}
        ColInfoRows.rewind();
        pc_type_col_info*       col_info;
	//
	// for 11g trigger (performance issue)
	//
	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		if (col_info->status == 5) continue;
		if (col_info->status >= 1 && col_info->status < 3) {
                	dgt_sint32      enc_len = 0;
			if (!strcasecmp(col_info->data_type,"date") || !strncasecmp(col_info->data_type,"time",4)) enc_len = 24;
			else if (col_info->data_precision) enc_len = col_info->data_precision + 2;
			else if (col_info->multi_byte_flag) enc_len = col_info->data_length * 3;
			else enc_len = col_info->data_length;
                	PCI_Context     ctx;
                        PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type, col_info->enc_mode,
                        		col_info->iv_type, col_info->n2n_flag, col_info->b64_txt_enc_flag,
                                       	col_info->enc_start_pos, col_info->enc_length);
	                enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
			*TmpBuf=0;
			sprintf(TmpBuf,"\t v_%s character varying(%d);\n", col_info->col_name, enc_len);
			strcat(TextBuf,TmpBuf);
		}
		*TmpBuf=0;
		if (use_dbms_sql == 1) {
			sprintf(TmpBuf,"\t v_%d character varying(1);\n",col_info->column_order);
			strcat(TextBuf,TmpBuf);
		}
	}
	strcat(TextBuf,"BEGIN");
	//
	// for check constraint
	//
	CheckTrgRows.rewind();
	typedef struct {
		dgt_schar	search_condition[4000];
		dgt_schar	default_val[4000];
	} type_check;
        type_check*    tmp_search=0;
        while(CheckTrgRows.next() && (tmp_search=(type_check*)CheckTrgRows.data())) {
		if (strlen(tmp_search->default_val) > 2 && strstr(tmp_search->search_condition,"IS NOT NULL")) continue;
		*TmpBuf=0;
		sprintf(TmpBuf,"\n IF NOT ");
		strcat(TextBuf,TmpBuf);
		*TmpBuf=0;
		sprintf(TmpBuf,"(:new.%s",tmp_search->search_condition + 1); // (val < 1000) -> (:new.val < 1000)
//		sprintf(TmpBuf,"(:new.%s)",tmp_search->search_condition);
		strcat(TextBuf,TmpBuf);
		*TmpBuf=0;
		sprintf(TmpBuf," THEN\n\t RAISE EXCEPTION 'new row for relation \"%s\" violates check constraint %s';\n END IF;", TabInfo.table_name, tmp_search->search_condition);
		strcat(TextBuf,TmpBuf);
	}
        *TmpBuf=0;
	sprintf(TmpBuf,"\n   IF inserting THEN\n");
        strcat(TextBuf,TmpBuf);
	*TmpBuf=0;
	ColInfoRows.rewind();
	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		*TmpBuf=0;
		if (col_info->status == 5) continue;
		if (col_info->status >= 1 && col_info->status < 3) {
			sprintf(TmpBuf,"\t\t v_%s := %s;\n",col_info->col_name,getFname(col_info->enc_col_id,1,1));
			strcat(TextBuf,TmpBuf);
		}
	} 
	//
	// dual sync mode (keep_org_tab_flag == 1) 
	//
	if (TabInfo.keep_org_tab_flag == 1) {
	        *TmpBuf=0;
	        sprintf(TmpBuf,"\t\tINSERT INTO %s.%s(",SchemaName, TabInfo.org_renamed_tab_name);
	        strcat(TextBuf,TmpBuf);
        	ColInfoRows.rewind();
	        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
        	        *TmpBuf=0;
                	sprintf(TmpBuf,"%s,",col_info->col_name);
	                strcat(TextBuf,TmpBuf);
        	}
	        TextBuf[strlen(TextBuf)-1]=0;
        	strcat(TextBuf,")\n\t\tVALUES(");
	        ColInfoRows.rewind();
        	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
			if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
				*TmpBuf=0;
				sprintf(TmpBuf,"coalesce(:new.%s,%s),",col_info->col_name,PetraNamePool->getNameString(col_info->col_default));
				strcat(TextBuf,TmpBuf);
			} else {
				*TmpBuf=0;
				sprintf(TmpBuf,":new.%s,",col_info->col_name);
				strcat(TextBuf,TmpBuf);
			}
        	}
	        TextBuf[strlen(TextBuf)-1]=0;
        	*TmpBuf=0;
        	sprintf(TmpBuf,");\n");
	        strcat(TextBuf,TmpBuf);
	}
	*TmpBuf=0;
	if (TabInfo.enc_type == 0) {
		sprintf(TmpBuf,"\t\tINSERT INTO %s.%s(",SchemaName, TabInfo.renamed_tab_name);
	} else {
		sprintf(TmpBuf,"\t\tINSERT INTO %s.%s(",SchemaName, TabInfo.table_name);
	}
	strcat(TextBuf,TmpBuf);
	
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		if (col_info->status == 5) continue;
                if (col_info->status >= 1 && col_info->status < 3 && is_final) continue;
                *TmpBuf=0;
                sprintf(TmpBuf,"%s,",col_info->col_name);
                strcat(TextBuf,TmpBuf);
        }
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		if (col_info->status == 5) continue;
                if (col_info->status >= 1 && col_info->status < 3) {
                        *TmpBuf=0;
	                sprintf(TmpBuf,"%s,",col_info->col_name);
        	        strcat(TextBuf,TmpBuf);
                        *TmpBuf=0;
                }
        }
        TextBuf[strlen(TextBuf)-1]=0;
        strcat(TextBuf,")\n\tVALUES(");
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		if (col_info->status == 5) continue;
                if (col_info->status >= 1 && col_info->status < 3 && is_final) continue;
                        if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
                                *TmpBuf=0;
                                sprintf(TmpBuf,"coalesce(:new.%s,%s),",col_info->col_name,PetraNamePool->getNameString(col_info->col_default));
                                strcat(TextBuf,TmpBuf);
                        } else {
                                *TmpBuf=0;
                                sprintf(TmpBuf,":new.%s,",col_info->col_name);
                                strcat(TextBuf,TmpBuf);
                        }
        }
        ColInfoRows.rewind();
        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		if (col_info->status == 5) continue;
                if (col_info->status >= 1 && col_info->status < 3) {
                        dgt_sint32 idx_flag=col_info->index_type;
                        *TmpBuf=0;
	                sprintf(TmpBuf,"v_%s,",col_info->col_name);
        	        strcat(TextBuf,TmpBuf);
                        *TmpBuf=0;
                }
        }
        TextBuf[strlen(TextBuf)-1]=0;
        *TmpBuf=0;
        sprintf(TmpBuf,");\n   ELSIF updating THEN");
        strcat(TextBuf,TmpBuf);

	if (use_dbms_sql == 1) {
		*TmpBuf=0;
		if (TabInfo.enc_type == 0) {
			sprintf(TmpBuf,"\n\t\tv_sql_main := 'UPDATE %s.%s SET ';", SchemaName, TabInfo.renamed_tab_name);
		} else {
			sprintf(TmpBuf,"\n\t\tv_sql_main := 'UPDATE %s.%s SET ';", SchemaName, TabInfo.table_name);
		}
		strcat(TextBuf,TmpBuf);
		if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
			*TmpBuf=0;
			sprintf(TmpBuf,"\n\t\tv_sql_main2 := 'UPDATE %s.%s SET ';", SchemaName, TabInfo.org_renamed_tab_name);
			strcat(TextBuf,TmpBuf);
		}
        	ColInfoRows.rewind();
	        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
			if (col_info->status == 5) continue;
        	        if (col_info->status >= 1 && col_info->status < 3) continue;
                        *TmpBuf=0;
			if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
			        sprintf(TmpBuf,"\n\t\tIF OLD.%s IS DISTINCT FROM NEW.%s THEN "
					       "\n\t\t\t v_%d := 'Y'; "
					       "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
					       "\n\t\t\t v_sql_set2 := v_sql_set2 || '%s=:d%d,';",
               			               col_info->col_name, col_info->col_name, col_info->column_order,
                                               col_info->col_name, col_info->column_order,
					       col_info->col_name, col_info->column_order);
			} else {
			        sprintf(TmpBuf,"\n\t\tIF OLD.%s IS DISTINCT FROM NEW.%s THEN "
					       "\n\t\t\t v_%d := 'Y'; "
					       "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';",
               			               col_info->col_name, col_info->col_name, col_info->column_order,
               			               col_info->col_name, col_info->column_order);
			}
	                strcat(TextBuf,TmpBuf);
        	        *TmpBuf=0;
        	        sprintf(TmpBuf,"\n\t\tEND IF;");
                	strcat(TextBuf,TmpBuf);
	        }
	        ColInfoRows.rewind();
        	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
			if (col_info->status == 5) continue;
                	if (col_info->status >= 1 && col_info->status < 3) {
				*TmpBuf=0;
				if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
	                        	sprintf(TmpBuf,"\n\t\tIF OLD.%s IS DISTINCT FROM NEW.%s THEN "
        	                        	       "\n\t\t\t v_%d := 'Y'; "
	        	                               "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
	        	                               "\n\t\t\t v_sql_set2 := v_sql_set2 || '%s=:d%d,';"
						       "\n\t\t\t v_%s := %s;",
                	        	               col_info->col_name, col_info->col_name, col_info->column_order,
						       col_info->col_name, col_info->column_order,
						       col_info->col_name, col_info->column_order,
						       col_info->col_name, getFname(col_info->enc_col_id,1,1));
				} else {
	                        	sprintf(TmpBuf,"\n\t\tIF OLD.%s IS DISTINCT FROM NEW.%s THEN "
        	                        	       "\n\t\t\t v_%d := 'Y'; "
	        	                               "\n\t\t\t v_sql_set := v_sql_set || '%s=:d%d,';"
						       "\n\t\t\t v_%s := %s;",
                	        	               col_info->col_name, col_info->col_name, col_info->column_order,
                	        	               col_info->col_name, col_info->column_order, 
						       col_info->col_name, getFname(col_info->enc_col_id,1,1));
				}
	                        strcat(TextBuf,TmpBuf);
        	                *TmpBuf=0;
                	        sprintf(TmpBuf,"\n\t\tEND IF;");
                        	strcat(TextBuf,TmpBuf);
			}
		
        	}
        	*TmpBuf=0;
		if (TabInfo.double_flag && IdxColRows.numRows() == 0) {
			sprintf(TmpBuf,"\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, length(v_sql_set)-1 );"
				       "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' WHERE ctid = ''' || :old.ctid || '''';"
				       "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
        	                       "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, DBMS_SQL.NATIVE);");
		} else {
			IdxColRows.rewind();
			if (IdxColRows.numRows() == 0) {
				sprintf(TmpBuf,"\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, length(v_sql_set)-1 );"
					       "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' WHERE ctid = ''' || :old.ctid || '''';"
					       "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
        		                       "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, DBMS_SQL.NATIVE);");
			} else {
				dgt_schar* col_name=0;
				dgt_sint32 seq=0;
				dgt_schar where_clause[512];
				dgt_schar tmp_clause[128];
				memset(where_clause,0,512);
				memset(tmp_clause,0,128);
				while (IdxColRows.next() && (col_name=(dgt_schar*)IdxColRows.data())) {
					seq++;
					if (seq == 1) {
						sprintf(tmp_clause," WHERE %s = :r%d",col_name,seq);
					} else {
						sprintf(tmp_clause," and %s = :r%d",col_name,seq);
					}
					strcat(where_clause,tmp_clause);
				}
				if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) { 
					sprintf(TmpBuf,"\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, length(v_sql_set)-1 );"
        	                                       "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' %s';"
                	                               "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                        	                       "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, DBMS_SQL.NATIVE);"
						       "\n\t\tv_sql_set2 := SUBSTR(v_sql_set2, 1, length(v_sql_set2)-1 );"
                                                       "\n\t\tv_sql_main2 := v_sql_main2 || v_sql_set2 || ' %s';"
                                                       "\n\t\tv_cursor2 := DBMS_SQL.OPEN_CURSOR;"
                                                       "\n\t\tDBMS_SQL.PARSE(v_cursor2, v_sql_main2, DBMS_SQL.NATIVE);"
							, where_clause, where_clause);
				} else {
					sprintf(TmpBuf,"\n\t\tv_sql_set := SUBSTR(v_sql_set, 1, length(v_sql_set)-1 );"
        	                                       "\n\t\tv_sql_main := v_sql_main || v_sql_set || ' %s';"
                	                               "\n\t\tv_cursor := DBMS_SQL.OPEN_CURSOR;"
                        	                       "\n\t\tDBMS_SQL.PARSE(v_cursor, v_sql_main, DBMS_SQL.NATIVE);", where_clause);
				}
			}
		}
		strcat(TextBuf,TmpBuf);
        	*TmpBuf=0;
		ColInfoRows.rewind();
		while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        *TmpBuf=0;
                        if (col_info->status == 5) continue;
                        if (col_info->status >= 1 && col_info->status < 3) {
				if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
					if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
							       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', v_%s);"
							       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, ':d%d', coalesce(:new.%s,%s));"
							       "\n\t\tEND IF;", col_info->column_order, col_info->column_order, col_info->col_name,
									        col_info->column_order, col_info->col_name, 
										PetraNamePool->getNameString(col_info->col_default));
					} else {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
							       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', v_%s);"
							       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, ':d%d', :new.%s);"
							       "\n\t\tEND IF;", col_info->column_order, col_info->column_order, col_info->col_name,
										col_info->column_order, col_info->col_name);
					}
					strcat(TextBuf,TmpBuf);
				} else {
					sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
						       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', v_%s);"
						       "\n\t\tEND IF;", col_info->column_order, col_info->column_order, col_info->col_name);
					strcat(TextBuf,TmpBuf);
				}
                        } else {
				if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
					if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', coalesce(:new.%s,%s));"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, ':d%d', coalesce(:new.%s,%s));"
                		                               "\n\t\tEND IF;", col_info->column_order, col_info->column_order,
										col_info->col_name, PetraNamePool->getNameString(col_info->col_default),
										col_info->column_order, col_info->col_name,
										PetraNamePool->getNameString(col_info->col_default));
					} else {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', coalesce(:new.%s,%s));"
                		                               "\n\t\tEND IF;", col_info->column_order, col_info->column_order,
										col_info->col_name, PetraNamePool->getNameString(col_info->col_default));
						
					}
				} else {
					if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', :new.%s);"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor2, ':d%d', :new.%s);"
                		                               "\n\t\tEND IF;", col_info->column_order, col_info->column_order, col_info->col_name,
										col_info->column_order, col_info->col_name);
					} else {
						sprintf(TmpBuf,"\n\t\tIF V_%d = 'Y' THEN"
        		                                       "\n\t\tDBMS_SQL.BIND_VARIABLE (v_cursor, ':d%d', :new.%s);"
                		                               "\n\t\tEND IF;", col_info->column_order, col_info->column_order, col_info->col_name);
					}
				}
                                strcat(TextBuf,TmpBuf);
			}
                }
		*TmpBuf=0;
	        sprintf(TmpBuf,"\n\t\tv_ret := DBMS_SQL.EXECUTE (v_cursor);"
			       "\n\t\tDBMS_SQL.CLOSE_CURSOR (v_cursor);");
		strcat(TextBuf,TmpBuf);
		if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
			*TmpBuf=0;
		        sprintf(TmpBuf,"\n\t\tv_ret2 := DBMS_SQL.EXECUTE (v_cursor2);"
				       "\n\t\tDBMS_SQL.CLOSE_CURSOR (v_cursor2);");
			strcat(TextBuf,TmpBuf);
		}
	       strcat(TextBuf,"\n\tEND IF;\nEND;");
        	if (saveSqlText() < 0) {
                	ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
		}
	} else {
		ColInfoRows.rewind();
		while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {	
			*TmpBuf=0;
			if (col_info->status == 5) continue;
			if (col_info->status >= 1 && col_info->status < 3) {
				sprintf(TmpBuf,"\n\t v_%s := %s;",col_info->col_name,
								  getFname(col_info->enc_col_id,1,1));
				strcat(TextBuf,TmpBuf);
			}
			*TmpBuf=0;
		}
	        *TmpBuf=0;
		if (TabInfo.enc_type == 0) {
	        	sprintf(TmpBuf,"\n\tUPDATE %s.%s SET\n",SchemaName,TabInfo.renamed_tab_name);
		} else {
	        	sprintf(TmpBuf,"\n\tUPDATE %s.%s SET\n",SchemaName,TabInfo.table_name);
		}
	        strcat(TextBuf,TmpBuf);
		ColInfoRows.rewind();
	        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
			if (col_info->status == 5) continue;
        	        if (col_info->status >= 1 && col_info->status < 3 && is_final) {
                        	*TmpBuf=0;
		               	sprintf(TmpBuf,"\n\t\t%s=v_%s,",col_info->col_name, col_info->col_name);
				strcat(TextBuf,TmpBuf);
			} else {
                		*TmpBuf=0;
				if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
			                sprintf(TmpBuf,"\n\t\t%s=coalesce(:new.%s,%s),",col_info->col_name,col_info->col_name,PetraNamePool->getNameString(col_info->col_default));
        			        strcat(TextBuf,TmpBuf);
				} else {
		        	        sprintf(TmpBuf,"\n\t\t%s=:new.%s,",col_info->col_name,col_info->col_name);
        			        strcat(TextBuf,TmpBuf);
				}
			}
	        }
        	TextBuf[strlen(TextBuf)-1]=0;
	        strcat(TextBuf,"\n      WHERE ctid = ''' || :old.ctid || '''';");
                *TmpBuf=0;
		if (TabInfo.keep_org_tab_flag == 1 && IdxColRows.numRows() > 0) {
                        sprintf(TmpBuf,"\n\tUPDATE %s.%s SET\n",SchemaName,TabInfo.org_renamed_tab_name);
		        strcat(TextBuf,TmpBuf);
        	        ColInfoRows.rewind();
               		while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                        	if (col_info->status == 5) continue;
                        	*TmpBuf=0;
	                        if (col_info->col_default && strlen(PetraNamePool->getNameString(col_info->col_default)) > 0) {
        	                        sprintf(TmpBuf,"\n\t\t%s=coalesce(:new.%s,%s),",col_info->col_name,col_info->col_name,PetraNamePool->getNameString(col_info->col_default));
                	                strcat(TextBuf,TmpBuf);
                        	} else {
	                                sprintf(TmpBuf,"\n\t\t%s=:new.%s,",col_info->col_name,col_info->col_name);
        	                        strcat(TextBuf,TmpBuf);
                	        }
                	}
	                TextBuf[strlen(TextBuf)-1]=0;
        	        strcat(TextBuf,"\n      WHERE ");
                	*TmpBuf=0;
                        IdxColRows.rewind();
			dgt_schar* col_name=0;
			dgt_sint32 seq=0;
			while (IdxColRows.next() && (col_name=(dgt_schar*)IdxColRows.data())) {
				seq++;
				*TmpBuf=0;
				if (seq == 1) {
					sprintf(TmpBuf,"%s = :old.%s ",col_name,col_name);
				} else {
					sprintf(TmpBuf,"\n\t AND %s = :old.%s",col_name,col_name);
				}
				strcat(TextBuf,TmpBuf);
			}
			strcat(TextBuf,";");
                }
        	strcat(TextBuf,"\n   END IF;\nEND;\n");
        	if (saveSqlText() < 0) {
                	ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        }
	}
	return 0;
}

typedef struct {
        dgt_schar org1[512];
        dgt_schar org2[512];
        dgt_schar enc1[512];
        dgt_schar enc2[512];
} pkfk_sql;

dgt_sint32 PccPostgresScriptBuilder::step1() throw(DgcExcept)
{
	//
	// new copy table encryption (non add column)
	//
        // create the copy table (same as original table) 
	//
        pc_type_col_info*       col_info;
        StepNo=1;
        StmtNo=1000;
        *TextBuf=0;
#if 0
	// copy with all constraints except fk
	sprintf(TextBuf,"CREATE TABLE %s.%s (LIKE %s.%s INCLUDING ALL)",
		SchemaName,TabInfo.renamed_tab_name, SchemaName,TabInfo.table_name); 
#else 
	// copy with all constraints excpet fk, index
	sprintf(TextBuf,"CREATE TABLE %s.%s (LIKE %s.%s "
		"INCLUDING DEFAULTS "
		"INCLUDING CONSTRAINTS "
//		"INCLUDING INDEXES "
		"INCLUDING STORAGE "
		"INCLUDING COMMENTS)",
		SchemaName,TabInfo.renamed_tab_name, SchemaName,TabInfo.table_name);
#endif
	if (TabInfo.target_tablespace_name[0]) {
		sprintf(TmpBuf," TABLESPACE %s", TabInfo.target_tablespace_name);
		strcat(TextBuf,TmpBuf);
	}
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}

	*TextBuf=0;
	*TmpBuf=0;
	sprintf(TextBuf,"ALTER TABLE %s.%s OWNER TO %s",SchemaName, TabInfo.renamed_tab_name, SchemaName);
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}
	
	//
	// alter encrypt column
	//
	StmtNo=2000;
	ColInfoRows.rewind();
	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) { 
		if (col_info->status == 1) {
			dgt_sint32	enc_len = 0;
			if (!strcasecmp(col_info->data_type,"date") || !strncasecmp(col_info->data_type,"time",4)) enc_len = 24;
			else if (col_info->data_precision) enc_len = col_info->data_precision + 2;
			else if (col_info->multi_byte_flag) enc_len = col_info->data_length * 3;
			else enc_len = col_info->data_length;
			PCI_Context     	ctx;
			PCI_initContext(&ctx, 0, col_info->key_size, col_info->cipher_type, col_info->enc_mode,
	                        col_info->iv_type, col_info->n2n_flag, col_info->b64_txt_enc_flag,
				col_info->enc_start_pos, col_info->enc_length);
			enc_len = (dgt_sint32)PCI_encryptLength(&ctx, enc_len);
			*TextBuf=0;
			sprintf(TextBuf,"ALTER TABLE %s.%s ALTER COLUMN %s TYPE character varying(%d)",
				SchemaName, TabInfo.renamed_tab_name, col_info->col_name, enc_len);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}

	//
	// insert encrypt data
	//
	StmtNo=6000;
	pc_type_checksql* cksql=0;     
	CheckSqlRows.rewind();
	while(CheckSqlRows.next() && (cksql=(pc_type_checksql*)CheckSqlRows.data())) {
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)cksql->enc1);
		if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
		}
	}

	*TextBuf=0;
	*TmpBuf=0;
	sprintf(TmpBuf,"INSERT INTO %s.%s \n SELECT ",SchemaName, TabInfo.renamed_tab_name);
	strcat(TextBuf,TmpBuf);
	ColInfoRows.rewind();
	while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
		*TmpBuf=0;
		if (col_info->status == 1) {
			sprintf(TmpBuf,"%s,",getFname(col_info->enc_col_id,1));
			strcat(TextBuf,TmpBuf);	
		} else {
			sprintf(TmpBuf,"%s,",col_info->col_name);
			strcat(TextBuf,TmpBuf);	
		}
	}
	TextBuf[strlen(TextBuf)-1]=0;
	*TmpBuf=0;
	sprintf(TmpBuf," FROM %s.%s",SchemaName,TabInfo.table_name);
	strcat(TextBuf,TmpBuf);
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}

	*TextBuf=0;
	sprintf(TextBuf,"COMMIT");
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}

        //
        // grant privilege
        //
	StmtNo=7000;
        *TextBuf=0;
        *TmpBuf=0;
        PrivSqlRows.rewind();
	pc_type_col_priv* priv_sql;
	if (TabInfo.grant_flag) {
		while(PrivSqlRows.next() && (priv_sql=(pc_type_col_priv*)PrivSqlRows.data())) {
			*TextBuf=0;
			if (priv_sql->enc1 && strlen(priv_sql->enc1) > 2) {
				strcpy(TextBuf,priv_sql->enc1);
				if (saveSqlText() < 0) {
					ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
				}
			}
		}
	}
	//
        // create comment
        //
        StmtNo=8000;
        *TextBuf=0;
        *TmpBuf=0;
        CommentInfoRows.rewind();
        pc_type_col_comment* comment_sql;
        while (CommentInfoRows.next() && (comment_sql=(pc_type_col_comment*)CommentInfoRows.data())) {
                *TextBuf=0;
                if (comment_sql->enc1 && strlen(comment_sql->enc1) > 2) {
                        strcpy(TextBuf,comment_sql->enc1);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }

	//
	// create the unique constraint
	//
	StmtNo=9000;
	*TextBuf=0;
	*TmpBuf=0;
	UniqueSqlRows1.rewind();
	dgt_schar* unisql=0;
	while(UniqueSqlRows1.next() && (unisql=(dgt_schar*)UniqueSqlRows1.data())) {
		if (unisql && strlen(unisql) > 2) {
			strcpy(TextBuf,unisql);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}

	//
	// rename original table 
	//
        StmtNo=10000;
	*TextBuf=0;
        *TmpBuf=0;
	sprintf(TextBuf,"ALTER TABLE %s.%s RENAME TO %s",SchemaName,TabInfo.table_name,TabInfo.org_renamed_tab_name);
        if (saveSqlText() < 0) {
                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        }

	return 0;
}

dgt_sint32 PccPostgresScriptBuilder::step2() throw(DgcExcept)
{
	//
	// Create the Constraint (Dependency Fk,Check)
        //
	StepNo=2;
	StmtNo=1000;

	*TextBuf=0;
	*TmpBuf=0;
	DefFkDropSqlRows2.rewind();
	dgt_schar* fkdropsql=0;
	while (DefFkDropSqlRows2.next() && (fkdropsql=(dgt_schar*)DefFkDropSqlRows2.data())) {
		if (fkdropsql && strlen(fkdropsql) > 2) {
			strcpy(TextBuf,fkdropsql);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	if (TabInfo.keep_org_tab_flag == 0) {
		DefFkDropSqlRows.rewind();
		typedef struct {
			dgt_schar enc_sql[512];
			dgt_schar org_sql[512];
		} enc_table_fk;
		enc_table_fk* tmp_ptr=0;
		StmtNo=2000;
		while (DefFkDropSqlRows.next() && (tmp_ptr=(enc_table_fk*)DefFkDropSqlRows.data())) {
			if (tmp_ptr->enc_sql && strlen(tmp_ptr->enc_sql) > 2) {
				strcpy(TextBuf,tmp_ptr->enc_sql);
				if (saveSqlText() < 0) {
					ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
				}
			}
		}
	}

	*TextBuf=0;
        *TmpBuf=0;
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
	// create view or rename encryption table -> original table name
	//
	StmtNo=7000;
	*TextBuf=0;
        *TmpBuf=0;
        if (TabInfo.enc_type == 0) {
                if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
                        sprintf(TextBuf,"CREATE OR REPLACE VIEW %s.%s AS\n SELECT ",SchemaName,TabInfo.first_view_name);
                        ColInfoRows.rewind();
			pc_type_col_info* col_info=0;
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                                *TmpBuf=0;
                                if (col_info->status == 1) {
                                        if (col_info->cipher_type == 4) {
                                                *TmpBuf=0;
	                                        sprintf(TmpBuf,"%s as %s,",col_info->col_name, col_info->col_name);
	                                        strcat(TextBuf,TmpBuf);
                                        } else {
                                                *TmpBuf=0;
	                                       	sprintf(TmpBuf,"%s as %s,", getFname(col_info->enc_col_id,2),col_info->col_name);
        	                    		strcat(TextBuf,TmpBuf);
					}
                                } else {
                                        sprintf(TmpBuf,"%s,",col_info->col_name);
                                        strcat(TextBuf,TmpBuf);
                                }
                        }
                        strcat(TextBuf,"ctid ctid");
                        *TmpBuf=0;
                        sprintf(TmpBuf,"\n   FROM %s.%s", SchemaName, TabInfo.renamed_tab_name);
                        strcat(TextBuf,TmpBuf);
			if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                        *TextBuf=0;
                        sprintf(TextBuf,"CREATE OR REPLACE VIEW %s.%s AS\n SELECT ",SchemaName, TabInfo.second_view_name);
                        ColInfoRows.rewind();
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                                *TmpBuf=0;
                                sprintf(TmpBuf,"%s,",col_info->col_name);
                                strcat(TextBuf,TmpBuf);
                        }
                        TextBuf[strlen(TextBuf)-1]=0;   // cut the last ";" off
                        *TmpBuf=0;
                        sprintf(TmpBuf," FROM %s.%s",SchemaName, TabInfo.first_view_name);
                        strcat(TextBuf,TmpBuf);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                } else {
                        sprintf(TextBuf,"CREATE OR REPLACE VIEW %s.%s AS\n SELECT ",SchemaName,TabInfo.second_view_name);
                        ColInfoRows.rewind();
			pc_type_col_info* col_info=0;
                        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                                *TmpBuf=0;
                                if (col_info->status == 1) {
                                        if (col_info->cipher_type == 4) {
                                                *TmpBuf=0;
	                                	sprintf(TmpBuf,"%s as %s,",col_info->col_name, col_info->col_name);
        	                                strcat(TextBuf,TmpBuf);
                                        } else {
                                                *TmpBuf=0;
	                                       	sprintf(TmpBuf,"%s as %s,", getFname(col_info->enc_col_id,2), col_info->col_name);
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
	                        strcat(TextBuf,",ctid ctid");
        	                *TmpBuf=0;
                	        sprintf(TmpBuf,"\n   FROM %s.%s", SchemaName,TabInfo.renamed_tab_name);
                        	strcat(TextBuf,TmpBuf);
	                	if (saveSqlText() < 0) {
        	                	ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        	        }
			} else {
				*TmpBuf=0;
                                sprintf(TmpBuf,"\n   FROM %s.%s", SchemaName,TabInfo.renamed_tab_name);
                                strcat(TextBuf,TmpBuf);
                                if (saveSqlText() < 0) {
                                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                                }
			}
                }
        } else {
	        sprintf(TextBuf,"ALTER TABLE %s.%s RENAME TO %s",SchemaName,TabInfo.renamed_tab_name,TabInfo.table_name);
        	if (saveSqlText() < 0) {
                	ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        }
	}
	StmtNo=8000;
	*TextBuf=0;
	*TmpBuf=0;
	if (TabInfo.enc_type != 0 && TabInfo.user_view_flag == 1) {
		sprintf(TextBuf,"CREATE OR REPLACE VIEW %s.%s AS\n SELECT ",SchemaName,TabInfo.first_view_name);
                ColInfoRows.rewind();
		pc_type_col_info* col_info=0;
                while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
                	*TmpBuf=0;
                        if (col_info->status == 1) {
                                if (col_info->cipher_type == 4) {
                                	*TmpBuf=0;
	                        	sprintf(TmpBuf,"%s as %s,",col_info->col_name, col_info->col_name);
        	                        strcat(TextBuf,TmpBuf);
                                } else {
                                	*TmpBuf=0;
                        		sprintf(TmpBuf,"%s as %s,", getFname(col_info->enc_col_id,2),col_info->col_name);
	                                strcat(TextBuf,TmpBuf);
				}
                        } else {
                        	sprintf(TmpBuf,"%s,",col_info->col_name);
                                strcat(TextBuf,TmpBuf);
                        }
                }
		IdxColRows.rewind();
		if (IdxColRows.numRows() == 0) {
	                strcat(TextBuf,"ctid ctid");
        	        *TmpBuf=0;
                	sprintf(TmpBuf,"\n   FROM %s.%s", SchemaName,TabInfo.table_name);
	                strcat(TextBuf,TmpBuf);
        	        if (saveSqlText() < 0) {
                		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		} else {
			TextBuf[strlen(TextBuf)-1]=0;
			*TmpBuf=0;
                        sprintf(TmpBuf,"\n   FROM %s.%s", SchemaName,TabInfo.table_name);
                        strcat(TextBuf,TmpBuf);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
		}
	}
	//
	// if plugin view -> create the instead of trigger
	// if dml_trg_flag=yes -> view + dml trigger(must modify update,insert sql`s tablename ex: insert into table -> insert into table$$
	//
	*TmpBuf=0;
	*TextBuf=0;
	StmtNo=9000;
	if (TabInfo.enc_type == 0) {
		if (insteadOfTrigger(1) < 0) {
        	        ATHROWnR(DgcError(SPOS,"insteadOfTigger failed."),-1);
	        }
	}

        //
        // If Pk,Fk Working set table then pk,fk migration
        //
	*TextBuf=0;
        *TmpBuf=0;
	StmtNo=15000;
        pkfk_sql* sql_row;
	FkSqlRows.rewind();
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
	while (PkSqlRows.next() && (sql_row=(pkfk_sql*)PkSqlRows.data())) {
		*TextBuf=0;
		if (sql_row->enc2 && strlen(sql_row->enc2) > 2) {
			strcpy(TextBuf,sql_row->enc2);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
		*TextBuf=0;
		if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
			strcpy(TextBuf,sql_row->enc1);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	FkSqlRows.rewind();
	while (FkSqlRows.next() && (sql_row=(pkfk_sql*)FkSqlRows.data())) {
		*TextBuf=0;
		if (sql_row->enc1 && strlen(sql_row->enc1) > 2) {
			strcpy(TextBuf,sql_row->enc1);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	idxsql* idxsql_type;
	IdxSqlRows.rewind();
	while (IdxSqlRows.next() && (idxsql_type=(idxsql*)IdxSqlRows.data())) {
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)idxsql_type->enc2);
		if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        	}
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)idxsql_type->enc1);
		if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        	}
	}

	//
	// drop original table 
	//
        StmtNo=20000;
	*TextBuf=0;
        *TmpBuf=0;
	if (TabInfo.keep_org_tab_flag == 0) {
		sprintf(TextBuf,"DROP TABLE %s.%s",SchemaName,TabInfo.org_renamed_tab_name);
	        if (saveSqlText() < 0) {
        	        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        }

                typedef struct {
                        dgt_schar       enc_sql[512];
                        dgt_schar       org_sql[512];
                } ref_table_sql;
                ref_table_sql* refsql;
		DefTabDropSqlRows.rewind();
		while (DefTabDropSqlRows.next() && (refsql=(ref_table_sql*)DefTabDropSqlRows.data())) {
			*TextBuf=0;
			sprintf(TextBuf,(dgt_schar*)refsql->enc_sql);
			if (saveSqlText() < 0) {
		                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        		}
		}
	}


	return 0;
}

dgt_sint32 PccPostgresScriptBuilder::reverse_step1() throw(DgcExcept)
{
	StepNo=-1;
	StmtNo=-11000;
	//
	// drop enc table & rename original table
	//
	StmtNo=-1000;
	*TextBuf=0;
	*TmpBuf=0;
	sprintf(TextBuf,"DROP TABLE %s.%s",SchemaName,TabInfo.renamed_tab_name);
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}

	typedef struct {
		dgt_schar       enc_sql[512];
		dgt_schar       org_sql[512];
	} ref_table_sql;
	ref_table_sql* refsql;
	DefTabDropSqlRows.rewind();
	while (DefTabDropSqlRows.next() && (refsql=(ref_table_sql*)DefTabDropSqlRows.data())) {
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)refsql->org_sql);
		if (saveSqlText() < 0) {
			ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
		}
	}

	*TextBuf=0;
	*TmpBuf=0;
	sprintf(TextBuf,"ALTER TABLE %s.%s RENAME TO %s",SchemaName,TabInfo.org_renamed_tab_name,TabInfo.table_name);
	if (saveSqlText() < 0) {
		ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	}
        return 0;
}

dgt_sint32 PccPostgresScriptBuilder::reverse_step2() throw(DgcExcept)
{
	StepNo=-2;
        StmtNo=-17000;
	*TextBuf=0;
	*TmpBuf=0;

        //////////////////////////////////////////////////////////////////////////
	//
	// create the copy table (same as original table)
	//
        //////////////////////////////////////////////////////////////////////////
	if (TabInfo.keep_org_tab_flag == 0) {
		//
		// copy table with all constraint except fk, index 
		//
	        pc_type_col_info* col_info=0;
		sprintf(TextBuf,"CREATE TABLE %s.%s (LIKE %s.%s "
			"INCLUDING DEFAULTS "
			"INCLUDING CONSTRAINTS "
//			"INCLUDING INDEXES "
			"INCLUDING STORAGE "
			"INCLUDING COMMENTS)",
			SchemaName,TabInfo.org_renamed_tab_name,SchemaName,TabInfo.renamed_tab_name);
		if (TabInfo.target_tablespace_name[0]) {
		        sprintf(TmpBuf," TABLESPACE %s",TabInfo.target_tablespace_name);
		        strcat(TextBuf,TmpBuf);
		}
	        if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        }

		*TextBuf=0;
		*TmpBuf=0;
		sprintf(TextBuf,"ALTER TABLE %s.%s OWNER TO %s",SchemaName, TabInfo.org_renamed_tab_name, SchemaName);
		if (saveSqlText() < 0) {
			ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
		}
		
		//
		// alter decrypt column
		//
	        ColInfoRows.rewind();
	        while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
	                if (col_info->status != 1) continue;
			*TextBuf=0;
			*TmpBuf=0;
			dgt_schar type[128];
		        memset(type,0,128);
			if (!strcasecmp(col_info->data_type, "numeric")) {
				if (col_info->data_precision && col_info->data_scale) {
					sprintf(TmpBuf," numeric(%d,%d)", col_info->data_precision, col_info->data_scale);
				}  else if (col_info->data_precision) {
					sprintf(TmpBuf," numeric(%d)", col_info->data_precision);
				} else {
					sprintf(TmpBuf," numeric");
				}
			} else if (!strcasecmp(col_info->data_type, "time with time zone")) {
				if (col_info->data_precision) sprintf(type,"(%d)", col_info->data_precision);
				sprintf(TmpBuf," time%.*s with time zone", (dgt_sint32)strlen(type), type);
			} else if (!strcasecmp(col_info->data_type, "time without time zone")) {
				if (col_info->data_precision) sprintf(type,"(%d)", col_info->data_precision);
				sprintf(TmpBuf," time%.*s without time zone", (dgt_sint32)strlen(type), type);
			} else if (!strcasecmp(col_info->data_type, "timestamp with time zone")) {
				if (col_info->data_precision) sprintf(type,"(%d)", col_info->data_precision);
				sprintf(TmpBuf," timestamp%.*s with time zone", (dgt_sint32)strlen(type), type);
			} else if (!strcasecmp(col_info->data_type, "timestamp without time zone")) {
				if (col_info->data_precision) sprintf(type,"(%d)", col_info->data_precision);
				sprintf(TmpBuf," timestamp%.*s without time zone", (dgt_sint32)strlen(type), type);
			} else if (col_info->data_length) {
				sprintf(TmpBuf," %s(%d)",col_info->data_type, col_info->data_length); 
			} else {
				sprintf(TmpBuf," %s", col_info->data_type);
			}
                       sprintf(TextBuf,"ALTER TABLE %s.%s ALTER COLUMN %s TYPE %s USING %s::%s", SchemaName, TabInfo.org_renamed_tab_name, col_info->col_name, TmpBuf, col_info->col_name, TmpBuf);
			if (*TextBuf && saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
	        }
		//
	        // insert decryption (parallel insert)
	        //
		pc_type_checksql* cksql=0;     
		CheckSqlRows.rewind();
		while(CheckSqlRows.next() && (cksql=(pc_type_checksql*)CheckSqlRows.data())) {
			*TextBuf=0;
			sprintf(TextBuf,(dgt_schar*)cksql->org1);
			if (saveSqlText() < 0) {
		                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}

	        *TextBuf=0;
	        *TmpBuf=0;
		sprintf(TmpBuf,"INSERT INTO %s.%s \n SELECT ",SchemaName,TabInfo.org_renamed_tab_name);
		strcat(TextBuf,TmpBuf);
		ColInfoRows.rewind();
		while(ColInfoRows.next() && (col_info=(pc_type_col_info*)ColInfoRows.data())) {
			*TmpBuf=0;
			if (col_info->status == 1) {
				sprintf(TmpBuf,"%s,",getFname(col_info->enc_col_id,2));
				strcat(TextBuf,TmpBuf);
			} else {
				sprintf(TmpBuf,"%s,",col_info->col_name);
				strcat(TextBuf,TmpBuf);
			} 
		}
		TextBuf[strlen(TextBuf)-1]=0;
		*TmpBuf=0;
		sprintf(TmpBuf," FROM %s.%s",SchemaName,TabInfo.renamed_tab_name);
		strcat(TextBuf,TmpBuf);
		if (saveSqlText() < 0) {
			ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
		}
	        *TextBuf=0;
	        sprintf(TextBuf,"COMMIT");
	        if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	        }
	

	        //
	        // grant privilege
	        //
	        StmtNo=-16000;
	        *TextBuf=0;
	        *TmpBuf=0;
	        PrivSqlRows.rewind();
		pc_type_col_priv* priv_sql;
		if (TabInfo.grant_flag) {
			while(PrivSqlRows.next() && (priv_sql=(pc_type_col_priv*)PrivSqlRows.data())) {
				*TextBuf=0;
				if (priv_sql->org1 && strlen(priv_sql->org1) > 2) {
					strcpy(TextBuf,priv_sql->org1);
					if (saveSqlText() < 0) {
						ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
					}
				}
			}
		}
		//
	        // create comment
	        //
	        *TextBuf=0;
	        *TmpBuf=0;
	        CommentInfoRows.rewind();
	        pc_type_col_comment* comment_sql;
	        while (CommentInfoRows.next() && (comment_sql=(pc_type_col_comment*)CommentInfoRows.data())) {
	                *TextBuf=0;
	                if (comment_sql->org1 && strlen(comment_sql->org1) > 2) {
	                        strcpy(TextBuf,comment_sql->org1);
	                        if (saveSqlText() < 0) {
	                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	                        }
	                }
	        }


	}
	
	//
	// make unique constraint 
	//
        StmtNo=-15000;
	*TextBuf=0;
	*TmpBuf=0;
	UniqueSqlRows2.rewind();
	dgt_schar* unisql=0;
	while(UniqueSqlRows2.next() && (unisql=(dgt_schar*)UniqueSqlRows2.data())) {
		if (unisql && strlen(unisql) > 2) {
			strcpy(TextBuf,unisql);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}

        //
        // Create the Constraint (Pk,Fk,Check)
        //
        *TextBuf=0;
        *TmpBuf=0;
        dgt_schar* pksql=0;
        StmtNo=-2000;
        DefFkDropSqlRows2.rewind();
        dgt_schar* fkdropsql=0;
        while (DefFkDropSqlRows2.next() && (fkdropsql=(dgt_schar*)DefFkDropSqlRows2.data())) {
                if (fkdropsql && strlen(fkdropsql) > 2) {
                        strcpy(TextBuf,fkdropsql);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }
        DefFkDropSqlRows.rewind();
        typedef struct {
                dgt_schar enc_sql[512];
                dgt_schar org_sql[512];
        } enc_table_fk;
        enc_table_fk* tmp_ptr=0;
        while (DefFkDropSqlRows.next() && (tmp_ptr=(enc_table_fk*)DefFkDropSqlRows.data())) {
                if (tmp_ptr->org_sql && strlen(tmp_ptr->org_sql) > 2) {
                        strcpy(TextBuf,tmp_ptr->org_sql);
                        if (saveSqlText() < 0) {
                                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                        }
                }
        }

        *TextBuf=0;
        *TmpBuf=0;
        StmtNo=-1000;
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

	//
	// drop enc table & rename original table
	//
        *TextBuf=0;
        *TmpBuf=0;
        if (TabInfo.enc_type == 0) {
#if 0
		sprintf(TextBuf,"DROP TABLE %s.%s",SchemaName,TabInfo.renamed_tab_name);
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
#endif
		*TextBuf=0;
                sprintf(TextBuf,"DROP VIEW %s.%s",SchemaName,TabInfo.second_view_name);
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
		if (TabInfo.double_flag == 1 && IdxColRows.numRows() == 0) {
			*TextBuf=0;
	                sprintf(TextBuf,"DROP VIEW %s.%s",SchemaName,TabInfo.first_view_name);
        	        if (saveSqlText() < 0) {
                	        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	                }
		}
        } else {
#if 1
                sprintf(TextBuf,"ALTER TABLE %s.%s RENAME TO %s",SchemaName,TabInfo.table_name, TabInfo.renamed_tab_name);
                if (saveSqlText() < 0) {
                        ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
                }
#endif
        }

        //
        // If Pk,Fk Working set table then pk,fk migration
        //
	*TextBuf=0;
        *TmpBuf=0;
        pkfk_sql* sql_row;
	FkSqlRows.rewind();
	while (FkSqlRows.next() && (sql_row=(pkfk_sql*)FkSqlRows.data())) {
		*TextBuf=0;
		if (sql_row->org2 && strlen(sql_row->org2) > 2) {
			strcpy(TextBuf,sql_row->org2);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	PkSqlRows.rewind();
	while (PkSqlRows.next() && (sql_row=(pkfk_sql*)PkSqlRows.data())) {
		*TextBuf=0;
		if (sql_row->org2 && strlen(sql_row->org2) > 2) {
			strcpy(TextBuf,sql_row->org2);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
		*TextBuf=0;
		if (sql_row->org1 && strlen(sql_row->org1) > 2) {
			strcpy(TextBuf,sql_row->org1);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	FkSqlRows.rewind();
	while (FkSqlRows.next() && (sql_row=(pkfk_sql*)FkSqlRows.data())) {
		*TextBuf=0;
		if (sql_row->org1 && strlen(sql_row->org1) > 2) {
			strcpy(TextBuf,sql_row->org1);
			if (saveSqlText() < 0) {
				ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
			}
		}
	}
	idxsql* idxsql_type;
	IdxSqlRows.rewind();
	while (IdxSqlRows.next() && (idxsql_type=(idxsql*)IdxSqlRows.data())) {
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)idxsql_type->org2);
		if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        	}
		*TextBuf=0;
		sprintf(TextBuf,(dgt_schar*)idxsql_type->org1);
		if (saveSqlText() < 0) {
	                ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
        	}
	}

        return 0;
}

PccPostgresScriptBuilder::PccPostgresScriptBuilder(DgcDatabase* db, DgcSession* sess,dgt_schar* schema_link)
	: PccScriptBuilder(db,sess,schema_link), 
          PrivSqlRows(2), 
          CommentInfoRows(2), PkSqlRows(4), FkSqlRows(4), 
          IdxSqlRows(4),
	  IdxColRows(1),
	  CheckTrgRows(2),CheckSqlRows(2),
	  DefFkDropSqlRows(2), DefFkDropSqlRows2(1), DefFkCreSqlRows2(1), DefFkCreSqlRows3(1), DefTabDropSqlRows(2),
	  UniqueSqlRows1(1), UniqueSqlRows2(1) 
{
        PrivSqlRows.addAttr(DGC_SCHR,1024,"org1");
        PrivSqlRows.addAttr(DGC_SCHR,1024,"enc1");

        CommentInfoRows.addAttr(DGC_SCHR,5000,"org1");
        CommentInfoRows.addAttr(DGC_SCHR,5000,"enc1");

        PkSqlRows.addAttr(DGC_SCHR,512,"org1");
        PkSqlRows.addAttr(DGC_SCHR,512,"org2");
        PkSqlRows.addAttr(DGC_SCHR,512,"enc1");
        PkSqlRows.addAttr(DGC_SCHR,512,"enc2");

        FkSqlRows.addAttr(DGC_SCHR,512,"org1");
        FkSqlRows.addAttr(DGC_SCHR,512,"org2");
        FkSqlRows.addAttr(DGC_SCHR,512,"enc1");
        FkSqlRows.addAttr(DGC_SCHR,512,"enc2");

	IdxSqlRows.addAttr(DGC_SCHR,512,"org1");
	IdxSqlRows.addAttr(DGC_SCHR,512,"org2");
	IdxSqlRows.addAttr(DGC_SCHR,512,"enc1");
	IdxSqlRows.addAttr(DGC_SCHR,512,"enc2");

        IdxColRows.addAttr(DGC_SCHR,130,"col_name");

        CheckTrgRows.addAttr(DGC_SCHR,4000,"search_condition");
        CheckTrgRows.addAttr(DGC_SCHR,4000,"default_value");

	CheckSqlRows.addAttr(DGC_SCHR,1024,"org1");
	CheckSqlRows.addAttr(DGC_SCHR,1024,"enc1");

	DefFkDropSqlRows.addAttr(DGC_SCHR,512,"enc_sql");
	DefFkDropSqlRows.addAttr(DGC_SCHR,512,"org_sql");

	DefFkDropSqlRows2.addAttr(DGC_SCHR,512,"sql_id");
	DefFkCreSqlRows2.addAttr(DGC_SCHR,512,"sql_id");
	DefFkCreSqlRows3.addAttr(DGC_SCHR,512,"sql_id");

	DefTabDropSqlRows.addAttr(DGC_SCHR,512,"enc_sql");
	DefTabDropSqlRows.addAttr(DGC_SCHR,512,"org_sql");

	UniqueSqlRows1.addAttr(DGC_SCHR,512,"sql_iq");
	UniqueSqlRows2.addAttr(DGC_SCHR,512,"sql_iq");
}


PccPostgresScriptBuilder::~PccPostgresScriptBuilder()
{
}

dgt_sint32 PccPostgresScriptBuilder::getTablespace(DgcMemRows* rtn_rows) throw(DgcExcept)
{
	if (!getConnection()) {
		ATHROWnR(DgcError(SPOS,"getConnection failed."),-1);
	}
	dgt_schar	sql_text[256];
	sprintf(sql_text,"select spcname, 1 relation from pg_tablespace");
	DgcCliStmt*	stmt=Connection->getStmt();
	if (!stmt) {
		Connection->disconnect();
		ATHROWnR(DgcError(SPOS,"getStmt failed."),-1);
	}
	if (stmt->execute(sql_text,strlen(sql_text),10) < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete stmt;
		Connection->disconnect();
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	DgcAttr*	attr=rtn_rows->attr();
	DgcMemRows*	rows=stmt->returnRows();
        while(rows && rows->numRows() > 0) {
		while(rows->next()) {
			rtn_rows->add();
			rtn_rows->next();
			for(dgt_uint32 i=0; i<rtn_rows->numCols(); i++) {
				dgt_sint32 	rtn=rows->getColData(i+1,(attr+i)->type(),(attr+i)->length(),rtn_rows->getColPtr(i+1));
				if (rtn) {
					DgcExcept*	e=EXCEPTnC;
					delete stmt;
					Connection->disconnect();
					RTHROWnR(e,DgcError(SPOS,"getColData failed."),-1);
				}
			}
		}
		rows->reset();
		if (stmt->fetch(10) < 0) {
			DgcExcept*      e=EXCEPTnC;
			delete stmt;
			Connection->disconnect();
			RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
		}
	}
	delete stmt;
	Connection->disconnect();
	rtn_rows->rewind();
	return 0;
}

dgt_sint32 PccPostgresScriptBuilder::buildScript(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept)
{
	//
	// enc_type = 0 (view)
        // enc_type = 1 (non view)
	//
	VersionNo=version_no;
	if (prepareTabInfo(enc_tab_id) < 0) ATHROWnR(DgcError(SPOS,"prepareTabInfo failed."),-1);
	if (prepareColInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareColInfo failed."),-1);
	if (preparePrivInfo() < 0) ATHROWnR(DgcError(SPOS,"preparePrivInfo failed."),-1);
	//if (prepareObjInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareObjInfo failed."),-1);
	if (prepareIdxInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareIdxInfo failed."),-1);
	if (prepareCommentInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareCommentInfo failed."),-1);
	//if (prepareSynonymInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareSynonymInfo failed."),-1);
	if (prepareCtInfo() < 0) ATHROWnR(DgcError(SPOS,"prepareCtInfo failed."),-1);
	if (prepareCt2Info() < 0) ATHROWnR(DgcError(SPOS,"prepareCt2Info failed."),-1);

        if (step1() < 0) ATHROWnR(DgcError(SPOS,"step1_ins failed."),-1);
        if (step2() < 0) ATHROWnR(DgcError(SPOS,"step2_ins failed."),-1);
        if (reverse_step1() < 0) ATHROWnR(DgcError(SPOS,"reverse step1_ins failed."),-1);
        if (reverse_step2() < 0) ATHROWnR(DgcError(SPOS,"reverse step2_ins failed."),-1);
	return 0;
}

dgt_sint32 PccPostgresScriptBuilder::buildInstallScript(dgt_sint64 agent_id,dgt_schar* agent_uid,dgt_schar* agent_pass,dgt_schar* soha_home) throw(DgcExcept)
{
	TabInfo.enc_tab_id=agent_id;

	//
	// system owner's scripts (step 0 ~ 1)
	//
	delete TextBuf;
	TextBuf=new dgt_schar[64000];
	VersionNo=0;
	StepNo=0;
	StmtNo=0;

	*TextBuf=0;
	sprintf(TextBuf, "CREATE USER %s WITH SUPERUSER PASSWORD '%s'", agent_uid, agent_pass);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0;
	sprintf(TextBuf, "CREATE SCHEMA %s AUTHORIZATION %s", agent_uid, agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0;
	sprintf(TextBuf, "GRANT USAGE ON SCHEMA %s TO PUBLIC", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	
	//
	// cipher owner's scripts (step 2 ~  )
	//
	StepNo=2;
	StmtNo=0;

	/* 1. create fucntion */
	*TextBuf=0;
	sprintf(TextBuf,
		"CREATE OR REPLACE FUNCTION %s.PCA_ENCRYPT(TEXT, TEXT) RETURNS TEXT"
		" as '%s/libPcaPgSql.so', 'pca_encrypt' "
		" LANGUAGE C STRICT", agent_uid, soha_home);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0;
	sprintf(TextBuf,
		"CREATE OR REPLACE FUNCTION %s.PCA_DECRYPT(TEXT, TEXT) RETURNS TEXT"
		" as '%s/libPcaPgSql.so', 'pca_decrypt' "
		" LANGUAGE C STRICT", agent_uid, soha_home);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);

	/* 2. create synonym */
	*TextBuf=0; sprintf(TextBuf,"CREATE OR REPLACE PUBLIC SYNONYM PCA_ENCRYPT FOR %s.PCA_ENCRYPT", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0; sprintf(TextBuf,"CREATE OR REPLACE PUBLIC SYNONYM PCA_DECRYPT FOR %s.PCA_DECRYPT", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);

	
	//
	// uninstall 
	//
	StepNo=-2;
	StmtNo=0;

	*TextBuf=0; sprintf(TextBuf,"DROP PUBLIC SYNONYM PCA_ENCRYPT");
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0; sprintf(TextBuf,"DROP PUBLIC SYNONYM PCA_DECRYPT");
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);

	*TextBuf=0; sprintf(TextBuf,"DROP FUNCTION %s.PCA_ENCRYPT", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	*TextBuf=0; sprintf(TextBuf,"DROP FUNCTION %s.PCA_DECRYPT", agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);
	
	StepNo=-1;
	StmtNo=0;
	*TextBuf=0;
	sprintf(TextBuf,
		"DO $do$"
		" BEGIN"
		"   RAISE NOTICE 'Run a script with superuser"
		"   DROP OWNED BY %s CASCADE;"
		"   DROP USER IF EXISTS %s;';"
		" END;"
		"$do$", agent_uid, agent_uid);
	if (saveSqlText() < 0) ATHROWnR(DgcError(SPOS,"saveSqlText failed."),-1);

	return 0;
}
