/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccMigValidTest
 *   Implementor        :       Mwpark
 *   Create Date        :       2015. 08. 14
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccMigValidTest.h"
#include "DgcSqlHandle.h"

PccMigValidTest::PccMigValidTest(const dgt_schar* name)
	: PccMetaProcedure(name), ItTabRows(2), DictItTabRows(2), ExpItTabRows(2)
{
	ItTabRows.addAttr(DGC_SB8,0,"IT_TAB_ID");
	ItTabRows.addAttr(DGC_SB8,0,"DB_ID");

	DictItTabRows.addAttr(DGC_SB8,0,"IT_TAB_ID");
	DictItTabRows.addAttr(DGC_SB8,0,"DB_ID");

	ExpItTabRows.addAttr(DGC_SB8,0,"IT_TAB_ID");
	ExpItTabRows.addAttr(DGC_SB8,0,"DB_ID");

	ItTabRows.reset();
	DictItTabRows.reset();
	ExpItTabRows.reset();
}

PccMigValidTest::~PccMigValidTest()
{
}

DgcExtProcedure* PccMigValidTest::clone()
{
	return new PccMigValidTest(procName());
}

typedef struct {
	dgt_sint64	it_tab_id;
	dgt_sint64	db_id;
} it_tab_st;

dgt_sint32 PccMigValidTest::setItTabRows() throw(DgcExcept)
{
        DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);
	if (TargetTabID == 0) {
 	       sprintf(sql_text,
"select it_tab_id, db_id "
"from   pct_it_table "
"where  status<=0 "
"order by db_id, it_tab_id");
	} else {
 	       sprintf(sql_text,
"select it_tab_id, db_id "
"from   pct_it_table "
"where  it_tab_id=%lld "
"order by db_id, it_tab_id ",TargetTabID);
	}
        if (sql_handle.execute(sql_text) < 0) {
                DgcExcept* e=EXCEPTnC;
                if (e) {
                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                }
        }
        dgt_void* rtn_row_ptr=0;
        while (1){
                if (sql_handle.fetch(rtn_row_ptr) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                        }
                } else if(rtn_row_ptr) {
                        ItTabRows.add();
                        ItTabRows.next();
                        memcpy(ItTabRows.data(),(it_tab_st*)rtn_row_ptr, sizeof(it_tab_st));
                } else {
                        break;
                }
        }
        ItTabRows.rewind();
        delete EXCEPTnC;
        return 0;	
}

dgt_sint32 PccMigValidTest::validDicExist() throw(DgcExcept)
{
	ItTabRows.rewind();
	it_tab_st*	it_tab_tmp=0;
	dgt_sint64	it_tab_id=0;
	dgt_sint64	db_id=0;
	dgt_sint32	err_flag=0;
	while (ItTabRows.next()) {
		err_flag=0;
		it_tab_tmp=(it_tab_st*)ItTabRows.data();
		it_tab_id=it_tab_tmp->it_tab_id;
		db_id=it_tab_tmp->db_id;
		//
		// target table valid check
		//
        	DgcSqlHandle sql_handle(Session);
	        dgt_schar sql_text[1024];
        	memset(sql_text,0,1024);
	        sprintf(sql_text,
"select a.table_name, b.enc_tab_id "
"from   pct_it_table a, "
      " ceea_table (+) b "
"where  a.it_tab_id = %lld "
"and    a.db_id = b.db_id "
"and    a.schema_name = b.schema_name "
"and    a.table_name  = b.table_name", it_tab_id);
	        if (sql_handle.execute(sql_text) < 0) {
        	        DgcExcept* e=EXCEPTnC;
	                if (e) {
        	                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                	}
	        }
		typedef struct {
			dgt_sint64	table_name;
			dgt_sint64	enc_tab_id;
		} target_table_st;
		target_table_st  target_table;
		memset(&target_table,0,sizeof(target_table_st));
        	dgt_void* rtn_row_ptr=0;
	        if (1) {
        	        if (sql_handle.fetch(rtn_row_ptr) < 0) {
                	        DgcExcept* e=EXCEPTnC;
                        	if (e) {
	                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
        	                }
                	} else if (rtn_row_ptr) {
                	        memcpy(&target_table,(target_table_st*)rtn_row_ptr,sizeof(target_table_st));
	                } else {
        	                break;
                	}
	        }
		if (target_table.enc_tab_id > 0) {
			//	
			// target table exist 
			// column valid check
			//
			memset(sql_text,0,1024);
	                sprintf(sql_text,
"select a.column_name, b.column_name "
"from   pct_it_column a, "
      " ceea_column (+) b "
"where  a.it_tab_id = %lld "
"and    b.enc_tab_id = %lld "
"and    a.column_name = b.column_name", it_tab_id, target_table.enc_tab_id);
			if (sql_handle.execute(sql_text) < 0) {
				DgcExcept* e=EXCEPTnC;
				if (e) {
					RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
				}
			}
			typedef struct {
				dgt_sint64      t_column_name;
				dgt_sint64      c_column_name;
			} target_column_st;
			target_column_st  target_column;
			memset(&target_column,0,sizeof(target_column_st));
			dgt_void* rtn_row_ptr=0;
			while (1){
				if (sql_handle.fetch(rtn_row_ptr) < 0) {
					DgcExcept* e=EXCEPTnC;
					if (e) {
						RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
					}
				} else if (rtn_row_ptr) {
					memcpy(&target_column,(target_column_st*)rtn_row_ptr,sizeof(target_column_st));
					if (target_column.c_column_name == 0) {
						//
						// target column not found
						//
						err_flag=1;
						dgt_schar	err_msg[256];
						memset(err_msg,0,256);
						sprintf(err_msg,"[%s.%s] column not found",PetraNamePool->getNameString(target_table.table_name),
											   PetraNamePool->getNameString(target_column.t_column_name));
						if (logging(it_tab_id, err_msg) < 0) {
							DgcExcept* e=EXCEPTnC;
							if (e) {
	                        			        RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
							}
						}
					}
				} else {
					break;
				}
			}
		} else {
			//	
			// target table not exist
			//
			err_flag=1;
			dgt_schar	err_msg[256];
			memset(err_msg,0,256);
			sprintf(err_msg,"[%s] table not found",PetraNamePool->getNameString(target_table.table_name));
			if (logging(it_tab_id, err_msg) < 0) {
				DgcExcept* e=EXCEPTnC;
				if (e) {
					RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
				}
			}
		}
		//
		// source table valid check
		//
                memset(sql_text,0,1024);
                sprintf(sql_text,
"select a.table_name, b.enc_tab_id, a.is_tab_id "
"from   pct_is_table a, "
      " ceea_table (+) b "
"where  a.it_tab_id = %lld "
"and    a.db_id = b.db_id "
"and    a.schema_name = b.schema_name "
"and    a.table_name  = b.table_name ", it_tab_id);

                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }
                typedef struct {
                        dgt_sint64      table_name;
                        dgt_sint64      enc_tab_id;
                        dgt_sint64      is_tab_id;
                } src_table_st;
                src_table_st  src_table;
                memset(&src_table,0,sizeof(src_table_st));
                rtn_row_ptr=0;
                while (1){
                	memset(&src_table,0,sizeof(src_table_st));
                        if (sql_handle.fetch(rtn_row_ptr) < 0) {
                                DgcExcept* e=EXCEPTnC;
                                if (e) {
                                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                                }
                        } else if (rtn_row_ptr) {
                                memcpy(&src_table,(src_table_st*)rtn_row_ptr,sizeof(src_table_st));
		                if (src_table.enc_tab_id > 0) {
                		        //
                		        // src table exist
		                        // column valid check
                		        //
		                        memset(sql_text,0,1024);
                		        sprintf(sql_text,
"select a.column_name, b.column_name "
"from   pct_is_column a, "
      " ceea_column (+) b "
"where  a.it_tab_id = %lld "
"and    a.is_tab_id = %lld "
"and    b.enc_tab_id = %lld "
"and    a.column_name = b.column_name", it_tab_id, src_table.is_tab_id, src_table.enc_tab_id);
					DgcSqlHandle col_handle(Session);
		                        if (col_handle.execute(sql_text) < 0) {
                		                DgcExcept* e=EXCEPTnC;
                                		if (e) {
		                                        RTHROWnR(e,DgcError(SPOS,"col_handle execute Failed"),-1);
                		                }
		                        }
                		        typedef struct {
		                                dgt_sint64      s_column_name;
                		                dgt_sint64      c_column_name;
		                        } src_column_st;
                		        src_column_st  src_column;
		                        memset(&src_column,0,sizeof(src_column_st));
                		        dgt_void* rtn_row_ptr=0;
		                        while (1){
                		                if (col_handle.fetch(rtn_row_ptr) < 0) {
                                		        DgcExcept* e=EXCEPTnC;
		                                        if (e) {
                		                                RTHROWnR(e,DgcError(SPOS,"col_handle execute failed"),-1);
                                		        }
		                                } else if (rtn_row_ptr) {
                		                        memcpy(&src_column,(src_column_st*)rtn_row_ptr,sizeof(src_column_st));
                                		        if (src_column.c_column_name == 0) {
		                                                //
                		                                // src column not found
                                		                //
		                                                err_flag=1;
                		                                dgt_schar       err_msg[256];
                                		                memset(err_msg,0,256);
		                                                sprintf(err_msg,"[%s.%s] column not found",PetraNamePool->getNameString(src_table.table_name),
                		                                                                           PetraNamePool->getNameString(src_column.s_column_name));
                                		                if (logging(it_tab_id, err_msg) < 0) {
									DgcExcept* e=EXCEPTnC;
									if (e) {
	                                                		        RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
									}
		                                                }
                		                        }
		                                } else {
                		                        break;
                                		}
		                        }
		                } else {
					//
		                        // src table not exist
                		        //
					err_flag=1;
		                        dgt_schar       err_msg[256];
                		        memset(err_msg,0,256);
		                        sprintf(err_msg,"[%s] table not found",PetraNamePool->getNameString(src_table.table_name));
                		        if (logging(it_tab_id, err_msg) < 0) {
						DgcExcept* e=EXCEPTnC;
						if (e) {
       							RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
						}
		                        }
                		}
                        } else {
                                break;
                        }
                }
		if (err_flag == 0) {
			DictItTabRows.add();
			DictItTabRows.next();
			memcpy(DictItTabRows.data(),it_tab_tmp,sizeof(it_tab_st));
		}
	}
        DictItTabRows.rewind();
        delete EXCEPTnC;
	return 0;
}

dgt_sint32 PccMigValidTest::validExpression() throw(DgcExcept)
{
	DictItTabRows.rewind();
	//
	// connect database
	//
        DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);
	dgt_sint64	db_id=0;
	dgt_sint64	it_tab_id=0;
	dgt_sint64	db_agent_id=0;
	it_tab_st*	it_tab_tmp=0;
	if (DictItTabRows.numRows() > 0) {
		if (DictItTabRows.next()) {
			it_tab_tmp=(it_tab_st*)DictItTabRows.data();
			it_tab_id=it_tab_tmp->it_tab_id;
			db_id=it_tab_tmp->db_id;
		}
		if (db_id > 0) {
		       	sprintf(sql_text,
"select db_agent_id "
"from   pct_db_agent "
"where  db_id=%lld",db_id);
        		if (sql_handle.execute(sql_text) < 0) {
                		DgcExcept* e=EXCEPTnC;
		                if (e) {
        		                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                		}
		        }
        		dgt_void* rtn_row_ptr=0;
	        	while (1){
	        	        if (sql_handle.fetch(rtn_row_ptr) < 0) {
        	        	        DgcExcept* e=EXCEPTnC;
	        	                if (e) {
        	        	                RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                	        	}
		                } else if(rtn_row_ptr) {
					memcpy(&db_agent_id,(dgt_sint64*)rtn_row_ptr,sizeof(dgt_sint64));
	        	        } else {
        	        	        break;
	                	}
		        }
			if (db_agent_id == 0) {
				dgt_schar       err_msg[256];
	                	memset(err_msg,0,256);
		                sprintf(err_msg,"not found db_agent_id in PCT_DB_AGENT[db_id=%lld]",db_id);
        		        if (logging(it_tab_id, err_msg) < 0) {
                		        DgcExcept* e=EXCEPTnC;
	                        	if (e) {
		                                RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
        		                }
                		}
				return 0;
			}
		} else {
			dgt_schar       err_msg[256];
			memset(err_msg,0,256);
			sprintf(err_msg,"db_id is 0");
			if (logging(it_tab_id, err_msg) < 0) {
				DgcExcept* e=EXCEPTnC;
				if (e) {
					RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
				}
			}
			return 0;
		}
		//
		// create select sql for business logic validition test
		//
		DictItTabRows.rewind();
		it_tab_tmp=0;
		it_tab_id=0;
		db_id=0;
		PccScriptBuilder*       cipher_builder=getScriptBuilder(db_agent_id,PCC_ID_TYPE_AGENT);
        	if (!cipher_builder) {
	                ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
        	}
		dgt_sint32	err_flag=0;
		if (DictItTabRows.next()) {
			err_flag=0;
			it_tab_tmp=(it_tab_st*)DictItTabRows.data();
			it_tab_id=it_tab_tmp->it_tab_id;
			db_id=it_tab_tmp->db_id;
			//
			// get src table column expression for select list
			//
			if (cipher_builder->migInsertSql(it_tab_id) < 0) {
                		ATHROWnR(DgcError(SPOS,"migInsertSql failed."),-1);
			}
			const dgt_schar* test_sql=cipher_builder->scriptText();
DgcWorker::PLOG.tprintf(0,"test_sql[%s]\n",test_sql);
	        	if (cipher_builder->runScript(test_sql) < 0) {
				err_flag=1;
	        	        DgcExcept*      e=EXCEPTnC;
                		delete cipher_builder;
		                if (e) {
        		                DgcError*       err=e->getErr();
                		        while(err->next()) err=err->next();
					dgt_schar	err_msg[1024];
					memset(err_msg,0,1024);
        	                	sprintf(err_msg,"[%s]",(dgt_schar*)err->message());
			                if (logging(it_tab_id, err_msg) < 0) {
                			        DgcExcept* e=EXCEPTnC;
		                	        if (e) {
                		        	        RTHROWnR(e,DgcError(SPOS,"err logging failed"),-1);
			                        }
        	        		}
	        	        }
				delete e;
			} 
			if (err_flag == 0) {
				ExpItTabRows.add();
				ExpItTabRows.next();
				memcpy(ExpItTabRows.data(),it_tab_tmp,sizeof(it_tab_st));
			}
		}	
	}
        delete EXCEPTnC;
	ExpItTabRows.rewind();
	return 0;
}

dgt_sint32 PccMigValidTest::registMtTabInfo() throw(DgcExcept)
{
	DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
	//
	// migrate table (it->mt, is->mt)
	//
	ExpItTabRows.rewind();
	while (ExpItTabRows.next()) {
		memset(sql_text,0,1024);
        	sprintf(sql_text,
"insert into pct_mt_table(enc_tab_id,it_tab_id,db_id,schema_name,table_name,where_clause,join_clause,schedule_id) "
"select  b.enc_tab_id, "
	"a.it_tab_id, "
	"a.db_id, "
	"a.schema_name, "
	"a.table_name, "
	"a.where_clause, "
	"a.join_clause, "
	"a.schedule_id "
"from    pct_it_table a, "
	"ceea_table b "
"where   a.it_tab_id = %lld "
"and     a.db_id = b.db_id "
"and     a.schema_name = b.schema_name "
"and     a.table_name = b.table_name", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
	        if (sql_handle.execute(sql_text) < 0) {
        	        DgcExcept* e=EXCEPTnC;
                	if (e) {
	                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
        	        }
	        }
		memset(sql_text,0,1024);
	        sprintf(sql_text,
"insert into pct_mt_column(enc_col_id,it_tab_id,enc_tab_id,db_id,schema_name,column_name,map_col_id,col_expression,key_id,column_order) "
"select  d.enc_col_id, "
	"a.it_tab_id, "
	"c.enc_tab_id, "
	"a.db_id, "
	"a.schema_name, "
	"b.column_name, "
	"b.map_col_id, "
	"b.col_expression, "
	"b.key_id, "
	"b.column_order "
"from    pct_it_table a, "
	"pct_it_column b, "
	"ceea_table c, "
	"ceea_column d "
"where   a.it_tab_id = %lld "
"and     a.it_tab_id = b.it_tab_id "
"and     c.enc_tab_id = d.enc_tab_id "
"and     a.db_id = c.db_id "
"and     a.schema_name = c.schema_name "
"and     a.table_name = c.table_name "
"and     b.column_name = d.column_name", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
               	if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }
        	memset(sql_text,0,1024);
	        sprintf(sql_text,
"insert into pct_ms_table(enc_tab_id,it_tab_id,db_id,schema_name,table_name,alias_name,dblink_name) "
"select  b.enc_tab_id, "
	"a.it_tab_id, "
	"a.db_id, "
	"a.schema_name, "
	"a.table_name, "
	"a.alias_name, "
	"a.dblink_name "
"from    pct_is_table a, "
	"ceea_table b "
"where   a.it_tab_id = %lld "
"and     a.db_id = b.db_id "
"and     a.schema_name = b.schema_name "
"and     a.table_name = b.table_name", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }
        	memset(sql_text,0,1024);
	        sprintf(sql_text,
"insert into pct_ms_column(enc_col_id,it_tab_id,enc_tab_id,db_id,schema_name,column_name,col_expression) "
"select c.is_col_id, "
	"a.it_tab_id, "
	"b.enc_tab_id, "
	"a.db_id, "
	"a.schema_name, "
	"c.column_name, "
	"c.col_expression "
"from    pct_is_table a, "
	"pct_ms_table b, "
	"pct_is_column c "
"where   a.it_tab_id = %lld "
"and     a.it_tab_id = b.it_tab_id "
"and     a.db_id = b.db_id "
"and     a.schema_name = b.schema_name "
"and     a.table_name = b.table_name "
"and     a.is_tab_id = c.is_tab_id", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }
        }
        delete EXCEPTnC;
	return 0;
}

dgt_sint32 PccMigValidTest::registEncTabInfo() throw(DgcExcept)
{
        DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        //
        // regist table (pct_enc_schema,pct_enc_table, pct_enc_column)
        //
        ExpItTabRows.rewind();
	while (ExpItTabRows.next()) {
	        memset(sql_text,0,1024);
        	sprintf(sql_text,
"insert into pct_enc_schema(schema_id, last_update, db_id, schema_name) "
"select  nextval('PTS_AID_SEQ'), "
	"nextlastupdate('PCT_ENC_SCHEMA',currval('PTS_AID_SEQ'),1), "
	"mid_tab.db_id, "
	"getname(mid_tab.schema_name) "
"from "
	"( "
	 "select distinct a.db_id db_id, a.schema_name schema_name, b.schema_name c "
	 "from   pct_mt_table   a, "
       	        "pct_enc_schema (+) b "
	 "where  a.it_tab_id = %lld "
	 "and    a.db_id = b.db_id "
	 "and    a.schema_name = getnameid(b.schema_name) "
	") mid_tab "
"where   mid_tab.c = ''", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }
	        memset(sql_text,0,1024);
        	sprintf(sql_text,
"insert into pct_enc_table(enc_tab_id, last_update, schema_id, table_name, tablespace_name) "
"select a.enc_tab_id, "
	"nextlastupdate('PCT_ENC_TABLE',a.enc_tab_id,1), "
	"c.schema_id, "
	"getname(a.table_name), "
	"getname(b.table_space_name) "
"from    pct_mt_table a, "
	"ceea_table b, "
	"pct_enc_schema c "
"where   a.enc_tab_id = b.enc_tab_id "
"and     b.db_id = c.db_id "
"and     b.schema_name = getnameid(c.schema_name) "
"and     a.it_tab_id = %lld", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }

		memset(sql_text,0,1024);
                sprintf(sql_text,
"insert into pct_job(job_id, enc_tab_id, schedule_id, exe_order) "
"select   nextval('PTS_AID_SEQ'), "
	" enc_tab_id, "
	" schedule_id, "
	" 1 "
"from    pct_mt_table "
"where   it_tab_id = %lld", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }


        	memset(sql_text,0,1024);
	        sprintf(sql_text,
"insert into pct_enc_column(enc_col_id,last_update,enc_tab_id,key_id,data_length,data_precision,data_scale,status,column_name,data_type) "
"select b.enc_col_id, "
	"nextlastupdate('PCT_ENC_COLUMN',b.enc_col_id,1), "
	"b.enc_tab_id, "
	"a.key_id, "
	"b.data_length, "
	"b.data_precison, "
	"b.data_scale, "
	"decode(a.key_id,0,0,1) , "
	"getname(b.column_name), "
	"getname(b.data_type) "
"from    pct_mt_column a, "
	"ceea_column b "
"where   a.enc_col_id = b.enc_col_id "
"and     a.it_tab_id = %lld", *(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (e) {
                                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                        }
                }

        	memset(sql_text,0,1024);
		sprintf(sql_text,"insert into pct_enc_col_index(enc_col_id,enc_tab_id,index_name,column_position,"
"index_owner,uniqueness,partitioned,generated,target_tablespace_name, "
"index_type,index_tablespace,logging,degree,column_expression,descend_flag,renamed_index_name1,renamed_index_name2,renamed_org_name1) "
"select a.enc_col_id,a.enc_tab_id,index_name,column_position,index_owner,uniqueness,partitioned,generated,index_tablespace, "
"index_type,index_tablespace,logging,degree,column_expression,descend_flag,getnameid(getname(index_name) || '_n$$'),"
"getnameid(getname(index_name) || '_f$$'),getnameid(getname(index_name) || '$$') "
"from ceea_col_index a, pct_mt_table b "
"where a.enc_tab_id = b.enc_tab_id "
" and  b.it_tab_id = %lld",*(dgt_sint64*)ExpItTabRows.getColPtr(1));
                if (sql_handle.execute(sql_text) < 0) {
			DgcExcept* e=EXCEPTnC;
			if (e) {
				RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
			}
		}
        }
        delete EXCEPTnC;

	return 0;
}

dgt_sint32 PccMigValidTest::updateStatus() throw(DgcExcept)
{
        DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);
	if (TargetTabID) {
	        sprintf(sql_text,
"update pct_it_table set(status)=(-1) where it_tab_id = %lld",TargetTabID);
	} else {
	        sprintf(sql_text,
"update pct_it_table set(status)=(-1) where status <=0");
	}
        if (sql_handle.execute(sql_text) < 0) {
                DgcExcept* e=EXCEPTnC;
                if (e) {
                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                }
        }
        delete EXCEPTnC;
        ExpItTabRows.rewind();
	memset(sql_text,0,1024);
	if (ExpItTabRows.numRows() > 0) {
	        sprintf(sql_text,
"update pct_it_table set(status)=(1) where it_tab_id=:1");
	        if (sql_handle.execute(sql_text,0,&ExpItTabRows) < 0) {
        	        DgcExcept* e=EXCEPTnC;
                	if (e) {
	                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
        	        }
	        }
	}
        return 0;
}


dgt_sint32 PccMigValidTest::clearLogTables() throw(DgcExcept)
{
	ItTabRows.rewind();
        DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);
	if (ItTabRows.numRows() > 0) {
		sprintf(sql_text,
"delete pct_it_error where it_tab_id = :1");
        	if (sql_handle.execute(sql_text,0,&ItTabRows) < 0) {
                	DgcExcept* e=EXCEPTnC;
	                if (e) {
        	                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                	}
	        }
	}
	return 0;
}

dgt_sint32 PccMigValidTest::logging(dgt_sint64 it_tab_id, dgt_schar* err_msg) throw(DgcExcept)
{
	DgcSqlHandle sql_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);
        sprintf(sql_text,
"insert into pct_it_error(it_tab_id, err_msg) values(%lld, '%s')", it_tab_id, err_msg);
        if (sql_handle.execute(sql_text) < 0) {
                DgcExcept* e=EXCEPTnC;
                if (e) {
                        RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                }
        }
	return 0;
}

dgt_sint32 PccMigValidTest::buildScript() throw(DgcExcept)
{
	ExpItTabRows.rewind();
        DgcSqlHandle sql_handle(Session);
	DgcSqlHandle delete_handle(Session);
        dgt_schar sql_text[1024];
        memset(sql_text,0,1024);

	if (ExpItTabRows.numRows() > 0) {
	        sprintf(sql_text,
"select a.enc_tab_id "
"from   pct_mt_table a, "
"       pct_enc_table b "
"where  a.enc_tab_id = b.enc_tab_id "
"and    a.it_tab_id = :1");
        	if (sql_handle.execute(sql_text,0,&ExpItTabRows) < 0) {
                	DgcExcept* e=EXCEPTnC;
	                if (e) {
        	                RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
                	}
	        }
        	dgt_void* rtn_row_ptr=0;
		dgt_sint64	enc_tab_id=0;
        	while (1){
	                if (sql_handle.fetch(rtn_row_ptr) < 0) {
                	        DgcExcept* e=EXCEPTnC;
        	                if (e) {
                	                RTHROWnR(e,DgcError(SPOS,"sql_handle execute failed"),-1);
                        	}
	                } else if(rtn_row_ptr) {
				enc_tab_id=*(dgt_sint64*)rtn_row_ptr;
				
				memset(sql_text,0,1024);
				sprintf(sql_text,"delete pct_script where enc_tab_id =%lld",enc_tab_id);		
        			if (delete_handle.execute(sql_text) < 0) {
		                	DgcExcept* e=EXCEPTnC;
	        		        if (e) {
        	                		RTHROWnR(e,DgcError(SPOS,"sql_handle execute Failed"),-1);
					}
	                	}
				PccScriptBuilder*       cipher_builder=getScriptBuilder(enc_tab_id,PCC_ID_TYPE_TABLE);
        	        	if (!cipher_builder) {
                	        	ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
		                }
        		        if (cipher_builder->buildScriptMig(enc_tab_id,0) < 0) {
   	        		     ATHROWnR(DgcError(SPOS,"buildScriptMig failed."),-1);
	                	}
	                } else {
        	                break;
                	}
	        }
	}
	return 0;
}

dgt_sint32 PccMigValidTest::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	enc_tab_id=0;
	if (!(enc_tab_id=(dgt_sint64*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	TargetTabID=*enc_tab_id;

        if (setItTabRows() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"setItTabRows failed"),-1);
        }
	if (clearLogTables() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"clearLogTables failed"),-1);
	}
        if (validDicExist() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"validDicExist failed"),-1);
        }
        if (validExpression() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"validDicExist failed"),-1);
        }
        if (registMtTabInfo() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"registMtTabInfo failed"),-1);
        }
        if (registEncTabInfo() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"registEncTabInfo failed"),-1);
        }
	if (updateStatus() < 0) {
		DgcExcept* e=EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"updateStatus failed"),-1);
	}
	if (buildScript() < 0) {
                DgcExcept* e=EXCEPTnC;
                RTHROWnR(e,DgcError(SPOS,"buildScript failed"),-1);
	}
	
        ReturnRows->reset();
        ReturnRows->add();
        ReturnRows->next();
        memset(ReturnRows->data(),0,ReturnRows->rowSize());
        sprintf((dgt_schar*)ReturnRows->data(),"validation check success.");
        ReturnRows->rewind();
        return 0;
}
