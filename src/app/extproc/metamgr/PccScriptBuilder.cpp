/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccScriptBuilder
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       script builder
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccScriptBuilder.h"

void check_logger(const char *fmt, ...)
{
    FILE*       fp;
    struct tm*  cl;
    time_t      current;

    if (fmt == NULL) return;
    fp=(FILE*)fopen("/tmp/check_cipher.log","a");
    if (fp == NULL) return;
    time(&current);
    cl=localtime(&current);
    dg_fprint(fp,"\n[%d.%02d.%02d.%02d:%02d:%02d] : ",
                        cl->tm_year+1900,
                        cl->tm_mon+1,
                        cl->tm_mday,
                        cl->tm_hour,
                        cl->tm_min,
                        cl->tm_sec);
    va_list argptr;
    va_start(argptr, fmt);
    dg_vfprintf(fp, fmt, argptr);
    va_end(argptr);
    fflush(fp);
    fclose(fp);
    return;
}

typedef struct {
	dgt_uint16 degree;
	dgt_schar  db_version[33];	
	dgt_sint64 db_id;
} pc_type_dbinfo;

dgt_sint32 PccScriptBuilder::prepareTabInfo(dgt_sint64 enc_tab_id) throw(DgcExcept)
{
	dgt_schar	sql_text[1024];
	sprintf(sql_text,"select * from pct_enc_table where enc_tab_id=%lld",enc_tab_id);
	DgcSqlStmt*	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	pct_type_enc_table*	ti;
	if ((ti=(pct_type_enc_table*)sql_stmt->fetch()) == 0) {
		DgcExcept*	e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
	}
	memcpy(&TabInfo, ti, sizeof(pct_type_enc_table));

	delete sql_stmt;
	//
	// Setting the Parallel Degree, SchemaName, IsPkFk
	//
	sprintf(sql_text,"select max(d.parallel_degree),max(e.db_version),max(c.db_id) from "
			 "pct_enc_table a, pct_enc_schema b, pt_database c, pct_db_agent d, pt_db_instance e "
			 "where a.schema_id = b.schema_id "
			 "and   b.db_id = c.db_id "
			 "and   c.db_id = d.db_id "
			 "and   e.instance_id = d.instance_id "
			// "and   d.parallel_degree != 0 "
			 "and   a.enc_tab_id = %lld",enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        pc_type_dbinfo*      db_info;
        if ((db_info=(pc_type_dbinfo*)sql_stmt->fetch())) {
	        memcpy(&ParallelDegree, &db_info->degree, sizeof(dgt_uint16));
		strncpy(DbVersion, db_info->db_version, 33);
		Dbid=db_info->db_id;
	}
	if (ParallelDegree == 0) {
		ParallelDegree=1;
	}
        delete sql_stmt;

	sprintf(sql_text,"select b.schema_name "
			 "from   pct_enc_table a, pct_enc_schema b "
			 "where  a.schema_id = b.schema_id "
			 "and    a.enc_tab_id =%lld",enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
	dgt_schar*	name_tmp;
        if ((name_tmp=(dgt_schar*)sql_stmt->fetch()) == 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
        }
	memset(SchemaName,0,33);
        strcpy(SchemaName,name_tmp);
        delete sql_stmt;
	
	sprintf(sql_text,"select a.working_set_id "
			 "from   ceea_working_set a, ceea_enc_column b "
			 "where  a.enc_col_id = b.enc_col_id "
			 "and    b.enc_tab_id = %lld",enc_tab_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64*      work_id_tmp;
	dgt_sint64	work_id=0;
        if ((work_id_tmp=(dgt_sint64*)sql_stmt->fetch())) {
		memcpy(&work_id,work_id_tmp,sizeof(dgt_sint64));
        }
        delete sql_stmt;
	sprintf(sql_text,"select count() "
			 "from ceea_working_set a, ceea_enc_column b "
			 "where a.enc_col_id = b.enc_col_id "
			 "and   b.enc_tab_id > %lld "
			 "and   a.working_set_id = %lld",enc_tab_id,work_id);
        sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64*      count_tmp;
        dgt_sint64      count=0;
        if ((count_tmp=(dgt_sint64*)sql_stmt->fetch())) {
        	memcpy(&count,count_tmp,sizeof(dgt_sint64));
	}
        delete sql_stmt;
	if (count == 0) {
		IsPkFk=1;
	} else {
		IsPkFk=0;
	}


	sprintf(sql_text,"select distinct user_name from "
"pct_db_agent a, pct_enc_table b, pct_enc_schema c, pt_database_link_info e "
"where b.schema_id = c.schema_id "
"and   a.db_id = c.db_id "
"and   a.admin_link = e.link_name "
"and   b.enc_tab_id =%lld",enc_tab_id);


	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_schar*      agent_tmp;
        if ((agent_tmp=(dgt_schar*)sql_stmt->fetch())) {
		memset(AgentName,0,33);
        	memcpy(AgentName,agent_tmp,strlen(agent_tmp));
	}
        delete sql_stmt;
//	VersionNo=0;
	return 1;
}

dgt_sint32 PccScriptBuilder::prepareColInfo() throw(DgcExcept)
{
	dgt_schar	sql_text[2048];
	DgcSqlStmt* sql_stmt=0;
	if (TabInfo.synonym_flag == 0) {
		sprintf(sql_text,
"select   a.column_name "
        ",a.column_order "
        ",a.data_type "
        ",a.data_length "
        ",a.data_precision "
        ",a.data_scale "
        ",a.nullable_flag "
        ",a.default "
        ",a.IS_IDENTITY "
        ",a.enc_col_id "
        ",a.renamed_col_name "
        ",a.multi_byte_flag "
        ",a.curr_enc_step "
        ",b.cipher_type "
        ",b.key_size "
        ",b.enc_mode "
        ",b.iv_type "
        ",b.n2n_flag "
        ",b.b64_txt_enc_flag "
        ",b.enc_start_pos "
        ",b.enc_length "
        ",b.mask_char "
        ",b.coupon_id "
        ",c.index_type "
        ",c.normal_idx_flag "
        ",a.domain_index_name "
        ",a.fbi_index_name "
        ",a.normal_index_name  "
        ",a.index_col_name "
        ",a.status "
"from     pct_enc_column a "
        ",pct_encrypt_key (+) b "
        ",pct_enc_index (+) c "
"WHERE    a.enc_tab_id=%lld "
"AND      a.key_id=b.key_id "
"AND      a.enc_col_id=c.enc_col_id "
"ORDER BY a.column_order ",TabInfo.enc_tab_id);
		sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	} else {
		sprintf(sql_text,
"select   a.column_name "
        ",a.column_order "
        ",a.data_type "
        ",a.data_length "
        ",a.data_precision "
        ",a.data_scale "
        ",a.nullable_flag "
        ",a.default "
        ",a.IS_IDENTITY "
        ",b.key_id "
        ",a.renamed_col_name "
        ",a.multi_byte_flag "
        ",a.curr_enc_step "
        ",b.cipher_type "
        ",b.key_size "
        ",b.enc_mode "
        ",b.iv_type "
        ",b.n2n_flag "
        ",b.b64_txt_enc_flag "
        ",b.enc_start_pos "
        ",b.enc_length "
        ",b.mask_char "
        ",b.coupon_id "
        ",c.index_type "
        ",c.normal_idx_flag "
        ",a.domain_index_name "
        ",a.fbi_index_name "
        ",a.normal_index_name  "
        ",a.index_col_name "
        ",a.status "
"from     pct_enc_column a "
        ",pct_encrypt_key (+) b "
        ",pct_enc_index (+) c "
"WHERE    a.enc_tab_id=%lld "
"AND      a.key_id=b.key_id "
"AND      a.enc_col_id=c.enc_col_id "
"ORDER BY a.column_order ",TabInfo.enc_tab_id);
		sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	}
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	ColInfoRows.reset();
	ColInfoRows2.reset();
	pc_type_col_info*	col_info;
	while ((col_info=(pc_type_col_info*)sql_stmt->fetch())) {
		ColInfoRows.add();
		ColInfoRows.next();
		ColInfoRows2.add();
		ColInfoRows2.next();
		memcpy(ColInfoRows.data(), col_info, sizeof(pc_type_col_info));
		memcpy(ColInfoRows2.data(), col_info, sizeof(pc_type_col_info));
	}
	DgcExcept*	e=EXCEPTnC;
	delete sql_stmt;
	if (e) {
		delete e;
	}
	ColInfoRows.rewind();
	ColInfoRows2.rewind();
	return ColInfoRows.numRows();
}

dgt_sint32 PccScriptBuilder::saveSqlText() throw(DgcExcept)
{
	StmtNo++;
	DgcTableSegment*	cs_tab=0;
	for (dgt_sint32 i=0; i<2; i++) {
		if ((cs_tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_SCRIPT",DGC_SEG_TABLE,Session->databaseUser())) == 0) {
			ATHROWnR(DgcError(SPOS,"getTable failed"),-1);
			THROWnR(DgcPdbExcept(DGC_EC_PDO_NOT_FOUND,new DgcError(SPOS,"table[PCT_SCRIPT] not found")),-1);
		}
		cs_tab->unlockShare();
		DgcRowList	cs_rows(cs_tab);
		dgt_uint32	remains=strlen(TextBuf);
		dgt_schar*	cp=TextBuf;
		dgt_uint32	seg_no=0;
		cs_rows.reset();
	
		dgt_uint32	count=0;
		while (remains > 0) {
			if (cs_tab->pinInsert(Session,cs_rows,1) != 0) {
				DgcExcept*	e=EXCEPTnC;
				cs_rows.rewind();
				if (cs_tab->pinRollback(cs_rows)) delete EXCEPTnC;
				RTHROWnR(e,DgcError(SPOS,"pinInsert failed"),-1);
			}
			cs_rows.next();
        		pct_type_script*	csp=(pct_type_script*)cs_rows.data();
			csp->enc_tab_id=TabInfo.enc_tab_id;
			if (i==0) csp->version_no=VersionNo;
			else csp->version_no=VersionNo+10;
			csp->step_no=StepNo;
			csp->stmt_no=StmtNo;
			csp->seg_no=++seg_no;
			if (remains < 64) {
				memcpy(csp->seg_text,cp,remains);
				remains=0;
			} else {
				dgt_uint32 i = 0;
				for (i=0; i<64;) {
					if (*(cp+i) & 0x80) {
						if (i>61) break;
						i+=3;
					} else {
						i++;
					}
				}

				memcpy(csp->seg_text,cp,i);
				remains-=i;
				cp+=i;
			}
			count++;
			if (count % 10 == 0) {
				cs_rows.rewind();
				if (cs_tab->insertCommit(Session,cs_rows) != 0) {
	                		DgcExcept*      e=EXCEPTnC;
			                if (cs_tab->pinRollback(cs_rows)) delete EXCEPTnC;
                			RTHROWnR(e,DgcError(SPOS,"insertCommit[PCT_SCRIPT] failed"),-1);
		        	}	
				cs_rows.reset();
			}
		}
		if (count % 10 != 0) {
			cs_rows.rewind();
			if (cs_tab->insertCommit(Session,cs_rows) != 0) {
				DgcExcept*      e=EXCEPTnC;
				if (cs_tab->pinRollback(cs_rows)) delete EXCEPTnC;
				RTHROWnR(e,DgcError(SPOS,"insertCommit[PCT_SCRIPT] failed"),-1);
			}
		}
	}
	return 0;
}


PccScriptBuilder::PccScriptBuilder(DgcDatabase* db, DgcSession* sess, dgt_schar* schema_link)
	: Database(db), Session(sess), Connection(0), ColInfoRows(29), ColInfoRows2(29), ScriptText(0)
{
	Dbid=0;
	strncpy(SchemaLink, schema_link, 32);
	TmpBuf=new dgt_schar[60000];
	TextBuf=new dgt_schar[200000];
	ColInfoRows.addAttr(DGC_SCHR,130,"col_name");
	ColInfoRows.addAttr(DGC_SB4,0,"column_order");
	ColInfoRows.addAttr(DGC_SCHR,33,"data_type");
	ColInfoRows.addAttr(DGC_SB4,0,"data_length");
	ColInfoRows.addAttr(DGC_SB4,0,"data_precision");
	ColInfoRows.addAttr(DGC_SB4,0,"data_scale");
	ColInfoRows.addAttr(DGC_SB4,0,"nullable");
	ColInfoRows.addAttr(DGC_SB8,0,"col_default");
	ColInfoRows.addAttr(DGC_SB4,0,"is_identity");
	ColInfoRows.addAttr(DGC_SB8,0,"enc_col_id");
	ColInfoRows.addAttr(DGC_SCHR,130,"renamed_col_name");
	ColInfoRows.addAttr(DGC_UB1,0,"multi_byte_flag");
	ColInfoRows.addAttr(DGC_SB2,0,"curr_enc_step");
	ColInfoRows.addAttr(DGC_UB1,0,"cipher_type");
	ColInfoRows.addAttr(DGC_UB2,0,"key_size");
	ColInfoRows.addAttr(DGC_UB1,0,"enc_mode");
	ColInfoRows.addAttr(DGC_UB1,0,"iv_type");
	ColInfoRows.addAttr(DGC_UB1,0,"n2n_flag");
	ColInfoRows.addAttr(DGC_UB1,0,"b64_txt_enc_flag");
	ColInfoRows.addAttr(DGC_UB1,0,"enc_start_pos");
	ColInfoRows.addAttr(DGC_UB4,0,"enc_length");
	ColInfoRows.addAttr(DGC_SCHR,33,"mask_char");
	ColInfoRows.addAttr(DGC_SB8,0,"coupon_id");
	ColInfoRows.addAttr(DGC_UB1,0,"index_type");
	ColInfoRows.addAttr(DGC_SCHR,130,"domain_index_name");
	ColInfoRows.addAttr(DGC_SCHR,130,"fbi_index_name");
	ColInfoRows.addAttr(DGC_SCHR,130,"normal_index_name");
	ColInfoRows.addAttr(DGC_SCHR,130,"index_col_name");
	ColInfoRows.addAttr(DGC_UB1,0,"status");

        ColInfoRows2.addAttr(DGC_SCHR,130,"col_name");
        ColInfoRows2.addAttr(DGC_SB4,0,"column_order");
        ColInfoRows2.addAttr(DGC_SCHR,33,"data_type");
        ColInfoRows2.addAttr(DGC_SB4,0,"data_length");
        ColInfoRows2.addAttr(DGC_SB4,0,"data_precision");
        ColInfoRows2.addAttr(DGC_SB4,0,"data_scale");
        ColInfoRows2.addAttr(DGC_SB4,0,"nullable");
        ColInfoRows2.addAttr(DGC_SB8,0,"col_default");
        ColInfoRows2.addAttr(DGC_SB4,0,"is_identity");
        ColInfoRows2.addAttr(DGC_SB8,0,"enc_col_id");
        ColInfoRows2.addAttr(DGC_SCHR,130,"renamed_col_name");
        ColInfoRows2.addAttr(DGC_UB1,0,"multi_byte_flag");
        ColInfoRows2.addAttr(DGC_SB2,0,"curr_enc_step");
        ColInfoRows2.addAttr(DGC_UB1,0,"cipher_type");
        ColInfoRows2.addAttr(DGC_UB2,0,"key_size");
        ColInfoRows2.addAttr(DGC_UB1,0,"enc_mode");
        ColInfoRows2.addAttr(DGC_UB1,0,"iv_type");
        ColInfoRows2.addAttr(DGC_UB1,0,"n2n_flag");
        ColInfoRows2.addAttr(DGC_UB1,0,"b64_txt_enc_flag");
        ColInfoRows2.addAttr(DGC_UB1,0,"enc_start_pos");
        ColInfoRows2.addAttr(DGC_UB4,0,"enc_length");
        ColInfoRows2.addAttr(DGC_SCHR,33,"mask_char");
        ColInfoRows2.addAttr(DGC_SB8,0,"coupon_id");
        ColInfoRows2.addAttr(DGC_UB1,0,"index_type");
        ColInfoRows2.addAttr(DGC_SCHR,130,"domain_index_name");
        ColInfoRows2.addAttr(DGC_SCHR,130,"fbi_index_name");
        ColInfoRows2.addAttr(DGC_SCHR,130,"normal_index_name");
        ColInfoRows2.addAttr(DGC_SCHR,130,"index_col_name");
        ColInfoRows2.addAttr(DGC_UB1,0,"status");

}


PccScriptBuilder::~PccScriptBuilder()
{
	delete TmpBuf;
	delete TextBuf;
	delete ScriptText;
	delete Connection;
}


dgt_sint32 PccScriptBuilder::getScript(
	dgt_sint64	enc_tab_id,
	dgt_uint16	version_no,
	dgt_sint16	step_no,
	dgt_sint16	stmt_no,
	DgcMemRows*	rtn_rows,
	dgt_uint8	comment_flag) throw(DgcExcept)
{
	if (!rtn_rows) {
		if (!ScriptText) ScriptText=new dgt_schar[PCC_MAX_SCRIPT_LEN];
		*ScriptText=0;
	}
	dgt_schar	sql_text[512];
	sprintf(sql_text,
		"select * \
		   from pct_script \
		  where enc_tab_id=%lld and version_no=%u and step_no=%d and stmt_no=decode(%d,0,stmt_no,%d) \
		  order by step_no asc, stmt_no asc, seg_no asc",
		enc_tab_id, version_no, step_no, stmt_no, stmt_no);
	DgcSqlStmt*	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	pct_type_script	prev;
	pct_type_script*	curr=0;
	memset(&prev,0,sizeof(pct_type_script));
	dgt_sint32	rtn;
	for(rtn=0; ((curr=(pct_type_script*)sql_stmt->fetch())); rtn++) {
		if (curr->step_no != prev.step_no || curr->stmt_no != prev.stmt_no) {
			dgt_schar	tmp[81];
			*tmp=0;
			if (comment_flag) {
				if (rtn > 0) sprintf(tmp,"\n/* step:%u stmt:%u */", curr->step_no, curr->stmt_no);
				else sprintf(tmp,"/* step:%u stmt:%u */", curr->step_no, curr->stmt_no);
			} else {
				if (rtn > 0) sprintf(tmp,"\n");
			}
			if (rtn_rows) {
				rtn_rows->add();
				rtn_rows->next();
				strncpy((dgt_schar*)rtn_rows->data(), tmp, 64);

			} else {
				dg_strcat(ScriptText, tmp);
			}
		}
		if (rtn_rows) {
			rtn_rows->add();
			rtn_rows->next();
			strncpy((dgt_schar*)rtn_rows->data(), curr->seg_text, 64);
		} else {
			dg_strcat(ScriptText, (dgt_schar*)curr->seg_text);
		}
		memcpy(&prev, curr, sizeof(pct_type_script));
	}
	DgcExcept*	e=EXCEPTnC;
	if (e) {
		if (e->errCode() != DGC_EC_PD_NOT_FOUND) {
			RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
		}
		delete e;
	}
	delete sql_stmt;
	return rtn;
}

dgt_sint32 PccScriptBuilder::runScript(const dgt_schar* script_text,DgcCliConnection* conn) throw(DgcExcept)
{
	if (conn) {
		DgcCliStmt*     stmt=conn->getStmt();
		if (!stmt) {
                	DgcExcept*      e=EXCEPTnC;
	                RTHROWnR(e,DgcError(SPOS,"getStmt failed."),-1);
	        }
        	if (stmt->execute((dgt_schar*)script_text,strlen(script_text)) < 0) {
                	DgcExcept*      e=EXCEPTnC;
	                delete stmt;
        	        RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	        }
	
        	delete stmt;
	        return 0;
	}
	if (getConnection() == 0) {
		ATHROWnR(DgcError(SPOS,"getConnection failed."),-1);
	}
	DgcCliStmt*	stmt=Connection->getStmt();
	if (!stmt) {
		DgcExcept*      e=EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"getStmt failed."),-1);
	}
	if (stmt->execute((dgt_schar*)script_text,strlen(script_text)) < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	delete stmt;
	return 0;
}

dgt_sint32 PccScriptBuilder::runVerifyScript(dgt_schar*   sql_text, DgcMemRows* rtn_rows) throw(DgcExcept)
{
        if (!getConnection()) {
                ATHROWnR(DgcError(SPOS,"getConnection failed."),-1);
        }
        DgcCliStmt*     stmt=Connection->getStmt();
        if (!stmt) {
                Connection->disconnect();
                ATHROWnR(DgcError(SPOS,"getStmt failed."),-1);
        }
        if (stmt->execute(sql_text,strlen(sql_text),10) < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete stmt;
                Connection->disconnect();
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        DgcAttr*        attr=rtn_rows->attr();
        DgcMemRows*     rows=stmt->returnRows();
	dgt_uint32	row_count=0;
        while (rows && rows->numRows() > 0) {
                while(rows->next()) {
			row_count++;
                        rtn_rows->add();
                        rtn_rows->next();
                        for(dgt_uint32 i=0; i<rtn_rows->numCols(); i++) {
                                dgt_sint32      rtn=rows->getColData(i+1,(attr+i)->type(),(attr+i)->length(),rtn_rows->getColPtr(i+1));
                                if (rtn) {
                                        DgcExcept*      e=EXCEPTnC;
                                        delete stmt;
                                        Connection->disconnect();
                                        RTHROWnR(e,DgcError(SPOS,"getColData failed."),-1);
                                }
                        }
                }
		if (row_count > 100) {
			break;
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
//        Connection->disconnect();
	return 0;
}

