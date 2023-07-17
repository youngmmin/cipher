/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetZoneParam
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetZoneParam.h"
#include "PciCryptoIf.h"
#include "DgcDbProcess.h"
#include "PccKredSessionPool.h"
#include "DgcSqlHandle.h"
#include "PfccTableTypes.h"

const dgt_schar PccKredStmtGetZoneParam::DELIMITER_PARAM_FORMAT[] =
		"(delimiter=(zone_id=%lld)(max_line_len=%u)(max_pattern_len=%u)(chars=\"%s\")(row_delimiter=\"%s\")(continue_delimiter=\"%s\"))\n";

const dgt_schar PccKredStmtGetZoneParam::FIXED_PARAM_FORMAT[] =
		"(fixed=(zone_id=%lld)(col_lengths=%s)(out_col_lengths=%s)(lead_space_trim=%s)(tail_space_trim=%s))\n";


PccKredStmtGetZoneParam::PccKredStmtGetZoneParam(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef = new DgcClass("select_list", 1);
	SelectListDef->addAttr(DGC_SCHR, 2049, "param");
	ResultParam = 0;

	KeyParamLen = 0;
	RegularParamLen = 0;
	DelimiterParamLen = 0;
	FixedParamLen = 0;

	KeyParam = 0;
	RegularParam = 0;
	DelimiterParam = 0;
	FixedParam = 0;
}


PccKredStmtGetZoneParam::~PccKredStmtGetZoneParam()
{
	if (ResultParam) delete ResultParam;

	if (KeyParam) delete KeyParam;
	if (RegularParam) delete RegularParam;
	if (DelimiterParam) delete DelimiterParam;
	if (FixedParam) delete FixedParam;
}


dgt_sint32 PccKredStmtGetZoneParam::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	dgt_sint64 zone_id = *((dgt_sint64*)mrows->data());
	if (!ResultParam) ResultParam = new dgt_schar[2049];
	memset(ResultParam,0,2049);

	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_schar stext[256];

	// 1. get zone_id
	sprintf(stext,
			"select * "
			"from pfct_enc_zone "
			"where enc_zone_id=%lld ",
			zone_id);
	dgt_sint32 ret = 0;
	dgt_void* rtn_row=0;
	if (sql_handle.execute(stext) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	if ((ret = sql_handle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	}
	if (!rtn_row) {
		THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"enc_zone not found : pfct_enc_zone.id[%lld]",zone_id)),-1);
	}
	pfct_type_enc_zone* enc_zone = (pfct_type_enc_zone*)rtn_row;

	DgcMemRows zone_id_rows(1);
	zone_id_rows.addAttr(DGC_SB8, 0, "enc_zone_id");
	zone_id_rows.reset();
	zone_id_rows.add();
	zone_id_rows.next();
	*((dgt_sint64*)zone_id_rows.data()) = enc_zone->enc_zone_id;

	dgt_uint32 idx = 0;
	dgt_uint32 pttn_num_rows = 0;
	dgt_uint32 deli_num_rows = 0;
	dgt_uint32 fixed_num_rows = 0;
	dgt_schar* header_version = 0;
	dgt_schar  zone_name[129];
	dgt_schar  out_extension[16];
	memset(zone_name, 0, sizeof(zone_name));
	memset(out_extension, 0, sizeof(out_extension));
	// set num_rows
	if (enc_zone->file_format == 2 /*PFCC_TYPE_FILE_FORMAT_PTTN*/) pttn_num_rows++;
	else if(enc_zone->file_format == 3 /*PFCC_TYPE_FILE_FORMAT_DELI*/) deli_num_rows++;
	else if(enc_zone->file_format == 4 /*PFCC_TYPE_FILE_FORMAT_FIXED*/) fixed_num_rows++;

	//set zone_name
	strncpy(zone_name, enc_zone->name, sizeof(zone_name));
	strncpy(out_extension, enc_zone->out_extension, sizeof(out_extension));

	//set header version
	switch (enc_zone->header_flag) {
		case 1 : 
			header_version = (dgt_schar*)"on";
			break;
		case 2 : 
			header_version = (dgt_schar*)"V2on";
			break;
		default :
			header_version = (dgt_schar*)"off";
				break;
	}

	dgt_uint32 len = 0;
	// 2. build key parameters
	// 2-1. calculate key parameter size
	dgt_sint64 col_key_num_rows = 0;
	memset(stext,0,256);
	sprintf(stext,
			"select count() from pfct_enc_zone_col_key "
			"where enc_zone_id = :1"
			);
	zone_id_rows.rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
	if ((ret = sql_handle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	}
	if (rtn_row) col_key_num_rows = *((dgt_sint64*)rtn_row);

	len = col_key_num_rows * PARAM_MIN_LEN;
	if (KeyParamLen < len) {
		if (KeyParam) delete KeyParam;
		KeyParam = new dgt_schar[len+1];
		KeyParamLen = len + 1;
	}
	memset(KeyParam,0,KeyParamLen);

	// 2-2. build key parameter
	memset(stext,0,256);
	sprintf(stext,
			"select k.enc_zone_id, k.enc_col_id, k.pattern_id, k.column_no, c.column_name enc_col_name from pfct_enc_zone_col_key k, pct_enc_column c "
			"where k.enc_zone_id = :1 "
			"and k.enc_col_id = c.enc_col_id "
			"order by k.enc_zone_id, k.column_no "
			);

	zone_id_rows.rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	// for regular parameters
	DgcMemRows pttn_col_key_rows(5);
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "enc_zone_id");
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "enc_col_id");
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "pattern_id");
	pttn_col_key_rows.addAttr(DGC_UB2, 0, "column_no");
	pttn_col_key_rows.addAttr(DGC_SCHR, 130, "enc_col_name");
	pttn_col_key_rows.reset();

	ret = 0;
	rtn_row = 0;
	idx = 0;
	pct_kred_apb_get_col_key_out* col_key_out = 0;
	dgt_sint64 pre_enc_zone_id = 0;
	dgt_uint16 key_no = 0;

	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
		col_key_out = (pct_kred_apb_get_col_key_out*) rtn_row;
		if (pre_enc_zone_id != col_key_out->enc_zone_id) {
			if (idx) {
				strcpy(KeyParam+idx,")\n"); //key node end
				idx += dg_strlen(KeyParam+idx);
			}
			// build key node start
			sprintf(KeyParam+idx,"(key=(zone_id=%lld)",col_key_out->enc_zone_id);
			idx += dg_strlen(KeyParam+idx);
			key_no = 0;
			pre_enc_zone_id = col_key_out->enc_zone_id;
		}
		if (col_key_out->pattern_id) {
			key_no = col_key_out->column_no;
			// add memory rows
			pttn_col_key_rows.add();
			pttn_col_key_rows.next();
			memcpy(pttn_col_key_rows.data(),col_key_out,sizeof(pct_kred_apb_get_col_key_out));
		} else {
			key_no++;
		}

		sprintf(KeyParam+idx,"(%u=(name=%s)(columns=%u))",key_no,col_key_out->enc_col_name,col_key_out->column_no);
		idx += dg_strlen(KeyParam+idx);
	}
	if (idx) {
		strcpy(KeyParam+idx,")"); //last key node end
		//added by shson for logging 2018.06.15
		idx++;
		sprintf(KeyParam+idx,"(system_info=(zone_name=%s))",zone_name);
		idx += dg_strlen(KeyParam+idx);
		sprintf(KeyParam+idx,"(mode=(header_flag=%s))",header_version);
		idx += dg_strlen(KeyParam+idx);
		sprintf(KeyParam+idx,"(out_extension=%s)",out_extension);
	}

	if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);

	// 3. build regular parmeter
	if (pttn_num_rows > 0) {
		pttn_col_key_rows.rewind();

		// 3-1. calculate regular parameter size
		len = pttn_col_key_rows.numRows() * REGULAR_PARAM_MAX_LEN_PER_ROW;
		if (RegularParamLen < len) {
			if (RegularParam) delete RegularParam;
			RegularParam = new dgt_schar[len+1];
			RegularParamLen = len + 1;
		}
		memset(RegularParam,0,RegularParamLen);

		col_key_out = 0;
		idx = 0;
		pre_enc_zone_id = 0;
		pfct_type_enc_pttn_file_format* file_format = 0;
		pfct_type_pattern_expr* pattern_expr = 0;
		dgt_uint32 pttn_idx = 0;
		while(pttn_col_key_rows.next() && (col_key_out=(pct_kred_apb_get_col_key_out*)pttn_col_key_rows.data())) {
			// 2-2. build regular parameter
			if (pre_enc_zone_id != col_key_out->enc_zone_id) {
				if (idx) {
					strcpy(RegularParam+idx,")\n"); //regular node end
					idx += dg_strlen(RegularParam+idx);
				}
				// build regular node start
				memset(stext,0,256);
				sprintf(stext,
						"select * from pfct_enc_pttn_file_format "
						"where enc_zone_id = %lld "
						,col_key_out->enc_zone_id);

				if (sql_handle.execute(stext) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

				ret = 0;
				rtn_row = 0;
				if ((ret = sql_handle.fetch(rtn_row)) < 0) {
					ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
				}
				if (!rtn_row) continue;
				file_format = (pfct_type_enc_pttn_file_format*) rtn_row;

				sprintf(RegularParam+idx,
						"(regular=(zone_id=%lld)(max_line_len=%u)(max_pattern_len=%u)"
						,col_key_out->enc_zone_id, file_format->max_line_len, file_format->max_pttn_len);
				idx += dg_strlen(RegularParam+idx);

				pre_enc_zone_id = col_key_out->enc_zone_id;
			}


			memset(stext,0,256);
			sprintf(stext,
					"select * from pfct_pattern_expr "
					"where pattern_id = %lld "
					,col_key_out->pattern_id);

			if (sql_handle.execute(stext) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

			ret = 0;
			rtn_row = 0;
			pttn_idx = 0;
			pattern_expr = 0;
			while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
				pattern_expr = (pfct_type_pattern_expr*) rtn_row;
				// check buffer size
				if (RegularParamLen-idx < (dgt_uint32)(dg_strlen(pattern_expr->pattern_expr)+20)) {
					dgt_uint32 optimal_len = RegularParamLen+REGULAR_PARAM_MAX_LEN_PER_ROW+1;
					dgt_schar* tmp_buffer = new dgt_schar[optimal_len];
					memset(tmp_buffer,0,optimal_len);
					memcpy(tmp_buffer,RegularParam,RegularParamLen);
					delete RegularParam;
					RegularParam = tmp_buffer;
					RegularParamLen = optimal_len;
				}

				pttn_idx++; //expr no
				if (pttn_idx == 1) {
					strcpy(RegularParam+idx,"("); idx++; //column no start
					sprintf(RegularParam+idx,"%d=",col_key_out->column_no); idx += dg_strlen(RegularParam+idx); //col_no set
				}

				sprintf(RegularParam+idx,"(%u=%s)",pttn_idx,pattern_expr->pattern_expr);
				idx += dg_strlen(RegularParam+idx);
			}
			strcpy(RegularParam+idx,")"); idx++;//column no end
		}

		if (idx) strcpy(RegularParam+idx,")\n"); //last regular node end
	} else {
		memset(RegularParam,0,RegularParamLen);
	}

	// 4. build delimiter parmeter
	if (deli_num_rows > 0) {
		// 4-1. calculate delimiter parameter size
		len = deli_num_rows * PARAM_MIN_LEN;
		if (DelimiterParamLen < len) {
			if (DelimiterParam) delete DelimiterParam;
			DelimiterParam = new dgt_schar[len+1];
			DelimiterParamLen = len + 1;
		}
		memset(DelimiterParam,0,DelimiterParamLen);

		memset(stext,0,256);
		sprintf(stext,
				"select * from pfct_enc_deli_file_format "
				"where enc_zone_id = :1 ");

		zone_id_rows.rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

		// 4-2. build delimiter parameters
		ret = 0;
		rtn_row = 0;
		idx = 0;
		pfct_type_enc_deli_file_format* file_format = 0;

		while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
			file_format = (pfct_type_enc_deli_file_format*)rtn_row;
			sprintf(DelimiterParam+idx,
					DELIMITER_PARAM_FORMAT,
					file_format->enc_zone_id,
					file_format->max_line_len,
					file_format->max_pttn_len,
					file_format->delimiter,
					file_format->row_delimiter,
					file_format->continue_delimiter
					);
			idx += dg_strlen(DelimiterParam+idx);
		}
		if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	} else {
		memset(DelimiterParam,0,DelimiterParamLen);
	}

	// 5. build fixed parameter
	if (fixed_num_rows > 0) {
		// 5-1. calculate fixed parameter size
		dgt_uint32 max_out_col_len = 0;
		dgt_sint64 col_key_num_rows = 0;
		memset(stext,0,256);
		sprintf(stext,
				"select max(strlen(out_col_lengths)) from pfct_enc_fixed_file_format "
				"where enc_zone_id = :1 "
				);
		zone_id_rows.rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
		if ((ret = sql_handle.fetch(rtn_row)) < 0) {
			ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
		}
		if (rtn_row) max_out_col_len = *((dgt_uint32*)rtn_row);

		if (max_out_col_len > 0) len = fixed_num_rows * (max_out_col_len*2 + PARAM_MIN_LEN);
		else len =  fixed_num_rows * (FIXED_PARAM_MAX_LEN_PER_ROW + PARAM_MIN_LEN);

		if (FixedParamLen < len) {
			if (FixedParam) delete FixedParam;
			FixedParam = new dgt_schar[len+1];
			FixedParamLen = len + 1;
		}
		memset(FixedParam,0,FixedParamLen);

		memset(stext,0,256);
		sprintf(stext,
				"select * from pfct_enc_fixed_file_format "
				"where enc_zone_id = :1 ");

		zone_id_rows.rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

		// 5-2. build fixed parameters
		ret = 0;
		rtn_row = 0;
		idx = 0;
		pfct_type_enc_fixed_file_format* file_format = 0;

		while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
			file_format = (pfct_type_enc_fixed_file_format*)rtn_row;
			sprintf(FixedParam+idx,
					FIXED_PARAM_FORMAT,
					file_format->enc_zone_id,
					file_format->col_lengths,
					file_format->out_col_lengths,
					file_format->lead_space_trim_flag?"yes":"no",
					file_format->tail_space_trim_flag?"yes":"no"
					);
			idx += dg_strlen(FixedParam+idx);
		}
		if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	} else {
		memset(FixedParam,0,FixedParamLen);
	}

	dgt_uint32 key_param_size = dg_strlen(KeyParam);
	dgt_uint32 reg_param_size = dg_strlen(RegularParam);
	dgt_uint32 deli_param_size = dg_strlen(DelimiterParam);
	dgt_uint32 fixed_param_size = dg_strlen(FixedParam);
	dgt_uint32 param_len = key_param_size + reg_param_size + deli_param_size + fixed_param_size;

	if (param_len > 2048) THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"reslut param size too big[%u]",param_len)),-1);

	idx = 0;
	if (key_param_size) {
		strcpy(ResultParam+idx,KeyParam);
		idx += key_param_size;
	}
	if (reg_param_size) {
		strcpy(ResultParam+idx,RegularParam);
		idx += reg_param_size;
	}

	if (deli_param_size) {
		strcpy(ResultParam+idx,DelimiterParam);
		idx += deli_param_size;
	}

	if (fixed_param_size) {
		strcpy(ResultParam+idx,FixedParam);
		idx += fixed_param_size;
	}
	ResultParam[param_len] = 0;

	IsExecuted=1;
	NumRtnRows=0;
	return 0;
}


dgt_uint8* PccKredStmtGetZoneParam::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)ResultParam;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
