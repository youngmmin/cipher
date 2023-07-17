/*******************************************************************
 *   File Type          :       main file
 *   Classes            :       PfccAgentParamBuilder
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713                  modified build parameter because dir_pttn, file_pttn is moved dependency to job_tgt_dir
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccAgentParamBuilder.h"
#include "DgcDbProcess.h"

const dgt_schar PfccAgentParamBuilder::SCHEDULE_PARAM_FORMAT[] =
		"(schedule=(id=%lld)(start_date=%u)(end_date=%u)(week_map=%u)(start_hour=%u)(end_hour=%u)(start_min=%u)(end_min=%u)(use_cores=%u)(buffer_size=%u))\n";

const dgt_schar PfccAgentParamBuilder::CRYPT_DIR_PARAM_FORMAT[] =
		"(crypt_dir=(id=%lld)(zone_id=%lld)(status=%u)(src_dir=\"%s\")(dst_dir=\"%s\")(dir_rule=(version=%d)(sfd=%d)(sld=%d)(efd=%d)(eld=%d)))\n";

const dgt_schar PfccAgentParamBuilder::ENC_ZONE_PARAM_FORMAT[] =
		"(zone=(id=%lld)(last_update=%lld)(name=\"%s\")(crypt_mode=%s)(file_format=%u)(close_after=%u)(header_flag=%u)(out_extension=%s)(backup_flag=%u)(overwrite_flag=%u)(ext_ip=%s)(ext_port=%u)(s_limit=%f)(s_enable=%d)(g_sigma=%f)(g_enable=%d)(c_enable=%d)(r_angle=%d)(r_enable=%d))\n";

const dgt_schar PfccAgentParamBuilder::SYSTEM_INFO_PARAM_FORMAT[] =
		"(system_info=(zone_id=%lld)(system_id=\"%lld\")(system_name=\"%s\")(system_ip=\"%s\"))\n";

const dgt_schar PfccAgentParamBuilder::DELIMITER_PARAM_FORMAT[] =
		"(delimiter=(zone_id=%lld)(max_line_len=%u)(max_pattern_len=%u)(chars=\"%s\")(row_delimiter=\"%s\")(continue_delimiter=\"%s\"))\n";

const dgt_schar PfccAgentParamBuilder::FIXED_PARAM_FORMAT[] =
		"(fixed=(zone_id=%lld)(max_line_len=%u)(max_pattern_len=%u)(row_delimiter=\"%s\")(continue_delimiter=\"%s\")(col_lengths=%s)(out_col_lengths=%s)(lead_space_trim=%s)(tail_space_trim=%s))\n";

PfccAgentParamBuilder::PfccAgentParamBuilder(dgt_sint64 agent_id, dgt_uint8 init_flag)
	: AgentID(agent_id), InitParamFlag(init_flag)
{
	JobType = 0;
	AgentParamSize = 0;
	EncZoneParamSize = 0;

	AgentParamLen = 0;
	EncZoneParamLen = 0;
	ScheduleParamLen = 0;
	CryptDirParamLen = 0;
	ZoneParamLen = 0;
	SystemInfoParamLen = 0;
	KeyParamLen = 0;
	RegularParamLen = 0;
	DelimiterParamLen = 0;
	FixedParamLen = 0;
	DirPttnParamLen = 0;
	FilePttnParamLen = 0;

	AgentParam = 0;
	EncZoneParam = 0;
	ScheduleParam = 0;
	CryptDirParam = 0;
	ZoneParam = 0;
	SystemInfoParam = 0;
	KeyParam = 0;
	RegularParam = 0;
	DelimiterParam = 0;
	FixedParam = 0;
	DirPttnParam = 0;
	FilePttnParam = 0;

	memset(SystemIP,0,65);
	memset(SystemName,0,129);
}


PfccAgentParamBuilder::~PfccAgentParamBuilder()
{
	if (AgentParam) delete AgentParam;
	if (EncZoneParam) delete EncZoneParam;
	if (ScheduleParam) delete ScheduleParam;
	if (CryptDirParam) delete CryptDirParam;
	if (ZoneParam) delete ZoneParam;
	if (SystemInfoParam) delete SystemInfoParam;
	if (KeyParam) delete KeyParam;
	if (RegularParam) delete RegularParam;
	if (DelimiterParam) delete DelimiterParam;
	if (FixedParam) delete FixedParam;
	if (DirPttnParam) delete DirPttnParam;
	if (FilePttnParam) delete FilePttnParam;
}


dgt_sint32 PfccAgentParamBuilder::getSystemInfo() throw(DgcExcept)
{
	SystemID = 0;
	memset(SystemIP,0,65);
	memset(SystemName,0,129);

	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_schar stext[256];
	memset(stext, 0, 256);
	// 1. get job_id
	sprintf(stext,
			"select * from pfct_enc_tgt_sys s, pfct_agent a "
			"where s.enc_tgt_sys_id = a.enc_tgt_sys_id "
			"and a.agent_id = %lld ",
			AgentID);

	if (sql_handle.execute(stext) < 0) {
		ATHROWnR(DgcError(SPOS,"execute failed"), -1);
	}
	dgt_sint32 ret = 0;
	dgt_void* rtn_row = 0;
	if ((ret = sql_handle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	}
	pfct_type_enc_tgt_sys* tgt_sys = 0;
	if (rtn_row) {
		tgt_sys = (pfct_type_enc_tgt_sys*) rtn_row;
		SystemID = tgt_sys->enc_tgt_sys_id;
		strcpy(SystemIP,tgt_sys->ip);
		strcpy(SystemName,tgt_sys->name);
	}
	return 0;
}

dgt_sint32 PfccAgentParamBuilder::buildDirPttnParams(DgcMemRows* enc_job_tgt_id_rows) throw(DgcExcept)
{
	if (!enc_job_tgt_id_rows) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"no enc_job_tgt_id_rows")),-1);
	// 1. build dir_pttn parameters
	// 1-1. calculate dir_pttn parameter size
	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_sint64 pttn_num_rows = 0;
	dgt_schar stext[256];
	memset(stext,0,256);
	sprintf(stext,
			"select count() from pfct_enc_zone_dir_name_pttn "
			"where enc_job_tgt_id = :1"
			);
	enc_job_tgt_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	dgt_sint32 ret = 0;
	dgt_void* rtn_row = 0;

	if ((ret = sql_handle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	}
	if (rtn_row) pttn_num_rows = *((dgt_sint64*)rtn_row);

	dgt_uint32 len = pttn_num_rows * (ENC_ZONE_PARAM_MAX_LEN_PER_ROW + 30);
	if (DirPttnParamLen < len) {
		if (DirPttnParam) delete DirPttnParam;
		DirPttnParam = new dgt_schar[len+1];
		DirPttnParamLen = len + 1;
	}
	memset(DirPttnParam,0,DirPttnParamLen);


	// 1-2. build dir_pttn parameters
	memset(stext,0,256);
	sprintf(stext,
			"select * from pfct_enc_zone_dir_name_pttn "
			"where enc_job_tgt_id = :1 "
			"order by enc_job_tgt_id ");
	enc_job_tgt_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	ret = 0;
	rtn_row = 0;
	pfct_type_enc_zone_dir_name_pttn* name_pttn = 0;
	dgt_sint64 pre_enc_job_tgt_id = 0;
	dgt_uint32 idx = 0;
	dgt_uint32 pttn_idx = 0;
	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
		name_pttn = (pfct_type_enc_zone_dir_name_pttn*) rtn_row;
		if (pre_enc_job_tgt_id != name_pttn->enc_job_tgt_id) {
			if (idx) {
				strcpy(DirPttnParam+idx,")\n"); //dir_pttn node end
				idx += dg_strlen(DirPttnParam+idx);
			}
			// build dir_pttn node start
			sprintf(DirPttnParam+idx,"(dir_pttn=(enc_job_tgt_id=%lld)",name_pttn->enc_job_tgt_id);
			idx += dg_strlen(DirPttnParam+idx);
			pre_enc_job_tgt_id = name_pttn->enc_job_tgt_id;
			pttn_idx = 0;
		}

		pttn_idx++;
		sprintf(DirPttnParam+idx,"(%u=\"%s\")",pttn_idx,name_pttn->pttn_expr);
		idx += dg_strlen(DirPttnParam+idx);
	}
	if (idx) strcpy(DirPttnParam+idx,")\n"); // last dir_pttn node end
	if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);

	return 0;
}


dgt_sint32 PfccAgentParamBuilder::buildFilePttnParams(DgcMemRows* enc_job_tgt_id_rows) throw(DgcExcept)
{
	if (!enc_job_tgt_id_rows) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"no enc_job_tgt_id_rows")),-1);

	// 1. build file_pttn parameters
	// 1-1. calculate file_pttn parameter size
	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_sint64 pttn_num_rows = 0;
	dgt_schar stext[256];
	memset(stext,0,256);
	sprintf(stext,
			"select count() from pfct_enc_zone_file_name_pttn "
			"where enc_job_tgt_id = :1"
			);
	enc_job_tgt_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	dgt_sint32 ret = 0;
	dgt_void* rtn_row = 0;

	if ((ret = sql_handle.fetch(rtn_row)) < 0) {
		ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	}
	if (rtn_row) pttn_num_rows = *((dgt_sint64*)rtn_row);

	dgt_uint32 len = pttn_num_rows * (ENC_ZONE_PARAM_MAX_LEN_PER_ROW + 30);
	if (FilePttnParamLen < len) {
		if (FilePttnParam) delete FilePttnParam;
		FilePttnParam = new dgt_schar[len+1];
		FilePttnParamLen = len + 1;
	}
	memset(FilePttnParam,0,FilePttnParamLen);


	// 1-2. build file_pttn parameters
	memset(stext,0,256);
	sprintf(stext,
			"select * from pfct_enc_zone_file_name_pttn "
			"where enc_job_tgt_id = :1 "
			"order by enc_job_tgt_id ");

	enc_job_tgt_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	ret = 0;
	rtn_row = 0;
	pfct_type_enc_zone_file_name_pttn* name_pttn = 0;
	dgt_sint64 pre_enc_job_tgt_id = 0;
	dgt_uint32 idx = 0;
	dgt_uint32 pttn_idx = 0;
	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
		name_pttn = (pfct_type_enc_zone_file_name_pttn*) rtn_row;
		if (pre_enc_job_tgt_id != name_pttn->enc_job_tgt_id) {
			if (idx) {
				strcpy(FilePttnParam+idx,")\n"); //file_pttn node end
				idx += dg_strlen(FilePttnParam+idx);
			}
			// build file_pttn node start
			sprintf(FilePttnParam+idx,"(file_pttn=(enc_job_tgt_id=%lld)",name_pttn->enc_job_tgt_id);
			idx += dg_strlen(FilePttnParam+idx);
			pre_enc_job_tgt_id = name_pttn->enc_job_tgt_id;
			pttn_idx = 0;
		}

		pttn_idx++;
		sprintf(FilePttnParam+idx,"(%u=\"%s\")",pttn_idx,name_pttn->pttn_expr);
		idx += dg_strlen(FilePttnParam+idx);
	}
	if (idx) strcpy(FilePttnParam+idx,")\n"); // last file_pttn node end

	if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);

	return 0;
}


dgt_sint32 PfccAgentParamBuilder::buildEncZoneParams(DgcMemRows* zone_id_rows) throw(DgcExcept)
{
	EncZoneParamSize = 0;
	if (!zone_id_rows) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"no zone_id_rows")),-1);
	// 0. get system info
	if (getSystemInfo() < 0) {
		DgcExcept* e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"getSystemInfo[%lld] failed.\n",AgentID);
			delete e;
		}
	}

	// 1. build zone parameters
	// 1-1. calculate zone parameter size
	dgt_uint32 len = zone_id_rows->numRows() * ENC_ZONE_PARAM_MAX_LEN_PER_ROW;
	if (ZoneParamLen < len) {
		if (ZoneParam) delete ZoneParam;
		ZoneParam = new dgt_schar[len+1];
		ZoneParamLen = len + 1;
	}
	memset(ZoneParam,0,ZoneParamLen);
	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_schar stext[256];
	memset(stext,0,256);
	sprintf(stext,
			"select * from pfct_enc_zone "
			"where enc_zone_id = :1 ");

	// 1-2. caluculate system info parameter size
	len = zone_id_rows->numRows() * ENC_ZONE_PARAM_MAX_LEN_PER_ROW + dg_strlen(SystemIP) + dg_strlen(SystemName);
	if (SystemInfoParamLen < len) {
		if (SystemInfoParam) delete SystemInfoParam;
		SystemInfoParam = new dgt_schar[len+1];
		SystemInfoParamLen = len + 1;
	}
	memset(SystemInfoParam,0,SystemInfoParamLen);

	zone_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	// 1-3. build zone and system info parameters
	dgt_sint32 ret = 0;
	dgt_void* rtn_row = 0;
	dgt_uint32 idx = 0;
	dgt_uint32 sys_info_idx = 0;
	pfct_type_enc_zone* enc_zone = 0;

	dgt_uint32 pttn_num_rows = 0;
	dgt_uint32 deli_num_rows = 0;
	dgt_uint32 fixed_num_rows = 0;

	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
		enc_zone = (pfct_type_enc_zone*)rtn_row;

		//
		// added by mwpark for fp masking
		//
		typedef struct {
			dgt_schar	ip[65];
			dgt_uint16	port;
		} ext_svr_rtn;
		ext_svr_rtn  ext_data;
		dgt_void*    ext_row;
		memset(&ext_data,0,sizeof(ext_svr_rtn));
		if (enc_zone->crypt_type >= 10 && enc_zone->crypt_type <13) {
			DgcSqlHandle sql_handle2(DgcDbProcess::sess());
		        dgt_schar stext2[256];
		        memset(stext2,0,256);
		        sprintf(stext2,
                	        "select ip, port from pfct_enc_ext_sys "
                        	"where name = '%s' ", enc_zone->reserved);
			if (sql_handle2.execute(stext2,dg_strlen(stext2)) < 0) {
				ATHROWnR(DgcError(SPOS,"execute failed"), -1);
			}
			dgt_sint32 rtn=0;
			if (!(rtn = sql_handle2.fetch(ext_row)) && ext_row) {
				memcpy(&ext_data, (ext_svr_rtn*)ext_row, sizeof(ext_svr_rtn));
			}
			delete EXCEPTnC;
		}
		// build zone parameter
		dgt_schar	crypt_mode[128];
		memset(crypt_mode,0,128);
		if (JobType == 5) {
			memset(crypt_mode, 0, sizeof(crypt_mode));
			sprintf(crypt_mode,"(detect=%d)", enc_zone->crypt_type);
		} else if (enc_zone->crypt_type == 1) {
			sprintf(crypt_mode,"%s","encrypt");
		} else if (enc_zone->crypt_type == 0 || enc_zone->crypt_type == 2) {
			sprintf(crypt_mode,"%s","decrypt");
		} else if (enc_zone->crypt_type == 10) {
			// file transper
			sprintf(crypt_mode,"%s","fp1");
		} else if (enc_zone->crypt_type == 11) {
			// detect fp
			sprintf(crypt_mode,"%s","fp2");
		} else if (enc_zone->crypt_type == 12) {
			// mask fp
			sprintf(crypt_mode,"%s","fp3");
		} else if (enc_zone->crypt_type == 13) {
			// detect & mask fp
			sprintf(crypt_mode,"%s","fp4");
		}  else if (enc_zone->crypt_type == 14) {
			// decoding
			sprintf(crypt_mode,"%s","fp5");
		} else {
			sprintf(crypt_mode,"%s","decrypt");
		}

		typedef struct {
			dgt_float64	s_limit;
			dgt_sint32	s_enable;
			dgt_float64	g_sigma;
			dgt_sint32	g_enable;
			dgt_sint32	c_enable;
			dgt_sint32	r_angle;
			dgt_sint32	r_enable;
                } fp_ms_rtn;
                fp_ms_rtn  ms_data;
                dgt_void*  ms_row;
                memset(&ms_data,0,sizeof(fp_ms_rtn));
                if (enc_zone->crypt_type >= 10 && enc_zone->crypt_type <13) {
                        DgcSqlHandle sql_handle2(DgcDbProcess::sess());
                        dgt_schar stext2[512];
                        memset(stext2,0,512);
                        sprintf(stext2,
"select	size_limit,"
       "size_limit_enable,"
       "gaussian_sigma,"
       "gaussian_enable,"
       "contrast_enable,"
       "rotate_angle,"
       "rotate_enable "
"from pfct_enc_zone_fp_conf "
"where enc_zone_id = %lld ", enc_zone->enc_zone_id);
                        if (sql_handle2.execute(stext2,dg_strlen(stext2)) < 0) {
                                ATHROWnR(DgcError(SPOS,"execute failed"), -1);
                        }
                        dgt_sint32 rtn=0;
                        if (!(rtn = sql_handle2.fetch(ms_row)) && ms_row) {
                                memcpy(&ms_data, (fp_ms_rtn*)ms_row, sizeof(fp_ms_rtn));
                        } else {
				ms_data.s_enable=-1;
				ms_data.g_enable=-1;
				ms_data.c_enable=-1;
				ms_data.r_enable=-1;
			}
                        delete EXCEPTnC;
                }

		sprintf(ZoneParam+idx,
				ENC_ZONE_PARAM_FORMAT,
				enc_zone->enc_zone_id,
				enc_zone->last_update,
				enc_zone->name,
				crypt_mode,
				enc_zone->file_format,
				enc_zone->close_after,
				enc_zone->header_flag,
				enc_zone->out_extension,
				enc_zone->backup_flag,
				enc_zone->overwrite_flag,
				ext_data.ip,
				ext_data.port,
				ms_data.s_limit, ms_data.s_enable,
				ms_data.g_sigma, ms_data.g_enable,
				ms_data.c_enable,
				ms_data.r_angle, ms_data.r_enable);
		idx += dg_strlen(ZoneParam+idx);

		// set num_rows
		if (enc_zone->file_format == PFCC_TYPE_FILE_FORMAT_PTTN) pttn_num_rows++;
		else if(enc_zone->file_format == PFCC_TYPE_FILE_FORMAT_DELI) deli_num_rows++;
		else if(enc_zone->file_format == PFCC_TYPE_FILE_FORMAT_FIXED) fixed_num_rows++;

		// build system info parameter
		sprintf(SystemInfoParam+sys_info_idx,
				SYSTEM_INFO_PARAM_FORMAT,
				enc_zone->enc_zone_id,
				SystemID,
				SystemName,
				SystemIP);
		sys_info_idx += dg_strlen(SystemInfoParam+sys_info_idx);
	}
	if (EXCEPT) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);


	// 2. build key parameters
	// 2-1. calculate key parameter size
	dgt_sint64 col_key_num_rows = 0;
	memset(stext,0,256);
	sprintf(stext,
			"select count() from pfct_enc_zone_col_key "
			"where enc_zone_id = :1"
			);
	zone_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
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
			"select k.enc_zone_id, k.enc_col_id, k.pattern_id, k.column_no, c.column_name enc_col_name, d.table_name table_name from pfct_enc_zone_col_key k, pct_enc_column c, pct_enc_table d "
			"where k.enc_zone_id = :1 "
			"and k.enc_col_id = c.enc_col_id "
			"and c.enc_tab_id = d.enc_tab_id "
			"order by k.enc_zone_id, k.column_no "
			);

	zone_id_rows->rewind();
	if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	// for regular parameters
	DgcMemRows pttn_col_key_rows(6);
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "enc_zone_id");
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "enc_col_id");
	pttn_col_key_rows.addAttr(DGC_SB8, 0, "pattern_id");
	pttn_col_key_rows.addAttr(DGC_UB2, 0, "column_no");
	pttn_col_key_rows.addAttr(DGC_SCHR, 130, "enc_col_name");
	pttn_col_key_rows.addAttr(DGC_SCHR, 130, "table_name");
	pttn_col_key_rows.reset();

	ret = 0;
	rtn_row = 0;
	idx = 0;
	pfct_apb_get_col_key_out* col_key_out = 0;
	dgt_sint64 pre_enc_zone_id = 0;
	dgt_uint16 key_no = 0;

	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) {
		col_key_out = (pfct_apb_get_col_key_out*) rtn_row;
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
			memcpy(pttn_col_key_rows.data(),col_key_out,sizeof(pfct_apb_get_col_key_out));
		} else {
			key_no++;
		}

		sprintf(KeyParam+idx,"(%u=(name=%s.%s)(columns=%u))",key_no,col_key_out->table_name,col_key_out->enc_col_name,col_key_out->column_no);
		idx += dg_strlen(KeyParam+idx);
	}
	if (idx) strcpy(KeyParam+idx,")\n"); //last key node end

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
		while(pttn_col_key_rows.next() && (col_key_out=(pfct_apb_get_col_key_out*)pttn_col_key_rows.data())) {
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

		zone_id_rows->rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

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
#if 0
		memset(stext,0,256);
		sprintf(stext,
				"select max(strlen(out_col_lengths)) from pfct_enc_fixed_file_format "
				"where enc_zone_id = :1 "
				);
		zone_id_rows->rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
		if ((ret = sql_handle.fetch(rtn_row)) < 0) {
			ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
		}
		if (rtn_row) max_out_col_len = *((dgt_uint32*)rtn_row);

		if (max_out_col_len > 0) len = fixed_num_rows * (max_out_col_len*2 + PARAM_MIN_LEN);
		else len =  fixed_num_rows * (FIXED_PARAM_MAX_LEN_PER_ROW + PARAM_MIN_LEN);
#else //modified by shson 2018.12.09 don't need max_out_col_len calculate
		len =  fixed_num_rows * (FIXED_PARAM_MAX_LEN_PER_ROW + PARAM_MIN_LEN);
#endif

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

		zone_id_rows->rewind();
		if (sql_handle.execute(stext,dg_strlen(stext),zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

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
					file_format->max_line_len,
					file_format->max_pttn_len,
					file_format->row_delimiter,
					file_format->continue_delimiter,
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

	dgt_uint32 zone_param_size = dg_strlen(ZoneParam);
	dgt_uint32 sys_info_param_size = dg_strlen(SystemInfoParam);
	dgt_uint32 key_param_size = dg_strlen(KeyParam);
	dgt_uint32 reg_param_size = dg_strlen(RegularParam);
	dgt_uint32 deli_param_size = dg_strlen(DelimiterParam);
	dgt_uint32 fixed_param_size = dg_strlen(FixedParam);

	EncZoneParamSize = zone_param_size + sys_info_param_size + key_param_size + reg_param_size + deli_param_size + fixed_param_size;

	if (EncZoneParamLen < EncZoneParamSize + 1) {
		if (EncZoneParam) delete EncZoneParam;
		EncZoneParam = new dgt_schar[EncZoneParamSize + 1];
		EncZoneParamLen = EncZoneParamSize + 1;
	}
	idx = 0;
	if (zone_param_size) {
		strcpy(EncZoneParam+idx,ZoneParam);
		idx += zone_param_size;
	}
	if (sys_info_param_size) {
		strcpy(EncZoneParam+idx,SystemInfoParam);
		idx += sys_info_param_size;
	}
	if (key_param_size) {
		strcpy(EncZoneParam+idx,KeyParam);
		idx += key_param_size;
	}
	if (reg_param_size) {
		strcpy(EncZoneParam+idx,RegularParam);
		idx += reg_param_size;
	}

	if (deli_param_size) {
		strcpy(EncZoneParam+idx,DelimiterParam);
		idx += deli_param_size;
	}

	if (fixed_param_size) {
		strcpy(EncZoneParam+idx,FixedParam);
		idx += fixed_param_size;
	}

	EncZoneParam[EncZoneParamSize] = 0;

	return 0;
}


dgt_sint32 PfccAgentParamBuilder::buildScheduleParams(dgt_sint64 schedule_date_id) throw(DgcExcept)
{
	dgt_uint32 start_date = 0;
	dgt_uint32 end_date = 0;

	dgt_uint8 week_map = 255;
	dgt_uint8 start_hour = 0;
	dgt_uint8 start_min = 0;
	dgt_uint8 end_hour = 23;
	dgt_uint8 end_min = 59;
	dgt_uint16 use_cores = 0;
	dgt_sint64 schedule_id = 0;
	if (schedule_date_id) {
		// 1. search pfct_schedule_date to get start_date and end_date
		DgcTableSegment* schedule_date_tab = PetraTableHandler->getTable("pfct_schedule_date");
		if (!schedule_date_tab) ATHROWnR(DgcError(SPOS,"getTable[pfct_schedule_date] failed"),-1);
		DgcIndexSegment* schedule_date_tab_idx = PetraTableHandler->getIndex("pfct_schedule_date_idx1");
		if (!schedule_date_tab_idx) ATHROWnR(DgcError(SPOS,"getIndex[pfct_schedule_date_idx1] failed"),-1);

		pfct_type_schedule_date search_date_row;
		memset(&search_date_row,0,sizeof(pfct_type_schedule_date));
		search_date_row.schedule_date_id = schedule_date_id;

		DgcRowList schedule_date_row_list(schedule_date_tab);
		schedule_date_row_list.reset();
		if (schedule_date_tab_idx->find((dgt_uint8*)&search_date_row,schedule_date_row_list,1) < 0) {
			ATHROWnR(DgcError(SPOS,"schedule_date_tab_idx search failed"),-1);
		}

		if (schedule_date_row_list.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"pfct_schedule_date[%lld] data not found",schedule_date_id)),-1);
		schedule_date_row_list.rewind();

		pfct_type_schedule_date* date = 0;
		if (schedule_date_row_list.next() && (date=(pfct_type_schedule_date*)schedule_date_row_list.data())) {
			start_date = date->schedule_start_date;
			end_date = date->schedule_end_date;
		}

		// 2. search pfct_weekly_work_schedule
		DgcTableSegment* weekly_work_schedule_tab = PetraTableHandler->getTable("pfct_weekly_work_schedule");
		if (!weekly_work_schedule_tab) ATHROWnR(DgcError(SPOS,"getTable[pfct_weekly_work_schedule] failed"),-1);
		DgcIndexSegment* weekly_work_schedule_idx2 = PetraTableHandler->getIndex("pfct_weekly_work_schedule_idx2");
		if (!weekly_work_schedule_idx2) ATHROWnR(DgcError(SPOS,"getIndex[pfct_weekly_work_schedule_idx2] failed"),-1);

		pfct_type_weekly_work_schedule work_schedule_row;
		memset(&work_schedule_row,0,sizeof(pfct_type_weekly_work_schedule));
		work_schedule_row.schedule_date_id = schedule_date_id;

		DgcRowList work_schedule_row_list(weekly_work_schedule_tab);
		work_schedule_row_list.reset();
		if (weekly_work_schedule_idx2->find((dgt_uint8*)&work_schedule_row,work_schedule_row_list,1) < 0) {
			ATHROWnR(DgcError(SPOS,"weekly_work_schedule_idx2 search failed"),-1);
		}
		if (work_schedule_row_list.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"pfct_weekly_work_schedule[%lld] data not found",schedule_date_id)),-1);
		work_schedule_row_list.rewind();

		dgt_uint32 len = work_schedule_row_list.numRows() * SCHEDULE_PARAM_MAX_LEN_PER_ROW;
		if (ScheduleParamLen < len) {
			if (ScheduleParam) delete ScheduleParam;
			ScheduleParam = new dgt_schar[len+1];
			ScheduleParamLen = len + 1;
		}
		memset(ScheduleParam,0,ScheduleParamLen);

		pfct_type_weekly_work_schedule* work_schedule = 0;
		dgt_uint32 buffer_size = 0;
		dgt_sint32 schedule_param_idx = 0;
		while (work_schedule_row_list.next() && (work_schedule=(pfct_type_weekly_work_schedule*)work_schedule_row_list.data())) {
			schedule_id = work_schedule->weekly_work_schedule_id;
			week_map = work_schedule->week_map;
			start_hour = work_schedule->start_hour;
			start_min = work_schedule->start_min;
			end_hour = work_schedule->end_hour;
			end_min = work_schedule->end_min;
			use_cores = work_schedule->use_cores;
			buffer_size = work_schedule->buffer_size;
//"(schedule=(id=%lld)(start_date=%u)(end_date=%u)(week_map=%u)(start_hour=%u)(end_hour=%u)(start_min=%u)(end_min=%u)(use_cores=%u))\n";
			sprintf(ScheduleParam + schedule_param_idx,
					SCHEDULE_PARAM_FORMAT,
					schedule_id,
					start_date,
					end_date,
					week_map,
					start_hour,
					end_hour,
					start_min,
					end_min,
					use_cores,
					buffer_size);
			schedule_param_idx = strlen(ScheduleParam);
		}

	} else {
		dgt_uint32 len = SCHEDULE_PARAM_MAX_LEN_PER_ROW;
		if (ScheduleParamLen < len) {
			if (ScheduleParam) delete ScheduleParam;
			ScheduleParam = new dgt_schar[len+1];
			ScheduleParamLen = len + 1;
		}
		memset(ScheduleParam,0,ScheduleParamLen);
		schedule_id = 1;
		sprintf(ScheduleParam,
				SCHEDULE_PARAM_FORMAT,
				schedule_id,
				start_date,
				end_date,
				week_map,
				start_hour,
				end_hour,
				start_min,
				end_min,
				use_cores,
				0);
	}

	return 0;
}


dgt_sint32 PfccAgentParamBuilder::buildJobParams(dgt_sint64 job_id) throw(DgcExcept)
{
	// 0. search pfct_enc_job_tgt for enc_zone_id, target_path and ouput_path
	DgcTableSegment* job_tgt_tab = PetraTableHandler->getTable("pfct_enc_job_tgt");
	if (!job_tgt_tab) ATHROWnR(DgcError(SPOS,"getTable[pfct_enc_job_tgt] failed"),-1);
	DgcIndexSegment* enc_job_tab_idx2 = PetraTableHandler->getIndex("pfct_enc_job_tgt_idx2");
	if (!enc_job_tab_idx2) ATHROWnR(DgcError(SPOS,"getIndex[pfct_enc_job_tgt_idx2] failed"),-1);

	pfct_type_enc_job_tgt job_tgt_row;
	memset(&job_tgt_row,0,sizeof(pfct_type_enc_job_tgt));
	job_tgt_row.enc_job_id = job_id;

	DgcRowList job_tgt_row_list(job_tgt_tab);
	job_tgt_row_list.reset();

	if (enc_job_tab_idx2->find((dgt_uint8*)&job_tgt_row,job_tgt_row_list,1) < 0) {
		ATHROWnR(DgcError(SPOS,"enc_job_tab_idx2 search failed"),-1);
	}

	//this exception is returned -901130,
	//because default configuration job is not error to be pfct_enc_job_tgt data not found
	//therefore -901130 return values have checking if default configuration job
	if (job_tgt_row_list.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"pfct_enc_job_tgt[%lld] data not found",job_id)),-901130);

	// 1. calculate crypt_dir parameter size
	pfct_type_enc_job_tgt* job_tgt = 0;
	dgt_uint32 len = 0;
	job_tgt_row_list.rewind();
	while (job_tgt_row_list.next() && (job_tgt=(pfct_type_enc_job_tgt*)job_tgt_row_list.data())) {
		len += dg_strlen(job_tgt->target_path);
		len += dg_strlen(job_tgt->output_path);
		len += PARAM_MIN_LEN;
	}

	if (CryptDirParamLen < len) {
		if (CryptDirParam) delete CryptDirParam;
		CryptDirParam = new dgt_schar[len+1];
		CryptDirParamLen = len + 1;
	}
	memset(CryptDirParam,0,CryptDirParamLen);
	// 2. build crypt_dir params
	DgcHashTable zone_id_hash(10);
	dgt_uint32	zone_id_count = 0;

	//2018.07.11 added by shson
	DgcHashTable enc_job_tgt_id_hash(100);
	dgt_uint32	enc_job_tgt_id_count = 0;
	job_tgt_row_list.rewind();
	dgt_uint32 idx  = 0;

	while (job_tgt_row_list.next() && (job_tgt=(pfct_type_enc_job_tgt*)job_tgt_row_list.data())) {
		//
		// "(crypt_dir=(id=%lld)(zone_id=%lld)(src_dir=\"%s\")(dst_dir=\"%s\")(dir_rule=(version=%d)(sfd=%d)(sld=%d)(efd=%d)(eld=%d)))"
		//
		if ((InitParamFlag && job_tgt->status == PCC_STATUS_TYPE_DELETED) || job_tgt->enc_zone_id == 0) continue;

		//2018.07.11 added by shson
		// get dir_rule
		pfct_type_enc_zone_dir_rule dir_rule_row;
		dir_rule_row.enc_job_tgt_id = job_tgt->enc_job_tgt_id;
		dir_rule_row.version = 0;
		dir_rule_row.search_first_depth = 0;
		dir_rule_row.search_last_depth = 100;
		dir_rule_row.enc_first_depth = 0;
		dir_rule_row.enc_last_depth = 100;

		DgcTableSegment* dir_rule_tab = PetraTableHandler->getTable("pfct_enc_zone_dir_rule");
		if (!dir_rule_tab) ATHROWnR(DgcError(SPOS,"getTable[pfct_enc_zone_dir_rule] failed"),-1);
		DgcIndexSegment* dir_rule_tab_idx = PetraTableHandler->getIndex("pfct_enc_zone_dir_rule_idx2");
		if (!dir_rule_tab_idx) ATHROWnR(DgcError(SPOS,"getIndex[pfct_schedule_date_idx2] failed"),-1);

		pfct_type_enc_zone_dir_rule search_dir_rule_row; // for index

		memset(&search_dir_rule_row,0,sizeof(pfct_type_enc_zone_dir_rule));
		search_dir_rule_row.enc_job_tgt_id = job_tgt->enc_job_tgt_id;


		DgcRowList dir_rule_row_list(dir_rule_tab);
		dir_rule_row_list.reset();
		if (dir_rule_tab_idx->find((dgt_uint8*)&search_dir_rule_row,dir_rule_row_list,1) < 0) {
			ATHROWnR(DgcError(SPOS,"dir_rule_tab_idx search failed"),-1);
		}

		if (dir_rule_row_list.numRows() > 0) {
			dir_rule_row_list.rewind();
			pfct_type_enc_zone_dir_rule* dir_rule = 0;
			if (dir_rule_row_list.next() && (dir_rule=(pfct_type_enc_zone_dir_rule*)dir_rule_row_list.data())) {
				dir_rule_row.version = dir_rule->version;
				dir_rule_row.search_first_depth = dir_rule->search_first_depth;
				dir_rule_row.search_last_depth = dir_rule->search_last_depth;
				dir_rule_row.enc_first_depth = dir_rule->enc_first_depth;
				dir_rule_row.enc_last_depth = dir_rule->enc_last_depth;
			}
		}

		sprintf(CryptDirParam+idx,
				CRYPT_DIR_PARAM_FORMAT,
				job_tgt->enc_job_tgt_id,
				job_tgt->enc_zone_id,
				job_tgt->status,
				job_tgt->target_path,
				job_tgt->output_path,
				dir_rule_row.version,
				dir_rule_row.search_first_depth,
				dir_rule_row.search_last_depth,
				dir_rule_row.enc_first_depth,
				dir_rule_row.enc_last_depth);
		idx += dg_strlen(CryptDirParam+idx);
		// put enc_zone_id into hash table
		if (zone_id_hash.findNode(job_tgt->enc_zone_id) == 0) {
			zone_id_hash.addNode(0,job_tgt->enc_zone_id,(dgt_void*)0);
			zone_id_count++;
		}
		//2018.07.11 added by shson
		if (enc_job_tgt_id_hash.findNode(job_tgt->enc_job_tgt_id) == 0) {
			enc_job_tgt_id_hash.addNode(0,job_tgt->enc_job_tgt_id,(dgt_void*)0);
			enc_job_tgt_id_count++;
		}
	}

	// 3. create bind rows with enc_zone_id
	DgcHashNode* hash_row = 0;
	dgt_sint64 enc_zone_id = 0;
	DgcMemRows zone_id_rows(1);
	zone_id_rows.addAttr(DGC_SB8, 0, "enc_zone_id");
	zone_id_rows.reset();
	zone_id_hash.rewind();
	while((hash_row=zone_id_hash.nextNode())) {
		enc_zone_id = (dgt_sint64)hash_row->NumKey;
		if (enc_zone_id) {
			zone_id_rows.add();
			zone_id_rows.next();
			*((dgt_sint64*)zone_id_rows.data()) = enc_zone_id;
		}
	}
	// 4. create bind rows with enc_job_tgt_id
	hash_row = 0;
	dgt_sint64 enc_job_tgt_id = 0;
	DgcMemRows enc_job_tgt_id_rows(1);
	enc_job_tgt_id_rows.addAttr(DGC_SB8, 0, "enc_job_tgt_id");
	enc_job_tgt_id_rows.reset();
	enc_job_tgt_id_hash.rewind();
	while((hash_row=enc_job_tgt_id_hash.nextNode())) {
		enc_job_tgt_id = (dgt_sint64)hash_row->NumKey;
		if (enc_job_tgt_id) {
			enc_job_tgt_id_rows.add();
			enc_job_tgt_id_rows.next();
			*((dgt_sint64*)enc_job_tgt_id_rows.data()) = enc_job_tgt_id;
		}
	}

	if (zone_id_rows.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"zone_id_rows data not found [%lld]",job_id)),-901130);

	if (enc_job_tgt_id_rows.numRows() == 0) THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"enc_job_tgt_id_rows data not found [%lld]",job_id)),-1);

	// 5. build zone parameters
	if (buildEncZoneParams(&zone_id_rows) < 0) ATHROWnR(DgcError(SPOS,"buildEncZoneParam failed"),-1);

	// 5. build dir_pttn parameters
	if (buildDirPttnParams(&enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"buildDirPttnParams failed"),-1);

	// 6. build file_pttn parameters
	if (buildFilePttnParams(&enc_job_tgt_id_rows) < 0) ATHROWnR(DgcError(SPOS,"buildFilePttnParams failed"),-1);

	return 0;
}


dgt_sint32 PfccAgentParamBuilder::buildAgentParams(dgt_sint64 job_id, dgt_sint64 schedule_date_id) throw(DgcExcept)
{
	dgt_sint32 rtn = 0;
	AgentParamSize = 0;
	// 1. build schedule parameter
	if (buildScheduleParams(schedule_date_id) < 0) ATHROWnR(DgcError(SPOS,"buildScheduleParams failed"),-1);

		
	DgcSqlHandle sql_handle(DgcDbProcess::sess());
	dgt_schar sql_text[256] = {0};
	sprintf(sql_text, "select job_type from pfct_enc_job where enc_job_id = %lld", job_id);
	if (sql_handle.execute(sql_text) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
	
	dgt_void* rtn_row = 0;
	if (sql_handle.fetch(rtn_row) < 0) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
	if (rtn_row) memcpy(&JobType, rtn_row, sizeof(dgt_sint32));

	// 2. build zone parameter
	if ((rtn=buildJobParams(job_id)) < 0) {
		ATHROWnR(DgcError(SPOS,"buildJobParams failed"),rtn);
	}

	dgt_uint32 schedule_param_size = dg_strlen(ScheduleParam);
	dgt_uint32 crypt_dir_param_size = dg_strlen(CryptDirParam);
	dgt_uint32 dir_pttn_param_size = dg_strlen(DirPttnParam);
	dgt_uint32 file_pttn_param_size = dg_strlen(FilePttnParam);
pr_debug("schedule_param_size[%u] EncZoneParamSize[%u] crypt_dir_param_size[%u] dir_pttn_param_size[%u] file_pttn_param_size[%u]\n",schedule_param_size,EncZoneParamSize,crypt_dir_param_size,dir_pttn_param_size,file_pttn_param_size);

	AgentParamSize = schedule_param_size + EncZoneParamSize + crypt_dir_param_size + dir_pttn_param_size + file_pttn_param_size;

	if (AgentParamLen < AgentParamSize + 1) {
		if (AgentParam) delete AgentParam;
		AgentParam = new dgt_schar[AgentParamSize + 1];
		AgentParamLen = AgentParamSize + 1;
	}

	dgt_uint32 idx = 0;
	if (schedule_param_size) {
		strcpy(AgentParam+idx,ScheduleParam);
		idx += schedule_param_size;
	}

	if (EncZoneParamSize) {
		strcpy(AgentParam+idx,EncZoneParam);
		idx += EncZoneParamSize;
	}

	if (crypt_dir_param_size) {
		strcpy(AgentParam+idx,CryptDirParam);
		idx += crypt_dir_param_size;
	}

	if (dir_pttn_param_size) {
		strcpy(AgentParam+idx,DirPttnParam);
		idx += dir_pttn_param_size;
	}

	if (file_pttn_param_size) {
		strcpy(AgentParam+idx,FilePttnParam);
		idx += file_pttn_param_size;
	}

	AgentParam[AgentParamSize] = 0;

pr_debug("##AgentParam:\n%s",AgentParam);
	return 0;
}
