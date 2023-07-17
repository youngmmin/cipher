/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PfccAgentParamBuilder
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 7. 31
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 modified build parameter because dir_pttn, file_pttn is moved dependency to job_tgt_dir
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_AGENT_PARAM_BUILDER_H
#define PFCC_AGENT_PARAM_BUILDER_H

#include "DgcSqlHandle.h"
#include "PfccTableTypes.h"
#include "DgcDgConstType.h"
#include "PccAgentMsg.h"

static const dgt_uint8 PFCC_TYPE_FILE_FORMAT_WHOLE		= 1;
static const dgt_uint8 PFCC_TYPE_FILE_FORMAT_PTTN		= 2;
static const dgt_uint8 PFCC_TYPE_FILE_FORMAT_DELI		= 3;
static const dgt_uint8 PFCC_TYPE_FILE_FORMAT_FIXED		= 4;

typedef struct {
	dgt_sint64 enc_zone_id;
	dgt_sint64 enc_col_id;
	dgt_sint64 pattern_id;
	dgt_uint16 column_no;
	dgt_schar enc_col_name[130];
	dgt_schar table_name[130];
} pfct_apb_get_col_key_out;

class PfccAgentParamBuilder : public DgcObject {
  private:
	static const dgt_uint32 PARAM_MIN_LEN						= 128;
	static const dgt_uint32 SCHEDULE_PARAM_MAX_LEN_PER_ROW		= 256;
	static const dgt_uint32 ENC_ZONE_PARAM_MAX_LEN_PER_ROW		= 384;
	static const dgt_uint32 REGULAR_PARAM_MAX_LEN_PER_ROW		= 512;
	static const dgt_uint32 DELIMITER_PARAM_MAX_LEN_PER_ROW		= 256;
	static const dgt_uint32 FIXED_PARAM_MAX_LEN_PER_ROW			= 1024;

	static const dgt_schar SCHEDULE_PARAM_FORMAT[];
	static const dgt_schar CRYPT_DIR_PARAM_FORMAT[];
	static const dgt_schar ENC_ZONE_PARAM_FORMAT[];
	static const dgt_schar SYSTEM_INFO_PARAM_FORMAT[];
	static const dgt_schar DELIMITER_PARAM_FORMAT[];
	static const dgt_schar FIXED_PARAM_FORMAT[];

	dgt_sint64	AgentID;
	dgt_uint8	InitParamFlag;
	dgt_sint32	JobType;
	// real size of parameter
	dgt_uint32	AgentParamSize;
	dgt_uint32	EncZoneParamSize;

	// optimal buffer size
	dgt_uint32	AgentParamLen;
	dgt_uint32	EncZoneParamLen;
	dgt_uint32	ScheduleParamLen;
	dgt_uint32	CryptDirParamLen;
	dgt_uint32	ZoneParamLen;
	dgt_uint32	SystemInfoParamLen;
	dgt_uint32	KeyParamLen;
	dgt_uint32	RegularParamLen;
	dgt_uint32	DelimiterParamLen;
	dgt_uint32	FixedParamLen;
	dgt_uint32	DirPttnParamLen;
	dgt_uint32	FilePttnParamLen;

	// parameter buffers
	dgt_schar*	AgentParam;
	dgt_schar*	EncZoneParam;
	dgt_schar*	ScheduleParam;
	dgt_schar*	CryptDirParam;
	dgt_schar*	ZoneParam;
	dgt_schar*	SystemInfoParam;
	dgt_schar*	KeyParam;
	dgt_schar*	RegularParam;
	dgt_schar*	DelimiterParam;
	dgt_schar*	FixedParam;
	dgt_schar*	DirPttnParam;
	dgt_schar*	FilePttnParam;

	dgt_sint64	SystemID;
	dgt_schar	SystemIP[65];
	dgt_schar	SystemName[129];

	dgt_sint32	getSystemInfo() throw(DgcExcept);
	dgt_sint32	getJobType(dgt_sint64 job_id) throw(DgcExcept);
  protected:
  public:
	PfccAgentParamBuilder(dgt_sint64 agent_id, dgt_uint8 init_flag=0);
	virtual ~PfccAgentParamBuilder();

	inline dgt_uint32 agentParamSize() { return AgentParamSize; };
	inline dgt_uint32 encZoneParamSize() { return EncZoneParamSize; };

	inline dgt_schar* agentParam() { return AgentParam; };
	inline dgt_schar* scheduleParam() { return ScheduleParam; };
	inline dgt_schar* cryptDirParam() { return CryptDirParam; };
	inline dgt_schar* encZoneParam() { return EncZoneParam; };
	inline dgt_schar* keyParam() { return KeyParam; };
	inline dgt_schar* regularParam() { return RegularParam; };
	inline dgt_schar* delimiterParam() { return DelimiterParam; };
	inline dgt_schar* fixedParam() { return FixedParam; };
	inline dgt_schar* dirPttnParam() { return DirPttnParam; };
	inline dgt_schar* filePttnParam() { return FilePttnParam; };

	dgt_sint32	buildDirPttnParams(DgcMemRows* enc_job_tgt_id_rows) throw(DgcExcept);
	dgt_sint32	buildFilePttnParams(DgcMemRows* enc_job_tgt_id_rows) throw(DgcExcept);
	dgt_sint32	buildEncZoneParams(DgcMemRows* zone_id_rows) throw(DgcExcept);
	dgt_sint32	buildScheduleParams(dgt_sint64 schedule_date_id) throw(DgcExcept);
	dgt_sint32	buildJobParams(dgt_sint64 job_id) throw(DgcExcept);
	dgt_sint32	buildAgentParams(dgt_sint64 job_id, dgt_sint64 schedule_id) throw(DgcExcept);
};

#endif
