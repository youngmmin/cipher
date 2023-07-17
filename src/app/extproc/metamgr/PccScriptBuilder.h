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
#ifndef PCC_SCRIPT_BUILDER_H
#define PCC_SCRIPT_BUILDER_H

#include "DgcDatabase.h"
#include "PccTableTypes.h"
#include "DgcCliConnection.h"
#include "DgcDbProcess.h"

typedef struct {
	dgt_schar	col_name[130];
	dgt_sint32	column_order;
	dgt_schar	data_type[33];
	dgt_sint32	data_length;
	dgt_sint32	data_precision;
	dgt_sint32	data_scale;
	dgt_sint32	nullable_flag;
	dgt_sint64	col_default;
	dgt_uint8	is_identity;
	dgt_sint64	enc_col_id;
	dgt_schar	renamed_col_name[130];
	dgt_uint8	multi_byte_flag;
	dgt_sint16	curr_enc_step;
	dgt_uint8   cipher_type;        /* 0:default, 1:'AES', 2:'SEED', 3:'ARIA', 3:'SHA' */
    dgt_uint16  key_size;            /* Key Size in bits, 128, 192, 256, 384(sha only), 512(sha only)  */
    dgt_uint8   enc_mode;            /* Encrypt Mode, 0:ECB, 1:CBC, 2:CFB, 3:OFB */
    dgt_uint8   iv_type;             /* initial vector type, 0:no iv, 1:random iv, 2:random within predefined iv, 3-7:predefined iv */
    dgt_uint8   n2n_flag;            /* null to null flag */
    dgt_uint8   b64_txt_enc_flag;    /* base64 text encoding flag */
    dgt_uint8   enc_start_pos;       /* encryption start position */
    dgt_uint32  enc_length;          /* encryption length */
    dgt_schar   mask_char[33];       /* mask character string for selecting with no privilige */
    dgt_sint64  coupon_id;
	dgt_uint8	index_type;
	dgt_uint8	normal_idx_flag;
	dgt_schar	domain_index_name[130];
	dgt_schar	fbi_index_name[130];
	dgt_schar	normal_index_name[130];
	dgt_schar	index_col_name[130];
	dgt_uint8	status;                 
} pc_type_col_info;

class PccScriptBuilder : public DgcObject {
  private:
  protected:
	static const dgt_sint32	PCC_MAX_SCRIPT_LEN=200000;
	DgcDatabase*		Database;
	DgcSession*		Session;
	dgt_schar		SchemaLink[33];
	DgcCliConnection*	Connection;

	pct_type_enc_table	TabInfo;
	DgcMemRows		ColInfoRows;
	DgcMemRows		ColInfoRows2;
	dgt_schar*		TextBuf;
	dgt_schar*		TmpBuf;
	dgt_uint16		VersionNo;
	dgt_sint16		StepNo;
	dgt_sint16		StmtNo;
	dgt_schar*		ScriptText;
	dgt_uint16		ParallelDegree;
	dgt_sint32		IsPkFk;
	dgt_schar		SchemaName[33];
	dgt_schar		AgentName[33];
	dgt_schar		DbVersion[33];
	dgt_sint64		Dbid;
	virtual DgcCliConnection* connect(dgt_schar* uid,dgt_schar* pw) throw(DgcExcept) = 0;

        //
        // TabInfo-> getting the table info and setting the parallel degree,IsPkFk,SchemaName
        //
        dgt_sint32 prepareTabInfo(dgt_sint64 enc_tab_id) throw(DgcExcept);
        dgt_sint32 prepareColInfo() throw(DgcExcept);

	dgt_sint32 saveSqlText() throw(DgcExcept);

  public:
	
	PccScriptBuilder(DgcDatabase* db, DgcSession* sess, dgt_schar* schma_link);
	virtual ~PccScriptBuilder();
	virtual dgt_sint32 checkDB(dgt_sint64 db_agent_id,dgt_schar* sys_uid,dgt_schar* sys_pass,dgt_schar* agent_uid,DgcMemRows* rtn_rows) throw(DgcExcept)=0;
	virtual dgt_sint32 setCharset(dgt_sint64 db_agent_id) throw(DgcExcept)=0;
	virtual dgt_sint32 agentTest(dgt_sint64 db_agent_id,DgcMemRows* rtn_rows) throw(DgcExcept)=0;
	virtual dgt_sint32 agentTableTest(dgt_sint64 db_agent_id,DgcMemRows* rtn_rows) throw(DgcExcept)=0;

	inline DgcCliConnection* getConnection(dgt_schar* uid=0,dgt_schar* pw=0) throw(DgcExcept)
	{
		if (!Connection && !(Connection=connect(uid,pw))) {
			ATHROWnR(DgcError(SPOS,"getConnection failed."),0);
		}
		return Connection;
	};

	inline const dgt_schar* scriptText() { return ScriptText; };

	virtual dgt_sint32 getTablespace(DgcMemRows* rtn_rows) throw(DgcExcept) = 0;
	virtual dgt_sint32 buildScript(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) = 0;
	virtual dgt_sint32 buildScriptMig(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) = 0;
	virtual dgt_sint32 migInsertSql(dgt_sint64 it_tab_id, dgt_uint8 gen_flag=0) throw(DgcExcept) = 0;
	virtual dgt_sint32 buildScriptAddCol(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) = 0;
	virtual dgt_sint32 buildScriptColAdmin(dgt_sint64 enc_tab_id,dgt_uint16 version_no) throw(DgcExcept) = 0;
	virtual dgt_sint32 runVerifyMig(dgt_sint64, pct_type_verify_job*) throw(DgcExcept) =0;
	virtual dgt_sint32 buildInstallScript(dgt_sint64 agent_id,dgt_schar* agent_uid,dgt_schar* agent_pass,dgt_schar* soha_home) throw(DgcExcept) = 0;

	virtual dgt_sint32 getScript(	dgt_sint64 enc_tab_id,
					dgt_uint16 version_no,
					dgt_sint16 step_no,
					dgt_sint16 stmt_no,
					DgcMemRows* rtn_rows=0,
					dgt_uint8 comment_flag=0) throw(DgcExcept);

	virtual dgt_sint32 runScript(const dgt_schar* script_text,DgcCliConnection* conn=0) throw(DgcExcept);
	virtual dgt_sint32 runVerifyScript(dgt_schar* script_text, DgcMemRows* rtn_rows) throw(DgcExcept);
};


#endif
