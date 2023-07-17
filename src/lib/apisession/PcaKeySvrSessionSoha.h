/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaKeySvrSessionSoha
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API key server session with soha
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_KEY_SVR_SESSION_SOHA_H
#define PCA_KEY_SVR_SESSION_SOHA_H


#include "PcaKeySvrSession.h"
#include "DgcCliConnection.h"


class PcaKeySvrSessionSoha : public PcaKeySvrSession {
  private:
	DgcMemRows		OpenSessBind;		// bind rows for opening session message
	DgcMemRows		GetPrivBind;		// bind rows for getting privilege
	DgcMemRows		GetKeyBind;		// bind rows for getting key
	DgcMemRows		AlertBind;		// bind rows for alerting
	DgcMemRows		ApproveBind;		// bind rows for approving
	DgcMemRows		GetEciBind;		// bind rows for getting encrypt column id
	DgcMemRows		GetZoneIdBind;		// bind rows for getting zone id
	DgcMemRows		GetRegEngineIdBind;		// bind rows for getting reg_engine id
	DgcMemRows		LogRqstBind;		// bind rows for logging request
	DgcMemRows		CryptBind;		// bind rows for encrypt, decrypt, ophuek, coupon
	DgcMemRows		EncCountBind;		// bind rows for enc_count
	DgcMemRows		PostBind;		// bind rows for post
	DgcMemRows		GetIVBind;		// bind rows for getting iv
	DgcMemRows		PutExtKeyBind;		// bind rows for putting ext key
	DgcMemRows		GetTrailerBind;		// bind rows for getting trailer
	DgcMemRows		FileLogRqstBind;	// bind rows for file logging request
	DgcMemRows		UserFileLogRqstBind;	// bind rows for file logging request
	DgcMemRows		GetVKeyDbPrivBind;		// bind rows for getting privilege with virtual key
	DgcMemRows		GetVKeyFilePrivBind;		// bind rows for getting privilege with virtual key
	DgcMemRows		GetZoneParamBind;		// bind rows for getting enc_zone_param with zone_name
	DgcMemRows		GetRegEngineBind;		// bind rows for getting regular engine with reg_name
	DgcMemRows		GetCryptParamBind;		// bind rows for getting crypt parameter with crypt_param_name
	DgcMemRows		DetectFileLogDataBind;		// bind rows for file logging request 
	DgcMemRows		DetectFileLogRqstBind;		// bind rows for file logging request 
	DgcMemRows              GetRsaKeyBind;                  // bind rows for getting rsa key with rsa_key_name

	DgcCliConnection*	CurrConn;		// current connection
	DgcCliStmt*		OpenSessStmt;		// statement for opening session
	DgcCliStmt*		GetPrivStmt;		// statement for getting privilege
	DgcCliStmt*		GetKeyStmt;		// statement for getting key
	DgcCliStmt*		AlertStmt;		// statement for alerting
	DgcCliStmt*		ApproveStmt;		// statement for approving
	DgcCliStmt*		GetEciStmt;		// statement for getting encrypt column id
	DgcCliStmt*		GetZoneIdStmt;		// statement for getting zone id
	DgcCliStmt*		GetRegEngineIdStmt;		// statement for getting reg_engine id
	DgcCliStmt*		LogRqstStmt;		// statement for logging request
	DgcCliStmt*		CryptStmt;		// statement for crypting
	DgcCliStmt*		EncCountStmt;		// statement for enc_count
	DgcCliStmt*		PostStmt;		// statement for post
	DgcCliStmt*		GetIVStmt;		// statement for getting iv
	DgcCliStmt*		PutExtKeyStmt;		// statement for putting ext key
	DgcCliStmt*		GetTrailerStmt;		// statement for getting trailer
	DgcCliStmt*		FileLogRqstStmt;	// statement for file logging request
	DgcCliStmt*		UserFileLogRqstStmt;	// statement for file logging request
	DgcCliStmt*		GetVKeyDbPrivStmt;		// statement for getting privilege with virtual key
	DgcCliStmt*		GetVKeyFilePrivStmt;		// statement for getting privilege with virtual key
	DgcCliStmt*		GetZoneParamStmt;		// statement for getting enc_zone_param with zone_name
	DgcCliStmt*		GetRegEngineStmt;		// statement for getting regular engine with reg_name
	DgcCliStmt*		GetCryptParamStmt;		// statement for getting crypt parameter with crypt_param_name
	DgcCliStmt*		DetectFileLogDataStmt;	// statement for file logging request
	DgcCliStmt*		DetectFileLogRqstStmt;	// statement for file logging request
	DgcCliStmt*		DetectFileGetRqstStmt;	// statement for file logging request
	DgcCliStmt*             GetRsaKeyStmt;                  // statement for getting rsa key with rsa_key_name


	inline dgt_void setError(DgcExcept* e)
	{
                memset(ErrMsg,0,4000);
		if (e) {
	                DgcError*       err=e->getErr();
        	        dgt_schar msg_buffer[512];
                	while(err->next()) {
	                        memset(msg_buffer,0,512);
        	                sprintf(msg_buffer,"[%s:%d][%s]\n",err->filename(),err->line(),err->message());
                	        strcat(ErrMsg, msg_buffer);
                        	err=err->next();
	                }
        	        memset(msg_buffer,0,512);
                	sprintf(msg_buffer,"[%s:%d][%s]\n",err->filename(),err->line(),err->message());
	                strcat(ErrMsg, msg_buffer);
		}
	};

	inline dgt_void cleanCurrConnection()
	{
		if (OpenSessStmt) { delete OpenSessStmt; OpenSessStmt=0; }
		if (GetKeyStmt) { delete GetKeyStmt; GetKeyStmt=0; }
		if (GetPrivStmt) { delete GetPrivStmt; GetPrivStmt=0; }
		if (AlertStmt) { delete AlertStmt; AlertStmt=0; }
		if (ApproveStmt) { delete ApproveStmt; ApproveStmt=0; }
		if (GetEciStmt) { delete GetEciStmt; GetEciStmt=0; }
		if (GetZoneIdStmt) { delete GetZoneIdStmt; GetZoneIdStmt=0; }
		if (GetRegEngineIdStmt) { delete GetRegEngineIdStmt; GetRegEngineIdStmt=0; }
		if (LogRqstStmt) { delete LogRqstStmt; LogRqstStmt=0; }
		if (CryptStmt) { delete CryptStmt; CryptStmt=0; }
		if (EncCountStmt) { delete EncCountStmt; EncCountStmt=0; }
		if (PostStmt) { delete PostStmt; PostStmt=0; }
		if (GetIVStmt) { delete GetIVStmt; GetIVStmt=0; }
		if (PutExtKeyStmt) { delete PutExtKeyStmt; PutExtKeyStmt=0; }
		if (GetTrailerStmt) { delete GetTrailerStmt; GetTrailerStmt=0; }
		if (FileLogRqstStmt) { delete FileLogRqstStmt; FileLogRqstStmt=0; }
		if (UserFileLogRqstStmt) { delete UserFileLogRqstStmt; UserFileLogRqstStmt=0; }
		if (GetVKeyDbPrivStmt) { delete GetVKeyDbPrivStmt; GetVKeyDbPrivStmt=0; }
		if (GetVKeyFilePrivStmt) { delete GetVKeyFilePrivStmt; GetVKeyFilePrivStmt=0; }
		if (GetZoneParamStmt) { delete GetZoneParamStmt; GetZoneParamStmt=0; }
		if (GetRegEngineStmt) { delete GetRegEngineStmt; GetRegEngineStmt=0; }
		if (GetCryptParamStmt) { delete GetCryptParamStmt; GetCryptParamStmt=0; }
		if (DetectFileLogDataStmt) { delete DetectFileLogDataStmt; DetectFileLogDataStmt=0; }
		if (DetectFileLogRqstStmt) { delete DetectFileLogRqstStmt; DetectFileLogRqstStmt=0; }
		if (DetectFileGetRqstStmt) { delete DetectFileGetRqstStmt; DetectFileGetRqstStmt=0; }
		if (GetRsaKeyStmt) { delete GetRsaKeyStmt; GetRsaKeyStmt=0; }
		if (CurrConn) { delete CurrConn; CurrConn=0; }
	};

	dgt_sint32 connectKeySvr();
	dgt_sint32 crypt(dgt_sint32      msg_type,
			 dgt_sint64      enc_col_id,
			 dgt_uint8*      src,
			 dgt_sint32      src_len,
			 dgt_uint8*      dst,
			 dgt_uint32*     dst_len);

	dgt_sint32 connectKeySvr(dgt_sint32 ksv_num);
	dgt_sint32 crypt(dgt_sint32      msg_type,
			 dgt_sint64      enc_col_id,
			 dgt_uint8*      src,
			 dgt_sint32      src_len,
			 dgt_uint8*      dst,
			 dgt_uint32*     dst_len,
			 dgt_sint32	 ksv_num);
  protected:
  public:
	PcaKeySvrSessionSoha();
	virtual ~PcaKeySvrSessionSoha();

	virtual dgt_sint32 initialize(const dgt_schar* credentials_password=0);

	virtual dgt_sint32 openSession(
		dgt_sint32		db_sid,
		const dgt_schar*	instance_name,
		const dgt_schar*	db_name,
		const dgt_schar*	ip,
		const dgt_schar*	db_user,
		const dgt_schar*	os_user,
		const dgt_schar*	program,
		dgt_uint8		protocol,
		const dgt_schar*	user_id,
		const dgt_schar*	mac,
		pc_type_open_sess_out* sess_out);

	virtual dgt_sint32 getPriv(
		dgt_sint64		user_sid,
		dgt_sint64		enc_col_id,
		pc_type_get_priv_out*   priv_out);

	virtual dgt_sint32 getVKeyPriv(
		dgt_sint64		user_sid,
		dgt_sint64 virtual_key_id,
		dgt_uint8		crypt_type,
		pc_type_get_vkey_priv_out*	priv_out,
		dgt_uint8		target_type,
		dgt_schar*	name1=0,
		dgt_schar*	name2=0,
		dgt_schar*	name3=0,
		dgt_schar*	name4=0,
		dgt_schar*	name5=0,
		dgt_schar*	name6=0,
		dgt_schar*	name7=0,
		dgt_schar*	name8=0,
		dgt_schar*	name9=0,
		dgt_schar*	name10=0);

	virtual dgt_sint32 getVKeyDbPriv(
		dgt_sint64		user_sid,
		dgt_sint64		virtual_key_id,
		dgt_uint8		crypt_type,
		dgt_schar*		db_name,
		dgt_schar*		schema_name,
		dgt_schar*		db_user_name,
		dgt_schar*		table_name,
		dgt_schar*		column_name,
		pc_type_get_vkey_priv_out*   priv_out);

	virtual dgt_sint32 getVKeyFilePriv(
		dgt_sint64		user_sid,
		dgt_sint64		virtual_key_id,
		dgt_uint8		crypt_type,
		dgt_schar*		host_name,
		dgt_schar*		os_user_name,
		dgt_schar*		file_path,
		dgt_schar*		file_name,
		pc_type_get_vkey_priv_out*   priv_out);

	virtual dgt_sint32 getKey(
		dgt_sint64		key_id,
		pc_type_get_key_out*    key_out);

	virtual dgt_sint32 alert(pc_type_alert_in* alert_request);

	virtual dgt_sint32 approve(
		dgt_sint64	user_sid,
		dgt_sint64	enc_col_id,
		dgt_sint64	approve_id,
		dgt_sint32*	result);

	virtual dgt_sint32 encrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len);

	virtual dgt_sint32 decrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len);

        virtual dgt_sint32 encrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
		dgt_sint32	ksv_num);

        virtual dgt_sint32 decrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
		dgt_sint32	ksv_num);

	virtual dgt_sint32 encryptCpn(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	coupon,
		dgt_uint32*	coupon_len);

	virtual dgt_sint32 decryptCpn(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	coupon,
		dgt_sint32	coupon_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len);

	virtual dgt_sint32 getEncColID(
                const dgt_schar*        name,
                dgt_sint64*             enc_col_id);

	virtual dgt_sint32 getZoneID(
                const dgt_schar*        name,
                dgt_sint64*             zone_id);

	virtual dgt_sint32 getRegEngineID(
                const dgt_schar*        name,
                dgt_sint64*             reg_engine_id);

        virtual dgt_sint32 encCount(
                dgt_sint64      enc_col_id,
                dgt_sint64      enc_count);

        virtual dgt_sint32 posting(
                dgt_sint64      user_sid,
                dgt_sint64      enc_col_id,
                dgt_sint32      err_code);

	virtual dgt_sint32 getIV(
		dgt_uint8		iv_no,
		dgt_uint16		iv_size,
		pc_type_get_iv_out*     iv_out);

	virtual dgt_sint32 logRequest(pc_type_log_request_in* log_request);
	virtual dgt_sint32 putExtKey(const dgt_schar* key_name,const dgt_schar* key, dgt_uint16 foramt_no);
        virtual dgt_sint32 getTrailer(
                dgt_sint64              key_id,
                pc_type_get_trailer_out* trailer_out);	

	virtual dgt_sint32 logFileRequest(pc_type_file_request_in* log_request);
	virtual dgt_sint32 logUserFileRequest(pc_type_user_file_request_in* log_request);

	virtual dgt_sint32 getZoneParam(dgt_sint64 zone_id, dgt_schar* param);
	virtual dgt_sint32 getRegEngine(dgt_sint64 reg_engine_id, dgt_schar* param);
	virtual dgt_sint32 getCryptParam(dgt_schar* crypt_param_name, dgt_schar* param);
	virtual dgt_sint32 logDetectFileRequest(pc_type_detect_file_request_in* log_request, DgcMemRows* log_data);
	virtual dgt_sint32 getDetectFileRequest(DgcMemRows* get_request);
	virtual dgt_sint32 getRsaKey(dgt_schar* key_param_name, dgt_schar* key_string);
};


#endif
