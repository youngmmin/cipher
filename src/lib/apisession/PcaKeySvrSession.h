/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaKeySvrSession
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API key server session
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_KEY_SVR_SESSION_H
#define PCA_KEY_SVR_SESSION_H


#include "DgcObject.h"
#include "PciMsgTypes.h"
#include "PcaCredentials.h"
#include "PcaLogger.h"

#include "DgcSockStream.h"
#include "DgcMemRows.h"

class PcaKeySvrSession : public DgcObject {
  private:
  protected:
	static const dgt_sint32 PKSS_BUFFER_LEN         =       1024;

        static const dgt_sint32 PKSS_DFLT_CON_TIMEOUT = 5;
        static const dgt_sint32 PKSS_DFLT_IN_TIMEOUT =  60;
        static const dgt_sint32 PKSS_DFLT_OUT_TIMEOUT = 60;
        static const dgt_uint16 PKSS_DFLT_SVR_PORT = 6699;

	static const dgt_sint32 PKSS_INVALID_HOST       =       -30340;
        static const dgt_sint32 PKSS_SOCKET_ERROR       =       -30341;
        static const dgt_sint32 PKSS_CONNECT_ERROR      =       -30342;
        static const dgt_sint32 PKSS_WRITE_ERROR        =       -30343;
        static const dgt_sint32 PKSS_READ_ERROR         =       -30344;
        static const dgt_sint32 PKSS_BUF_OVERFLOW       =       -30345;
        static const dgt_sint32 PKSS_KEY_NOT_FOUND      =       -30354;

	static dgt_schar	ConfFilePath[256];

	typedef struct {
		dgt_schar	host[65];
		dgt_uint16	port;
		dgt_sint32	con_timeout;
		dgt_sint32	in_timeout;
		dgt_sint32	out_timeout;
		dgt_schar	credentials[1024];
	} pkss_type_hostdef;

	pkss_type_hostdef	Primary;
	pkss_type_hostdef	Secondary;
	pkss_type_hostdef	Third;
	pkss_type_hostdef*	Current;
	dgt_sint32		ErrCode;
	//dgt_schar		ErrMsg[256];
	dgt_schar		ErrMsg[4000];
	dgt_uint8		MarshallBuffer[PKSS_BUFFER_LEN];
	dgt_schar               CredentialsPassword[33]; // credentials password
	PcaCredentials		Credentials;
	dgt_sint32		ConnectTryCnt;
	pkss_type_hostdef*	ConnectList[3];
	dgt_sint32		LoadCount;


#if 0
	//
	// udp logging for oltp service 
	//
#ifndef WIN32
	dgt_sint32		OltpLogMode; // for udp logging mode
	dgt_schar		UdpHost1[65]; // udp host
	dgt_uint16		UdpPort1;     // udp port
        DgcSockDatagram         ClientDatagram1;                // OltpLogMode (for udp connection)
        dgt_sint32              UdpBindFlag;
        dgt_sint64              UdpSendCount;
	dgt_uint8		MashallBuffer[256];
#endif
#endif
	

	inline dgt_sint32 setConnectList()
	{
		ConnectTryCnt = 0;
		if (Current == 0) {
			ConnectList[ConnectTryCnt++] = &Primary;
			if (Secondary.host[0]) ConnectList[ConnectTryCnt++] = &Secondary;
			if (Third.host[0]) ConnectList[ConnectTryCnt++] = &Third;
		} else if (Current == &Primary) {
			if (Secondary.host[0]) ConnectList[ConnectTryCnt++] = &Secondary;
			if (Third.host[0]) ConnectList[ConnectTryCnt++] = &Third;
			ConnectList[ConnectTryCnt++] = &Primary;
		} else if (Current == &Secondary) {
			if (Third.host[0]) ConnectList[ConnectTryCnt++] = &Third;
			ConnectList[ConnectTryCnt++] = &Primary;
			ConnectList[ConnectTryCnt++] = &Secondary;
		} else {
			ConnectList[ConnectTryCnt++] = &Primary;
			if (Secondary.host[0]) ConnectList[ConnectTryCnt++] = &Secondary;
			ConnectList[ConnectTryCnt++] = &Third;
		}
		return ConnectTryCnt;
	};

#if 0
#ifndef WIN32
	dgt_sint32	oltpLogging(pc_type_log_request_in* log_request);
#endif
#endif

	
  public:
        static const dgt_sint32 PKSS_COLUMN_NOT_FOUND   =       -30353;
        static const dgt_sint32 PKSS_SESSION_NOT_FOUND   =       -30701;

	static inline dgt_void logging(const char *fmt, ...)
        {
                va_list ap;
                va_start(ap,fmt);
                PcaLogger::logging(fmt,ap);
                va_end(ap);
        };

        static inline dgt_void logging(dgt_sint32 err_code,const dgt_schar* log_msg)
        {
                PcaLogger::logging(err_code, log_msg);
        };

	static dgt_schar* findConfPath(dgt_schar* conf_file_path);

	PcaKeySvrSession();
	virtual ~PcaKeySvrSession();

	inline dgt_sint32 errCode() { return ErrCode; };
	inline dgt_schar* errMsg() { return ErrMsg; };
	inline PcaCredentials& credentials() { return Credentials; };

	dgt_sint32	loadConfFile(dgt_sint32 is_agent=0);

	virtual dgt_sint32 initialize(const dgt_schar* credentials_password) = 0;

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
		pc_type_open_sess_out*  sess_out) = 0;

	virtual dgt_sint32 getPriv(
		dgt_sint64		user_sid,
		dgt_sint64		enc_col_id,
		pc_type_get_priv_out*	priv_out) = 0;

	virtual dgt_sint32 getVKeyPriv(
		dgt_sint64		user_sid,
		dgt_sint64		virtual_key_id,
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
		dgt_schar*	name10=0) = 0;

	virtual dgt_sint32 getKey(
		dgt_sint64		key_id,
		pc_type_get_key_out*	key_out) = 0;

	virtual dgt_sint32 getIV(
		dgt_uint8		iv_type,
		dgt_uint16		iv_size,
		pc_type_get_iv_out*	iv_out) = 0;

	virtual dgt_sint32 alert(
		pc_type_alert_in* alert_request) = 0;

        virtual dgt_sint32 approve(
                dgt_sint64      user_sid,
                dgt_sint64      enc_col_id,
                dgt_sint64      approve_id,
                dgt_sint32*     result) = 0;

	virtual dgt_sint32 encrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len) = 0;

	virtual dgt_sint32 decrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len) = 0;

	virtual dgt_sint32 encrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len,
		dgt_sint32	ksv_num) = 0;

	virtual dgt_sint32 decrypt(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len,
		dgt_sint32	ksv_num) = 0;

	virtual dgt_sint32 encryptCpn(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	src,
		dgt_sint32	src_len,
		dgt_uint8*	coupon,
		dgt_uint32*	coupon_len) = 0;

	virtual dgt_sint32 decryptCpn(
		dgt_sint64 	enc_col_id,
		dgt_uint8*	coupon,
		dgt_sint32	coupon_len,
		dgt_uint8*	dst,
		dgt_uint32*	dst_len) = 0;

	virtual dgt_sint32 getEncColID(
		const dgt_schar*	name,
		dgt_sint64*		enc_col_id) = 0;

	virtual dgt_sint32 getZoneID(
		const dgt_schar*	name,
		dgt_sint64*		zone_id) = 0;

	virtual dgt_sint32 getRegEngineID(
		const dgt_schar*	name,
		dgt_sint64*		reg_engine_id) = 0;

	virtual dgt_sint32 encCount(
                dgt_sint64	enc_col_id,
		dgt_sint64	enc_count) = 0;

	virtual dgt_sint32 posting(
                dgt_sint64      user_sid,
                dgt_sint64      enc_col_id,
                dgt_sint32      err_code) = 0;

	virtual dgt_sint32 logRequest(pc_type_log_request_in* log_request) = 0;
	virtual dgt_sint32 putExtKey(const dgt_schar* key_name,const dgt_schar* key, dgt_uint16 foramt_no) = 0;
        virtual dgt_sint32 getTrailer(
                dgt_sint64              key_id,
                pc_type_get_trailer_out* trailer_out) = 0;

	virtual dgt_sint32 logFileRequest(pc_type_file_request_in* log_request) = 0;
	virtual dgt_sint32 logUserFileRequest(pc_type_user_file_request_in* log_request) = 0;

	virtual dgt_sint32 getZoneParam(dgt_sint64 zone_id, dgt_schar* param) = 0;
	virtual dgt_sint32 getRegEngine(dgt_sint64 reg_engine_id, dgt_schar* param) = 0;
	virtual dgt_sint32 getCryptParam(dgt_schar* crypt_param_name, dgt_schar* param) = 0;
	virtual dgt_sint32 logDetectFileRequest(pc_type_detect_file_request_in* log_request,DgcMemRows* log_data) = 0;
	virtual dgt_sint32 getDetectFileRequest(DgcMemRows* get_request) = 0;
	virtual dgt_sint32 getRsaKey(dgt_schar* key_name, dgt_schar* key_string) = 0;

};


#endif
