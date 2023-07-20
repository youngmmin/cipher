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
#include "PcaKeySvrSession.h"

dgt_schar PcaKeySvrSession::ConfFilePath[256] = "";

#ifdef WIN32
static const dgt_schar* PKSS_DEFAULT_CONF_FILE_PATH =
    "C:\\Program Files\\SINSIWAY\\Petra\\api\\petra_cipher_api.conf";
#else
static const dgt_schar* PKSS_DEFAULT_CONF_FILE_PATH =
    "/var/tmp/.petra/petra_cipher_api.conf";
#endif

dgt_schar* PcaKeySvrSession::findConfPath(dgt_schar* conf_file_path) {
    memset(ConfFilePath, 0, 256);
    if (conf_file_path && *conf_file_path) {
        strncpy(ConfFilePath, conf_file_path, 255);
        return ConfFilePath;
    }
#ifdef WIN32

#else
    FILE* fp = 0;
    //
    // added by mwpark
    // 2016. 09. 01 nh requirement
    // conf file using os enviorment variable
    //
    if ((conf_file_path = dg_getenv("PC_CONF_FILE")) && *conf_file_path) {
        sprintf(ConfFilePath, "%s", conf_file_path);
        if ((fp = fopen(ConfFilePath, "r"))) {
            fclose(fp);
            return ConfFilePath;
        }
    }

    if ((conf_file_path = dg_getenv("ORACLE_SID")) && *conf_file_path) {
        sprintf(ConfFilePath, "/var/tmp/.petra/petra_cipher_api_ora_%s.conf",
                dg_strnupper(conf_file_path, 256));
        if ((fp = fopen(ConfFilePath, "r"))) {
            fclose(fp);
            return ConfFilePath;
        }
    }

    if ((conf_file_path = dg_getenv("ORACLE_HOME")) && *conf_file_path) {
        sprintf(ConfFilePath, "%s/petra_cipher_api.conf", conf_file_path);
        if ((fp = fopen(ConfFilePath, "r"))) {
            fclose(fp);
            return ConfFilePath;
        }
    }

    if ((conf_file_path = dg_getenv("TB_SID")) && *conf_file_path) {
        sprintf(ConfFilePath, "/var/tmp/.petra/petra_cipher_api_tib_%s.conf",
                dg_strnupper(conf_file_path, 256));
        if ((fp = fopen(ConfFilePath, "r"))) {
            fclose(fp);
            return ConfFilePath;
        }
    }
#endif
    strncpy(ConfFilePath, PKSS_DEFAULT_CONF_FILE_PATH, 255);
    return ConfFilePath;
}

PcaKeySvrSession::PcaKeySvrSession()
#ifndef WIN32
    : Current(0),
      ErrCode(0),
      LoadCount(0)
#else
    : Current(0),
      ErrCode(0),
      LoadCount(0)
#endif
{
    memset(&Primary, 0, sizeof(Primary));
    memset(&Secondary, 0, sizeof(Secondary));
    memset(&Third, 0, sizeof(Third));
    Primary.con_timeout = Secondary.con_timeout = Third.con_timeout =
        PKSS_DFLT_CON_TIMEOUT;
    Primary.in_timeout = Secondary.in_timeout = Third.in_timeout =
        PKSS_DFLT_IN_TIMEOUT;
    Primary.out_timeout = Secondary.out_timeout = Third.out_timeout =
        PKSS_DFLT_OUT_TIMEOUT;
    Primary.port = Secondary.port = Third.port = PKSS_DFLT_SVR_PORT;
    memset(ErrMsg, 0, 256);
    memset(CredentialsPassword, 0, 33);
}

PcaKeySvrSession::~PcaKeySvrSession() {}

#include "PcaNameValuePair.h"

dgt_sint32 PcaKeySvrSession::loadConfFile(dgt_sint32 is_agent) {
    PcaNameValuePair nvp;
    if ((ErrCode = nvp.parseFromFile(ConfFilePath))) {
        strncpy(ErrMsg, nvp.errMsg(), 255);
        logging("%s, parsing[%s].", ErrMsg, ConfFilePath);
    } else {
        dgt_schar* val = 0;
        dgt_sint32 reload_before_conn_flag = 0;
        if ((val = nvp.getValue("keysvr.reload_before_connect_flag")))
            reload_before_conn_flag = strtol(val, 0, 10);
        if (LoadCount++ == 0 || reload_before_conn_flag) {
            if (is_agent) {
                if ((val = nvp.getValue("agent.primary.host")))
                    strncpy(Primary.host, val, 64);
                if ((val = nvp.getValue("agent.primary.port")))
                    Primary.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.primary.credentials")))
                    strncpy(Primary.credentials, val, 1023);
                if ((val = nvp.getValue("agent.secondary.host")))
                    strncpy(Secondary.host, val, 64);
                if ((val = nvp.getValue("agent.secondary.port")))
                    Secondary.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.secondary.credentials")))
                    strncpy(Secondary.credentials, val, 1023);
                if ((val = nvp.getValue("agent.third.host")))
                    strncpy(Third.host, val, 64);
                if ((val = nvp.getValue("agent.third.port")))
                    Third.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.third.credentials")))
                    strncpy(Third.credentials, val, 1023);
            } else {
                if ((val = nvp.getValue("keysvr.primary.host")))
                    strncpy(Primary.host, val, 64);
                if ((val = nvp.getValue("keysvr.primary.port")))
                    Primary.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.primary.con_timeout")))
                    Primary.con_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.primary.In_timeout")))
                    Primary.in_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.primary.out_timeout")))
                    Primary.out_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.primary.credentials")))
                    strncpy(Primary.credentials, val, 1023);
                if ((val = nvp.getValue("keysvr.secondary.host")))
                    strncpy(Secondary.host, val, 64);
                if ((val = nvp.getValue("keysvr.secondary.port")))
                    Secondary.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.secondary.con_timeout")))
                    Secondary.con_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.secondary.In_timeout")))
                    Secondary.in_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.secondary.out_timeout")))
                    Secondary.out_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.secondary.credentials")))
                    strncpy(Secondary.credentials, val, 1023);
                if ((val = nvp.getValue("keysvr.third.host")))
                    strncpy(Third.host, val, 64);
                if ((val = nvp.getValue("keysvr.third.port")))
                    Third.port = (dgt_uint16)strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.third.con_timeout")))
                    Third.con_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.third.In_timeout")))
                    Third.in_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.third.out_timeout")))
                    Third.out_timeout = strtol(val, 0, 10);
                if ((val = nvp.getValue("keysvr.third.credentials")))
                    strncpy(Third.credentials, val, 1023);
#if 0
#ifndef WIN32
				if ((val=nvp.getValue("oltp_log_mode"))) OltpLogMode=(dgt_sint32)strtol(val,0,10);
				if ((val=nvp.getValue("udp_host1"))) strncpy(UdpHost1,val,64);
				if ((val=nvp.getValue("udp_port1"))) UdpPort1=(dgt_uint16)strtol(val,0,10);
#endif
#endif
            }
        }
    }
    return ErrCode;
}

#if 0
#ifndef WIN32
dgt_sint32	PcaKeySvrSession::oltpLogging(pc_type_log_request_in* log_request)
{
	//
        // udp connection logging mode
        //
        if (UdpBindFlag == 0) {
        	//
                // try udp bind
                //
                dgt_sint32      ntry=0;
                if (UdpPort1) {
                	if (ClientDatagram1.bindSvrAddress(UdpHost1,UdpPort1) <= 0) {
                        	logging("OLTP LogMode Udp[%s-%u] bind failed.",UdpHost1,UdpPort1);
                                return 0;
                        }
                        UdpBindFlag=1;
                } else {
                	UdpBindFlag=2;
                }
	}
	if (UdpBindFlag == 1) {
		//
		// udp bind success
		//
		memset(MarshallBuffer,0,256);
		mcp8((dgt_uint8*)MarshallBuffer, (dgt_uint8*)&log_request->user_sid);
		mcp8((dgt_uint8*)MarshallBuffer+8, (dgt_uint8*)&log_request->enc_col_id);
		mcp8((dgt_uint8*)MarshallBuffer+16, (dgt_uint8*)&log_request->enc_count);
		mcp8((dgt_uint8*)MarshallBuffer+24, (dgt_uint8*)&log_request->dec_count);
		mcp8((dgt_uint8*)MarshallBuffer+32, (dgt_uint8*)&log_request->lapse_time);
		mcp8((dgt_uint8*)MarshallBuffer+40, (dgt_uint8*)&log_request->stmt_id);
		mcp8((dgt_uint8*)MarshallBuffer+48, (dgt_uint8*)&log_request->sql_cpu_time);
		mcp8((dgt_uint8*)MarshallBuffer+56, (dgt_uint8*)&log_request->sql_elapsed_time);
		mcp4((dgt_uint8*)MarshallBuffer+64, (dgt_uint8*)&log_request->start_date);
		mcp4((dgt_uint8*)MarshallBuffer+68, (dgt_uint8*)&log_request->sql_type);
		*(MarshallBuffer+72)=log_request->enc_no_priv_flag;
		*(MarshallBuffer+73)=log_request->dec_no_priv_flag;
		memcpy(MarshallBuffer+74,&log_request->sql_hash,65);
		memcpy(MarshallBuffer+139,&log_request->reserved,33);
		if (ClientDatagram1.sendData((dgt_uint8*)MarshallBuffer,200) < 0) {
			logging("OLTP LogMode Udp[%s-%u] send failed.",UdpHost1,UdpPort1);
			return 0;
		}
	} else {
		//
		// not defined udp port
		//
		return 0;
	}
	return 0;
}
#endif
#endif
