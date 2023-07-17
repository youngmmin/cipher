/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaKeySvrSessionSock
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API key server session
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PcaKeySvrSessionSoha.h"
#include "PcaNameValuePair.h"
#include "PcaCredentials.h"
#include "DgcSohaConnection.h"
#ifndef WIN32
#include "PccLocalConnection.h"
#endif


dgt_sint32 PcaKeySvrSessionSoha::connectKeySvr()
{
	//
	// clean current client statements & connection
	//
	cleanCurrConnection();

	//
	// load configuration file before connecting
	//
	if (loadConfFile()) return ErrCode;

	//
	// connect to availble key server
	//
	dgt_schar	sql_text[128];
	setConnectList();
	for(dgt_sint32 i=0; i < ConnectTryCnt; i++) {
                Current = ConnectList[i];
		//
		// parse credentials which has service name, user id, password
		//
		if ((ErrCode=Credentials.parse(Current->credentials,CredentialsPassword))) {
			sprintf(ErrMsg,"parsing credentials failed[%s]", Credentials.errMsg());
			logging("%s, 1[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// connect to the key server
		//
		if (strcasecmp(Current->host,"local") == 0) {
			//
			// local(pipe) connection
			//
#ifdef WIN32
			cleanCurrConnection();
			sprintf(ErrMsg,"local connection not available in windows");
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 2[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
#else
			CurrConn = new PccLocalConnection(Current->in_timeout, Current->out_timeout );
			if (CurrConn->connect(Credentials.svcHome(), Credentials.svcName(), Credentials.userID(), Credentials.password(), "petra_cipher_api")) {
				setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
				ErrCode = PKSS_CONNECT_ERROR;
				logging("%s, 3[%s:%u].", ErrMsg, Current->host, Current->port);
				continue;
			}
#endif
		} else {
			//
			// tcp connection
			//
			dgt_schar	con_string[256];
			sprintf(con_string,"(address=(protocol=tcp)(host=%s)(port=%u)(conn_timeout=%d)(in_timeout=%d)(out_timeout=%d)(db_name=%s))",
				Current->host,Current->port,Current->con_timeout,Current->in_timeout,Current->out_timeout,Credentials.svcName());
			CurrConn = new DgcSohaConnection();
			if (CurrConn->connect(con_string, Credentials.svcName(), Credentials.userID(), Credentials.password(), "petra_cipher_api")) {
				setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
				ErrCode = PKSS_CONNECT_ERROR;
				logging("%s, 6[%s:%u].", ErrMsg, Current->host, Current->port);
				continue;
			}
		}
		//
	        // prepare open session statement
		//
		if ((OpenSessStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 7[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call open_session()");
		if (OpenSessStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 7[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get priv statement
		//
		if ((GetPrivStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 9[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_priv()");
		if (GetPrivStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 10[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get key statement
		//
		if ((GetKeyStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 11[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_key()");
		if (GetKeyStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 12[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare alert statement
		//
		if ((AlertStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 13[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call alert()");
		if (AlertStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 14[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare approve statement
		//
		if ((ApproveStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 15[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call approve()");
		if (ApproveStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 16[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get_eci statement
		//
		if ((GetEciStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_eci()");
		if (GetEciStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get_zone_id statement
		//
		if ((GetZoneIdStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_zone_id()");
		if (GetZoneIdStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get_reg_engine_id statement
		//
		if ((GetRegEngineIdStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_reg_engine_id()");
		if (GetRegEngineIdStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare log request statement
		//
		if ((LogRqstStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 19[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call log_request()");
		if (LogRqstStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 20[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare crypt statement
		//
		if ((CryptStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 21[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call crypt()");
		if (CryptStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 22[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare enccount statement
		//
		if ((EncCountStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 23[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call enc_count()");
		if (EncCountStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 24[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare post statement
		//
		if ((PostStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 25[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call post()");
		if (PostStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 26[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// repare getting iv statement
		//
		if ((GetIVStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 27[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_iv()");
		if (GetIVStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 28[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare putting external key statement
		//
		if ((PutExtKeyStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 29[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call put_ext_key()");
		if (PutExtKeyStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 30[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare getting trailer statement
		//
		if ((GetTrailerStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 31[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_trailer()");
		if (GetTrailerStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 32[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare file log request
		//
		if ((FileLogRqstStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 31[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call file_request()");
		if (FileLogRqstStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 32[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}

		//
		// prepare user file logging statement
		//
		if ((UserFileLogRqstStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 33[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call user_file_request()");
		if (UserFileLogRqstStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 34[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		//
		// prepare get vkey db priv statement
		//
		if ((GetVKeyDbPrivStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 33[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_vkey_db_priv()");
		if (GetVKeyDbPrivStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 34[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}

		//
		// prepare get vkey file priv statement
		//
		if ((GetVKeyFilePrivStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 35[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_vkey_file_priv()");
		if (GetVKeyFilePrivStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 36[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}

		//
		// prepare get enc_zone_param statement
		//
		if ((GetZoneParamStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 37[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_zone_param()");
		if (GetZoneParamStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 38[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}

		//
                // prepare get reg engine statement
                //
                if ((GetRegEngineStmt=CurrConn->getStmt()) == 0) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        ErrCode = PKSS_CONNECT_ERROR;
                        logging("%s, 39[%s:%u].", ErrMsg, Current->host, Current->port);
                        continue;
                }
                sprintf(sql_text,"call get_reg_engine()");
                if (GetRegEngineStmt->open(sql_text,strlen(sql_text))) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        ErrCode = PKSS_CONNECT_ERROR;
                        logging("%s, 40[%s:%u].", ErrMsg, Current->host, Current->port);
                        continue;
                }

		//
		// prepare get crypt param statement
		//
		if ((GetCryptParamStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 41[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}
		sprintf(sql_text,"call get_crypt_param()");
		if (GetCryptParamStmt->open(sql_text,strlen(sql_text))) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 42[%s:%u].", ErrMsg, Current->host, Current->port);
			continue;
		}

		//
		// prepare detect file logging statement
		//
		if ((DetectFileLogDataStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
	                ErrCode = PKSS_CONNECT_ERROR;
        	        logging("%s, 43[%s:%u].", ErrMsg, Current->host, Current->port);
                	continue;
	        }
        	sprintf(sql_text,"call detect_file_data()");
	        if (DetectFileLogDataStmt->open(sql_text,strlen(sql_text))) {
        	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                	ErrCode = PKSS_CONNECT_ERROR;
	                logging("%s, 44[%s:%u].", ErrMsg, Current->host, Current->port);
        	        continue;
	        }

		//
		// prepare detect file logging statement
		//
		if ((DetectFileLogRqstStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
	                ErrCode = PKSS_CONNECT_ERROR;
        	        logging("%s, 45[%s:%u].", ErrMsg, Current->host, Current->port);
                	continue;
	        }
        	sprintf(sql_text,"call detect_file_request()");
	        if (DetectFileLogRqstStmt->open(sql_text,strlen(sql_text))) {
        	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                	ErrCode = PKSS_CONNECT_ERROR;
	                logging("%s, 46[%s:%u].", ErrMsg, Current->host, Current->port);
        	        continue;
	        }
		
		//
		// prepare detect file logging statement
		//
		if ((DetectFileGetRqstStmt=CurrConn->getStmt()) == 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
	                ErrCode = PKSS_CONNECT_ERROR;
        	        logging("%s, 47[%s:%u].", ErrMsg, Current->host, Current->port);
                	continue;
	        }
        	sprintf(sql_text,"call get_detect_file_request()");
	        if (DetectFileGetRqstStmt->open(sql_text,strlen(sql_text))) {
        	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                	ErrCode = PKSS_CONNECT_ERROR;
	                logging("%s, 48[%s:%u].", ErrMsg, Current->host, Current->port);
        	        continue;
	        }

		//
		// prepare get rsa key statement
		//
		if ((GetRsaKeyStmt=CurrConn->getStmt()) == 0) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        ErrCode = PKSS_CONNECT_ERROR;
                        logging("%s, 43[%s:%u].", ErrMsg, Current->host, Current->port);
                        continue;
                }
                sprintf(sql_text,"call get_rsa_key()");
                if (GetRsaKeyStmt->open(sql_text,strlen(sql_text))) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        ErrCode = PKSS_CONNECT_ERROR;
                        logging("%s, 44[%s:%u].", ErrMsg, Current->host, Current->port);
                        continue;
                }



		ErrCode = 0;
		//logging("[%s:%u] connected.", Current->host, Current->port);
		break;
	}
	return ErrCode;
}


dgt_sint32 PcaKeySvrSessionSoha::crypt(
	dgt_sint32	msg_type,
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len)
{
	//
	// prepare bind
	//
	CryptBind.reset();
	CryptBind.add();
	CryptBind.next();
	//
	// marshall crypt header, the first bind row
	//
	dgt_uint8*	cp=CryptBind.data();
	mcp4(cp, (dgt_uint8*)&msg_type); // msg_type
	mcp8(cp += 4, (dgt_uint8*)&enc_col_id); // encryption column ID
	mcp4(cp += 8, (dgt_uint8*)&src_len); // source length
	cp += 4;
	dgt_sint32	remains = src_len;
	dgt_sint32	seg_remains = PCI_CRYPT_COL_LEN - 16;
	while(remains > 0) {
		if (remains < seg_remains) seg_remains = remains;
		memcpy(cp, src, seg_remains);
		if ((remains-=seg_remains) > 0) {
			src += seg_remains;
			CryptBind.add();
			CryptBind.next();
			cp = CryptBind.data();
			seg_remains = PCI_CRYPT_COL_LEN;
		}
	}
	dgt_sint32	ntry=0;
CONNECT_AGAIN:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute stmt
	//
	CryptBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=CryptStmt->execute(1000, &CryptBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 1connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// read crypt length first
	//
	DgcMemRows*	rtn_rows = CryptStmt->returnRows();
	dgt_uint32	rtn_remains = 0;
	cp = 0;
	seg_remains = 0;
	if (rtn_rows && rtn_rows->next() && (cp=rtn_rows->data())) {
		mcp4((dgt_uint8*)&rtn_remains, cp);
		cp += 4;
		seg_remains = PCI_CRYPT_COL_LEN - 4;
	}
	if (*dst_len < rtn_remains) {
		sprintf(ErrMsg,"output buffer[%u] underflow for %u", *dst_len, rtn_remains);
		return ErrCode=PKSS_READ_ERROR;
	}
	*dst_len = rtn_remains;

	//
	// read crypt body
	//
	while(rtn_remains > 0) {
		if (rtn_remains < (dgt_uint32)seg_remains) seg_remains = (dgt_sint32)rtn_remains;
		memcpy(dst, cp, rtn_remains);
		if ((rtn_remains-=seg_remains) > 0) {
			if (rtn_rows->next() == 0) {
				//
				// next fetch
				//
				if ((frows=CryptStmt->fetch()) < 0) {
					setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
					return PKSS_READ_ERROR;
				}
				rtn_rows = CryptStmt->returnRows();
				if (rtn_rows == 0 || rtn_rows->next() == 0) {
					//
					// not as much data returned as defined in header
					//
					sprintf(ErrMsg,"not enough crypt data returned");
					return PKSS_READ_ERROR;
				}
			}
			dst += seg_remains;
			cp = rtn_rows->data();
			seg_remains = PCI_CRYPT_COL_LEN;
		}
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::connectKeySvr(dgt_sint32 ksv_num)
{
	//
	// clean current client statements & connection
	//
	cleanCurrConnection();

	//
	// load configuration file before connecting
	//
	if (loadConfFile()) return ErrCode;

	//
	// connect to availble key server
	//
	dgt_schar	sql_text[128];

	Current = 0;
	switch(ksv_num)	{
		case 0: Current = &Primary;					break;
		case 1: if (Secondary.host[0]) Current = &Secondary;		break;
		case 2: if (Third.host[0]) Current = &Third;			break;
		default: return PKSS_INVALID_HOST;	//invalid Key Server
	}
	if (!Current) return PKSS_SESSION_NOT_FOUND;	//key server info. is not exist.

	//
	// parse credentials which has service name, user id, password
	//
	if ((ErrCode=Credentials.parse(Current->credentials,CredentialsPassword))) {
		sprintf(ErrMsg,"parsing credentials failed[%s]", Credentials.errMsg());
		logging("%s, 1[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// connect to the key server
	//
	if (strcasecmp(Current->host,"local") == 0) {
		//
		// local(pipe) connection
		//
#ifdef WIN32
		cleanCurrConnection();
		sprintf(ErrMsg,"local connection not available in windows");
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 2[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
#else
		CurrConn = new PccLocalConnection(Current->in_timeout, Current->out_timeout );
		if (CurrConn->connect(Credentials.svcHome(), Credentials.svcName(), Credentials.userID(), Credentials.password(), "petra_cipher_api")) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 3[%s:%u].", ErrMsg, Current->host, Current->port);
			return ErrCode;
		}
#endif
	} else {
		//
		// tcp connection
		//
		dgt_schar	con_string[256];
		sprintf(con_string,"(address=(protocol=tcp)(host=%s)(port=%u)(conn_timeout=%d)(in_timeout=%d)(out_timeout=%d)(db_name=%s))",
			Current->host,Current->port,Current->con_timeout,Current->in_timeout,Current->out_timeout,Credentials.svcName());
		CurrConn = new DgcSohaConnection();
		if (CurrConn->connect(con_string, Credentials.svcName(), Credentials.userID(), Credentials.password(), "petra_cipher_api")) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			ErrCode = PKSS_CONNECT_ERROR;
			logging("%s, 6[%s:%u].", ErrMsg, Current->host, Current->port);
			return ErrCode;
		}
	}
	//
        // prepare open session statement
	//
	if ((OpenSessStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 7[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call open_session()");
	if (OpenSessStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 7[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get priv statement
	//
	if ((GetPrivStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 9[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_priv()");
	if (GetPrivStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 10[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get key statement
	//
	if ((GetKeyStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 11[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_key()");
	if (GetKeyStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 12[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare alert statement
	//
	if ((AlertStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 13[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call alert()");
	if (AlertStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 14[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare approve statement
	//
	if ((ApproveStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 15[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call approve()");
	if (ApproveStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 16[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get_eci statement
	//
	if ((GetEciStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_eci()");
	if (GetEciStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get_zone_id statement
	//
	if ((GetZoneIdStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_zone_id()");
	if (GetZoneIdStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get_reg_engine_id statement
	//
	if ((GetRegEngineIdStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 17[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_reg_engine_id()");
	if (GetRegEngineIdStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 18[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare log request statement
	//
	if ((LogRqstStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 19[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call log_request()");
	if (LogRqstStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 20[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare crypt statement
	//
	if ((CryptStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 21[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call crypt()");
	if (CryptStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 22[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare enccount statement
	//
	if ((EncCountStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 23[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call enc_count()");
	if (EncCountStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 24[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare post statement
	//
	if ((PostStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 25[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call post()");
	if (PostStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 26[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// repare getting iv statement
	//
	if ((GetIVStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 27[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_iv()");
	if (GetIVStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 28[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare putting external key statement
	//
	if ((PutExtKeyStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 29[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call put_ext_key()");
	if (PutExtKeyStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 30[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare getting trailer statement
	//
	if ((GetTrailerStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 31[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_trailer()");
	if (GetTrailerStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 32[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare file log request
	//
	if ((FileLogRqstStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 31[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call file_request()");
	if (FileLogRqstStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 32[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}

	//
	// prepare user file logging statement
	//
	if ((UserFileLogRqstStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 33[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call user_file_request()");
	if (UserFileLogRqstStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 34[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	//
	// prepare get vkey db priv statement
	//
	if ((GetVKeyDbPrivStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 33[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_vkey_db_priv()");
	if (GetVKeyDbPrivStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 34[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}

	//
	// prepare get vkey file priv statement
	//
	if ((GetVKeyFilePrivStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 35[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_vkey_file_priv()");
	if (GetVKeyFilePrivStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 36[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}

	//
	// prepare get enc_zone_param statement
	//
	if ((GetZoneParamStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 37[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_zone_param()");
	if (GetZoneParamStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 38[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}

	//
        // prepare get reg engine statement
        //
        if ((GetRegEngineStmt=CurrConn->getStmt()) == 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                ErrCode = PKSS_CONNECT_ERROR;
                logging("%s, 39[%s:%u].", ErrMsg, Current->host, Current->port);
                return ErrCode;
        }
        sprintf(sql_text,"call get_reg_engine()");
        if (GetRegEngineStmt->open(sql_text,strlen(sql_text))) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                ErrCode = PKSS_CONNECT_ERROR;
                logging("%s, 40[%s:%u].", ErrMsg, Current->host, Current->port);
                return ErrCode;
        }

	//
	// prepare get crypt param statement
	//
	if ((GetCryptParamStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 41[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}
	sprintf(sql_text,"call get_crypt_param()");
	if (GetCryptParamStmt->open(sql_text,strlen(sql_text))) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		ErrCode = PKSS_CONNECT_ERROR;
		logging("%s, 42[%s:%u].", ErrMsg, Current->host, Current->port);
		return ErrCode;
	}

	//
	// prepare detect file logging statement
	//
	if ((DetectFileLogDataStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                ErrCode = PKSS_CONNECT_ERROR;
	        logging("%s, 43[%s:%u].", ErrMsg, Current->host, Current->port);
        	return ErrCode;
        }
	sprintf(sql_text,"call detect_file_request()");
        if (DetectFileLogDataStmt->open(sql_text,strlen(sql_text))) {
	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
        	ErrCode = PKSS_CONNECT_ERROR;
                logging("%s, 44[%s:%u].", ErrMsg, Current->host, Current->port);
	        return ErrCode;
        }

	//
	// prepare detect file logging statement
	//
	if ((DetectFileLogRqstStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                ErrCode = PKSS_CONNECT_ERROR;
	        logging("%s, 45[%s:%u].", ErrMsg, Current->host, Current->port);
        	return ErrCode;
        }
	sprintf(sql_text,"call detect_file_request()");
        if (DetectFileLogRqstStmt->open(sql_text,strlen(sql_text))) {
	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
        	ErrCode = PKSS_CONNECT_ERROR;
                logging("%s, 46[%s:%u].", ErrMsg, Current->host, Current->port);
	        return ErrCode;
        }

	//
	// prepare detect file logging statement
	//
	if ((DetectFileGetRqstStmt=CurrConn->getStmt()) == 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                ErrCode = PKSS_CONNECT_ERROR;
	        logging("%s, 47[%s:%u].", ErrMsg, Current->host, Current->port);
        	return ErrCode;
        }
	sprintf(sql_text,"call get_detect_file_request()");
        if (DetectFileGetRqstStmt->open(sql_text,strlen(sql_text))) {
	        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
        	ErrCode = PKSS_CONNECT_ERROR;
                logging("%s, 48[%s:%u].", ErrMsg, Current->host, Current->port);
	        return ErrCode;
	}

	ErrCode = 0;
	//logging("[%s:%u] connected.", Current->host, Current->port);
	return ErrCode;
}


dgt_sint32 PcaKeySvrSessionSoha::crypt(
	dgt_sint32	msg_type,
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len,
	dgt_sint32	ksv_num)
{
	//
	// prepare bind
	//
	CryptBind.reset();
	CryptBind.add();
	CryptBind.next();
	//
	// marshall crypt header, the first bind row
	//
	dgt_uint8*	cp=CryptBind.data();
	mcp4(cp, (dgt_uint8*)&msg_type); // msg_type
	mcp8(cp += 4, (dgt_uint8*)&enc_col_id); // encryption column ID
	mcp4(cp += 8, (dgt_uint8*)&src_len); // source length
	cp += 4;
	dgt_sint32	remains = src_len;
	dgt_sint32	seg_remains = PCI_CRYPT_COL_LEN - 16;
	while(remains > 0) {
		if (remains < seg_remains) seg_remains = remains;
		memcpy(cp, src, seg_remains);
		if ((remains-=seg_remains) > 0) {
			src += seg_remains;
			CryptBind.add();
			CryptBind.next();
			cp = CryptBind.data();
			seg_remains = PCI_CRYPT_COL_LEN;
		}
	}
	dgt_sint32	ntry=0;
CONNECT_AGAIN:
	//
	// check connection status
	// 
	if ((ErrCode = connectKeySvr(ksv_num))) return ErrCode;

	//
	// execute stmt
	//
	CryptBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=CryptStmt->execute(1000, &CryptBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 1connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// read crypt length first
	//
	DgcMemRows*	rtn_rows = CryptStmt->returnRows();
	dgt_uint32	rtn_remains = 0;
	cp = 0;
	seg_remains = 0;
	if (rtn_rows && rtn_rows->next() && (cp=rtn_rows->data())) {
		mcp4((dgt_uint8*)&rtn_remains, cp);
		cp += 4;
		seg_remains = PCI_CRYPT_COL_LEN - 4;
	}
	if (*dst_len < rtn_remains) {
		sprintf(ErrMsg,"output buffer[%u] underflow for %u", *dst_len, rtn_remains);
		return ErrCode=PKSS_READ_ERROR;
	}
	*dst_len = rtn_remains;

	//
	// read crypt body
	//
	while(rtn_remains > 0) {
		if (rtn_remains < (dgt_uint32)seg_remains) seg_remains = (dgt_sint32)rtn_remains;
		memcpy(dst, cp, rtn_remains);
		if ((rtn_remains-=seg_remains) > 0) {
			if (rtn_rows->next() == 0) {
				//
				// next fetch
				//
				if ((frows=CryptStmt->fetch()) < 0) {
					setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
					return PKSS_READ_ERROR;
				}
				rtn_rows = CryptStmt->returnRows();
				if (rtn_rows == 0 || rtn_rows->next() == 0) {
					//
					// not as much data returned as defined in header
					//
					sprintf(ErrMsg,"not enough crypt data returned");
					return PKSS_READ_ERROR;
				}
			}
			dst += seg_remains;
			cp = rtn_rows->data();
			seg_remains = PCI_CRYPT_COL_LEN;
		}
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::encrypt(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len,
	dgt_sint32	ksv_num)
{
	return crypt(PCI_MSG_ENCRYPT, enc_col_id, src, src_len, dst, dst_len, ksv_num);
}


dgt_sint32 PcaKeySvrSessionSoha::decrypt(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len,
	dgt_sint32	ksv_num)
{
	return crypt(PCI_MSG_DECRYPT, enc_col_id, src, src_len, dst, dst_len, ksv_num);
}

PcaKeySvrSessionSoha::PcaKeySvrSessionSoha()
	: OpenSessBind(10),
	  GetPrivBind(2),
	  GetKeyBind(1),
	  AlertBind(10),
	  ApproveBind(3),
	  GetEciBind(1),
	  GetZoneIdBind(1),
	  GetRegEngineIdBind(1),
	  LogRqstBind(14),
	  CryptBind(1),
	  EncCountBind(2),
	  PostBind(3),
	  GetIVBind(2),
	  PutExtKeyBind(3),
	  GetTrailerBind(1),
	  FileLogRqstBind(13),
	  UserFileLogRqstBind(14),
	  GetVKeyDbPrivBind(9),
	  GetVKeyFilePrivBind(8),
	  GetZoneParamBind(1),
	  GetRegEngineBind(1),
	  GetCryptParamBind(1),
	  DetectFileLogDataBind(8),
	  DetectFileLogRqstBind(14),
	  GetRsaKeyBind(1),
	  CurrConn(0),
	  OpenSessStmt(0),
	  GetPrivStmt(0),
	  GetKeyStmt(0),
	  AlertStmt(0),
	  ApproveStmt(0),
	  GetEciStmt(0),
	  GetZoneIdStmt(0),
	  GetRegEngineIdStmt(0),
	  LogRqstStmt(0),
	  CryptStmt(0),
	  EncCountStmt(0),
	  PostStmt(0),
	  GetIVStmt(0),
	  PutExtKeyStmt(0),
	  GetTrailerStmt(0),
	  FileLogRqstStmt(0),
	  UserFileLogRqstStmt(0),
	  GetVKeyDbPrivStmt(0),
	  GetVKeyFilePrivStmt(0),
	  GetZoneParamStmt(0),
	  GetRegEngineStmt(0),
	  GetCryptParamStmt(0),
	  DetectFileLogDataStmt(0),
	  DetectFileLogRqstStmt(0),
	  DetectFileGetRqstStmt(0),
	  GetRsaKeyStmt(0)
{

#ifndef WIN32 // added by chchung, 2012.12.8 ensuring the initialization of DgcSession's static variables
	DgcSession::initialization();
#endif
	OpenSessBind.addAttr(DGC_UB4,0,"db_sid");
    OpenSessBind.addAttr(DGC_SCHR,33,"instance_name");
    OpenSessBind.addAttr(DGC_SCHR,33,"db_name");
    OpenSessBind.addAttr(DGC_SCHR,65,"client_ip");
    OpenSessBind.addAttr(DGC_SCHR,33,"db_user");
    OpenSessBind.addAttr(DGC_SCHR,33,"os_user");
    OpenSessBind.addAttr(DGC_SCHR,129,"protocol");
    OpenSessBind.addAttr(DGC_UB1,0,"protocol");
    OpenSessBind.addAttr(DGC_SCHR,33,"user_id");
    OpenSessBind.addAttr(DGC_SCHR,65,"client_mac");
    OpenSessBind.add();

    GetPrivBind.addAttr(DGC_SB8,0,"user_sid");
    GetPrivBind.addAttr(DGC_SB8,0,"enc_col_id");
    GetPrivBind.add();

    GetKeyBind.addAttr(DGC_SB8,0,"key_id");
    GetKeyBind.add();

    AlertBind.addAttr(DGC_SB8,0,"user_sid");
    AlertBind.addAttr(DGC_SB8,0,"enc_col_id");
    AlertBind.addAttr(DGC_SB8,0,"dec_count");
    AlertBind.addAttr(DGC_SB8,0,"stmt_id");
    AlertBind.addAttr(DGC_SB8,0,"level_id");
    AlertBind.addAttr(DGC_UB4,0,"start_date");
    AlertBind.addAttr(DGC_SB4,0,"sql_type");
    AlertBind.addAttr(DGC_UB1,0,"dec_no_priv_flag");
    AlertBind.addAttr(DGC_UB1,0,"op_type");
    AlertBind.addAttr(DGC_SCHR,65,"sql_hash");
    AlertBind.add();

    ApproveBind.addAttr(DGC_SB8,0,"user_sid");
    ApproveBind.addAttr(DGC_SB8,0,"enc_col_id");
    ApproveBind.addAttr(DGC_SB8,0,"approve_id");
    ApproveBind.add();

    GetEciBind.addAttr(DGC_SCHR,132,"enc_name");
    GetEciBind.add();

    GetZoneIdBind.addAttr(DGC_SCHR,132,"zone_name");
    GetZoneIdBind.add();

    GetRegEngineIdBind.addAttr(DGC_SCHR,132,"reg_engine_name");
    GetRegEngineIdBind.add();
    LogRqstBind.addAttr(DGC_SB8,0,"user_sid");
    LogRqstBind.addAttr(DGC_SB8,0,"enc_col_id");
    LogRqstBind.addAttr(DGC_SB8,0,"enc_count");
    LogRqstBind.addAttr(DGC_SB8,0,"dec_count");
    LogRqstBind.addAttr(DGC_SB8,0,"lapse_time");
    LogRqstBind.addAttr(DGC_SB8,0,"stmt_id");
    LogRqstBind.addAttr(DGC_SB8,0,"sql_cpu_time");
    LogRqstBind.addAttr(DGC_SB8,0,"sql_elapsed_time");
    LogRqstBind.addAttr(DGC_UB4,0,"start_time");
    LogRqstBind.addAttr(DGC_SB4,0,"sql_type");
    LogRqstBind.addAttr(DGC_UB1,0,"enc_no_priv_flag");
    LogRqstBind.addAttr(DGC_UB1,0,"dec_no_priv_flag");
    LogRqstBind.addAttr(DGC_SCHR,65,"sql_hash");
    LogRqstBind.addAttr(DGC_SCHR,33,"reserved");
    LogRqstBind.add();

    CryptBind.addAttr(DGC_ACHR, PCI_CRYPT_COL_LEN, "crypt_data");
    CryptBind.add();

    EncCountBind.addAttr(DGC_SB8,0,"enc_col_id");
    EncCountBind.addAttr(DGC_SB8,0,"enc_count");
    EncCountBind.add();

    PostBind.addAttr(DGC_SB8,0,"user_sid");
    PostBind.addAttr(DGC_SB8,0,"enc_col_id");
    PostBind.addAttr(DGC_SB4,0,"err_code");
    PostBind.add();

    GetIVBind.addAttr(DGC_UB1,0,"iv_no");
    GetIVBind.addAttr(DGC_UB2,0,"iv_size");
    GetIVBind.add();

    PutExtKeyBind.addAttr(DGC_SCHR,33,"key_name");
    PutExtKeyBind.addAttr(DGC_SCHR,513,"key");
    PutExtKeyBind.addAttr(DGC_UB2,0,"format_no");
    PutExtKeyBind.add();

    GetTrailerBind.addAttr(DGC_SB8,0,"key_id");
    GetTrailerBind.add();

    FileLogRqstBind.addAttr(DGC_SB8,0,"PSU_ID");
    FileLogRqstBind.addAttr(DGC_SCHR,65,"SYSTEM_NAME");
    FileLogRqstBind.addAttr(DGC_SCHR,128,"SYSTEM_IP");
    FileLogRqstBind.addAttr(DGC_SCHR,256,"FILE_NAME");
    FileLogRqstBind.addAttr(DGC_SCHR,32,"ENC_TYPE");
    FileLogRqstBind.addAttr(DGC_UB1,0,"MODE");
    FileLogRqstBind.addAttr(DGC_SCHR,130,"KEY_NAME");
    FileLogRqstBind.addAttr(DGC_SB8,0,"FILE_SIZE");
    FileLogRqstBind.addAttr(DGC_SB8,0,"PROCESSED_BYTE");
    FileLogRqstBind.addAttr(DGC_SCHR,130,"ZONE_NAME");
    FileLogRqstBind.addAttr(DGC_UB4,0,"ENC_START_DATE");
    FileLogRqstBind.addAttr(DGC_UB4,0,"ENC_END_DATE");
    FileLogRqstBind.addAttr(DGC_SCHR,256,"ERR_MSG");
    FileLogRqstBind.add();

	UserFileLogRqstBind.addAttr(DGC_SB8,0,"PTU_ID");
	UserFileLogRqstBind.addAttr(DGC_SCHR,128,"CLIENT_IP");
	UserFileLogRqstBind.addAttr(DGC_SCHR,65,"SYSTEM_NAME");
	UserFileLogRqstBind.addAttr(DGC_SCHR,128,"SYSTEM_IP");
	UserFileLogRqstBind.addAttr(DGC_SCHR,256,"FILE_NAME");
	UserFileLogRqstBind.addAttr(DGC_SCHR,32,"ENC_TYPE");
	UserFileLogRqstBind.addAttr(DGC_UB1,0,"MODE");
	UserFileLogRqstBind.addAttr(DGC_SCHR,130,"KEY_NAME");
	UserFileLogRqstBind.addAttr(DGC_SB8,0,"FILE_SIZE");
	UserFileLogRqstBind.addAttr(DGC_SB8,0,"PROCESSED_BYTE");
	UserFileLogRqstBind.addAttr(DGC_SCHR,130,"ZONE_NAME");
	UserFileLogRqstBind.addAttr(DGC_UB4,0,"ENC_START_DATE");
	UserFileLogRqstBind.addAttr(DGC_UB4,0,"ENC_END_DATE");
	UserFileLogRqstBind.addAttr(DGC_SCHR,256,"ERR_MSG");
	UserFileLogRqstBind.add();

	GetVKeyDbPrivBind.addAttr(DGC_SB8, 0, "user_sid");
	GetVKeyDbPrivBind.addAttr(DGC_SB8, 0, "virtual_key_id");
	GetVKeyDbPrivBind.addAttr(DGC_UB1, 0, "crypt_type");
	GetVKeyDbPrivBind.addAttr(DGC_UB1, 0, "target_type");
	GetVKeyDbPrivBind.addAttr(DGC_SCHR, 33, "name1");
	GetVKeyDbPrivBind.addAttr(DGC_SCHR, 33, "name2");
	GetVKeyDbPrivBind.addAttr(DGC_SCHR, 33, "name3");
	GetVKeyDbPrivBind.addAttr(DGC_SCHR, 33, "name4");
	GetVKeyDbPrivBind.addAttr(DGC_SCHR, 33, "name5");
	GetVKeyDbPrivBind.add();

	GetVKeyFilePrivBind.addAttr(DGC_SB8, 0, "user_sid");
	GetVKeyFilePrivBind.addAttr(DGC_SB8, 0, "virtual_key_id");
	GetVKeyFilePrivBind.addAttr(DGC_UB1, 0, "crypt_type");
	GetVKeyFilePrivBind.addAttr(DGC_UB1, 0, "target_type");
	GetVKeyFilePrivBind.addAttr(DGC_SCHR, 65, "name1");
	GetVKeyFilePrivBind.addAttr(DGC_SCHR, 65, "name2");
	GetVKeyFilePrivBind.addAttr(DGC_SCHR, 513, "name3");
	GetVKeyFilePrivBind.addAttr(DGC_SCHR, 129, "name4");
	GetVKeyFilePrivBind.add();

	//GetZoneParamBind.addAttr(DGC_SCHR,129,"zone_name");
	GetZoneParamBind.addAttr(DGC_SB8, 0, "zone_id");
	GetZoneParamBind.add();
	GetRegEngineBind.addAttr(DGC_SB8,0,"reg_engine_id");
	GetRegEngineBind.add();
	GetCryptParamBind.addAttr(DGC_SCHR,33,"crypt_param_name");
	GetCryptParamBind.add();

	DetectFileLogDataBind.addAttr(DGC_SB8,0,"JOB_ID");
	DetectFileLogDataBind.addAttr(DGC_SB8,0,"DIR_ID");
	DetectFileLogDataBind.addAttr(DGC_SB8,0,"FILE_ID");
	DetectFileLogDataBind.addAttr(DGC_SCHR,2048,"FILE_NAME");
	DetectFileLogDataBind.addAttr(DGC_SB8,0,"START_OFFSET");
	DetectFileLogDataBind.addAttr(DGC_SB8,0,"END_OFFSET");
	DetectFileLogDataBind.addAttr(DGC_SCHR,1024,"EXPR");
	DetectFileLogDataBind.addAttr(DGC_SCHR,1024,"DATA");
	DetectFileLogDataBind.add();

	DetectFileLogRqstBind.addAttr(DGC_SB8,0,"JOB_ID");
	DetectFileLogRqstBind.addAttr(DGC_SB8,0,"DIR_ID");
	DetectFileLogRqstBind.addAttr(DGC_SB8,0,"FILE_ID");
	DetectFileLogRqstBind.addAttr(DGC_SCHR,65,"SYSTEM_NAME");
	DetectFileLogRqstBind.addAttr(DGC_SCHR,128,"SYSTEM_IP");
	DetectFileLogRqstBind.addAttr(DGC_SCHR,2048,"FILE_NAME");
	DetectFileLogRqstBind.addAttr(DGC_SB8,0,"FILE_SIZE");
	DetectFileLogRqstBind.addAttr(DGC_UB4,0,"FILE_MTIME");
	DetectFileLogRqstBind.addAttr(DGC_UB4,0,"START_DATE");
	DetectFileLogRqstBind.addAttr(DGC_UB4,0,"END_DATE");
	DetectFileLogRqstBind.addAttr(DGC_SB8,0,"PTTN_NUM");
	DetectFileLogRqstBind.addAttr(DGC_SB4,0,"IS_SKIPPED");
	DetectFileLogRqstBind.addAttr(DGC_SCHR,1024,"PARAMETERS");
	DetectFileLogRqstBind.addAttr(DGC_SCHR,256,"ERR_MSG");
	DetectFileLogRqstBind.add();

	GetRsaKeyBind.addAttr(DGC_SCHR,128,"key_name");
        GetRsaKeyBind.add();
}


PcaKeySvrSessionSoha::~PcaKeySvrSessionSoha()
{
	cleanCurrConnection();
}


dgt_sint32 PcaKeySvrSessionSoha::initialize(const dgt_schar* credentials_password)
{
	if (credentials_password) strncpy(CredentialsPassword, credentials_password, 32);
#if 0
	return connectKeySvr();
#else
	return 0;
#endif
}


dgt_sint32 PcaKeySvrSessionSoha::openSession(
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
	pc_type_open_sess_out*	sess_out)
{
	//
	// build bind data
	//
	pc_type_open_sess_in	sess_in;
	memset(&sess_in, 0, sizeof(sess_in));
	sess_in.db_sid=db_sid;
	if (instance_name) strncpy(sess_in.instance_name,instance_name,32);
	if (db_name) strncpy(sess_in.db_name,db_name,32);
	if (ip) strncpy(sess_in.client_ip,ip,64);
	if (db_user) strncpy(sess_in.db_user,db_user,32);
	if (os_user) strncpy(sess_in.os_user,os_user,32);
	if (program) strncpy(sess_in.client_program,program,127);
	sess_in.protocol=protocol;
	if (user_id) strncpy(sess_in.user_id,user_id,32);
	if (mac) strncpy(sess_in.client_mac,mac,64);
	OpenSessBind.rewind();
	OpenSessBind.next();
	memcpy(OpenSessBind.data(), &sess_in, sizeof(pc_type_open_sess_in));
	dgt_sint32	ntry=0;
CONNECT_AGAIN1:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute stmt
	//
	OpenSessBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=OpenSessStmt->execute(1, &OpenSessBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 2connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN1;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=OpenSessStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 3connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN1;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	DgcMemRows*	rtn_rows=OpenSessStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		memcpy(sess_out, rtn_rows->data(), sizeof(pc_type_open_sess_out));
	} else {
		sprintf(ErrMsg,"key server not return session user ID");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::getPriv(
	dgt_sint64		user_sid,
	dgt_sint64 		enc_col_id,
	pc_type_get_priv_out*	priv_out)
{
	//
	// marshall getKey message
	//
	pc_type_get_priv_in	priv_in = {user_sid, enc_col_id};
	GetPrivBind.rewind();
	GetPrivBind.next();
	memcpy(GetPrivBind.data(), &priv_in, sizeof(priv_in));
	dgt_sint32	ntry=0;
CONNECT_AGAIN2:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetPrivBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetPrivStmt->execute(1, &GetPrivBind)) < 0) {
		setError(EXCEPT);
		if (strstr(ErrMsg,"session user")) {
			delete EXCEPTnC;
			return ErrCode = PcaKeySvrSession::PKSS_SESSION_NOT_FOUND;
		}
		delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 4connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN2;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetPrivStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 5connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN2;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetPrivStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		memcpy(priv_out, rtn_rows->data(), sizeof(pc_type_get_priv_out));
	} else {
		sprintf(ErrMsg,"key server not return priv info");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::getVKeyPriv(
	dgt_sint64		user_sid,
	dgt_sint64		virtual_key_id,
	dgt_uint8		crypt_type,
	pc_type_get_vkey_priv_out*	priv_out,
	dgt_uint8		target_type,
	dgt_schar*	name1,
	dgt_schar*	name2,
	dgt_schar*	name3,
	dgt_schar*	name4,
	dgt_schar*	name5,
	dgt_schar*	name6,
	dgt_schar*	name7,
	dgt_schar*	name8,
	dgt_schar*	name9,
	dgt_schar*	name10)
{
	if (target_type == PCI_VKEY_TARGET_TYPE_DB) {
		return getVKeyDbPriv(user_sid,virtual_key_id,crypt_type,name1,name2,name3,name4,name5,priv_out);
	} else if (target_type == PCI_VKEY_TARGET_TYPE_FILE) {
		return getVKeyFilePriv(user_sid,virtual_key_id,crypt_type,name1,name2,name3,name4,priv_out);
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getVKeyDbPriv(
	dgt_sint64		user_sid,
	dgt_sint64		virtual_key_id,
	dgt_uint8		crypt_type,
	dgt_schar*		db_name,
	dgt_schar*		schema_name,
	dgt_schar*		db_user_name,
	dgt_schar*		table_name,
	dgt_schar*		column_name,
	pc_type_get_vkey_priv_out*   priv_out)
{
	// build bind data
	pc_type_get_vkey_db_priv_in priv_in;
	priv_in.user_sid = user_sid;
	priv_in.virtual_key_id = virtual_key_id;
	priv_in.crypt_type = crypt_type;
	priv_in.target_type = PCI_VKEY_TARGET_TYPE_DB;

	if (db_name) strncpy(priv_in.name1,db_name,dg_strlen(db_name)>32?32:dg_strlen(db_name));
	if (schema_name) strncpy(priv_in.name2,schema_name,dg_strlen(schema_name)>32?32:dg_strlen(schema_name));
	if (db_user_name) strncpy(priv_in.name3,db_user_name,dg_strlen(db_user_name)>32?32:dg_strlen(db_user_name));
	if (table_name) strncpy(priv_in.name4,table_name,dg_strlen(table_name)>32?32:dg_strlen(table_name));
	if (column_name) strncpy(priv_in.name5,column_name,dg_strlen(column_name)>32?32:dg_strlen(column_name));

	GetVKeyDbPrivBind.rewind();
	GetVKeyDbPrivBind.next();
	memcpy(GetVKeyDbPrivBind.data(), &priv_in, sizeof(priv_in));
	dgt_sint32	ntry=0;
CONNECT_AGAIN11:
	//
	// check connection status
	//
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetVKeyDbPrivBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetVKeyDbPrivStmt->execute(1, &GetVKeyDbPrivBind)) < 0) {
		setError(EXCEPT);
		if (strstr(ErrMsg,"session user")) {
			delete EXCEPTnC;
			return ErrCode = PcaKeySvrSession::PKSS_SESSION_NOT_FOUND;
		} else if (strstr(ErrMsg,"getEncColumn failed")) {
			delete EXCEPTnC;
			return ErrCode = PcaKeySvrSession::PKSS_COLUMN_NOT_FOUND;
		}

		delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 4.1connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN11;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetVKeyDbPrivStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 5.1connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN11;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetVKeyDbPrivStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		memcpy(priv_out, rtn_rows->data(), sizeof(pc_type_get_vkey_priv_out));
	} else {
		sprintf(ErrMsg,"key server not return priv info");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getVKeyFilePriv(
	dgt_sint64		user_sid,
	dgt_sint64		virtual_key_id,
	dgt_uint8		crypt_type,
	dgt_schar*		host_name,
	dgt_schar*		os_user_name,
	dgt_schar*		file_path,
	dgt_schar*		file_name,
	pc_type_get_vkey_priv_out*   priv_out)
{
	// build bind data
	pc_type_get_vkey_file_priv_in priv_in;
	priv_in.user_sid = user_sid;
	priv_in.virtual_key_id = virtual_key_id;
	priv_in.crypt_type = crypt_type;
	priv_in.target_type = PCI_VKEY_TARGET_TYPE_FILE;
	if (host_name) strncpy(priv_in.name1,host_name,64);
	if (os_user_name) strncpy(priv_in.name2,os_user_name,64);
	if (file_path) strncpy(priv_in.name3,file_path,512);
	if (file_name) strncpy(priv_in.name4,file_name,128);

	GetVKeyFilePrivBind.rewind();
	GetVKeyFilePrivBind.next();
	memcpy(GetVKeyFilePrivBind.data(), &priv_in, sizeof(priv_in));
	dgt_sint32	ntry=0;
CONNECT_AGAIN12:
	//
	// check connection status
	//
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetVKeyFilePrivBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetVKeyFilePrivStmt->execute(1, &GetVKeyFilePrivBind)) < 0) {
		setError(EXCEPT);
		if (strstr(ErrMsg,"session user")) {
			delete EXCEPTnC;
			return ErrCode = PcaKeySvrSession::PKSS_SESSION_NOT_FOUND;
		} else if (strstr(ErrMsg,"getEncColumn failed")) {
			delete EXCEPTnC;
			return ErrCode = PcaKeySvrSession::PKSS_COLUMN_NOT_FOUND;
		}
		delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 4.2connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN12;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetVKeyFilePrivStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 5.2connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN12;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetVKeyFilePrivStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		memcpy(priv_out, rtn_rows->data(), sizeof(pc_type_get_vkey_priv_out));
	} else {
		sprintf(ErrMsg,"key server not return priv info");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getKey(
	dgt_sint64		key_id,
	pc_type_get_key_out*	key_out)
{
	//
	// marshall getKey message
	//
	GetKeyBind.rewind();
	GetKeyBind.next();
	memcpy(GetKeyBind.data(), &key_id, sizeof(key_id));
	dgt_sint32	ntry=0;
CONNECT_AGAIN8:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetKeyBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetKeyStmt->execute(1, &GetKeyBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 6connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetKeyStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 7connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetKeyStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		memcpy(key_out, rtn_rows->data(), sizeof(pc_type_get_key_out));
	} else {
		sprintf(ErrMsg,"key server not return key info");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::alert(pc_type_alert_in* alert_request)
{
	//
	// marshall alert message
	//
	AlertBind.rewind();
	AlertBind.next();
	pc_type_alert_in* alt_in=(pc_type_alert_in*)AlertBind.data();
        alt_in->user_sid = alert_request->user_sid;
        alt_in->enc_col_id = alert_request->enc_col_id;
        alt_in->dec_count = alert_request->dec_count;
        alt_in->stmt_id = alert_request->stmt_id;
        alt_in->level_id = alert_request->level_id;
        alt_in->start_date = alert_request->start_date;
        alt_in->sql_type = alert_request->sql_type;
        alt_in->dec_no_priv_flag = alert_request->dec_no_priv_flag;
        alt_in->op_type = alert_request->op_type;
        memcpy(alt_in->sql_hash,alert_request->sql_hash,65);
	dgt_sint32	ntry=0;
CONNECT_AGAIN3:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute
	//
	dgt_sint32	frows=0;
	AlertBind.rewind();
	if ((frows=AlertStmt->execute(1, &AlertBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 8connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN3;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::approve(
	dgt_sint64		user_sid,
	dgt_sint64 		enc_col_id,
	dgt_sint64 		approve_id,
	dgt_sint32*		result)
{
	//
	// marshall approve message
	//
	ApproveBind.rewind();
	ApproveBind.next();
	pc_type_approve_in* apv_in=(pc_type_approve_in*)ApproveBind.data();
	apv_in->user_sid = user_sid;
	apv_in->enc_col_id = enc_col_id;
	apv_in->approve_id = approve_id;
	dgt_sint32	ntry=0;
CONNECT_AGAIN4:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	dgt_sint32	frows=0;
	ApproveBind.rewind();
	if ((frows=ApproveStmt->execute(1, &ApproveBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 9connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN4;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=ApproveStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 10connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN4;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// set return
	//
	DgcMemRows*	rtn_rows = ApproveStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		*result = *(dgt_sint32*)rtn_rows->data();
	} else {
		sprintf(ErrMsg,"key server not return approve result");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::encrypt(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len)
{
	return crypt(PCI_MSG_ENCRYPT, enc_col_id, src, src_len, dst, dst_len);
}


dgt_sint32 PcaKeySvrSessionSoha::decrypt(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len)
{
	return crypt(PCI_MSG_DECRYPT, enc_col_id, src, src_len, dst, dst_len);
}


dgt_sint32 PcaKeySvrSessionSoha::encryptCpn(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	src,
	dgt_sint32	src_len,
	dgt_uint8*	coupon,
	dgt_uint32*	coupon_len)
{
	return crypt(PCI_MSG_ENCRYPT_COUPON, enc_col_id, src, src_len, coupon, coupon_len);
}


dgt_sint32 PcaKeySvrSessionSoha::decryptCpn(
	dgt_sint64 	enc_col_id,
	dgt_uint8*	coupon,
	dgt_sint32	coupon_len,
	dgt_uint8*	dst,
	dgt_uint32*	dst_len)
{
	return crypt(PCI_MSG_DECRYPT_COUPON, enc_col_id, coupon,coupon_len, dst, dst_len);
}


dgt_sint32 PcaKeySvrSessionSoha::getEncColID(const dgt_schar* name,dgt_sint64* enc_col_id)
{
	GetEciBind.rewind();
	GetEciBind.next();
	strncpy((dgt_schar*)GetEciBind.data(), name, 131);
	dgt_sint32	ntry=0;
CONNECT_AGAIN5:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetEciBind.rewind();
	if (GetEciStmt->execute(1, &GetEciBind) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN5;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetEciStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		if ((*enc_col_id=*(dgt_sint64*)rtn_rows->data()) < 0) {
#if 0
                        sprintf(ErrMsg,"get_eci return error[%lld]",*enc_col_id);
#else
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        logging("get_eci return error[%lld]",*enc_col_id);
                        logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                        if (ntry++ == 0) goto CONNECT_AGAIN5;
                        return ErrCode = PKSS_CONNECT_ERROR;
#endif

		}
	} else {
		sprintf(ErrMsg,"key server not return get_eci result");
		return ErrCode=PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getZoneID(const dgt_schar* name,dgt_sint64* zone_id)
{
	GetZoneIdBind.rewind();
	GetZoneIdBind.next();
	strncpy((dgt_schar*)GetZoneIdBind.data(), name, 131);
	dgt_sint32	ntry=0;
CONNECT_AGAIN5:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetZoneIdBind.rewind();
	if (GetZoneIdStmt->execute(1, &GetZoneIdBind) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN5;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetZoneIdStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		if ((*zone_id=*(dgt_sint64*)rtn_rows->data()) < 0) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        logging("get_zone_id return error[%lld]",*zone_id);
                        logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                        if (ntry++ == 0) goto CONNECT_AGAIN5;
                        return ErrCode = PKSS_CONNECT_ERROR;
		}
	} else {
		sprintf(ErrMsg,"key server not return get zone_id result");
		return ErrCode=PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getRegEngineID(const dgt_schar* name,dgt_sint64* reg_engine_id)
{
	GetRegEngineIdBind.rewind();
	GetRegEngineIdBind.next();
	strncpy((dgt_schar*)GetRegEngineIdBind.data(), name, 131);
	dgt_sint32	ntry=0;
CONNECT_AGAIN5:
	//
	// check connection status
	// 
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;

	//
	// execute & fetch
	//
	GetRegEngineIdBind.rewind();
	if (GetRegEngineIdStmt->execute(1, &GetRegEngineIdBind) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN5;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetRegEngineIdStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		if ((*reg_engine_id=*(dgt_sint64*)rtn_rows->data()) < 0) {
                        setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                        logging("get_zone_id return error[%lld]",*reg_engine_id);
                        logging("%s, 11connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                        if (ntry++ == 0) goto CONNECT_AGAIN5;
                        return ErrCode = PKSS_CONNECT_ERROR;
		}
	} else {
		sprintf(ErrMsg,"key server not return get zone_id result");
		return ErrCode=PKSS_READ_ERROR;
	}
	return 0;
}
dgt_sint32 PcaKeySvrSessionSoha::logRequest(pc_type_log_request_in* log_request)
{
	//
	// soha connection logging mode
	//
	LogRqstBind.rewind();
	LogRqstBind.next();
	memcpy(LogRqstBind.data(), log_request, sizeof(pc_type_log_request_in));
	dgt_sint32      ntry=0;
CONNECT_AGAIN6:
	//
	// check connection status
	//
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;
	//
	// execute & fetch
	//
	LogRqstBind.rewind();
	if (LogRqstStmt->execute(1, &LogRqstBind) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 12connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN6;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::encCount(dgt_sint64 enc_col_id, dgt_sint64 enc_count)
{
        //
        // marshall enc_count message
        //
        EncCountBind.rewind();
        EncCountBind.next();
        pc_type_enc_count_in* enc_count_in=(pc_type_enc_count_in*)EncCountBind.data();
        enc_count_in->enc_col_id = enc_col_id;
        enc_count_in->enc_count = enc_count;
        dgt_sint32      ntry=0;
CONNECT_AGAIN3:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute
        //
        dgt_sint32      frows=0;
        EncCountBind.rewind();
        if ((frows=EncCountStmt->execute(1, &EncCountBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 8connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN3;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::posting(dgt_sint64 user_sid, dgt_sint64 enc_col_id, dgt_sint32 err_code)
{
        //
        // marshall posting message
        //
        PostBind.rewind();
        PostBind.next();
        pc_type_posting_in* post_in=(pc_type_posting_in*)PostBind.data();
        post_in->user_sid = user_sid;
        post_in->enc_col_id = enc_col_id;
        post_in->err_code = err_code;
        dgt_sint32      ntry=0;
CONNECT_AGAIN3:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute
        //
        dgt_sint32      frows=0;
        PostBind.rewind();
        if ((frows=PostStmt->execute(1, &PostBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 8connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN3;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getIV(
        dgt_uint8               iv_no,
        dgt_uint16              iv_size,
        pc_type_get_iv_out*     iv_out)
{
        //
        // marshall getIV message
        //
        GetIVBind.rewind();
        GetIVBind.next();
        pc_type_get_iv_in* iv_in = (pc_type_get_iv_in*)GetIVBind.data();
	iv_in->iv_type=iv_no;
	iv_in->iv_size=iv_size;
        dgt_sint32      ntry=0;
CONNECT_AGAIN8:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute & fetch
        //
        GetIVBind.rewind();
        dgt_sint32      frows=0;
        if ((frows=GetIVStmt->execute(1, &GetIVBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 6connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        if ((frows=GetIVStmt->fetch()) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 7connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        //
        // set return
        //
        DgcMemRows*     rtn_rows = GetIVStmt->returnRows();
        if (rtn_rows && rtn_rows->next()) {
                memcpy(iv_out, rtn_rows->data(), sizeof(pc_type_get_iv_out));
        } else {
                sprintf(ErrMsg,"key server not return iv info");
                return ErrCode = PKSS_READ_ERROR;
        }
        return 0;
}


dgt_sint32 PcaKeySvrSessionSoha::putExtKey
        (const dgt_schar* key_name,
         const dgt_schar* key,
         dgt_uint16 foramt_no)
{
        //
        // marshall putExtKey message
        //
        PutExtKeyBind.rewind();
        PutExtKeyBind.next();
        pc_type_put_ext_key_in* key_in = (pc_type_put_ext_key_in*)PutExtKeyBind.data();
        memcpy(key_in->key_name,key_name,33);
        memcpy(key_in->key,key,513);
        key_in->format_no=foramt_no;

        dgt_sint32      ntry=0;
CONNECT_AGAIN9:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;
        //
        // execute
        //
        dgt_sint32      frows=0;
        PutExtKeyBind.rewind();
        if ((frows=PutExtKeyStmt->execute(1, &PutExtKeyBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 10connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN9;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getTrailer(dgt_sint64 key_id, pc_type_get_trailer_out* trailer_out)
{
        //
        // marshall getTrailer message
        //
        GetTrailerBind.rewind();
        GetTrailerBind.next();
        pc_type_get_trailer_in* trailer_in = (pc_type_get_trailer_in*)GetTrailerBind.data();
        trailer_in->key_id=key_id;

        dgt_sint32      ntry=0;
CONNECT_AGAIN10:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute & fetch
        //
        GetTrailerBind.rewind();
        dgt_sint32      frows=0;
        if ((frows=GetTrailerStmt->execute(1, &GetTrailerBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 9connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN10;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        if ((frows=GetTrailerStmt->fetch()) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 7connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN10;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        //
        // set return
        //
        DgcMemRows*     rtn_rows = GetTrailerStmt->returnRows();
        if (rtn_rows && rtn_rows->next()) {
                memcpy(trailer_out, rtn_rows->data(), sizeof(pc_type_get_trailer_out));
        } else {
                sprintf(ErrMsg,"key server not return iv info");
                return ErrCode = PKSS_READ_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::logFileRequest(pc_type_file_request_in* log_request)
{
        //
        // soha connection logging mode
        //
        FileLogRqstBind.rewind();
        FileLogRqstBind.next();
        memcpy(FileLogRqstBind.data(), log_request, sizeof(pc_type_file_request_in));
        dgt_sint32      ntry=0;
CONNECT_AGAIN6:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;
        //
        // execute & fetch
        //
        FileLogRqstBind.rewind();
        if (FileLogRqstStmt->execute(1, &FileLogRqstBind) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN6;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::logUserFileRequest(pc_type_user_file_request_in* log_request)
{
        //
        // soha connection logging mode
        //
        UserFileLogRqstBind.rewind();
        UserFileLogRqstBind.next();
        memcpy(UserFileLogRqstBind.data(), log_request, sizeof(pc_type_user_file_request_in));
        dgt_sint32      ntry=0;
CONNECT_AGAIN6:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;
        //
        // execute & fetch
        //
        UserFileLogRqstBind.rewind();
        if (UserFileLogRqstStmt->execute(1, &UserFileLogRqstBind) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN6;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getZoneParam(dgt_sint64 zone_id,dgt_schar* param)
{
	//
	// marshall get zone param message
	//
	GetZoneParamBind.rewind();
	GetZoneParamBind.next();
	memcpy(GetZoneParamBind.data(), &zone_id, sizeof(zone_id));
	dgt_sint32	ntry=0;
CONNECT_AGAIN8:
	//
	// check connection status
	//
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;
	//
	// execute & fetch
	//
	GetZoneParamBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetZoneParamStmt->execute(1, &GetZoneParamBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 9connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetZoneParamStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 7connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetZoneParamStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		dgt_schar* result_param = (dgt_schar*)rtn_rows->data();
		dgt_uint32 result_len = dg_strlen(result_param);
		strncpy(param,result_param,result_len>2048?2048:result_len);
	} else {
		sprintf(ErrMsg,"key server not return zone param");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getRegEngine(dgt_sint64 reg_engine_id,dgt_schar* param)
{
        //
        // marshall get reg_engine param message
        //
        GetRegEngineBind.rewind();
        GetRegEngineBind.next();
		memcpy(GetRegEngineBind.data(), &reg_engine_id, sizeof(reg_engine_id));

        dgt_sint32      ntry=0;
CONNECT_AGAIN8:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute & fetch
        //
        GetRegEngineBind.rewind();
        dgt_sint32      frows=0;
        if ((frows=GetRegEngineStmt->execute(1, &GetRegEngineBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 9connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        if ((frows=GetRegEngineStmt->fetch()) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 7connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        //
        // set return
        //
        DgcMemRows*     rtn_rows = GetRegEngineStmt->returnRows();
        if (rtn_rows && rtn_rows->next()) {
                dgt_schar* result_param = (dgt_schar*)rtn_rows->data();
#ifndef WIN32
                dgt_uint32 result_len = dg_strlen(result_param);
#else
                dgt_uint32 result_len = strlen(result_param);
#endif
				if(result_len > 2048) {
					sprintf(ErrMsg,"big parameter than 2048byte [parameter size : %d]",result_len);
					return ErrCode = PKSS_BUF_OVERFLOW;
				}
                strncpy(param,result_param,result_len>2048?2048:result_len);
        } else {
                sprintf(ErrMsg,"key server not return regEngine param");
                return ErrCode = PKSS_READ_ERROR;
        }
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getCryptParam(dgt_schar* crypt_param_name,dgt_schar* param)
{
	//
	// mashall get zone param message
	//
	GetCryptParamBind.rewind();
	GetCryptParamBind.next();
#ifndef WIN32
	dgt_uint32 crypt_param_name_len = dg_strlen(crypt_param_name);
	dg_strncpy((dgt_schar*)GetCryptParamBind.data(),crypt_param_name,crypt_param_name_len>33?33:crypt_param_name_len);
#else
	dgt_uint32 crypt_param_name_len = strlen(crypt_param_name);
	strncpy((dgt_schar*)GetCryptParamBind.data(),crypt_param_name,crypt_param_name_len>33?33:crypt_param_name_len);
#endif

	dgt_sint32	ntry=0;
CONNECT_AGAIN8:
	//
	// check connection status
	//
	if (CurrConn == 0 && connectKeySvr()) return ErrCode;
	
	//
	// execute & fetch
	//
	GetCryptParamBind.rewind();
	dgt_sint32	frows=0;
	if ((frows=GetCryptParamStmt->execute(1, &GetCryptParamBind)) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 20connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	if ((frows=GetCryptParamStmt->fetch()) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, 21connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN8;
		return ErrCode = PKSS_CONNECT_ERROR;
	}
	//
	// set return
	//
	DgcMemRows*	rtn_rows = GetCryptParamStmt->returnRows();
	if (rtn_rows && rtn_rows->next()) {
		dgt_schar* result_param = (dgt_schar*)rtn_rows->data();
#ifndef WIN32
		dgt_uint32 result_len = dg_strlen(result_param);
#else
		dgt_uint32 result_len = strlen(result_param);
#endif
		strncpy(param,result_param,result_len>2048?2048:result_len);
	} else {
		sprintf(ErrMsg,"key server not return crypt param");
		return ErrCode = PKSS_READ_ERROR;
	}
	return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::logDetectFileRequest(pc_type_detect_file_request_in* log_request, DgcMemRows* log_data)
{
        dgt_sint32      ntry=0;
CONNECT_AGAIN14:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;
        //
        // execute & fetch
        //
        DetectFileLogRqstBind.rewind();
        DetectFileLogRqstBind.next();
        memcpy(DetectFileLogRqstBind.data(), log_request, sizeof(pc_type_detect_file_request_in));
        if (DetectFileLogRqstStmt->execute(1, &DetectFileLogRqstBind) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN14;
                return ErrCode = PKSS_CONNECT_ERROR;
        }

	DetectFileLogDataBind.rewind();
	DetectFileLogDataBind.next();
	log_data->rewind();
	pc_type_detect_file_data_in* row = 0;
	while (log_data->next()) {
		memset(DetectFileLogDataBind.data(), 0, DetectFileLogDataBind.rowSize());
		memcpy(DetectFileLogDataBind.getColPtr(1), &log_request->job_id, sizeof(dgt_sint64));
		memcpy(DetectFileLogDataBind.getColPtr(2), &log_request->dir_id, sizeof(dgt_sint64));
		memcpy(DetectFileLogDataBind.getColPtr(3), &log_request->file_id, sizeof(dgt_sint64));
		memcpy(DetectFileLogDataBind.getColPtr(4), &log_request->file_name, strlen(log_request->file_name));
		memcpy(DetectFileLogDataBind.getColPtr(5), log_data->data(), log_data->rowSize());

		if (DetectFileLogDataStmt->execute(1, &DetectFileLogDataBind) < 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
			if (ntry++ == 0) goto CONNECT_AGAIN14;
			return ErrCode = PKSS_CONNECT_ERROR;
		}
	}
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getDetectFileRequest(DgcMemRows* get_request)
{
        dgt_sint32      ntry=0;
CONNECT_AGAIN15:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;
        //
        // execute & fetch
        //
	if (DetectFileGetRqstStmt->execute(1, get_request) < 0) {
		setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
		logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
		if (ntry++ == 0) goto CONNECT_AGAIN15;
		return ErrCode = PKSS_CONNECT_ERROR;
	}

	dgt_sint32	frows = 0;
	while((frows=DetectFileGetRqstStmt->fetch())) {
		if (frows < 0) {
			setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
			logging("%s, file request connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
			if (ntry++ == 0) goto CONNECT_AGAIN15;
			return ErrCode = PKSS_CONNECT_ERROR;
		}
	}

	DgcMemRows*	rtn_rows = DetectFileGetRqstStmt->returnRows();
	get_request->reset();
	while (rtn_rows && rtn_rows->next()) {
		get_request->add();
		get_request->next();
		memcpy(get_request->data(), rtn_rows->data(), get_request->rowSize());
	}
	get_request->rewind();
        return 0;
}

dgt_sint32 PcaKeySvrSessionSoha::getRsaKey(dgt_schar* key_name,dgt_schar* key_string)
{
        //
        // marshall get rsa key message
        //
        GetRsaKeyBind.rewind();
        GetRsaKeyBind.next();
#ifndef WIN32
        dgt_uint32 key_name_len = dg_strlen(key_name);
        dg_strncpy((dgt_schar*)GetRsaKeyBind.data(),key_name,key_name_len>33?33:key_name_len);
#else
        dgt_uint32 key_name_len = strlen(key_name);
        strncpy((dgt_schar*)GetRsaKeyBind.data(),key_name,key_name_len>33?33:key_name_len);
#endif

        dgt_sint32      ntry=0;
CONNECT_AGAIN8:
        //
        // check connection status
        //
        if (CurrConn == 0 && connectKeySvr()) return ErrCode;

        //
        // execute & fetch
        //
        GetRsaKeyBind.rewind();
        dgt_sint32      frows=0;
        if ((frows=GetRsaKeyStmt->execute(1, &GetRsaKeyBind)) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 22connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        if ((frows=GetRsaKeyStmt->fetch()) < 0) {
                setError(EXCEPT); delete EXCEPTnC; cleanCurrConnection();
                logging("%s, 23connection[%s:%u] closed.", ErrMsg, Current->host, Current->port);
                if (ntry++ == 0) goto CONNECT_AGAIN8;
                return ErrCode = PKSS_CONNECT_ERROR;
        }
        //
        // set return
        //
        DgcMemRows*     rtn_rows = GetRsaKeyStmt->returnRows();
        if (rtn_rows && rtn_rows->next()) {
                dgt_schar* result = (dgt_schar*)rtn_rows->data();
#ifndef WIN32
                dgt_uint32 result_len = dg_strlen(result);
#else
                dgt_uint32 result_len = strlen(result);
#endif
                strncpy(key_string,result,result_len>2048?2048:result_len);
        } else {
                sprintf(ErrMsg,"key server not return crypt param");
                return ErrCode = PKSS_READ_ERROR;
        }
        return 0;
}

