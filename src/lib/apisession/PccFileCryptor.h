/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccFileCryptor
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_FILE_CRYPTOR_H
#define PCC_FILE_CRYPTOR_H

#include "PccCryptDivision.h"

class PccFileCryptor : public DgcObject {
  private :
	static const dgt_sint32 MAX_PARAMS = 32;
	
	PccKeyMap		KeyMap;
	PccSearchEngineFactory	SearchEngineFactory;
	PccCryptorFactory	CryptorFactory;
	PccHeaderManager	HeaderManager;
	DgcBgmrList*		ParamList;
	dgt_sint32		NumParams;
	const dgt_schar*	InFileName;
	const dgt_schar*	OutFileName;
	const dgt_schar*	LogFileName;
	dgt_uint8		ForceTargetWrite;
	dgt_sint64		OutBufLen;
	dgt_sint64		InFileSize;
	dgt_sint64		OutFileSize;
	dgt_sint32		ManagerID;

	//added by shson 2017.07.02 - for logging
	dgt_sint32		LastErrCode;
	dgt_schar*		ErrString;
	dgt_sint32		BypassCheck;
	dgt_sint32		UserLogging;
	dgt_sint64   		PtuId;
	dgt_uint8		ValidationFlag;
	dgt_schar   	SystemName[65];
	dgt_schar   	SystemIp[128];
	dgt_schar   	ZoneName[130];
	dgt_schar   	ClientIp[128];

	//added by mjkim 2019.05.28 - for detect logging
	dgt_sint64		JobId;
	dgt_sint64		DirId;
	dgt_sint64		NumPttns;
	dgt_sint32		IsSkip;
	const dgt_schar*	Parameter;
	DgcMemRows*		DetectData;

	dgt_void openLogStream();
	dgt_sint32 getFileParams(DgcBgrammer* bg);
	dgt_sint32 getKeyParams(DgcBgrammer* bg);
	dgt_sint32 getDelimiterParams(DgcBgrammer* bg);
	dgt_sint32 getFixedParams(DgcBgrammer* bg);
	dgt_sint32 getRegularParams(DgcBgrammer* bg);
	dgt_sint32 getCryptParams(DgcBgrammer* bg);
	dgt_sint32 getSessionParams(DgcBgrammer* bg);
	dgt_sint32 getModeParams(DgcBgrammer* bg);
	dgt_sint32 importKeyInfo(DgcBgrammer* bg);
	dgt_sint32 getSystemInfo(DgcBgrammer* bg);
	dgt_sint32 getLoggingInfo(DgcBgrammer* bg);
	dgt_sint32 getParams(DgcBgrammer* bg);
	dgt_void cryptLogging(dgt_uint32 start_time, dgt_uint32 end_time);
	dgt_void userCryptLogging(dgt_uint32 start_time, dgt_uint32 end_time);
	dgt_void detectLogging(dgt_uint32 start_time, dgt_uint32 end_time);
  protected :
  public :
	PccFileCryptor(const dgt_schar* pgm_name=0,const dgt_schar* crypt_mode=0, dgt_sint32 trace_level=0, dgt_sint32 manager_id=0);
	virtual ~PccFileCryptor();
	inline const dgt_schar* errString() { return ErrString; };
	inline dgt_sint32 errCode() { return LastErrCode; };
	inline dgt_void setCryptMode(const dgt_schar* crypt_mode) { SearchEngineFactory.setCryptMode(crypt_mode); };
	inline dgt_void setMaxDetection(dgt_sint64 max_detection) { SearchEngineFactory.setMaxDetection(max_detection); };
	inline dgt_void setProgramName(const dgt_schar* pgm_name) { CryptorFactory.setProgramName(pgm_name); };
	inline dgt_void setOsUser(const dgt_schar* os_user) { CryptorFactory.setOsUser(os_user); };
	inline dgt_void setSessionID(dgt_sint32 sid) { CryptorFactory.setSessionID(sid); };
	inline dgt_sint64 outBufLen() { return OutBufLen; };
	inline dgt_sint64 inFileSize() { return InFileSize; };
	inline dgt_sint64 outFileSize() { return OutFileSize; };
	inline PccHeaderManager* headerManager() { return &HeaderManager; };
	
	//added by shson 2017.07.02 - for logging
	inline dgt_schar* systemName() { return SystemName; };
	inline dgt_schar* systemIp() { return SystemIp; };
	inline dgt_schar* zoneName() { return ZoneName; };

	//added by mjkim 2019.05.28 - for detect logging
	inline dgt_sint64 jobId() { return JobId; };
	inline dgt_sint64 dirId() { return DirId; };
	inline dgt_sint64 numPttns() { return NumPttns; };
	inline dgt_sint32 isSkip() { return IsSkip; };
	inline DgcMemRows* detectData() { return DetectData; };

	dgt_sint32 getDetectList(DgcMemRows* list);
	
	// added by mwpark 2017.08.20 - for bypass in case of double encrypt/decrypt
	inline dgt_void setBypassCheck(dgt_sint32 bypass_check) { BypassCheck=bypass_check; };

	dgt_sint32 compileParam(dgt_schar* param);
	dgt_sint32 compileParamList(const dgt_schar* param_list);
	dgt_sint32 compileParamFile(const dgt_schar* param_file);
	dgt_sint32 crypt(const dgt_schar* in_file=0,const dgt_schar* out_file=0);
	dgt_sint32 crypt(dgt_sint32 sid,const dgt_schar* parameters,const dgt_schar* in_file=0,const dgt_schar* out_file=0,dgt_sint32 agent_mode=0,const dgt_schar* enc_col_name=0,const dgt_schar* header_flag=0, dgt_sint32 buffer_size=0);
	dgt_sint32 detect(const dgt_schar* parameters,const dgt_schar* in_file=0);
	dgt_sint32 detect(dgt_sint32 sid,const dgt_schar* parameters,const dgt_schar* in_file=0,dgt_sint64 max_detection=10,dgt_sint64 job_id=0,dgt_sint64 dir_id=0);
};

#endif
