/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptZone
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 move function dir_rule, isTargetDir, isTargetFile, compileDirPttn, compileFilePttn to PccCryptDir
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptZone.h"
#include "DgcWorker.h"

PccCryptZone::PccCryptZone(dgt_sint64 zone_id)
	: ZoneID(zone_id)
{
	RegularParam = 0;
	DelimiterParam = 0;
	FixedParam = 0;
	ErrString = 0;
	cleanZoneAttrs();
	NSL = 0;
	ELF = 0;
	SystemID = 0;
	memset(ExtIp,0,65);
	ExtPort=0;
        Slimit=0;                 // SizeLimit
        Senable=-1;                // SizeLimit enable flag
        Gsigma=0;                 // GaussianSmoothing
        Genable=-1;                // GaussianSmoothing enable flag
        Cenable=-1;                // Contrast enable flag
        Rangle=0;                 // Rotate angle
        Renable=-1;                // Rotate enable flag
	KeyId = 0;
	DgcSpinLock::unlock(&Lock);
}


PccCryptZone::~PccCryptZone()
{
	if (RegularParam) delete [] RegularParam; RegularParam = 0;
	if (DelimiterParam) delete [] DelimiterParam; DelimiterParam = 0;
	if (FixedParam) delete [] FixedParam; FixedParam = 0;
	if (ErrString) delete [] ErrString; ErrString = 0;

}

dgt_sint32 PccCryptZone::lock() throw(DgcExcept)
{
	if (DgcSpinLock::lock(&Lock) != 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
			new DgcError(SPOS,"zone_id[%lld] lock timeout.",ZoneID)),-1);
	}
	return 0;
}


dgt_void PccCryptZone::unlock() throw(DgcExcept)
{
	DgcSpinLock::unlock(&Lock);
}


dgt_sint32 PccCryptZone::lockExclusive(dgt_uint8 lock_type) throw(DgcExcept)
{
	dgt_uint32 nap_count = 0;
	dgt_uint32 max_nap = LOCK_MAX_NAP;
	for (;;) {
		if (lock() != 0) ATHROWnR(DgcError(SPOS,"lock failed."),-1);
		if (NSL == 0 && ELF == 0) {
			ELF = lock_type;
			break;
		}
		unlock();
		++nap_count;
		if (max_nap > 0 && nap_count >= max_nap) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,	new DgcError(SPOS,"zone_id[%lld] lockExclusive[ELF:%u][NSL:%d] timeout.",ZoneID,ELF,NSL)),-1);
		}
		napAtick();
	}
	unlock();
	return 0;
}


dgt_sint32 PccCryptZone::unlockExclusive() throw(DgcExcept)
{
	if (lock() != 0) {
		DgcExcept* e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"zone_id[%lld] lock failed while unlockExclusive[ELF:%u][NSL:%d]\n",ZoneID,ELF,NSL);
			delete e;
		}
		return 0;
	}
	if (ELF) ELF = 0;
	unlock();
	return 0;
}


dgt_sint32 PccCryptZone::lockShare() throw(DgcExcept)
{
	dgt_uint32 nap_count = 0;
	dgt_uint32 max_nap = LOCK_MAX_NAP;
	for(;;) {
		if (lock() != 0) ATHROWnR(DgcError(SPOS,"lock failed."),-1);
		if (ELF == 0) {
			NSL++;
			break;
		}
		unlock();
		++nap_count;
		if (max_nap > 0 && nap_count >= max_nap) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
				new DgcError(SPOS,"zone_id[%lld] lockShare[ELF:%u][NSL:%d] timeout.",ZoneID,ELF,NSL)),-1);
		}
		napAtick();
	}
	unlock();
	return 0;
}


dgt_sint32 PccCryptZone::unlockShare() throw(DgcExcept)
{
	if (lock() != 0) {
		DgcExcept* e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"zone_id[%lld] lock failed while unlockShare[ELF:%u][NSL:%d]\n",ZoneID,ELF,NSL);
			delete e;
		}
		return 0;
	}
	if (NSL > 0) NSL--;
	unlock();
	return 0;
}



dgt_sint32 PccCryptZone::checkParams(dgt_schar* err_string) throw(DgcExcept)
{
	if (lockShare() < 0) ATHROWnR(DgcError(SPOS,"checkParams: lockShare failed"),-1);
	if (*KeyParam == 0) {
		sprintf(err_string,"key not defined");
		unlockShare();
		return -88002;
	} else if (FileFormat == 2 && *RegularParam == 0) {
		sprintf(err_string,"regular param not defined");
		unlockShare();
		return -88003;
	} else if (FileFormat == 3 && *DelimiterParam == 0) { // delimiter
		sprintf(err_string,"delimiter param not defined");
		unlockShare();
		return -88003;
	} else if (FileFormat == 4 && *FixedParam == 0) { // fixed
		sprintf(err_string,"fixed param not defined");
		unlockShare();
		return -88003;
	}
	unlockShare();
	return 0;
}


dgt_void PccCryptZone::cleanZoneAttrs()
{
	memset(Name,0,33);
	CloseAfter = 0;
	FileFormat = 0;
	memset(EncColName,0,33);

	HeaderFlag = 0;
	memset(OutExtension,0,33);
	memset(KeyParam,0,257);
	memset(SystemInfoParam,0,257);
	if (!RegularParam) RegularParam = new dgt_schar[1025];
	memset(RegularParam,0,1025);
	if (!DelimiterParam) DelimiterParam = new dgt_schar[1025];
	memset(DelimiterParam,0,1025);
	if (!FixedParam) FixedParam = new dgt_schar[1025];
	memset(FixedParam,0,1025);
	if (!ErrString) ErrString = new dgt_schar[1025];
	memset(ErrString,0,1025);

	HeaderFlag = 0;
	EncryptFlag = 0;
	DetectFlag = 0;
	BackupFlag = 0;
	OverWriteFlag = 0;
	memset(ExtIp,0,65);
	ExtPort=0;
}

dgt_sint32 PccCryptZone::setZoneParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_ZONE_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setZoneParams: lockExclusive failed"),-1);
	dgt_sint32	rtn = 0;
	for(;;) {
		dgt_schar*	val;
		if ((val=bg->getValue("zone.name")) == 0 || *val == 0) {
			sprintf(err_string,"name not found"); rtn = -77002; break;
		}
		strncpy(Name,val,32);
		
		if ((val=bg->getValue("zone.crypt_mode.detect"))) {
			DetectFlag = 1;
			EncryptFlag = (dgt_sint32)strtol(val,0,10); // type
		} else if ((val=bg->getValue("zone.crypt_mode")) == 0 || *val == 0) {
			sprintf(err_string,"mode not found"); rtn = -77003; break;
		} else {
			if (strncasecmp(val,"encrypt",7) == 0) EncryptFlag = 1;
			if (strncasecmp(val,"fp1",3) == 0) EncryptFlag = 10;
			if (strncasecmp(val,"fp2",3) == 0) EncryptFlag = 11;
			if (strncasecmp(val,"fp3",3) == 0) EncryptFlag = 12;
			if (strncasecmp(val,"fp4",3) == 0) EncryptFlag = 13;
			if (strncasecmp(val,"fp5",3) == 0) EncryptFlag = 14;
		}
		if ((val=bg->getValue("zone.file_format")) == 0 || *val == 0) {
			sprintf(err_string,"file_format not found"); rtn = -77004; break;
		}
		FileFormat = (dgt_uint8)strtol(val,0,10);
		if ((val=bg->getValue("zone.close_after")) && *val) CloseAfter = strtol(val,0,10);
		if ((val=bg->getValue("zone.header_flag")) && *val) HeaderFlag = (dgt_uint8)strtol(val,0,10);
		if ((val=bg->getValue("zone.backup_flag")) && *val) BackupFlag = (dgt_uint8)strtol(val,0,10);
		if ((val=bg->getValue("zone.overwrite_flag")) && *val) OverWriteFlag = (dgt_uint8)strtol(val,0,10);
		if ((val=bg->getValue("zone.out_extension")) && *val) strncpy(OutExtension,val,32);
		if ((val=bg->getValue("zone.ext_ip")) && *val) strncpy(ExtIp,val,65);
		if ((val=bg->getValue("zone.ext_port")) && *val) ExtPort = (dgt_uint16)strtol(val,0,10);
#ifndef WIN32
#ifdef linux
		if ((val=bg->getValue("zone.s_limit")) && *val) Slimit = (dgt_float64)strtof(val,0);
		if ((val=bg->getValue("zone.s_enable")) && *val) Senable = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.g_sigma")) && *val) Gsigma = (dgt_float64)strtof(val,0);
#else
		if ((val=bg->getValue("zone.s_limit")) && *val) Slimit = (dgt_float64)atof(val);
		if ((val=bg->getValue("zone.s_enable")) && *val) Senable = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.g_sigma")) && *val) Gsigma = (dgt_float64)atof(val);
#endif /* linux */
#else
		if ((val=bg->getValue("zone.s_limit")) && *val) Slimit = (dgt_float64)strtol(val,0, 10);
		if ((val=bg->getValue("zone.s_enable")) && *val) Senable = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.g_sigma")) && *val) Gsigma = (dgt_float64)strtol(val,0, 10);
#endif /* WIN32 */
		if ((val=bg->getValue("zone.g_enable")) && *val) Genable = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.c_enable")) && *val) Cenable = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.r_angle")) && *val) Rangle = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("zone.r_enable")) && *val) Renable = (dgt_sint32)strtol(val,0,10);

		if (FileFormat == 1) { // all
		} else if (FileFormat == 2) { // regular
		} else if (FileFormat == 3) { // delmiter
		} else if (FileFormat == 4) { // fixed
		} else {
			sprintf(err_string,"unknown file format[%u]",FileFormat); rtn = -77008;
		}
		break;
	}
	unlockExclusive();
	return rtn;
}


dgt_sint32 PccCryptZone::setKeyParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_KEY_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setKeyParams: lockExclusive failed"),-1);
	if (FileFormat == 1) { //whole crypt
		//get EncColName
		dgt_schar*	val;
		if ((val=bg->getValue("key.1.name")) == 0 || *val == 0) {
			sprintf(err_string,"EncColName not found [-77020]"); 
			return -77020; 
		}
		strncpy(EncColName,val,sizeof(EncColName));

		//getsession for getKeyId api
		dgt_sint32 sid = -1;
		if ((sid=PcaApiSessionPool::getApiSession("","","","","","",0)) < 0) 
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getApiSession failed[%d] in cryptStatus",sid)),-1);

		PcaApiSession*  session = 0;
		if ((session=PcaApiSessionPool::getApiSession(sid)) == 0) 
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getApiSession[%d] failed in cryptStatus",sid)),-1);

		//get current key id
		dgt_sint64 curr_key_id = session->getKeyId(EncColName);
		if (curr_key_id < 0) {
			sprintf(err_string,"get key failed [%d]", (dgt_sint32)curr_key_id); 
			return (dgt_sint32)curr_key_id; 
		}
		KeyId = curr_key_id;
		
	} //if (FileFormat == 1) end
	strncpy(KeyParam,bg->getText(),256);
	unlockExclusive();
	return 0;
}

dgt_sint32 PccCryptZone::setRegularParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_REG_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setRegularParams: lockExclusive failed"),-1);
	strncpy(RegularParam,bg->getText(),256);
	dgt_schar* ch;
	ch = strchr(RegularParam, '\'');
	if (ch != NULL) {
		*ch = '\"';
		ch = strrchr(RegularParam, '\'');
		if (ch != NULL) {
			*ch = '\"';
		}
	}
	unlockExclusive();
	return 0;
}

dgt_sint32 PccCryptZone::setDelimiterParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_DELI_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setDelimiterParams: lockExclusive failed"),-1);
	strncpy(DelimiterParam,bg->getText(),256);
	unlockExclusive();
	return 0;
}

dgt_sint32 PccCryptZone::setFixedParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_FIXED_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setFixedParams: lockExclusive failed"),-1);
	strncpy(FixedParam,bg->getText(),256);
	unlockExclusive();
	return 0;
}

dgt_sint32 PccCryptZone::setSystemInfoParams(DgcBgrammer* bg,dgt_schar* err_string) throw(DgcExcept)
{
	if (lockExclusive(ELF_TYPE_SET_SYSINFO_PARAM) < 0) ATHROWnR(DgcError(SPOS,"setSystemInfoParams: lockExclusive failed"),-1);
	dgt_sint32	rtn = 0;
	for(;;) {
		dgt_schar*	val;
		if ((val=bg->getValue("system_info.system_id")) == 0 || *val == 0) {
			sprintf(err_string,"name not found"); rtn = -77002; break;
		}
#ifndef WIN32
		SystemID = dg_strtoll(val,0,10);
#else
		SystemID = (dgt_sint64)_strtoi64(val,0,10);
#endif
		break;
	}
	strncpy(SystemInfoParam,bg->getText(),256);
	unlockExclusive();
	return 0;
}

dgt_sint32 PccCryptZone::buildParam(dgt_schar* buf,dgt_uint32* buf_len, dgt_sint32 migration_flag) throw(DgcExcept)
{
	dgt_sint32	rtn = 0;
	memset(ErrString,0,1025);
	if ((rtn=checkParams(ErrString))) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"checkParams failed:%s",ErrString)),-1);
	}

	dgt_uint32	tmp_len = 0;
	dgt_schar	tmp[129];
	if (lockShare() < 0) ATHROWnR(DgcError(SPOS,"buildParam: lockShare failed"),-1);
	for(;;) {
		memset(tmp,0,129);
		dgt_schar* header_version = 0;
		switch (HeaderFlag) {
			case 1 : 
				header_version = (dgt_schar*)"on";
				break;
			case 2 : 
				header_version = (dgt_schar*)"V2on";
				break;
			case 3 : 
				header_version = (dgt_schar*)"V3on";
				break;
			case 4 : 
				header_version = (dgt_schar*)"V4on";
				break;
			default :
				header_version = (dgt_schar*)"off";
				break;
		}
		dgt_schar crypt_mode[128];
		memset(crypt_mode,0,128);
		if (EncryptFlag == 1) {
			if (migration_flag == 1) sprintf(crypt_mode,"%s","migration");
			else sprintf(crypt_mode,"%s","encrypt");
		} else if (EncryptFlag == 10) {
			sprintf(crypt_mode,"%s","fp1");
		} else if (EncryptFlag == 11) {
			sprintf(crypt_mode,"%s","fp2");
		} else if (EncryptFlag == 12) {
			sprintf(crypt_mode,"%s","fp3");
		} else if (EncryptFlag == 13) {
			sprintf(crypt_mode,"%s","fp4");
		} else if (EncryptFlag == 14) {
			sprintf(crypt_mode,"%s","fp5");
		}else {
			sprintf(crypt_mode,"%s","decrypt");
		}
		if (DetectFlag) {
			sprintf(tmp,"(mode=(detect=%d)(overwrite_flag=%s))",EncryptFlag,OverWriteFlag?"on":"off");
		} else if (ExtPort == 0) { // added by mwpark 2018.11.14 for fp masking
			sprintf(tmp,"(mode=(crypt=%s)(header_flag=%s)(overwrite_flag=%s))",crypt_mode,header_version,OverWriteFlag?"on":"off");
		} else {
			sprintf(tmp,"(mode=(crypt=%s)(header_flag=%s)(overwrite_flag=%s)(ext_ip=%s)(ext_port=%u))",crypt_mode,header_version,OverWriteFlag?"on":"off",ExtIp,ExtPort);
		}
		if ((tmp_len=strlen(tmp)) > *buf_len) {
			rtn = -1; break;
		}
		strcat(buf,tmp); *buf_len -= tmp_len;
		if ((tmp_len=strlen(KeyParam)) > *buf_len) {
			rtn = -1; break;
		}
		strcat(buf,KeyParam); *buf_len -= tmp_len;
		if (FileFormat == 2) { // regular
			if ((tmp_len=strlen(RegularParam)) > *buf_len) {
				rtn = -1; break;
			}
			strcat(buf,RegularParam); *buf_len -= tmp_len;
		} else if (FileFormat == 3) { // delimiter
			if ((tmp_len=strlen(DelimiterParam)) > *buf_len) {
				rtn = -1; break;
			}
			strcat(buf,DelimiterParam); *buf_len -= tmp_len;
		} else if (FileFormat == 4) { // fixed
			if ((tmp_len=strlen(FixedParam)) > *buf_len) {
				rtn = -1; break;
			}
			strcat(buf,FixedParam); *buf_len -= tmp_len;
		}
		if ((tmp_len=strlen(SystemInfoParam)) > *buf_len) { //add system_info
			rtn = -1; break;
		}
		strcat(buf,SystemInfoParam); *buf_len -= tmp_len;
		break;
	}
	unlockShare();
	if (rtn < 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"not enough buffer length for [%d]",tmp_len)),-1);
	}
	return 0;
}

