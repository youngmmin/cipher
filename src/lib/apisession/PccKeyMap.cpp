#include "PccKeyMap.h"
#include "PccFileCipherConstTypes.h"

PccKeyMap::PccKeyMap()
{ 
	KeyType = 0;
	for(dgt_uint16 i=0; i<MAX_COLS; i++) {
		KeyMap[i]=""; OutColLengths[i] = 0;
	}

	for(dgt_uint16 i=0; i<MAX_COLS; i++) {
		VirtualKeyMap[i]=0;
	}
	InputFileNamePtr = 0;
	memset(HostName,0,65);
	memset(OsUser,0,65);
	dgt_schar*		InputFileNamePtr;	// for virtual key priv
	dgt_schar		HostName[65];
	dgt_schar		OsUser[65];
}

PccKeyMap::~PccKeyMap()
{
}

dgt_void PccKeyMap::addKeyMap(const dgt_schar* enc_name,dgt_schar* col_string)
{
	dgt_schar*	last;
#ifndef WIN32
	dgt_schar*	cp = strtok_r(col_string," ,\f\n",&last);
#else
	dgt_schar*	cp = strtok_s(col_string," ,\f\n",&last);
#endif
	do {
		dgt_uint16 col_no = strtol(cp,0,10);
		if (col_no && col_no < MAX_COLS) KeyMap[col_no] = enc_name;
#ifndef WIN32
	} while ((cp=strtok_r(0," ,\f\n",&last)));
#else
	} while ((cp=strtok_s(0," ,\f\n",&last)));
#endif

	KeyType = USE_KEY_TYPE_ENC_NAME;
}

dgt_void PccKeyMap::addVirtualKeyMap(dgt_sint64 vkey_id,dgt_schar* col_string)
{
	dgt_schar*	last;
#ifndef WIN32
	dgt_schar*	cp = strtok_r(col_string," ,\f\n",&last);
#else
	dgt_schar*	cp = strtok_s(col_string," ,\f\n",&last);
#endif
	do {
		dgt_uint16 col_no = strtol(cp,0,10);
		if (col_no && col_no < MAX_COLS) VirtualKeyMap[col_no] = vkey_id;
#ifndef WIN32
	} while ((cp=strtok_r(0," ,\f\n",&last)));
#else
	} while ((cp=strtok_s(0," ,\f\n",&last)));
#endif

	KeyType = USE_KEY_TYPE_VIRTUAL_KEY;
}

dgt_sint32 PccKeyMap::addOutColLengths(dgt_schar* length_string)
{
	dgt_uint16	num_cols=0;
	dgt_schar*	last;
#ifndef WIN32
	dgt_schar*	cp = strtok_r(length_string," ,\f\n",&last);
#else
	dgt_schar*	cp = strtok_s(length_string," ,\f\n",&last);
#endif
	do {
		dgt_uint16 col_length = strtol(cp,0,10);
		if (col_length && num_cols < MAX_COLS) {
			OutColLengths[num_cols++] = col_length;
		}
#ifndef WIN32
	} while ((cp=strtok_r(0," ,\f\n",&last)));
#else
	} while ((cp=strtok_s(0," ,\f\n",&last)));
#endif
	return num_cols;
}

const dgt_schar* PccKeyMap::encName(dgt_uint16 col_no)
{
	if (col_no < MAX_COLS) return KeyMap[col_no];
	return "";
}

dgt_sint64 PccKeyMap::virtualKeyID(dgt_uint16 col_no)
{
	if (col_no < MAX_COLS) return VirtualKeyMap[col_no];
	return 0;
}

dgt_void PccKeyMap::setVKeyTargetEnv(const dgt_schar* target_file)
{
#ifndef WIN32
	if (gethostname(HostName,64) != 0) {
		DgcWorker::PLOG.tprintf(0,"gethostname failed:[%d:%s]\n",errno,strerror(errno));
	}
	dgt_schar* os_user = dg_getenv("LOGNAME");
	if (os_user) {
		strncpy(OsUser,dg_getenv("LOGNAME"),dg_strlen(os_user)>64?64:dg_strlen(os_user));
	}
#else
	// windows get host and os user
#endif
	InputFileNamePtr = target_file;
}
