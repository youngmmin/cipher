#include "PccCryptorFactory.h"


PccCryptorFactory::PccCryptorFactory(PccKeyMap& key_map,PccSearchEngineFactory& sef,const dgt_schar* pgm_name,dgt_sint32 manager_id)
	: KeyMap(key_map),SearchEngineFactory(sef),ProgramName(pgm_name),SessionID(-1),
	  NumBuffers(NUM_BUFFERS),BufferSize(BUFFER_SIZE),NumThreads(0),BinaryFlag(0),HeaderFlag(0),
	  NumCryptor(0),RunSize(0), EncZoneId(0), BypassCheck(0),BypassFlag(0)
{
	DgcSpinLock::unlock(&FactoryLock);
	TraceLevel = 0;
	KeyID = 0;
	ManagerID=manager_id;
	OsUser=0;
	StreamDecBufSize = 0;
}

PccCryptorFactory::~PccCryptorFactory()
{
	for(dgt_sint32 i=0; i<NumCryptor; i++) delete Cryptors[i];
}

dgt_sint32 PccCryptorFactory::initialize(DgcBgrammer* dg,dgt_schar* err_string)
{
	dgt_schar* val;
	dgt_sint32 tmp;
#if 0 // fix buffer amount - modified by shson 2017.07.30
	if ((val=dg->getValue("parallel.buffer.amount")) && (tmp=strtol(val,0,10))) NumBuffers = tmp;
#else
	NumBuffers=3;
#endif 


	if (dg) {
#if 1 // fix buffer size - modified by jhpark 2017.07.20
		if ((val=dg->getValue("parallel.buffer.size")) && (tmp=strtol(val,0,10))) BufferSize = tmp;
#else // modifed by shson 2017.07.24 - fix buffer size has a few problem
	BufferSize=2097152;
#endif
		if ((val=dg->getValue("parallel.threads")) && (tmp=strtol(val,0,10))) NumThreads = tmp;
			if (NumThreads > 3) {
				NumBuffers = (dgt_sint32)floor(NumThreads*1.5);
			}
		if ((val=dg->getValue("parallel.binary_flag")) && (tmp=strtol(val,0,10))) BinaryFlag = tmp;
		if ((val=dg->getValue("parallel.run_size"))) {
#ifndef WIN32
			dgt_sint64 tmp = (dgt_sint64)dg_strtoll(val,0,10);
#else
			dgt_sint64 tmp = (dgt_sint64)_strtoi64(val,0,10);
#endif
			if (tmp) RunSize=tmp;
	 	       if (dgt_sint32 adjustSize=BufferSize%16) { BufferSize+=adjustSize; }
		}
	}

#ifdef WIN32 // added by chchung 2017.6.20 because windows do not support thread yet
	RunSize = 0;
#endif
	if (BufferSize && RunSize && (dgt_sint64)BufferSize > RunSize) {
		sprintf(err_string,"buffer_size[%d] should be smaller than run_size[%lld]",BufferSize,RunSize);
		return -1;
	}
	if (NumBuffers < 3) {
		sprintf(err_string,"buffer amount[%d] should be greater than 2",NumBuffers);
		return -1;
	}
	return 0;
}

#if 1 // added by chchung 2017.6.12 for supporting shared or private session depending on user's choice
// private session is used when ProgramName is defined
PcaApiSession* PccCryptorFactory::getSession(dgt_schar* err_string) throw(DgcExcept)
{
	dgt_sint32      sid = -1;
	if ((sid=SessionID) < 0) { // a private session in case of ProgramName is defined and SessionID is not set yet
		//added by shson 18.02.28
		//when use multiple threads, 
		//each session should be private session
		//because remove dependency num_shared_session parameter in petra_cipher_api.conf
		//so input parameter that no mean db_user
		dgt_schar db_user[16];
		memset(db_user,0,sizeof(db_user));
		sprintf(db_user,"%d-%d",SessionID,ManagerID); // this SessionID is no mean(simply number has been increasing)
		// 
		// added by mwpark 18.10.01
		// for controling os_user(file`s owner)
		// 
		if (OsUser && *OsUser) {
			if ((sid=PcaApiSessionPool::getApiSession("","","","",db_user,OsUser,0)) < 0) {
				sprintf(err_string,"getApiSession failed[%d]",sid);
				THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getApiSession failed[%d]",sid)),0);
			}
		} else {
			if ((sid=PcaApiSessionPool::getApiSession("","","","",db_user,"",0)) < 0) {
				sprintf(err_string,"getApiSession failed[%d]",sid);
				THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getApiSession failed[%d]",sid)),0);
			}
		}
	}
	PcaApiSession*  session = 0;
	if ((session=PcaApiSessionPool::getApiSession(sid)) == 0) {
		sprintf(err_string,"getApiSession[%d] failed",sid);
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getApiSession[%d] failed",sid)),0);
	}
	return session;
}
#endif


PccCryptor* PccCryptorFactory::getCryptor(dgt_schar* err_string, dgt_sint32 shared_flag) throw(DgcExcept)
{
	PcaApiSession*	session = 0;
	if (shared_flag > 0) setSessionID(-shared_flag);
	if ((session=getSession(err_string)) == 0) {
		ATHROWnR(DgcError(SPOS,"getSession failed"),0);
	}
	PccCryptor* cryptor = 0;
	if (BypassFlag) {
		cryptor = new PccBypassEncryptor(session,KeyMap);
	} else {
		switch(SearchEngineFactory.engineType()) {
			case PccSearchEngineFactory::FORMAT_DECRYPTOR :
				cryptor = new PccFormatDecryptor(session,KeyMap);
				break;
			case PccSearchEngineFactory::FORMAT_ENCRYPTOR :
				cryptor = new PccFormatEncryptor(session,KeyMap);
				break;
			case PccSearchEngineFactory::PATTERN_DECRYPTOR :
				cryptor = new PccPatternDecryptor(session,KeyMap);
				break;
			case PccSearchEngineFactory::PATTERN_ENCRYPTOR :
				cryptor = new PccPatternEncryptor(session,KeyMap);
				break;
			case PccSearchEngineFactory::WHOLE_DECRYPTOR :
				cryptor = new PccWholeDecryptor(session,KeyMap,HeaderFlag);
				break;
			case PccSearchEngineFactory::WHOLE_ENCRYPTOR :
				cryptor = new PccWholeEncryptor(session,KeyMap,HeaderFlag);
				break;
			case PccSearchEngineFactory::WHOLE_MIGRATOR :
				cryptor = new PccWholeMigrator(session,KeyMap,HeaderFlag);
				break;
		}
	}
	for(;;) {
		if (DgcSpinLock::lock(&FactoryLock) == 0) {
			Cryptors[NumCryptor++] = cryptor;
			DgcSpinLock::unlock(&FactoryLock);
			break;
		}
	}
	return cryptor;
}
