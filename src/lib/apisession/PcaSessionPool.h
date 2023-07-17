/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API session
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_SESSION_POOL_H
#define PCA_SESSION_POOL_H


#include "DgcBgmrList.h"
#include "PcaSession.h"
#include "PcaKeySvrSessionPool.h"
#include "PcaNamePool.h"
#include "PcaKeyPool.h"
#include "PcaIVPool.h"


class PcaSessionPool : public DgcObject {
  private:
	static const dgt_sint32	PSP_MAX_SESSIONS = 4096;	// size of session hash table
	static const dgt_sint32	PSP_RAMDOM_SEED = 100000000;	// random session id seed
	static const dgt_sint32 PSP_ERR_LOCK_FAIL = -30309;	// error code for spin locking failure 
#ifndef WIN32
        static PcaSessionPool*  SessionPool;
#else
        static PcaSessionPool   SessionPool;
#endif
	dgt_slock		PoolLatch;	// spin lock for concurrency control
	dgt_slock		ApisLatch;	// spin lock for concurrency control over ApiSessions
	dgt_sint32		RandomSID;	// random session ID
	dgt_sint32		SingleHashVal;	// single session hash value
	dgt_sint32		InitializeFlag;	// initialize flag
	PcaKeySvrSessionPool*	KeySvrSessionPool;	// key server session pool
	PcaNamePool*		NamePool;	// encrypt column name pool
	PcaKeyPool*		KeyPool;	// key pool
	PcaIVPool*		IVPool;	// iv pool
	PcaSession*		SessionTable[PSP_MAX_SESSIONS];	// API session table

#if 1 // added by chchung 2017.5.31 for stand alone mode
 	dgt_sint32		StandAloneFlag;
	PcaPrivHolder		PrivHolder;

	dgt_sint32 setStandAlone(const dgt_schar* key_info_buffer,dgt_uint32 buffer_len,const dgt_schar* passwd)
	{
		dgt_sint32	rtn;
		PcaPrivCompiler	priv_compiler;
		if ((rtn=priv_compiler.importKeyInfo(passwd,key_info_buffer,buffer_len)) < 0) return rtn;
		if ((rtn=PrivHolder.putPriv(priv_compiler.encColID(),priv_compiler.privInfo())) < 0) return rtn;
		StandAloneFlag = 1;
#ifndef WIN32
		SessionPool->initializeKeySvrSessionPool(0,0);
#else
		SessionPool.initializeKeySvrSessionPool(0,0);
#endif
		NamePool->putName(priv_compiler.encColName(),priv_compiler.encColID());
		KeyPool->putKeyInfo(priv_compiler.privInfo()->key_id,priv_compiler.keyInfo(),priv_compiler.trailerInfo());
		return 0;
	}
#endif

	inline dgt_sint32 initializeKeySvrSessionPool(dgt_schar* file_path,const dgt_schar* credentials_pw)
	{
		dgt_sint32	rtn = 0;
		if (InitializeFlag == 0) {
			if (!(rtn=KeySvrSessionPool->initialize(file_path,credentials_pw,StandAloneFlag))) {
			}
			InitializeFlag = 1;

#if 1 // added by chchung 2017.6.11 for adding system level standalone mode
			if (*(KeySvrSessionPool->keyInfoFilePath())) {
				DgcBgmrList	key_infos(KeySvrSessionPool->keyInfoFilePath());
				if (EXCEPT) {
					DgcExcept* e = EXCEPTnC;
					PcaKeySvrSessionPool::logging("key_info_file[%s] compilation failed:%d",KeySvrSessionPool->keyInfoFilePath(),e->errCode());
					delete e;
				} else {
					DgcBgrammer*    bg = 0;
					while((bg=key_infos.getNext())) {
						dgt_schar*	key_info_buffer = bg->getValue("key_info");
						if (key_info_buffer) {
							dgt_sint32	rtn = setStandAlone(key_info_buffer,strlen(key_info_buffer),0);
							if (rtn) PcaKeySvrSessionPool::logging("key_info[%s] load failed:%d",key_info_buffer,rtn);
						}
					}
				}
			}
#endif

		}
		return rtn;
	};

	inline dgt_sint32 maxSharedSession()
	{
#if 0 // modified by chchung 2017.6.11 for adding system level standalone mode
		if (InitializeFlag == 0) {
			InitializeFlag = 1;
			KeySvrSessionPool->initialize(0,0);
		}
#else
		initializeKeySvrSessionPool(0,0);
#endif
		return KeySvrSessionPool->numSharedSession();
	};

	inline dgt_sint32 maxSession()
	{
#if 0 // modified by chchung 2017.6.11 for adding system level standalone mode
		if (InitializeFlag == 0) {
			InitializeFlag = 1;
			KeySvrSessionPool->initialize(0,0);
		}
#else
		initializeKeySvrSessionPool(0,0);
#endif
		return KeySvrSessionPool->maxPrivateSession();
	};

	inline PcaSession* findSession(dgt_sint32 sid)
	{
		if (sid < 0) return 0;
		else if (sid == 0) return SessionTable[SingleHashVal]; // single session
		dgt_sint32	hval = sid % PSP_MAX_SESSIONS;
		PcaSession*	session=0;
		if (DgcSpinLock::lock(&PoolLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the session pool failed");
		} else {
			session=SessionTable[hval];
			while(session) {
				if (session->sid() == sid) break;
				session = (PcaSession*)session->next();
			}
			DgcSpinLock::unlock(&PoolLatch);
		}
		return session;
	};
	
	inline PcaSession* findSessionNL(dgt_sint32 sid)
        {
                if (sid < 0) return 0;
                else if (sid == 0) return SessionTable[SingleHashVal]; // single session
                dgt_sint32      hval = sid % PSP_MAX_SESSIONS;
                PcaSession*     session=0;
                session=SessionTable[hval];
                while(session) {
                	if (session->sid() == sid) break;
			session = (PcaSession*)session->next();
		}
                return session;
        };


// added by chchung 2017.10.17 for altibase rdbms
	PcaNamePool* namePoolPtr() { return NamePool; }
	

	PcaSession*	newSession(dgt_sint32 sid);
	dgt_void	removeSession(dgt_sint32 sid);
  protected:
  public:
	PcaSessionPool();
	virtual ~PcaSessionPool();

	static inline dgt_sint32 initialize(dgt_schar* info_file_path=0,const dgt_schar* credentials_pw=0)
	{
#ifndef WIN32
		return SessionPool->initializeKeySvrSessionPool(info_file_path,credentials_pw);
#else
		return SessionPool.initializeKeySvrSessionPool(info_file_path,credentials_pw);
#endif
	};

	static inline dgt_sint32 numSharedSession()
	{
#ifndef WIN32
		return SessionPool->maxSharedSession();
#else
		return SessionPool.maxSharedSession();
#endif
	};

	static inline dgt_sint32 maxPrivateSession()
	{
#ifndef WIN32
		return SessionPool->maxSession();
#else
		return SessionPool.maxSession();
#endif
	};

	static inline PcaSession* openSession(dgt_sint32 sid)
	{
#ifndef WIN32
		return SessionPool->newSession(sid);
#else
		return SessionPool.newSession(sid);
#endif
	};

	static inline PcaSession* getSession(dgt_sint32 sid, dgt_uint8 no_lock=0)
	{
#ifndef WIN32
		if (no_lock) return SessionPool->findSessionNL(sid);
		return SessionPool->findSession(sid);
#else
		if (no_lock) return SessionPool.findSessionNL(sid);
		return SessionPool.findSession(sid);
#endif
	};

	static inline dgt_void closeSession(dgt_sint32 sid)
	{
#ifndef WIN32
		SessionPool->removeSession(sid);
#else
		SessionPool.removeSession(sid);
#endif
	};

// added by chchung 2017.5.31 for stand alone session
	static dgt_sint32 putKeyInfo(const dgt_schar* key_info_buffer,dgt_uint32 buffer_len,const dgt_schar* passwd)
	{
#ifndef WIN32
		return SessionPool->setStandAlone(key_info_buffer,buffer_len,passwd);
#else
		return SessionPool.setStandAlone(key_info_buffer,buffer_len,passwd);
#endif
	}

#ifndef WIN32
	static inline dgt_void initializer() { SessionPool = new PcaSessionPool(); };
	static inline dgt_void finalizer() { delete SessionPool; };
#endif

// added by chchung 2017.10.17 for altibase rdbms
	static inline PcaNamePool* namePool()
	{
#ifndef WIN32
		return SessionPool->namePoolPtr();
#else
		return SessionPool.namePoolPtr();
#endif
	}
};


#endif
