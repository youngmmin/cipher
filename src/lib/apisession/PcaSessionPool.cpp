/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaSessionPool
 *   Implementor        :       chchung
 *   Create Date        :       2012. 4. 5
 *   Description        :       petra cipher API session pool
 *   Modification history
 *   date                    modification
-----------------------------------------------------------

********************************************************************/
#include "PcaSessionPool.h"


#ifndef WIN32
__attribute__((constructor)) void __pcApiCoreInitializer(void) { PcaSessionPool::initializer(); }
__attribute__((destructor)) void __pcApiCoreFinalizer(void) { PcaSessionPool::finalizer(); }
PcaSessionPool*	PcaSessionPool::SessionPool = 0;
#else
PcaSessionPool  PcaSessionPool::SessionPool;
#endif

PcaSessionPool::PcaSessionPool()
	: RandomSID(PSP_RAMDOM_SEED),
	  SingleHashVal(0),
	  InitializeFlag(0),
	  KeySvrSessionPool(0),
	  NamePool(0),
	  KeyPool(0),
	  IVPool(0),
	  StandAloneFlag(0)
{
	DgcSpinLock::unlock(&PoolLatch);
	KeySvrSessionPool = new PcaKeySvrSessionPool();
	NamePool = new PcaNamePool(KeySvrSessionPool);
	KeyPool = new PcaKeyPool(KeySvrSessionPool);
	IVPool = new PcaIVPool(KeySvrSessionPool);
	memset(SessionTable, 0, sizeof(SessionTable));
}


PcaSession* PcaSessionPool::newSession(dgt_sint32 sid)
{
	PcaSession*	session = 0;
	if (DgcSpinLock::lock(&PoolLatch)) {
		PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the session pool failed");
	} else {
		if (InitializeFlag == 0) {
			initializeKeySvrSessionPool(0,0);
		}
		if (sid == 0) sid = ++RandomSID;
		dgt_sint32	hval = sid % PSP_MAX_SESSIONS;
		session = SessionTable[hval];
		while(session) {
			if (session->sid() == sid) {
				//
				// any session with the same sid is considered as an closed session. reset & reuse
				//
				session->reset();
				break;
			}
			session = (PcaSession*)session->next();
		}
		if (!session) {
			//
			// create a new session and set it as the first node in its hash list
			//
			session = new PcaSession(sid, KeySvrSessionPool, NamePool, KeyPool, IVPool, (StandAloneFlag ? &PrivHolder:0) );
if (PcaKeySvrSessionPool::traceLevel() > 0) PcaKeySvrSessionPool::logging("new session[%d] created.",sid);
			if (SessionTable[hval]) session->setNext(SessionTable[hval]); // set it as the first node
			SessionTable[hval] = session;
			if (sid > RandomSID) RandomSID = sid + 1; // to avoid sid collision
			SingleHashVal = hval;
		}
		DgcSpinLock::unlock(&PoolLatch);
	}
	return session;
}


dgt_void PcaSessionPool::removeSession(dgt_sint32 sid)
{
	if (sid == 0) {
		delete SessionTable[SingleHashVal];
		SessionTable[SingleHashVal] = 0;
	} else {
		dgt_sint32	hval = sid % PSP_MAX_SESSIONS;
		PcaSession*	prev = 0;
		PcaSession*	curr = 0;
		if (DgcSpinLock::lock(&PoolLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the session pool failed");
		} else {
			curr = SessionTable[hval];
			while(curr) {
				if (curr->sid() == sid) {
					if (prev) prev->setNext(curr->next());
					else SessionTable[hval] = (PcaSession*)curr->next();
					curr->setNext();
					delete curr;
					break;
				}
				prev = curr;
				curr = (PcaSession*)curr->next();
			}
			DgcSpinLock::unlock(&PoolLatch);
		}
	}
if (PcaKeySvrSessionPool::traceLevel() > 0) PcaKeySvrSessionPool::logging("session[%d] removed.",sid);
}


PcaSessionPool::~PcaSessionPool()
{
#ifndef WIN32
if (PcaKeySvrSessionPool::traceLevel() > 0) PcaKeySvrSessionPool::logging("SessionPool[%u] destructed",getpid());
#endif

	for(dgt_sint32 i=0; i<PSP_MAX_SESSIONS; i++) delete SessionTable[i];
	delete NamePool;
	delete KeyPool;
	delete IVPool;
	delete KeySvrSessionPool;
}
