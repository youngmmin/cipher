/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaApiSessionPool
 *   Implementor        :       chchung
 *   Create Date        :       2012. 4. 5
 *   Description        :       petra cipher API session pool
 *   Modification history
 *   date                    modification
-----------------------------------------------------------

********************************************************************/
#include "PcaApiSessionPool.h"


#ifdef hpux11
PcaApiSessionPool*	PcaApiSessionPool::ApiSessionPool = 0;
#else
PcaApiSessionPool	PcaApiSessionPool::ApiSessionPool;
#endif


PcaApiSessionPool::PcaApiSessionPool()
	: ApiSharedSessions(0),
	  NumSharedSession(0),
	  SharedFreePool(0),
	  FreePoolSize(0)
{
	DgcSpinLock::unlock(&PoolLatch);
	memset(ApiSessions, 0, sizeof(ApiSessions));
}


PcaApiSessionPool::~PcaApiSessionPool()
{
	for(dgt_sint32 i=0; i<PSP_MAX_SESSIONS; i++) delete ApiSessions[i];
	for(dgt_sint32 i=0; i<NumSharedSession; i++) delete ApiSharedSessions[i];
	delete ApiSharedSessions;
	delete SharedFreePool;
}
