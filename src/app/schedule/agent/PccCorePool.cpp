/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCorePool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PccCorePool.h"

PccCorePool::PccCorePool()
	: TotalCores(0),FreeCores(0), Cores(0)
{
	Cores = new PccCores[MAX_CORES];
	for(dgt_sint32 i=0; i<MAX_CORES-1; i++) Cores[i].setNext(&(Cores[i+1]));
	FirstFree = &(Cores[0]);
	LastFree = &(Cores[MAX_CORES-1]);
	DgcSpinLock::unlock(&PoolLock);
}

PccCorePool::~PccCorePool()
{
	if (Cores) {
	delete [] Cores;
	}
}

dgt_void PccCorePool::setCores(dgt_sint32 num_cores)
{
	for(;;) { // until holding the pool lock
		if (DgcSpinLock::lock(&PoolLock) == 0) {
			FreeCores += (num_cores - TotalCores);
			TotalCores = num_cores;
			DgcSpinLock::unlock(&PoolLock);
			return;
		}
	}
}

PccCores* PccCorePool::getCores(dgt_sint32 num_cores)
{
	PccCores* rtn = 0;
	for(;;) { // until holding the pool lock
		if (DgcSpinLock::lock(&PoolLock) == 0) {
			if (num_cores <= FreeCores) {
				if ((rtn=FirstFree)) {
					if ((FirstFree=rtn->next()) == 0) LastFree = 0; // now empty
					rtn->setCores(num_cores);
					rtn->setNext(0);
					FreeCores -= num_cores;
				}
			}
			DgcSpinLock::unlock(&PoolLock);
		}
		break;
	}
	return rtn;
}

dgt_void PccCorePool::returnCores(PccCores* cores)
{
	for(;;) { // until holding the pool lock
		if (DgcSpinLock::lock(&PoolLock) == 0) {
			FreeCores += cores->numCores();
			cores->setCores(0);
			if (LastFree) LastFree->setNext(cores);
			else FirstFree = cores;
			LastFree = cores;
			DgcSpinLock::unlock(&PoolLock);
			return;
		}
	}
}
