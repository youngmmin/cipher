/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCorePool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CORE_POOL_H
#define PCC_CORE_POOL_H

#include "PccCryptMir.h"

class PccCores : public DgcObject {
  private:
	dgt_sint32	NumCores;
	PccCores*	Next;
  protected:
  public:
	PccCores() : NumCores(0), Next(0) {}
	virtual ~PccCores() {};
	dgt_void setCores(dgt_sint32 num_cores) { NumCores = num_cores; }
	dgt_void setNext(PccCores* next) { Next = next; }
	PccCores* next() { return Next; }
	dgt_sint32 numCores() { return NumCores; }
};

class PccCorePool : public DgcObject {
  private:
	static const dgt_sint32	MAX_CORES = 500;
	dgt_sint32	TotalCores;
	dgt_sint32	FreeCores;
	PccCores*	Cores;
	PccCores*	FirstFree;
	PccCores*	LastFree;
	dgt_slock	PoolLock;
  protected:
  public:
	PccCorePool();
	virtual ~PccCorePool();
	dgt_sint32 totalCores() { return TotalCores; }
	dgt_sint32 freeCores() { return FreeCores; }
	dgt_void setCores(dgt_sint32 num_cores);
	PccCores* getCores(dgt_sint32 num_cores);
	dgt_void returnCores(PccCores* cores);
};

#endif
