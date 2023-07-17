#include "PccCipher.h"


dgt_sint32 PccCipher::run() throw(DgcExcept)
{
	PccCryptBuffer *curr=0;
	dgt_sint32 rtn;
	if (*LastErrCode) return 1;
	while ((rtn=DataQueue.get(&curr,&Waiter)) == 0) {
		if (*LastErrCode) return 1; // added by ihjin for thread normal stop
		DataQueueWaits++;
	}
	if (rtn < 0) return 1; // the end of job
	if ((rtn = SearchEngine->patternSearch(curr)) < 0) { // search patterns in the data buffer
		*LastErrCode = rtn;
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"crypt failed[%d]",rtn)),-1);
	}
	if ((rtn=Cryptor->crypt(curr)) < 0) { // encrypt patterns in the data buffer
		*LastErrCode = rtn;
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"crypt failed[%d]",rtn)),-1);
#if 1 // added by mwpark for encrypt bytes logging
	} else if (rtn > 0) OutBufLen += rtn;
#else
} else if (rtn > 0 && OutBufLen == 0) OutBufLen = rtn;
#endif
CryptQueue.put(curr); // return the crypt buffers into the crypt queue
CryptBuffers++;
return 0;
}
