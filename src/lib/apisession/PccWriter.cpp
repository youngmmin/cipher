#include "PccWriter.h"

dgt_sint32 PccWriter::write(PccCryptBuffer* curr) throw(DgcExcept)
{
	if (StopFlag) return 1;
	dgt_sint32 nbytes;
	dgt_sint32 wbytes = 0;
	if (StreamFlag) {
		for (dgt_sint32 i = 0; i<curr->DstLength ; i++) {
			if (*(curr->DstDataPtr + i) != 0x00) wbytes++;
			else break;
		}
		if ((nbytes=OutStream->sendData(curr->DstDataPtr,wbytes)) < 0) {
			*LastErrCode = nbytes;
			ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
		}
	} else {
		//added by shson  2018.12.04
		//for decryption kernel encrypting file 
		//OrgSize set when header version 4
		if (curr->LastFlag == 1 && OrgSize) wbytes = OrgSize - OutStream->fileSize();
		else wbytes = curr->DstLength;

		if ((nbytes=OutStream->sendData(curr->DstDataPtr,wbytes)) < 0) {
			*LastErrCode = nbytes;
			ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
		}
	}
	return 0;
}

dgt_sint32 PccWriter::run() throw(DgcExcept)
{
	PccCryptBuffer* curr=0;
	dgt_sint32 rtn;
	if (*LastErrCode) return 1;
	while ((rtn=CryptQueue.get(&curr,&Waiter)) == 0) {
		if (StopFlag) return 1;
		if (*LastErrCode) return 1; // added by ihjin for thread normal stop
		CryptQueueWaits++;
	}
	if (rtn < 0) return 1; // the end of job

	PccCryptBuffer* crypted_bufs = curr;
	dgt_sint32 nbytes;
	dgt_sint32 wbytes = 0;
	//added by shson  2018.12.04
	//for decryption kernel encrypting file 
	//OrgSize set when header version 4
	if (curr->LastFlag == 1 && OrgSize) wbytes = OrgSize - OutStream->fileSize();
	else wbytes = curr->DstLength;

	while(crypted_bufs) {
		if ((nbytes=OutStream->sendData(crypted_bufs->DstDataPtr,wbytes)) < 0) {
			*LastErrCode = PFC_WT_ERR_CODE_SEND_DATA_FAILED;
			ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
		}
		WriteBuffers++;
		crypted_bufs = crypted_bufs->Next;
	}
	CryptBufList.put(curr); // return the crypted buffers into the free buffer list
	return 0;
}

