/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccRunStream
 *   Implementor        :       chchung
 *   Create Date        :       2017. 04. 24
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PccRunStream.h"

PccRunStream::PccRunStream(const dgt_schar* file_name, dgt_sint32 oflag, mode_t perm, dgt_sint64 start_offset, dgt_sint64 length)
		: DgcFileStream(file_name,oflag,perm), StartOffset(start_offset), Length(length), Remains(Length)
{
	FileName = 0;
	if (EXCEPT) {
		StartOffset = 0;
		Length = 0;
		Remains = 0;
		ATHROW(DgcError(SPOS,"DgcFileStream failed"));
	} else {
		dgt_sint32 len = dg_strlen(file_name) + 1;
		FileName = new dgt_schar[len];
		strcpy(FileName,file_name);
		FileName[len-1] = 0;
		if (StartOffset) seek(StartOffset,SEEK_SET);
	}
}


PccRunStream::~PccRunStream()
{
	if (FileName) delete FileName;
}


dgt_sint32 PccRunStream::recvData(dgt_uint8* buf,dgt_sint32 len,dgt_sint32 timeout) throw(DgcOsExcept)
{
	dgt_sint32 rbytes;
	if (Length) {
		// limited run
		if (Remains >= (dgt_uint32)len) rbytes = DgcFileStream::recvData(buf,len,timeout);
		else if (Remains == 0) rbytes = 0;
		else rbytes = DgcFileStream::recvData(buf,Remains,timeout);
		ATHROWnR(DgcError(SPOS,"recvData failed"),-1);
		if (rbytes > 0) Remains -= rbytes;
	} else {
		// unlimited run
		rbytes = DgcFileStream::recvData(buf,len,timeout);
		ATHROWnR(DgcError(SPOS,"recvData failed"),-1);
	}
	return rbytes;
}


dgt_sint32 PccRunStream::sendData(const dgt_uint8* buf,dgt_sint32 len,dgt_sint32 timeout) throw(DgcOsExcept)
{
	dgt_sint32 wbytes;
	if (Length) {
		// limited run
		if (Remains >= (dgt_uint32)len) wbytes = DgcFileStream::sendData(buf,len,timeout);
		else if (Remains == 0) wbytes = 0;
		else wbytes = DgcFileStream::sendData(buf,Remains,timeout);
		ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
		if (wbytes > 0) Remains -= wbytes;
	} else {
		// unlimited run
		wbytes = DgcFileStream::sendData(buf,len,timeout);
		ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
	}
	return wbytes;
}


dgt_sint64 PccRunStream::fileSize() throw(DgcOsExcept)
{
	return Length ? Length : DgcFileStream::fileSize();
}
