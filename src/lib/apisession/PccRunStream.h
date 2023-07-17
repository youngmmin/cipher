/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccRunStream
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_STREAM_H
#define PCC_RUN_STREAM_H

#include "PccCryptUnit.h"
#include "DgcFileStream.h"

class PccRunStream : public DgcFileStream {
  private :
	dgt_schar*	FileName;
	dgt_sint64	StartOffset;
	dgt_sint64	Length;
	dgt_sint64	Remains;
  protected :
  public :
#ifndef WIN32
	PccRunStream(const dgt_schar* file_name,dgt_sint32 oflag=O_RDONLY,mode_t perm=0666,dgt_sint64 start_offset=0,dgt_sint64 length=0);
#else
	PccRunStream(const dgt_schar* file_name,dgt_sint32 oflag=O_RDONLY|_O_BINARY,mode_t perm=0666,dgt_sint64 start_offset=0,dgt_sint64 length=0);
#endif
	virtual ~PccRunStream();
	inline const dgt_schar* fileName() { return FileName; };
	virtual dgt_sint32 recvData(dgt_uint8* buf,dgt_sint32 len,dgt_sint32 timeout=-1) throw(DgcOsExcept);
	virtual dgt_sint32 sendData(const dgt_uint8* buf,dgt_sint32 len,dgt_sint32 timeout=-1) throw(DgcOsExcept);
	virtual dgt_sint64 fileSize() throw(DgcOsExcept);
};

#endif
