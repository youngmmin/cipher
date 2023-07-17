/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccCryptUnit
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptUnit.h"


PccCryptUnit::PccCryptUnit(DgcFileStream* in,DgcFileStream* out,PccSearchEngineFactory& sef,PccCryptorFactory& cf,PccHeaderManager& hm,dgt_sint32* last_err_code)
	: InStream(in), OutStream(out), SearchEngineFactory(sef), CryptorFactory(cf), HeaderManager(hm), LastErrCode(last_err_code), ErrString(0),
	  CryptBufList(cf.cryptMode(), cf.numBuffers(), cf.bufferSize()),
	  CryptQueue(cf.numBuffers()), Reader(0), NumCiphers(0), Writer(0), OutBufLen(0), InFileSize(0)
{
	ErrString = new dgt_schar[MAX_ERR_STRING];
	memset(ErrString, 0, MAX_ERR_STRING);
}


PccCryptUnit::~PccCryptUnit()
{
	if (ErrString) delete ErrString;
}

dgt_void PccCryptUnit::in() throw(DgcExcept)
{
	PccPttnSearchEngine* search_engine = SearchEngineFactory.getEngine();
	if (!search_engine) {
		*LastErrCode = PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED;
		THROW(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getEngine failed")));
	}
	Reader = new PccReader(InStream,CryptBufList,search_engine,DataQueue,CryptorFactory.cryptMode() ? 0 : HeaderManager.headerSize(),LastErrCode);
	Reader->start(1);
	if (EXCEPT) {
		*LastErrCode = PFC_UNIT_ERR_CODE_START_READER_FAILED;
		sprintf(ErrString,"reader start failed:%d",*LastErrCode);
		ATHROW(DgcError(SPOS,"reader start failed"));
	}
	for(dgt_sint32 i=0; i<CryptorFactory.numThreads() && ++NumCiphers <= MAX_CIPHERS; i++) {
		PccCryptor*		cryptor = CryptorFactory.getCryptor(ErrString, i+1);
		if (EXCEPT) {
			*LastErrCode = PFC_UNIT_ERR_CODE_GET_CRYPTOR_FAILED;
			ATHROW(DgcError(SPOS,"getCryptor failed"));
		}
		Ciphers[i] = new PccCipher(DataQueue,CryptQueue,SearchEngineFactory.getEngine(),cryptor,LastErrCode);
		Ciphers[i]->start(1);
		if (EXCEPT) {
			*LastErrCode = PFC_UNIT_ERR_CODE_START_CIPHER_FAILED;
			sprintf(ErrString,"%d-th cipher start failed:%d",i+1,*LastErrCode);
			ATHROW(DgcError(SPOS,"%d-th cipher start failed",i+1));
		}
	}
	Writer = new PccWriter(OutStream,CryptQueue,CryptBufList,LastErrCode);
	if (HeaderManager.headerVersion() == 4 && !CryptorFactory.cryptMode()) Writer->setOrgSize(HeaderManager.inFileSize());
	Writer->start(1);
	if (EXCEPT) {
		*LastErrCode = PFC_UNIT_ERR_CODE_START_WRITER_FAILED;
		sprintf(ErrString,"writer start failed:%d",*LastErrCode);
		ATHROW(DgcError(SPOS,"writer start failed"));
	}
}


dgt_sint32 PccCryptUnit::run() throw(DgcExcept)
{
	if (*LastErrCode || !Reader->isAlive()) return 1; // nornal end
	napAtick();
	return 0;
}


dgt_void PccCryptUnit::out() throw(DgcExcept)
{
	if (Reader->isAlive()) { // abnormal stop by force in middle of work
                                     // fixed by ihjin 17.07.20
                                     // if do not have the encryption Privilege, the filesize is large, and mutiple mode,
                                     // error message is not printed.
                                     // using DgcWorker->stop(), main process is stop.
                    //Reader->stop();
                    if (Reader) while(Reader->isAlive()) napAtick();
                    for(dgt_sint32 i=0; i<NumCiphers; i++) {
                            if (Ciphers[i]) while(Ciphers[i]->isAlive()) napAtick();
                    //      Ciphers[i]->stop();
                    }
                    //if (Writer) Writer->stop();
                    if (Writer) while(Writer->isAlive()) napAtick();
	} else {
		dgt_sint32	total_buffers = CryptBufList.seqNo() ? CryptBufList.seqNo() : 1;
		DataQueue.setTotalBuffers(total_buffers);
		for(;;) {
			dgt_sint32 alive_count = 0;
			for(dgt_sint32 i=0; i<NumCiphers; i++) {
				if (Ciphers[i]) {
					if (Ciphers[i]->isAlive()) alive_count++;
				}
			}
			if (alive_count == 0) break;
			napAtick();
		}
		CryptQueue.setTotalBuffers(total_buffers);
		if (Writer) while(Writer->isAlive()) napAtick();
	}
	delete Reader;
	if (Ciphers[0]) OutBufLen = Ciphers[0]->outBufLen();
	for(dgt_sint32 i=0; i<NumCiphers; i++) delete Ciphers[i];
	delete Writer;
}


dgt_sint32 PccCryptUnit::crypt() throw(DgcExcept)
{
	PccPttnSearchEngine* search_engine = SearchEngineFactory.getEngine();
	if (!search_engine) {
		*LastErrCode = PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED;
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getEngine failed")),-1);
	}

	dgt_sint32 stream_flag = 0; //added by shson 2018.12.06 for support kernel encryption
	if (CryptorFactory.cryptMode()) {
		if (HeaderManager.headerVersion() == 3) stream_flag = 1; 
		else if (HeaderManager.headerVersion() == 4) stream_flag = 2;
	}
	PccReader reader(InStream,CryptBufList,search_engine,DataQueue,CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT ? 0 : HeaderManager.headerSize(),LastErrCode,stream_flag);
	if (stream_flag == 1) {
		dgt_sint64 remain_bytes = InFileSize - (dgt_sint64)InStream->seek(0,SEEK_CUR);
		reader.setRemainBytes(remain_bytes);
	}
	PccCipher cipher(DataQueue,CryptQueue,search_engine,CryptorFactory.getCryptor(ErrString),LastErrCode);
	if (EXCEPT) {
		*LastErrCode = PFC_UNIT_ERR_CODE_CRYPT_UNIT_ERROR;
		ATHROWnR(DgcError(SPOS,"exception occured"),-1);
	}
	PccWriter writer(OutStream,CryptQueue,CryptBufList,LastErrCode,HeaderManager.headerVersion() == 3 ? 1:0);
	if (HeaderManager.headerVersion() == 4 && !CryptorFactory.cryptMode()) writer.setOrgSize(HeaderManager.inFileSize());
	PccCryptBuffer* curr = 0;
	dgt_sint32 rtn = 0;
	while ((rtn=reader.readAndHandover(&curr)) > 0 && curr) {
		if ((rtn=cipher.crypt(curr)) < 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"cipher crypt failed")),-1);
		}
		if (writer.write(curr) <= 0) {
			ATHROWnR(DgcError(SPOS,"write failed"),-1);
		}
	}
	ATHROWnR(DgcError(SPOS,"readAndHandover failed"),rtn);
	OutBufLen = cipher.outBufLen();
 	return 0;
}
