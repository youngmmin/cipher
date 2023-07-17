/*******************************************************************
 *   File Type          :       File Detection Program.
 *   Classes            :       PccDetectUnit
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 28
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccDetectUnit.h"


PccDetectUnit::PccDetectUnit(DgcFileStream* in,PccSearchEngineFactory& sef,PccCryptorFactory& cf,dgt_sint32* last_err_code)
	: InStream(in), SearchEngineFactory(sef), CryptorFactory(cf), LastErrCode(last_err_code), ErrString(0),
	  CryptBufList(cf.cryptMode(), cf.numBuffers(), cf.bufferSize()),
	  CryptQueue(cf.numBuffers()), Reader(0), NumDetectors(0), NumPttns(0), IsSkip(0) 
{
	ErrString = new dgt_schar[MAX_ERR_STRING];

	DetectData = new DgcMemRows(4);
	DetectData->addAttr(DGC_SB8,0,"start_offset");
	DetectData->addAttr(DGC_SB8,0,"end_offset");
	DetectData->addAttr(DGC_SCHR,1024,"expr");
	DetectData->addAttr(DGC_SCHR,1024,"data");
	DetectData->reset();
}


PccDetectUnit::~PccDetectUnit()
{
	if (ErrString) delete ErrString;
	if (DetectData) delete DetectData;
}

dgt_void PccDetectUnit::in() throw(DgcExcept)
{
	PccPttnSearchEngine* search_engine = SearchEngineFactory.getEngine();
	if (!search_engine) {
		*LastErrCode = PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED;
		THROW(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getEngine failed")));
	}
	Reader = new PccReader(InStream,CryptBufList,search_engine,DataQueue,0,LastErrCode);
	Reader->start(1);
	if (EXCEPT) {
		*LastErrCode = PFC_UNIT_ERR_CODE_START_READER_FAILED;
		sprintf(ErrString,"reader start failed:%d",*LastErrCode);
		ATHROW(DgcError(SPOS,"reader start failed"));
	}
	for(dgt_sint32 i=0; i<CryptorFactory.numThreads() && ++NumDetectors <= MAX_CIPHERS; i++) {
		Detectors[i] = new PccDetector(DataQueue,CryptQueue,SearchEngineFactory.getEngine(),LastErrCode);
		Detectors[i]->start(1);
		if (EXCEPT) {
			*LastErrCode = PFC_UNIT_ERR_CODE_START_CIPHER_FAILED;
			sprintf(ErrString,"%d-th detector start failed:%d",i+1,*LastErrCode);
			ATHROW(DgcError(SPOS,"%d-th detector start failed",i+1));
		}
	}
}


dgt_sint32 PccDetectUnit::run() throw(DgcExcept)
{
	if (*LastErrCode || !Reader->isAlive()) return 1; // nornal end

	// check the number of patterns to speed up detectiong
	dgt_sint64 num_pttns = 0;
	for(dgt_sint32 i=0; i<NumDetectors; i++) {
		if ( Detectors[i]->numPttns() ) {
			num_pttns += Detectors[i]->numPttns();
		}
	}
	dgt_sint64 max_detection = SearchEngineFactory.maxDetection();
	if (max_detection && max_detection < num_pttns) {
		IsSkip = 1;
		Reader->askStop();
		for(dgt_sint32 i=0; i<NumDetectors; i++) {
			Detectors[i]->askStop();
		}
		return 1;
	}

	napAtick();
	return 0;
}


dgt_void PccDetectUnit::out() throw(DgcExcept)
{
	if (Reader->isAlive()) { // abnormal stop by force in middle of work
                                     // fixed by ihjin 17.07.20
                                     // if do not have the encryption Privilege, the filesize is large, and mutiple mode,
                                     // error message is not printed.
                                     // using DgcWorker->stop(), main process is stop.
                    //Reader->stop();
                    if (Reader) while(Reader->isAlive()) napAtick();
                    for(dgt_sint32 i=0; i<NumDetectors; i++) {
                            if (Detectors[i]) while(Detectors[i]->isAlive()) napAtick();
                    //      Detectors[i]->stop();
                    }
	} else {
		dgt_sint32	total_buffers = CryptBufList.seqNo() ? CryptBufList.seqNo() : 1;
		DataQueue.setTotalBuffers(total_buffers);
		for(;;) {
			dgt_sint32 alive_count = 0;
			for(dgt_sint32 i=0; i<NumDetectors; i++) {
				if (Detectors[i]) {
					if (Detectors[i]->isAlive()) alive_count++;
				}
			}
			if (alive_count == 0) break;
			napAtick();
		}
		CryptQueue.setTotalBuffers(total_buffers);
	}
	delete Reader;
	NumPttns = 0;
	for(dgt_sint32 i=0; i<NumDetectors; i++) NumPttns += Detectors[i]->numPttns();
	for(dgt_sint32 i=0; i<NumDetectors; i++) delete Detectors[i];
}


dgt_sint32 PccDetectUnit::detect() throw(DgcExcept)
{
	PccPttnSearchEngine* search_engine = SearchEngineFactory.getEngine();
	if (!search_engine) {
		*LastErrCode = PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED;
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getEngine failed")),-1);
	}

	PccReader reader(InStream,CryptBufList,search_engine,DataQueue,0,LastErrCode,0);
	PccDetector detector(DataQueue,CryptQueue,search_engine,LastErrCode);
	if (EXCEPT) {
		*LastErrCode = PFC_UNIT_ERR_CODE_CRYPT_UNIT_ERROR;
		ATHROWnR(DgcError(SPOS,"exception occured"),-1);
	}
	PccCryptBuffer* curr = 0;
	dgt_sint32 rtn = 0;
	dgt_sint64 max_detection = SearchEngineFactory.maxDetection();
	while ((rtn=reader.readAndHandover(&curr)) > 0 && curr) {
		if (max_detection && max_detection < detector.numPttns()) {
			IsSkip = 1;
			break;
		}
		if ((rtn=detector.detect(curr)) < 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"detector detect failed")),-1);
		} 

		dgt_uint8* dp = curr->DstDataPtr;
		for (dgt_sint32 i = 0; i < curr->SegList->numPttnSegs(); i++) {
			DetectData->add();
			DetectData->next();
			memcpy(DetectData->data(), dp, sizeof(pc_type_detect_file_data_in));
			dp += sizeof(pc_type_detect_file_data_in);
		}
	}
	ATHROWnR(DgcError(SPOS,"readAndHandover failed"),-1);
	NumPttns = detector.numPttns();
 	return 0;
}
