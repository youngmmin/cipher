/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccDetectUnit
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 28
 *   Description        :
 *   Modification history
 *   date                    modificationf
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_DETECT_UNIT_H
#define PCC_DETECT_UNIT_H


#include "PccReader.h"
#include "PccDetector.h"
#include "DgcMemRows.h"

class PccDetectUnit : public DgcWorker {
  private :
	DgcFileStream*		InStream;
	PccSearchEngineFactory&	SearchEngineFactory;
	PccCryptorFactory&	CryptorFactory;

	dgt_sint32*		LastErrCode;
	dgt_schar*		ErrString;
	PccFreeCryptBufList	CryptBufList;
	PccCryptBufFifoQueue    DataQueue;
	PccCryptList		CryptQueue;
	PccReader*		Reader;
	PccDetector*		Detectors[MAX_CIPHERS];
	dgt_sint32		NumDetectors;
	dgt_sint64		NumPttns;
	dgt_sint32		IsSkip;
	DgcMemRows*		DetectData;

	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_sint32 run() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  protected :
  public :
	PccDetectUnit(DgcFileStream* in,PccSearchEngineFactory& sef,PccCryptorFactory& cf,dgt_sint32* last_err_code);
	virtual ~PccDetectUnit();

	inline dgt_sint64 numPttns() { return NumPttns; };
	inline dgt_sint32 isSkip() { return IsSkip; };
	inline DgcMemRows* detectData() { return DetectData; }; 
	inline const dgt_schar* errString() { return ErrString; };
	dgt_sint32 detect() throw(DgcExcept);
};


#endif
