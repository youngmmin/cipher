/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccFileSpliter
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_FILE_SPLITER_H
#define PCC_FILE_SPLITER_H

#include "PccRunStream.h"

class PccFileSpliter : public DgcFileStream {
  private :
	static const dgt_sint32 MAX_RUNS = 1024;
	const dgt_schar* 	FileName;
	PccPttnSearchEngine*	SearchEngine;
	PccCryptorFactory&	CryptorFactory;
	dgt_sint64		RunSize;
	dgt_uint32		NumRuns;
	dgt_sint64		CurrOffset;
	dgt_sint32		CurrRuns;
	DgcFileStream*		Runs[MAX_RUNS];

	dgt_sint32 computeNextOffset() throw(DgcExcept);
  protected :
  public :
	PccFileSpliter(const dgt_schar* file_name,PccPttnSearchEngine* se,PccCryptorFactory& cf);
	virtual ~PccFileSpliter();
	inline dgt_sint64 runSize() { return RunSize; };
	inline dgt_uint32 numRuns() { return NumRuns; };

	dgt_void resetCurrOffset();
	DgcFileStream* getRun() throw(DgcExcept);
};

#endif
