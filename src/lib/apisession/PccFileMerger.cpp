/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccFileMerger
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

#include "PccFileMerger.h"
#include "PccRunStream.h"

PccFileMerger::PccFileMerger(PccCryptorFactory&	cf,const dgt_schar* file_name,dgt_sint64 run_size, dgt_sint32 file_flag)
	: DgcFileStream(file_name,file_flag,0644),CryptorFactory(cf), BinaryFlag(cf.binaryFlag()),FileName(file_name),
		  RunSize(run_size),NumRuns(0),CopyBuffer(0)
{
	if (EXCEPT) {
		ATHROW(DgcError(SPOS,"creating file_merger failed"));
	} else {
		CopyBuffer = new dgt_uint8[COPY_BUF_SIZE];
		for(dgt_sint32 i=1; i<MAX_RUNS; i++) Runs[i] = 0;
	}
}


PccFileMerger::~PccFileMerger()
{
	for(dgt_sint32 i=1; i<NumRuns; i++) {
		if (Runs[i]) delete Runs[i];
	}
	if (CopyBuffer) delete CopyBuffer;
}


DgcFileStream* PccFileMerger::getRun(dgt_sint32 ith) throw(DgcExcept)
{
	// ith starts from 1
	DgcFileStream* rtn_run = 0;
	if (ith == 0) {
		rtn_run = this; // the first run should be the self.
	} else {
		if (BinaryFlag) {
			// limited run
#ifndef WIN32
			rtn_run = new PccRunStream(FileName,O_RDWR,0644,(ith-1)*RunSize);
#else
			rtn_run = new PccRunStream(FileName,O_RDWR|_O_BINARY,0644,(ith-1)*RunSize);
#endif
			ATHROWnR(DgcError(SPOS,"open[%s] failed",FileName),0);
		} else {
			// unlimited run needs an independent run file
			dgt_sint32 len = dg_strlen(FileName) + 65;
			dgt_schar* run_file_name = new dgt_schar[len];
			sprintf(run_file_name,"%s.run%d",FileName,ith);
#ifndef WIN32
			rtn_run = new PccRunStream(run_file_name,O_CREAT|O_TRUNC|O_RDWR,0644);
#else
			rtn_run = new PccRunStream(run_file_name,O_CREAT|O_TRUNC|O_RDWR|_O_BINARY,0644);
#endif
			delete run_file_name;
			ATHROWnR(DgcError(SPOS,"open failed"),0);
		}
	}
	Runs[NumRuns++] = rtn_run;
	return rtn_run;
}


dgt_sint32 PccFileMerger::mergeRuns() throw(DgcExcept)
{
	if (BinaryFlag) return 0;
	for(dgt_sint32 i=1; i<NumRuns; i++) {
		Runs[i]->seek(0,SEEK_SET);
		dgt_sint32 rbytes = 0;
		while((rbytes=Runs[i]->recvData(CopyBuffer,COPY_BUF_SIZE)) > 0) {
			if ((rbytes=sendData(CopyBuffer,rbytes)) < 0) {
				ATHROWnR(DgcError(SPOS,"sendData[%s] or sendData failed",FileName),-1);
				break;
			}
		}
		ATHROWnR(DgcError(SPOS,"recvData[%s] failed",((PccRunStream*)Runs[i])->fileName()),-1);

		if (unlink(((PccRunStream*)Runs[i])->fileName())) {
			if (CryptorFactory.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"mergeRuns:unlink[%s] failed:%s\n",
				((PccRunStream*)Runs[i])->fileName(),strerror(errno));
		}
	}
	return 0;
}


dgt_void PccFileMerger::removeRunFiles()
{
	for(dgt_sint32 i=1; i<NumRuns; i++) {
		if (unlink(((PccRunStream*)Runs[i])->fileName())) {
			if (CryptorFactory.traceLevel() > 10) DgcWorker::PLOG.tprintf(0,"removeRunFiles:unlink[%s] failed:%s\n",
				((PccRunStream*)Runs[i])->fileName(),strerror(errno));
		}
	}
}
