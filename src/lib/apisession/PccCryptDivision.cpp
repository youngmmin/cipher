/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccCryptDivision
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

#include "PccCryptDivision.h"

PccCryptDivision::PccCryptDivision(PccSearchEngineFactory& sef,PccCryptorFactory& cf,PccHeaderManager& hm)
	: SearchEngineFactory(sef),CryptorFactory(cf),HeaderManager(hm),LastErrCode(0),OutBufLen(0),NumPttns(0),InFileSize(0),OutFileSize(0),IsSkip(0),DetectData(0)
{
}


PccCryptDivision::~PccCryptDivision()
{
}


dgt_sint32 PccCryptDivision::crypt(const dgt_schar* in_file,const dgt_schar* out_file, dgt_uint8 force_target_write, dgt_schar* err_string)
{
	LastErrCode = 0;
	DgcExcept* e = 0;
	if (CryptorFactory.parallelism() == 0) {
		//
		// single mode, single processing
		//
#ifndef WIN32
		DgcFileStream in(in_file,O_RDWR);
#else
		DgcFileStream in(in_file,O_RDWR|_O_BINARY);
#endif

		if ((e=EXCEPTnC)) {
			LastErrCode = PFC_DVS_ERR_CODE_OPEN_IN_FILE_FAILED;
			sprintf(err_string,"in_file[%s] open failed",in_file);
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}
			InFileSize=in.fileSize();
		if (!InFileSize) {
#if 1
			LastErrCode = PFC_DVS_ERR_CODE_ZERO_FILE_SIZE;
			sprintf(err_string,"in_file[%s] size is zero",in_file);
			DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
#else
			dgt_sint32 file_flag = 0;
			if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY;
			else file_flag = O_CREAT|O_EXCL|O_WRONLY;
			DgcFileStream out(out_file,file_flag,0664);
#endif
			

			return LastErrCode;
		}
		dgt_sint32 file_flag = 0;
#ifndef WIN32
		if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY;
		else file_flag = O_CREAT|O_EXCL|O_WRONLY;
#else
		if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY|_O_BINARY;
		else file_flag = O_CREAT|O_EXCL|O_WRONLY|_O_BINARY;
#endif
		//added by shson 2019.06.20 for stream encrypt
#ifndef WIN32
		if (HeaderManager.headerFlag() == 3) file_flag = O_CREAT|O_RDWR;
#else
		if (HeaderManager.headerFlag() == 3) file_flag = O_CREAT|O_RDWR|_O_BINARY;
#endif
		DgcFileStream out(out_file,file_flag,0664);
		if ((e=EXCEPTnC)) {
#ifndef WIN32
			if (e->errCode() == EEXIST) {
#else
			if (e->errCode() == ERROR_FILE_EXISTS) {
#endif
				LastErrCode = PFC_DVS_ERR_CODE_OUT_FILE_ALREADY_EXIST;
				sprintf(err_string,"out_file[%s] already exist",out_file);
			} else {
				LastErrCode = PFC_DVS_ERR_CODE_OPEN_OUT_FILE_FAILED;
#ifndef WIN32
				sprintf(err_string,"out_file[%s] open failed : err_code[%d]",out_file,e->errCode());
#else
				sprintf(err_string,"out_file[%s] open failed : err_code[%d:%d]",out_file,e->errCode(),GetLastError());
#endif
			}
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}
		OutFileSize = out.fileSize();
		dgt_sint32 rtn = 0;
		dgt_sint32 file_indicator = 0;
		dgt_sint32 new_stream_file_flag = 0; //if first stream encryption, value 1
		dgt_sint64 old_in_file_size = 0;
		if (HeaderManager.headerFlag() == 3 && out.fileSize() == 0) new_stream_file_flag = 1;
		dgt_header_info out_header_info;
		memset(&out_header_info, 0, sizeof(out_header_info));
		//17.06.22 add shson
		//this source is encrypting header check and write
		//if headerflag=on and encrypt mode, write header
		//if headerflag=off and encrypt mode, don'y write header
		//role of header is two kinds
		//one. prevent duplication encrypting
		//two. when decrypting, check integrity
		//if you when encrypting set header_flag=on, must give same header_flag when decrypting
		//read and check header from in file
		if (HeaderManager.headerFlag()) {
			rtn = HeaderManager.checkHeader(&in);
			//rtn 1 : encrypting file
			//    0 : text file
			//   -1 : broken file
			if (rtn == PFC_HEADER_FILE_TYPE_ENCRYPT && CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT) {
				//in this, occur error for duplication encrypting
				if (CryptorFactory.bypassCheck()) {
					CryptorFactory.setBypassFlag();
#if 0
					//2017.12.15 added by shson
					//for nhlife
					//issue that more time bypass_check logic than cp
					//so only read and direct wirte when bypass_check = on, replace memcpy
		dgt_uint8* read_buffer = 0;				
		dgt_sint32 read_buffer_size = 0;
		dgt_sint32 nbytes = 0;
		if (InFileSize < 2097152) read_buffer_size = InFileSize;
		else read_buffer_size = 2097152;
		
		read_buffer = new dgt_uint8[read_buffer_size];
		while((nbytes=in.recvData(read_buffer,read_buffer_size)) > 0)
			nbytes=out.sendData(read_buffer,nbytes);
				if ((e=EXCEPTnC)) {
					LastErrCode = -70000;
					sprintf(err_string,"recvData or sendData failed[%d]",nbytes);
					DgcWorker::PLOG.tprintf(0,*e,"bypass failed : [%s]\n",err_string);
					delete e;
					return LastErrCode;
				}
		OutFileSize = out.fileSize();
		return 0;
#endif
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_ALREADY_ENCRYPTED; //error for duplication encrypt
					sprintf(err_string,"integrity check faild : already encrypted file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else if (rtn == PFC_HEADER_FILE_TYPE_ORIGINAL && CryptorFactory.cryptMode() == PFC_CRYPT_MODE_DECRYPT) {
				//in this, occur error for duplication decrypting
				if (CryptorFactory.bypassCheck()) {
					CryptorFactory.setBypassFlag();
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_ORIGINAL_FILE;
					sprintf(err_string,"integrity check faild : original text file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else if (rtn < 0) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_CHECK_HEADER_FAILED;
					sprintf(err_string,"checkHeader[%s] failed",in_file);
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
					return LastErrCode;
				} else {
					//in this, file be damaged integrity
					LastErrCode = PFC_DVS_ERR_CODE_BROKEN_FILE;
					sprintf(err_string,"integrity check faild : broken file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			}

			//added by shson 2019.06.20 for stream encrypt
			//header check and compare in_file size for judge target file
			if (HeaderManager.headerFlag() == 3 && CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT && new_stream_file_flag == 0) { //case already exist out file
				file_indicator = out.seek(0,SEEK_SET);
				if(file_indicator != 0)
					ATHROWnR(DgcError(SPOS,"out.seek failed [%d]",file_indicator),-1);
				rtn = HeaderManager.checkHeader(&out, &out_header_info);
				if (rtn == PFC_HEADER_FILE_TYPE_ORIGINAL) {
					LastErrCode = PFC_DVS_ERR_CODE_ORIGINAL_FILE;
					sprintf(err_string,"integrity check faild : original text file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				} else if (rtn < 0) {
					if ((e=EXCEPTnC)) {
						LastErrCode = PFC_DVS_ERR_CODE_CHECK_HEADER_FAILED;
						sprintf(err_string,"checkHeader[%s] failed",out_file);
						DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
						delete e;
						return LastErrCode;
					} else {
						//in this, file be damaged integrity
						LastErrCode = PFC_DVS_ERR_CODE_BROKEN_FILE;
						sprintf(err_string,"integrity check faild : broken file");
						DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
						return LastErrCode;
					}
				} //else if (rtn < 0) end
				if (HeaderManager.inFileSize() == InFileSize) return 0; //unchanged file, this not target
				old_in_file_size = HeaderManager.inFileSize();
			} // if (HeaderManager.headerFlag() == 3 && out.fileSize() > 0) end




			//header version 3,4 encryption
			if (CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT && (HeaderManager.headerFlag() == 3 || HeaderManager.headerFlag() == 4)) CryptorFactory.setBufferSize(1024);
			//write header to out file
			if (!CryptorFactory.bypassFlag() && CryptorFactory.cryptMode()) {
				if (HeaderManager.writeHeader(&out, 
					HeaderManager.headerFlag(), 
					CryptorFactory.cryptMode() == PFC_CRYPT_MODE_MIGRATION ? HeaderManager.inFileSize() : InFileSize, 
					CryptorFactory.cryptMode() == PFC_CRYPT_MODE_MIGRATION ? HeaderManager.bufferSize() : CryptorFactory.bufferSize(),
					CryptorFactory.encZoneId(),
					CryptorFactory.keyId()) < 0) {
					LastErrCode = PFC_DVS_ERR_CODE_WRITE_HEADER_FAILED;
					sprintf(err_string,"writeHeader[%s] failed\n",out_file);
					if ((e=EXCEPTnC)) {
						DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
						delete e;
					} else {
						DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					}
					return LastErrCode;
				}
			}
		}
		if (EXCEPT) {
			e = EXCEPTnC;
			LastErrCode = PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED;
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : unkwon exception occured\n");
			delete e;
			return LastErrCode;
		}
		
		if (HeaderManager.headerFlag() == 3 && CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT && new_stream_file_flag == 0) {
			// for appending, infile offset moving at infilesize offset of header
			file_indicator = in.seek(out_header_info.in_file_size,SEEK_SET);
			if(file_indicator != 0)
				ATHROWnR(DgcError(SPOS,"in.seek failed [%d]",file_indicator),-1);
			// for appending, outfile offset moving at end offset
			file_indicator = out.seek(0,SEEK_END);
			if(file_indicator != 0)
				ATHROWnR(DgcError(SPOS,"out.seek failed [%d]",file_indicator),-1);
		}

		//converting buffer size for stream encryption and kernel encryption
		if ((HeaderManager.headerVersion() == 3 || HeaderManager.headerVersion() == 4) && !CryptorFactory.cryptMode()) {
			CryptorFactory.setBufferSize(CryptorFactory.streamDecBufSize());
		}

		PccCryptUnit crypt_unit(&in,&out,SearchEngineFactory,CryptorFactory,HeaderManager, &LastErrCode);
		if ((HeaderManager.headerVersion() == 3 && CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT)) crypt_unit.setInFileSize(InFileSize);
		if ((rtn=crypt_unit.crypt()) < 0) {
			sprintf(err_string,"crypt_unit crypt failed : rtn[%d]",rtn);
			LastErrCode = rtn;
			if ((e=EXCEPTnC)) {
				DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
				delete e;
			}
			return LastErrCode;
		}
		//commitHeader function write hash value, encrypting data of filesize through SHA256
		if(!CryptorFactory.bypassFlag()&& HeaderManager.headerFlag() && CryptorFactory.cryptMode() ) {
			if((rtn = HeaderManager.commitHeader()) < 0) {
				LastErrCode = PFC_DVS_ERR_CODE_COMMIT_HEADER_FAILED;
				sprintf(err_string,"commitHeader failed[%d]",rtn);
				if ((e=EXCEPTnC)) {
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
				}
				return LastErrCode;
			}
		}
		OutFileSize = out.fileSize();
		//added by shson 2019.07.01 for stream encryption
		//converting to null from source data
		if (CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT && HeaderManager.headerFlag() == 3) { //convert original data
			file_indicator = in.seek(old_in_file_size,SEEK_SET);
			if(file_indicator != 0)
				ATHROWnR(DgcError(SPOS,"in.seek failed [%d]",file_indicator),-1);

			dgt_sint64 remain_bytes = InFileSize - old_in_file_size;
			dgt_sint32 nbytes = 0;
			dgt_sint32 delete_size = 0;
			dgt_uint8* convert_buffer = new dgt_uint8[CryptorFactory.bufferSize()];
			memset(convert_buffer, 0, CryptorFactory.bufferSize());

			while(remain_bytes > 0) {
				if(remain_bytes > CryptorFactory.bufferSize()) {
					delete_size = CryptorFactory.bufferSize();
				} else {
					delete_size = remain_bytes;
				}

				if ((nbytes = in.sendData(convert_buffer,delete_size) < 0)) {
					if (convert_buffer) delete convert_buffer;
					convert_buffer = 0;
					ATHROWnR(DgcError(SPOS,"sendData failed: convert_buffer insert failed"),-1);
				}
				remain_bytes-=delete_size;
			} //while(remain_bytes > 0) end


			if (convert_buffer) delete convert_buffer;
			convert_buffer = 0;
		} // if (CryptorFactory.cryptMode() == PFC_CRYPT_MODE_ENCRYPT && HeaderManager.headerFlag() == 3) end


#if 0
                // deleted 2017.12.07 by shson, ihjin
                // do not using this logic

		// added 2017.09.11 by shson
		// for IBK requirement
		// when on the option that Double_enc_check,decrypt_Fail_Src_rtn in petra_cipher_api.conf
		// if header_flag = on, for ignore option Double_enc_check,decrypt_Fail_Src_rtn
		// compare InFileSize and OutFileSize
		if (HeaderManager.headerFlag()) {	//when header_flag = on
			if (CryptorFactory.cryptMode()) { //when encrypting
				if (InFileSize == OutFileSize - HeaderManager.headerSize()) { //compare file size
					LastErrCode = PFC_DVS_ERR_CODE_INCOMPLETE_ENCRYPTION;
					sprintf(err_string,"incompletely encrypted, change off option that double_enc_check, decrypt_fail_src_rtn ");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else { //when decrypting
				if (InFileSize == OutFileSize + HeaderManager.headerSize()) {
					LastErrCode = PFC_DVS_ERR_CODE_INCOMPLETE_DECRYPTION;
					sprintf(err_string,"incompletely decrypted, change off option that double_enc_check, decrypt_fail_src_rtn");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} // else end
		} //if (HeaderManager.headerFlag()) {  end
#endif
		OutBufLen = crypt_unit.outBufLen();
	} else {
		//
		// multiple mode, parallel processing
		//
		PccFileSpliter	file_spliter(in_file,SearchEngineFactory.getEngine(),CryptorFactory);
		if ((e=EXCEPTnC)) {
			LastErrCode = PFC_DVS_ERR_CODE_OPEN_FSPLITER_FAILED;
			sprintf(err_string,"file_spliter[%s] open failed",in_file);
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}
		InFileSize = file_spliter.fileSize();
		if (!InFileSize) {
#if 1
			LastErrCode = PFC_DVS_ERR_CODE_ZERO_FILE_SIZE;
			sprintf(err_string,"in_file[%s] size is zero",in_file);
			DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
#else
			dgt_sint32 file_flag = 0;
			if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY;
			else file_flag = O_CREAT|O_EXCL|O_WRONLY;
			DgcFileStream out(out_file,file_flag,0664);
#endif
			return LastErrCode;
		}
		dgt_sint32 file_flag = 0;
#ifndef WIN32
		if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY;
		else file_flag = O_CREAT|O_EXCL|O_WRONLY;
#else
		if (force_target_write) file_flag = O_CREAT|O_TRUNC|O_WRONLY|_O_BINARY;
		else file_flag = O_CREAT|O_EXCL|O_WRONLY|_O_BINARY;
#endif
		PccFileMerger	file_merger(CryptorFactory,out_file,file_spliter.runSize(),file_flag);
		if ((e=EXCEPTnC)) {
			if (e->errCode() == EEXIST) {
				LastErrCode = PFC_DVS_ERR_CODE_OUT_FILE_ALREADY_EXIST;
				sprintf(err_string,"out_file[%s] already exist",out_file);
			} else {
				LastErrCode = PFC_DVS_ERR_CODE_OPEN_FMERGER_FAILED;
				sprintf(err_string,"file_merger[%s] open failed",out_file);
			}
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}

		//17.06.22 add shson fstat
		//this source is encrypting header check and write
		//if headerflag=on and encrypt mode, write header
		//if headerflag=off and encrypt mode, don'y write header
		//role of header is two kinds
		//one. prevent duplication encrypting
		//two. when decrypting, check integrity
		//if you when encrypting set header_flag=on, must give same header_flag when decrypting
		dgt_sint32 rtn=0;
		if (HeaderManager.headerFlag()) {
			DgcFileStream* in;
			if ((in = file_spliter.getRun()) == 0) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_GET_RUN_FAILED;
					sprintf(err_string,"getRun failed");
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
					return LastErrCode;
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_FSTREAM_NOT_ALLOCATED;
					sprintf(err_string,"file_streams are not allocated : in[%p]\n",in);
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			}
			//read and check header from in file
			rtn = HeaderManager.checkHeader(in);
			//rtn 1 : encrypting file
			//    0 : text file
			//   -1 : broken file
			if (rtn == 1 && CryptorFactory.cryptMode()) {
				//in this, occur error for duplication encrypting
				if (CryptorFactory.bypassCheck()) {
					CryptorFactory.setBypassFlag();
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_ALREADY_ENCRYPTED;
					sprintf(err_string,"integrity check faild : already encrypt file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else if (rtn == 0 && !CryptorFactory.cryptMode()) {
				//in this, occur error for duplication encrypting
				if (CryptorFactory.bypassCheck()) {
					CryptorFactory.setBypassFlag();
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_ORIGINAL_FILE;
					sprintf(err_string,"integrity check faild : original text file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else if (rtn < 0) {
				//in this, file be damaged integrity
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_CHECK_HEADER_FAILED;
					sprintf(err_string,"checkHeader[%s] failed",in_file);
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
					return LastErrCode;
				} else {
					//in this, file be damaged integrity
					LastErrCode = PFC_DVS_ERR_CODE_BROKEN_FILE;
					sprintf(err_string,"integrity check faild : broken file");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			}
			file_spliter.resetCurrOffset();
			//header version 4 encryption
			if (CryptorFactory.cryptMode() && HeaderManager.headerFlag() == 4) CryptorFactory.setBufferSize(1024);
			//write header to out file
			if (!CryptorFactory.bypassFlag() && CryptorFactory.cryptMode()) {
				if (HeaderManager.writeHeader(&file_merger, HeaderManager.headerFlag(), CryptorFactory.cryptMode() == PFC_CRYPT_MODE_MIGRATION ? HeaderManager.inFileSize() : InFileSize, CryptorFactory.bufferSize(), CryptorFactory.encZoneId(),CryptorFactory.keyId()) < 0) {
					LastErrCode = PFC_DVS_ERR_CODE_WRITE_HEADER_FAILED;
					sprintf(err_string,"writeHeader[%s] failed\n",out_file);
					if ((e=EXCEPTnC)) {
						DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
						delete e;
					} else {
						DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					}
					return LastErrCode;
				}
			}
		} //if( HeaderManager.headerFlag() ) end

		dgt_uint32 num_runs = 0;
#ifndef WIN32
		num_runs = file_spliter.numRuns();
		PccCryptUnit*	crypt_units[num_runs];
#else
		num_runs = 1;
		PccCryptUnit*	crypt_units[1]; // for windows but deleted by jhpark 2017.11.06
#endif
		//converting buffer size for stream encryption and kernel encryption
		if ((HeaderManager.headerVersion() == 3 || HeaderManager.headerVersion() == 4) && !CryptorFactory.cryptMode()) {
			CryptorFactory.setBufferSize(CryptorFactory.streamDecBufSize());
		}
		//
		// create crypt units
		//
		for(dgt_uint32 i=0; i<num_runs; i++) {
			DgcFileStream*	in = 0;
			DgcFileStream*	out = 0;
			if ((in=file_spliter.getRun()) == 0 || (out=file_merger.getRun(i)) == 0) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_GET_RUN_FAILED;
					sprintf(err_string,"getRun failed");
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_FSTREAM_NOT_ALLOCATED;
					sprintf(err_string,"file_streams are not allocated : in[%p] out[%p]\n",in,out);
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
				}
				for(dgt_uint32 j=0; j<i; j++) delete crypt_units[j];
				return LastErrCode;
			}
			crypt_units[i] = new PccCryptUnit(in,out,SearchEngineFactory,CryptorFactory,HeaderManager,&LastErrCode);
		}

		//
		// start crypt units
		//
		for(dgt_uint32 i=0; i<num_runs; i++) {
			if (crypt_units[i]->start(1)) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_START_CRYPT_UNIT_FALED;
					sprintf(err_string,"%d-th units start failed",i+1);
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
				}
				for(dgt_uint32 j=0; j<i; j++) crypt_units[i]->stop();
			}
		}
		if (LastErrCode == 0 && num_runs) {
			//
			// wait for units to end
			//
			dgt_sint32 alive_units = 0;
			do {
				napAtick();
				alive_units = 0;
				for(dgt_uint32 i=0; i<num_runs; i++) {
					if (crypt_units[i]->isAlive() && crypt_units[i]->status() != DGC_WS_CREAT) alive_units++;
				}
			} while (alive_units);
		}
		if (LastErrCode == 0) {
			// merge output runs
			if (file_merger.mergeRuns()) {
				if ((e=EXCEPTnC)) {
					LastErrCode = -66025;
					sprintf(err_string,"mergeRuns failed");
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
				}
			}
		}
		if (LastErrCode) file_merger.removeRunFiles();
		for(dgt_uint32 i=0; i<num_runs; i++) {
			if (OutBufLen == 0) OutBufLen = crypt_units[i]->outBufLen();
			delete crypt_units[i];
		}

        //commitHeader function write hash value, encrypting data of filesize through SHA256
        if(!CryptorFactory.bypassFlag() && HeaderManager.headerFlag() && CryptorFactory.cryptMode()) {
            if((rtn = HeaderManager.commitHeader()) < 0) {
				LastErrCode = PFC_DVS_ERR_CODE_COMMIT_HEADER_FAILED;
				sprintf(err_string,"commitHeader failed[%d]",rtn);
				if ((e=EXCEPTnC)) {
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : [%s]\n",err_string);
					delete e;
				}
				return LastErrCode;
            }
        }
		OutFileSize = file_merger.fileSize();

#if 0
		// deleted 2017.12.07 by shson, ihjin
		// do not using this logic

		// added 2017.09.11 by shson
		// for IBK requirement
		// when on the option that Double_enc_check,decrypt_Fail_Src_rtn in petra_cipher_api.conf
		// if header_flag = on, for ignore option Double_enc_check,decrypt_Fail_Src_rtn
		// compare InFileSize and OutFileSize
		if (HeaderManager.headerFlag()) {	//when header_flag = on
			if (CryptorFactory.cryptMode()) { //when encrypting
				if (InFileSize == OutFileSize - HeaderManager.headerSize()) { //compare file size
					LastErrCode = PFC_DVS_ERR_CODE_INCOMPLETE_ENCRYPTION;
					sprintf(err_string,"incompletely encrypted, change off option that double_enc_check, decrypt_fail_src_rtn ");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} else { //when decrypting
				if (InFileSize == OutFileSize + HeaderManager.headerSize()) {
					LastErrCode = PFC_DVS_ERR_CODE_INCOMPLETE_DECRYPTION;
					sprintf(err_string,"incompletely decrypted, change off option that double_enc_check, decrypt_fail_src_rtn");
					DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
					return LastErrCode;
				}
			} // else end
		} //if (HeaderManager.headerFlag()) {  end
#endif

		if (EXCEPT) {
			e = EXCEPTnC;
			if (!LastErrCode) LastErrCode = PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED;
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division crypt failed : unkwon exception occured\n");
			delete e;
			return LastErrCode;
		}
	} //multiple processing else end
		if (CryptorFactory.cryptMode() == PFC_CRYPT_MODE_MIGRATION && InFileSize != OutFileSize) {
			if (!LastErrCode) LastErrCode = -910214;
			sprintf(err_string,"incompletely migration, something is wrong!!");
			DgcWorker::PLOG.tprintf(0,"crypt_division crypt failed : [%s]\n",err_string);
			return LastErrCode;
		}
	return LastErrCode;
} //crypt end

dgt_sint32 PccCryptDivision::detect(const dgt_schar* in_file,DgcMemRows* detect_data,dgt_schar* err_string)
{
	LastErrCode = 0;
	DgcExcept *e = 0;
	
	DetectData = detect_data;
	DetectData->reset();

	if (CryptorFactory.parallelism() == 0) {
		// 
		// single mode, single processing
		//
		
		// 1. create in_file stream
#ifndef WIN32
		DgcFileStream in(in_file,O_RDONLY);
#else
		DgcFileStream in(in_file,O_RDONLY|_O_BINARY);
#endif
		if ((e=EXCEPTnC)) {
			LastErrCode = PFC_DVS_ERR_CODE_OPEN_IN_FILE_FAILED;
			sprintf(err_string,"in_file[%s] open failed",in_file);
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}
		InFileSize=in.fileSize();
		if (!InFileSize) {
			LastErrCode = PFC_DVS_ERR_CODE_ZERO_FILE_SIZE;
			sprintf(err_string,"in_file[%s] size is zero",in_file);
			DgcWorker::PLOG.tprintf(0,"crypt_division detect failed : [%s]\n",err_string);
			return LastErrCode;
		}
		
		dgt_sint32 rtn = 0;
		// 2. create detect unit
		PccDetectUnit detect_unit(&in,SearchEngineFactory,CryptorFactory,&LastErrCode);
		if ((rtn=detect_unit.detect()) < 0) {
			if (!LastErrCode) LastErrCode = PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED;
			sprintf(err_string,"detect_unit.detect failed : rtn[%d]",rtn);
			if ((e=EXCEPTnC)) {
				DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : [%s]\n",err_string);
				delete e;
			}
			return LastErrCode;
		}
		NumPttns = detect_unit.numPttns();
		IsSkip = detect_unit.isSkip();
		
		DgcMemRows* rtn_rows = detect_unit.detectData();
		rtn_rows->rewind();
		DetectData->rewind();
		while (rtn_rows->next()) {
			DetectData->add();
			DetectData->next();
			memcpy(DetectData->data(), rtn_rows->data(), rtn_rows->rowSize());
		}
		DetectData->rewind();
	} else {
		// 
		// muliple mode, parallel processing
		//
		
		//1 . create in_file stream
		PccFileSpliter	file_spliter(in_file,SearchEngineFactory.getEngine(),CryptorFactory);
		if ((e=EXCEPTnC)) {
			LastErrCode = PFC_DVS_ERR_CODE_OPEN_FSPLITER_FAILED;
			sprintf(err_string,"file_spliter[%s] open failed",in_file);
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : [%s]\n",err_string);
			delete e;
			return LastErrCode;
		}
		InFileSize = file_spliter.fileSize();
		if (!InFileSize) {
			LastErrCode = PFC_DVS_ERR_CODE_ZERO_FILE_SIZE;
			sprintf(err_string,"in_file[%s] size is zero",in_file);
			DgcWorker::PLOG.tprintf(0,"crypt_division detect failed : [%s]\n",err_string);
			return LastErrCode;
		}
		
		// 2. create detect units
		dgt_uint32 num_runs = 0;
#ifndef WIN32
		num_runs = file_spliter.numRuns();
		PccDetectUnit*	detect_units[num_runs];
#else
		num_runs = 1;
		PccDetectUnit*	detect_units[1]; // for windows but deleted by jhpark 2017.11.06
#endif
		for(dgt_uint32 i=0; i<num_runs; i++) {
			DgcFileStream*	in = 0;
			DgcFileStream*	out = 0;
			if ((in=file_spliter.getRun()) == 0) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_GET_RUN_FAILED;
					sprintf(err_string,"getRun failed");
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : [%s]\n",err_string);
					delete e;
				} else {
					LastErrCode = PFC_DVS_ERR_CODE_FSTREAM_NOT_ALLOCATED;
					sprintf(err_string,"file_streams are not allocated : in[%p] out[%p]\n",in,out);
					DgcWorker::PLOG.tprintf(0,"crypt_division detect failed : [%s]\n",err_string);
				}
				for(dgt_uint32 j=0; j<i; j++) delete detect_units[j];
				return LastErrCode;
			}
			detect_units[i] = new PccDetectUnit(in,SearchEngineFactory,CryptorFactory,&LastErrCode);
		}

		//
		// start crypt units
		//
		for(dgt_uint32 i=0; i<num_runs; i++) {
			if (detect_units[i]->start(1)) {
				if ((e=EXCEPTnC)) {
					LastErrCode = PFC_DVS_ERR_CODE_START_CRYPT_UNIT_FALED;
					sprintf(err_string,"%d-th units start failed",i+1);
					DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : [%s]\n",err_string);
					delete e;
				}
				for(dgt_uint32 j=0; j<i; j++) detect_units[i]->stop();
			}
		}
		if (LastErrCode == 0 && num_runs) {
			//
			// wait for units to end
			//
			dgt_sint32 alive_units = 0;
			do {
				napAtick();
				alive_units = 0;
				for(dgt_uint32 i=0; i<num_runs; i++) {
					if (detect_units[i]->isAlive() && detect_units[i]->status() != DGC_WS_CREAT) alive_units++;
				}
			} while (alive_units);
		}
		DetectData->rewind();
		for(dgt_uint32 i=0; i<num_runs; i++) {
			NumPttns += detect_units[i]->numPttns();
			if (!IsSkip) IsSkip = detect_units[i]->isSkip();

			DgcMemRows* rtn_rows = detect_units[i]->detectData();
			rtn_rows->rewind();
			while (rtn_rows->next()) {
				DetectData->add();
				DetectData->next();
				memcpy(DetectData->data(), rtn_rows->data(), rtn_rows->rowSize());
			}
			delete detect_units[i];
		}
		DetectData->rewind();
		if (EXCEPT) {
			e = EXCEPTnC;
			if (!LastErrCode) LastErrCode = PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED;
			DgcWorker::PLOG.tprintf(0,*e,"crypt_division detect failed : unkwon exception occured\n");
			delete e;
			return LastErrCode;
		}
	} //multiple processing else end

	if (!NumPttns) LastErrCode = PFC_DVS_ERR_CODE_ZERO_FILE_SIZE;
	return LastErrCode;
} //detect end
