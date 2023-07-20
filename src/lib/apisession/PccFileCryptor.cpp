/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccFileCryptor
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

#include "PccFileCryptor.h"

PccFileCryptor::PccFileCryptor(const dgt_schar* pgm_name,
                               const dgt_schar* crypt_mode,
                               dgt_sint32 trace_level, dgt_sint32 manager_id)
    : SearchEngineFactory(KeyMap, crypt_mode),
      CryptorFactory(KeyMap, SearchEngineFactory, pgm_name, manager_id),
      HeaderManager(),
      ParamList(0),
      NumParams(0),
      InFileName(0),
      OutFileName(0),
      LogFileName(0),
      ForceTargetWrite(0),
      OutBufLen(0),
      InFileSize(0),
      OutFileSize(0),
      LastErrCode(0),
      ErrString(0),
      BypassCheck(0),
      UserLogging(0),
      PtuId(0),
      ValidationFlag(0),
      JobId(0),
      DirId(0),
      NumPttns(0),
      IsSkip(0) {
    ErrString = new dgt_schar[MAX_ERR_STRING];
    memset(ErrString, 0, MAX_ERR_STRING);
    memset(SystemName, 0, sizeof(SystemName));
    memset(SystemIp, 0, sizeof(SystemIp));
    memset(ZoneName, 0, sizeof(ZoneName));
    memset(ClientIp, 0, sizeof(ClientIp));
    CryptorFactory.setTraceLevel(trace_level);
    ManagerID = manager_id;

    DetectData = new DgcMemRows(4);
    DetectData->addAttr(DGC_SB8, 0, "start_offset");
    DetectData->addAttr(DGC_SB8, 0, "end_offset");
    DetectData->addAttr(DGC_SCHR, 1024, "expr");
    DetectData->addAttr(DGC_SCHR, 1024, "data");
    DetectData->reset();
}

PccFileCryptor::~PccFileCryptor() {
    if (ErrString) delete ErrString;
    if (ParamList) delete ParamList;
    if (DetectData) delete DetectData;
}

dgt_void PccFileCryptor::openLogStream() {
    for (; DgcWorker::PLOG.logStream() == 0;) {
        DgcFileStream* fs = new DgcFileStream(
            PcaLogger::logFilePath(), O_CREAT | O_APPEND | O_WRONLY, 0666);
        if (EXCEPT) {
            delete EXCEPTnC;
            fs = 0;
        }
        if (fs) {
            DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
            break;
        }
        fs = new DgcFileStream("/tmp/petra_cipher_api.log",
                               O_CREAT | O_APPEND | O_WRONLY, 0666);
        if (EXCEPT) {
            delete EXCEPTnC;
            fs = 0;
        }
        if (fs) {
            DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
            break;
        }
        fs = new DgcFileStream(0, 1);
        DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
        break;
    }
}

dgt_sint32 PccFileCryptor::getFileParams(DgcBgrammer* bg) {
    InFileName = bg->getValue("file.in");
    OutFileName = bg->getValue("file.out");
    DgcFileStream* fs = 0;
    if ((LogFileName = bg->getValue("file.log"))) {
        DgcFileStream* fs =
            new DgcFileStream(LogFileName, O_CREAT | O_APPEND | O_WRONLY, 0666);
        if (EXCEPT) {
            LastErrCode = PFC_FC_ERR_CODE_OPEN_LOG_FILE_FAILED;
            DgcExcept* e = EXCEPTnC;
            openLogStream();
            sprintf(ErrString, "log file open failed[%s]", LogFileName);
            DgcWorker::PLOG.tprintf(
                0, *e, "file_cryptor getFileParams failed:[%s]\n", ErrString);
            delete e;
            return LastErrCode;
        } else {
            DgcWorker::PLOG.setLog(10, DGC_TRUE, new DgcBufferStream(fs, 1));
        }
    }
    openLogStream();
    return 0;
}

dgt_sint32 PccFileCryptor::getKeyParams(DgcBgrammer* bg) {
    dgt_sint32 col_no;
    for (col_no = 1;; col_no++) {
        dgt_schar* enc_name;
        dgt_schar* col_string;
        dgt_schar node_name[128];
        sprintf(node_name, "key.%d.name", col_no);
        if ((enc_name = bg->getValue(node_name))) {
            sprintf(node_name, "key.%d.columns", col_no);
            if ((col_string = bg->getValue(node_name))) {
                KeyMap.addKeyMap(enc_name, col_string);
            } else {  // not define key columns
                LastErrCode = PFC_FC_ERR_CODE_KEY_COL_NOT_DEFINED;
                sprintf(ErrString, "not define columns in key node [col_no:%d]",
                        col_no);
                if (CryptorFactory.traceLevel() > 10)
                    if (CryptorFactory.traceLevel() > 10)
                        DgcWorker::PLOG.tprintf(
                            0, "file_cryptor getKeyParams failed:[%s]\n",
                            ErrString);
                return LastErrCode;
            }
        } else {                // not define key name
            if (col_no == 1) {  // when not exist col_no 1 is error
                LastErrCode = PFC_FC_ERR_CODE_KEY_NAME_NOT_DEFINED;
                sprintf(ErrString, "not define name in key node [col_no:%d]",
                        col_no);
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, "file_cryptor getKeyParams failed:[%s]\n",
                        ErrString);
                return LastErrCode;
            }
            break;
        }
    }  // for end

    if (KeyMap.keyType() != USE_KEY_TYPE_ENC_NAME) {
        // get virtual key
        for (col_no = 1;; col_no++) {
            dgt_schar* vkey_id_str;
            dgt_schar* col_string;
            dgt_schar node_name[128];
            sprintf(node_name, "key.%d.vkey_id", col_no);
            if ((vkey_id_str = bg->getValue(node_name))) {
                sprintf(node_name, "key.%d.columns", col_no);
                if ((col_string = bg->getValue(node_name))) {
#ifndef WIN32
                    dgt_sint64 vkey_id = dg_strtoll(vkey_id_str, 0, 10);
#else
                    dgt_sint64 vkey_id = _strtoi64(vkey_id_str, 0, 10);
#endif
                    KeyMap.addVirtualKeyMap(vkey_id, col_string);
                }
            } else
                break;
        }
    }

    if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
        KeyMap.setVKeyTargetEnv(InFileName);
    }
    // added by shson 2018.05.29
    // for using header
    dgt_schar* val = 0;
    if ((val = bg->getValue("key.zone_id"))) {
#ifndef WIN32
        dgt_sint64 enc_zone_id = dg_strtoll(val, 0, 10);
#else
        dgt_sint64 enc_zone_id = _strtoi64(val, 0, 10);
#endif
        CryptorFactory.setEncZoneId(enc_zone_id);
    }

    return 0;
}

dgt_sint32 PccFileCryptor::getDelimiterParams(DgcBgrammer* bg) {
    return SearchEngineFactory.initDelimiter(bg, ErrString);
}

dgt_sint32 PccFileCryptor::getFixedParams(DgcBgrammer* bg) {
    return SearchEngineFactory.initFixed(bg, ErrString);
}

dgt_sint32 PccFileCryptor::getRegularParams(DgcBgrammer* bg) {
    return SearchEngineFactory.initRegular(bg, ErrString);
}

dgt_sint32 PccFileCryptor::getCryptParams(DgcBgrammer* bg) {
    return CryptorFactory.initialize(bg, ErrString);
}

dgt_sint32 PccFileCryptor::getSessionParams(DgcBgrammer* bg) {
    dgt_schar* val;
    if ((val = bg->getValue("session.program_id")))
        CryptorFactory.setProgramName(val);
    return 0;
}

dgt_sint32 PccFileCryptor::getModeParams(DgcBgrammer* bg) {
    dgt_schar* val;
    if ((val = bg->getValue("mode.crypt"))) {
        // modify shson 2018.06.19 for validation mode
        // if crypt paramter equel "validation", It't just only change
        // ValidationFlag other operating be same decrypt machanism
        // ValidationFlag used for logging

        if (strlen(val) &&
            (strncasecmp(val, "validation", 10) == 0)) {  // when validation
            ValidationFlag = 1;
            val = (dgt_schar*)"decrypt";  // change decrypt mode
        }
        SearchEngineFactory.setCryptMode(val);
    }
    if ((val = bg->getValue("mode.crypt.detect")) ||
        (val = bg->getValue("mode.detect"))) {
#ifndef WIN32
        dgt_sint32 detect_mode = (dgt_sint32)dg_strtoll(val, 0, 10);
#else
        dgt_sint32 detect_mode = (dgt_sint32)_strtoi64(val, 0, 10);
#endif
        SearchEngineFactory.setDetectMode(detect_mode);
    }
    if ((val = bg->getValue("mode.header_flag"))) {
        HeaderManager.setHeaderFlag(val);
        CryptorFactory.setHeaderFlag(HeaderManager.headerFlag());
    }
    if ((val = bg->getValue("mode.bypass_check"))) {
        if (!strncasecmp(val, "on", 2)) CryptorFactory.setBypassCheck(1);
    }
    if ((val = bg->getValue("mode.overwrite_flag")) ||
        (val = bg->getValue("mode.force_target_write"))) {
        if (val && strncmp(val, "on", 2) == 0) ForceTargetWrite = 1;
    }
    if ((val = bg->getValue("mode.user_logging"))) {
        if (val && strncmp(val, "on", 2) == 0) UserLogging = 1;
    }
    return 0;
}

dgt_sint32 PccFileCryptor::importKeyInfo(DgcBgrammer* bg) {
    dgt_schar* val;
    if ((val = bg->getValue("key_info"))) {
        dgt_sint32 rtn;
        if ((rtn = PcaSessionPool::putKeyInfo(val, strlen(val), 0)) < 0) {
            LastErrCode = rtn;
            DgcExcept* e = 0;
            sprintf(ErrString, "putKeyInfo[%s] open failed", val);
            if ((e = EXCEPTnC)) {
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, *e, "file_cryptor importKeyInfo failed : [%s]\n",
                        ErrString);
                delete e;
            } else {
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, "file_cryptor importKeyInfo failed : [%s]\n",
                        ErrString);
            }
            return LastErrCode;
        }
    }
    return 0;
}

dgt_sint32 PccFileCryptor::getSystemInfo(DgcBgrammer* bg) {
    // added by shson 2017.07.02 - for logging
    dgt_schar* val;
    if ((val = bg->getValue("system_info.system_name")))
        strcat(SystemName, val);
    if ((val = bg->getValue("system_info.system_ip"))) strcat(SystemIp, val);
    if ((val = bg->getValue("system_info.zone_name"))) strcat(ZoneName, val);
    return 0;
}

dgt_sint32 PccFileCryptor::getLoggingInfo(DgcBgrammer* bg) {
    // added by shson 2018.06.18 - for user logging
    dgt_schar* val = 0;
    if ((val = bg->getValue("logging_info.ptu_id"))) {
#ifndef WIN32
        dgt_sint64 ptu_id = dg_strtoll(val, 0, 10);
#else
        dgt_sint64 ptu_id = _strtoi64(val, 0, 10);
#endif
        if (ptu_id) PtuId = ptu_id;
    }
    if ((val = bg->getValue("logging_info.client_ip"))) strcat(ClientIp, val);

    return 0;
}

dgt_sint32 PccFileCryptor::getParams(DgcBgrammer* bg) {
    dgt_sint32 rtn = 0;
    if (bg->getNode("file"))
        rtn = getFileParams(bg);
    else if (bg->getNode("key"))
        rtn = getKeyParams(bg);
    else if (bg->getNode("delimiter"))
        rtn = getDelimiterParams(bg);
    else if (bg->getNode("fixed"))
        rtn = getFixedParams(bg);
    else if (bg->getNode("regular"))
        rtn = getRegularParams(bg);
    else if (bg->getNode("parallel"))
        rtn = getCryptParams(bg);
    else if (bg->getNode("session"))
        rtn = getSessionParams(bg);
    else if (bg->getNode("mode"))
        rtn = getModeParams(bg);
    else if (bg->getNode("key_info"))
        rtn = importKeyInfo(bg);
    else if (bg->getNode("system_info"))
        rtn = getSystemInfo(bg);
    else if (bg->getNode("logging_info"))
        rtn = getLoggingInfo(bg);
    else if (bg->getNode("out_extension"))
        rtn = 0;  // not to do
    else {
        LastErrCode = PFC_FC_ERR_CODE_UNSUPPORTED_PARAM;
        sprintf(ErrString, "unsupported parameter[%s]", bg->getText());
        if (CryptorFactory.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "file_cryptor getParams failed : [%s]\n",
                                    ErrString);
        return LastErrCode;
    }
    return rtn;
}

dgt_sint32 PccFileCryptor::compileParamList(const dgt_schar* param_list) {
    // if param_list is not bgrammer format, be returned
    dgt_sint32 idx = 0;
    while (param_list[idx] != '(') {
        if (param_list[idx] == ' ') {
            idx++;
        } else {
            LastErrCode = PFC_FC_ERR_CODE_INVALID_PARAML_FORMAT;
            sprintf(ErrString, "invalid param_list format [%s] \n", param_list);
            if (CryptorFactory.traceLevel() > 10)
                DgcWorker::PLOG.tprintf(
                    0, "file_cryptor compileParamList failed : [%s]\n",
                    ErrString);
            return LastErrCode;
        }
    }

    if (ParamList) delete ParamList;
    ParamList = new DgcBgmrList(param_list, 1);
    if (EXCEPT) {
        LastErrCode = PFC_FC_ERR_CODE_BUILD_PARAML_FAILED;
        DgcExcept* e = EXCEPTnC;
        openLogStream();
        if (e) {
            sprintf(ErrString, "build param_list[%s] failed", param_list);
            if (CryptorFactory.traceLevel() > 10)
                DgcWorker::PLOG.tprintf(
                    0, *e, "file_cryptor compileParamList failed : [%s]\n",
                    ErrString);
            delete e;
        }
        return LastErrCode;
    }
    DgcBgrammer* bg = 0;
    while ((bg = ParamList->getNext())) {
        dgt_sint32 rtn = 0;
        if ((rtn = getParams(bg))) return rtn;
    }
    return 0;
}

dgt_sint32 PccFileCryptor::compileParamFile(const dgt_schar* param_file) {
    if (ParamList) delete ParamList;
    // if param_file is bgrammer format or black, be returned
    if (param_file[0] == '(' || param_file[0] == ' ') return 1;
    ParamList = new DgcBgmrList(param_file);
    if (EXCEPT) {
        LastErrCode = PFC_FC_ERR_CODE_BUILD_PARAMF_FAILED;
        DgcExcept* e = EXCEPTnC;
        openLogStream();
        if (e) {
            sprintf(ErrString, "build param_file[%s] failed", param_file);
            DgcWorker::PLOG.tprintf(
                0, *e, "file_cryptor compileParamFile failed : [%s]\n",
                ErrString);
            delete e;
        }
        return LastErrCode;
    }
    DgcBgrammer* bg = 0;
    while ((bg = ParamList->getNext())) {
        dgt_sint32 rtn = 0;
        if ((rtn = getParams(bg))) return rtn;
    }
    return 0;
}

dgt_sint32 PccFileCryptor::crypt(const dgt_schar* in_file,
                                 const dgt_schar* out_file) {
    openLogStream();
    if (in_file == 0 || (in_file && strlen(in_file) == 0)) in_file = InFileName;
    if (out_file == 0 || (out_file && strlen(out_file) == 0))
        out_file = OutFileName;
    if (in_file == 0) {
        LastErrCode = PFC_FC_ERR_CODE_IN_FILE_NOT_DEFINED;
        sprintf(ErrString, "input file is not defined");
        if (CryptorFactory.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "file_cryptor crypt failed : [%s]\n",
                                    ErrString);
        return LastErrCode;
    }

    if (out_file && strlen(out_file) && (strcmp(in_file, out_file) == 0)) {
        LastErrCode = PFC_FC_ERR_CODE_IN_FILE_OUT_FILE_SAME;
        sprintf(ErrString, "input file and out file are same");
        if (CryptorFactory.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "file_cryptor crypt failed : [%s]\n",
                                    ErrString);
        return LastErrCode;
    }

    dgt_sint32 rtn = 0;
    //
    // for logging
    //
    InFileName = in_file;
    OutFileName = out_file;

    dgt_uint8 overwrite_flag = 0;
    dgt_schar* ow_tmp_file = 0;
    if (out_file == 0 || (out_file && strlen(out_file) == 0)) {
        dgt_sint32 tmp_file_len = dg_strlen(in_file) + 10;
        overwrite_flag = 1;
        ow_tmp_file = new dgt_schar[tmp_file_len];
        sprintf(ow_tmp_file, "%s_pfc", in_file);
        out_file = OutFileName = ow_tmp_file;
    }

    for (; in_file && out_file;) {
#if 1  // added by shson 2017.6.5 for automatic calculation of the read buffer
       // size when decrypting a whole file
        // based on the read buffer size being used when encrypting,
        // which means the size of buffer in decrypting parameters should be the
        // same as the size of buffer in encrypting parameters
        //
        if (SearchEngineFactory.engineType() ==
                SearchEngineFactory.WHOLE_DECRYPTOR ||
            SearchEngineFactory.engineType() ==
                SearchEngineFactory.WHOLE_MIGRATOR) {
            PcaApiSession* session = CryptorFactory.getSession(ErrString);
            if (!session) {
                LastErrCode = PFC_FC_ERR_CODE_GET_API_SESSION_FAILED;
                sprintf(ErrString, "getSession failed");
                if (EXCEPT) {
                    DgcExcept* e = EXCEPTnC;
                    if (CryptorFactory.traceLevel() > 10)
                        DgcWorker::PLOG.tprintf(
                            0, *e, "file_cryptor crypt failed : [%s]\n",
                            ErrString);
                    delete e;
                }
                rtn = LastErrCode;
                break;
            }

            dgt_sint32 decrypt_read_buf_size = 0;
            dgt_sint32 stream_dec_buf_size = 0;
            if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                decrypt_read_buf_size = session->encryptLengthWithVirtualKey(
                    KeyMap.virtualKeyID(1), CryptorFactory.bufferSize(),
                    PCI_VKEY_CRYPT_TYPE_DEC, PCI_VKEY_TARGET_TYPE_FILE,
                    (dgt_schar*)KeyMap.hostName(), (dgt_schar*)KeyMap.osUser(),
                    (dgt_schar*)InFileName);
                if (decrypt_read_buf_size < 0) {
                    LastErrCode = decrypt_read_buf_size;
                    sprintf(ErrString,
                            "encryptLengthWithVirtualKey faild:[%d] ",
                            decrypt_read_buf_size);
                    if (CryptorFactory.traceLevel() > 10)
                        DgcWorker::PLOG.tprintf(
                            0, "file_cryptor crypt failed : [%s]\n", ErrString);
                    rtn = LastErrCode;
                    break;
                }
            } else {
                decrypt_read_buf_size = session->encryptLength(
                    KeyMap.encName(1), CryptorFactory.bufferSize());
                stream_dec_buf_size =
                    session->encryptLength(KeyMap.encName(1), 1024);
                if (decrypt_read_buf_size < 0) {
                    LastErrCode = decrypt_read_buf_size;
                    sprintf(ErrString,
                            "getEncryptLength faild:buffer_size[%d] ",
                            decrypt_read_buf_size);
                    if (CryptorFactory.traceLevel() > 10)
                        DgcWorker::PLOG.tprintf(
                            0, "file_cryptor crypt failed : [%s]\n", ErrString);
                    rtn = LastErrCode;
                    break;
                }
            }
            //			if (session->sharedFlag())
            //PcaApiSessionPool::returnApiSession(session->sid());
            CryptorFactory.setBufferSize(decrypt_read_buf_size);
            CryptorFactory.setStreamBufferSize(stream_dec_buf_size);
#if 1  // added by mwpark 2017.06.26 for massive data decrypt control
            if (KeyMap.keyType() != USE_KEY_TYPE_VIRTUAL_KEY) {
                dgt_sint64 ctl_bytes =
                    session->maskingDecCount(KeyMap.encName(1));
                if (ctl_bytes) {
                    DgcFileStream ctl_file(in_file, O_RDONLY);
                    DgcExcept* e = 0;
                    if ((e = EXCEPTnC)) {
                        LastErrCode = PFC_FC_ERR_CODE_OPEN_IN_FILE_FAILED;
                        sprintf(ErrString,
                                "in_file[%s] open failed for massive data "
                                "decrypt control",
                                in_file);
                        if (CryptorFactory.traceLevel() > 10)
                            DgcWorker::PLOG.tprintf(
                                0, *e, "file_cryptor crypt failed : [%s]\n",
                                ErrString);
                        delete e;
                        rtn = LastErrCode;
                        break;
                    }
                    if (ctl_file.fileSize() > ctl_bytes) {
                        LastErrCode = PFC_FC_ERR_CODE_NO_PRIV_BY_SIZE_CTRL;
                        sprintf(
                            ErrString,
                            "no privilege by size control : ctl_bytes[%lld]",
                            ctl_bytes);
                        if (CryptorFactory.traceLevel() > 10)
                            DgcWorker::PLOG.tprintf(
                                0, "file_cryptor crypt failed : [%s]\n",
                                ErrString);
                        rtn = LastErrCode;
                        break;
                    }
                }
            }
#endif
        }
#endif
        //
        // added by mwpark 2017.12.06
        // for getting PcaKeySvrSessionPool
        //
        PcaApiSession* session = CryptorFactory.getSession(ErrString);
        if (!session) {
            LastErrCode = PFC_FC_ERR_CODE_GET_API_SESSION_FAILED;
            sprintf(ErrString, "getSession failed");
            if (EXCEPT) {
                DgcExcept* e = EXCEPTnC;
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, *e, "file_cryptor crypt failed : [%s]\n", ErrString);
                delete e;
            }
            rtn = LastErrCode;
            break;
        } else {
            // header flag check
            // if opmode, not use header
            PcaKeySvrSessionPool* keySvrSessionPool =
                session->keySvrSessionPool();
            if (keySvrSessionPool) {
                if (keySvrSessionPool->opMode() > 0) {
                    HeaderManager.setHeaderFlag("off");
                }
            }
#if 1
            // get key_id for V2 header
            if (SearchEngineFactory.engineType() ==
                    SearchEngineFactory.WHOLE_DECRYPTOR ||
                SearchEngineFactory.engineType() ==
                    SearchEngineFactory.WHOLE_ENCRYPTOR ||
                SearchEngineFactory.engineType() ==
                    SearchEngineFactory.WHOLE_MIGRATOR) {
                dgt_sint64 key_id = session->getKeyId(KeyMap.encName(1));
                if (key_id < 0) {
                    LastErrCode = key_id;
                    sprintf(ErrString, "getKeyId faild:Error Code[%lld] ",
                            key_id);
                    if (CryptorFactory.traceLevel() > 10)
                        DgcWorker::PLOG.tprintf(
                            0, "file_cryptor crypt failed : [%s]\n", ErrString);
                    rtn = LastErrCode;
                    break;
                }
                CryptorFactory.setKeyId(key_id);
            }  // if (SearchEngineFactory.engineType() ==
               // SearchEngineFactory.WHOLE_DECRYPTOR) end
#endif
        }
        PccCryptDivision cd(SearchEngineFactory, CryptorFactory, HeaderManager);
        if ((rtn = cd.crypt(in_file, out_file, ForceTargetWrite, ErrString)) <
            0) {
            LastErrCode = rtn;
            DgcWorker::PLOG.tprintf(
                0, "crypt failed[%d] : in_file [%s] out_file [%s]", LastErrCode,
                in_file, out_file);
            break;
        }
        OutBufLen = cd.outBufLen();
        InFileSize = cd.inFileSize();
        OutFileSize = cd.outFileSize();
        break;
    }  // for end
    if (rtn < 0) {
        // crypting is failed
        if (HeaderManager.headerFlag() != 3) {
            if (rtn == PFC_DVS_ERR_CODE_OUT_FILE_ALREADY_EXIST ||
                rtn == PFC_DVS_ERR_CODE_OPEN_OUT_FILE_FAILED) {
                // this is out_file open error
                // don't remove out_file
            } else {
                if (unlink(out_file) < 0)
                    DgcWorker::PLOG.tprintf(0, "unlink[%s] failed:%s\n",
                                            in_file, strerror(errno));
            }  // else end
        }      // if (HeaderManager.headerFlag() != 3) end
    } else if (overwrite_flag) {
        // overwrite file
        // remove the source file and rename the output file
        if (unlink(in_file) < 0) {
            if (CryptorFactory.traceLevel() > 10)
                DgcWorker::PLOG.tprintf(0, "unlink[%s] failed:%s\n", in_file,
                                        strerror(errno));
        } else {
            if (rename(out_file, in_file) < 0) {  // rename the output file
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, "rename old[%s] new[%s] failed:%s\n", out_file,
                        in_file, strerror(errno));
            }
        }
    }
    if (ow_tmp_file) delete ow_tmp_file;
    return rtn;
}

dgt_sint32 PccFileCryptor::crypt(dgt_sint32 sid, const dgt_schar* parameters,
                                 const dgt_schar* in_file,
                                 const dgt_schar* out_file,
                                 dgt_sint32 agent_mode,
                                 const dgt_schar* enc_col_name,
                                 const dgt_schar* header_flag,
                                 dgt_sint32 buffer_size) {
    dgt_sint32 rtn;
    // added by mwpark 18.10.01
    if (agent_mode == 0 || agent_mode == 3) {
        if (sid >= 0) setSessionID(sid);
    }
#if 0 
	if ((rtn=compileParamFile(parameters))) { //if rtn values 1, execute compileParamList()
		if (rtn == 1 && (rtn=compileParamList(parameters))) {
	        if (rtn != 0) {
				LastErrCode = rtn;
				return rtn;
			}
		}
	}
#endif
    if (agent_mode > 1 && enc_col_name && *enc_col_name) {
        dgt_schar col_string[16];
        memset(col_string, 0, 16);
        sprintf(col_string, "%s", "1");
        KeyMap.addKeyMap(enc_col_name, col_string);
        CryptorFactory.initialize(0, ErrString);
        SearchEngineFactory.setCryptMode(parameters);
        if (header_flag && *header_flag) {
            HeaderManager.setHeaderFlag(header_flag);
        } else {
            HeaderManager.setHeaderFlag("V2on");
        }
        if (buffer_size) CryptorFactory.setBufferSize(buffer_size);
        CryptorFactory.setHeaderFlag(HeaderManager.headerFlag());
    } else {
        rtn = compileParamFile(parameters);  // case parameters is file
        if (rtn == 1)  // if rtn values 1, execute compileParamList()
            rtn = compileParamList(
                parameters);  // case parameters is bgrammer string
        if (rtn != 0) {       // when bgrammer parsing error
            LastErrCode = rtn;
            return rtn;
        }
    }

    dgt_uint32 start_time = dgtime((dgt_uint32*)&start_time);
    rtn = crypt(in_file, out_file);
    LastErrCode = rtn;
    dgt_uint32 end_time = dgtime((dgt_uint32*)&end_time);
    if (UserLogging)
        userCryptLogging(start_time, end_time);
    else
        cryptLogging(start_time, end_time);
    return rtn;
}

dgt_sint32 PccFileCryptor::detect(const dgt_schar* parameters,
                                  const dgt_schar* in_file) {
    openLogStream();
    Parameter = parameters;
    if (in_file == 0 || (in_file && strlen(in_file) == 0)) in_file = InFileName;
    if (in_file == 0) {
        LastErrCode = PFC_FC_ERR_CODE_IN_FILE_NOT_DEFINED;
        sprintf(ErrString, "input file is not defined");
        if (CryptorFactory.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "file_cryptor detect failed : [%s]\n",
                                    ErrString);
        return LastErrCode;
    }

    dgt_sint32 rtn = 0;
    //
    // for loging
    //
    InFileName = in_file;

    //
    // To improve detection speed, check file type and skip the detection
    //
    dgt_sint32 file_type = 0;
    if (SearchEngineFactory.detectMode()) {
        if (!file_type) {
            file_type = PFC_DETECT_MODE_TEXT;
#ifndef WIN32
            DgcFileStream in(in_file, O_RDONLY);
#else
            DgcFileStream in(in_file, O_RDONL | _O_BINARY);
#endif
            dgt_uint8 buf[32] = {0};
            dgt_sint32 nbytes = 0;
            if ((nbytes = in.recvData(buf, sizeof(buf))) < 0)
                ATHROWnR(DgcError(SPOS, "src_file[%s] read failed\n", in_file),
                         -1);
            for (dgt_sint32 i = 0; i < 32 && i < nbytes; i++) {
                // 1. If the control character(ex. 0x00 ~ 0x1F) exists in
                // 32bytes, judge it is a binary file
                // 2. The newline character(ex. 0x0A, 0x0D, 0x1E) is used on new
                // lines so they are excluded from judgment.
                // 3. The tab character(ex. 0x09) is excluded
                if (buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != 0x09 &&
                    buf[i] != 0x0A && buf[i] != 0x0D && buf[i] != 0x1E) {
                    file_type = PFC_DETECT_MODE_BINARY;
                    break;
                }
            }
        }
        if (!(SearchEngineFactory.detectMode() & file_type)) {
            LastErrCode = PFC_FC_ERR_CODE_UNSUPPORTED_FILE_FORMAT;
            sprintf(ErrString,
                    "the file[%s]'s type does not match the detect mode",
                    in_file);
            return LastErrCode;
        }
    }
    for (; in_file;) {
        //
        // added byte mwpark 2017.12.06 for getting PcaKeySvrSessionPool
        //
        PcaApiSession* session = CryptorFactory.getSession(ErrString);
        if (!session) {
            LastErrCode = PFC_FC_ERR_CODE_GET_API_SESSION_FAILED;
            sprintf(ErrString, "getSession failed");
            if (EXCEPT) {
                DgcExcept* e = EXCEPTnC;
                if (CryptorFactory.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(
                        0, *e, "file_cryptor detect failed : [%s]\n",
                        ErrString);
                delete e;
            }
            rtn = LastErrCode;
            break;
        }

        PccCryptDivision cd(SearchEngineFactory, CryptorFactory, HeaderManager);
        if ((rtn = cd.detect(in_file, DetectData, ErrString)) < 0) {
            LastErrCode = rtn;
            break;
        }
        NumPttns = cd.numPttns();
        IsSkip = cd.isSkip();
        InFileSize = cd.inFileSize();
        break;
    }  // for end
    return rtn;
}

dgt_sint32 PccFileCryptor::detect(dgt_sint32 sid, const dgt_schar* parameters,
                                  const dgt_schar* in_file,
                                  dgt_sint64 max_detection, dgt_sint64 job_id,
                                  dgt_sint64 dir_id) {
    if (job_id) JobId = job_id;
    if (dir_id) DirId = dir_id;

    dgt_schar params[1024] = {0};

    dgt_sint32 rtn;
    if (sid >= 0) setSessionID(sid);
    if (max_detection) setMaxDetection(max_detection);

    //
    // compile and read parameters
    //
    rtn = compileParamFile(parameters);  // case parameters is file
    if (rtn == 1) {  // if rtn values 1, execute compileParamList()
        rtn =
            compileParamList(parameters);  // case parameters is bgrammer string
        memcpy(params, parameters, strlen(parameters));
    } else {
        // for saving the used parameters
#ifndef WIN32
        DgcFileStream param_file(parameters, O_RDONLY);
#else
        DgcFileStream param_file(parameters, O_RDONLY | _O_BINARY);
#endif
        dgt_sint32 file_size = param_file.fileSize();
        if (file_size > 1024) {
            rtn = PFC_FC_ERR_CODE_INVALID_PARAML_FORMAT;
        } else {
            dgt_sint32 nbytes = 0;
            if ((nbytes = param_file.recvData((dgt_uint8*)params, file_size)) <
                0)
                rtn = nbytes;
        }
        param_file.closeStream();
    }
    if (rtn != 0) {  // when bgrammer parsing error
        LastErrCode = rtn;
        return rtn;
    }

    //
    // detecting
    //
    dgt_uint32 start_time = dgtime((dgt_uint32*)&start_time);
    rtn = detect(params, in_file);
    LastErrCode = rtn;
    dgt_uint32 end_time = dgtime((dgt_uint32*)&end_time);
    detectLogging(start_time, end_time);
    return rtn;
}

dgt_void PccFileCryptor::cryptLogging(dgt_uint32 start_time,
                                      dgt_uint32 end_time) {
    PcaApiSession* session = CryptorFactory.getSession(ErrString);
    if (session == 0) {
        delete EXCEPTnC;
        return;
    }
    if (strlen(SystemName) == 0) {
        PcaKeySvrSessionPool* keySvrSessionPool = session->keySvrSessionPool();
        if (keySvrSessionPool) {
            strncpy(SystemName, keySvrSessionPool->systemName(), 64);
            strncpy(SystemIp, keySvrSessionPool->systemIp(), 64);
        }
    }
    pc_type_file_request_in file_request;
    memset(&file_request, 0, sizeof(pc_type_file_request_in));
    file_request.enc_start_date = start_time;
    file_request.enc_end_date = end_time;
    if (LastErrCode == -30301) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "no encrypt privilege");
    } else if (LastErrCode == -30401) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "no decrypt privilege");
    } else if (LastErrCode == -30118) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "not encrypted file");
    }

    dgt_sint64 virtual_key_id = 0;
    dgt_schar enc_col_name[130];
    memset(enc_col_name, 0, 130);
    dgt_sint32 i = 0;

    for (i = 1; i < KeyMap.maxCols(); i++) {
        if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
            if ((virtual_key_id = KeyMap.virtualKeyID(i)) > 0) {
                break;
            }
        } else {
            if (strlen(KeyMap.encName(i)) > 0) {
                memcpy(enc_col_name, KeyMap.encName(i),
                       strlen(KeyMap.encName(i)));
                break;
            }
        }
    }
    if (SearchEngineFactory.cryptMode()) {
        // encrypt
        dgt_sint32 i = 0;
        if (session->isEncryptAudit(enc_col_name)) {
            memcpy(file_request.file_name, InFileName, strlen(InFileName));
            memcpy(file_request.system_name, SystemName, strlen(SystemName));
            memcpy(file_request.system_ip, SystemIp, strlen(SystemIp));
            memcpy(file_request.zone_name, ZoneName, strlen(ZoneName));
            if (SearchEngineFactory.engineType() ==
                PccSearchEngineFactory::FORMAT_ENCRYPTOR) {
                sprintf(file_request.enc_type, "SAM");
            } else if (SearchEngineFactory.engineType() ==
                       PccSearchEngineFactory::PATTERN_ENCRYPTOR) {
                sprintf(file_request.enc_type, "PATTERN");
            } else {
                sprintf(file_request.enc_type, "FULL");
            }
            file_request.mode = 1;
#if 0
			sprintf(file_request.key_name,KeyMap.encName(1));
#else
            sprintf(file_request.key_name, enc_col_name);
#endif
            file_request.file_size = InFileSize;
            file_request.processed_byte = OutBufLen;
            if (strlen(ErrString))
                memcpy(file_request.err_msg, ErrString, 255);
            else
                sprintf(file_request.err_msg, "success");
            session->logFileRequest(&file_request);
        }
    } else {
        // decrypt
        dgt_uint8 is_audit_flag = 0;
        if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
            is_audit_flag = 1;
        } else {
            is_audit_flag = session->isDecryptAudit(enc_col_name);
        }

        if (is_audit_flag) {
            memcpy(file_request.file_name, InFileName, strlen(InFileName));
            memcpy(file_request.system_name, SystemName, strlen(SystemName));
            memcpy(file_request.system_ip, SystemIp, strlen(SystemIp));
            memcpy(file_request.zone_name, ZoneName, strlen(ZoneName));
            if (SearchEngineFactory.engineType() ==
                PccSearchEngineFactory::FORMAT_DECRYPTOR) {
                sprintf(file_request.enc_type, "SAM");
            } else if (SearchEngineFactory.engineType() ==
                       PccSearchEngineFactory::PATTERN_DECRYPTOR) {
                sprintf(file_request.enc_type, "PATTERN");
            } else {
                sprintf(file_request.enc_type, "FULL");
            }
            if (ValidationFlag)
                file_request.mode = 3;
            else
                file_request.mode = 2;
            if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                sprintf(file_request.key_name, "vkey_id[%lld]", virtual_key_id);
            } else {
#if 0
				sprintf(file_request.key_name,KeyMap.encName(1));
#else
                sprintf(file_request.key_name, enc_col_name);
#endif
            }
            file_request.file_size = InFileSize;
            file_request.processed_byte = OutBufLen;
            if (strlen(ErrString))
                memcpy(file_request.err_msg, ErrString, 255);
            else
                sprintf(file_request.err_msg, "success");
            session->logFileRequest(&file_request);
        }
    }
}

dgt_void PccFileCryptor::userCryptLogging(dgt_uint32 start_time,
                                          dgt_uint32 end_time) {
    PcaApiSession* session = CryptorFactory.getSession(ErrString);
    if (session == 0) {
        delete EXCEPTnC;
        return;
    }
    if (strlen(SystemName) == 0) {
        PcaKeySvrSessionPool* keySvrSessionPool = session->keySvrSessionPool();
        if (keySvrSessionPool) {
            strncpy(SystemName, keySvrSessionPool->systemName(), 64);
            strncpy(SystemIp, keySvrSessionPool->systemIp(), 64);
        }
    }
    pc_type_user_file_request_in file_request;
    memset(&file_request, 0, sizeof(pc_type_user_file_request_in));
    file_request.enc_start_date = start_time;
    file_request.enc_end_date = end_time;
    if (LastErrCode == -30301) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "no encrypt privilege");
    } else if (LastErrCode == -30401) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "no decrypt privilege");
    } else if (LastErrCode == -30118) {
        memset(ErrString, 0, MAX_ERR_STRING);
        sprintf(ErrString, "not encrypted file");
    }

    dgt_sint64 virtual_key_id = 0;
    dgt_schar enc_col_name[130];
    memset(enc_col_name, 0, 130);
    dgt_sint32 i = 0;

    for (i = 1; i < KeyMap.maxCols(); i++) {
        if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
            if ((virtual_key_id = KeyMap.virtualKeyID(i)) > 0) {
                break;
            }
        } else {
            if (strlen(KeyMap.encName(i)) > 0) {
                memcpy(enc_col_name, KeyMap.encName(i),
                       strlen(KeyMap.encName(i)));
                break;
            }
        }
    }
    if (SearchEngineFactory.cryptMode()) {
        // encrypt
        dgt_sint32 i = 0;
        if (session->isEncryptAudit(enc_col_name)) {
            file_request.ptu_id = PtuId;
            memcpy(file_request.client_ip, ClientIp, strlen(ClientIp));
            memcpy(file_request.file_name, InFileName, strlen(InFileName));
            memcpy(file_request.system_name, SystemName, strlen(SystemName));
            memcpy(file_request.system_ip, SystemIp, strlen(SystemIp));
            memcpy(file_request.zone_name, ZoneName, strlen(ZoneName));
            if (SearchEngineFactory.engineType() ==
                PccSearchEngineFactory::FORMAT_ENCRYPTOR) {
                sprintf(file_request.enc_type, "SAM");
            } else if (SearchEngineFactory.engineType() ==
                       PccSearchEngineFactory::PATTERN_ENCRYPTOR) {
                sprintf(file_request.enc_type, "PATTERN");
            } else {
                sprintf(file_request.enc_type, "FULL");
            }
            file_request.mode = 1;
#if 0
			sprintf(file_request.key_name,KeyMap.encName(1));
#else
            sprintf(file_request.key_name, enc_col_name);
#endif
            file_request.file_size = InFileSize;
            file_request.processed_byte = OutBufLen;
            if (strlen(ErrString))
                memcpy(file_request.err_msg, ErrString, 255);
            else
                sprintf(file_request.err_msg, "success");
            session->logUserFileRequest(&file_request);
        }
    } else {
        // decrypt
        dgt_uint8 is_audit_flag = 0;
        if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
            is_audit_flag = 1;
        } else {
            is_audit_flag = session->isDecryptAudit(enc_col_name);
        }

        if (is_audit_flag) {
            file_request.ptu_id = PtuId;
            memcpy(file_request.client_ip, ClientIp, strlen(ClientIp));
            memcpy(file_request.file_name, InFileName, strlen(InFileName));
            memcpy(file_request.system_name, SystemName, strlen(SystemName));
            memcpy(file_request.system_ip, SystemIp, strlen(SystemIp));
            memcpy(file_request.zone_name, ZoneName, strlen(ZoneName));
            if (SearchEngineFactory.engineType() ==
                PccSearchEngineFactory::FORMAT_DECRYPTOR) {
                sprintf(file_request.enc_type, "SAM");
            } else if (SearchEngineFactory.engineType() ==
                       PccSearchEngineFactory::PATTERN_DECRYPTOR) {
                sprintf(file_request.enc_type, "PATTERN");
            } else {
                sprintf(file_request.enc_type, "FULL");
            }
            if (ValidationFlag)
                file_request.mode = 3;
            else
                file_request.mode = 2;
            if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                sprintf(file_request.key_name, "vkey_id[%lld]", virtual_key_id);
            } else {
#if 0
				sprintf(file_request.key_name,KeyMap.encName(1));
#else
                sprintf(file_request.key_name, enc_col_name);
#endif
            }
            file_request.file_size = InFileSize;
            file_request.processed_byte = OutBufLen;
            if (strlen(ErrString))
                memcpy(file_request.err_msg, ErrString, 255);
            else
                sprintf(file_request.err_msg, "success");
            session->logUserFileRequest(&file_request);
        }
    }
}

dgt_void PccFileCryptor::detectLogging(dgt_uint32 start_time,
                                       dgt_uint32 end_time) {
    PcaApiSession* session = CryptorFactory.getSession(ErrString);
    if (session == 0) {
        delete EXCEPTnC;
        return;
    }
    if (strlen(SystemName) == 0) {
        PcaKeySvrSessionPool* keySvrSessionPool = session->keySvrSessionPool();
        if (keySvrSessionPool) {
            strncpy(SystemName, keySvrSessionPool->systemName(), 64);
            strncpy(SystemIp, keySvrSessionPool->systemIp(), 64);
        }
    }
#ifndef WIN32
    struct stat fstat;
    if (stat(InFileName, &fstat) < 0) return;
#else
    struct _stati64 fstat;
    if (_stati64(InFileName, &fstat) < 0) return;
#endif

    // log file
    pc_type_detect_file_request_in file_request;
    memset(&file_request, 0, sizeof(pc_type_detect_file_request_in));
    file_request.job_id = JobId;
    file_request.dir_id = DirId;
    file_request.file_id = fstat.st_ino;
    memcpy(file_request.system_name, SystemName, strlen(SystemName));
    memcpy(file_request.system_ip, SystemIp, strlen(SystemIp));
    memcpy(file_request.file_name, InFileName, strlen(InFileName));
    file_request.file_size = fstat.st_size;
    file_request.file_mtime = fstat.st_mtime;
    file_request.start_date = start_time;
    file_request.end_date = end_time;
    file_request.pttn_num = NumPttns;
    file_request.is_skipped = IsSkip;
    memcpy(file_request.parameter, Parameter, strlen(Parameter));
    if (strlen(ErrString))
        memcpy(file_request.err_msg, ErrString, 255);
    else
        sprintf(file_request.err_msg, "success");

    session->logDetectFileRequest(&file_request, DetectData);
}
