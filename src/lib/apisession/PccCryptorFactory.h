#ifndef PCC_CRYPTOR_FACTORY_H
#define PCC_CRYPTOR_FACTORY_H

#include "PcaApiSessionPool.h"
#include "PccSearchEngineFactory.h"

class PccCryptor : public DgcObject {
   private:
   protected:
    PcaApiSession* Session;
    PccKeyMap& KeyMap;

   public:
    PccCryptor(PcaApiSession* session, PccKeyMap& key_map)
        : Session(session), KeyMap(key_map) {}
    virtual ~PccCryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) = 0;
};

class PccLocalCryptor : public PccCryptor {
   private:
   protected:
    dgt_sint32 HeaderFlag;

   public:
    PccLocalCryptor(PcaApiSession* session, PccKeyMap& key_map,
                    dgt_sint32 header_flag = 0)
        : PccCryptor(session, key_map) {
        HeaderFlag = header_flag;
    }
    virtual ~PccLocalCryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) = 0;
};

static const dgt_schar* PPE_TAG = "<P%02d:%03d>";

class PccPatternEncryptor : public PccLocalCryptor {
   private:
    dgt_schar EncTag[PPE_TAG_LEN + 1];

   protected:
   public:
    PccPatternEncryptor(PcaApiSession* session, PccKeyMap& key_map)
        : PccLocalCryptor(session, key_map) {}
    virtual ~PccPatternEncryptor() {}

    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        unsigned char* cebp =
            crypt_buf->DstDataPtr;  // the current encrypting buffer pointer
        PccSegment* seg;
        dgt_uint32 dst_buf_len = crypt_buf->DstLength;
        crypt_buf->DstLength = 0;
        crypt_buf->SegList->rewind();

        while ((seg = crypt_buf->SegList->next())) {
            unsigned char* sp = crypt_buf->SrcDataPtr + seg->sOffset();
            if (seg->type() == PccSegment::SEG_T_PTTN) {
                // pattern segment should be encrypted
                dgt_sint32 rtn;
                dgt_uint32 dst_len = dst_buf_len - crypt_buf->DstLength;
                if ((rtn = Session->encrypt(KeyMap.encName(seg->colNo()), sp,
                                            seg->length(), cebp, &dst_len)) <
                    0) {
#if 1
                    return rtn;
#else
                    DgcWorker::PLOG.tprintf(0, "encrypt failed[%d]\n", rtn);
                    memcpy(cebp, sp, seg->length());
                    cebp += seg->length();
                    crypt_buf->DstLength += seg->length();
#endif
                } else {
                    cebp += dst_len;
                    crypt_buf->DstLength += dst_len;
                    sprintf(EncTag, PPE_TAG, seg->colNo(), dst_len);
                    memcpy(cebp, EncTag, PPE_TAG_LEN);
                    cebp += PPE_TAG_LEN;
                    crypt_buf->DstLength += PPE_TAG_LEN;
                }
            } else {
                // text segment
                memcpy(cebp, sp, seg->length());
                cebp += seg->length();
                crypt_buf->DstLength += seg->length();
            }
        }
        return crypt_buf->DstLength;
    }
};

class PccPatternDecryptor : public PccLocalCryptor {
   private:
    dgt_uint16 colNo(const dgt_uint8* tag) {
        return (*(tag + 2) - 48) * 10 + (*(tag + 3) - 48);
    }
    dgt_uint16 encLen(const dgt_uint8* tag) {
        return (*(tag + 5) - 48) * 100 + (*(tag + 6) - 48) * 10 +
               (*(tag + 7) - 48);
    }

   protected:
   public:
    PccPatternDecryptor(PcaApiSession* session, PccKeyMap& key_map)
        : PccLocalCryptor(session, key_map) {}
    virtual ~PccPatternDecryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        unsigned char* cdbp =
            crypt_buf->DstDataPtr;  // the current encrypting buffer pointer
        PccSegment* seg;
        dgt_uint32 dst_buf_len = crypt_buf->DstLength;
        crypt_buf->DstLength = 0;
        crypt_buf->SegList->rewind();
        while ((seg = crypt_buf->SegList->next())) {
            unsigned char* sp = crypt_buf->SrcDataPtr + seg->sOffset();
            dgt_sint32 enc_len = 0;
            dgt_uint8* enc_tag = crypt_buf->SrcDataPtr + seg->eOffset();
            if (seg->type() == PccSegment::SEG_T_TEXT && seg->next() &&
                seg->next()->type() == PccSegment::SEG_T_PTTN &&
                (enc_len = encLen(enc_tag)) <= seg->length()) {
                // seg may have encrypted data
                dgt_uint32 dst_len = dst_buf_len - crypt_buf->DstLength;
                dgt_uint8* enc_start_pos = sp + seg->length() - enc_len;
                // copy unencypted part first
                memcpy(cdbp, sp, seg->length() - enc_len);
                cdbp += seg->length() - enc_len;
                crypt_buf->DstLength += seg->length() - enc_len;
                dgt_sint32 rtn;

                if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                    rtn = Session->decrypt_vkey(
                        KeyMap.virtualKeyID(colNo(enc_tag)), enc_start_pos,
                        enc_len, cdbp, &dst_len, PCI_VKEY_TARGET_TYPE_FILE,
                        (dgt_schar*)KeyMap.hostName(),
                        (dgt_schar*)KeyMap.osUser(),
                        (dgt_schar*)KeyMap.inputFileNamePtr());
                } else {
                    rtn = Session->decrypt(KeyMap.encName(colNo(enc_tag)),
                                           enc_start_pos, enc_len, cdbp,
                                           &dst_len);
                }
                if (rtn < 0) {
#if 1
                    return rtn;
#else
                    DgcWorker::PLOG.tprintf(0, "decrypt failed[%d]\n", rtn);
                    memcpy(cdbp, enc_start_pos, enc_len);
                    cdbp += enc_len;
                    crypt_buf->DstLength += enc_len;
#endif
                } else {
                    cdbp += dst_len;
                    crypt_buf->DstLength += dst_len;
                    crypt_buf->SegList->next();  // pass the encrypting tag
                }
            } else {
                // text segment
                memcpy(cdbp, sp, seg->length());
                cdbp += seg->length();
                crypt_buf->DstLength += seg->length();
            }
        }
        return crypt_buf->DstLength;
    }
};

class PccFormatEncryptor : public PccLocalCryptor {
   private:
   protected:
   public:
    PccFormatEncryptor(PcaApiSession* session, PccKeyMap& key_map)
        : PccLocalCryptor(session, key_map) {}
    virtual ~PccFormatEncryptor() {}

    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        unsigned char* cebp =
            crypt_buf->DstDataPtr;  // the current encrypting buffer pointer
        dgt_uint32 dst_buf_len = crypt_buf->DstLength;
        crypt_buf->DstLength = 0;
        crypt_buf->SegList->rewind();
        PccSegment* seg;
        while ((seg = crypt_buf->SegList->next())) {
            unsigned char* sp = crypt_buf->SrcDataPtr + seg->sOffset();
            if (seg->type() == PccSegment::SEG_T_PTTN ||
                seg->type() == PccSegment::SEG_T_PTTN_NULL) {
                // pattern segment should be encrypted
                dgt_sint32 rtn;
                dgt_uint32 dst_len = dst_buf_len - crypt_buf->DstLength;
                if ((seg->type() == PccSegment::SEG_T_PTTN) &&
                    (rtn = Session->encrypt(KeyMap.encName(seg->colNo()), sp,
                                            seg->length(), cebp, &dst_len)) <
                        0) {
#if 1
                    return rtn;
#else
                    DgcWorker::PLOG.tprintf(0, "encrypt failed[%d]\n", rtn);
                    memcpy(cebp, sp, seg->length());
                    cebp += seg->length();
                    crypt_buf->DstLength += seg->length();
#endif
                } else {
                    if (seg->type() ==
                        PccSegment::SEG_T_PTTN_NULL) {  // SEG_T_PTTN_NULL is
                                                        // space string,
                        memcpy(cebp, sp,
                               seg->length());  // copy source buffer to dst
                                                // buffer because of do not
                                                // execute encrypt function
                        dst_len = seg->length();
                    }
                    cebp += dst_len;
                    crypt_buf->DstLength += dst_len;
                    //
                    // space stuffing at the end of output
                    //
                    dgt_uint32 out_col_len;
                    if ((out_col_len = KeyMap.outColLength(seg->colNo()))) {
                        dgt_sint32 stuff_len = out_col_len - dst_len;
                        memset(cebp, ' ', abs(stuff_len));
                        cebp += stuff_len;
                        crypt_buf->DstLength += stuff_len;
                    }
                }
            } else if (seg->type() == PccSegment::SEG_T_TEXT) {
                // text segment
                memcpy(cebp, sp, seg->length());
                cebp += seg->length();
                crypt_buf->DstLength += seg->length();
            }
        }
        return crypt_buf->DstLength;
    }
};

class PccFormatDecryptor : public PccLocalCryptor {
   private:
   protected:
   public:
    PccFormatDecryptor(PcaApiSession* session, PccKeyMap& key_map)
        : PccLocalCryptor(session, key_map) {}
    virtual ~PccFormatDecryptor() {}

    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        unsigned char* cebp =
            crypt_buf->DstDataPtr;  // the current encrypting buffer pointer
        dgt_uint32 dst_buf_len = crypt_buf->DstLength;
        crypt_buf->DstLength = 0;
        crypt_buf->SegList->rewind();
        PccSegment* seg;
        while ((seg = crypt_buf->SegList->next())) {
            unsigned char* sp = crypt_buf->SrcDataPtr + seg->sOffset();
            if (seg->type() == PccSegment::SEG_T_PTTN ||
                seg->type() == PccSegment::SEG_T_PTTN_NULL) {
                // pattern segment should be encrypted
                dgt_sint32 rtn = 0;
                dgt_uint32 dst_len = dst_buf_len - crypt_buf->DstLength;
                if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY &&
                    seg->type() == PccSegment::SEG_T_PTTN) {
                    rtn = Session->decrypt_vkey(
                        KeyMap.virtualKeyID(seg->colNo()), sp, seg->length(),
                        cebp, &dst_len, PCI_VKEY_TARGET_TYPE_FILE,
                        (dgt_schar*)KeyMap.hostName(),
                        (dgt_schar*)KeyMap.osUser(),
                        (dgt_schar*)KeyMap.inputFileNamePtr());
                } else if (seg->type() == PccSegment::SEG_T_PTTN) {
                    rtn = Session->decrypt(KeyMap.encName(seg->colNo()), sp,
                                           seg->length(), cebp, &dst_len);
                }

                if (rtn < 0) {
#if 1
                    return rtn;
#else
                    DgcWorker::PLOG.tprintf(0, "decrypt failed[%d]\n", rtn);
                    memcpy(cebp, sp, seg->length());
                    cebp += seg->length();
                    crypt_buf->DstLength += seg->length();
#endif
                } else {  // success decrypt
                    if (seg->type() ==
                        PccSegment::SEG_T_PTTN_NULL) {  // SEG_T_PTTN_NULL is
                                                        // space string,
                        memcpy(cebp, sp,
                               seg->length());  // copy source buffer to dst
                                                // buffer because of do not
                                                // execute decrypt function
                        dst_len = seg->length();
                    }
                    cebp += dst_len;
                    crypt_buf->DstLength += dst_len;
                    //
                    // space stuffing at the end of output
                    //
                    dgt_uint32 out_col_len;
                    if ((out_col_len = KeyMap.outColLength(seg->colNo()))) {
                        dgt_sint32 stuff_len = out_col_len - dst_len;
                        memset(cebp, ' ', abs(stuff_len));
                        cebp += stuff_len;
                        crypt_buf->DstLength += stuff_len;
                    }
                }
            } else if (seg->type() == PccSegment::SEG_T_TEXT) {
                // text segment
                memcpy(cebp, sp, seg->length());
                cebp += seg->length();
                crypt_buf->DstLength += seg->length();
            }
        }
        return crypt_buf->DstLength;
    }
};

class PccWholeEncryptor : public PccLocalCryptor {
   private:
   protected:
   public:
    PccWholeEncryptor(PcaApiSession* session, PccKeyMap& key_map,
                      dgt_sint32 header_flag = 0)
        : PccLocalCryptor(session, key_map, header_flag) {}
    virtual ~PccWholeEncryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        dgt_sint32 rtn;
        dgt_schar* header_flag_str = 0;
        if (HeaderFlag > 0)
            header_flag_str = (dgt_schar*)"on";
        else
            header_flag_str = (dgt_schar*)"off";
        dgt_uint32 dst_len = crypt_buf->DstLength;
        if ((rtn = Session->encrypt(KeyMap.encName(1), crypt_buf->SrcDataPtr,
                                    crypt_buf->SrcLength, crypt_buf->DstDataPtr,
                                    &dst_len, header_flag_str)) < 0) {
#if 1
            return rtn;
#else
            DgcWorker::PLOG.tprintf(0, "encrypt failed[%d]\n", rtn);
            memcpy(crypt_buf->DstDataPtr, crypt_buf->SrcDataPtr,
                   crypt_buf->SrcLength);
            crypt_buf->DstLength = crypt_buf->SrcLength;
#endif
        } else {
            crypt_buf->DstLength = dst_len;
        }
        return crypt_buf->DstLength;
    }
};

class PccWholeDecryptor : public PccLocalCryptor {
   private:
   protected:
   public:
    PccWholeDecryptor(PcaApiSession* session, PccKeyMap& key_map,
                      dgt_sint32 header_flag = 0)
        : PccLocalCryptor(session, key_map, header_flag) {}
    virtual ~PccWholeDecryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        dgt_sint32 rtn;
        dgt_schar* header_flag_str = 0;
        if (HeaderFlag > 0)
            header_flag_str = (dgt_schar*)"on";
        else
            header_flag_str = (dgt_schar*)"off";
        dgt_uint32 dst_len = crypt_buf->DstLength;

        if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
            rtn = Session->decrypt_vkey(
                KeyMap.virtualKeyID(1), crypt_buf->SrcDataPtr,
                crypt_buf->SrcLength, crypt_buf->DstDataPtr, &dst_len,
                PCI_VKEY_TARGET_TYPE_FILE, (dgt_schar*)KeyMap.hostName(),
                (dgt_schar*)KeyMap.osUser(),
                (dgt_schar*)KeyMap.inputFileNamePtr());
        } else {
            rtn = Session->decrypt(KeyMap.encName(1), crypt_buf->SrcDataPtr,
                                   crypt_buf->SrcLength, crypt_buf->DstDataPtr,
                                   &dst_len, header_flag_str);
        }

        if (rtn < 0) {
#if 1
            return rtn;
#else
            DgcWorker::PLOG.tprintf(0, "decrypt failed[%d]\n", rtn);
            memcpy(crypt_buf->DstDataPtr, crypt_buf->SrcDataPtr,
                   crypt_buf->DstLength);
#endif
        } else {
            crypt_buf->DstLength = dst_len;
        }
        return crypt_buf->DstLength;
    }
};

class PccBypassEncryptor : public PccLocalCryptor {
   private:
   protected:
   public:
    PccBypassEncryptor(PcaApiSession* session, PccKeyMap& key_map)
        : PccLocalCryptor(session, key_map) {}
    virtual ~PccBypassEncryptor() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        dgt_sint32 rtn;
        crypt_buf->DstLength = crypt_buf->SrcLength;
        memcpy(crypt_buf->DstDataPtr, crypt_buf->SrcDataPtr,
               crypt_buf->SrcLength);
        return crypt_buf->DstLength;
    }
};

// added by shson 20190315 for migration
class PccWholeMigrator : public PccLocalCryptor {
   private:
    dgt_sint64 CurrentKeyId;

   protected:
   public:
    PccWholeMigrator(PcaApiSession* session, PccKeyMap& key_map,
                     dgt_sint32 header_flag = 0)
        : PccLocalCryptor(session, key_map, header_flag) {
        CurrentKeyId = 0;
    }
    virtual ~PccWholeMigrator() {}
    virtual dgt_sint32 crypt(PccCryptBuffer* crypt_buf) {
        dgt_sint32 rtn;
        dgt_schar* header_flag_str = 0;
        if (HeaderFlag > 0)
            header_flag_str = (dgt_schar*)"on";
        else
            header_flag_str = (dgt_schar*)"off";
        dgt_uint32 dst_len = crypt_buf->DstLength;
        // 1. create decrypt buffer
        dgt_uint8* decrypt_buffer = new dgt_uint8[crypt_buf->SrcLength];
        dgt_uint32 decrypt_buffer_len = crypt_buf->SrcLength;
        // 2. get CurrentKeyId
        if (CurrentKeyId == 0) {
            CurrentKeyId = (dgt_sint64)Session->getKeyId(KeyMap.encName(1));
            if (CurrentKeyId < 0) {
                delete decrypt_buffer;
                return (dgt_sint32)CurrentKeyId;
            }  // if (CurrentKeyId < 0) end
        }      // if (CurrentKeyId == 0) end
        // 3. compare CurrentKeyId and keyId of src file
        // if keyid equel , not migration target file
        if (CurrentKeyId == (dgt_sint64) * (crypt_buf->SrcDataPtr - 1)) {
            delete decrypt_buffer;
            return -920514;  // this number mean not migration target file,
                             // origin is birthday of daryu~
        }

        // 4. decryption old encrypting data
        if ((rtn = Session->decrypt(
                 KeyMap.encName(1), crypt_buf->SrcDataPtr, crypt_buf->SrcLength,
                 decrypt_buffer, &decrypt_buffer_len, header_flag_str)) < 0) {
            delete decrypt_buffer;
            return rtn;
        } else {  // decrypt success
            // 5. new encrypt decrypting data
            if ((rtn = Session->encrypt(
                     KeyMap.encName(1), decrypt_buffer, decrypt_buffer_len,
                     crypt_buf->DstDataPtr, &dst_len, header_flag_str)) <
                0) {  // encrypt failed
                delete decrypt_buffer;
                return rtn;
            }  // encrypt end
            else
                crypt_buf->DstLength = dst_len;  // encrypt success
        }                                        // migration end
        delete decrypt_buffer;
        return crypt_buf->DstLength;
    }
};

class PccCryptorFactory : public DgcObject {
   private:
    static const dgt_sint32 NUM_BUFFERS = 3;
    static const dgt_sint32 MAX_CRYPTORS = 1024;

    PccKeyMap& KeyMap;
    PccSearchEngineFactory& SearchEngineFactory;
    const dgt_schar* ProgramName;
    const dgt_schar* OsUser;
    dgt_sint32 SessionID;
    dgt_sint32 NumBuffers;
    dgt_sint32 BufferSize;
    dgt_sint32 NumThreads;
    dgt_sint32 BinaryFlag;
    dgt_sint32 HeaderFlag;
    dgt_sint32 NumCryptor;
    dgt_sint64 RunSize;
    dgt_sint64 EncZoneId;
    //
    // added by mwpark 2017.08.20
    // for kb sb requirement (bypass flag)
    //
    dgt_sint32 BypassCheck;
    dgt_sint32 BypassFlag;
    dgt_slock FactoryLock;
    PccCryptor* Cryptors[MAX_CRYPTORS];
    dgt_sint32 TraceLevel;
    dgt_sint64 KeyID;
    dgt_sint32 ManagerID;
    dgt_sint32 StreamDecBufSize;

   protected:
   public:
    static const dgt_sint32 BUFFER_SIZE = 2097152;
    PccCryptorFactory(PccKeyMap& key_map, PccSearchEngineFactory& sef,
                      const dgt_schar* pgm_name = 0, dgt_sint32 manager_id = 0);
    virtual ~PccCryptorFactory();

    inline dgt_void setProgramName(const dgt_schar* pgm_name) {
        ProgramName = pgm_name;
    };
    inline dgt_void setOsUser(const dgt_schar* os_user) { OsUser = os_user; };
    inline dgt_void setSessionID(dgt_sint32 sid) { SessionID = sid; };
    inline dgt_void setBufferSize(dgt_sint32 buf_size) {
        BufferSize = buf_size;
    };
    inline dgt_void setEncZoneId(dgt_sint64 enc_zone_id) {
        EncZoneId = enc_zone_id;
    };
    inline dgt_void setTraceLevel(dgt_sint32 trace_level) {
        TraceLevel = trace_level;
    };
    inline dgt_void setBypassFlag() { BypassFlag = 1; };
    inline dgt_void setBypassCheck(dgt_sint32 bypass_check) {
        BypassCheck = bypass_check;
    };
    inline dgt_void setHeaderFlag(dgt_sint32 header_flag) {
        HeaderFlag = header_flag;
    };
    inline dgt_void setKeyId(dgt_sint64 key_id) { KeyID = key_id; };
    inline dgt_void setStreamBufferSize(dgt_sint32 stream_dec_buf_size) {
        StreamDecBufSize = stream_dec_buf_size;
    };

    inline dgt_sint32 sessionID() { return SessionID; };
    inline dgt_sint32 cryptMode() { return SearchEngineFactory.cryptMode(); };
    inline dgt_sint32 numBuffers() { return NumBuffers; };
    inline dgt_sint32 bufferSize() { return BufferSize; };
    inline dgt_sint32 numThreads() { return NumThreads; };
    inline dgt_sint32 binaryFlag() { return BinaryFlag; };
    inline dgt_sint32 headerFlag() { return HeaderFlag; };
    inline dgt_sint64 runSize() { return RunSize; };
    inline dgt_sint64 encZoneId() { return EncZoneId; };
    inline dgt_sint32 parallelism() { return NumThreads || RunSize ? 1 : 0; };
    inline dgt_sint32 bypassCheck() { return BypassCheck; };
    inline dgt_sint32 traceLevel() { return TraceLevel; };
    inline dgt_sint64 keyId() { return KeyID; };
    inline dgt_sint32 streamDecBufSize() { return StreamDecBufSize; };

    inline dgt_sint32 bypassFlag() { return BypassFlag; };

    dgt_sint32 initialize(DgcBgrammer* dg, dgt_schar* err_string);
    PcaApiSession* getSession(dgt_schar* err_string) throw(DgcExcept);
    PccCryptor* getCryptor(dgt_schar* err_string,
                           dgt_sint32 shared_flag = 0) throw(DgcExcept);
};

#endif
