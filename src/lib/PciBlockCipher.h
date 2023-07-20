/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciBlockCipher
 *   Implementor        :       Jaehun
 *   Create Date        :       2013. 1. 15
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
2015.8.11 enhancement: add padding
********************************************************************/
#ifndef PCI_BLOCK_CIPHER_H
#define PCI_BLOCK_CIPHER_H

#include "PciCipher.h"

class PciBlockCipher : public PciCipher {
   private:
    static const dgt_uint16 MAX_BLOCK_BYTES = 128;
    static const dgt_sint32 PCI_ERR_INVALID_PADDING = -30118;
    dgt_uint8* TmpBuf1;
    dgt_uint8* TmpBuf2;
    dgt_uint8* TmpBuf3;

    virtual dgt_sint32 encryptBlock(dgt_uint8* iblock, dgt_uint8* oblock) = 0;
    virtual dgt_sint32 decryptBlock(dgt_uint8* iblock, dgt_uint8* oblock) = 0;

    inline dgt_uint8 padding(dgt_uint16 remains, dgt_uint8* ibuf,
                             dgt_uint8* pad_buf) {
        dgt_uint8 pad_char = 0;
        dgt_uint8 pad_len = 0;
        if (PadType == PAD_PKCS7) {
            pad_len = pad_char = (dgt_uint8)BlockBytes;
            if (remains) pad_len = pad_char = (dgt_uint8)(BlockBytes - remains);
        } else if (remains)
            pad_len = (dgt_uint8)(BlockBytes - remains);
        if (pad_len) {
            memset(pad_buf, pad_char, BlockBytes);
            memcpy(pad_buf, ibuf, remains);
        }
        return pad_len;
    }

    inline dgt_sint32 encryptECB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
        dgt_uint32 cbytes;
        for (cbytes = 0; (cbytes + BlockBytes) <= (dgt_uint32)len;
             cbytes += BlockBytes) {
            memcpy(TmpBuf2, ibuf, BlockBytes);
            if (encryptBlock(TmpBuf2, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        *olen = cbytes;
        if (padding(len % BlockBytes, ibuf, TmpBuf1)) {
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            *olen += BlockBytes;
        }
        return 0;
    };

    inline dgt_sint32 decryptECB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
        for (dgt_sint32 i = 0; i < len; i += BlockBytes) {
            if (decryptBlock(ibuf, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        if (PadType == PAD_PKCS7) {
            if (*(obuf - 1) > BlockBytes) return PCI_ERR_INVALID_PADDING;
            *olen = len - *(obuf - 1);
        }
        return 0;
    };

    inline dgt_sint32 encryptCBC(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        dgt_uint32 cbytes;
        for (cbytes = 0; (cbytes + BlockBytes) <= (dgt_uint32)len;
             cbytes += BlockBytes) {
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(TmpBuf1 + j) ^= *(ibuf + j);
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            memcpy(TmpBuf1, obuf, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        *olen = cbytes;
        if (padding(len % BlockBytes, ibuf, TmpBuf2)) {
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(TmpBuf1 + j) ^= *(TmpBuf2 + j);
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            *olen += BlockBytes;
        }
        return 0;
    };

    inline dgt_sint32 decryptCBC(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_sint32 i = 0; i < len; i += BlockBytes) {
            if (decryptBlock(ibuf, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(TmpBuf1 + j);
            memcpy(TmpBuf1, ibuf, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        if (PadType == PAD_PKCS7) {
            if (*(obuf - 1) > BlockBytes) return PCI_ERR_INVALID_PADDING;
            *olen = len - *(obuf - 1);
        }
        return 0;
    };

    inline dgt_sint32 encryptCBC0(dgt_uint8* ibuf, dgt_sint32 len,
                                  dgt_uint8* obuf, dgt_uint32* olen) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        dgt_uint32 cbytes;
        for (cbytes = 0; (cbytes + BlockBytes) <= (dgt_uint32)len;
             cbytes += BlockBytes) {
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(TmpBuf2 + j) = *(TmpBuf1 + j) ^ *(ibuf + j);
            if (encryptBlock(TmpBuf2, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        *olen = cbytes;
        if (padding(len % BlockBytes, ibuf, TmpBuf2)) {
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(TmpBuf2 + j) ^= *(TmpBuf1 + j);
            if (encryptBlock(TmpBuf2, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            *olen += BlockBytes;
        }
        return 0;
    };

    inline dgt_sint32 decryptCBC0(dgt_uint8* ibuf, dgt_sint32 len,
                                  dgt_uint8* obuf, dgt_uint32* olen) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_sint32 i = 0; i < len; i += BlockBytes) {
            if (decryptBlock(ibuf, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(TmpBuf1 + j);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        return 0;
    };

    inline dgt_sint32 encryptCFB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_uint32 i = 0; (i + BlockBytes) <= (dgt_uint32)len;
             i += BlockBytes) {
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(ibuf + j);
            memcpy(TmpBuf1, obuf, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        dgt_sint32 remains = len % BlockBytes;
        if (remains) {
            if (encryptBlock(TmpBuf1, TmpBuf2)) return -1;
            for (dgt_uint16 j = 0; j < remains; j++)
                *(obuf + j) = *(TmpBuf2 + j) ^ *(ibuf + j);
        }
        return 0;
    };

    inline dgt_sint32 decryptCFB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_uint32 i = 0; (i + BlockBytes) <= (dgt_uint32)len;
             i += BlockBytes) {
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(ibuf + j);
            memcpy(TmpBuf1, ibuf, BlockBytes);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        dgt_sint32 remains = len % BlockBytes;
        if (remains) {
            if (encryptBlock(TmpBuf1, TmpBuf2)) return -1;
            for (dgt_uint16 j = 0; j < remains; j++)
                *(obuf + j) = *(TmpBuf2 + j) ^ *(ibuf + j);
        }
        return 0;
    };

    inline dgt_sint32 encryptOFB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_uint32 i = 0; (i + BlockBytes) <= (dgt_uint32)len;
             i += BlockBytes) {
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            memcpy(TmpBuf1, obuf, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(ibuf + j);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        dgt_sint32 remains = len % BlockBytes;
        if (remains) {
            if (encryptBlock(TmpBuf1, TmpBuf2)) return -1;
            for (dgt_uint16 j = 0; j < remains; j++)
                *(obuf + j) = *(TmpBuf2 + j) ^ *(ibuf + j);
        }
        return 0;
    };

    inline dgt_sint32 decryptOFB(dgt_uint8* ibuf, dgt_sint32 len,
                                 dgt_uint8* obuf) {
        if (IV == 0)
            memset(TmpBuf1, 0, BlockBytes);
        else
            memcpy(TmpBuf1, IV, BlockBytes);
        for (dgt_uint32 i = 0; (i + BlockBytes) <= (dgt_uint32)len;
             i += BlockBytes) {
            if (encryptBlock(TmpBuf1, TmpBuf3)) return -1;
            memcpy(obuf, TmpBuf3, BlockBytes);
            memcpy(TmpBuf1, obuf, BlockBytes);
            for (dgt_uint16 j = 0; j < BlockBytes; j++)
                *(obuf + j) ^= *(ibuf + j);
            ibuf += BlockBytes;
            obuf += BlockBytes;
        }
        dgt_sint32 remains = len % BlockBytes;
        if (remains) {
            if ((encryptBlock(TmpBuf1, TmpBuf2))) return -1;
            for (dgt_uint16 j = 0; j < remains; j++)
                *(obuf + j) = *(TmpBuf2 + j) ^ *(ibuf + j);
        }
        return 0;
    };

   protected:
    static const dgt_uint8 KEY_SET_NON = 0;
    static const dgt_uint8 KEY_SET_ENC = 1;
    static const dgt_uint8 KEY_SET_DEC = 2;

   public:
    PciBlockCipher() {
        TmpBuf1 = new dgt_uint8[MAX_BLOCK_BYTES];
        TmpBuf2 = new dgt_uint8[MAX_BLOCK_BYTES];
        TmpBuf3 = new dgt_uint8[MAX_BLOCK_BYTES];
    }

    virtual ~PciBlockCipher() {
        delete TmpBuf1;
        delete TmpBuf2;
        delete TmpBuf3;
    }

    inline dgt_sint32 decrypt(dgt_uint8* ibuf, dgt_uint32 len, dgt_uint8* obuf,
                              dgt_uint32* olen) {
        *olen = len;
        if (OpMode == MODE_CBC)
            return decryptCBC(ibuf, len, obuf, olen);
        else if (OpMode == MODE_CBC0)
            return decryptCBC0(ibuf, len, obuf, olen);
        else if (OpMode == MODE_CFB)
            return decryptCFB(ibuf, len, obuf);
        else if (OpMode == MODE_OFB)
            return decryptOFB(ibuf, len, obuf);
        return decryptECB(ibuf, len, obuf, olen);
    }

    virtual dgt_sint32 encrypt(dgt_uint8* ibuf, dgt_uint32 len, dgt_uint8* obuf,
                               dgt_uint32* olen) {
        *olen = len;
        if (OpMode == MODE_CBC)
            return encryptCBC(ibuf, len, obuf, olen);
        else if (OpMode == MODE_CBC0)
            return encryptCBC0(ibuf, len, obuf, olen);
        else if (OpMode == MODE_CFB)
            return encryptCFB(ibuf, len, obuf);
        else if (OpMode == MODE_OFB)
            return encryptOFB(ibuf, len, obuf);
        return encryptECB(ibuf, len, obuf, olen);
    }
};

#endif
