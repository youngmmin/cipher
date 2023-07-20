/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciCipher
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 10
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_CIPHER_H
#define PCI_CIPHER_H

#include "DgcExcept.h"

#if 1  // added by chchung 2018.8.27 for adding a PCI exception
static const dgt_uint16 DGC_EXT_PCI = 0x0099;
class DgcPciExcept : public DgcExcept {
   private:
   protected:
   public:
    DgcPciExcept(dgt_sint32 err_code = 0, DgcError* t = 0)
        : DgcExcept(DGC_EXT_PCI, err_code, t){};
    DgcPciExcept(const DgcPciExcept& t) : DgcExcept(t){};
    DgcPciExcept& operator=(const DgcPciExcept& t) {
        DgcExcept::operator=(t);
        return *this;
    };
    virtual ~DgcPciExcept(){};
};
static const dgt_sint16 DGC_EC_PCI_BASE = -15000;
static const dgt_sint16 DGC_EC_PCI_ERR = DGC_EC_PCI_BASE - 1;
#endif

class PciCipher {
   private:
    static const dgt_uint8 MAX_KEY_BYTES = 128;

    virtual dgt_sint32 initializeContext() = 0;

   protected:
    dgt_uint8 Key[MAX_KEY_BYTES];
    dgt_uint16 KeyBits;
    dgt_uint16 BlockBytes;
    dgt_uint8 OpMode;
    dgt_uint8 PadType;
    const dgt_uint8* IV;
    dgt_uint8 KeySetFlag;

   public:
    static const dgt_uint8 MODE_ECB = 1;
    static const dgt_uint8 MODE_CBC = 2;
    static const dgt_uint8 MODE_CFB = 3;
    static const dgt_uint8 MODE_OFB = 4;
    static const dgt_uint8 MODE_CBC0 = 5;

    static const dgt_uint8 PAD_ZERO = 1;
    static const dgt_uint8 PAD_PKCS7 = 2;
    static const dgt_uint8 PAD_NONE = 3;

    PciCipher()
        : KeyBits(0),
          BlockBytes(0),
          OpMode(0),
          PadType(PAD_ZERO),
          IV(0),
          KeySetFlag(0) {
        memset(Key, 0, MAX_KEY_BYTES);
    }
    virtual ~PciCipher() {}

    inline dgt_sint32 initialize(const dgt_uint8* key, dgt_uint16 key_bits,
                                 dgt_uint8 op_mode = MODE_CBC,
                                 dgt_uint8 pad_type = PAD_PKCS7) {
        memset(Key, 0, MAX_KEY_BYTES);
        KeySetFlag = 0;
        if (key) {
            memcpy(Key, key, key_bits / 8);
            KeySetFlag = 1;
        }
        KeyBits = key_bits;
        IV = 0;
        OpMode = op_mode;
        PadType = pad_type;
        return initializeContext();
    }

    inline dgt_void setIV(const dgt_uint8* iv) {
        if (OpMode != MODE_ECB) IV = iv;
    }

    inline dgt_uint16 blockSize() { return BlockBytes; }
    inline dgt_uint8 opMode() { return OpMode; }
    inline dgt_uint8 padType() { return PadType; }
    inline const dgt_uint8* iv() { return IV; }
    inline dgt_uint8 keySetFlag() { return KeySetFlag; };

    virtual dgt_sint32 encrypt(dgt_uint8* ibuf, dgt_uint32 len, dgt_uint8* obuf,
                               dgt_uint32* olen) = 0;
};

#endif
