/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PciShaCipher
 *   Implementor        :       chchung
 *   Create Date        :       2015. 8. 16
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciShaCipher.h"

dgt_sint32 PciShaCipher::initializeContext() { return 0; }

PciShaCipher::PciShaCipher() {}

PciShaCipher::~PciShaCipher() {}

dgt_sint32 PciShaCipher::encrypt(dgt_uint8* ibuf, dgt_uint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
    *olen = (dgt_uint32)(KeyBits / 8);
    if (OpMode == MODE_ECB) return encryptECB(ibuf, len, obuf, olen);
    return encryptCBC(ibuf, len, obuf, olen);
}
