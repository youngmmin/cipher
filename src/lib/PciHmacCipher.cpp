/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciHmacCipher
 *   Implementor        :       ihjin
 *   Create Date        :       2018. 10. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
2018.10.18 enhancement: source code refactoring  
********************************************************************/
#include "PciHmacCipher.h"

dgt_sint32 PciHmacCipher::initializeContext()
{
        return 0;
}

PciHmacCipher::PciHmacCipher()
{
}

PciHmacCipher::~PciHmacCipher()
{
}

dgt_sint32 PciHmacCipher::encrypt(dgt_uint8* ibuf,dgt_uint32 len,dgt_uint8* obuf,dgt_uint32* olen)
{
	*olen = (dgt_uint32)(KeyBits/8);
	return encryptECB(ibuf,len,obuf,olen);
}
