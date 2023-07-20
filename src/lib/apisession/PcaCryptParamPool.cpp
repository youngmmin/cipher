/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaCryptParamPool
 *   Implementor        :       shson
 *   Create Date        :       2018. 11. 30.
 *   Description        :       petra cipher API crypt param
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaCryptParamPool.h"

#include "DgcCRC64.h"

PcaCryptParamPool::PcaCryptParamPool() : CryptParamList(20) {}

PcaCryptParamPool::~PcaCryptParamPool() {
    PccHashNode* hnp = 0;
    CryptParamList.rewind();
    while ((hnp = CryptParamList.nextNode())) {
        delete (dgt_schar*)hnp->value();
        hnp->setValue();
    }
}

dgt_schar* PcaCryptParamPool::getCryptParam(dgt_schar* crypt_param_name) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = 0;
#ifndef WIN32
    key_id = DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)crypt_param_name,
                                    dg_strlen(crypt_param_name));
#else
    key_id = DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)crypt_param_name,
                                    strlen(crypt_param_name));
#endif
    // find crypt param
    PccHashNode* hnp = CryptParamList.findNode(key_id);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "not found CryptParam [%s]", crypt_param_name);

    return 0;
}

dgt_schar* PcaCryptParamPool::putCryptParam(dgt_schar* crypt_param_name,
                                            dgt_schar* param) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = 0;
#ifndef WIN32
    key_id = DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)crypt_param_name,
                                    strlen(crypt_param_name));
#else
#endif

    PccHashNode* hnp = CryptParamList.addNode(key_id, param);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "put CryptParam Failed[%s]", crypt_param_name);
    return 0;
}
