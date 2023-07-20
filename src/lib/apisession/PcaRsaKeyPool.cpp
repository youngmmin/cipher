/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaRsaKeyPool
 *   Implementor        :       mwpark
 *   Create Date        :       2019. 4. 30.
 *   Description        :       petra cipher API rsa key pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaRsaKeyPool.h"

#include "DgcCRC64.h"

PcaRsaKeyPool::PcaRsaKeyPool() : RsaKeyList(20) {}

PcaRsaKeyPool::~PcaRsaKeyPool() {
    PccHashNode* hnp = 0;
    RsaKeyList.rewind();
    while ((hnp = RsaKeyList.nextNode())) {
        delete (dgt_schar*)hnp->value();
        hnp->setValue();
    }
}

dgt_schar* PcaRsaKeyPool::getRsaKey(dgt_schar* key_name) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = 0;
#ifndef WIN32
    key_id = DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)key_name,
                                    dg_strlen(key_name));
#else
    key_id =
        DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)key_name, strlen(key_name));
#endif
    // find enc zone
    PccHashNode* hnp = RsaKeyList.findNode(key_id);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "not found RsaKeyPool [%s]", key_name);

    return 0;
}

dgt_schar* PcaRsaKeyPool::putRsaKey(dgt_schar* key_name,
                                    dgt_schar* key_string) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = 0;
#ifndef WIN32
    key_id =
        DgcCRC64::calCRC64Case(key_id, (dgt_uint8*)key_name, strlen(key_name));
#else
#endif

    PccHashNode* hnp = RsaKeyList.addNode(key_id, key_string);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "put RsaKEyList Failed[%s]", key_name);
    return 0;
}
