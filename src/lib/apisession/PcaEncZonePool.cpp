/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaEncZonePool
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 8. 8.
 *   Description        :       petra cipher API enc zone
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaEncZonePool.h"

#include "DgcCRC64.h"

PcaEncZonePool::PcaEncZonePool() : EncZoneList(20) {}

PcaEncZonePool::~PcaEncZonePool() {
    PccHashNode* hnp = 0;
    EncZoneList.rewind();
    while ((hnp = EncZoneList.nextNode())) {
        delete (dgt_schar*)hnp->value();
        hnp->setValue();
    }
}

dgt_schar* PcaEncZonePool::getEncZoneParam(dgt_sint64 zone_id) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = zone_id;
    // find enc zone
    PccHashNode* hnp = EncZoneList.findNode(key_id);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "not found EncZone [%lld]", zone_id);

    return 0;
}

dgt_schar* PcaEncZonePool::putEncZone(dgt_sint64 zone_id, dgt_schar* param) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = zone_id;
    PccHashNode* hnp = EncZoneList.addNode(key_id, param);
    if (hnp) return (dgt_schar*)hnp->value();
    sprintf(ErrMsg, "put EncZone Failed[%lld]", zone_id);
    return 0;
}
