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
#ifndef PCA_ENC_ZONE_POOL_H
#define PCA_ENC_ZONE_POOL_H

#include "PccHashTable.h"

class PcaEncZonePool : public DgcObject {
   private:
    dgt_schar ErrMsg[1024];
    PccHashTable EncZoneList;

   protected:
   public:
    PcaEncZonePool();
    virtual ~PcaEncZonePool();
    dgt_schar* getErr() { return ErrMsg; }

    dgt_schar* getEncZoneParam(dgt_sint64 zone_id);
    dgt_schar* putEncZone(dgt_sint64 zone_id, dgt_schar* param);
};

#endif
