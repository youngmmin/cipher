/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptMir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_ZONE_POOL_H
#define PCC_CRYPT_ZONE_POOL_H

#include "PccCryptZone.h"

class PccCryptZonePool : public DgcObject {
  private:
	static const dgt_sint32	MAX_ZONES = 2048;
	PccCryptZone*	CryptZones[MAX_ZONES];	// zone pool
	dgt_sint32	NumZones;		// a number of zones
	dgt_schar*	ErrString;
  protected:
  public:
	PccCryptZonePool();
	virtual ~PccCryptZonePool();
	PccCryptZone* getZoneByID(dgt_sint64 zone_id) throw(DgcExcept);
	dgt_sint32 addCryptZone(dgt_sint64 zone_id,const dgt_schar* zone_info) throw(DgcExcept);
	dgt_sint32 setParams(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 setParams(const dgt_schar* param_list) throw(DgcExcept);
};

#endif
