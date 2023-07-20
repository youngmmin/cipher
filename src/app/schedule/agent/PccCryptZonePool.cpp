/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptZonePool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 remove dir_pttn, file_pttn parameter parsing
--------------------------------------------------------------------

********************************************************************/
#include "PccCryptZonePool.h"


PccCryptZonePool::PccCryptZonePool() : NumZones(0), ErrString(0)
{
	ErrString = new dgt_schar[1024];
}

PccCryptZonePool::~PccCryptZonePool()
{
	delete [] ErrString;
	for(dgt_sint32 i=0; i<NumZones; i++) delete CryptZones[i];
}

PccCryptZone* PccCryptZonePool::getZoneByID(dgt_sint64 zone_id) throw(DgcExcept)
{
	for(dgt_sint32 i=0; i<NumZones; i++) if (CryptZones[i]->zoneID() == zone_id) return CryptZones[i];
	return 0;
}

dgt_sint32 PccCryptZonePool::setParams(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_schar*	val = 0;
	dgt_sint32	param_type = 0;
	if ((val=bg->getValue("zone.id"))) param_type = 1;
	else if ((val=bg->getValue("key.zone_id"))) param_type = 4;
	else if ((val=bg->getValue("regular.zone_id"))) param_type = 5;
	else if ((val=bg->getValue("delimiter.zone_id"))) param_type = 6;
	else if ((val=bg->getValue("fixed.zone_id"))) param_type = 7;
	else if ((val=bg->getValue("system_info.zone_id"))) param_type = 8;
	if (param_type == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"unsupported params[%s]",bg->getText())),-1);
	}
	
	dgt_sint64	zone_id = dg_strtoll(val,0,10);

	PccCryptZone*	crypt_zone = getZoneByID(zone_id);
	if (crypt_zone == 0) {
		if (param_type == 1) {
			if (NumZones == MAX_ZONES) {
				THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"ZoonPool is full[%d]",NumZones)),-1);
			}
			crypt_zone = new PccCryptZone(zone_id);
			CryptZones[NumZones++] = crypt_zone;
		}
	}
	if (crypt_zone == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"CryptZone[%lld] not found",zone_id)),-1);
	}
	dgt_sint32	rtn = 0;
	memset(ErrString,0,1024);
	if (param_type == 1) rtn=crypt_zone->setZoneParams(bg,ErrString);
	else if (param_type == 4) rtn=crypt_zone->setKeyParams(bg,ErrString);
	else if (param_type == 5) rtn=crypt_zone->setRegularParams(bg,ErrString);
	else if (param_type == 6) rtn=crypt_zone->setDelimiterParams(bg,ErrString);
	else if (param_type == 7) rtn=crypt_zone->setFixedParams(bg,ErrString);
	else if (param_type == 8) rtn=crypt_zone->setSystemInfoParams(bg,ErrString);
	if (rtn < 0) {
		ATHROWnR(DgcError(SPOS,"setting zone parameters failed: %s",ErrString),-1);
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"%s",ErrString)),rtn);
	}
	return 0;
}

dgt_sint32 PccCryptZonePool::setParams(const dgt_schar* param_list) throw(DgcExcept)
{
	DgcBgmrList params(param_list,1);
	ATHROWnR(DgcError(SPOS,"parse[%s] failed",param_list),-1);
	DgcBgrammer*    bg = 0;
	while((bg=params.getNext())) {
		setParams(bg);
		ATHROWnR(DgcError(SPOS,"setParams failed"),-1);
	}
	return 0;
}
