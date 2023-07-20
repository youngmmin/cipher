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
#ifndef PCC_CRYPT_ZONE_H
#define PCC_CRYPT_ZONE_H

#include "DgcBgmrList.h"
#include "PcaApiSessionPool.h"
#include "PccCryptTargetFileQueue.h"
#include "PtChunkObjectList.h"

class PccCryptZone : public DgcObject {
   private:
    static const dgt_uint32 LOCK_MAX_NAP = 200;
    static const dgt_uint8 ELF_TYPE_SET_PARAM = 1;
    static const dgt_uint8 ELF_TYPE_SET_ZONE_PARAM = 2;
    static const dgt_uint8 ELF_TYPE_SET_DIR_PTTN = 3;
    static const dgt_uint8 ELF_TYPE_SET_FILE_PTTN = 4;
    static const dgt_uint8 ELF_TYPE_SET_KEY_PARAM = 5;
    static const dgt_uint8 ELF_TYPE_SET_REG_PARAM = 6;
    static const dgt_uint8 ELF_TYPE_SET_DELI_PARAM = 7;
    static const dgt_uint8 ELF_TYPE_SET_FIXED_PARAM = 8;
    static const dgt_uint8 ELF_TYPE_SET_SYSINFO_PARAM = 9;
    dgt_sint64 ZoneID;           // zone if
    dgt_schar Name[33];          // name
    dgt_sint32 CloseAfter;       // file close decision time
    dgt_schar EncColName[33];    // encrypt column name used in total crypting
    dgt_schar OutExtension[33];  // output file extension
    dgt_schar KeyParam[257];
    dgt_schar SystemInfoParam[257];
    dgt_schar* RegularParam;    // pattern parameters
    dgt_schar* DelimiterParam;  // delimeter parameters
    dgt_schar* FixedParam;      // fixed parameters
    dgt_schar* ErrString;       // error string
    dgt_uint8 FileFormat;       // source file format
    dgt_uint8 HeaderFlag;       // header flag for preventing double encrypting
    dgt_uint8 OverWriteFlag;    // header flag for preventing double encrypting
    dgt_uint8 EncryptFlag;
    dgt_uint8 DetectFlag;
    dgt_uint8 BackupFlag;

    dgt_slock Lock;
    dgt_uint8 ELF;   // for updating zone parameters
    dgt_sint32 NSL;  // for using zone parameters

    dgt_sint64 SystemID;  // added by shson 2018.10.01 for CryptStat member
                          // variable, SystemID

    dgt_schar ExtIp[65];  // added by mwpark 2018.11.14 for finger print masking
    dgt_uint16 ExtPort;   // added by mwpark 2018.11.14 for finger print masking
                          // bogonet fp configuration
    dgt_float64 Slimit;   // SizeLimit
    dgt_sint32 Senable;   // SizeLimit enable flag
    dgt_float64 Gsigma;   // GaussianSmoothing
    dgt_sint32 Genable;   // GaussianSmoothing enable flag
    dgt_sint32 Cenable;   // Contrast enable flag
    dgt_sint32 Rangle;    // Rotate angle
    dgt_sint32 Renable;   // Rotate enable flag
    dgt_sint64 KeyId;     // added by shson 2019.03.20 for migration

    dgt_sint32 lock() throw(DgcExcept);
    dgt_void unlock() throw(DgcExcept);
    dgt_sint32 lockExclusive(dgt_uint8 lock_type = ELF_TYPE_SET_PARAM) throw(
        DgcExcept);
    dgt_sint32 unlockExclusive() throw(DgcExcept);
    dgt_sint32 lockShare() throw(DgcExcept);
    dgt_sint32 unlockShare() throw(DgcExcept);

    dgt_sint32 checkParams(dgt_schar* err_string) throw(DgcExcept);

   protected:
   public:
    PccCryptZone(dgt_sint64 zone_id);
    virtual ~PccCryptZone();
    inline dgt_sint64 zoneID() { return ZoneID; };

    // using zone parameters without shared lock because they are not critical
    // parameters in file cryption
    inline dgt_uint8 headerFlag() { return HeaderFlag; };
    inline dgt_uint8 encryptFlag() { return EncryptFlag; };
    inline dgt_uint8 detectFlag() { return DetectFlag; };
    inline dgt_uint8 backupFlag() { return BackupFlag; };
    inline dgt_uint8 hasOutExtension() { return *OutExtension ? 1 : 0; };
    inline dgt_schar* outExtension() { return OutExtension; };
    inline dgt_sint32 closeAfter() { return CloseAfter; };
    inline dgt_sint64 systemID() { return SystemID; };
    inline dgt_schar* extIp() { return ExtIp; };
    inline dgt_uint16 extPort() { return ExtPort; };
    inline dgt_float64 sLimit() { return Slimit; };
    inline dgt_sint32 sEnable() { return Senable; };
    inline dgt_float64 gSigma() { return Gsigma; };
    inline dgt_sint32 gEnable() { return Genable; };
    inline dgt_sint32 cEnable() { return Cenable; };
    inline dgt_sint32 rAngle() { return Rangle; };
    inline dgt_sint32 rEnable() { return Renable; };
    inline dgt_schar* encColName() { return EncColName; };
    inline dgt_sint64 keyId() { return KeyId; };

    dgt_void cleanZoneAttrs();

    // update zone parameters
    dgt_sint32 setZoneParams(DgcBgrammer* bg,
                             dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 setKeyParams(DgcBgrammer* bg,
                            dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 setRegularParams(DgcBgrammer* bg,
                                dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 setDelimiterParams(DgcBgrammer* bg,
                                  dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 setFixedParams(DgcBgrammer* bg,
                              dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 setSystemInfoParams(DgcBgrammer* bg,
                                   dgt_schar* err_string) throw(DgcExcept);

    // using zone parameters
    dgt_sint32 buildParam(dgt_schar* buf, dgt_uint32* buf_len,
                          dgt_sint32 migration_flag = 0) throw(DgcExcept);
};

#endif
