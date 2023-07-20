/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccFileMemMap
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_FILE_MEM_MAP_H
#define PCC_FILE_MEM_MAP_H

#include "DgcExcept.h"

class PccFileMemMap : public DgcObject {
   private:
    dgt_uint8* Address;
    dgt_sint32 Size;

    dgt_sint32 openFile(const dgt_schar* file_name,
                        dgt_sint32 o_flag) throw(DgcExcept);
    dgt_void unlinkFile(const dgt_schar* file_name);

   protected:
   public:
    PccFileMemMap();
    virtual ~PccFileMemMap();

    inline dgt_uint8 isLoaded() {
        if (Address) return 1;
        return 0;
    };
    inline dgt_void* address() { return (dgt_void*)Address; };

    dgt_sint32 load(const dgt_schar* file_name, dgt_sint32 size, dgt_uint8* buf,
                    dgt_uint8 create_flag = 1) throw(DgcExcept);
    dgt_sint32 sync(dgt_uint8* sync_ptr, dgt_sint32 sync_size) throw(DgcExcept);
    dgt_void unload();
};

#endif
