/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccFileMemMap
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 09. 21
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PccFileMemMap.h"

#include "DgcWorker.h"
#ifdef WIN32
#include "windows.h"
#endif

PccFileMemMap::PccFileMemMap() : Address(0), Size(0) {}

PccFileMemMap::~PccFileMemMap() { unload(); }

dgt_sint32 PccFileMemMap::openFile(const dgt_schar* file_name,
                                   dgt_sint32 o_flag) throw(DgcExcept) {
    mode_t u_mask = umask(0);
    dgt_sint32 fd = open(file_name, o_flag, 0666);
    umask(u_mask);
    dgt_sint32 eno = errno;
    if (fd < 0)
        THROWnR(DgcOsExcept(
                    eno, new DgcError(SPOS, "file[%s] open failed", file_name)),
                -1);
    return fd;
}

dgt_void PccFileMemMap::unlinkFile(const dgt_schar* file_name) {
    if (unlink(file_name) < 0 && errno != ENOENT) {
        DgcWorker::PLOG.tprintf(0, "unlink[%s] failed[%s]:\n", file_name,
                                strerror(errno));
    }
}

dgt_sint32 PccFileMemMap::load(const dgt_schar* file_name, dgt_sint32 size,
                               dgt_uint8* buf,
                               dgt_uint8 create_flag) throw(DgcExcept) {
    if (Address)
        THROWnR(DgcOsExcept(-1, new DgcError(SPOS, "already loaded")), -1);
    dgt_sint32 o_flag = O_RDWR;
    dgt_sint32 fd = openFile(file_name, o_flag);
    if (fd < 0) {
        // file is not exist
        if (EXCEPT && EXCEPT->errCode() == ENOENT && create_flag) {
            delete EXCEPTnC;
            o_flag = O_RDWR | O_CREAT | O_EXCL;
            fd = openFile(file_name, o_flag);
            if (fd < 0) ATHROWnR(DgcError(SPOS, "creating file failed"), -1);
            dgt_uint8* file_map = new dgt_uint8[size];
            memset(file_map, 0, size);
            dgt_sint32 remain_bytes = size;
            dgt_sint32 cp = 0;
            while (remain_bytes > 0) {
                dgt_sint32 rtn_bytes =
                    (remain_bytes >= size)
                        ? write(fd, file_map, size)
                        : write(fd, file_map + cp, remain_bytes);
                if (rtn_bytes < 0) {
                    close(fd);
                    unlinkFile(file_name);
                    delete[] file_map;
                    THROWnR(
                        DgcOsExcept(
                            errno,
                            new DgcError(
                                SPOS, "write failed, may be file-system full")),
                        -1);
                }
                cp += rtn_bytes;
                remain_bytes -= rtn_bytes;
            }
            delete[] file_map;
        } else {
            ATHROWnR(DgcError(SPOS, "openFile failed"), -1);
            THROWnR(
                DgcOsExcept(errno, new DgcError(SPOS, "file[%s] open failed",
                                                file_name)),
                -1);
        }
    } else {
        // check file size
#ifndef WIN32
        struct stat sb;
        if (fstat(fd, &sb) < 0) {
            THROWnR(DgcOsExcept(errno, new DgcError(SPOS, "fstat failed")), -1);
        }
#else
        struct _stat sb;
        if (_fstat(fd, &sb) < 0) {
            THROWnR(DgcOsExcept(errno, new DgcError(SPOS, "_fstat failed")),
                    -1);
        }
#endif
        if (sb.st_size != size)
            THROWnR(
                DgcOsExcept(-1, new DgcError(SPOS, "invalid file size[%d:%d]",
                                             sb.st_size, size)),
                -1);
    }
#ifndef WIN32
    dgt_uint8* addr =
        (dgt_uint8*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED || addr == 0) {
        dgt_sint32 eno = errno;
        close(fd);
        THROWnR(DgcOsExcept(eno, new DgcError(SPOS, "mmap failed ")), -1);
    }

    if (close(fd) < 0) {
        dgt_sint32 eno = errno;
        munmap(addr, size);
        THROWnR(DgcOsExcept(eno, new DgcError(SPOS, "file close failed")), -1);
    }
#else
    HANDLE hd = (HANDLE)_get_osfhandle(fd);
    if (hd == INVALID_HANDLE_VALUE) {
        dgt_sint32 eno = errno;
        close(fd);
        THROWnR(DgcOsExcept(eno, new DgcError(SPOS, "_get_osfhandle failed[%d]",
                                              GetLastError())),
                -1);
    }
    HANDLE h_file_map =
        CreateFileMapping((HANDLE)hd, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (h_file_map == NULL) {
        dgt_sint32 eno = errno;
        close(fd);
        THROWnR(
            DgcOsExcept(eno, new DgcError(SPOS, "CreateFileMapping failed[%d]",
                                          GetLastError())),
            -1);
    }
    dgt_uint8* addr = (dgt_uint8*)MapViewOfFile(
        h_file_map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size);
    if (addr == 0) {
        dgt_sint32 eno = errno;
        CloseHandle(h_file_map);
        close(fd);
        THROWnR(DgcOsExcept(eno, new DgcError(SPOS, "MapViewOfFile failed[%d]",
                                              GetLastError())),
                -1);
    }
    CloseHandle(h_file_map);
    if (close(fd) < 0) {
        dgt_sint32 eno = errno;
        UnmapViewOfFile(addr);
        THROWnR(DgcOsExcept(eno, new DgcError(SPOS, "file close failed")), -1);
    }
#endif

    Address = addr;
    Size = size;
    if (buf && Address && size > 0) memcpy(buf, Address, size);
    return 0;
}

dgt_sint32 PccFileMemMap::sync(dgt_uint8* sync_ptr,
                               dgt_sint32 sync_size) throw(DgcExcept) {
    if (!Address)
        THROWnR(DgcOsExcept(-1, new DgcError(SPOS, "Address is not loaded")),
                -1);

    if (sync_ptr && sync_size > 0) {
        memcpy(Address, sync_ptr, Size < sync_size ? Size : sync_size);
#ifndef WIN32
        if (msync(Address, Size, MS_ASYNC) < 0) {
            THROWnR(DgcOsExcept(errno, new DgcError(SPOS, "msync failed")), -1);
        }
#else
        if (FlushViewOfFile(Address, Size) == 0) {
            THROWnR(DgcOsExcept(
                        errno, new DgcError(SPOS, "FlushViewOfFile failed:[%d]",
                                            GetLastError())),
                    -1);
        }
#endif
    }
    return 0;
}

dgt_void PccFileMemMap::unload() {
#ifndef WIN32
    if (Address) munmap(Address, Size);
#else
    if (Address) UnmapViewOfFile(Address);
#endif
    Address = 0;
    Size = 0;
}
