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
#ifndef PCC_CRYPT_MIR_H
#define PCC_CRYPT_MIR_H

#include "DgcSpinLock.h"
#include "PccHashTable.h"

typedef struct {                // for mirroring directories & files
    dgt_uint64 file_id;         // file id, inode number in linux and unix
    dgt_sint64 file_size;       // file size
    dgt_time lm_time;           // last modified time
    dgt_time cllt_time;         // collecting time
    dgt_time ctst_time;         // crypt start time
    dgt_time cted_time;         // crypt end time
    dgt_uint32 check_seq;       // check sequence
    dgt_sint8 encrypt_flag;     // encrypt flag
    dgt_uint8 ref_count;        // reference count
    dgt_uint8 check_migration;  // is check migration ?
} pcct_file_node;

class PccCryptMir : public DgcObject {
   private:
    static const dgt_uint32 CHILD_MIR_HASH_SIZE = 100;
    static const dgt_uint32 FILE_NODE_HASH_SIZE = 1000;
    PccHashTable ChildMirList;  // child crypt mirror directory list
    PccHashTable FileNodeList;  // child file node list
    dgt_uint64 FileID;          // file id
    dgt_time LastModified;      // last modified time
    dgt_uint32
        CheckSeq;  // check sequence which's increased by 1 every openDir()
    dgt_uint32 ParentSeq;  // parent's sequence
    dgt_sint8 ChangeFlag;  // change flag
    dgt_sint8 DropFlag;    // set when actual directory was dropped
    dgt_sint8 RefCount;  // reference count increased by 1 when findMir() called
    dgt_slock MirListLock;   // ChildMirList lock
    dgt_slock NodeListLock;  // FileNodeList lock
   protected:
   public:
    PccCryptMir(dgt_uint64 file_id);
    virtual ~PccCryptMir();
    dgt_uint64 fileID() { return FileID; }
    dgt_uint32 parentSeq() { return ParentSeq; }
    dgt_void setParentSeq(dgt_uint32 seq) { ParentSeq = seq; }
    dgt_void setDropFlag() { DropFlag = 1; }
    dgt_sint8 changeFlag() { return ChangeFlag; }
    dgt_sint8 dropFlag() { return DropFlag; }
    dgt_void openMir() {
        if (ChangeFlag) CheckSeq++;
    }
    dgt_void incReference() { RefCount++; }
    dgt_void decReference() { RefCount--; }
    dgt_sint8 isRefered() { return RefCount; }
    dgt_sint32 reset();

    pcct_file_node* checkFileNode(struct stat* fstat, dgt_sint64 ino = 0);

    dgt_void setLastModified(dgt_time last_modified);
    PccCryptMir* getChildMir(dgt_uint64 file_id, dgt_time last_modified);
    dgt_void closeMir();
    PccCryptMir* findCryptMir(dgt_uint64 file_id,
                              dgt_sint32 is_child_search = 1);
    pcct_file_node* findFileNode(dgt_uint64 file_id);
    dgt_void removeFileNode(dgt_uint64 file_id);
};

#endif
