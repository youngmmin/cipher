/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptMir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptMir.h"

PccCryptMir::PccCryptMir(dgt_uint64 file_id)
    : ChildMirList(CHILD_MIR_HASH_SIZE),
      FileNodeList(FILE_NODE_HASH_SIZE),
      FileID(file_id),
      LastModified(0),
      CheckSeq(0),
      ParentSeq(0),
      ChangeFlag(1),
      DropFlag(0),
      RefCount(0) {
    DgcSpinLock::unlock(&MirListLock);
    DgcSpinLock::unlock(&NodeListLock);
}

PccCryptMir::~PccCryptMir() {
    PccHashNode* hnp = 0;

    FileNodeList.rewind();
    dgt_sint32 delete_cnt = 0;
    while ((hnp = FileNodeList.nextNode())) {
        delete (pcct_file_node*)hnp->value();
        hnp->setValue(0);
        delete_cnt++;
    }
    ChildMirList.rewind();
    delete_cnt = 0;
    while ((hnp = ChildMirList.nextNode())) {
        delete (PccCryptMir*)hnp->value();
        hnp->setValue(0);
        delete_cnt++;
    }
}

pcct_file_node* PccCryptMir::checkFileNode(struct stat* fstat, dgt_sint64 ino) {
    for (;;) {
        pcct_file_node* file_node = 0;
        if (DgcSpinLock::lock(&NodeListLock) == 0) {
            PccHashNode* hnp = FileNodeList.findNode(fstat->st_ino);
            if (hnp == 0) {  // not found and create one
                file_node = new pcct_file_node();
                memset(file_node, 0, sizeof(pcct_file_node));
                file_node->file_id = fstat->st_ino;
                FileNodeList.addNode(fstat->st_ino, file_node);
            } else {
                file_node = (pcct_file_node*)hnp->value();
            }

            if (file_node->lm_time == 0) {
                file_node->lm_time = fstat->st_mtime;
                file_node->file_size = fstat->st_size;
            } else if (file_node->lm_time != fstat->st_mtime) {
                if (file_node->file_size != fstat->st_size) {
                    // reset cllt_time for recollecting if the file is modified
                    file_node->lm_time = fstat->st_mtime;
                    file_node->file_size = fstat->st_size;
                    file_node->cllt_time = 0;
                }
            }
            file_node->check_seq = CheckSeq;
            file_node->ref_count++;
            DgcSpinLock::unlock(&NodeListLock);
        }
        if (file_node) return file_node;
    }
    return 0;
}

dgt_void PccCryptMir::setLastModified(dgt_time last_modified) {
    for (;;) {
        pcct_file_node* file_node = 0;
        if (DgcSpinLock::lock(&NodeListLock) == 0) {
            if (last_modified == LastModified) {
                //
                // directory is not changed
                // so there's no need to check the child files
                //
                PccHashNode* hnp = 0;
                FileNodeList.rewind();
                while ((hnp = FileNodeList.nextNode())) {
                    pcct_file_node* file_node = (pcct_file_node*)hnp->value();
                    file_node->check_seq = CheckSeq;
                }
                ChangeFlag = 0;
            } else {
                LastModified = last_modified;
                ChangeFlag = 1;
            }
            DgcSpinLock::unlock(&NodeListLock);
            break;
        }
    }
}

PccCryptMir* PccCryptMir::getChildMir(dgt_uint64 file_id,
                                      dgt_time last_modified) {
    for (;;) {
        PccCryptMir* mir = 0;
        if (DgcSpinLock::lock(&MirListLock) == 0) {
            PccHashNode* hnp = ChildMirList.findNode(file_id);
            if (hnp == 0) {  // not found and create one
                mir = new PccCryptMir(file_id);
                ChildMirList.addNode(file_id, mir);
            } else {
                mir = (PccCryptMir*)hnp->value();
                mir->setLastModified(last_modified);
            }
            mir->setParentSeq(CheckSeq);
            DgcSpinLock::unlock(&MirListLock);
        }
        if (mir) return mir;
    }
    return 0;
}

dgt_void PccCryptMir::closeMir() {
    static const dgt_sint32 MAX_REMOVE_FILE = 100;
    dgt_uint64 remove_file_ids[MAX_REMOVE_FILE];
    dgt_sint32 num_rfis = 0;
    PccHashNode* hnp = 0;
    //
    // clean file nodes for dropped files
    //
    for (;;) {
        if (DgcSpinLock::lock(&NodeListLock) == 0) {
            num_rfis = 0;
            hnp = 0;
            FileNodeList.rewind();
            while ((hnp = FileNodeList.nextNode()) &&
                   num_rfis < MAX_REMOVE_FILE) {
                pcct_file_node* file_node = (pcct_file_node*)hnp->value();
                if (file_node->check_seq < CheckSeq &&
                    file_node->ref_count == 0) {  // dropped file
                    remove_file_ids[num_rfis++] = file_node->file_id;
                    delete file_node;
                    hnp->setValue(0);
                }
            }
            for (dgt_sint32 i = 0; i < num_rfis; i++) {
                dgt_sint32 rtn = FileNodeList.removeNode(remove_file_ids[i]);
            }
            DgcSpinLock::unlock(&NodeListLock);
            if (num_rfis < MAX_REMOVE_FILE) break;
        }
    }
    //
    // clean mirs for dropped directories
    //
    num_rfis = 0;
    for (;;) {
        if (DgcSpinLock::lock(&MirListLock) == 0) {
            ChildMirList.rewind();
            num_rfis = 0;
            hnp = 0;
            while ((hnp = ChildMirList.nextNode()) &&
                   num_rfis < MAX_REMOVE_FILE) {
                PccCryptMir* mir = (PccCryptMir*)hnp->value();
                if ((mir->dropFlag() || mir->parentSeq() != CheckSeq) &&
                    !mir->isRefered()) {  // dropped file
                    remove_file_ids[num_rfis++] = mir->fileID();
                    delete mir;
                    hnp->setValue(0);
                }
            }
            for (dgt_sint32 i = 0; i < num_rfis; i++)
                ChildMirList.removeNode(remove_file_ids[i]);
            DgcSpinLock::unlock(&MirListLock);
        }
        if (num_rfis < MAX_REMOVE_FILE) break;
    }
}

PccCryptMir* PccCryptMir::findCryptMir(dgt_uint64 file_id,
                                       dgt_sint32 is_child_search) {
    for (;;) {
        PccCryptMir* mir = 0;
        if (DgcSpinLock::lock(&MirListLock) == 0) {
            PccHashNode* hnp = ChildMirList.findNode(file_id);
            if (hnp) {
                mir = (PccCryptMir*)hnp->value();
                if (mir) mir->incReference();
            } else if (is_child_search) {
                ChildMirList.rewind();
                while ((hnp = ChildMirList.nextNode())) {
                    if ((mir = ((PccCryptMir*)hnp->value())
                                   ->findCryptMir(file_id, is_child_search)))
                        break;
                    mir = 0;
                }
            }
            DgcSpinLock::unlock(&MirListLock);
        }
    }
    return 0;
}

pcct_file_node* PccCryptMir::findFileNode(dgt_uint64 file_id) {
    pcct_file_node* file_node = 0;
    if (DgcSpinLock::lock(&NodeListLock) == 0) {
        PccHashNode* hnp = FileNodeList.findNode(file_id);
        if (hnp) {
            file_node = (pcct_file_node*)hnp->value();
            file_node->ref_count++;
        }
        DgcSpinLock::unlock(&NodeListLock);
    }
    if (file_node) return file_node;
    return 0;
}

dgt_void PccCryptMir::removeFileNode(dgt_uint64 file_id) {
    pcct_file_node* file_node = 0;
    if (DgcSpinLock::lock(&NodeListLock) == 0) {
        PccHashNode* hnp = FileNodeList.findNode(file_id);
        if (hnp) {
            file_node = (pcct_file_node*)hnp->value();
            FileNodeList.removeNode(file_node->file_id);
            delete file_node;
            hnp->setValue(0);
        }
        DgcSpinLock::unlock(&NodeListLock);
    }
}

dgt_sint32 PccCryptMir::reset() {
    if (DgcSpinLock::lock(&NodeListLock) == 0) {
        PccHashNode* hnp = 0;
        FileNodeList.rewind();
        while ((hnp = FileNodeList.nextNode())) {
            pcct_file_node* file_node = (pcct_file_node*)hnp->value();
            file_node->cllt_time = 0;
        }

        DgcSpinLock::unlock(&NodeListLock);
    }
    return 0;
}
