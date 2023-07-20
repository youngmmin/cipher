/*******************************************************************
 *   File Type          :       hash table classes declaration
 *   Classes            :       PccHashTable
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_HASH_NODE_H
#define PCC_HASH_NODE_H

#include "DgcObject.h"
#include "PtChunkObjectList.h"

class PccHashNode {
   private:
    dgt_uint64 Key;
    dgt_void* Value;
    PccHashNode* Next;

   protected:
   public:
    PccHashNode(dgt_uint64 key, dgt_uint8* value)
        : Key(key), Value(value), Next(0) {}
    ~PccHashNode() {}
    dgt_uint64 key() { return Key; }
    dgt_void* value() { return Value; }
    PccHashNode* next() { return Next; }
    dgt_void setNext(PccHashNode* next = 0) { Next = next; }
    dgt_void setValue(dgt_void* value = 0) { Value = value; }
    dgt_void reset(dgt_uint64 key = 0, dgt_void* value = 0) {
        Key = key;
        Value = value;
        Next = 0;
    }
};

class PccHashTable : public DgcObject {
   private:
    static const dgt_uint32 HASH_SIZE = 500;
    static const dgt_sint32 MAX_LISTS = 10000;
    dgt_sint32 Size;
    PccHashNode** Table;
    PccHashNode* FirstFree;
    PccHashNode* LastFree;
    dgt_sint32 CurrPos;
    PccHashNode* CurrNode;
    PtChunkObjectList* NodePool[MAX_LISTS];
    dgt_sint32 CurrList;
    PccHashNode* getFreeNode(dgt_uint64 key, dgt_void* value);

   protected:
   public:
    PccHashTable(dgt_sint32 size);
    virtual ~PccHashTable();

    inline dgt_sint32 size() { return Size; };
    inline dgt_sint32 currPos() { return CurrPos; };
    inline dgt_sint32 currList() { return CurrList; };
    inline dgt_void rewind() {
        CurrPos = -1;
        CurrNode = 0;
    }

    PccHashNode* addNode(dgt_uint64 key, dgt_void* value);
    PccHashNode* findNode(dgt_uint64 key);
    dgt_sint32 removeNode(dgt_uint64 key);
    PccHashNode* nextNode();
};

#endif
