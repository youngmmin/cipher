#ifndef PCC_CRYPT_BUFFER_H
#define PCC_CRYPT_BUFFER_H

#include "PccFileCipherConstTypes.h"

class PccSegment : public DgcObject {
   private:
    dgt_sint32 Soffset;
    dgt_sint32 Eoffset;
    dgt_uint8 Type;
    dgt_uint16 ColNo;
    dgt_sint32 ExprNo;
    dgt_schar* Expr;
    PccSegment* Prev;
    PccSegment* Next;

   protected:
   public:
    static const dgt_uint8 SEG_T_TEXT = 1;
    static const dgt_uint8 SEG_T_PTTN = 2;
    static const dgt_uint8 SEG_T_TAG = 3;
    static const dgt_uint8 SEG_T_PASS = 4;
    static const dgt_uint8 SEG_T_PTTN_NULL =
        5;  // this type is only space character and apply padding

    PccSegment(dgt_uint32 so, dgt_uint32 eo, dgt_uint8 st,
               dgt_uint16 col_no = 0, dgt_sint32 expr_no = 0,
               dgt_schar* expr = 0);
    virtual ~PccSegment();

    dgt_sint32 adjustsOffset(dgt_sint32 offset) { return Soffset += offset; }
    dgt_sint32 adjusteOffset(dgt_sint32 offset) { return Eoffset += offset; }
    dgt_sint32 sOffset() { return Soffset; }
    dgt_sint32 eOffset() { return Eoffset; }
    dgt_uint8 type() { return Type; }
    dgt_uint16 colNo() { return ColNo; }
    dgt_sint32 exprNo() { return ExprNo; }
    dgt_schar* expr() { return Expr; }
    dgt_sint32 length() { return Eoffset - Soffset; }
    PccSegment* prev() { return Prev; }
    PccSegment* next() { return Next; }
    dgt_void setNext(PccSegment* seg) { Next = seg; }
    dgt_void setPrev(PccSegment* seg) { Prev = seg; }
    dgt_void update(PccSegment* seg) {
        if (seg) {
            Soffset = seg->sOffset();
            Eoffset = seg->eOffset();
            Type = seg->type();
        }
    }

    virtual dgt_sint8 compare(DgcObject* obj);
};

class PccSortedSegList : public DgcObject {
   private:
    PccSegment* First;
    PccSegment* Last;
    PccSegment* Curr;
    dgt_sint32 NumPttnSegs;
    dgt_sint32 NumTextSegs;

   protected:
   public:
    PccSortedSegList();
    virtual ~PccSortedSegList();

    dgt_sint32 numPttnSegs() { return NumPttnSegs; }
    dgt_sint32 numTextSegs() { return NumTextSegs; }
    dgt_void rewind() { Curr = First; }
    PccSegment* next() {
        PccSegment* rtn = Curr;
        if (Curr) Curr = Curr->next();
        return rtn;
    }

    dgt_void add(PccSegment* seg);
    dgt_void complete(dgt_sint32 last_eo);
};

class PccCryptBuffer : public DgcObject {
   public:
    dgt_uint64 SeqNo;           // sequence number
    PccCryptBuffer* Next;       // next pointer for the free list & fifo queue
    PccSortedSegList* SegList;  // segment list
    dgt_uint8* SrcDataPtr;      // source data pointer
    dgt_uint8* DstDataPtr;      // destination data pointer
    dgt_sint32 SrcLength;       // source buffer length including adjust size
    dgt_sint32 DstLength;       // crypted data length
    dgt_sint32 FirstSplitPttnOffset;  // the first split pattern offset
    dgt_uint8 FirstSplitPttnChar;     // the first split pattern first char
    dgt_uint8 LastFlag;               // last buffer
    PccCryptBuffer();
    virtual ~PccCryptBuffer();

    dgt_void readReset(dgt_uint64 seq_no, dgt_sint32 src_length,
                       dgt_sint32 dst_length);
};

#endif
