#include "PccCryptBuffer.h"

PccSegment::PccSegment(dgt_uint32 so,dgt_uint32 eo,dgt_uint8 st,dgt_uint16 col_no,dgt_sint32 expr_no, dgt_schar* expr)
	: Soffset(so), Eoffset(eo), Type(st), ColNo(col_no), ExprNo(expr_no), Expr(expr), Prev(0), Next(0)
{
}

PccSegment::~PccSegment()
{
}

dgt_sint8 PccSegment::compare(DgcObject* obj)
{
	if (obj == 0) return -1; // null object is the biggest
	dgt_sint32 soffset = ((PccSegment*)obj)->sOffset();
	dgt_sint32 eoffset = ((PccSegment*)obj)->eOffset();
	if ((soffset <= Soffset && Soffset < eoffset) || (Soffset <= soffset && soffset < Eoffset)) return 0;
	else if (Soffset > soffset) return 1;
	return -1;
}

PccSortedSegList::PccSortedSegList()
	: First(0), Last(0), Curr(0), NumPttnSegs(0), NumTextSegs(0)
{
}

PccSortedSegList::~PccSortedSegList()
{
	PccSegment* curr = First;
	for(;curr;) {
		PccSegment* tmp = curr;
		curr = curr->next();
		delete tmp;
	}
}

dgt_void PccSortedSegList::add(PccSegment* seg)
{
	if (seg) {
		NumPttnSegs++;
		if (First == 0) { // empty list
			First=Last=seg;
		} else {
			PccSegment* curr = Last; // from the last
			for(;curr;) {
				dgt_sint8 cmp_val;
				if ((cmp_val=seg->compare(curr)) > 0) {
					// inserting the seg next to the curr
					PccSegment* next = curr->next();
					seg->setPrev(curr);
					seg->setNext(next);
					curr->setNext(seg);
					if (next) next->setPrev(seg);
 					else Last = seg; // change the Last because the curr is the Last
					seg = 0;
					break;
				} else if (cmp_val == 0) {
					// the longer pattern has preference
					if (seg->eOffset() > curr->eOffset()) curr->update(seg);
					delete seg;
					seg = 0;
					break;
				}
				curr = curr->prev(); // move backward
			}
			if (seg) { // the seg is the smallest
				// inserting the seg before the First
				seg->setNext(First);
				First->setPrev(seg);
				First = seg; // change the First
			}
		}
	}
}

dgt_void PccSortedSegList::complete(dgt_sint32 last_eo) // last_eo is the length of the text to be searched
{
	//
	// Segment List has only pattern segments before completion.
	// First, Last, and in-between segment that is between two pattern segments 
	// should be added.
	// complete is a process that all text segments have been added at their correct position.
	//
	rewind();
	//
	// for the first text segment
	//
	PccSegment* curr = next();
	PccSegment* tmp;
	if (curr && curr->sOffset()) {
		// insert the first text segment only if the first pattern segment's starting offset > 0
		tmp = new PccSegment(0,curr->sOffset(),PccSegment::SEG_T_TEXT);
		tmp->setNext(curr);
		curr->setPrev(tmp);
		NumTextSegs++;
	}
	//
	// for in-between text segments
	//
	PccSegment* prev = curr;
	if (prev) {
		for(;(curr=curr->next());) {
			if (prev->eOffset() != curr->sOffset()) {
				// insert the in-between text segment between prev and curr
				tmp = new PccSegment(prev->eOffset(),curr->sOffset(),PccSegment::SEG_T_TEXT);
				tmp->setNext(curr);
				tmp->setPrev(prev);
				prev->setNext(tmp);
				curr->setPrev(tmp);
				NumTextSegs++;
			}
			prev = curr;
		}
	}
	if (prev) { // there're pattern segments
		if (prev->eOffset() < last_eo) {
			// insert the last text segment only if the last pattern segment's ending offset < text length
			tmp = new PccSegment(prev->eOffset(),last_eo,PccSegment::SEG_T_TEXT);
			tmp->setPrev(prev);
			prev->setNext(tmp);
			NumTextSegs++;
		}
		if (First->prev()) First = First->prev(); // change the First
		if (Last->next()) Last = Last->next(); // change the Last
	} else {
		// no pattern segment means one single text segment
		First=Last=new PccSegment(0,last_eo,PccSegment::SEG_T_TEXT);
		NumTextSegs++;
	}
	rewind();
}

PccCryptBuffer::PccCryptBuffer()
	: SeqNo(0), Next(0), SegList(0), SrcDataPtr(0), DstDataPtr(0), SrcLength(0), DstLength(0), FirstSplitPttnOffset(0), FirstSplitPttnChar(0), LastFlag(0)
{
}

PccCryptBuffer::~PccCryptBuffer()
{
	if (SegList) delete SegList;
}

dgt_void PccCryptBuffer::readReset(dgt_uint64 seq_no,dgt_sint32 src_length,dgt_sint32 dst_length)
{
	SeqNo = seq_no;
	Next = 0;
	delete SegList;
	SegList = 0;
	SrcLength = src_length;
	DstLength = dst_length;
	FirstSplitPttnOffset = 0;
	FirstSplitPttnChar = 0;
}
