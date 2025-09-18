// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/vision/VisionDB.h"
using namespace moho;

void VisionDB::Pool::FreeZoneArraysOnly(ZoneNode* head)
{
    if (!head) return;
    for (ZoneNode* it = static_cast<ZoneNode*>(head->mNext); it != head; it = static_cast<ZoneNode*>(it->mNext)) {
        if (it->items40) {
            ::operator delete[](it->items40);
            it->items40 = nullptr;
        }
    }
}

VisionDB::Pool::Pool()
{
    // Heads are heap-allocated sentinels (as in asm).
    zones_ = new ZoneNode();
    zoneCount_ = 0;
    pad0_ = 0;
    handlesHead_ = new HandleNode();
    handleCount_ = 0;

    ResetCircle(zones_);
    ResetCircle(handlesHead_);
}

void VisionDB::Pool::Clear()
{
    // sub_81AD20: free arrays in zones first
    FreeZoneArraysOnly(zones_);

    // handles list: reset ring, zero count, delete nodes, delete head, null it
    ResetCircle(handlesHead_);
    handleCount_ = 0;
    DeleteRange(handlesHead_);
    ::operator delete(handlesHead_);
    handlesHead_ = nullptr;

    // zones list: reset ring, zero count, delete nodes, delete head, null it
    ResetCircle(zones_);
    zoneCount_ = 0;
    DeleteRange(zones_);
    ::operator delete(zones_);
    zones_ = nullptr;
}

VisionDB::Pool::~Pool()
{
    Clear();
}

VisionDB::Handle* VisionDB::Handle::Init(
    Handle* self,
    const std::uintptr_t linkPtr,
    const std::uintptr_t ownerPtr)
{
    if (!self) {
        return nullptr;
    }
    self->ownerPtr_ = ownerPtr;   // v1 = a3
    self->linkPtr_ = linkPtr;    // v2 = a2
    return self;
}

/**
 * Raw unlink helper that assumes first two fields are mPrev, mNext pointers.
 */
void VisionDB::Handle::EraseNode(void* node)
{
    if (!node) {
        return;
    }

    struct RawLink {
        RawLink* mPrev;
        RawLink* mNext;
    };

    auto* n = static_cast<RawLink*>(node);
    auto* p = n->mPrev;
    auto* q = n->mNext;

    if (p && q) {
        p->mNext = q;
        q->mPrev = p;
        n->mPrev = n;
        n->mNext = n;
    }
}

/**
 *
 * Best-effort owner unbind emulation (original calls sub_81ABF0(owner+4, node)).
 */
void VisionDB::Handle::UnbindFromOwner(std::uintptr_t /*ownerPlus4*/, void* /*node*/)
{
    // Semantics unknown yet; kept as a stub to match call pattern.
}

VisionDB::Handle::~Handle()
{
    // sub_81AE20 pattern: unlink by v2, then unbind by (v1+4, v2)
    EraseNode(reinterpret_cast<void*>(linkPtr_));
    if (ownerPtr_) {
        UnbindFromOwner(ownerPtr_ + 4u, reinterpret_cast<void*>(linkPtr_));
    }

    ownerPtr_ = 0;
    linkPtr_ = 0;
}

VisionDB::VisionDB()
    : pool_()
    , unknown_(nullptr)
{
    // sub_81AE90: vptr set by compiler, Pool constructed, a1[8] = 0
}

VisionDB::~VisionDB()
{
    // 0x0081AEB0: nothing special beyond member destruction
    unknown_ = nullptr;
}
