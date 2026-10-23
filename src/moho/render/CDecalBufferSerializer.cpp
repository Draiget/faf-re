#include "moho/render/CDecalBufferSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/Sim.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  // Defined in gpg/core/containers/ArchiveSerialization.cpp; builds one reflected
  // reference for a `moho::Sim*` while preserving derived runtime type.
} // namespace gpg

namespace
{

  [[nodiscard]] gpg::RType* CachedIdPoolType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00779CE0 (FUN_00779CE0)
   *
   * IDA signature:
   * void __usercall sub_779CE0(Moho::CDecalBuffer *buf@<eax>, BinaryWriteArchive *ar@<ebx>);
   *
   * What it does:
   * Walks the intrusive `CDecalHandle` list (head node at +0xCB8, node link at
   * +0x34 inside each handle) and writes each live handle as an owned tracked
   * pointer, matching the traversal used by `CreateHandle`/`DestroyHandle`.
   * Terminates with a null owned-pointer sentinel so the reader stops.
   */
  void WriteDecalHandles(const CDecalBuffer* const buf, gpg::WriteArchive* const ar)
  {
    const auto* const listHead = static_cast<const CDecalHandleListNode*>(&buf->mHandleListHead);

    for (CDecalHandleListNode* node = buf->mHandleListHead.mNext; node != listHead; node = node->mNext) {
      // Preserve the binary's `ptr != nullptr ? handle : nullptr` guard even
      // though loop nodes are always non-null before the sentinel.
      CDecalHandle* const handle = (node != nullptr) ? CDecalHandle::FromListNode(node) : nullptr;

      ar->WritePointer<moho::CDecalHandle>(handle, gpg::TrackedPointerState::Owned, gpg::RRef{});
    }

    ar->WritePointer<moho::CDecalHandle*>(nullptr, gpg::TrackedPointerState::Owned, gpg::RRef{});
  }

  /**
   * Address: 0x0077F0F0 (FUN_0077F0F0)
   *
   * IDA signature:
   * void __usercall sub_77F0F0(gpg::ReadArchive *ar@<eax>, Moho::CDecalBuffer *buf@<esi>);
   *
   * What it does:
   * Load body for one `CDecalBuffer`: reads the owning `Sim` (+0x00) as a
   * tracked pointer, the `IdPool` sub-object (+0x08) via reflection with a
   * lazily-resolved `RType`, then the owned decal-handle list. Each lane gets
   * its own zeroed owner reference, matching the two locals the binary clears
   * at 0x0077F106 and 0x0077F11A.
   */
  void CDecalBuffer::MemberDeserialize(gpg::ReadArchive* const ar)
  {
    const gpg::RRef simRef{};
    (void)ar->ReadPointer(&mSim, &simRef);

    ar->Read(CachedIdPoolType(), &mPool, gpg::RRef{});

    ReadDecalHandles(ar);
  }

  /**
   * Address: 0x0077F160 (FUN_0077F160)
   *
   * IDA signature:
   * void __usercall sub_77F160(BinaryWriteArchive *ar@<eax>, Moho::CDecalBuffer *buf@<esi>);
   *
   * What it does:
   * Save body for one `CDecalBuffer`: writes the owning `Sim` (+0x00) as an
   * unowned tracked pointer, the `IdPool` sub-object (+0x08) via reflection with
   * a lazily-resolved `RType`, then the owned decal-handle list.
   */
  void CDecalBuffer::MemberSerialize(gpg::WriteArchive* const ar) const
  {
    ar->WritePointer<moho::Sim>(mSim, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    ar->Write(CachedIdPoolType(), &mPool, gpg::RRef{});

    WriteDecalHandles(this, ar);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CDecalBuffer>`, vtable 0x00E373D8.
   *
   * Address: 0x00BDD880 (FUN_00BDD880 -- constructs the global and registers its destructor.)
   * Address: 0x00C028B0 (FUN_00C028B0 -- the global's destructor.)
   * Address: 0x00779C50 (FUN_00779C50 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0077AB00 (FUN_0077AB00 -- `Init`.)
   * Address: 0x00779C30 (FUN_00779C30 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00779C40 (FUN_00779C40 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CDecalBufferSerializer : gpg::SerSaveLoadHelper<CDecalBuffer>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BBD0C -- process-global `CDecalBufferSerializer` singleton.
  moho::CDecalBufferSerializer gCDecalBufferSerializer;
} // namespace
