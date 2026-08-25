#include "moho/ai/HPathCellSerializer.h"

#include <bit>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiPathFinder.h"

namespace
{
  /**
   * Address: 0x00762F80 (FUN_00762F80, Moho::HPathCellSerializer::Deserialize)
   *
   * What it does:
   * Reflection LOAD adapter for `Moho::HPathCell`. The raw disassembly reads
   * the archive's own vtable slot +0x20 (`gpg::ReadArchive::ReadUInt`)
   * directly on the archive pointer with no per-field access at all -- the
   * `{x, z}` pair packs to exactly one `unsigned int` with no padding, so the
   * binary's wire format for `HPathCell` is a single packed 32-bit read.
   * `std::bit_cast` reproduces that packed transfer without raw pointer
   * punning.
   */
  void DeserializeHPathCellCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const cell = reinterpret_cast<moho::HPathCell*>(static_cast<std::uintptr_t>(objectPtr));
    static_assert(sizeof(moho::HPathCell) == sizeof(unsigned int), "HPathCell must pack to one unsigned int for archive I/O");

    unsigned int packed = 0;
    archive->ReadUInt(&packed);
    *cell = std::bit_cast<moho::HPathCell>(packed);
  }

  /**
   * Address: 0x00762FA0 (FUN_00762FA0, Moho::HPathCellSerializer::Serialize)
   *
   * What it does:
   * Reflection SAVE adapter for `Moho::HPathCell`: the exact inverse of
   * `DeserializeHPathCellCallback` above, dispatching through the archive's
   * own `WriteUInt` vtable slot on the packed `{x, z}` value.
   */
  void SerializeHPathCellCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto* const cell = reinterpret_cast<const moho::HPathCell*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteUInt(std::bit_cast<unsigned int>(*cell));
  }
} // namespace

namespace moho
{
  HPathCellSerializer gHPathCellSerializer;

  /**
   * Address: 0x00C016E0 (FUN_00C016E0, atexit-registered cleanup target)
   * ICF twins: 0x00762FF0 (FUN_00762FF0), 0x00763020 (FUN_00763020) --
   * identical unlink/self-link bodies hardcoded to the same global; only
   * 0x00C016E0 is the one `register_HPathCellSerializer` (0x00BDC630)
   * actually registers via `atexit`.
   *
   * What it does:
   * Unlinks this helper node from the intrusive serializer-helper list and
   * restores a self-linked sentinel state.
   */
  void cleanup_HPathCellSerializer()
  {
    gHPathCellSerializer.ResetLinks();
  }

  /**
   * Address: 0x00BDC630 (FUN_00BDC630, register_HPathCellSerializer,
   * dynamic initializer for the global `HPathCellSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
   * splices it into the process-global `sNewHelpers` pending list), then
   * binds the deserialize/serialize callback fields and installs
   * process-exit cleanup.
   */
  HPathCellSerializer::HPathCellSerializer()
    : mLoadCallback(&DeserializeHPathCellCallback)
    , mSaveCallback(&SerializeHPathCellCallback)
  {
    (void)std::atexit(&cleanup_HPathCellSerializer);
  }

  /**
   * Address: 0x007632D0 (FUN_007632D0, gpg::SerSaveLoadHelper<Moho::HPathCell>::Init)
   *
   * What it does:
   * Resolves `HPathCell` RTTI (via the cached `HPathCell::sType`, falling
   * back to `gpg::LookupRType(typeid(HPathCell))` on a cache miss) and binds
   * this helper's load/save callbacks into the reflected type descriptor.
   * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
   * drained from the pending list (vtable slot 0).
   */
  void HPathCellSerializer::Init()
  {
    gpg::RType* type = HPathCell::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(HPathCell));
      HPathCell::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
