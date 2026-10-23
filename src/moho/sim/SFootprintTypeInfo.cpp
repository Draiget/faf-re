#include "moho/sim/SFootprintTypeInfo.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SFootprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  /**
   * Address: 0x00BF22F0 (FUN_00BF22F0, atexit destructor of the SFootprintTypeInfo object)
   */
  [[nodiscard]] moho::SFootprintTypeInfo* AcquireSFootprintTypeInfo()
  {
    static moho::SFootprintTypeInfo sInstance;
    return &sInstance;
  }
} // namespace

namespace moho
{
  gpg::RType* SFootprint::sType = nullptr;

  /**
   * Address: 0x0050AEE0 (FUN_0050AEE0)
   *
   * What it does:
   * Returns whether two footprint payload lanes are byte-identical across the
   * full 0x10-byte `SFootprint` layout.
   */
  [[maybe_unused]] [[nodiscard]] bool AreSFootprintBytesEqual(
    const SFootprint& lhs,
    const SFootprint& rhs
  ) noexcept
  {
    return std::memcmp(&lhs, &rhs, sizeof(SFootprint)) == 0;
  }

  /**
   * Address: 0x0050C410 (FUN_0050C410, Moho::SFootprintTypeInfo::SFootprintTypeInfo)
   *
   * What it does:
   * Preregisters the `SFootprint` RTTI descriptor with the reflection map.
   */
  SFootprintTypeInfo::SFootprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SFootprint), this);
  }

  /**
   * Address: 0x0050C4A0 (FUN_0050C4A0, Moho::SFootprintTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SFootprintTypeInfo::~SFootprintTypeInfo() = default;

  /**
   * Address: 0x0050C490 (FUN_0050C490, Moho::SFootprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SFootprint`.
   */
  const char* SFootprintTypeInfo::GetName() const
  {
    return "SFootprint";
  }

  /**
   * Address: 0x0050C470 (FUN_0050C470, Moho::SFootprintTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size, installs field metadata, and finalizes the type.
   */
  void SFootprintTypeInfo::Init()
  {
    size_ = sizeof(SFootprint);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050C540 (FUN_0050C540, Moho::SFootprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers reflected lanes for all `SFootprint` members in binary order.
   */
  void SFootprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->AddField<unsigned char>("SizeX", offsetof(SFootprint, mSizeX));
    typeInfo->AddField<unsigned char>("SizeZ", offsetof(SFootprint, mSizeZ));
    typeInfo->AddField<float>("MaxSlope", offsetof(SFootprint, mMaxSlope));
    typeInfo->AddField<float>("MinWaterDepth", offsetof(SFootprint, mMinWaterDepth));
    typeInfo->AddField<unsigned char>("OccupancyCaps", offsetof(SFootprint, mOccupancyCaps));
    typeInfo->AddField<unsigned char>("Flags", offsetof(SFootprint, mFlags));
  }

  /**
   * Address: 0x0050D090 (FUN_0050D090, Moho::SFootprint::MemberDeserialize)
   *
   * What it does:
   * Loads the footprint fields in the exact binary archive order.
   */
  void SFootprint::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    archive->ReadUByte(&mSizeX);
    archive->ReadUByte(&mSizeZ);
    archive->ReadFloat(&mMaxSlope);
    archive->ReadFloat(&mMinWaterDepth);
    archive->ReadUByte(reinterpret_cast<unsigned char*>(&mOccupancyCaps));
    archive->ReadUByte(reinterpret_cast<unsigned char*>(&mFlags));
  }

  /**
   * Address: 0x0050D0E0 (FUN_0050D0E0, Moho::SFootprint::MemberSerialize)
   *
   * What it does:
   * Writes the footprint fields in the exact binary archive order.
   */
  void SFootprint::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    archive->WriteUByte(mSizeX);
    archive->WriteUByte(mSizeZ);
    archive->WriteFloat(mMaxSlope);
    archive->WriteFloat(mMinWaterDepth);
    archive->WriteUByte(static_cast<unsigned char>(mOccupancyCaps));
    archive->WriteUByte(static_cast<unsigned char>(mFlags));
  }

  /**
   * Address: 0x00BC7E40 (FUN_00BC7E40, register_SFootprintTypeInfo)
   *
   * What it does:
   * Constructs the static `SFootprintTypeInfo` instance, which preregisters it.
   */
  void register_SFootprintTypeInfo()
  {
    (void)AcquireSFootprintTypeInfo();
  }

} // namespace moho

namespace
{
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SFootprintTypeInfo_d68759, moho::register_SFootprintTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SFootprint>`, vtable 0x00E0DE2C.
   *
   * Address: 0x00BC7E60 (FUN_00BC7E60 -- constructs the global and registers its destructor.)
   * Address: 0x00BF2350 (FUN_00BF2350 -- the global's destructor.)
   * Address: 0x0050C5D0 (FUN_0050C5D0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0050C9B0 (FUN_0050C9B0 -- `Init`.)
   * Address: 0x0050C5A0 (FUN_0050C5A0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0050C5B0 (FUN_0050C5B0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SFootprintSerializer : gpg::SerSaveLoadHelper<SFootprint>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AA42C -- process-global `SFootprintSerializer` singleton.
  moho::SFootprintSerializer gSFootprintSerializer;
} // namespace
