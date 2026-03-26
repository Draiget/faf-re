#include "moho/render/SEfxCurve.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* SEfxCurve::sType = nullptr;

  gpg::RType* SEfxCurve::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SEfxCurve));
    }
    return sType;
  }

  /**
   * Address: 0x00514D40 (FUN_00514D40, Moho::SEfxCurveSerializer::Deserialize)
   */
  void SEfxCurve::DeserializeFromArchive(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const curve = reinterpret_cast<SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00514D50 (FUN_00514D50, Moho::SEfxCurveSerializer::Serialize)
   */
  void SEfxCurve::SerializeToArchive(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const curve = reinterpret_cast<const SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberSerialize(archive);
  }

  /**
   * Address: 0x00516D20 (FUN_00516D20, Moho::SEfxCurve::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall func_ReadArchive_SEfxCurve(Moho::SEfxCurve *a1@<eax>, gpg::ReadArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Read(vector2Type, &mBoundsMin, nullOwner);
    archive->Read(vector2Type, &mBoundsMax, nullOwner);
    archive->Read(keyVectorType, &mKeys, nullOwner);
  }

  /**
   * Address: 0x00516DD0 (FUN_00516DD0, Moho::SEfxCurve::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::SEfxCurve::MemberSerialize(Moho::SEfxCurve *a1@<eax>, BinaryWriteArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Write(vector2Type, &mBoundsMin, nullOwner);
    archive->Write(vector2Type, &mBoundsMax, nullOwner);
    archive->Write(keyVectorType, &mKeys, nullOwner);
  }
} // namespace moho
