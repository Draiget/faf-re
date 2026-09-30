#include "moho/serialization/SSavedGameArmyInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  moho::SSavedGameArmyInfoTypeInfo gSavedGameArmyInfoTypeInfo;

  /**
   * Address: 0x0087FF00 (FUN_0087FF00, preregister_SSavedGameArmyInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::SSavedGameArmyInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SSavedGameArmyInfoTypeInfo()
  {
    gpg::PreRegisterRType(typeid(moho::SSavedGameArmyInfo), &gSavedGameArmyInfoTypeInfo);
    return &gSavedGameArmyInfoTypeInfo;
  }
} // namespace

namespace moho
{
  gpg::RType* SSavedGameArmyInfo::sType = nullptr;

  gpg::RType* SSavedGameArmyInfo::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SSavedGameArmyInfo));
    }
    return sType;
  }

  /**
   * Address: 0x0087FF80 (FUN_0087FF80)
   */
  const char* SSavedGameArmyInfoTypeInfo::GetName() const
  {
    return "SSavedGameArmyInfo";
  }

  /**
   * Address: 0x0087FF60 (FUN_0087FF60)
   */
  void SSavedGameArmyInfoTypeInfo::Init()
  {
    size_ = sizeof(SSavedGameArmyInfo);
    gpg::RType::Init();
    Finish();
  }

} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSavedGameArmyInfoTypeInfo_ed43fe, preregister_SSavedGameArmyInfoTypeInfo)

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<SSavedGameArmyInfo>::Deserialize` 0x00880040.
   */
  void SSavedGameArmyInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->ReadString(&mPlayerName);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<SSavedGameArmyInfo>::Serialize` 0x00880060.
   */
  void SSavedGameArmyInfo::MemberSerialize(gpg::WriteArchive* const archive)
  {
    archive->WriteString(&mPlayerName);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSavedGameArmyInfo>`, vtable 0x00E49CF0.
   *
   * Address: 0x00BE6FE0 (FUN_00BE6FE0 -- constructs the global and registers its destructor.)
   * Address: 0x00C07CC0 (FUN_00C07CC0 -- the global's destructor.)
   * Address: 0x00882090 (FUN_00882090 -- `Init`.)
   * Address: 0x00880040 (FUN_00880040 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00880060 (FUN_00880060 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SSavedGameArmyInfoSerializer : gpg::SerSaveLoadHelper<SSavedGameArmyInfo>
  {};
} // namespace moho

namespace
{
  // Address: 0x010C4D88 -- process-global `SSavedGameArmyInfoSerializer` singleton.
  moho::SSavedGameArmyInfoSerializer gSSavedGameArmyInfoSerializer;
} // namespace
