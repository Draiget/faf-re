#include "moho/serialization/SSavedGameArmyInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  moho::SSavedGameArmyInfoTypeInfo gSavedGameArmyInfoTypeInfo;

  // Address: 0x010C4D88 -- process-global `SSavedGameArmyInfoSerializer` singleton.
  moho::SSavedGameArmyInfoSerializer gSavedGameArmyInfoSerializer;

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

  /**
   * Address: 0x00880040 (FUN_00880040, Moho::SSavedGameArmyInfoSerializer::Deserialize)
   */
  void SSavedGameArmyInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const info = reinterpret_cast<SSavedGameArmyInfo*>(objectPtr);
    archive->ReadString(&info->mPlayerName);
  }

  /**
   * Address: 0x00880060 (FUN_00880060, Moho::SSavedGameArmyInfoSerializer::Serialize)
   */
  void SSavedGameArmyInfoSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const info = reinterpret_cast<SSavedGameArmyInfo*>(objectPtr);
    archive->WriteString(&info->mPlayerName);
  }

  /**
   * Address: 0x00BE6FE0 (FUN_00BE6FE0, register_SSavedGameArmyInfoSerializer,
   * dynamic initializer for the global `SSavedGameArmyInfoSerializer`
   * singleton)
   */
  SSavedGameArmyInfoSerializer::SSavedGameArmyInfoSerializer()
    : mSerLoadFunc(&SSavedGameArmyInfoSerializer::Deserialize)
    , mSerSaveFunc(&SSavedGameArmyInfoSerializer::Serialize)
  {}

  /**
   * Address: 0x00C07CC0 (FUN_00C07CC0)
   */
  SSavedGameArmyInfoSerializer::~SSavedGameArmyInfoSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00882090 (FUN_00882090, Moho::SSavedGameArmyInfoSerializer::Init)
   *
   * What it does:
   * Registers load/save callbacks for SSavedGameArmyInfo.
   */
  void SSavedGameArmyInfoSerializer::Init()
  {
    gpg::RType* const type = SSavedGameArmyInfo::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSavedGameArmyInfoTypeInfo_ed43fe, preregister_SSavedGameArmyInfoTypeInfo)
