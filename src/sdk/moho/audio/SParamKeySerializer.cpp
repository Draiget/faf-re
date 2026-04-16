#include "moho/audio/SParamKeySerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

namespace
{
  using Serializer = moho::SParamKeySerializer;

  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

  alignas(Serializer) unsigned char gSParamKeySerializerStorage[sizeof(Serializer)];
  bool gSParamKeySerializerConstructed = false;

  [[nodiscard]] Serializer& GetSParamKeySerializer() noexcept
  {
    return *reinterpret_cast<Serializer*>(gSParamKeySerializerStorage);
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(Serializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
    return SerializerSelfNode(serializer);
  }

  void cleanup_SParamKeySerializer_atexit()
  {
    (void)moho::cleanup_SParamKeySerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004DEFD0 (FUN_004DEFD0, Moho::SParamKeySerializer::Deserialize)
   */
  void SParamKeySerializer::Deserialize(gpg::ReadArchive* const archive, SParamKey* const key)
  {
    archive->ReadString(&key->mCueName);
    archive->ReadString(&key->mBankName);
    archive->ReadString(&key->mLodCutoffVariableName);
    archive->ReadString(&key->mRpcLoopVariableName);
  }

  /**
   * Address: 0x004DF010 (FUN_004DF010, Moho::SParamKeySerializer::Serialize)
   */
  void SParamKeySerializer::Serialize(gpg::WriteArchive* const archive, SParamKey* const key)
  {
    archive->WriteString(&key->mCueName);
    archive->WriteString(&key->mBankName);
    archive->WriteString(&key->mLodCutoffVariableName);
    archive->WriteString(&key->mRpcLoopVariableName);
  }

  /**
   * Address: 0x004E1600 (FUN_004E1600)
   */
  void SParamKeySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SParamKey::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SParamKey));
      SParamKey::sType = type;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationSourcePath);
    }
    type->serLoadFunc_ = mDeserialize;

    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationSourcePath);
    }
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF0E50 (FUN_00BF0E50, Moho::SParamKeySerializer::dtr)
   */
  SParamKeySerializer::~SParamKeySerializer() noexcept
  {
    (void)UnlinkSerializerNode(*this);
  }

  /**
   * Address: 0x004DF080 (FUN_004DF080)
   *
   * What it does:
   * Unlinks the global `SParamKeySerializer` helper node and rewires it as a
   * self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_SParamKeySerializer_alias0()
  {
    if (!gSParamKeySerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(GetSParamKeySerializer());
  }

  /**
   * Address: 0x004DF0B0 (FUN_004DF0B0)
   *
   * What it does:
   * Alias lane of `cleanup_SParamKeySerializer_alias0` with identical
   * unlink-and-self-link behavior.
   */
  gpg::SerHelperBase* cleanup_SParamKeySerializer_alias1()
  {
    return cleanup_SParamKeySerializer_alias0();
  }

  /**
    * Alias of FUN_00BF0E50 (non-canonical helper lane).
   */
  gpg::SerHelperBase* cleanup_SParamKeySerializer()
  {
    if (!gSParamKeySerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(GetSParamKeySerializer());
  }

  /**
   * Address: 0x00BC6860 (FUN_00BC6860, register_SParamKeySerializer)
   */
  void register_SParamKeySerializer()
  {
    if (!gSParamKeySerializerConstructed) {
      new (gSParamKeySerializerStorage) SParamKeySerializer();
      gSParamKeySerializerConstructed = true;
    }

    SParamKeySerializer& serializer = GetSParamKeySerializer();
    InitializeSerializerNode(serializer);
    serializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&SParamKeySerializer::Deserialize);
    serializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&SParamKeySerializer::Serialize);
    (void)std::atexit(&cleanup_SParamKeySerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SParamKeySerializerBootstrap
  {
    SParamKeySerializerBootstrap()
    {
      moho::register_SParamKeySerializer();
    }
  };

  [[maybe_unused]] SParamKeySerializerBootstrap gSParamKeySerializerBootstrap;
} // namespace
