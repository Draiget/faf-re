#include "moho/resource/CSimResourcesSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  using Serializer = moho::CSimResourcesSerializer;

  Serializer gCSimResourcesSerializer{};

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

  [[nodiscard]] gpg::SerHelperBase* ResetCSimResourcesSerializerHelperLinks() noexcept
  {
    gCSimResourcesSerializer.mHelperNext->mPrev = gCSimResourcesSerializer.mHelperPrev;
    gCSimResourcesSerializer.mHelperPrev->mNext = gCSimResourcesSerializer.mHelperNext;
    gpg::SerHelperBase* const self = SerializerSelfNode(gCSimResourcesSerializer);
    gCSimResourcesSerializer.mHelperPrev = self;
    gCSimResourcesSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00546C20 (FUN_00546C20)
   *
   * What it does:
   * Initializes callback lanes for global `CSimResourcesSerializer` helper
   * storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] Serializer* InitializeCSimResourcesSerializerStartupThunk() noexcept
  {
    InitializeSerializerNode(gCSimResourcesSerializer);
    gCSimResourcesSerializer.mDeserialize = &moho::CSimResourcesSerializer::Deserialize;
    gCSimResourcesSerializer.mSerialize = &moho::CSimResourcesSerializer::Serialize;
    return &gCSimResourcesSerializer;
  }

  /**
   * Address: 0x00546C50 (FUN_00546C50)
   *
   * What it does:
   * Unlinks `CSimResourcesSerializer` helper node from the intrusive helper
   * list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCSimResourcesSerializerHelperNodePrimary() noexcept
  {
    return ResetCSimResourcesSerializerHelperLinks();
  }

  /**
   * Address: 0x00546C80 (FUN_00546C80)
   *
   * What it does:
   * Secondary entrypoint for `CSimResourcesSerializer` helper-node unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupCSimResourcesSerializerHelperNodeSecondary() noexcept
  {
    return ResetCSimResourcesSerializerHelperLinks();
  }

  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] gpg::RType* ResolveResourceDepositVectorType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(msvc8::vector<moho::ResourceDeposit>));
    }
    return sType;
  }

  struct CSimResourcesSerializerStartup
  {
    CSimResourcesSerializerStartup()
    {
      moho::register_CSimResourcesSerializer();
    }
  };

  [[maybe_unused]] CSimResourcesSerializerStartup gCSimResourcesSerializerStartup;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546B80 (FUN_00546B80, Moho::CSimResourcesSerializer::Deserialize)
   */
  void CSimResourcesSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    CSimResources* const object = reinterpret_cast<CSimResources*>(objectPtr);
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Read(vectorType, &object->deposits_, NullOwnerRef());
  }

  /**
   * Address: 0x00546BD0 (FUN_00546BD0, Moho::CSimResourcesSerializer::Serialize)
   */
  void CSimResourcesSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    CSimResources* const object = reinterpret_cast<CSimResources*>(objectPtr);
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Write(vectorType, &object->deposits_, NullOwnerRef());
  }

  /**
   * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
   */
  void CSimResourcesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCSimResourcesType();
    resource_reflection::RegisterSerializeCallbacks(typeInfo, mDeserialize, mSerialize);
  }

  /**
   * Address: 0x00BF42C0 (FUN_00BF42C0, cleanup_CSimResourcesSerializer)
   */
  void cleanup_CSimResourcesSerializer()
  {
    (void)CleanupCSimResourcesSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x00BC96D0 (FUN_00BC96D0, register_CSimResourcesSerializer)
   */
  void register_CSimResourcesSerializer()
  {
    InitializeSerializerNode(gCSimResourcesSerializer);
    gCSimResourcesSerializer.mDeserialize = &CSimResourcesSerializer::Deserialize;
    gCSimResourcesSerializer.mSerialize = &CSimResourcesSerializer::Serialize;
    (void)std::atexit(&cleanup_CSimResourcesSerializer);
  }
} // namespace moho
