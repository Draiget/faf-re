#include "moho/resource/CSimResourcesTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  alignas(moho::CSimResourcesTypeInfo) unsigned char gCSimResourcesTypeInfoStorage[sizeof(moho::CSimResourcesTypeInfo)];
  bool gCSimResourcesTypeInfoConstructed = false;

  [[nodiscard]] moho::CSimResourcesTypeInfo& AcquireCSimResourcesTypeInfo()
  {
    if (!gCSimResourcesTypeInfoConstructed) {
      new (gCSimResourcesTypeInfoStorage) moho::CSimResourcesTypeInfo();
      gCSimResourcesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::CSimResourcesTypeInfo*>(gCSimResourcesTypeInfoStorage);
  }

  void cleanup_CSimResourcesTypeInfo()
  {
    if (!gCSimResourcesTypeInfoConstructed) {
      return;
    }

    AcquireCSimResourcesTypeInfo().~CSimResourcesTypeInfo();
    gCSimResourcesTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00546B30 (FUN_00546B30)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `CSimResourcesTypeInfo`.
   */
  [[maybe_unused]] void cleanup_CSimResourcesTypeInfoRTypeBase(moho::CSimResourcesTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00546B70 (FUN_00546B70)
   *
   * What it does:
   * Register-shape adapter that forwards one reflected type lane into
   * `CSimResourcesTypeInfo` base-registration semantics.
   */
  [[maybe_unused]] void AddBaseISimResourcesRegistrationThunk(gpg::RType* const typeInfo)
  {
    moho::resource_reflection::AddBase(typeInfo, moho::resource_reflection::ResolveISimResourcesType());
  }

  struct CSimResourcesTypeInfoCallbackLaneView
  {
    unsigned char reserved00_47[0x48];
    gpg::RType::new_ref_func_t newRefFunc;   // +0x48
    gpg::RType::cpy_ref_func_t cpyRefFunc;   // +0x4C
    gpg::RType::delete_func_t deleteFunc;    // +0x50
    gpg::RType::ctor_ref_func_t ctorRefFunc; // +0x54
    gpg::RType::mov_ref_func_t movRefFunc;   // +0x58
    gpg::RType::dtr_func_t dtrFunc;          // +0x5C
    bool v24;                                // +0x60
    unsigned char reserved61_63[0x03];
  };

  static_assert(
    offsetof(CSimResourcesTypeInfoCallbackLaneView, newRefFunc) == 0x48,
    "CSimResourcesTypeInfoCallbackLaneView::newRefFunc offset must be 0x48"
  );
  static_assert(
    offsetof(CSimResourcesTypeInfoCallbackLaneView, deleteFunc) == 0x50,
    "CSimResourcesTypeInfoCallbackLaneView::deleteFunc offset must be 0x50"
  );
  static_assert(
    offsetof(CSimResourcesTypeInfoCallbackLaneView, ctorRefFunc) == 0x54,
    "CSimResourcesTypeInfoCallbackLaneView::ctorRefFunc offset must be 0x54"
  );
  static_assert(
    offsetof(CSimResourcesTypeInfoCallbackLaneView, dtrFunc) == 0x5C,
    "CSimResourcesTypeInfoCallbackLaneView::dtrFunc offset must be 0x5C"
  );
  static_assert(sizeof(CSimResourcesTypeInfoCallbackLaneView) == 0x64, "Callback lane view size must be 0x64");

  /**
   * Address: 0x00547820 (FUN_00547820)
   *
   * What it does:
   * Writes one `gpg::RType` callback lane set for `CSimResources`
   * allocate/construct/delete/destruct behavior.
   */
  [[nodiscard]] moho::CSimResourcesTypeInfo* BindCSimResourcesTypeInfoCallbackLanes(
    moho::CSimResourcesTypeInfo* const typeInfo,
    const gpg::RType::new_ref_func_t newRefFunc,
    const gpg::RType::ctor_ref_func_t ctorRefFunc,
    const gpg::RType::delete_func_t deleteFunc,
    const gpg::RType::dtr_func_t dtrFunc
  ) noexcept
  {
    if (typeInfo == nullptr) {
      return nullptr;
    }

    auto* const lanes = reinterpret_cast<CSimResourcesTypeInfoCallbackLaneView*>(typeInfo);
    lanes->newRefFunc = newRefFunc;
    lanes->ctorRefFunc = ctorRefFunc;
    lanes->deleteFunc = deleteFunc;
    lanes->dtrFunc = dtrFunc;
    return typeInfo;
  }

  [[nodiscard]] gpg::RRef MakeCSimResourcesRef(moho::CSimResources* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::resource_reflection::ResolveCSimResourcesType();
    return out;
  }

  [[nodiscard]] gpg::RType* ResolveResourceDepositVectorType()
  {
    static gpg::RType* sResourceDepositVectorType = nullptr;
    if (sResourceDepositVectorType == nullptr) {
      sResourceDepositVectorType = gpg::LookupRType(typeid(msvc8::vector<moho::ResourceDeposit>));
    }
    return sResourceDepositVectorType;
  }

  /**
   * Address: 0x00548840 (FUN_00548840)
   *
   * What it does:
   * Lazily resolves reflected type for `vector<ResourceDeposit>` and
   * deserializes `CSimResources::deposits_`.
   */
  [[maybe_unused]] void DeserializeCSimResourcesDepositsPrimary(
    gpg::ReadArchive* const archive,
    moho::CSimResources* const object
  )
  {
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    gpg::RRef ownerRef{};
    archive->Read(vectorType, &object->deposits_, ownerRef);
  }

  /**
   * Address: 0x00548890 (FUN_00548890)
   *
   * What it does:
   * Lazily resolves reflected type for `vector<ResourceDeposit>` and
   * serializes `CSimResources::deposits_`.
   */
  [[maybe_unused]] void SerializeCSimResourcesDepositsPrimary(
    gpg::WriteArchive* const archive,
    moho::CSimResources* const object
  )
  {
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    gpg::RRef ownerRef{};
    archive->Write(vectorType, &object->deposits_, ownerRef);
  }

  /**
   * Address: 0x00549120 (FUN_00549120)
   *
   * What it does:
   * Secondary deserialize entrypoint for the same `CSimResources::deposits_`
   * archive lane.
   */
  [[maybe_unused]] void DeserializeCSimResourcesDepositsSecondary(
    gpg::ReadArchive* const archive,
    moho::CSimResources* const object
  )
  {
    DeserializeCSimResourcesDepositsPrimary(archive, object);
  }

  /**
   * Address: 0x00549170 (FUN_00549170)
   *
   * What it does:
   * Secondary serialize entrypoint for the same `CSimResources::deposits_`
   * archive lane.
   */
  [[maybe_unused]] void SerializeCSimResourcesDepositsSecondary(
    gpg::WriteArchive* const archive,
    moho::CSimResources* const object
  )
  {
    SerializeCSimResourcesDepositsPrimary(archive, object);
  }

  struct CSimResourcesTypeInfoStartup
  {
    CSimResourcesTypeInfoStartup()
    {
      moho::register_CSimResourcesTypeInfo();
    }
  };

  [[maybe_unused]] CSimResourcesTypeInfoStartup gCSimResourcesTypeInfoStartup;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546A20 (FUN_00546A20, Moho::CSimResourcesTypeInfo::CSimResourcesTypeInfo)
   */
  CSimResourcesTypeInfo::CSimResourcesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSimResources), this);
  }

  /**
   * Address: 0x00546AD0 (FUN_00546AD0, Moho::CSimResourcesTypeInfo::dtr)
   */
  CSimResourcesTypeInfo::~CSimResourcesTypeInfo() = default;

  /**
   * Address: 0x00546AC0 (FUN_00546AC0, Moho::CSimResourcesTypeInfo::GetName)
   */
  const char* CSimResourcesTypeInfo::GetName() const
  {
    return "CSimResources";
  }

  /**
   * Address: 0x00546A80 (FUN_00546A80, Moho::CSimResourcesTypeInfo::Init)
   */
  void CSimResourcesTypeInfo::Init()
  {
    size_ = sizeof(CSimResources);
    (void)BindCSimResourcesTypeInfoCallbackLanes(
      this,
      &CSimResourcesTypeInfo::NewRef,
      &CSimResourcesTypeInfo::CtrRef,
      &CSimResourcesTypeInfo::Delete,
      &CSimResourcesTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_ISimResources(this);
    Finish();
  }

  /**
   * Address: 0x005487E0 (FUN_005487E0, Moho::CSimResourcesTypeInfo::AddBase_ISimResources)
   */
  void CSimResourcesTypeInfo::AddBase_ISimResources(gpg::RType* const typeInfo)
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveISimResourcesType());
  }

  /**
   * Address: 0x005484A0 (FUN_005484A0, Moho::CSimResourcesTypeInfo::NewRef)
   */
  gpg::RRef CSimResourcesTypeInfo::NewRef()
  {
    CSimResources* const object = CSimResources::Create();
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548530 (FUN_00548530, Moho::CSimResourcesTypeInfo::CtrRef)
   */
  gpg::RRef CSimResourcesTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      new (object) CSimResources();
    }
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548510 (FUN_00548510, Moho::CSimResourcesTypeInfo::Delete)
   */
  void CSimResourcesTypeInfo::Delete(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      delete object;
    }
  }

  /**
   * Address: 0x005485A0 (FUN_005485A0, Moho::CSimResourcesTypeInfo::Destruct)
   */
  void CSimResourcesTypeInfo::Destruct(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    object->~CSimResources();
  }

  /**
   * Address: 0x00BC96B0 (FUN_00BC96B0, register_CSimResourcesTypeInfo)
   */
  void register_CSimResourcesTypeInfo()
  {
    (void)AcquireCSimResourcesTypeInfo();
    (void)std::atexit(&cleanup_CSimResourcesTypeInfo);
  }
} // namespace moho
