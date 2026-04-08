#include "moho/sim/ManipulatorStartupRegistrations.h"

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAimManipulator.h"
#include "moho/ai/CAimManipulatorSerializer.h"
#include "moho/ai/CAimManipulatorTypeInfo.h"
#include "moho/animation/CSlideManipulator.h"
#include "moho/console/CConCommand.h"
#include "moho/containers/BitStorage32.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAimManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryIAniManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCBoneEntityManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCBuilderArmManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCCollisionManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCFootPlantManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAnimationManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCRotateManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCSlaveManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCSlideManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCStorageManipulatorIndex = 0;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCThrustManipulatorIndex = 0;

  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A18 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A08 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A20 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A20 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A38 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A38 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A64 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A64 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A7C = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A7C = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A98 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A98 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A98_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59A98_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B00_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B00_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59ACC = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59ACC = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59ACC_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59ACC_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B80 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B80 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B98 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B98 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B34 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B34 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B34_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B34_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B64 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B64 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59BB4 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59BB4 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59BCC = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59BCC = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59BE8 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59BE8 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59C00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59C00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59C1C = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59C1C = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59C34 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59C34 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59C50 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59C50 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59C68 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59C68 = nullptr;

  [[nodiscard]] moho::CScrLuaInitFormSet* FindLuaInitFormSetByName(const char* const setName) noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, setName) == 0) {
        return set;
      }
    }
    return nullptr;
  }

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  template <moho::CScrLuaInitForm** PrevLane, moho::CScrLuaInitForm** AnchorLane>
  [[nodiscard]] moho::CScrLuaInitForm* RegisterRecoveredSimInitLinkerLane() noexcept
  {
    moho::CScrLuaInitFormSet* const simSet = FindLuaInitFormSetByName("sim");
    if (simSet == nullptr) {
      *PrevLane = nullptr;
      return nullptr;
    }

    moho::CScrLuaInitForm* const result = simSet->mForms;
    *PrevLane = result;
    simSet->mForms = reinterpret_cast<moho::CScrLuaInitForm*>(AnchorLane);
    return result;
  }

  [[nodiscard]] moho::TConVar<bool>& StartupConVar_dbg_Ballistics() noexcept
  {
    static moho::TConVar<bool> conVar("dbg_Ballistics", "", &moho::dbg_Ballistics);
    return conVar;
  }

  class RVectorTypeBool final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  using VectorBoolStorage = moho::SBitStorage32;

  alignas(RVectorTypeBool) unsigned char gRecoveredRVectorTypeBoolStorage[sizeof(RVectorTypeBool)] = {};
  bool gRecoveredRVectorTypeBoolConstructed = false;
  thread_local bool gRecoveredRVectorTypeBoolSubscriptScratch = false;
  msvc8::string gRecoveredRVectorTypeBoolName;
  bool gRecoveredRVectorTypeBoolNameCleanupRegistered = false;

  [[nodiscard]] RVectorTypeBool* AcquireRecoveredRVectorTypeBool()
  {
    if (!gRecoveredRVectorTypeBoolConstructed) {
      new (gRecoveredRVectorTypeBoolStorage) RVectorTypeBool();
      gRecoveredRVectorTypeBoolConstructed = true;
    }

    return reinterpret_cast<RVectorTypeBool*>(gRecoveredRVectorTypeBoolStorage);
  }

  [[nodiscard]] gpg::RType* ResolveBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("bool");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVectorBoolElementType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  /**
   * Address: 0x00642580 (FUN_00642580, preregister_RVectorType_bool)
   *
   * What it does:
   * Constructs/preregisters startup reflection metadata for `std::vector<bool>`
   * using the packed bit-storage runtime view.
   */
  [[nodiscard]] gpg::RType* preregister_RVectorType_bool()
  {
    RVectorTypeBool* const type = AcquireRecoveredRVectorTypeBool();
    gpg::PreRegisterRType(typeid(std::vector<bool>), type);
    return type;
  }

  /**
   * Address: 0x00BFB080 (FUN_00BFB080, cleanup_RVectorType_bool)
   *
   * What it does:
   * Tears down startup-owned `std::vector<bool>` reflection metadata.
   */
  void cleanup_RVectorType_bool()
  {
    if (!gRecoveredRVectorTypeBoolConstructed) {
      return;
    }

    AcquireRecoveredRVectorTypeBool()->~RVectorTypeBool();
    gRecoveredRVectorTypeBoolConstructed = false;
  }

  void cleanup_RVectorTypeBoolName()
  {
    gRecoveredRVectorTypeBoolName.clear();
    gRecoveredRVectorTypeBoolNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00641C20 (FUN_00641C20, gpg::RVectorType_bool::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `vector<bool>` type name.
   */
  const char* RVectorTypeBool::GetName() const
  {
    if (gRecoveredRVectorTypeBoolName.empty()) {
      const gpg::RType* const elementType = CachedVectorBoolElementType();
      const char* const elementName = elementType ? elementType->GetName() : "bool";
      gRecoveredRVectorTypeBoolName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "bool");
      if (!gRecoveredRVectorTypeBoolNameCleanupRegistered) {
        gRecoveredRVectorTypeBoolNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_RVectorTypeBoolName);
      }
    }

    return gRecoveredRVectorTypeBoolName.c_str();
  }

  const gpg::RIndexed* RVectorTypeBool::IsIndexed() const
  {
    return this;
  }

  void RVectorTypeBool::Init()
  {
    size_ = sizeof(VectorBoolStorage);
    version_ = 1;
  }

  gpg::RRef RVectorTypeBool::SubscriptIndex(void* const obj, const int ind) const
  {
    auto* const storage = static_cast<VectorBoolStorage*>(obj);

    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = ResolveBoolType();
    if (!storage || ind < 0 || static_cast<std::uint32_t>(ind) >= storage->mBitCount) {
      return out;
    }

    gRecoveredRVectorTypeBoolSubscriptScratch = storage->TestBit(static_cast<std::uint32_t>(ind));
    out.mObj = &gRecoveredRVectorTypeBoolSubscriptScratch;
    return out;
  }

  size_t RVectorTypeBool::GetCount(void* const obj) const
  {
    const auto* const storage = static_cast<const VectorBoolStorage*>(obj);
    return storage ? static_cast<size_t>(storage->mBitCount) : 0u;
  }

  void RVectorTypeBool::SetCount(void* const obj, const int count) const
  {
    auto* const storage = static_cast<VectorBoolStorage*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(count >= 0);
    if (!storage || count < 0) {
      return;
    }

    storage->Resize(static_cast<std::uint32_t>(count), false);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD1980 (FUN_00BD1980, register_sim_SimInits_mForms_offVariant1)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A08`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant1()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A18, &gRecoveredSimLuaInitFormAnchor_off_F59A08>();
  }

  /**
   * Address: 0x00BD21F0 (FUN_00BD21F0, register_sim_SimInits_mForms_offVariant2)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A20`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant2()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A20, &gRecoveredSimLuaInitFormAnchor_off_F59A20>();
  }

  /**
   * Address: 0x00BD2210 (FUN_00BD2210, register_sim_SimInits_mForms_offVariant3)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A38`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant3()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A38, &gRecoveredSimLuaInitFormAnchor_off_F59A38>();
  }

  /**
   * Address: 0x00BFA8D0 (FUN_00BFA8D0, cleanup_TConVar_dbg_Ballistics)
   *
   * What it does:
   * Unregisters startup console convar `dbg_Ballistics`.
   */
  void cleanup_TConVar_dbg_Ballistics()
  {
    TeardownConCommandRegistration(StartupConVar_dbg_Ballistics());
  }

  /**
   * Address: 0x00BD2230 (FUN_00BD2230, register_TConVar_dbg_Ballistics)
   *
   * What it does:
   * Registers startup console convar `dbg_Ballistics` and installs process-exit
   * cleanup.
   */
  void register_TConVar_dbg_Ballistics()
  {
    RegisterConCommand(StartupConVar_dbg_Ballistics());
    (void)std::atexit(&cleanup_TConVar_dbg_Ballistics);
  }

  /**
   * Address: 0x00BD2350 (FUN_00BD2350, register_CScrLuaMetatableFactory_CAimManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CAimManipulator`.
   */
  int register_CScrLuaMetatableFactory_CAimManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCAimManipulatorIndex>();
  }

  /**
   * Address: 0x00BD2370 (FUN_00BD2370, register_CScrLuaMetatableFactory_IAniManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `IAniManipulator`.
   */
  int register_CScrLuaMetatableFactory_IAniManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryIAniManipulatorIndex>();
  }

  /**
   * Address: 0x00BD2400 (FUN_00BD2400, register_sim_SimInits_mForms_offVariant4)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A64`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant4()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A64, &gRecoveredSimLuaInitFormAnchor_off_F59A64>();
  }

  /**
   * Address: 0x00BD2420 (FUN_00BD2420, register_sim_SimInits_mForms_offVariant5)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A7C`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant5()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A7C, &gRecoveredSimLuaInitFormAnchor_off_F59A7C>();
  }

  /**
   * Address: 0x00BD24C0 (FUN_00BD24C0, register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CBoneEntityManipulator`.
   */
  int register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCBoneEntityManipulatorIndex>();
  }

  /**
   * Address: 0x00BD2550 (FUN_00BD2550, register_sim_SimInits_mForms_offVariant6)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A98`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant6()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A98, &gRecoveredSimLuaInitFormAnchor_off_F59A98>();
  }

  /**
   * Address: 0x00BD2570 (FUN_00BD2570, register_sim_SimInits_mForms_off_F59A98_mFactory)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to the
   * `off_F59A98.mFactory` lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59A98_mFactory()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59A98_mFactory, &gRecoveredSimLuaInitFormAnchor_off_F59A98_mFactory>();
  }

  /**
   * Address: 0x00BD2630 (FUN_00BD2630, register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CBuilderArmManipulator`.
   */
  int register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCBuilderArmManipulatorIndex>();
  }

  /**
   * Address: 0x00BD26C0 (FUN_00BD26C0, register_sim_SimInits_mForms_offVariant7)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59ACC`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant7()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59ACC, &gRecoveredSimLuaInitFormAnchor_off_F59ACC>();
  }

  /**
   * Address: 0x00BD26E0 (FUN_00BD26E0, register_sim_SimInits_mForms_off_F59ACC_mFactory)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to the
   * `off_F59ACC.mFactory` lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59ACC_mFactory()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59ACC_mFactory, &gRecoveredSimLuaInitFormAnchor_off_F59ACC_mFactory>();
  }

  /**
   * Address: 0x00BD27B0 (FUN_00BD27B0, register_CScrLuaMetatableFactory_CCollisionManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CCollisionManipulator`.
   */
  int register_CScrLuaMetatableFactory_CCollisionManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCCollisionManipulatorIndex>();
  }

  /**
   * Address: 0x00BD29C0 (FUN_00BD29C0, register_sim_SimInits_mForms_offVariant8)
   *
   * What it does:
   * Saves the current `sim` init-form head and relinks the list to
   * `off_F59B00`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant8()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B00, &gRecoveredSimLuaInitFormAnchor_off_F59B00>();
  }

  /**
   * Address: 0x00BD29E0 (FUN_00BD29E0, register_sim_SimInits_mForms_off_F59B00_mFactory)
   *
   * What it does:
   * Saves the current `sim` init-form head and relinks the list to the
   * `off_F59B00.mFactory` lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59B00_mFactory()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B00_mFactory, &gRecoveredSimLuaInitFormAnchor_off_F59B00_mFactory>();
  }

  /**
   * Address: 0x00BD2A70 (FUN_00BD2A70, register_CScrLuaMetatableFactory_CFootPlantManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CFootPlantManipulator`.
   */
  int register_CScrLuaMetatableFactory_CFootPlantManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCFootPlantManipulatorIndex>();
  }

  /**
   * Address: 0x00BD2C00 (FUN_00BD2C00, register_sim_SimInits_mForms_offVariant9)
   *
   * What it does:
   * Saves the current `sim` init-form head and relinks the list to
   * `off_F59B34`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant9()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B34, &gRecoveredSimLuaInitFormAnchor_off_F59B34>();
  }

  /**
   * Address: 0x00BD2D50 (FUN_00BD2D50, register_sim_SimInits_mForms_off_F59B34_mFactory)
   *
   * What it does:
   * Saves the current `sim` init-form head and relinks the list to the
   * `off_F59B34.mFactory` lane.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59B34_mFactory()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B34_mFactory, &gRecoveredSimLuaInitFormAnchor_off_F59B34_mFactory>();
  }

  /**
   * Address: 0x00BD2D70 (FUN_00BD2D70, register_sim_SimInits_mForms_offVariant10)
   *
   * What it does:
   * Saves the current `sim` init-form head and relinks the list to
   * `off_F59B64`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant10()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B64, &gRecoveredSimLuaInitFormAnchor_off_F59B64>();
  }

  /**
   * Address: 0x00BD2F00 (FUN_00BD2F00, register_RVectorType_bool)
   *
   * What it does:
   * Registers startup reflection metadata for `std::vector<bool>` and installs
   * process-exit cleanup.
   */
  int register_RVectorType_bool()
  {
    (void)preregister_RVectorType_bool();
    return std::atexit(&cleanup_RVectorType_bool);
  }

  /**
   * Address: 0x00BD2F20 (FUN_00BD2F20, sub_BD2F20)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CAnimationManipulator`.
   */
  int register_CScrLuaMetatableFactory_CAnimationManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCAnimationManipulatorIndex>();
  }

  /**
   * Address: 0x00BD2FB0 (FUN_00BD2FB0, sub_BD2FB0)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59B80`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant11()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B80, &gRecoveredSimLuaInitFormAnchor_off_F59B80>();
  }

  /**
   * Address: 0x00BD2FD0 (FUN_00BD2FD0, sub_BD2FD0)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59B98`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant12()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59B98, &gRecoveredSimLuaInitFormAnchor_off_F59B98>();
  }

  /**
   * Address: 0x00BD3100 (FUN_00BD3100, sub_BD3100)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CRotateManipulator`.
   */
  int register_CScrLuaMetatableFactory_CRotateManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCRotateManipulatorIndex>();
  }

  /**
   * Address: 0x00BD3190 (FUN_00BD3190, sub_BD3190)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59BB4`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant13()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59BB4, &gRecoveredSimLuaInitFormAnchor_off_F59BB4>();
  }

  /**
   * Address: 0x00BD31B0 (FUN_00BD31B0, sub_BD31B0)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59BCC`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant14()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59BCC, &gRecoveredSimLuaInitFormAnchor_off_F59BCC>();
  }

  /**
   * Address: 0x00BD3250 (FUN_00BD3250, sub_BD3250)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CSlaveManipulator`.
   */
  int register_CScrLuaMetatableFactory_CSlaveManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCSlaveManipulatorIndex>();
  }

  /**
   * Address: 0x00BD3460 (FUN_00BD3460, sub_BD3460)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59BE8`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant15()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59BE8, &gRecoveredSimLuaInitFormAnchor_off_F59BE8>();
  }

  /**
   * Address: 0x00BD3480 (FUN_00BD3480, sub_BD3480)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59C00`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant16()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59C00, &gRecoveredSimLuaInitFormAnchor_off_F59C00>();
  }

  /**
   * Address: 0x00BD3570 (FUN_00BD3570, sub_BD3570)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CSlideManipulator`.
   */
  int register_CScrLuaMetatableFactory_CSlideManipulator_Index()
  {
    const int index = RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCSlideManipulatorIndex>();
    CScrLuaMetatableFactory<CSlideManipulator>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x00BD3600 (FUN_00BD3600, sub_BD3600)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59C1C`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant17()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59C1C, &gRecoveredSimLuaInitFormAnchor_off_F59C1C>();
  }

  /**
   * Address: 0x00BD3620 (FUN_00BD3620, sub_BD3620)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59C34`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant18()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59C34, &gRecoveredSimLuaInitFormAnchor_off_F59C34>();
  }

  /**
   * Address: 0x00BD36B0 (FUN_00BD36B0, sub_BD36B0)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CStorageManipulator`.
   */
  int register_CScrLuaMetatableFactory_CStorageManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCStorageManipulatorIndex>();
  }

  /**
   * Address: 0x00BD3740 (FUN_00BD3740, sub_BD3740)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59C50`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant19()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59C50, &gRecoveredSimLuaInitFormAnchor_off_F59C50>();
  }

  /**
   * Address: 0x00BD3760 (FUN_00BD3760, sub_BD3760)
   *
   * What it does:
   * Saves current `sim` Lua-init form head and re-links to recovered startup
   * lane anchor `off_F59C68`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant20()
  {
    return RegisterRecoveredSimInitLinkerLane<&gRecoveredSimLuaInitFormPrev_off_F59C68, &gRecoveredSimLuaInitFormAnchor_off_F59C68>();
  }

  /**
   * Address: 0x00BD3800 (FUN_00BD3800, sub_BD3800)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CThrustManipulator`.
   */
  int register_CScrLuaMetatableFactory_CThrustManipulator_Index()
  {
    return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCThrustManipulatorIndex>();
  }
} // namespace moho

namespace
{
  struct ManipulatorStartupRegistrationsBootstrap
  {
    ManipulatorStartupRegistrationsBootstrap()
    {
      (void)moho::register_sim_SimInits_mForms_offVariant1();
      (void)moho::register_sim_SimInits_mForms_offVariant2();
      (void)moho::register_sim_SimInits_mForms_offVariant3();
      (void)moho::register_TConVar_dbg_Ballistics();
      moho::register_CAimManipulatorTypeInfo();
      moho::register_CAimManipulatorSerializer();
      (void)moho::register_CScrLuaMetatableFactory_CAimManipulator_Index();
      (void)moho::register_CScrLuaMetatableFactory_IAniManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant4();
      (void)moho::register_sim_SimInits_mForms_offVariant5();
      (void)moho::register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant6();
      (void)moho::register_sim_SimInits_mForms_off_F59A98_mFactory();
      (void)moho::register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant7();
      (void)moho::register_sim_SimInits_mForms_off_F59ACC_mFactory();
      (void)moho::register_CScrLuaMetatableFactory_CCollisionManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant8();
      (void)moho::register_sim_SimInits_mForms_off_F59B00_mFactory();
      (void)moho::register_CScrLuaMetatableFactory_CFootPlantManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant9();
      (void)moho::register_sim_SimInits_mForms_off_F59B34_mFactory();
      (void)moho::register_sim_SimInits_mForms_offVariant10();
      (void)moho::register_RVectorType_bool();
      (void)moho::register_CScrLuaMetatableFactory_CAnimationManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant11();
      (void)moho::register_sim_SimInits_mForms_offVariant12();
      (void)moho::register_CScrLuaMetatableFactory_CRotateManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant13();
      (void)moho::register_sim_SimInits_mForms_offVariant14();
      (void)moho::register_CScrLuaMetatableFactory_CSlaveManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant15();
      (void)moho::register_sim_SimInits_mForms_offVariant16();
      (void)moho::register_CScrLuaMetatableFactory_CSlideManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant17();
      (void)moho::register_sim_SimInits_mForms_offVariant18();
      (void)moho::register_CScrLuaMetatableFactory_CStorageManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant19();
      (void)moho::register_sim_SimInits_mForms_offVariant20();
      (void)moho::register_CScrLuaMetatableFactory_CThrustManipulator_Index();
    }
  };

  [[maybe_unused]] ManipulatorStartupRegistrationsBootstrap gManipulatorStartupRegistrationsBootstrap;
} // namespace
