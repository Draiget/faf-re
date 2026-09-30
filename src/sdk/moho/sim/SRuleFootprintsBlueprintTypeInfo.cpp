#include "moho/sim/SRuleFootprintsBlueprint.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  class SRuleFootprintsBlueprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00513F00 (FUN_00513F00, Moho::SRuleFootprintsBlueprintTypeInfo::dtr)
     *
     * What it does:
     * Destroys reflected field/base storage through the inherited `gpg::RType`
     * teardown lane.
     */
    ~SRuleFootprintsBlueprintTypeInfo() override;

    /**
     * Address: 0x00513EF0 (FUN_00513EF0, Moho::SRuleFootprintsBlueprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the RTTI label for `SRuleFootprintsBlueprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00513ED0 (FUN_00513ED0, Moho::SRuleFootprintsBlueprintTypeInfo::Init)
     *
     * What it does:
     * Registers the reflected `Footprints` list member and finalizes the type
     * descriptor.
     */
    void Init() override;

    /**
     * Address: 0x00513FA0 (FUN_00513FA0, Moho::SRuleFootprintsBlueprintTypeInfo::AddFields)
     *
     * What it does:
     * Reflects the `Footprints` list: a tail jump into its `AddField`
     * 0x005146E0.
     */
    static gpg::RField* AddFields(gpg::RType* typeInfo);
  };

  static_assert(sizeof(SRuleFootprintsBlueprintTypeInfo) == 0x64, "SRuleFootprintsBlueprintTypeInfo size must be 0x64");

  /**
   * Address: 0x00513EF0 (FUN_00513EF0, Moho::SRuleFootprintsBlueprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the RTTI label for `SRuleFootprintsBlueprint`.
   */
  const char* SRuleFootprintsBlueprintTypeInfo::GetName() const
  {
    return "SRuleFootprintsBlueprint";
  }

  /**
   * Address: 0x00513ED0 (FUN_00513ED0, Moho::SRuleFootprintsBlueprintTypeInfo::Init)
   *
   * What it does:
   * Registers the reflected `Footprints` list member and finalizes the type
   * descriptor.
   */
  void SRuleFootprintsBlueprintTypeInfo::Init()
  {
    static_assert(sizeof(moho::SRuleFootprintsBlueprint) == 0x0C, "moho::SRuleFootprintsBlueprint is 0x0C bytes on x86");
    size_ = sizeof(moho::SRuleFootprintsBlueprint);
    gpg::RType::Init();
    (void)AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00513FA0 (FUN_00513FA0, Moho::SRuleFootprintsBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Reflects the `Footprints` list: a tail jump into its `AddField`
   * 0x005146E0.
   */
  gpg::RField* SRuleFootprintsBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    return typeInfo->AddField<msvc8::list<moho::SNamedFootprint>>(
      "Footprints", offsetof(moho::SRuleFootprintsBlueprint, mFootprints)
    );
  }

  /**
   * Address: 0x00513F00 (FUN_00513F00, Moho::SRuleFootprintsBlueprintTypeInfo::dtr)
   *
   * What it does:
   * Destroys reflected field/base storage through the inherited `gpg::RType`
   * teardown lane.
   */
  SRuleFootprintsBlueprintTypeInfo::~SRuleFootprintsBlueprintTypeInfo() = default;

  bool gSRuleFootprintsBlueprintTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF2880 (FUN_00BF2880, atexit destructor of the SRuleFootprintsBlueprintTypeInfo object)
   */
  [[nodiscard]] SRuleFootprintsBlueprintTypeInfo* AcquireSRuleFootprintsBlueprintTypeInfo()
  {
    static SRuleFootprintsBlueprintTypeInfo sInstance;
    return &sInstance;
  }

  struct SRuleFootprintsBlueprintTypeInfoBootstrap
  {
    SRuleFootprintsBlueprintTypeInfoBootstrap()
    {
      (void)moho::register_SRuleFootprintsBlueprintTypeInfoStartup();
    }
  };

  [[maybe_unused]] SRuleFootprintsBlueprintTypeInfoBootstrap gSRuleFootprintsBlueprintTypeInfoBootstrap;
} // namespace

namespace moho
{
  gpg::RType* SRuleFootprintsBlueprint::sType = nullptr;

  /**
   * Address: 0x00513E70 (FUN_00513E70, preregister_SRuleFootprintsBlueprintTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `SRuleFootprintsBlueprint`.
   */
  gpg::RType* preregister_SRuleFootprintsBlueprintTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireSRuleFootprintsBlueprintTypeInfo();
    SRuleFootprintsBlueprint::sType = typeInfo;
    if (!gSRuleFootprintsBlueprintTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(SRuleFootprintsBlueprint), typeInfo);
      gSRuleFootprintsBlueprintTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BC8380 (FUN_00BC8380, register_SRuleFootprintsBlueprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SRuleFootprintsBlueprint` RTTI.
   */
  void register_SRuleFootprintsBlueprintTypeInfoStartup()
  {
    (void)preregister_SRuleFootprintsBlueprintTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SRuleFootprintsBlueprintTypeInfoStartup_6adcb7, moho::register_SRuleFootprintsBlueprintTypeInfoStartup)

GPG_PREREGISTER_INIT(preregister_SRuleFootprintsBlueprintTypeInfo_6adcb7, moho::preregister_SRuleFootprintsBlueprintTypeInfo)
