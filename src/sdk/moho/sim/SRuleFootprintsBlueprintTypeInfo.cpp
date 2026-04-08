#include "moho/sim/SRuleFootprintsBlueprint.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  /**
   * Address: 0x005146E0 (FUN_005146E0, gpg::RType::AddField_list_SNamedFootprint_0x0Footprints)
   *
   * What it does:
   * Adds the reflected `std::list<SNamedFootprint>` field named `Footprints`
   * at offset `0x00`.
   */
  gpg::RField* AddNamedFootprintsField(gpg::RType* const owner)
  {
    if (!owner) {
      return nullptr;
    }

    GPG_ASSERT(!owner->initFinished_);
    gpg::RField field{};
    field.mName = "Footprints";
    field.mType = moho::preregister_SNamedFootprintListTypeInfo();
    owner->fields_.push_back(field);
    return &owner->fields_.back();
  }

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
     * Forwards to the shared helper that reflects the `Footprints` list field.
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
    size_ = 0x0C;
    gpg::RType::Init();
    (void)AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00513FA0 (FUN_00513FA0, Moho::SRuleFootprintsBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Forwards to the shared helper that reflects the `Footprints` list field.
   */
  gpg::RField* SRuleFootprintsBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    return AddNamedFootprintsField(typeInfo);
  }

  /**
   * Address: 0x00513F00 (FUN_00513F00, Moho::SRuleFootprintsBlueprintTypeInfo::dtr)
   *
   * What it does:
   * Destroys reflected field/base storage through the inherited `gpg::RType`
   * teardown lane.
   */
  SRuleFootprintsBlueprintTypeInfo::~SRuleFootprintsBlueprintTypeInfo() = default;

  alignas(SRuleFootprintsBlueprintTypeInfo)
    unsigned char gSRuleFootprintsBlueprintTypeInfoStorage[sizeof(SRuleFootprintsBlueprintTypeInfo)]{};
  bool gSRuleFootprintsBlueprintTypeInfoConstructed = false;
  bool gSRuleFootprintsBlueprintTypeInfoPreregistered = false;

  [[nodiscard]] SRuleFootprintsBlueprintTypeInfo* AcquireSRuleFootprintsBlueprintTypeInfo()
  {
    if (!gSRuleFootprintsBlueprintTypeInfoConstructed) {
      new (gSRuleFootprintsBlueprintTypeInfoStorage) SRuleFootprintsBlueprintTypeInfo();
      gSRuleFootprintsBlueprintTypeInfoConstructed = true;
    }

    return reinterpret_cast<SRuleFootprintsBlueprintTypeInfo*>(gSRuleFootprintsBlueprintTypeInfoStorage);
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
   * Address: 0x00BF2880 (FUN_00BF2880, cleanup_SRuleFootprintsBlueprintTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SRuleFootprintsBlueprintTypeInfo` storage at process exit.
   */
  void cleanup_SRuleFootprintsBlueprintTypeInfo()
  {
    if (!gSRuleFootprintsBlueprintTypeInfoConstructed) {
      return;
    }

    AcquireSRuleFootprintsBlueprintTypeInfo()->~SRuleFootprintsBlueprintTypeInfo();
    gSRuleFootprintsBlueprintTypeInfoConstructed = false;
    gSRuleFootprintsBlueprintTypeInfoPreregistered = false;
    SRuleFootprintsBlueprint::sType = nullptr;
  }

  /**
   * Address: 0x00BC8380 (FUN_00BC8380, register_SRuleFootprintsBlueprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SRuleFootprintsBlueprint` RTTI and installs process-exit cleanup.
   */
  int register_SRuleFootprintsBlueprintTypeInfoStartup()
  {
    (void)preregister_SRuleFootprintsBlueprintTypeInfo();
    return std::atexit(&cleanup_SRuleFootprintsBlueprintTypeInfo);
  }
} // namespace moho
