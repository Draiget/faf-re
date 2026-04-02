#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/BVIntSet.h"
#include "moho/sim/SSTICommandSource.h"

namespace gpg
{
  class ReadArchive;
} // namespace gpg

namespace moho
{
  class RRuleGameRules;
  struct SSessionSaveData;
  class STIMap;

  struct SLaunchCommandSources
  {
    msvc8::vector<SSTICommandSource> mSrcs;     // +0x00
    std::int32_t v4 = 0;                        // +0x10
    std::int32_t mOriginalSource = -1;          // +0x14
  };

  static_assert(sizeof(SLaunchCommandSources) == 0x18, "SLaunchCommandSources size must be 0x18");
  static_assert(
    offsetof(SLaunchCommandSources, mSrcs) == 0x00, "SLaunchCommandSources::mSrcs offset must be 0x00"
  );
  static_assert(offsetof(SLaunchCommandSources, v4) == 0x10, "SLaunchCommandSources::v4 offset must be 0x10");
  static_assert(
    offsetof(SLaunchCommandSources, mOriginalSource) == 0x14,
    "SLaunchCommandSources::mOriginalSource offset must be 0x14"
  );

  class LaunchInfoNew;
  class LaunchInfoLoad;

  class LaunchInfoBase
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x005423B0 (FUN_005423B0)
     */
    LaunchInfoBase();

    /**
     * Address: 0x00542440 (FUN_00542440 deleting dtor thunk)
     * Address: 0x00542460 (FUN_00542460 destructor core)
     */
    virtual ~LaunchInfoBase();

    /**
     * Address: 0x00541FB0 (FUN_00541FB0)
     */
    [[nodiscard]] virtual LaunchInfoNew* GetNew();

    /**
     * Address: 0x00541FC0 (FUN_00541FC0)
     */
    [[nodiscard]] virtual LaunchInfoLoad* GetLoad();

    /**
     * Address context:
     * - slot 3 is purecall in `LaunchInfoBase` vftable.
     * - `LaunchInfoNew::Create` and `LaunchInfoLoad::Create` override this slot.
     */
    virtual void Create(boost::SharedPtrRaw<void>& outCreated) = 0;

    [[nodiscard]] static gpg::RType* StaticGetClass();

  public:
    RRuleGameRules* mGameRules;                  // +0x04
    STIMap* mMap;                                // +0x08
    msvc8::string mGameMods;                     // +0x0C
    msvc8::string mScenarioInfo;                 // +0x28
    msvc8::vector<BVIntSet> mArmyLaunchInfo;     // +0x44
    SLaunchCommandSources mCommandSources;       // +0x54
    msvc8::string mLanguage;                     // +0x6C
    bool mCheatsEnabled;                         // +0x88
    std::uint8_t pad_89[3];                      // +0x89
  };

  static_assert(offsetof(LaunchInfoBase, mGameRules) == 0x04, "LaunchInfoBase::mGameRules offset must be 0x04");
  static_assert(offsetof(LaunchInfoBase, mMap) == 0x08, "LaunchInfoBase::mMap offset must be 0x08");
  static_assert(offsetof(LaunchInfoBase, mGameMods) == 0x0C, "LaunchInfoBase::mGameMods offset must be 0x0C");
  static_assert(
    offsetof(LaunchInfoBase, mScenarioInfo) == 0x28, "LaunchInfoBase::mScenarioInfo offset must be 0x28"
  );
  static_assert(
    offsetof(LaunchInfoBase, mArmyLaunchInfo) == 0x44, "LaunchInfoBase::mArmyLaunchInfo offset must be 0x44"
  );
  static_assert(
    offsetof(LaunchInfoBase, mCommandSources) == 0x54, "LaunchInfoBase::mCommandSources offset must be 0x54"
  );
  static_assert(offsetof(LaunchInfoBase, mLanguage) == 0x6C, "LaunchInfoBase::mLanguage offset must be 0x6C");
  static_assert(
    offsetof(LaunchInfoBase, mCheatsEnabled) == 0x88, "LaunchInfoBase::mCheatsEnabled offset must be 0x88"
  );
  static_assert(sizeof(LaunchInfoBase) == 0x8C, "LaunchInfoBase size must be 0x8C");

  class LaunchInfoNew final : public LaunchInfoBase
  {
  public:
    /**
     * Address: 0x00542790 (FUN_00542790)
     */
    LaunchInfoNew();

    /**
     * Address: 0x00542810 (FUN_00542810)
     */
    ~LaunchInfoNew() override;

    /**
     * Address: 0x00541FD0 (FUN_00541FD0)
     */
    [[nodiscard]] LaunchInfoNew* GetNew() override;

    /**
     * Address: 0x00542870 (FUN_00542870)
     */
    void Create(boost::SharedPtrRaw<void>& outCreated) override;

  public:
    void* mProps;                                // +0x8C
    msvc8::vector<msvc8::string> mStrVec;        // +0x90
    std::int32_t mInitSeed;                      // +0xA0
  };

  static_assert(offsetof(LaunchInfoNew, mProps) == 0x8C, "LaunchInfoNew::mProps offset must be 0x8C");
  static_assert(offsetof(LaunchInfoNew, mStrVec) == 0x90, "LaunchInfoNew::mStrVec offset must be 0x90");
  static_assert(offsetof(LaunchInfoNew, mInitSeed) == 0xA0, "LaunchInfoNew::mInitSeed offset must be 0xA0");
  static_assert(sizeof(LaunchInfoNew) == 0xA4, "LaunchInfoNew size must be 0xA4");

  class LaunchInfoLoad final : public LaunchInfoBase
  {
  public:
    /**
     * Address: 0x00542AE0 (FUN_00542AE0)
     */
    LaunchInfoLoad();

    /**
     * Address: 0x00542B80 (FUN_00542B80)
     */
    ~LaunchInfoLoad() override;

    /**
     * Address: 0x00541FE0 (FUN_00541FE0)
     */
    [[nodiscard]] LaunchInfoLoad* GetLoad() override;

    /**
     * Address: 0x00541FF0 (FUN_00541FF0)
     */
    void Create(boost::SharedPtrRaw<void>& outCreated) override;

  public:
    gpg::ReadArchive* mReadArchive;                          // +0x8C
    boost::SharedPtrRaw<SSessionSaveData> mLoadSessionData; // +0x90
    boost::SharedPtrRaw<LaunchInfoBase> mSharedLaunchInfo;  // +0x98
  };

  static_assert(
    offsetof(LaunchInfoLoad, mReadArchive) == 0x8C, "LaunchInfoLoad::mReadArchive offset must be 0x8C"
  );
  static_assert(
    offsetof(LaunchInfoLoad, mLoadSessionData) == 0x90, "LaunchInfoLoad::mLoadSessionData offset must be 0x90"
  );
  static_assert(
    offsetof(LaunchInfoLoad, mSharedLaunchInfo) == 0x98, "LaunchInfoLoad::mSharedLaunchInfo offset must be 0x98"
  );
  static_assert(sizeof(LaunchInfoLoad) == 0xA0, "LaunchInfoLoad size must be 0xA0");

  class LaunchInfoBaseTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00542300 (FUN_00542300, deleting dtor thunk)
     */
    ~LaunchInfoBaseTypeInfo() override;

    /**
     * Address: 0x005422F0 (FUN_005422F0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005422D0 (FUN_005422D0)
     */
    void Init() override;
  };

  static_assert(sizeof(LaunchInfoBaseTypeInfo) == 0x64, "LaunchInfoBaseTypeInfo size must be 0x64");

  class LaunchInfoBaseSerializer
  {
  public:
    /**
     * Address: 0x00542550 (FUN_00542550, Moho::LaunchInfoBaseSerializer::Deserialize)
     *
     * What it does:
     * Archive callback thunk forwarding into LaunchInfoBase load body.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00542560 (FUN_00542560, Moho::LaunchInfoBaseSerializer::Serialize)
     *
     * What it does:
     * Archive callback thunk forwarding into LaunchInfoBase save body.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00543190 (FUN_00543190, sub_543190)
     *
     * What it does:
     * Registers load/save callbacks into LaunchInfoBase RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * Address: 0x00BC94C0 (FUN_00BC94C0, register_LaunchInfoBaseSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for `LaunchInfoBase`
   * and schedules process-exit cleanup.
   */
  void register_LaunchInfoBaseSerializer();

  static_assert(
    offsetof(LaunchInfoBaseSerializer, mHelperNext) == 0x04,
    "LaunchInfoBaseSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(LaunchInfoBaseSerializer, mHelperPrev) == 0x08,
    "LaunchInfoBaseSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(LaunchInfoBaseSerializer, mSerLoadFunc) == 0x0C,
    "LaunchInfoBaseSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(LaunchInfoBaseSerializer, mSerSaveFunc) == 0x10,
    "LaunchInfoBaseSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(LaunchInfoBaseSerializer) == 0x14, "LaunchInfoBaseSerializer size must be 0x14");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00885170 (FUN_00885170)
   */
  RRef* RRef_LaunchInfoBase(RRef* outRef, moho::LaunchInfoBase* value);
} // namespace gpg
