#include "CWldSession.h"

#include "platform/WxWidgets.h"
#include <wx/app.h>

#include "legacy/algorithms/Sort.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/BVSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/animation/CAniPose.h"
#include "moho/mesh/Mesh.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/command/CommandManager.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/IClientManager.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/resource/RResId.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "gpg/core/streams/BinaryReader.h"
#include "moho/console/CConCommand.h"
#include "lua/LuaTableIterator.h"
#include "moho/sim/CArmyLuaFunctionRegistrations.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EGenericIconTypeTypeInfo.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/sim/SDesyncInfo.h"
#include "moho/misc/TimeBar.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/RCamManager.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CFormation.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/client/Localization.h"
#include "moho/misc/SessionStartup.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/PauseListener.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SSelectionEvent.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/ESTITargetTypeTypeInfo.h"
#include "moho/sim/UserArmy.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/ui/CUIManager.h"
#include "moho/unit/core/EFireStateTypeInfo.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/math/MathReflection.h"
#include "moho/unit/core/IUnit.h"
#include "moho/ui/IUIManager.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  // TEMPORARY PROBE SINK -- unload-subset triage, delete when resolved.
  // gpg::Warnf reaches nothing unless `/log <name>` installed a target, so the
  // drag-unload probes append here instead. The file lands beside the exe.
  void UnloadDragDiagLine(const char* const fmt, ...)
  {
    std::FILE* const sink = std::fopen("faf_diag.log", "a");
    if (sink == nullptr) {
      return;
    }
    std::va_list args;
    va_start(args, fmt);
    (void)std::vfprintf(sink, fmt, args);
    va_end(args);
    (void)std::fputc('\n', sink);
    (void)std::fclose(sink);
  }

  /**
   * One formation-placement ghost: the preview mesh `MeshRenderer` handed back
   * and the "UnitFormationPreview" material it was shaded with.
   *
   * The implicit destructor is the binary's FUN_00859E90 - it drops the
   * last-declared member first (`mMaterial`, then `mMesh`), which is exactly
   * what MSVC emits for this member order. No source line spells it out.
   */
  struct SFormationPreviewGhost
  {
    boost::shared_ptr<moho::MeshInstance> mMesh;     // +0x00
    boost::shared_ptr<moho::MeshMaterial> mMaterial; // +0x08
  };
  static_assert(sizeof(SFormationPreviewGhost) == 0x10, "SFormationPreviewGhost size must be 0x10");

  /**
   * Session-global ghost list for the formation-placement preview.
   *
   * This is one plain `msvc8::vector` parked at 0x010C4258, not the three loose
   * pointer globals an earlier pass modelled:
   *   myProxy_ +0x00 -> 0x010C4258   first_ +0x04 -> 0x010C425C
   *   last_    +0x08 -> 0x010C4260   end_   +0x0C -> 0x010C4264
   *
   * That the container head is 0x010C4258 is settled by FUN_0085A280 and
   * FUN_0085A630: both are a bare `mov eax, offset 0x010C4258; retn`, i.e.
   * they hand back the container itself. FUN_00859F70 pins the 0x10-byte
   * element width - it derives both size and capacity by `sar ..., 4` over the
   * same three lanes.
   *
   * `CWldSession::RenderMeshPreviews` (0x008599D0) is the only writer: it
   * clears the vector at the top of every frame and repopulates it.
   */
  msvc8::vector<SFormationPreviewGhost> gFormationPreviews;

  // `StrategicIconAux` (the real type) and `gStrategicIconAuxiliary`
  // live in the `moho`-scoped anonymous namespace alongside the type's
  // definition (see `CWldSession::RenderStrategicIcons`'s callee cluster) -
  // a plain forward declaration here would name an unrelated, permanently
  // incomplete type in *this* (global-scope) anonymous namespace instead.

  [[nodiscard]] gpg::RType* ResolveSessionSaveNodeMapArchiveType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::SSessionSaveNodeMap));
    }
    return cached;
  }

  // The formation-preview container emissions used to live here as one
  // hand-written free function per operation. They are `msvc8::vector`
  // members, so the addresses now sit on the template in
  // `legacy/containers/Vector.h` and the call sites just use the container:
  //
  //   FUN_00859E90  ~SFormationPreviewGhost (implicit, member order)
  //   FUN_0085A1D0  destroy_range
  //   FUN_0085A9F0  copy_or_move_assign, one slot
  //   FUN_0085A130  erase, first..last
  //   FUN_00859FE0  pop_back
  //   FUN_00859F70  push_back
  //   FUN_0085A920  uninit_fill_n / in-place construct, push_back fast path
  //   FUN_0085A0E0  reallocate_to + insert, push_back grow path
  //
} // namespace

// Defined at file scope (global namespace, external linkage) in
// CrtRuntimeHelpers.cpp - shared by every legacy VC8 "<container> too long"
// throw lane in that file. Forward-declared here rather than duplicated so
// UICommandGraph's own hash-table growth guard (CheckedIncrementListSize) can
// reuse the identical message/exception construction instead of re-emitting it
// inline a second time. The bucket vector's own overflow lane (FUN_00830620)
// is msvc8::vector<void*>::throw_too_long and is cited there.
[[noreturn]] void EngineThrowContainerTooLong(const char* message);

namespace
{
  /**
   * Address: 0x00861DC0 (FUN_00861DC0)
   *
   * IDA signature:
   * void* __cdecl sub_861DC0();
   *
   * What it does:
   * Allocates one 3152-byte (0xC50) buffer through VC8's `_Allocate` with the
   * count folded to the constant (0x008620F0, cited on
   * `msvc8::detail::allocate_checked`), zeroes the first three dwords and marks
   * a two-byte initialized / not-yet-flushed flag pair near the end
   * (`+0xC48 = 1`, `+0xC49 = 0`).
   *
   * Reached directly from the CRT static-initializer table (`__xc_a`, depth
   * 1): the constructor body of a namespace-scope static object with
   * non-trivial construction. Its address neighbours (0x00861D70, then
   * 0x00861EB0 in this file) place it in this translation unit; the owning
   * global is not yet identified from the binary (its callers 0x00860DE0,
   * 0x008614D0, 0x00861A60 and the `__xc_a` registrar 0x00BE5CF0 are
   * unrecovered), so it stays a free function until that declaration lands.
   */
  [[maybe_unused]] void* AllocateAndTagStaticBootstrapBuffer3152()
  {
    void* const buffer = msvc8::detail::allocate_checked<std::uint8_t>(0xC50u);
    if (buffer != nullptr) {
      auto* const dwords = static_cast<std::uint32_t*>(buffer);
      dwords[0] = 0u;
      dwords[1] = 0u;
      dwords[2] = 0u;

      auto* const bytes = static_cast<std::uint8_t*>(buffer);
      bytes[0xC48] = 1u;
      bytes[0xC49] = 0u;
    }
    return buffer;
  }
} // namespace

namespace moho
{
  gpg::RType* SSessionSaveData::sType = nullptr;

  // Beat-scoped console toggles, defined in `moho/misc/RuntimeTuningGlobals.cpp`.
  extern bool ren_FogOfWar;
  extern bool dbg_Metronome;
  extern bool wld_RunWithTheWind;

  /// Lazily-bound engine-stat handles. `DoBeat` publishes how many units it
  /// ticked; `SessionFrame` publishes how many beats the drain consumed.
  StatItem* sEngineStat_UserSync_SessionTick_NumTickers = nullptr;
  StatItem* sEngineStat_Sync_Count = nullptr;

  /**
   * Address: 0x0089AEC0 (FUN_0089AEC0, boost::shared_ptr_SSessionSaveData::shared_ptr_SSessionSaveData)
   *
   * What it does:
   * Constructs one `shared_ptr<SSessionSaveData>` from one raw save-data
   * pointer lane.
   */
  boost::shared_ptr<SSessionSaveData>* ConstructSharedSessionSaveDataFromRaw(
    boost::shared_ptr<SSessionSaveData>* const outSaveData,
    SSessionSaveData* const saveData
  )
  {
    return ::new (outSaveData) boost::shared_ptr<SSessionSaveData>(saveData);
  }

  MouseInfo::MouseInfo()
    : mHitValid(0u)
    , pad_01{0u, 0u, 0u}
    , mMouseWorldPos(0.0f, 0.0f, 0.0f)
    , mUnitHover()
    , mIsDragger(-1)
    , mMouseScreenPos(0.0f, 0.0f)
  {}

  /**
   * Address: 0x0081CF00 (FUN_0081CF00, ??0UICursorInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs cursor info and relinks weak hovered-unit ownership to this instance.
   */
  MouseInfo::MouseInfo(const MouseInfo& other)
    : mHitValid(other.mHitValid)
    , pad_01{0u, 0u, 0u}
    , mMouseWorldPos(other.mMouseWorldPos)
    , mUnitHover(other.mUnitHover)
    , mIsDragger(other.mIsDragger)
    , mMouseScreenPos(other.mMouseScreenPos)
  {
  }

  /**
   * Address: 0x00893140 (FUN_00893140, ??1UICursorInfo@Moho@@QAE@@Z)
   * Address: 0x007B3DB0 (FUN_007B3DB0, ICF twin -- identical function_sha256
   *          to the canonical address above)
   * Address: 0x007B4E30 (FUN_007B4E30, ICF twin -- identical function_sha256)
   * Address: 0x007B50A0 (FUN_007B50A0, ICF twin -- identical function_sha256)
   * Address: 0x007B5040 (FUN_007B5040, `.c`-verified same walk-and-splice
   *          algorithm over the same `this+0x10` slot; distinct
   *          function_sha256 only because this emission preserves and
   *          returns the original `this` pointer in `eax` instead of the
   *          unlink cursor -- the `UnlinkIntrusiveOwnerNodeAt10AndReturnOwner`
   *          calling-convention lane)
   *
   * What it does:
   * Unlinks this cursor info from the hovered-unit weak-owner chain.
   *
   * All four twin addresses above were formerly duplicated in
   * `LegacyContainerFillLanes.cpp` as a standalone a deleted overlay
   * offset struct (`{pad[0x10], IntrusiveLink link}`) plus four
   * near-identical wrapper functions reaching into "an unidentified owning
   * class at +0x10" -- that file's own `IntrusiveLink` citation
   * flagged this as the last unresolved dependency blocking its cleanup.
   * `function_sha256` ties three of the four directly to this destructor;
   * the fourth matches by direct `.c` comparison. `mUnitHover` sits at
   * `MouseInfo`'s own +0x10 (`static_assert`-confirmed in `CWldSession.h`),
   * matching the offset both there and here exactly. The four duplicate
   * wrappers have been deleted; this destructor (via
   * `UnlinkCursorInfoWeakOwnerRef`) is their sole recovery.
   */
  MouseInfo::~MouseInfo() = default;

  /**
   * Address: 0x0082B270 (FUN_0082B270, Moho::UICursorInfo::Copy)
   *
   * What it does:
   * Assigns cursor info and updates hovered-unit weak-owner chain links.
   */
  MouseInfo& MouseInfo::operator=(const MouseInfo& other)
  {
    mHitValid = other.mHitValid;
    mMouseWorldPos = other.mMouseWorldPos;
    mUnitHover = other.mUnitHover;
    mIsDragger = other.mIsDragger;
    mMouseScreenPos = other.mMouseScreenPos;
    return *this;
  }

  UserEntity* MouseInfo::HoveredEntity() const noexcept
  {
    return mUnitHover.GetObjectPtr();
  }

  void MouseInfo::SetHoveredEntity(UserEntity* const entity) noexcept
  {
    mUnitHover.ResetFromObject(entity);
  }

  /**
   * Address: 0x0081F6C0 (FUN_0081F6C0, ??0SCommandModeData@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs command mode state, including both cursor snapshots.
   */
  CommandModeData::CommandModeData(const CommandModeData& other)
    : mMode(other.mMode)
    , mCommandCaps(other.mCommandCaps)
    , mBlueprint(other.mBlueprint)
    , mMouseDragStart(other.mMouseDragStart)
    , mMouseDragEnd(other.mMouseDragEnd)
    , mModifiers(other.mModifiers)
    , mIsDragged(other.mIsDragged)
    , mReserved5C(other.mReserved5C)
  {}

  /**
   * Address: 0x0081CEA0 (FUN_0081CEA0)
   * Address: 0x0081F760 (FUN_0081F760, sub_81F760)
   * Address: 0x0081FC80 (FUN_0081FC80, sub_81FC80)
   *
   * What it does:
   * Initializes command mode from one cursor snapshot and one modifier lane:
   * clears mode/caps/blueprint, copy-constructs drag-start, resets drag-end,
   * and sets both trailing sentinel lanes to `-1`.
   *
   * All three addresses are the same constructor. Byte-comparing the three
   * `.asm` bodies shows one identical instruction sequence - same field order,
   * same `xorps`/`or eax,-1` idioms, same `MouseInfo` copy-ctor call at
   * `this+0x0C` - differing only in the relative displacement of that call and
   * in the epilogue (`retn` at 0x0081F760, `retn 4` at 0x0081CEA0 and
   * 0x0081FC80, i.e. whether the call site or the callee pops the single
   * `modifiers` word). 0x0081F760 and 0x0081FC80 are the two call-site-
   * specialised emissions `Moho::CUIWorldView::HandleEvent` uses: 0x0081FC80
   * from its wheel-rotation arm (0x008708CD) and 0x0081F760 from its
   * middle-button-press arm (0x00870B29). Those two natural `CommandModeData
   * mode(cursorInfo, eventData.mModifiers);` declarations in
   * moho/ui/UiRuntimeTypes.cpp are the recovery of both.
   */
  CommandModeData::CommandModeData(const MouseInfo& mouseInfo, const int modifiers)
    : mMode(COMMOD_None)
    , mCommandCaps(RULEUCC_None)
    , mBlueprint(nullptr)
    , mMouseDragStart(mouseInfo)
    , mMouseDragEnd()
    , mModifiers(modifiers)
    , mIsDragged(-1)
    , mReserved5C(-1)
  {
    mMouseDragEnd.mHitValid = 0u;
    mMouseDragEnd.mMouseWorldPos = Wm3::Vector3f(0.0f, 0.0f, 0.0f);
    mMouseDragEnd.SetHoveredEntity(nullptr);
    mMouseDragEnd.mIsDragger = -1;
    mMouseDragEnd.mMouseScreenPos = Wm3::Vector2f(0.0f, 0.0f);
  }

  /**
   * Address: 0x007EF070 (FUN_007EF070, ??1SCommandModeData@Moho@@QAE@XZ)
   *
   * What it does:
   * Destroys command-mode cursor snapshots and unlinks both hovered-unit
   * weak-owner lanes.
   */
  CommandModeData::~CommandModeData() = default;

  /**
   * Address: 0x0082B230 (FUN_0082B230, ??0SCommandModeData@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Assigns command mode state from another value and copies both cursor-info
   * lanes via `MouseInfo::operator=`.
   */
  CommandModeData& CommandModeData::operator=(const CommandModeData& other)
  {
    mMode = other.mMode;
    mCommandCaps = other.mCommandCaps;
    mBlueprint = other.mBlueprint;
    mMouseDragStart = other.mMouseDragStart;
    mMouseDragEnd = other.mMouseDragEnd;
    mModifiers = other.mModifiers;
    mIsDragged = other.mIsDragged;
    mReserved5C = other.mReserved5C;
    return *this;
  }
} // namespace moho

namespace gpg
{
  class RMultiMapType_EntId_string : public RType
  {
  public:
    /**
     * Address: 0x0089B4C0 (FUN_0089B4C0, gpg::RMultiMapType_EntId_string::dtr)
     */
    ~RMultiMapType_EntId_string() override = default;

    /**
     * Address: 0x00899120 (FUN_00899120, gpg::RMultiMapType_EntId_string::Init)
     *
     * What it does:
     * Sets multimap size/version metadata and binds load/save serializers for
     * `multimap<EntId,std::string>`.
     */
    void Init() override;

    /**
     * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
     *
     * What it does:
     * Returns the cached lexical label for the reflected
     * `multimap<EntId,std::string>` lane.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current multimap element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
  };
} // namespace gpg

namespace
{
  gpg::RType* gEntIdStringMultiMapKeyType = nullptr;
  gpg::RType* gEntIdStringMultiMapValueType = nullptr;
  using EntIdStringMultiMap = std::multimap<moho::EntId, msvc8::string>;

  [[nodiscard]] gpg::RType* ResolveEntIdTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapKeyType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "EntId",
        "Moho::EntId",
        "int",
        "signed int",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapKeyType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapKeyType == nullptr) {
        gEntIdStringMultiMapKeyType = gpg::LookupRType(typeid(std::int32_t));
      }
    }

    return gEntIdStringMultiMapKeyType;
  }

  [[nodiscard]] gpg::RType* ResolveStringTypeForMultiMapName()
  {
    if (gEntIdStringMultiMapValueType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "std::string",
        "msvc8::string",
        "string",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapValueType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapValueType == nullptr) {
        gEntIdStringMultiMapValueType = gpg::LookupRType(typeid(msvc8::string));
      }
    }

    return gEntIdStringMultiMapValueType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdArchiveType()
  {
    gpg::RType* const resolved = ResolveEntIdTypeForMultiMapName();
    if (resolved != nullptr) {
      return resolved;
    }
    return gpg::LookupRType(typeid(moho::EntId));
  }

  /**
   * Address: 0x008999A0 (FUN_008999A0)
   *
   * What it does:
   * Clears destination multimap storage and then loads serialized
   * `(EntId, string)` pairs in archive order.
   */
  void DeserializeEntIdStringMultiMap(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<EntIdStringMultiMap*>(static_cast<std::uintptr_t>(objectPtr));
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    destination->clear();
    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (unsigned int index = 0u; index < count; ++index) {
      moho::EntId key = 0;
      archive->Read(entIdType, &key, *ownerRef);

      msvc8::string value{};
      archive->ReadString(&value);

      destination->insert(std::make_pair(key, value));
    }
  }

  /**
   * Address: 0x00899B20 (FUN_00899B20)
   *
   * What it does:
   * Writes multimap element count and serializes each `(EntId, string)` pair
   * in key-order.
   */
  void SerializeEntIdStringMultiMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const EntIdStringMultiMap*>(static_cast<std::uintptr_t>(objectPtr));
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);
    if (source == nullptr) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (const auto& entry : *source) {
      archive->Write(entIdType, &entry.first, *ownerRef);
      msvc8::string value = entry.second;
      archive->WriteString(&value);
    }
  }
} // namespace

/**
 * Address: 0x00899120 (FUN_00899120, gpg::RMultiMapType_EntId_string::Init)
 *
 * What it does:
 * Sets multimap size/version metadata and binds load/save serializers for
 * `multimap<EntId,std::string>`.
 */
void gpg::RMultiMapType_EntId_string::Init()
{
  static_assert(sizeof(msvc8::multimap<moho::EntId, msvc8::string>) == 0x0C, "msvc8::multimap<moho::EntId, msvc8::string> is 0x0C bytes on x86");
  size_ = sizeof(msvc8::multimap<moho::EntId, msvc8::string>);
  version_ = 1;
  serSaveFunc_ = &SerializeEntIdStringMultiMap;
  serLoadFunc_ = &DeserializeEntIdStringMultiMap;
}

/**
 * Address: 0x00899060 (FUN_00899060, gpg::RMultiMapType_EntId_string::GetName)
 * Address: 0x00C082E0 (FUN_00C082E0, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds `multimap<EntId,std::string>` once and returns it.
 */
const char* gpg::RMultiMapType_EntId_string::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf(
    "multimap<%s,%s>", ResolveEntIdTypeForMultiMapName()->GetName(), ResolveStringTypeForMultiMapName()->GetName()
  );
  return sName.c_str();
}

/**
 * Address: 0x00899140 (FUN_00899140, gpg::RMultiMapType_EntId_string::GetLexical)
 *
 * What it does:
 * Formats inherited lexical text and appends current multimap element count.
 */
msvc8::string gpg::RMultiMapType_EntId_string::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  // The reflected object is the `EntIdStringMultiMap` this type describes; a
  // private `{proxy, head, size}` view of it read the third word, which is not
  // where that container keeps its count.
  const auto* const map = static_cast<const EntIdStringMultiMap*>(ref.mObj);
  const int size = map ? static_cast<int>(map->size()) : 0;
  return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
}

/**
 * Address: 0x0089B460 (FUN_0089B460, preregister_RMultiMapType_EntId_string)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `std::multimap<moho::EntId,msvc8::string>`.
 */
[[nodiscard]] gpg::RType* preregister_RMultiMapType_EntId_string()
{
  static gpg::RMultiMapType_EntId_string typeInfo;
  gpg::PreRegisterRType(typeid(EntIdStringMultiMap), &typeInfo);
  return &typeInfo;
}

// Forward declaration: this symbol is referenced by the linker at global
// scope (not inside namespace moho), so its definition stays at global scope
// near the end of this file - but `DrawPathPreview` (namespace moho, below)
// needs to call it ahead of that point.
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession);

namespace moho
{
  // Address lanes:
  // - 0x010A645D (`ui_DebugAltClick`)
  // - 0x010A645E (`UI_SelectAnything`)
  // Recovered as process-global convar-backed toggles used by selection paths.
  bool ui_DebugAltClick = false;
  bool UI_SelectAnything = false;

  // Command-waypoint drawing parameters; see the declarations in CWldSession.h
  // for the per-symbol addresses. All seven are zero at image load and stay so
  // until `UICommandGraph::LoadWaypointParams` imports them.
  std::int32_t ui_CurveSegments = 20;          // 0x00F57CC0

  // Projectile strategic-icon CVars. None of these existed in the tree; the
  // addresses come from the store/compare operands in FUN_008621B0.
  float UI_StrategicProjectileLOD = 128.0f; // 0x00F57B20
  // 0x00F57A8E holds 0x01 in bin/2025.7.1/ForgedAlliance.exe's .data, so the
  // resource splats are on unless a console command turns them off.
  bool UI_RenResources = true;              // 0x00F57A8E
  bool UI_RenProjectileIcons = true;        // 0x00F57A8F
  bool UI_RenProjectileGlow = true;         // 0x00F57B24
  bool UI_forceWeaponsToYellow = true;      // 0x00F57B25
  float UI_RenProjectileGlowMin = 0.01f;    // 0x00F57B28
  float UI_RenProjectileGlowMax = 0.15f;    // 0x00F57B2C
  float UI_RenProjectileGlowPeriod = 2.0f;  // 0x00F57B30
  float UI_CurGlowTime = 0.0f;              // 0x010A6460

  // Read once per deposit by `CWldSession::RenderResources` (0x00862E68). The
  // 75 is the shipped value: `bin/2025.7.1/ForgedAlliance.exe` holds
  // 0x42960000 at 0x00F57B08, and `func_UI_ResourceLODCutoff_ConVarDef`
  // (0x00BE6010) only binds the console variable to this same storage.
  float UI_ResourceLODCutoff = 75.0f;       // 0x00F57B08

  // Strategic-icon and unit-bar console variables. None of these existed in
  // the tree; every address below is the absolute operand of the instruction
  // that reads it, taken from the `.asm` of the five functions that make up
  // the strategic-icon pass (0x0085B6E0, 0x0085CD40, 0x0085D9A0, 0x0085E0A0,
  // 0x0085E3A0). An earlier note here said they all ship zeroed and left the
  // console/UI layer to write them. They do not: every address in this block
  // lands inside `.data`'s raw bytes in bin/2025.7.1/ForgedAlliance.exe and
  // carries a real static initialiser, transcribed below. Shipping them zeroed
  // turned the whole pass off - `ui_RenderIcons` false is the gate at
  // 0x0085C0B1 that drops every collected strategic icon, and a 0.0f
  // `ui_LifebarLOD` can never exceed the current zoom (0x0085BFE8), so no unit
  // bar was ever collected either.
  bool ui_RenderUnitBars = true;                  // 0x00F57B26 (0x0085BFDB)
  bool ui_RenderIcons = true;                     // 0x00F57B27 (0x0085C0B1)
  float ui_lifebarHeight = 0.125f;                // 0x00F57B6C (0x0085CDCB)
  float ui_LifebarWidth = 1.5f;                   // 0x00F57B70 (0x0085CDB6)
  float ui_LifebarLOD = 200.0f;                   // 0x00F57B74 (0x0085BFE8)
  float ui_LifebarOffset = 0.1f;                  // 0x00F57B78 (0x0085CECE)
  bool ui_NisRenderIcons = true;                  // 0x00F57B7C (0x0085C0A4)
  bool ui_RenderCustomNames = true;               // 0x00F57B7D (0x0085E0BE)
  bool ui_RenderSelectionSetNames = true;         // 0x00F57B7E (0x0085E3BE)
  std::uint32_t ui_CustomNameColor = 0xFF00AA00u; // 0x00F57B80 (0x0085E2ED)
  std::int32_t ui_CustomNameFontSize = 12;        // 0x00F57B84 (0x0085E145)
  std::uint32_t ui_SelectionSetNamesColor = 0xFF00AA00u; // 0x00F57B88 (0x0085E72A)
  float ui_StrategicIconBlinkRate = 0.6f;         // 0x00F57B8C (0x0085DC44)
  float ui_FuelEmptyBlinkRate = 0.1f;             // 0x00F57B90 (0x0085D113)
  float ui_StrategicIconBlinkDuration = 0.5f;     // 0x00F57B94 (0x0085DC22)
  std::uint32_t ui_LifeBarGoodColor = 0xFF00FF00u; // 0x00F57B98 (0x0085D070)
  std::uint32_t ui_LifeBarMedColor = 0xFFFFFF00u; // 0x00F57B9C (0x0085D085)
  std::uint32_t ui_LifeBarBadColor = 0xFFFF0000u; // 0x00F57BA0 (0x0085D065)
  float ui_LifeBarGoodCutoff = 0.75f;             // 0x00F57BA4 (0x0085D05E)
  float ui_LifeBarBadCutoff = 0.25f;              // 0x00F57BA8 (0x0085D07C)
  std::uint32_t ui_FuelBarColor = 0xFFF4EC4Du;    // 0x00F57BAC (0x0085D0EE)
  std::uint32_t ui_FuelWarningColor = 0xFFFF0000u; // 0x00F57BB0 (0x0085D135)
  std::uint32_t ui_ShieldBarColor = 0xFF00C3F7u;  // 0x00F57BB4 (0x0085D0DA)
  std::uint32_t ui_ProgressBarColor = 0xFFFF9900u; // 0x00F57BB8 (0x0085D14B)
  msvc8::string ui_CustomNameFont{};              // 0x00F5B300 (0x0085E124)
  bool ui_ForceLifbarsOnEnemy = false;            // 0x010A644A (0x0085C031)
  bool ui_AlwaysRenderStrategicIcons = false;     // 0x010A644B (0x0085C148)
  // 0x010A6443 lies past ForgedAlliance.exe's raw .data (zero-filled BSS tail),
  // so the path-preview overlay ships off.
  bool ui_DrawPathPreview = false;          // 0x010A6443
  bool ui_PathPreview = false;              // 0x010A6448

  // Per-army team-color palette, distinct from `StrategicIconAux`'s own
  // Self/Ally/Enemy/Neutral relation colors: `RenderUnitIcon` (0x0085D9A0)
  // indexes this one directly by the icon's owning army's `mArmyIndex`
  // (`mov eax, offset teamcolors` / `mov ecx, [eax+ecx*4]`, the cold
  // out-of-line chunk at 0x0128E837..0x0128E83C). Sized to the original
  // game's eight-slot army cap; no loader/population site has been
  // identified yet, so - like the console variables above - it ships
  // zeroed until one is found.
  std::uint32_t teamcolors[8]{}; // 0x0128F1C0

  // Entity ids carry their family in the top nibble; 0x1_______ is a projectile.
  constexpr std::uint32_t kEntityFamilyMask = 0xF0000000u;
  constexpr std::uint32_t kEntityFamilyProjectile = 0x10000000u;
  constexpr std::uint32_t kProjectileIconColor = 0xFFFFFFFFu;
  constexpr std::uint32_t kProjectileForcedColor = 0xFFFFFF00u;
  constexpr const char* kProjectileIconTechnique = "TAlphaBlendLinearSampleNoDepth";
  // 0x008624F2 masks the layer with 6 - seabed | sub - to pick the recon grid.
  constexpr std::int32_t kLayerUnderwaterMask = LAYER_Seabed | LAYER_Sub;


  float ui_CurveSmoothness = 0.0f;             // 0x00F57CC4
  float ui_PathSmoothness = 0.0f;              // 0x00F57CC8
  float ui_MaxTextLOD = 0.0f;                  // 0x00F57CCC
  std::int32_t ui_CommandGraphMaxNodeUnits = 0; // 0x00F57CD0

  /**
   * Degenerate-length cutoff `RecomputeDrawNodeOrientation` compares its summed
   * edge direction against before normalizing (`flt_D71BFC`, loaded at
   * 0x00827979). Below it the node keeps a zero orientation hint rather than
   * normalizing noise into an arbitrary direction.
   */
  constexpr float kCommandGraphOrientationEpsilon = 1.0e-6f;
  float ui_MinWaypointSize = 0.0f;             // 0x00F57CD4
  float ui_MaxWaypointSize = 0.0f;             // 0x00F57CD8
  float ui_WaypointLineScale = 0.0f;           // 0x00F57CDC

  struct UICommandGraphNode
  {
    boost::SharedPtrRaw<void> mOrderlineTexture{}; // +0x00 (shared `(px,pi)` pair)
    float mOrderlineAspectRatio = 0.0f;            // +0x08
    float mOrderlineAnimRate = 0.0f;               // +0x0C
    std::uint32_t mOrderlineColor = 0;             // +0x10
    std::uint32_t mOrderlineSelectedColor = 0;     // +0x14
    std::uint32_t mOrderlineHighlightColor = 0;    // +0x18
    float mOrderlineGlow = 0.0f;                   // +0x1C
    float mOrderlineSelectedGlow = 0.0f;           // +0x20
    float mOrderlineHighlightGlow = 0.0f;          // +0x24
    std::uint32_t mWaypointColor = 0;              // +0x28
    std::uint32_t mWaypointSelectedColor = 0;      // +0x2C
    std::uint32_t mWaypointHighlightColor = 0;     // +0x30
    float mWaypointScale = 0.0f;                   // +0x34
    float mWaypointSelectedScale = 0.0f;           // +0x38
    float mWaypointHighlightScale = 0.0f;          // +0x3C
    float mArrowheadCapOffset = 0.0f;              // +0x40
    boost::SharedPtrRaw<void> mWaypointTexture{};  // +0x44 (shared `(px,pi)` pair)
    boost::SharedPtrRaw<void> mArrowheadTexture{}; // +0x4C (shared `(px,pi)` pair)

    /**
     * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one command-graph node style payload with default
     * orderline/waypoint scales and cleared texture shared pointers.
     */
    UICommandGraphNode();

    /**
     * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
     * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
     *
     * What it does:
     * Releases command-graph texture shared-control lanes in arrowhead,
     * waypoint, then orderline teardown order.
     */
    ~UICommandGraphNode();

    /**
     * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
     *
     * What it does:
     * Copies one command-graph style node payload, including shared-texture
     * control lanes for orderline/waypoint/arrowhead textures. Each lane is a
     * strong retain-then-release rebind through FUN_004229B0
     * (`sp_counted_base::release()`, see BoostWrappers.h) - see the definition
     * for the 2026-08-20 audit note.
     */
    UICommandGraphNode* CopyFrom(const UICommandGraphNode& other);

    /**
     * Address: 0x00825570 (FUN_00825570)
     * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
     *
     * What it does:
     * Loads command-graph texture/style lanes from one Lua table entry, honoring
     * `inherit_from` recursion before overriding local orderline/waypoint/
     * arrowhead keys.
     */
    void LoadTextures(LuaPlus::LuaObject rootTable, const char* key, LuaPlus::LuaState* state);
  };

  static_assert(sizeof(UICommandGraphNode) == 0x54, "UICommandGraphNode size must be 0x54");
  static_assert(offsetof(UICommandGraphNode, mWaypointTexture) == 0x44, "UICommandGraphNode::mWaypointTexture offset must be 0x44");
  static_assert(offsetof(UICommandGraphNode, mArrowheadTexture) == 0x4C, "UICommandGraphNode::mArrowheadTexture offset must be 0x4C");

  class UICommandGraph
  {
  public:
    friend class CWldSession;

    /**
     * Its real caller (`sub_829190`) always passes `this` explicitly - see
     * `DrawPathPreview`'s own doc comment in CWldSession.h for why the IDA
     * decompile's declared first parameter is misleading here.
     */
    friend void DrawPathPreview(
      UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick,
      float tickFraction
    );

    /**
     * `func_ProcessCommandDrag` (0x00829B40, `UICommandDragger::DragMove`/
     * `DragRelease`'s worker in UiRuntimeTypes.cpp) needs `mSession` and
     * `mMapAB0` plus the hash primitives below.
     */
    friend void ProcessCommandDrag(
      const Wm3::Vector3f& mouse, UICommandGraph& graph, CmdId cmdId, bool released
    );

    /**
     * `sub_82A030` (`UICommandDragger::OnCurrentDraggerReplaced`'s worker in
     * UiRuntimeTypes.cpp) needs `mSession` and `mMapAB0` for the same reason
     * `ProcessCommandDrag` does.
     */
    friend void ReanchorCommandGraphDrawNode(UICommandGraph& graph, CmdId cmdId);

    /**
     * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds command-graph caches, map/index containers, debug font handle,
     * and synchronizes command-graph UI visibility in Lua.
     */
    explicit UICommandGraph(CWldSession* session);

    /**
     * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
     */
    ~UICommandGraph();

  public:
    using CommandGraphNode = UICommandGraphNode;

    /**
     * `mMapD`'s node: keyed by the edge's own touch count (the same 32-bit
     * `key ^ 0xDEADBEEF` Park-Miller-Schrage hash `mMapAB0`/`mMapAB1` use -
     * see `FindHashListNode10`/`InsertOrFindHashListNode10` below), payload
     * is the memoized orderline width `CalculateWaypointLineWidth` returned
     * for that touch count. `LinkCommandGraphEdge` (0x00826960) uses this
     * table purely as a per-frame cache so it can skip re-invoking the Lua
     * width calculation on every visit of an edge it has already priced.
     * Confirmed 2-dword payload from `sub_82FB10`'s (0x0082FB10) construct
     * body: `result[2] = *a1; result[3] = a1[1];`, no third field.
     */
    struct HashListNode10
    {
      HashListNode10* mNext; // +0x00
      HashListNode10* mPrev; // +0x04
      std::uint32_t mKey;    // +0x08, CommandGraphEdge::mTouchCount at cache time
      float mWidth;          // +0x0C, cached CalculateWaypointLineWidth() result
    };
    static_assert(sizeof(HashListNode10) == 0x10, "UICommandGraph::HashListNode10 size must be 0x10");

    /**
     * `mMapC`'s node forward declaration - its payload is a full
     * `CommandGraphEdge`, which isn't a complete type yet at this point in
     * the class; the full definition sits just after `CommandGraphEdge`
     * below.
     */
    struct HashListNode2C;

    /**
     * One dword lane in the engine's four-pointer `gpg::fastvector` shape, with
     * inline storage for a single element.
     *
     * `mCapacity` points one past `mInline[0]` while the lane is inline. When
     * the grow helper spills the lane to the heap it stashes that inline
     * capacity-end *into* `mInline[0]` before overwriting `mBegin`
     * (0x0082E708: `if (begin == inlineOrigin) *inlineOrigin = capacity;`),
     * which is exactly what lets `ReleaseToInline` below restore the capacity
     * with one indirect load rather than recomputing it. `mInline[1]` is
     * reserved storage the constructor deliberately keeps outside the capacity.
     */
    struct CommandGraphEdge;

    /**
     * Payload of one command-graph hash node — the drawable record for a single
     * command. `mMapAB0` keys these by the issuing command, `mMapAB1` by the
     * head command of a queue, in which case `mPositionSum`/`mWeight` accumulate
     * across every unit sharing that queue so the graph can draw one node at
     * their centroid.
     *
     * This payload is *not* trivially destructible: it owns two heap-capable
     * dword lanes and one weak reference, which is why the binary's map-erase
     * paths call the destructor below before freeing the node.
     */
    struct UICommandGraphDrawNode
    {
      CmdId mCommandId;                    // +0x00
      /// The command's issue helper; its chain holds every draw node for it.
      WeakPtr<UserCommandIssueHelper> mHelperLink; // +0x04
      Wm3::Vector3f mPositionSum;          // +0x0C
      float mWeight;                       // +0x18
      std::uint8_t mHasResolvedPosition;   // +0x1C
      std::uint8_t mIsChainBoundary;       // +0x1D
      std::uint8_t mIsVisible;             // +0x1E
      std::uint8_t pad_1F;                 // +0x1F
      /**
       * The node's drawable mesh, owned strongly. `sub_826550` decrements the
       * control block's *use* count at +0x04 and calls vtable slot 1 (dispose)
       * on last release, which is `release()` and not `weak_release()` — the
       * two differ by which counter they touch, so getting it wrong either
       * leaks the mesh or frees it early. 0x008282B0 / 0x00828DD0 read the same
       * lane back as a `MeshInstance*` to stance it at the node's anchor.
       */
      boost::SharedPtrRaw<MeshInstance> mMeshInstance; // +0x20
      /**
       * Orderline tangent override: 0x008288D0 reads this as one `Vector3f`
       * (previously mis-split as `field_0x28`(uint32)/`field_0x2C`/
       * `field_0x30`, three separate scalars - it is one 12-byte vector) and
       * uses it in place of the computed from/to tangent whenever it's
       * non-zero.
       */
      Wm3::Vector3f mOrientationHint;      // +0x28
      Wm3::Vector3f mPreviousCentroid;     // +0x34
      /**
       * Render scale driven by how busy the node is: `RecomputeDrawNodeOrientation`
       * sets it to `sqrt(units on the busier edge lane)`, and the waypoint and
       * ETA-label passes multiply their style scale by it. Was `field_0x40`
       * until 0x008275B0's write at 0x008279E8 pinned the meaning.
       */
      float mUnitCountScale;               // +0x40
      /**
       * The game tick this order is estimated to finish on, propagated through
       * the edge graph by `ResolveDrawNodeCompletionTick`. `DisplayCommandNode`
       * subtracts the current tick from it to render "ETA: mm:ss". Was
       * `field_0x44` until 0x008272A0's write at 0x008272E0 pinned the meaning.
       */
      std::uint32_t mCompletionTick;       // +0x44
      /**
       * The two edge lists: `mLaneA` holds the edges arriving here, `mLaneB`
       * the edges leaving. Each is the 0x10 header plus two inline slots;
       * growth, copy and release go through the template (`push_back`, the
       * copy constructor, `ResetStorageToInline`).
       */
      gpg::fastvector_n<CommandGraphEdge*, 2> mLaneA; // +0x48
      gpg::fastvector_n<CommandGraphEdge*, 2> mLaneB; // +0x60

      /**
       * Address: 0x00824600 (FUN_00824600, sub_824600)
       *
       * What it does:
       * A fresh node: no command (`-1`), not linked to any helper, zero
       * position sum/weight/orientation/centroid/scale/ETA, no mesh, visible,
       * both edge lanes empty on their inline storage. Callers:
       * `FindOrInsertCommandGraphDrawNode` (0x0082B300) and
       * `AddCommandQueueToCommandGraph` (0x00826140).
       */
      UICommandGraphDrawNode();

      /**
       * Address: 0x00826550 (FUN_00826550, sub_826550)
       *
       * What it does:
       * Releases both dword lanes back to inline storage (freeing any spilled
       * heap block), drops the weak owner reference, and unlinks the node from
       * its command's intrusive chain.
       */
      ~UICommandGraphDrawNode();
    };

    /**
     * The AB tables' node. Unlike the 0x2C and 0x10 tables this one carries a
     * non-trivial payload, so `ClearHashListNodes` runs `DestroyPayload` before
     * releasing the allocation — mirroring the binary's list-erase helper at
     * 0x0082EF80, which calls the payload destructor on `node + 0x10` and only
     * then frees the node.
     */
    struct HashListNode88
    {
      HashListNode88* mNext;          // +0x00
      HashListNode88* mPrev;          // +0x04
      std::uint32_t mKey;             // +0x08
      std::uint32_t mKeyHigh;         // +0x0C
      UICommandGraphDrawNode mDraw;   // +0x10

      static void DestroyPayload(HashListNode88* const node) noexcept
      {
        node->mDraw.~UICommandGraphDrawNode();
      }
    };

    // {_Alproxy, _Myfirst, _Mylast, _Myend} at +0x00/04/08/0C, 0x10 bytes --
    // this is msvc8::vector<void*>, not a distinct type.
    using HashBucketVector = msvc8::vector<void*>;

    template <typename TNode>
    struct HashTable
    {
      std::uint8_t mOwnerByte; // +0x00
      std::uint8_t pad_01[7];
      TNode* mListHead;           // +0x08
      std::uint32_t mListSize;    // +0x0C
      HashBucketVector mBuckets;  // +0x10
      std::uint32_t mBucketMask;  // +0x20
      std::uint32_t mBucketCount; // +0x24
    };
    static_assert(sizeof(HashTable<void>) == 0x28, "HashTable<TNode> size must be 0x28");
    static_assert(offsetof(HashTable<void>, mListHead) == 0x08, "HashTable<TNode>::mListHead offset must be 0x08");
    static_assert(offsetof(HashTable<void>, mListSize) == 0x0C, "HashTable<TNode>::mListSize offset must be 0x0C");
    static_assert(offsetof(HashTable<void>, mBuckets) == 0x10, "HashTable<TNode>::mBuckets offset must be 0x10");
    static_assert(offsetof(HashTable<void>, mBucketMask) == 0x20, "HashTable<TNode>::mBucketMask offset must be 0x20");
    static_assert(offsetof(HashTable<void>, mBucketCount) == 0x24, "HashTable<TNode>::mBucketCount offset must be 0x24");

    /**
     * `mCommandGraphTree`'s value: a texture-keyed bucket of orderline edges.
     * The tree is a real msvc8-shaped red-black tree (`mColorOrAllocated` /
     * `mIsSentinel` at the offsets a real `_Tree` node uses) whose nodes carry
     * this pair by value at +0x0C.
     */
    struct CommandGraphTreeBucket
    {
      /// An `ID3DTextureSheet`, not a `CD3DBatchTexture`. `orderline_texture`
      /// is loaded through `ID3DDeviceResources::GetTexture`, which hands back
      /// an `RD3DTextureResource` -- and that derives from `ID3DTextureSheet`.
      /// The binary agrees from the consuming side: the two orderline passes
      /// call `SetTexture(boost::shared_ptr<ID3DTextureSheet>)` at 0x00829226
      /// and 0x00829396, and only the flat-white node pass at 0x0082952C takes
      /// the `CD3DBatchTexture` overload.
      boost::SharedPtrRaw<ID3DTextureSheet> mTexture;   // +0x00
      msvc8::vector<CommandGraphEdge*> mEdges;          // +0x08
    };
    static_assert(sizeof(CommandGraphTreeBucket) == 0x18, "CommandGraphTreeBucket size must be 0x18");

    /**
     * One `mCommandGraphTree` node. The bucket used to sit in a 0x18-byte raw
     * payload array and was reinterpreted in place, which only fits on x86.
     * Nodes are still bought raw (`operator new` + `InitCommandGraphTreeBucketValue`
     * for the bucket) and released raw, as the binary does.
     */
    struct CommandGraphTreeNode
    {
      CommandGraphTreeNode* mLeft;    // +0x00
      CommandGraphTreeNode* mParent;  // +0x04
      CommandGraphTreeNode* mRight;   // +0x08
      CommandGraphTreeBucket mBucket; // +0x0C
      std::uint8_t mColorOrAllocated; // +0x24
      std::uint8_t mIsSentinel;       // +0x25
      std::uint8_t pad_26[2];
    };
    static_assert(offsetof(CommandGraphTreeNode, mBucket) == 0x0C, "CommandGraphTreeNode::mBucket offset must be 0x0C");
    static_assert(
      offsetof(CommandGraphTreeNode, mColorOrAllocated) == 0x24,
      "CommandGraphTreeNode::mColorOrAllocated offset must be 0x24"
    );

    struct CommandGraphTree
    {
      void* mAllocProxy;           // +0x00
      CommandGraphTreeNode* mHead; // +0x04
      std::uint32_t mSize;         // +0x08
    };

    /**
     * One drawn segment of a queued-order "orderline" - the ribbon connecting
     * two command-graph draw nodes. `mCommandGraphTree` buckets these by
     * texture: each tree node's `mBucket` holds a
     * `{boost::SharedPtrRaw<ID3DTextureSheet>, msvc8::vector<CommandGraphEdge*>}`
     * pair, and the render pass walks the bucket's vector once per texture.
     *
     * `mEdge` sits at offset +0x10 of the 0x2C-byte `HashListNode2C` that
     * owns it (`mNext@0/mPrev@4/mKeyLow@8/mKeyHigh@0xC/mEdge@0x10`), which
     * pins this struct's size at exactly 0x1C (0x2C - 0x10).
     */
    struct CommandGraphEdge
    {
      /**
       * Touch/visit refcount: 0x00826960 increments this by one every time
       * a queued order resolves to this (fromNode,toNode) edge, and reads
       * it back (clamped to `ui_CommandGraphMaxNodeUnits`) as the edge's
       * apparent unit weight in 0x008275B0's orientation-hint accumulation.
       */
      std::uint32_t mTouchCount{};          // +0x00, confirmed by FUN_00826960/FUN_008275B0
      float mBaseWidth{};                   // +0x04, confirmed by FUN_008288D0.c:85 and FUN_00826960
      UICommandGraphDrawNode* mFromNode{};  // +0x08
      UICommandGraphDrawNode* mToNode{};    // +0x0C
      /**
       * Per-lane bundle-spacing index, both written by 0x008275B0 as
       * `(loopIndex / max(laneCount - 1, 1)) - 0.5`: `mLaneBDistribution`
       * while walking `mFromNode->mLaneB` (this edge seen from its "from"
       * endpoint), `mLaneADistribution` while walking `mToNode->mLaneA`
       * (this edge seen from its "to" endpoint).
       */
      float mLaneBDistribution{};           // +0x10, confirmed by FUN_008275B0
      float mLaneADistribution{};           // +0x14, confirmed by FUN_008275B0
      /**
       * When set, 0x008288D0 skips `ResolveDrawNodeHighlightState` entirely
       * and draws this edge with the owning `CommandGraphNode`'s
       * mOrderlineHighlightColor/mOrderlineHighlightGlow directly - i.e. this
       * forces the "highlighted" style, it does not carry a per-edge custom
       * color (an earlier read of this struct assumed `+0x1C`/`+0x28` held a
       * per-edge override color/alpha; neither offset is actually read
       * anywhere in 0x008288D0, so that guess has been dropped).
       */
      bool mForceHighlightStyle{};           // +0x18
      std::uint8_t mUnknown19_1B[0x03]{};    // +0x19, unconfirmed - not touched by FUN_00826960/FUN_008275B0
    };

    static_assert(sizeof(CommandGraphEdge) == 0x1C, "CommandGraphEdge size must be 0x1C");
    static_assert(offsetof(CommandGraphEdge, mBaseWidth) == 0x04, "CommandGraphEdge::mBaseWidth offset must be 0x04");
    static_assert(offsetof(CommandGraphEdge, mFromNode) == 0x08, "CommandGraphEdge::mFromNode offset must be 0x08");
    static_assert(offsetof(CommandGraphEdge, mToNode) == 0x0C, "CommandGraphEdge::mToNode offset must be 0x0C");
    static_assert(offsetof(CommandGraphEdge, mLaneBDistribution) == 0x10, "CommandGraphEdge::mLaneBDistribution offset must be 0x10");
    static_assert(offsetof(CommandGraphEdge, mLaneADistribution) == 0x14, "CommandGraphEdge::mLaneADistribution offset must be 0x14");
    static_assert(offsetof(CommandGraphEdge, mForceHighlightStyle) == 0x18, "CommandGraphEdge::mForceHighlightStyle offset must be 0x18");

    /**
     * `mMapC`'s node (forward-declared above `CommandGraphEdge`): keyed by
     * the 64-bit `{fromNode, toNode}` draw-node pointer pair as two raw
     * dwords, payload is the edge itself. `LinkCommandGraphEdge`'s
     * find-or-create (0x0082B490 / 0x0082C750 / 0x0082C480) confirmed this
     * shape - 0x008269AA/0x008269AD write `mFromNode`/`mToNode` through the
     * pointer `FindOrInsertCommandGraphEdge` returns, which is exactly
     * `&node->mEdge` (node+0x10).
     */
    struct HashListNode2C
    {
      HashListNode2C* mNext;   // +0x00
      HashListNode2C* mPrev;   // +0x04
      std::uint32_t mKeyLow;   // +0x08, fromNode (draw-node pointer, as key dword)
      std::uint32_t mKeyHigh;  // +0x0C, toNode
      CommandGraphEdge mEdge;  // +0x10
    };
    static_assert(sizeof(HashListNode2C) == 0x2C, "UICommandGraph::HashListNode2C size must be 0x2C");
    static_assert(offsetof(HashListNode2C, mKeyHigh) == 0x0C, "UICommandGraph::HashListNode2C::mKeyHigh offset must be 0x0C");
    static_assert(offsetof(HashListNode2C, mEdge) == 0x10, "UICommandGraph::HashListNode2C::mEdge offset must be 0x10");

    /**
     * `EstimateDrawNodeWorkTicks` (0x00826F10) reaches the game rules through
     * `mSession` to build the "assisting unit" category: 0x0082700F loads
     * `graph+0x0D24` and 0x00827015 the rules at `session+0x18` before the two
     * `GetEntityCategory` dispatches. Declared here rather than beside the
     * other friends above because it names `UICommandGraphDrawNode`, which is
     * only complete from this point on.
     */
    friend std::int32_t EstimateDrawNodeWorkTicks(
      UICommandGraph& graph, UICommandGraphDrawNode& drawNode
    );

    /**
     * `LinkCommandGraphEdge` (0x00826960) needs `mMapC`/`mMapD`/`mNodes` and
     * the private find-or-insert primitives built on them - declared here
     * (rather than with the other friends above) for the same reason
     * `EstimateDrawNodeWorkTicks` is: it names `UICommandGraphDrawNode`,
     * only complete from this point on. See its own doc comment, on the
     * out-of-line definition, for the full address decomposition.
     */
    friend void LinkCommandGraphEdge(
      UICommandGraphDrawNode& toNode, UICommandGraphDrawNode& fromNode, UICommandGraph& graph, bool forceHighlight
    );

    /**
     * `AddCommandQueueToCommandGraph` (0x00826140) needs `mMapAB0`/`mMapAB1`/
     * `mSession` and `FindOrInsertCommandGraphDrawNode` - declared here for
     * the same reason `LinkCommandGraphEdge` is.
     */
    friend void AddCommandQueueToCommandGraph(UserEntity& entity, UICommandGraph& graph, UserCommandQueue* queue);

    /**
     * Tri-state highlight the render pass picks a waypoint/orderline style
     * color and scale from - see `ResolveDrawNodeHighlightState`.
     */
    enum class ECommandNodeHighlightState : std::int32_t
    {
      Normal = 0,
      Highlighted = 1,
      Selected = 2,
    };

    /**
     * Address: 0x00828280 (FUN_00828280, sub_828280)
     *
     * IDA signature:
     * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
     *
     * What it does:
     * The "selected" test `ResolveDrawNodeHighlightState` ends on: resolves the
     * draw node's owning command-issue helper, asks that helper for the entity
     * set the command is aimed at, and reports whether that set shares any live
     * entity with the session's current selection. A node with no owning helper
     * is never selected.
     *
     * Its own null-helper guard is kept even though the only caller has already
     * checked the same field - the binary re-tests it here.
     */
    [[nodiscard]] bool DrawNodeSharesLiveEntityWithSelection(const UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x008281E0 (FUN_008281E0, sub_8281E0)
     * Address: 0x00831110 (FUN_00831110, sub_831110) - now
     * `WeakSet<UserEntity>::HasCommonLiveEntityWith`
     *
     * What it does:
     * Picks the style state a command-graph draw node renders with this
     * frame: `Highlighted` when the cursor is hovering a unit the node's
     * command affects, or when the node's command is the session's
     * currently-interacting one; `Selected` when the node's affected-entity
     * set shares any live entity with the current selection; `Normal`
     * otherwise, and always `Normal` for a node with no owning command.
     *
     * The binary's `mIsDragger` comparison (0x00828249: `cmp ebx,[esi+18h]`)
     * reads `MouseInfo::mIsDragger` as a `CmdId`, not a boolean "currently
     * dragging" flag - it is genuinely the id of whichever command the
     * session is presently interacting with. Preserved as a raw field read
     * with this comment rather than renaming the widely-shared `MouseInfo`
     * field.
     */
    [[nodiscard]] ECommandNodeHighlightState
      ResolveDrawNodeHighlightState(const UICommandGraphDrawNode& drawNode) const;

  private:
    static void ReleaseIntrusive(CD3DFont*& font);
    static void AssignIntrusive(CD3DFont*& dst, CD3DFont* src);

    /**
     * Address: 0x0082F030 (FUN_0082F030)
     */
    static HashListNode88* AllocateMapABListSentinel();

    /**
     * Address: 0x0082F5B0 (FUN_0082F5B0)
     */
    static HashListNode2C* AllocateMapCListSentinel();

    /**
     * Address: 0x0082FAF0 (FUN_0082FAF0)
     */
    static HashListNode10* AllocateMapDListSentinel();

    /**
     * Address: 0x0082BF40 (FUN_0082BF40)
     */
    static void InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C400 (FUN_0082C400)
     */
    static void InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082C8D0 (FUN_0082C8D0)
     */
    static void InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* owner);

    /**
     * Address: 0x0082FAB0 (FUN_0082FAB0, MSVC8 std::list<T>::clear inline expansion)
     * Address: 0x0082C840 (FUN_0082C840, the HashListNode2C instantiation)
     *
     * What it does:
     * Clears one sentinel-headed hash-list in place without freeing the
     * sentinel head. Payload nodes are trivially destructible.
     */
    template <typename TNode>
    static void ClearHashListNodes(HashTable<TNode>& table) noexcept;

    template <typename TNode>
    static void DestroyMap(HashTable<TNode>& table);

    /**
     * The value portion of one HashListNode88 - everything after the
     * intrusive mNext/mPrev link header. ConstructHashListNode88
     * copy-constructs a new node's mKey/mDraw from one of these; the source
     * may be a real existing node's tail (during rehash relocation,
     * `&oldNode->mKey` overlays this exactly - the ctor-arg evidence at
     * 0x00830523) or a freestanding stack composite built for a fresh
     * insert (mMapAB0's insert-if-missing path, sub_82B300 at 0x0082B35C).
     *
     * mUnused04 mirrors HashListNode88::mKeyHigh's position but is never
     * read by any of mMapAB0's find/insert primitives recovered below -
     * only the low key dword participates in hashing/comparison, so this
     * field is left exactly as uninitialized as the binary leaves it
     * (0x00831D80 copies just the leading dword before delegating the tail
     * to the draw-node relocate at 0x0082D530).
     */
    struct HashListNode88Value
    {
      std::uint32_t mKey;             // +0x00
      std::uint32_t mUnused04;        // +0x04
      UICommandGraphDrawNode mDraw;   // +0x08
    };

    /**
     * Address: 0x0082D530 (FUN_0082D530, sub_82D530)
     * Address: 0x00826620 (FUN_00826620, the no-EH emission of this same body)
     *
     * What it does:
     * Relocate-copies one command-graph draw node's full payload: command
     * id, the intrusive command-issue helper chain link (re-publishing the
     * helper's head to point at `destination` in place of `source`),
     * position/weight/flag scalars, the owned mesh instance (retaining a
     * new strong reference on the shared control block rather than
     * transferring it, since `source` keeps its own reference until
     * destroyed separately), the orientation hint/previous-centroid/
     * reserved scalars, and both dword lanes. Used by the hash node
     * constructor below whenever a node is built from an existing node's
     * payload (rehash relocation) or a fresh stack value.
     */
    static UICommandGraphDrawNode* RelocateDrawNode(UICommandGraphDrawNode* destination, UICommandGraphDrawNode& source);

    /**
     * Address: 0x00831AB0 (FUN_00831AB0, sub_831AB0)
     *
     * What it does:
     * Overflow-checked `operator new` for `count` HashListNode88 (0x88-byte)
     * slots; throws `std::bad_alloc` when `count` would overflow the byte
     * count. Matches the legacy VC8 `std::_Allocate<T>` shape already used
     * throughout legacy/containers/Vector.h for other element sizes.
     */
    [[nodiscard]] static void* AllocateHashListNode88Storage(std::size_t count);

    /**
     * Address: 0x00831D80 (FUN_00831D80, sub_831D80)
     *
     * What it does:
     * Constructs one HashListNode88Value in place: copies the key dword,
     * then relocate-copies the draw-node payload via RelocateDrawNode.
     * `mUnused04` is left untouched, matching the binary exactly.
     */
    static HashListNode88Value* ConstructHashListNode88Value(HashListNode88Value* destination, HashListNode88Value& source);

    /**
     * Address: 0x008304D0 (FUN_008304D0, sub_8304D0)
     *
     * What it does:
     * Allocates one HashListNode88, links it explicitly via the caller-
     * supplied `next`/`prev` (the classic Dinkumware `_Buynode(_Next, _Prev,
     * _Val)` shape), then constructs its value portion from `valueSource`.
     * If construction throws, the raw node is freed before the exception
     * propagates (matches the binary's SEH cleanup funclet at 0x00830540).
     */
    [[nodiscard]] static HashListNode88* ConstructHashListNode88(
      HashListNode88* next, HashListNode88* prev, HashListNode88Value& valueSource
    );

    /**
     * Address: 0x0082C240 (FUN_0082C240, sub_82C240)
     *
     * What it does:
     * Finds the node whose key exactly matches `key` within its hash
     * bucket, or returns the table's list sentinel (`mListHead`) when no
     * exact match exists - the same "not found" convention
     * InsertOrFindHashListNode88/FindOrInsertCommandGraphDrawNode use to
     * detect a miss.
     */
    [[nodiscard]] static HashListNode88* FindHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082C2E0 (FUN_0082C2E0, sub_82C2E0)
     *
     * What it does:
     * Returns the `[first, last)` equal-range of nodes matching `key`
     * within their hash bucket. An empty range collapses both ends to the
     * table's list sentinel (`mListHead`), matching the binary's fallback
     * (it reuses the sentinel rather than the bucket's own end pointer once
     * no match is found).
     */
    [[nodiscard]] static std::pair<HashListNode88*, HashListNode88*>
      EqualRangeHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082B450 (FUN_0082B450, sub_82B450)
     *
     * What it does:
     * Counts nodes matching `key` by walking EqualRangeHashListNode88's
     * `[first, last)` range one `mNext` step at a time.
     */
    [[nodiscard]] static std::uint32_t CountHashListNode88(HashTable<HashListNode88>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082F050 (FUN_0082F050, sub_82F050)
     *
     * What it does:
     * Adds `count` to `sizeField` after an overflow guard against the
     * legacy VC8 list max-size (0x1FFFFFF), throwing
     * `std::length_error("list<T> too long")` on overflow. Calls the same
     * shared throw lane as msvc8::vector<T>::throw_too_long.
     */
    static std::uint32_t CheckedIncrementListSize(std::uint32_t count, std::uint32_t& sizeField);

    /**
     * Address: 0x0082BFB0 (FUN_0082BFB0, sub_82BFB0)
     *
     * What it does:
     * `mMapAB0`'s hash-bucket insert lane: grows/rehashes one bucket at a
     * time when the load factor is exceeded, then finds-or-inserts `key`,
     * returning the existing node when found (`outInserted=false`) or a
     * freshly constructed node linked into its bucket and the table's
     * global list (`outInserted=true`, `mListSize` bumped via
     * CheckedIncrementListSize).
     */
    static HashListNode88*
      InsertOrFindHashListNode88(HashTable<HashListNode88>& table, HashListNode88Value& valueSource, bool& outInserted);

    /**
     * Address: 0x0082B300 (FUN_0082B300, sub_82B300)
     *
     * What it does:
     * `mMapAB0`'s public find-or-insert entry point: looks `key` up via
     * FindHashListNode88 first; on a miss, default-constructs a temporary
     * draw node payload (0x00824600), relocate-copies it into a second
     * temporary, and inserts a real node built from `{key, temporary}` via
     * InsertOrFindHashListNode88. Always returns a pointer to the resolved
     * node's draw-node payload (`&node->mDraw`).
     */
    [[nodiscard]] static UICommandGraphDrawNode*
      FindOrInsertCommandGraphDrawNode(std::uint32_t key, HashTable<HashListNode88>& table);

    /**
     * The value portion of one HashListNode2C - `mMapC`'s payload,
     * everything after the intrusive mNext/mPrev link header. Mirrors
     * HashListNode88Value's role for the 88-byte table: `MakeHashListNode2C`
     * copy-constructs a fresh node's `mKeyLow`/`mKeyHigh`/`mEdge` from one of
     * these (0x00830700's `qmemcpy(result + 2, a3, 0x24u)` copies exactly
     * this 0x24-byte shape).
     */
    struct HashListNode2CValue
    {
      std::uint32_t mKeyLow;   // +0x00
      std::uint32_t mKeyHigh;  // +0x04
      CommandGraphEdge mEdge;  // +0x08
    };
    static_assert(sizeof(HashListNode2CValue) == 0x24, "UICommandGraph::HashListNode2CValue size must be 0x24");

    /**
     * The value portion of one HashListNode10 - `mMapD`'s payload.
     * `MakeHashListNode10` copies both dwords from one of these
     * (0x0082FB10's `result[2] = *a1; result[3] = a1[1];`).
     */
    struct HashListNode10Value
    {
      std::uint32_t mKey;  // +0x00
      float mWidth;         // +0x04
    };
    static_assert(sizeof(HashListNode10Value) == 0x08, "UICommandGraph::HashListNode10Value size must be 0x08");

    /**
     * Addresses: 0x00831BA0 (FUN_00831BA0, HashListNode2C's overflow-checked
     * `operator new`) and 0x00831C90 (FUN_00831C90, HashListNode10's).
     * Same shape as `AllocateHashListNode88Storage` for each node's own
     * size, generalised over `TNode` instead of forked per node size.
     */
    template <typename TNode>
    [[nodiscard]] static void* NewHashListNodeStorage(std::size_t count);

    /**
     * Address: 0x00830700 (FUN_00830700, sub_830700)
     *
     * What it does:
     * Allocates one HashListNode2C, links it via the caller-supplied
     * `next`/`prev`, and copies its value from `valueSource` - the binary
     * uses a flat `qmemcpy` here rather than a placement-construct chain,
     * because `CommandGraphEdge` (and the key dwords) are trivially
     * copyable, unlike `HashListNode88Value`'s owned draw-node payload.
     */
    [[nodiscard]] static HashListNode2C* MakeHashListNode2C(
      HashListNode2C* next, HashListNode2C* prev, HashListNode2CValue& valueSource
    );

    /**
     * Address: 0x0082FB10 (FUN_0082FB10, sub_82FB10)
     *
     * What it does:
     * Allocates one HashListNode10, links it via the caller-supplied
     * `next`/`prev`, and copies its 2-dword value from `valueSource`.
     */
    [[nodiscard]] static HashListNode10* MakeHashListNode10(
      HashListNode10* next, HashListNode10* prev, HashListNode10Value& valueSource
    );

    /**
     * Address: 0x0082F5D0 (FUN_0082F5D0, sub_82F5D0)
     *
     * What it does:
     * `CheckedIncrementListSize` for `HashListNode2C`'s own Dinkumware
     * `list<T>::max_size()` bound (`119304647`, i.e. `0xFFFFFFFF / 0x24 - 1`
     * for the 0x24-byte `HashListNode2CValue`). Byte-identical shape to
     * `CheckedIncrementListSize` (0x0082F050) apart from that constant.
     */
    static std::uint32_t CheckedIncrementListSize2C(std::uint32_t count, std::uint32_t& sizeField);

    /**
     * Address: 0x0082DD60 (FUN_0082DD60, sub_82DD60)
     *
     * What it does:
     * `CheckedIncrementListSize` for `HashListNode10`'s own max-size bound
     * (`0x1FFFFFFF`). Byte-identical shape to `CheckedIncrementListSize`
     * (0x0082F050) apart from that constant.
     */
    static std::uint32_t CheckedIncrementListSize10(std::uint32_t count, std::uint32_t& sizeField);

    /**
     * Not a distinct binary function - the scalar 32-bit-key half of the
     * hash scramble, generalised over `TNode` so `HashListNode10` (`mMapD`)
     * shares this template with `HashListNode88` (`mMapAB0`/`mMapAB1`)
     * rather than forking a copy - both tables hash the exact same way
     * (0x0082C240's scramble == 0x0082C950's).
     *
     * The scramble is Park-Miller "minimal standard":
     * `ldiv(key ^ 0xDEADBEEF, 127773)` then `16807*rem - 2836*quot`, with
     * negative results wrapped by `+0x7FFFFFFF`. The binary inlines it
     * independently at every hash-table site (0x0082C240, 0x0082C2E0,
     * 0x0082BFB0 x2) rather than sharing it; it is lifted into this one
     * named helper per the intent-first helper contract.
     *
     * A non-template `HashListNode88` declaration of this name used to sit
     * above `CheckedIncrementListSize10`. Being an exact match it won
     * overload resolution against this template at every `mMapAB0`/`mMapAB1`
     * call site, and it had no definition anywhere - so those calls resolved
     * to nothing and, under /FORCE, linked against garbage.
     */
    template <typename TNode>
    [[nodiscard]] static std::uint32_t HashKeyToBucketIndex(const HashTable<TNode>& table, std::uint32_t key) noexcept;

    /**
     * Not a distinct binary function - the 64-bit pair-key half of
     * `HashKeyToBucketIndex`'s scramble, used only by `HashListNode2C`
     * (`mMapC`). Diffed against the scalar scramble above: identical
     * Park-Miller-Schrage tail, different combine step
     * (`3863*lo + 7919*hi + 53849*(lo^hi)` vs `key ^ 0xDEADBEEF`) -
     * confirmed from 0x0082D960 (the 2C lane's dedicated hash function),
     * genuinely called from 0x0082C750/`FindHashListNode2C`'s rehash loop.
     * `FUN_0082C480`/`ObtainHashListNode2C` does NOT call 0x0082D960 -
     * the identical formula is inlined there twice instead (its own final-
     * insert step and rehash loop both compute it directly); confirmed via
     * `_callgraph_index.sqlite`, whose complete caller set for 0x0082D960
     * is `{FUN_0082C750, an unclassified owner=<none> byte-gap chunk at
     * 0x0082D924}` - `FUN_0082C480` is absent. The recovered C++ is
     * unaffected either way (`HashKeyToBucketIndex<TNode>`'s pair overload
     * is correctly called by name from both real call sites, matching
     * RULE ONE's "recover the shared function even where the compiler
     * inlined one instantiation" pattern) - only this prose previously
     * overstated the binary call graph.
     */
    template <typename TNode>
    [[nodiscard]] static std::uint32_t
      HashKeyToBucketIndex(const HashTable<TNode>& table, std::uint32_t keyLow, std::uint32_t keyHigh) noexcept;

    /**
     * Not a distinct binary function - the shared scalar-key find shape
     * `FindHashListNode88` (0x0082C240) and `FindHashListNode10`
     * (0x0082C950) both compile to (same load-factor-free bucket walk,
     * same "== bucketEnd -> sentinel" miss convention), generalised over
     * `TNode` per RULE ONE rather than duplicated per node size.
     */
    template <typename TNode>
    [[nodiscard]] static TNode* FindHashListNode(HashTable<TNode>& table, std::uint32_t key) noexcept;

    /**
     * Not a distinct binary function - the shared 64-bit pair-key find
     * shape, used only by `FindHashListNode2C` (0x0082C750).
     */
    template <typename TNode>
    [[nodiscard]] static TNode*
      FindHashListNode(HashTable<TNode>& table, std::uint32_t keyLow, std::uint32_t keyHigh) noexcept;

    /**
     * Not a distinct binary function - the shared scalar-key
     * rehash/insert-point-walk shape `InsertOrFindHashListNode88`
     * (0x0082BFB0) and `ObtainHashListNode10` (0x0082B5E0) both compile to.
     * `constructNode`/`incrementListSize` are the two points where the two
     * instantiations genuinely differ (node size, max-size bound), passed
     * in rather than duplicating the ~80-line rehash body per node size.
     */
    template <typename TNode, typename TValue>
    [[nodiscard]] static TNode* ObtainHashListNode(
      HashTable<TNode>& table, TValue& valueSource, bool& outInserted,
      TNode* (*constructNode)(TNode*, TNode*, TValue&), std::uint32_t (*incrementListSize)(std::uint32_t, std::uint32_t&)
    );

    /**
     * Not a distinct binary function - the shared 64-bit pair-key
     * rehash/insert-point-walk shape, used only by `ObtainHashListNode2C`
     * (0x0082C480).
     */
    template <typename TNode, typename TValue>
    [[nodiscard]] static TNode* ObtainHashListNodePair(
      HashTable<TNode>& table, TValue& valueSource, bool& outInserted,
      TNode* (*constructNode)(TNode*, TNode*, TValue&), std::uint32_t (*incrementListSize)(std::uint32_t, std::uint32_t&)
    );

    /**
     * Address: 0x0082C750 (FUN_0082C750, sub_82C750)
     */
    [[nodiscard]] static HashListNode2C*
      FindHashListNode2C(HashTable<HashListNode2C>& table, std::uint32_t keyLow, std::uint32_t keyHigh) noexcept;

    /**
     * Address: 0x0082C480 (FUN_0082C480, sub_82C480)
     */
    static HashListNode2C* ObtainHashListNode2C(
      HashTable<HashListNode2C>& table, HashListNode2CValue& valueSource, bool& outInserted
    );

    /**
     * Address: 0x0082C950 (FUN_0082C950, sub_82C950)
     */
    [[nodiscard]] static HashListNode10* FindHashListNode10(HashTable<HashListNode10>& table, std::uint32_t key) noexcept;

    /**
     * Address: 0x0082B5E0 (FUN_0082B5E0, sub_82B5E0)
     */
    static HashListNode10*
      ObtainHashListNode10(HashTable<HashListNode10>& table, HashListNode10Value& valueSource, bool& outInserted);

    /**
     * Address: 0x0082B490 (FUN_0082B490, sub_82B490)
     *
     * What it does:
     * `mMapC`'s public find-or-insert entry point, the exact analogue of
     * `FindOrInsertCommandGraphDrawNode` for the edge table: looks the
     * `{fromNode, toNode}` pair up via `FindHashListNode2C` first; on a
     * miss, inserts a zero-initialized `CommandGraphEdge` (the binary
     * `memset`s the value composite before the insert - a fresh edge has no
     * source line of its own, matching `CommandGraphEdge`'s in-class
     * default member initializers). Always returns `&node->mEdge`.
     */
    [[nodiscard]] static CommandGraphEdge* FindOrInsertCommandGraphEdge(
      UICommandGraphDrawNode* fromNode, UICommandGraphDrawNode* toNode, HashTable<HashListNode2C>& table
    );

    /**
     * Address: 0x008300D0 (FUN_008300D0)
     */
    static CommandGraphTreeNode* AllocateTreeSentinelNode();

    static void InitTree(CommandGraphTree& tree);

    /**
     * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
     *
     * What it does:
     * Frees one command-graph tree bucket's edge-pointer vector storage (if
     * spilled off the vector's inline/proxy state to a heap buffer) and
     * releases its owned batch-texture control block. Does not free the
     * owning tree node - callers do that immediately afterward. Before this
     * recovery pass, `DestroyTree`'s node-delete walk never called this,
     * leaking `mEdges`' heap buffer and the texture refcount on every
     * teardown (including the class destructor) - see the fix in
     * `DestroyTree` below.
     */
    static void ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept;

    /**
     * Not a distinct binary function - the post-order (right subtree, this
     * node, left subtree) node-destroy walk that 0x00824B50 (`DestroyTree`)
     * inlines in the binary (0x0082CDE0 is that copy). A second binary copy
     * at 0x00826000 (`PrepareForRebuild`, see below) inlines the identical
     * walk for its rebuild-reset path - both are now recovered against this
     * one shared helper, so the bucket-resource release runs on every node
     * from both call sites. Lifted into one shared helper here per the
     * intent-first helper contract instead of duplicating the walk.
     */
    static void DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* sentinelHead, CommandGraphTreeNode* node);

    /**
     * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
     *
     * What it does:
     * Destroys one command-graph runtime tree (nodes + head sentinel) and
     * clears head/size lanes. Releases each node's bucket resources
     * (texture refcount + edge-vector heap buffer) via
     * `ReleaseCommandGraphTreeBucket` before freeing the node.
     */
    static void DestroyTree(CommandGraphTree& tree);

    /**
     * Address: 0x0082D330 (FUN_0082D330, sub_82D330)
     *
     * What it does:
     * Constructs one `CommandGraphTreeBucket` in place: retains a new
     * strong reference on `texture`'s shared control block (matching
     * `boost::shared_ptr`'s copy constructor - `_InterlockedExchangeAdd`
     * on the control block in the binary) and default-constructs the edge
     * vector.
     */
    static CommandGraphTreeBucket* InitCommandGraphTreeBucketValue(
      CommandGraphTreeBucket* destination, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x00830010 (FUN_00830010)
     *
     * What it does:
     * Standard red-black left rotation, transcribed against
     * `CommandGraphTreeNode`'s own field names - same shape as
     * `legacy/containers/RbTree.h`'s `rotate_left` (already cited there for
     * this exact tree instantiation).
     */
    static void PivotCommandGraphTreeLeft(CommandGraphTree& tree, CommandGraphTreeNode* n) noexcept;

    /**
     * Address: 0x00830080 (FUN_00830080)
     *
     * What it does:
     * Mirror of `PivotCommandGraphTreeLeft` - same shape as
     * `legacy/containers/RbTree.h`'s `rotate_right` (already cited there
     * for this exact tree instantiation).
     */
    static void PivotCommandGraphTreeRight(CommandGraphTree& tree, CommandGraphTreeNode* n) noexcept;

    /**
     * Address: 0x0082E320 (FUN_0082E320, sub_82E320), buy+link+rebalance half
     *
     * What it does:
     * Allocates one fresh tree node, retains `texture` into its bucket
     * payload, links it under `where`/`addLeft`, then repairs the
     * red-red violation - the exact shape `legacy/containers/RbTree.h`'s
     * `insert_at` (`buy_node` + `link_and_rebalance`) already documents for
     * this map instantiation, transcribed against `CommandGraphTreeNode`'s
     * own field names rather than routed through `detail::rb_tree<Traits>`:
     * `boost::SharedPtrRaw<T>` is an explicit-retain, non-owning view by
     * design (see `BoostWrappers.h`), so a generic value-type copy
     * constructor would silently skip the add-ref the binary performs
     * explicitly via `sub_82D330` (`InitCommandGraphTreeBucketValue` above).
     */
    static CommandGraphTreeNode* AttachCommandGraphNodeAt(
      CommandGraphTree& tree, bool addLeft, CommandGraphTreeNode* where, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x0082E170 (FUN_0082E170, sub_82E170)
     *
     * What it does:
     * Plain unique insert: descends comparing the owner-based key (the
     * texture's control-block pointer), confirms uniqueness against the
     * in-order predecessor when the descent bottomed out on a left branch,
     * and links via `AttachCommandGraphNodeAt`. Same shape as
     * `legacy/containers/RbTree.h`'s `insert_unique`, already cited there
     * for this map instantiation.
     */
    static CommandGraphTreeNode*
      AttachCommandGraphNodeUnique(CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture);

    /**
     * Address: 0x0082CC80 (FUN_0082CC80, sub_82CC80)
     *
     * What it does:
     * Hinted unique insert: the empty-tree fast path, `hint == leftmost()`
     * check, `hint == end()` check against `rightmost()`, then the
     * decrement/increment straddle checks, each tailing into
     * `AttachCommandGraphNodeAt` with the decided `addLeft`, and a final
     * fallback to `AttachCommandGraphNodeUnique`. Same shape as
     * `legacy/containers/RbTree.h`'s `insert_hint`, already cited there for
     * this exact map instantiation - `mCommandGraphTree[texture]`'s
     * `lower_bound` result feeding straight back in as the hint.
     */
    static CommandGraphTreeNode* AttachCommandGraphNodeHinted(
      CommandGraphTree& tree, CommandGraphTreeNode* hint, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
    );

    /**
     * Address: 0x0082B8B0 (FUN_0082B8B0, sub_82B8B0)
     *
     * What it does:
     * `mCommandGraphTree[texture]` (VC8 `map::operator[]`): descends
     * comparing the owner-based key (the texture's control-block pointer,
     * `pi`) against each candidate bucket's own `pi` lane, records the last
     * node the search went left at, and on a miss inserts a fresh bucket
     * retaining `texture` via `AttachCommandGraphNodeHinted`. Returns
     * the resolved bucket's edge vector - `LinkCommandGraphEdge`
     * (0x00826960) pushes the new edge straight into it via
     * `CommandGraphTreeBucket::mEdges.push_back` (0x0082BCB0).
     */
    static msvc8::vector<CommandGraphEdge*>&
      FindOrInsertCommandGraphBucket(CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture);

    /**
     * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
     */
    static void OnCommandGraphShow(LuaPlus::LuaState* state, bool visible);

    /**
     * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
     */
    void LoadPathParams();

    /**
     * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
     */
    static void LoadWaypointParams();

    /**
     * Address: 0x00828FB0 (FUN_00828FB0, Moho::UICommandGraph::CreateMeshes)
     *
     * IDA signature:
     * void callcnv_33 Moho::UICommandGraph::CreateMeshes(Moho::UICommandGraph *a1);
     *
     * What it does:
     * The command graph's once-per-frame build pass. When the graph is dirty it
     * rebuilds every queued-order node and edge from the live command queues and
     * recomputes each node's orderline orientation. It then re-binds every
     * draw node to whichever command-issue helper currently owns its command id
     * (commands retire and are re-issued between frames, so the intrusive chain
     * has to be re-pointed), seeding a node's world anchor from the helper's
     * command history the first time that node resolves. On a rebuild frame it
     * additionally propagates completion-tick estimates through the edge graph
     * and creates the translucent "UnitPlace" preview mesh for mobile-build
     * orders. Finally it drives the console path-preview overlay.
     */
    void CreateMeshes();

    /**
     * Address: 0x00826740 (FUN_00826740, sub_826740)
     *
     * IDA signature:
     * void __thiscall sub_826740(Moho::UICommandGraph *this);
     *
     * What it does:
     * Rebuilds the whole command-graph node/edge set from scratch. Resets the
     * per-frame containers, collects every mesh-bearing entity in the session's
     * spatial database, and folds each significant unit's command queue into
     * the graph - plus the separate factory build queue for stationary
     * factories.
     */
    void RebuildCommandQueueNodes();

    /**
     * Address: 0x00826000 (FUN_00826000, sub_826000)
     *
     * IDA signature:
     * void __usercall sub_826000(Moho::UICommandGraph *this@<edi>);
     *
     * What it does:
     * Clears everything a rebuild pass regenerates: the edge hash table and its
     * buckets, the texture-keyed orderline tree, and both draw-node tables' edge
     * lanes. Queue-head nodes (`mMapAB1`) additionally have their accumulated
     * centroid and weight zeroed, because the rebuild re-accumulates them across
     * every unit sharing the queue.
     */
    void PrepareForRebuild();

    /**
     * Address: 0x00826BA0 (FUN_00826BA0, sub_826BA0)
     *
     * IDA signature:
     * _DWORD **__usercall sub_826BA0@<eax>(Moho::UICommandGraph *this@<ebx>);
     *
     * What it does:
     * Recomputes the orderline orientation hint of every draw node, queue-head
     * table first and per-command table second.
     */
    void RecomputeAllDrawNodeOrientations();

    /**
     * Address: 0x008275B0 (FUN_008275B0, sub_8275B0)
     *
     * IDA signature:
     * void __usercall sub_8275B0(Moho::UICommandGraph::UICommandGraphDrawNode *this@<esi>);
     *
     * What it does:
     * Derives one draw node's orderline tangent from the edges on both of its
     * lanes: each edge contributes the unit vector towards its far endpoint's
     * centroid, scaled by that edge's unit count (clamped to
     * `ui_CommandGraphMaxNodeUnits`). The summed direction is normalized into
     * `mOrientationHint`, and the node's render scale becomes the square root of
     * the busier lane's unit total. Each edge also records where it sits in its
     * lane's ribbon bundle, so parallel orderlines fan out instead of
     * overlapping.
     */
    static void RecomputeDrawNodeOrientation(UICommandGraphDrawNode& drawNode);

    /**
     * Address: 0x008272A0 (FUN_008272A0, sub_8272A0)
     *
     * IDA signature:
     * void __thiscall sub_8272A0(Moho::UICommandGraph *this, _DWORD *drawNode);
     *
     * What it does:
     * Resolves the game tick one queued order is estimated to complete on, by
     * depth-first walking the edges it depends on. Writing the current tick into
     * the node up front doubles as the cycle guard: a node already being
     * resolved returns immediately, so a cyclic order graph terminates.
     */
    void ResolveDrawNodeCompletionTick(UICommandGraphDrawNode& drawNode);

    /**
     * Address: 0x00827360 (FUN_00827360, sub_827360)
     *
     * IDA signature:
     * void __userpurge sub_827360(
     *   Moho::UICommandGraph::UICommandGraphDrawNode *drawNode@<esi>, Moho::UICommandGraph *graph);
     *
     * What it does:
     * Gives a pending mobile-build order its translucent green placement mesh -
     * the ghost of the unit that order will produce, stanced at the order's
     * position. Only builds one when the node has no mesh yet and its command is
     * a `BuildMobile`; every other order draws with waypoint markers alone.
     *
     * The chain, with the three offsets an earlier pass could not place now
     * resolved against the disassembly:
     *  - `helper+0x20` is `mConstantData.blueprint` (`mConstantData` sits at
     *    helper+0x04, `blueprint` at its own +0x1C), an `REntityBlueprint*`;
     *  - virtual slot 5 (0x008273B2, `[eax+0x14]`) is
     *    `REntityBlueprint::IsUnitBlueprint`, returning the `RUnitBlueprint`
     *    whose `Display` subobject starts at +0x200 - which is what makes
     *    +0x21C `Display.MeshBlueprint` (an `RResId`, *not* the `VTransform`
     *    the decompiler infers from its 0x1C-byte width) and +0x270
     *    `Display.UniformScale`;
     *  - virtual slot 15 (0x008273D3, `[edx+0x3C]`) on `CWldSession::mRules`
     *    is `RRuleGameRules::GetMeshBlueprint(const RResId&)`, which is why
     *    the +0x21C `RResId` is the argument handed to it;
     *  - the "+0x64 string triple" is not a field of `RMeshBlueprint` at all.
     *    `mLods` starts at +0x60 and +0x64 is its `first_` lane, so the three
     *    strings the binary addresses at +0x1C/+0x38/+0x54 off that pointer
     *    are `mAlbedoName`/`mNormalsName`/`mSpecularName` of `mLods[0]`.
     *
     * Note the colour appears twice and the decompiler folds them together:
     * `CreateMeshInstance` is handed 0xFF00FF00, then the instance's own
     * colour lane is overwritten with 0xD800D800 - the alpha-0xD8 translucent
     * green the ghost actually renders in.
     */
    static void CreateBuildPreviewMesh(UICommandGraphDrawNode& drawNode, UICommandGraph& graph);

    void MarkDirty() noexcept
    {
      mNeedsRebuild = 1u;
    }

    /**
     * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
     *
     * What it does:
     * Draws one command node's waypoint marker quad: a flat square centered
     * on the node's averaged position, sized to a roughly-constant apparent
     * screen size via the camera's viewport perspective-width row, colored
     * and scaled by `ResolveDrawNodeHighlightState`.
     */
    void DrawWaypointMarker(const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode) const;

    /**
     * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
     *
     * What it does:
     * Poses the node's owned mesh instance at its resolved (or history-
     * resolved fallback) anchor and, when that anchor came from a real unit
     * blueprint, draws the unit's footprint skirt there too.
     */
    void DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const;

    /**
     * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
     *
     * What it does:
     * Draws the "ETA: mm:ss" text label above one command-graph draw node.
     */
    void DisplayCommandNode(const GeomCamera3& camera, const UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const;

    /**
     * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
     *
     * What it does:
     * Draws one command-graph "orderline" ribbon segment between two draw
     * nodes' averaged positions.
     */
    void DrawCommandOrderline(
      const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction,
      const CommandGraphEdge& edge, bool isGlow
    ) const;

  public:
    /**
     * Address: 0x00829190 (FUN_00829190, sub_829190)
     *
     * What it does:
     * The per-frame command-graph render pass: draws every queued-order
     * orderline (opaque then glow, grouped by texture), every waypoint
     * marker, positions each node's anchored mesh/skirt, the path-preview
     * overlay, then switches to a screen-space projection and draws every
     * node's ETA text label.
     *
     * IDA's `__userpurge` signature adds two register arguments (typed
     * `CRenderWorldView*` and `boost::shared_ptr<UICommandGraph>&` in the
     * analyst database) that are only the caller's leftover `ecx`/`edx`; this
     * body never reads either.
     *
     * Public (unlike its `DrawWaypointMarker`/`DrawCommandOrderline`/etc.
     * siblings above, which are only ever called from here): its real caller
     * is `CWldSession::RenderCommandGraph` (0x0085AF40), outside this class.
     */
    void DrawCommandGraphMesh(const GeomCamera3& camera, CD3DPrimBatcher& batcher, std::int32_t tick, float tickFraction);

    /**
     * Address: 0x00829800 (FUN_00829800, sub_829800)
     *
     * IDA signature:
     * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
     *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
     *
     * What it does:
     * Per-frame cursor/waypoint hit test for the command graph: walks every
     * draw node in `mMapAB0`'s hash list, frustum-culls its averaged anchor
     * (`mPositionSum / mWeight`) against the camera's view solid, and for
     * every surviving node compares its projected screen position against
     * `cursorScreenPos` within a depth-scaled, `ui_MinWaypointSize`/
     * `ui_MaxWaypointSize`-clamped tolerance (`ui_WaypointLineScale` applied
     * on top - the decompiled read shows as `ui_CommandClickScale`, which is
     * not a real symbol; see `UICommandGraph::LoadPathParams`'s doc comment
     * on why both Lua keys resolve to `ui_WaypointLineScale`), the same
     * style knobs `DrawWaypointMarker` uses for the visible marker size).
     * Ferry-command nodes get a small (0.1) tolerance bonus,
     * matching the binary's dedicated `UNITCOMMAND_Ferry` branch. Among the
     * nodes within tolerance, the closest wins unless a farther node's
     * cursor-entity set already shares a live entity with the current
     * session selection, in which case that node preempts distance.
     *
     * Returns the winning node's command id, or -1 when none qualifies.
     */
    [[nodiscard]] CmdId ResolveCursorHighlightCommandId(
      const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
    ) const;

  private:
    std::uint8_t mNeedsRebuild; // +0x0000
    std::uint8_t pad_0001[3];
    CommandGraphNode mNodes[40];        // +0x0004
    CWldSession* mSession;              // +0x0D24
    void* mSessionRes1;                 // +0x0D28
    CD3DFont* mDebugFont;               // +0x0D2C
    HashTable<HashListNode88> mMapAB0;  // +0x0D30
    HashTable<HashListNode88> mMapAB1;  // +0x0D58
    HashTable<HashListNode2C> mMapC;    // +0x0D80
    HashTable<HashListNode10> mMapD;    // +0x0DA8
    CommandGraphTree mCommandGraphTree; // +0x0DD0
  };

  static_assert(sizeof(UICommandGraph::CommandGraphNode) == 0x54, "UICommandGraph::CommandGraphNode size must be 0x54");
  static_assert(sizeof(UICommandGraph::HashListNode88) == 0x88, "UICommandGraph::HashListNode88 size must be 0x88");
  static_assert(
    sizeof(UICommandGraph::UICommandGraphDrawNode::mLaneA) == 0x18,
    "UICommandGraph::UICommandGraphDrawNode::mLaneA size must be 0x18"
  );
  static_assert(
    sizeof(UICommandGraph::UICommandGraphDrawNode) == 0x78,
    "UICommandGraph::UICommandGraphDrawNode size must be 0x78"
  );
  static_assert(
    offsetof(UICommandGraph::HashListNode88, mDraw) == 0x10,
    "UICommandGraph::HashListNode88::mDraw offset must be 0x10"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mHelperLink) == 0x04,
    "UICommandGraphDrawNode::mHelperLink offset must be 0x04"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPositionSum) == 0x0C,
    "UICommandGraphDrawNode::mPositionSum offset must be 0x0C"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mWeight) == 0x18,
    "UICommandGraphDrawNode::mWeight offset must be 0x18"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mMeshInstance) == 0x20,
    "UICommandGraphDrawNode::mMeshInstance offset must be 0x20"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mOrientationHint) == 0x28,
    "UICommandGraphDrawNode::mOrientationHint offset must be 0x28"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mPreviousCentroid) == 0x34,
    "UICommandGraphDrawNode::mPreviousCentroid offset must be 0x34"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneA) == 0x48,
    "UICommandGraphDrawNode::mLaneA offset must be 0x48"
  );
  static_assert(
    offsetof(UICommandGraph::UICommandGraphDrawNode, mLaneB) == 0x60,
    "UICommandGraphDrawNode::mLaneB offset must be 0x60"
  );
  static_assert(sizeof(UICommandGraph::HashListNode2C) == 0x2C, "UICommandGraph::HashListNode2C size must be 0x2C");
  static_assert(sizeof(UICommandGraph::HashListNode10) == 0x10, "UICommandGraph::HashListNode10 size must be 0x10");
  static_assert(sizeof(UICommandGraph::HashBucketVector) == 0x10, "UICommandGraph::HashBucketVector size must be 0x10");
  static_assert(
    sizeof(UICommandGraph::HashTable<UICommandGraph::HashListNode88>) == 0x28,
    "UICommandGraph::HashTable size must be 0x28"
  );
  static_assert(
    sizeof(UICommandGraph::CommandGraphTreeNode) == 0x28, "UICommandGraph::CommandGraphTreeNode size must be 0x28"
  );
  static_assert(sizeof(UICommandGraph::CommandGraphTree) == 0x0C, "UICommandGraph::CommandGraphTree size must be 0x0C");
  static_assert(sizeof(UICommandGraph) == 0xDDC, "UICommandGraph size must be 0xDDC");

  /**
   * Address: 0x008243F0 (FUN_008243F0, ??0UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??0UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Seeds one command-graph style node with default animation/scaling lanes
   * and clears orderline/waypoint/arrowhead texture shared pointers.
   */
  UICommandGraphNode::UICommandGraphNode()
  {
    mOrderlineTexture.px = nullptr;
    mOrderlineTexture.pi = nullptr;
    mOrderlineAnimRate = 0.1f;
    mOrderlineAspectRatio = 1.0f;
    mOrderlineColor = 0u;
    mOrderlineSelectedColor = 0u;
    mOrderlineHighlightColor = 0u;
    mOrderlineGlow = 0.0f;
    mOrderlineSelectedGlow = 0.0f;
    mOrderlineHighlightGlow = 0.0f;
    mWaypointColor = 0u;
    mWaypointSelectedColor = 0u;
    mWaypointHighlightColor = 0u;
    mWaypointScale = 1.0f;
    mWaypointSelectedScale = 1.0f;
    mWaypointHighlightScale = 1.0f;
    mWaypointTexture.px = nullptr;
    mWaypointTexture.pi = nullptr;
    mArrowheadTexture.px = nullptr;
    mArrowheadTexture.pi = nullptr;
  }

  /**
   * Address: 0x008249B0 (FUN_008249B0, ??1UICommandGraphNode@Moho@@QAE@@Z)
   * Mangled: ??1UICommandGraphNode@Moho@@QAE@@Z
   *
   * What it does:
   * Releases command-graph texture shared-control lanes in arrowhead, waypoint,
   * then orderline teardown order.
   */
  UICommandGraphNode::~UICommandGraphNode()
  {
    mArrowheadTexture.release();
    mWaypointTexture.release();
    mOrderlineTexture.release();
  }

  /**
   * Address: 0x00825060 (FUN_00825060, Moho::UICommandGraphNode::cpy)
   *
   * NOTE (2026-08-20 audit): all three texture-lane releases below previously
   * called `.weak_release()`. FUN_00825060 confirms all three inline copies of
   * the retain/release pattern call FUN_004229B0 for the release step
   * (verified by manual displacement calculation at 0x00825087, 0x0082510E,
   * 0x0082513B), which is `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()` to match.
   *
   * What it does:
   * Copies one command-graph style node payload, including shared-texture
   * control lanes for orderline/waypoint/arrowhead textures.
   */
  UICommandGraphNode* UICommandGraphNode::CopyFrom(const UICommandGraphNode& other)
  {
    mOrderlineTexture.px = other.mOrderlineTexture.px;
    boost::detail::sp_counted_base* incomingControl = other.mOrderlineTexture.pi;
    if (incomingControl != mOrderlineTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mOrderlineTexture.pi != nullptr) {
        mOrderlineTexture.pi->release();
      }
      mOrderlineTexture.pi = incomingControl;
    }

    mOrderlineAspectRatio = other.mOrderlineAspectRatio;
    mOrderlineAnimRate = other.mOrderlineAnimRate;
    mOrderlineColor = other.mOrderlineColor;
    mOrderlineSelectedColor = other.mOrderlineSelectedColor;
    mOrderlineHighlightColor = other.mOrderlineHighlightColor;
    mOrderlineGlow = other.mOrderlineGlow;
    mOrderlineSelectedGlow = other.mOrderlineSelectedGlow;
    mOrderlineHighlightGlow = other.mOrderlineHighlightGlow;
    mWaypointColor = other.mWaypointColor;
    mWaypointSelectedColor = other.mWaypointSelectedColor;
    mWaypointHighlightColor = other.mWaypointHighlightColor;
    mWaypointScale = other.mWaypointScale;
    mWaypointSelectedScale = other.mWaypointSelectedScale;
    mWaypointHighlightScale = other.mWaypointHighlightScale;
    mArrowheadCapOffset = other.mArrowheadCapOffset;

    mWaypointTexture.px = other.mWaypointTexture.px;
    incomingControl = other.mWaypointTexture.pi;
    if (incomingControl != mWaypointTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mWaypointTexture.pi != nullptr) {
        mWaypointTexture.pi->release();
      }
      mWaypointTexture.pi = incomingControl;
    }

    mArrowheadTexture.px = other.mArrowheadTexture.px;
    incomingControl = other.mArrowheadTexture.pi;
    if (incomingControl != mArrowheadTexture.pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (mArrowheadTexture.pi != nullptr) {
        mArrowheadTexture.pi->release();
      }
      mArrowheadTexture.pi = incomingControl;
    }

    return this;
  }

  /**
   * Address: 0x00825570 (FUN_00825570)
   * Mangled: ?LoadTextures@UICommandGraphNode@Moho@@QAEXPAVLuaObject@LuaPlus@@PBDPAVLuaState@3@@Z
   *
   * NOTE (2026-08-20 audit): all three texture-lane assignments below
   * (orderline/waypoint/arrowhead) previously called `.weak_release()` in the
   * shared `assignSharedLane` lambda. FUN_00825570 confirms all three call
   * sites (0x008256E4, 0x00825B26, 0x00825EF9, xref-verified) target
   * FUN_004229B0, i.e. `sp_counted_base::release()`, not `weak_release()`
   * (see BoostWrappers.h). The acquire side (`add_ref_copy()`) was already
   * correct. Corrected to `.release()`; the lambda was renamed from
   * `assignWeakSharedLane` to match (function-local, no external callers).
   *
   * What it does:
   * Loads command-graph texture/style lanes from one Lua table entry, honoring
   * `inherit_from` recursion before overriding local orderline/waypoint/
   * arrowhead keys.
   */
  void UICommandGraphNode::LoadTextures(LuaPlus::LuaObject rootTable, const char* const key, LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject nodeTable = rootTable[key];
    if (nodeTable.IsNil()) {
      return;
    }

    LuaPlus::LuaObject inheritFrom = nodeTable["inherit_from"];
    if (!inheritFrom.IsNil()) {
      LoadTextures(LuaPlus::LuaObject(rootTable), inheritFrom.GetString(), state);
    }

    const auto hasKey = [&nodeTable](const char* const fieldName) -> bool {
      LuaPlus::LuaObject probe = nodeTable[fieldName];
      return !probe.IsNil();
    };

    const auto assignSharedLane = [](
                                    boost::SharedPtrRaw<void>& destination,
                                    void* const sourcePx,
                                    boost::detail::sp_counted_base* const sourceControl
                                  ) {
      destination.px = sourcePx;
      if (sourceControl != destination.pi) {
        if (sourceControl != nullptr) {
          sourceControl->add_ref_copy();
        }
        if (destination.pi != nullptr) {
          destination.pi->release();
        }
        destination.pi = sourceControl;
      }
    };

    if (hasKey("orderline_texture")) {
      if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          LuaPlus::LuaObject textureValue = nodeTable["orderline_texture"];
          ID3DDeviceResources::TextureResourceHandle loadedTexture{};
          resources->GetTexture(loadedTexture, textureValue.GetString(), 0, true);

          const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
          assignSharedLane(mOrderlineTexture, loadedRaw.px, loadedRaw.pi);
        }
      }
    }

    if (hasKey("orderline_uv_aspect_ratio")) {
      mOrderlineAspectRatio = static_cast<float>(nodeTable["orderline_uv_aspect_ratio"].GetNumber());
    }

    if (hasKey("orderline_anim_rate")) {
      mOrderlineAnimRate = static_cast<float>(nodeTable["orderline_anim_rate"].GetNumber());
    }

    if (hasKey("orderline_color")) {
      mOrderlineColor = SCR_DecodeColor(state, nodeTable["orderline_color"]);
    }

    if (hasKey("orderline_selected_color")) {
      mOrderlineSelectedColor = SCR_DecodeColor(state, nodeTable["orderline_selected_color"]);
    }

    if (hasKey("orderline_highlight_color")) {
      mOrderlineHighlightColor = SCR_DecodeColor(state, nodeTable["orderline_highlight_color"]);
    }

    if (hasKey("orderline_glow")) {
      mOrderlineGlow = static_cast<float>(nodeTable["orderline_glow"].GetNumber());
    }

    if (hasKey("orderline_selected_glow")) {
      mOrderlineSelectedGlow = static_cast<float>(nodeTable["orderline_selected_glow"].GetNumber());
    }

    if (hasKey("orderline_highlight_glow")) {
      mOrderlineHighlightGlow = static_cast<float>(nodeTable["orderline_highlight_glow"].GetNumber());
    }

    if (hasKey("waypoint_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["waypoint_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mWaypointTexture, loadedRaw.px, loadedRaw.pi);
    }

    if (hasKey("waypoint_color")) {
      mWaypointColor = SCR_DecodeColor(state, nodeTable["waypoint_color"]);
    }

    if (hasKey("waypoint_selected_color")) {
      mWaypointSelectedColor = SCR_DecodeColor(state, nodeTable["waypoint_selected_color"]);
    }

    if (hasKey("waypoint_highlight_color")) {
      mWaypointHighlightColor = SCR_DecodeColor(state, nodeTable["waypoint_highlight_color"]);
    }

    if (hasKey("waypoint_scale")) {
      mWaypointScale = static_cast<float>(nodeTable["waypoint_scale"].GetNumber());
    }

    if (hasKey("waypoint_selected_scale")) {
      mWaypointSelectedScale = static_cast<float>(nodeTable["waypoint_selected_scale"].GetNumber());
    }

    if (hasKey("waypoint_highlight_scale")) {
      mWaypointHighlightScale = static_cast<float>(nodeTable["waypoint_highlight_scale"].GetNumber());
    }

    if (hasKey("arrowhead_cap_offset")) {
      mArrowheadCapOffset = static_cast<float>(nodeTable["arrowhead_cap_offset"].GetNumber());
    }

    if (hasKey("arrowhead_texture")) {
      LuaPlus::LuaObject textureValue = nodeTable["arrowhead_texture"];
      const boost::shared_ptr<CD3DBatchTexture> loadedTexture = CD3DBatchTexture::FromFile(textureValue.GetString(), 1u);
      const boost::SharedPtrRaw<CD3DBatchTexture> loadedRaw = boost::SharedPtrRawFromSharedBorrow(loadedTexture);
      assignSharedLane(mArrowheadTexture, loadedRaw.px, loadedRaw.pi);
    }
  }

  /**
   * Address: 0x00824480 (FUN_00824480, sub_824480)
   *
   * What it does:
   * See the declaration in UserTarget.h.
   */
  UserTarget::UserTarget(UserEntity* const entity) noexcept
    : targetType(UserTargetType::Entity)
    , targetEntity(entity)
  {}

  /**
   * Address: 0x00823B40 (FUN_00823B40, struct_BuildTemplate::struct_BuildTemplate)
   *
   * What it does:
   * Copy-constructs one build-template entry (position, heading, blueprint id).
   */
  SBuildTemplateInfo::SBuildTemplateInfo(const SBuildTemplateInfo& other)
    : mPos(other.mPos)
    , mBuildOrder(other.mBuildOrder)
    , mBlueprintId(other.mBlueprintId)
  {}

  namespace
  {
    [[nodiscard]] IWldUIProvider* ResolveWldUIProvider() noexcept
    {
      if (sWldUIProvider == nullptr) {
        return nullptr;
      }

      return dynamic_cast<IWldUIProvider*>(sWldUIProvider);
    }

    // Forward-declared here (rather than defined) because the process-global
    // singleton lane below only ever holds a pointer; `StrategicIconAux`
    // itself is defined later in this same `moho`-scoped anonymous
    // namespace, next to `CWldSession::RenderStrategicIcons`'s callee
    // cluster (0x0085B6E0's lazy-init target, address 0x010C4300).
    struct StrategicIconAux;
    StrategicIconAux* gStrategicIconAuxiliary = nullptr;

    /**
     * Address: 0x0085EFE0 (FUN_0085EFE0)
     *
     * What it does:
     * Returns the global strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneA() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085EFF0 (FUN_0085EFF0)
     *
     * What it does:
     * Secondary entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneB() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    /**
     * Address: 0x0085F000 (FUN_0085F000)
     *
     * What it does:
     * Third entrypoint returning the strategic-icon auxiliary object lane.
     */
    [[nodiscard]] StrategicIconAux* GetStrategicIconAuxiliaryLaneC() noexcept
    {
      return gStrategicIconAuxiliary;
    }

    CWldSession* gActiveWldSession = nullptr;

    /**
     * The world session's simulation driver (`sSimDriver`, 0x010C4F50), a
     * `boost::scoped_ptr`. Its out-of-line members are LTCG copies specialised
     * on this global, none of them referenced:
     * Address: 0x0088E8B0 (FUN_0088E8B0, `reset`: new value stored first, old
     *   one deleted through vtable slot 0, no self-test)
     * Address: 0x0088E8F0 (FUN_0088E8F0, `operator unspecified_bool_type`: 0 when
     *   set, -1 - the null data-member pointer - when empty)
     * Address: 0x0088E9F0 (FUN_0088E9F0, `swap`: three plain stores)
     * Address: 0x00C07EB0 (FUN_00C07EB0, atexit destructor: delete through slot 0)
     * `get` is WLD_GetDriver (0x0088D330); 0x0088E8D0 and 0x0088E8E0 are its ICF
     * twins.
     */
    boost::scoped_ptr<ISTIDriver> sSimDriver;

    /**
     * The next session's launch description (0x010C4F58), a `std::auto_ptr`.
     * Address: 0x0088E900 (FUN_0088E900, its `operator=(auto_ptr&)` specialised
     *   on this global: release the source, delete the old value when it
     *   differs, return the global) - WLD_BeginSession's assignment.
     */
    msvc8::auto_ptr<SWldSessionInfo> gPendingWldSessionInfo;
    EWldFrameAction gWldFrameAction = EWldFrameAction::Inactive;

    /**
     * Address: 0x00869870 (FUN_00869870, session-listener attach dispatch)
     *
     * What it does:
     * Attaches every registered session listener to the current active world
     * session. The binary calls **vtable slot 0** here -
     * `(**v4)(v4, Moho::sWldSession)` - which is
     * `ISessionListener::AttachToSessionListenerLane`, not the detach slot the
     * teardown pass uses (see `DoTeardownCallbacks`, FUN_008698B0, which takes
     * `*v4 + 4`).
     */
    void DispatchSessionListenerAttach(WldTeardownCallbackVector* const callbacks)
    {
      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->AttachToSessionListenerLane(gActiveWldSession);
      }
    }

    [[nodiscard]] std::intptr_t DispatchSessionListenerAttachAndReturnLastResult(
      WldTeardownCallbackVector* const callbacks
    )
    {
      if (callbacks == nullptr) {
        return 0;
      }

      // The binary's return register still holds `_Myfirst` when the callback
      // list is empty, and otherwise whatever the last slot-0 call left in eax.
      // The attach hook is `void`, so the seed is the only defined value here
      // and no caller reads the result for anything but its truthiness.
      std::intptr_t result = reinterpret_cast<std::intptr_t>(callbacks->data());

      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->AttachToSessionListenerLane(gActiveWldSession);
      }

      return result;
    }

    /**
     * Address: 0x008698B0 (FUN_008698B0, func_DoTeardownCallbacks)
     *
     * What it does:
     * Detaches every registered session listener from the current active world
     * session. This is the teardown half of the pair: the binary dispatches
     * `(*(*v4 + 4))(v4, Moho::sWldSession)` - **vtable slot 1**,
     * `ISessionListener::DetachFromSessionListenerLane` - where the
     * creation-time pass at FUN_00869870 dispatches slot 0.
     */
    [[nodiscard]] std::intptr_t DoTeardownCallbacks(WldTeardownCallbackVector* const callbacks)
    {
      if (callbacks == nullptr) {
        return 0;
      }

      std::intptr_t result = reinterpret_cast<std::intptr_t>(callbacks->data());

      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->DetachFromSessionListenerLane(gActiveWldSession);
      }

      return result;
    }


    // `DestroyBuildTemplateInfo` (0x00823E10, per-element blueprint-id string
    // release) and `DestroyBuildTemplateRange` (0x00823DD0, the loop over it)
    // are the compiler's per-element/range release for `SBuildTemplateInfo`'s
    // `msvc8::string mBlueprintId` member -- the same release
    // `SBuildTemplateInfo`'s implicit destructor already performs. Now that
    // `gpg::fastvector_n<SBuildTemplateInfo, 16>` is `gpg::fastvector_n<SBuildTemplateInfo, 16>`
    // (CWldSession.h), that release happens through the container's own
    // element lifetime (array-new/delete[] on the heap arm, implicit dtor on
    // scope exit / overwrite-by-assignment on the inline arm -- see
    // `FastVectorN::ResetInline_`/`GrowInsertDeepCopy` in FastVector.h) rather
    // than a hand-rolled per-type free function; there is no separate body to
    // recover them into.

    void SortBuildTemplateRangeByOrder(SBuildTemplateInfo* const begin, SBuildTemplateInfo* const end)
    {
      if (begin == nullptr || end == nullptr || begin == end || begin + 1 == end) {
        return;
      }

      // The binary's whole sort instantiation for this element hangs off this
      // one line -- twelve emitted bodies, catalogued on the members of
      // legacy/algorithms/Sort.h. `msvc8::sort` rather than `std::sort`
      // because only the former models VC8's introsort exactly: the same
      // 32-element insertion-sort cutoff, the same 40-element ninther
      // threshold in the median pick, and the same three-quarters recursion
      // budget before it falls back to heapsort.
      msvc8::sort(
        begin,
        end,
        [](const SBuildTemplateInfo& lhs, const SBuildTemplateInfo& rhs) noexcept { return lhs.mBuildOrder < rhs.mBuildOrder; }
      );
    }

    // `RebindAndCopyBuildTemplateBufferInline` (0x00898E50) was the hand-rolled
    // rebind-to-inline + copy-construct pass that duplicated
    // `gpg::core::FastVectorN<SBuildTemplateInfo, 16>`'s own copy constructor
    // (`FastVectorN(const FastVectorN&) : FastVectorN() { ResetFrom(other); }`,
    // FastVector.h). `gpg::fastvector_n<SBuildTemplateInfo, 16>` now being that template directly
    // (CWldSession.h), the address is cited on that constructor instead; call
    // sites use placement-new (`GetActiveBuildTemplate` below) or plain
    // copy-construction, matching the binary's hidden-return-slot ABI for
    // returning a non-trivial type by value.

    /**
     * Address: 0x00823D30 (FUN_00823D30, sub_823D30)
     *
     * What it does:
     * Returns one first-dword lane from one build-template helper payload.
     */
    [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane0(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *static_cast<const std::uint32_t*>(value);
    }

    /**
     * Address: 0x00823D40 (FUN_00823D40, sub_823D40)
     *
     * What it does:
     * Returns one second-dword lane from one build-template helper payload.
     */
    [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane4(const void* const value) noexcept
    {
      if (value == nullptr) {
        return 0u;
      }
      return *(reinterpret_cast<const std::uint32_t*>(value) + 1);
    }

    constexpr std::uint32_t kBuildPreviewValidColor = 0xD800D800u;
    constexpr std::uint32_t kBuildPreviewInvalidColor = 0xD8D80000u;

    [[nodiscard]] SCoordsVec2 BuildPreviewCoordsFromWorldPosition(const Wm3::Vector3f& worldPosition) noexcept
    {
      return SCoordsVec2{worldPosition.x, worldPosition.z};
    }

    [[nodiscard]] std::uint32_t SelectBuildPreviewColor(
      const CWldSession& session,
      const bool placementAccepted
    ) noexcept
    {
      if (placementAccepted || !session.mShowInvalidBuildPlacementPreview) {
        return kBuildPreviewValidColor;
      }

      return kBuildPreviewInvalidColor;
    }

    void CopyOccupationPositionToPreviewTransform(
      const SOccupationResult& occupation,
      VTransform& previewTransform
    ) noexcept
    {
      previewTransform.pos_ = occupation.pos;
    }

    /**
     * Address: 0x00854930 (FUN_00854930, sub_854930)
     *
     * Wm3::Vector3f const &, Moho::RUnitBlueprint const *, Moho::VTransform &, Moho::CWldSession &, std::uint32_t &
     *
     * IDA signature:
     * int __userpurge sub_854930@<eax>(float *a1@<eax>, Moho::RUnitBlueprint *a2@<edx>, float *a3@<edi>, int esi0@<esi>, int *a5);
     *
     * What it does:
     * Evaluates build placement for one template-entry preview position, writes
     * the preview color, and snaps the preview transform to the occupation result.
     */
    [[nodiscard]] std::uint32_t ApplyBuildTemplatePlacementPreviewStatus(
      const Wm3::Vector3f& worldPosition,
      const RUnitBlueprint* const buildBlueprint,
      VTransform& previewTransform,
      CWldSession& session,
      std::uint32_t& outPreviewColor
    )
    {
      SOccupationResult occupation{};
      const SCoordsVec2 buildPosition = BuildPreviewCoordsFromWorldPosition(worldPosition);
      const bool canBuild = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);

      outPreviewColor = SelectBuildPreviewColor(session, canBuild);
      CopyOccupationPositionToPreviewTransform(occupation, previewTransform);
      return outPreviewColor;
    }

    /**
     * Address: 0x00854860 (FUN_00854860, sub_854860)
     *
     * Moho::CommandModeData const &, Wm3::Vector3f const &, Moho::CWldSession &, Moho::VTransform &, std::uint32_t &
     *
     * IDA signature:
     * float *__userpurge sub_854860@<eax>(_DWORD *a1@<edi>, float *a2@<esi>, int a3, float *arg4, int *a5);
     *
     * What it does:
     * Evaluates single-blueprint build preview placement, including anchored
     * build-distance validation, then writes preview color and snapped transform.
     */
    [[nodiscard]] VTransform* ApplyCommandModeBuildPlacementPreviewStatus(
      const CommandModeData& commandMode,
      const Wm3::Vector3f& worldPosition,
      CWldSession& session,
      VTransform& previewTransform,
      std::uint32_t& outPreviewColor
    )
    {
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(commandMode.mBlueprint);
      const SCoordsVec2 buildPosition = BuildPreviewCoordsFromWorldPosition(worldPosition);

      bool withinBuildDistance = true;
      if (commandMode.mMode == COMMOD_BuildAnchored) {
        withinBuildDistance = USERUNIT_WithinBuildDistance(session, buildBlueprint, buildPosition);
      }

      SOccupationResult occupation{};
      const bool canBuild = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);

      outPreviewColor = SelectBuildPreviewColor(session, withinBuildDistance && canBuild);
      CopyOccupationPositionToPreviewTransform(occupation, previewTransform);
      return &previewTransform;
    }

    /**
     * One classified entity in the strategic-icon pass - `struct_UnitIconData`
     * in the IDB. `CWldSession::RenderStrategicIcons` fills one of these per
     * visible entity, files it into one of the five runs on
     * `StrategicIconAux` below, and the emitters read it back.
     *
     * Layout evidence, all from the binary:
     *  - the copy-assignment at 0x0085CB00 walks every lane in order: two
     *    dwords at `+0`/`+4`, three floats at `+8`/`+12`/`+16`, three
     *    shared-pointer pairs at `+20`/`+24`, `+28`/`+32` and `+36`/`+40`
     *    (each re-seated through the `use_count_`/`weak_release` pair, so each
     *    is a `boost::shared_ptr`), then five single bytes at `+44`..`+48`;
     *  - the destructor at 0x0085CA20 releases exactly the control blocks held
     *    at `+0x18` (`mov esi, [edi+18h]`), `+0x20` and `+0x28`, which pins the
     *    three shared pointers to `+0x14`, `+0x1C` and `+0x24`;
     *  - the element stride is 0x34 in both the vector grow lane
     *    (`add esi, 34h` @ 0x0085EF3A) and the lifebar loop
     *    (`add edi, 34h` @ 0x0085C9C5), and every size computation in the
     *    family divides the byte span by 52.
     *
     * Flag roles come from `RenderUnitIcon` (0x0085D9A0), which is the only
     * reader: `+0x2C` gates the newly-created blink (0x0085DBF6), `+0x2D` the
     * pause overlay quad (0x0085DCD5), `+0x2E` the stunned overlay quad
     * (0x0085DD3C), `+0x2F` suppresses the base icon quad (0x0085DC90) and
     * `+0x30` marks the formation-preview ghost, whose colour is alpha-halved
     * instead of team-coloured (0x0085DBE1).
     *
     * The binary's per-type container and special-member emissions for this
     * struct are all covered by code that already exists, so none of them get
     * a hand-written copy here:
     *  - 0x0085CA20 is the compiler-generated `~UnitIconData` (three
     *    `shared_ptr` releases in reverse declaration order);
     *  - 0x0085CB00 is the compiler-generated `operator=`;
     *  - 0x0085ED70 / 0x0085EED0 / 0x0085F1B0 / 0x0085F290 are
     *    `msvc8::vector<UnitIconData>`'s `reserve` / `push_back` /
     *    `erase(first,last)` / destructor, and 0x0085F140, 0x0085F930,
     *    0x0085FDB0, 0x0085FFB0 and 0x0085F310 are that same instantiation's
     *    grow, allocate, copy-construct, uninitialised-copy and length-error
     *    lanes. They belong on `msvc8::vector<T>` in
     *    src/sdk/legacy/containers/Vector.h next to the other per-type
     *    emissions listed there, not as a second set of container primitives.
     * Address: 0x0085F740 (FUN_0085F740 -- the implicit copy constructor `UnitIconData(const UnitIconData&)`, emitted out of line for `msvc8::vector<UnitIconData>`'s placement copies: member-wise in declaration order (the two pointers, the three floats through `fld`/`fstp`, each `shared_ptr` with a `lock xadd` +1 on the non-null control block's `use_count_` at +0x18/+0x20/+0x28, then the five flag bytes up to +0x30), no release, so a construction rather than `operator=` 0x0085CB00; callers 0x0085F414 (`_Insert_n` 0x0085F3F0's `_Tmp = _Val`), 0x0085FDC8 (`_Uninit_fill_n` 0x0085FDB0), 0x0085FFC9 (`_Uninit_copy` 0x0085FFB0), 0x0085FFF8 (0x0085FFE0), and the null-guarded tail jumps 0x0085FE64 / 0x0085FF24 (`_Construct` / `allocator::construct`, nothing references them); formerly `CopyRefCountedPayload49Runtime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
     */
    struct UnitIconData
    {
      UserEntity* mUnit = nullptr;                       // +0x00
      const REntityBlueprint* mBlueprint = nullptr;      // +0x04
      float mWorldX = 0.0f;                              // +0x08
      float mWorldY = 0.0f;                              // +0x0C
      float mWorldZ = 0.0f;                              // +0x10
      boost::shared_ptr<CD3DBatchTexture> mIconTexture;    // +0x14
      boost::shared_ptr<CD3DBatchTexture> mPausedTexture;  // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mStunnedTexture; // +0x24
      /// Own or allied unit: the only ones whose icon blinks while fresh.
      bool mIsFriendly = false;        // +0x2C
      /// Draw the pause/toggle-off overlay over the icon.
      bool mShowPausedOverlay = false; // +0x2D
      /// Draw the stunned overlay over the icon.
      bool mShowStunnedOverlay = false; // +0x2E
      /// The unit's mesh is already on screen, so only the overlays are drawn.
      bool mSuppressBaseIcon = false;  // +0x2F
      /// Formation-preview ghost rather than a live unit.
      bool mIsFormationGhost = false;  // +0x30
      // +0x31..+0x33 is alignment padding, not a member: neither the copy
      // constructor (0x0085F740) nor `operator=` (0x0085CB00) copies it.
    };

    static_assert(sizeof(UnitIconData) == 0x34, "UnitIconData size must be 0x34");
    static_assert(offsetof(UnitIconData, mBlueprint) == 0x04, "UnitIconData::mBlueprint offset must be 0x04");
    static_assert(offsetof(UnitIconData, mWorldX) == 0x08, "UnitIconData::mWorldX offset must be 0x08");
    static_assert(offsetof(UnitIconData, mWorldZ) == 0x10, "UnitIconData::mWorldZ offset must be 0x10");
    static_assert(offsetof(UnitIconData, mIconTexture) == 0x14, "UnitIconData::mIconTexture offset must be 0x14");
    static_assert(offsetof(UnitIconData, mPausedTexture) == 0x1C, "UnitIconData::mPausedTexture offset must be 0x1C");
    static_assert(
      offsetof(UnitIconData, mStunnedTexture) == 0x24, "UnitIconData::mStunnedTexture offset must be 0x24"
    );
    static_assert(offsetof(UnitIconData, mIsFriendly) == 0x2C, "UnitIconData::mIsFriendly offset must be 0x2C");
    static_assert(
      offsetof(UnitIconData, mIsFormationGhost) == 0x30, "UnitIconData::mIsFormationGhost offset must be 0x30"
    );

    /**
     * The strategic-icon pass's per-frame scratch object - `struct_IconAux` in
     * the IDB. `CWldSession::RenderStrategicIcons` lazily allocates exactly one
     * of these into a process-global lane (0x010C4300) on its first frame and
     * reuses it forever after, clearing the five icon runs at the top of each
     * frame rather than reallocating them.
     *
     * Size evidence: the single allocation site pushes 0xACh
     * (`push 0ACh` @ 0x0085B72D) into `operator new` before running the
     * constructor at 0x0085B2A0.
     *
     * Field evidence (constructor 0x0085B2A0 unless noted):
     *  - `+0x00..0x0F` is the camera's viewport rect, copied a float at a time
     *    from `GeomCamera3::viewport.r[3]` (`fld [eax+2B4h]` ->
     *    `fstp [ebp+0]` .. `fld [eax+2C0h]` -> `fstp [ebp+0Ch]`,
     *    0x0085B864..0x0085B88B). It is the one region the constructor leaves
     *    alone, because the render entry rewrites it every frame.
     *  - `+0x10` session (`mov [ebp+10h], edi` @ 0x0085B861), `+0x14` batcher
     *    (`mov [ebp+14h], ebx` @ 0x0085B7C6), `+0x18` camera view
     *    (`mov [ebp+18h], eax` @ 0x0085B7C0).
     *  - `+0x1C` is a float, not the `CWldMap*` the mangled name types into
     *    that argument slot: the render entry stores the incoming slot with
     *    `movss dword ptr [ebp+1Ch], xmm0` (0x0085B85C) after loading it with
     *    `movss xmm0, [esp+argC]`, and the constructor zeroes it with
     *    `movss dword ptr [esi+1Ch], xmm0` (0x0085B2D0) rather than a `mov`.
     *    The lifebar emitter reads it back as the sub-tick interpolant that
     *    drives the fuel-empty blink (`*(float *)(aux+28)` at 0x0085D103).
     *  - `+0x20` the 0xFFFFFFFF solid-colour texture the bar quads are drawn
     *    with (`CD3DBatchTexture::FromSolidColor` @ 0x0085B349, stored at
     *    0x0085B35B/0x0085B38A).
     *  - `+0x28` the generic-icon table: `GetGenericIcons` is handed `aux+0x28`
     *    (`add eax, 28h` @ 0x0085B788) and indexes it as 8-byte elements
     *    (`&_Myfirst[2 * iconType]`), and 0x0085F020 sizes it to exactly 8.
     *  - `+0x38`/`+0x40` the pause and stunned rest textures.
     *  - `+0x48`, `+0x58`, `+0x68`, `+0x78`, `+0x88` the five icon runs, each
     *    a 0x10-byte `msvc8::vector` header the frame entry clears in turn
     *    (`lea eax, [ebp+48h]` .. `lea eax, [ebp+88h]`,
     *    0x0085B7C3..0x0085B82D) and the constructor reserves at
     *    0x200/0x200/0x40/0x80/0x80 elements.
     *  - `+0x98`, `+0x9C`, `+0xA0`, `+0xA4` the four `GameColors.TeamColorMode`
     *    entries, decoded in source order Self/Ally/Enemy/Neutral but stored
     *    Self/Neutral/Ally/Enemy (`mov [esi+98h], eax` 0x0085B4B1,
     *    `[esi+0A0h]` 0x0085B54C, `[esi+0A4h]` 0x0085B5DF, `[esi+9Ch]`
     *    0x0085B672), and `+0xA8` the unidentified-blip colour
     *    (`mov [esi+0A8h], eax` @ 0x0085B6AD).
     *
     * The five runs are drawn in declaration order, which is why the split
     * matters: ground icons, then air icons on top of them (the classifier
     * picks the second run when `RUnitBlueprint::Air.CanFly`, blueprint+0x368,
     * is set - 0x0085C2E8), then the high-sort-priority icons whose blueprint
     * carries its own texture, then the selected units, and finally the
     * lifebars under their own `TLifeBar` technique.
     */
    struct StrategicIconAux
    {
      float mViewportX = 0.0f;              // +0x00
      float mViewportY = 0.0f;              // +0x04
      float mViewportWidth = 0.0f;          // +0x08
      float mViewportHeight = 0.0f;         // +0x0C
      CWldSession* mSession = nullptr;      // +0x10
      CD3DPrimBatcher* mBatcher = nullptr;  // +0x14
      const GeomCamera3* mCamera = nullptr; // +0x18
      /// Sub-tick interpolant for this frame; see the `+0x1C` note above.
      float mTickFraction = 0.0f;                                       // +0x1C
      boost::shared_ptr<CD3DBatchTexture> mWhiteTexture;                // +0x20
      msvc8::vector<boost::shared_ptr<CD3DBatchTexture>> mGenericIcons; // +0x28
      boost::shared_ptr<CD3DBatchTexture> mPauseRestTexture;            // +0x38
      boost::shared_ptr<CD3DBatchTexture> mStunnedRestTexture;          // +0x40
      msvc8::vector<UnitIconData> mGroundIcons;       // +0x48
      msvc8::vector<UnitIconData> mAirIcons;          // +0x58
      msvc8::vector<UnitIconData> mHighPriorityIcons; // +0x68
      msvc8::vector<UnitIconData> mSelectedIcons;     // +0x78
      msvc8::vector<UnitIconData> mLifebarIcons;      // +0x88
      std::uint32_t mSelfColor = 0u;         // +0x98
      std::uint32_t mNeutralColor = 0u;      // +0x9C
      std::uint32_t mAllyColor = 0u;         // +0xA0
      std::uint32_t mEnemyColor = 0u;        // +0xA4
      std::uint32_t mUnidentifiedColor = 0u; // +0xA8

      /**
       * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
       * Mangled: struct_IconAux *__stdcall struct_TeamColors::struct_TeamColors(struct_IconAux *this)
       *
       * What it does:
       * Builds the white solid-colour texture, reserves the five icon runs to
       * their binary-observed capacities (0x200/0x200/0x40/0x80/0x80 for
       * ground/air/high-priority/selected/lifebar), and decodes the four
       * `GameColors.TeamColorMode` entries plus the unidentified-blip colour.
       * `mGenericIcons`/`mPauseRestTexture`/`mStunnedRestTexture` are left
       * empty here - the binary fills them from separate calls
       * (`LoadGenericIcons`/`LoadPauseAndStunnedRestTextures`) right after
       * construction, not from this constructor.
       */
      StrategicIconAux();

      /**
       * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
       * Mangled: LuaPlus::LuaObject *__cdecl struct_IconAux::GetGenericIcons(Moho::CWldSession *session, std::vector *target)
       *
       * What it does:
       * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
       * fills one `mGenericIcons` slot per `EGenericIconType` key with the
       * named batch texture. `mGenericIcons` is sized to exactly 8 first
       * (0x0085F020, the `msvc8::vector<boost::shared_ptr<CD3DBatchTexture>>`
       * resize lane for this instantiation - a per-type container emission
       * already covered generically by `msvc8::vector<T>::resize`, the same
       * way the sibling `UnitIconData` instantiation's reserve/push_back/erase
       * lanes are documented above rather than hand-recovered).
       */
      void LoadGenericIcons(CWldSession* session);

      /**
       * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
       *
       * What it does:
       * Imports strategic icon Lua tables and refreshes pause/stunned overlay
       * rest textures for one icon-aux runtime object.
       */
      void LoadPauseAndStunnedRestTextures(CWldSession* session);
    };

    static_assert(sizeof(StrategicIconAux) == 0xAC, "StrategicIconAux size must be 0xAC");
    static_assert(
      offsetof(StrategicIconAux, mViewportWidth) == 0x08, "StrategicIconAux::mViewportWidth offset must be 0x08"
    );
    static_assert(
      offsetof(StrategicIconAux, mSession) == 0x10, "StrategicIconAux::mSession offset must be 0x10"
    );
    static_assert(
      offsetof(StrategicIconAux, mBatcher) == 0x14, "StrategicIconAux::mBatcher offset must be 0x14"
    );
    static_assert(offsetof(StrategicIconAux, mCamera) == 0x18, "StrategicIconAux::mCamera offset must be 0x18");
    static_assert(
      offsetof(StrategicIconAux, mTickFraction) == 0x1C, "StrategicIconAux::mTickFraction offset must be 0x1C"
    );
    static_assert(
      offsetof(StrategicIconAux, mWhiteTexture) == 0x20, "StrategicIconAux::mWhiteTexture offset must be 0x20"
    );
    static_assert(
      offsetof(StrategicIconAux, mGenericIcons) == 0x28, "StrategicIconAux::mGenericIcons offset must be 0x28"
    );
    static_assert(
      offsetof(StrategicIconAux, mPauseRestTexture) == 0x38,
      "StrategicIconAux::mPauseRestTexture offset must be 0x38"
    );
    static_assert(
      offsetof(StrategicIconAux, mStunnedRestTexture) == 0x40,
      "StrategicIconAux::mStunnedRestTexture offset must be 0x40"
    );
    static_assert(
      offsetof(StrategicIconAux, mGroundIcons) == 0x48, "StrategicIconAux::mGroundIcons offset must be 0x48"
    );
    static_assert(
      offsetof(StrategicIconAux, mAirIcons) == 0x58, "StrategicIconAux::mAirIcons offset must be 0x58"
    );
    static_assert(
      offsetof(StrategicIconAux, mHighPriorityIcons) == 0x68,
      "StrategicIconAux::mHighPriorityIcons offset must be 0x68"
    );
    static_assert(
      offsetof(StrategicIconAux, mSelectedIcons) == 0x78, "StrategicIconAux::mSelectedIcons offset must be 0x78"
    );
    static_assert(
      offsetof(StrategicIconAux, mLifebarIcons) == 0x88, "StrategicIconAux::mLifebarIcons offset must be 0x88"
    );
    static_assert(
      offsetof(StrategicIconAux, mSelfColor) == 0x98, "StrategicIconAux::mSelfColor offset must be 0x98"
    );
    static_assert(
      offsetof(StrategicIconAux, mUnidentifiedColor) == 0xA8,
      "StrategicIconAux::mUnidentifiedColor offset must be 0xA8"
    );

    /**
     * Address: 0x0085B2A0 (FUN_0085B2A0, struct_TeamColors::struct_TeamColors)
     *
     * What it does:
     * Builds the white solid-colour texture, reserves the five icon runs to
     * their binary-observed capacities, and decodes the team-color palette.
     * See the class comment above for the full field-by-field evidence.
     */
    StrategicIconAux::StrategicIconAux()
    {
      mWhiteTexture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);

      mGroundIcons.reserve(0x200);
      mAirIcons.reserve(0x200);
      mHighPriorityIcons.reserve(0x40);
      mSelectedIcons.reserve(0x80);
      mLifebarIcons.reserve(0x80);

      // Held until the LuaObjects below are gone: they live in the shared colour LuaState.
      const auto colorLock = moho::LockColorLuaState();
      LuaPlus::LuaObject* const colors = moho::GetColors();
      const LuaPlus::LuaObject gameColors = (*colors)["GameColors"];
      const LuaPlus::LuaObject teamColorMode = gameColors["TeamColorMode"];

      // Decoded in the binary's source order (Self/Ally/Enemy/Neutral); the
      // storage order (Self/Neutral/Ally/Enemy) is just field layout, not a
      // reordering of which key feeds which member.
      mSelfColor = SCR_DecodeColor(msvc8::string(teamColorMode["Self"].GetString()));
      mAllyColor = SCR_DecodeColor(msvc8::string(teamColorMode["Ally"].GetString()));
      mEnemyColor = SCR_DecodeColor(msvc8::string(teamColorMode["Enemy"].GetString()));
      mNeutralColor = SCR_DecodeColor(msvc8::string(teamColorMode["Neutral"].GetString()));

      mUnidentifiedColor = moho::GetUnidentifiedColor();
    }

    /**
     * Address: 0x0085E7F0 (FUN_0085E7F0, struct_IconAux::GetGenericIcons)
     *
     * What it does:
     * Loads `/lua/ui/game/strategicIcons.lua`'s `GenericIcons` table and
     * fills one `mGenericIcons` slot per `EGenericIconType` key with the
     * named batch texture.
     */
    void StrategicIconAux::LoadGenericIcons(CWldSession* const session)
    {
      mGenericIcons.resize(8);

      const LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      const LuaPlus::LuaObject genericIcons = iconTable.GetByName("GenericIcons");

      for (LuaPlus::LuaTableIterator iter(genericIcons, 1); iter.IsValid(); iter.Next()) {
        EGenericIconType iconType{};
        gpg::RRef enumRef{};
        enumRef = gpg::MakeRRef<moho::EGenericIconType>(&iconType);
        SCR_GetEnum(session->mState, iter.GetKey().GetString(), enumRef);

        mGenericIcons[static_cast<std::size_t>(iconType)] = CD3DBatchTexture::FromFile(iter.GetValue().GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085EA60 (FUN_0085EA60, struct_IconAux::GetStunIcons)
     *
     * What it does:
     * Imports strategic icon Lua tables and refreshes pause/stunned overlay
     * rest textures for one icon-aux runtime object.
     */
    void StrategicIconAux::LoadPauseAndStunnedRestTextures(CWldSession* const session)
    {
      LuaPlus::LuaObject iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject pauseIcons = iconTable.GetByName("PauseIcons");
      LuaPlus::LuaObject pauseRest = pauseIcons.GetByName("PauseRest");
      if (pauseRest.IsString()) {
        mPauseRestTexture = CD3DBatchTexture::FromFile(pauseRest.GetString(), 0u);
      }

      iconTable = SCR_Import(session->mState, "/lua/ui/game/strategicIcons.lua");
      LuaPlus::LuaObject stunnedIcons = iconTable.GetByName("StunnedIcons");
      LuaPlus::LuaObject stunnedRest = stunnedIcons.GetByName("StunnedRest");
      if (stunnedRest.IsString()) {
        mStunnedRestTexture = CD3DBatchTexture::FromFile(stunnedRest.GetString(), 0u);
      }
    }

    /**
     * Address: 0x0085CBD0 (FUN_0085CBD0, sub_85CBD0)
     *
     * IDA signature:
     * _DWORD *callcnv_F3 sub_85CBD0@<eax>(_DWORD *a1@<eax>, _DWORD **a2@<ebx>, int a3@<edi>, _DWORD *a4@<esi>, char a5);
     *
     * What it does:
     * Picks the shared "no specific blueprint icon" texture for one unit:
     * a fixed structure icon for immobile blueprints, or a land/naval/air
     * icon looked up by the unit's movement layer for mobile ones, or the
     * plain white texture when the layer doesn't match any of those three.
     * `wantHighlightVariant` selects the `*HL` (highlight) icon set over the
     * plain set - the caller (`PickUnitStrategicIconTexture` below) passes
     * `true` for the mouse-over case and `false` otherwise.
     *
     * Evidence: `iconData->mBlueprint->IsMobile()` is the vtable-slot-4
     * dispatch at 0x0085CBD9/0x0085CBDC (`REntityBlueprint` vftable slot 4,
     * byte-verified against `bin/2025.7.1/ForgedAlliance.exe` at 0x00E0F604
     * == 0x00511B60 == `REntityBlueprint::IsMobile`). The category switch
     * reads `iconData->mUnit->mVariableData.mLayerMask` (UserEntity+0xF0,
     * `cmp .. 0F0h` @ 0x0085CC20/0x0085CC87) and its case labels (1 / 2,4,8 /
     * 16) match `ELayer`'s `LAYER_Land` / `LAYER_Seabed|LAYER_Sub|LAYER_Water`
     * / `LAYER_Air` exactly. Every branch is a plain `boost::shared_ptr`
     * copy (`sub_428340`, itself just `*dst = *src; if (src.pn)
     * ++src.pn->use_count_`) from one of `aux->mGenericIcons`'s eight slots
     * or `aux->mWhiteTexture` - never a weak-to-shared promotion.
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture> PickGenericStrategicIconTexture(
      const StrategicIconAux& aux, const UnitIconData& iconData, const bool wantHighlightVariant
    )
    {
      if (!iconData.mBlueprint->IsMobile()) {
        return aux.mGenericIcons[wantHighlightVariant ? GIT_StructureHL : GIT_Structure];
      }

      switch (static_cast<ELayer>(iconData.mUnit->mVariableData.mLayerMask)) {
        case LAYER_Land:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_LandHL : GIT_Land];
        case LAYER_Seabed:
        case LAYER_Sub:
        case LAYER_Water:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_NavalHL : GIT_Naval];
        case LAYER_Air:
          return aux.mGenericIcons[wantHighlightVariant ? GIT_AirHL : GIT_Air];
        default:
          return aux.mWhiteTexture;
      }
    }

    /**
     * Address: 0x0085D880 (FUN_0085D880, sub_85D880)
     *
     * IDA signature:
     * Moho::CAniPose **__usercall sub_85D880@<eax>(Moho::UserEntity **eax0@<eax>,
     *   Moho::CAniPose **a2@<edx>, char a3@<cl>, int a4, char a5, _DWORD *a1);
     *
     * What it does:
     * Picks the strategic-icon texture for one classified unit. A unit that
     * qualifies for a per-blueprint icon (is a real `UserUnit` and its
     * `mIntelStateFlags` "has real blueprint data" bit is set - the same bit
     * `UserEntity.cpp` already names `kSelectionBracketEnemyVisibleMask`) picks
     * one of the blueprint's four cached textures by `(isHovered, isSelected
     * && selectedVariantEligible)`: Rest / Over / Selected / SelectedOver.
     * Everything else (recon blips, wrecks, props, or a unit whose intel
     * doesn't carry full blueprint data) falls back to
     * `PickGenericStrategicIconTexture`.
     *
     * Evidence, all byte-verified in `FUN_0085D880.asm`:
     *  - `mov edx, [eax+0Ch]; call edx` (0x0085D893/0x0085D89E) is vtable
     *    slot 3 on `iconData.mUnit`, i.e. `UserEntity::IsUserUnit()`
     *    (Hex-Rays' "IsUserUnit2" is its own disambiguation of the
     *    const/non-const overload pair, not a distinct virtual).
     *  - `test byte ptr [eax+3E0h], 10h` (0x0085D8AB/0x0085D954) reads bit
     *    0x10 of `UserUnit::mIntelStateFlags` (already documented on that
     *    field: "0x10=has-data").
     *  - The four cached-texture fetches are inlined `boost::shared_ptr`
     *    copies (unconditional `lock xadd`, no expiry check) from
     *    `iconData.mBlueprint`+0x15C/0x164/0x16C/0x174 -
     *    `mStrategicIconRest/Selected/Over/SelectedOver` exactly (see the
     *    retype note on those fields in `REntityBlueprint.h`).
     */
    [[nodiscard]] boost::shared_ptr<CD3DBatchTexture> PickUnitStrategicIconTexture(
      const StrategicIconAux& aux,
      const UnitIconData& iconData,
      const bool isSelected,
      const bool selectedVariantEligible,
      const bool isHovered
    )
    {
      UserUnit* const asUnit = iconData.mUnit->IsUserUnit();
      // Same bit UserEntity.cpp's kSelectionBracketEnemyVisibleMask names on
      // mIntelStateFlags; re-declared locally because that constant is
      // file-private there.
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool usesGenericIcon =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) == 0u;

      if (isHovered) {
        if (usesGenericIcon) {
          return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/true);
        }
        return (isSelected && selectedVariantEligible) ? iconData.mBlueprint->mStrategicIconSelectedOver
                                                         : iconData.mBlueprint->mStrategicIconOver;
      }

      if (isSelected && selectedVariantEligible) {
        return iconData.mBlueprint->mStrategicIconSelected;
      }
      if (usesGenericIcon) {
        return PickGenericStrategicIconTexture(aux, iconData, /*wantHighlightVariant=*/false);
      }
      return iconData.mBlueprint->mStrategicIconRest;
    }

    template <typename TNode>
    [[nodiscard]] TNode* AllocateSelfLinkedNode()
    {
      auto* const node = static_cast<TNode*>(::operator new(sizeof(TNode)));
      std::memset(node, 0, sizeof(TNode));
      node->mNext = node;
      node->mPrev = node;
      return node;
    }

  } // namespace

  void UICommandGraph::ReleaseIntrusive(CD3DFont*& font)
  {
    if (!font) {
      return;
    }

    --font->mRefCount;
    if (font->mRefCount == 0) {
      font->Release(1);
    }
    font = nullptr;
  }

  void UICommandGraph::AssignIntrusive(CD3DFont*& dst, CD3DFont* const src)
  {
    if (dst == src) {
      return;
    }

    ReleaseIntrusive(dst);
    dst = src;
    if (dst) {
      ++dst->mRefCount;
    }
  }

  /**
   * Address: 0x00826550 (FUN_00826550, sub_826550)
   *
   * IDA signature:
   * _DWORD *__stdcall sub_826550(int a1);
   *
   * What it does:
   * Tears one draw node down: both dword lanes are released back to their
   * inline storage (freeing the spilled heap block if there is one), the weak
   * owner reference is dropped, and the node is spliced out of its command's
   * intrusive chain.
   *
   * The binary releases lane B before lane A; the order is preserved because
   * `operator delete[]` is observable.
   */
  /**
   * Address: 0x00824600 (FUN_00824600, sub_824600)
   *
   * What it does:
   * Seeds a fresh draw node in the binary's store order: `mCommandId = -1`,
   * the helper link nulled, the +0x0C..+0x18 float run zeroed, the two
   * flag bytes cleared and `mIsVisible = 1` (+0x1E; the pad byte at +0x1F is
   * not written), no mesh, the +0x28..+0x44 run zeroed, then both lanes armed
   * on their inline windows. It was a free function over a padded 0x78-byte
   * view that `FindOrInsertCommandGraphDrawNode` then reinterpreted as this
   * type.
   *
   * The binary arms each lane with a one-slot capacity (`lea edx,[ecx+4]` at
   * 0x00824667/0x00824670, and the same in the lane copy constructor
   * 0x0082E5E0); the lanes here are modelled as two-slot `fastvector_n`s, so
   * their own constructor arms two. Every default node is only ever copied
   * (`RelocateDrawNode`) and destroyed, neither of which reads the capacity
   * of an empty inline lane.
   */
  UICommandGraph::UICommandGraphDrawNode::UICommandGraphDrawNode()
    : mCommandId(-1)
    , mHelperLink()
    , mPositionSum(0.0f, 0.0f, 0.0f)
    , mWeight(0.0f)
    , mHasResolvedPosition(0u)
    , mIsChainBoundary(0u)
    , mIsVisible(1u)
    , mMeshInstance{}
    , mOrientationHint(0.0f, 0.0f, 0.0f)
    , mPreviousCentroid(0.0f, 0.0f, 0.0f)
    , mUnitCountScale(0.0f)
    , mCompletionTick(0u)
    , mLaneA()
    , mLaneB()
  {}

  UICommandGraph::UICommandGraphDrawNode::~UICommandGraphDrawNode()
  {
    mLaneB.ResetStorageToInline();
    mLaneA.ResetStorageToInline();

    mMeshInstance.release();
    // `mHelperLink` unlinks as the last member (0x008265E8).
  }

  /**
   * Address: 0x0082F030 (FUN_0082F030)
   */
  UICommandGraph::HashListNode88* UICommandGraph::AllocateMapABListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode88>();
  }

  /**
   * Address: 0x0082F5B0 (FUN_0082F5B0)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::AllocateMapCListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode2C>();
  }

  /**
   * Address: 0x0082FAF0 (FUN_0082FAF0)
   */
  UICommandGraph::HashListNode10* UICommandGraph::AllocateMapDListSentinel()
  {
    return AllocateSelfLinkedNode<HashListNode10>();
  }

  /**
   * Address: 0x0082BF40 (FUN_0082BF40)
   */
  void UICommandGraph::InitMapAB(HashTable<HashListNode88>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapABListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C400 (FUN_0082C400)
   */
  void UICommandGraph::InitMapC(HashTable<HashListNode2C>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapCListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082C8D0 (FUN_0082C8D0)
   */
  void UICommandGraph::InitMapD(HashTable<HashListNode10>& table, const UICommandGraph* const owner)
  {
    table.mOwnerByte = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(owner) & 0xFFu);
    table.mListHead = AllocateMapDListSentinel();
    table.mListSize = 0u;
    table.mBuckets.assign(9u, table.mListHead);
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082FAB0 (FUN_0082FAB0, MSVC8 `std::list<T>::clear` inline expansion for
   *                      trivial-destructor hash-list nodes)
   * Address: 0x0082C840 (FUN_0082C840, the `HashListNode2C` instantiation of this same
   *                      template, reached from mMapC's teardown. Verified as the same
   *                      body rather than assumed: both are 19 instructions with an
   *                      identical mnemonic sequence, and the sole `call rel32` in each
   *                      resolves to the same target, 0x00957A60 `operator delete`. The
   *                      two node types compile to identical code because neither
   *                      payload needs destroying, so only the link teardown remains.)
   *
   * IDA signature:
   * _DWORD *__usercall sub_82FAB0@<eax>(int a1@<esi>);
   *
   * What it does:
   * Clears one sentinel-headed doubly-linked list in place. Resets the sentinel
   * head's next/prev to itself, zeroes the size lane, then walks each former
   * payload node, destroys its payload and frees its allocation.
   *
   * 0x0082FAB0 is the 0x10-node table's clear and frees without destroying,
   * because that table's payload really is trivially destructible. The AB
   * tables are not: their list-erase helper at 0x0082EF80 calls the draw-node
   * destructor on `node + 0x10` before `operator delete(node)`, so `TNode`
   * opts in through `DestroyPayload`. Without that call each cleared node
   * leaks both spilled dword lanes and one weak reference.
   *
   * Address: 0x0082EFF0 (FUN_0082EFF0, the `HashListNode88` instantiation
   * predicted above -- confirmed against its own decompile, not just the
   * prose prediction: `_DWORD* v2` per-node cursor, `v2 + 4` in the raw
   * pseudocode is DWORD-stride pointer arithmetic (`v2` is `_DWORD*`), i.e.
   * byte offset `+0x10`, matching this citation's "node + 0x10" exactly.
   * Self-link reset (`*headSlot = headSlot`) happens BEFORE the destroy
   * loop, matching this member's reentrancy-safety ordering. Reached from
   * three call sites: `UICommandGraph::UICommandGraph` (0x00824810),
   * `~UICommandGraph` (0x00824B80), and `InitMapAB` (0x0082BF40, cited
   * below) -- `InitMapAB` calling a clear routine before its own
   * from-scratch setup reads as a defensive pre-clear; the ctor's own
   * direct call likely covers a table `InitMapAB` doesn't own. The
   * "0x0082EF80" address this comment predicted for the per-node
   * destructor-calling helper is a separate, still-unrecovered token from
   * this one (0x0082EFF0 is the whole clear-loop, not the inner call);
   * not chased down further in this pass.)
   */
  template <typename TNode>
  void UICommandGraph::ClearHashListNodes(HashTable<TNode>& table) noexcept
  {
    TNode* const head = table.mListHead;
    if (head == nullptr) {
      return;
    }

    // Detach circular list: sentinel becomes empty before node frees so any
    // re-entrancy during ::operator delete cannot observe stale next/prev links.
    TNode* current = head->mNext;
    head->mNext = head;
    head->mPrev = head;
    table.mListSize = 0u;

    while (current != head) {
      TNode* const next = current->mNext;
      // The sentinel head is deliberately excluded from this walk: the binary
      // never constructs its payload, and neither does AllocateSelfLinkedNode.
      if constexpr (requires(TNode* node) { TNode::DestroyPayload(node); }) {
        TNode::DestroyPayload(current);
      }
      ::operator delete(current);
      current = next;
    }
  }

  template <typename TNode>
  void UICommandGraph::DestroyMap(HashTable<TNode>& table)
  {
    ClearHashListNodes(table);

    if (table.mListHead) {
      ::operator delete(table.mListHead);
      table.mListHead = nullptr;
    }

    table.mBuckets = HashBucketVector{};  // VC8 _Tidy(): destroy + free + null the lanes
    table.mBucketMask = 1u;
    table.mBucketCount = 1u;
  }

  /**
   * Address: 0x0082D530 (FUN_0082D530, sub_82D530 -- the SEH-wrapped emission:
   *                      it installs SEH_82D530, carries unwind funclets at
   *                      0x00B843xx and ends in ___CxxFrameHandler3_0)
   * Address: 0x00826620 (FUN_00826620, the same source body emitted without EH
   *                      scaffolding, 86 instructions vs 128)
   *
   * NOTE: these two are NOT ICF twins, despite an earlier note in the progress
   * DB saying so - ICF folds byte-identical COMDATs and these differ in size
   * and at the very first instruction (`push ebx` vs `mov eax, large fs:0`).
   * They are one source function emitted twice, once in a context needing
   * exception scaffolding and once not; the field-by-field copy order is
   * identical in both (mCommandId, helper-link relink, the +0x0C..+0x18 float
   * quad, the three +0x1C..+0x1E bytes, +0x20, the +0x24 weak_release/
   * lock-xadd add_ref pair, the +0x28..+0x40 float run, +0x44, then the two
   * dword-lane copies).
   */
  UICommandGraph::UICommandGraphDrawNode* UICommandGraph::RelocateDrawNode(
    UICommandGraphDrawNode* const destination, UICommandGraphDrawNode& source
  )
  {
    destination->mCommandId = source.mCommandId;

    // `WeakPtr`'s copy constructor into the raw destination slot: the copy
    // joins the source's helper chain, and the source stays on it until its
    // caller destroys it.
    ::new (static_cast<void*>(&destination->mHelperLink)) WeakPtr<UserCommandIssueHelper>(source.mHelperLink);

    destination->mPositionSum = source.mPositionSum;
    destination->mWeight = source.mWeight;
    destination->mHasResolvedPosition = source.mHasResolvedPosition;
    destination->mIsChainBoundary = source.mIsChainBoundary;
    destination->mIsVisible = source.mIsVisible;

    // Retain a new strong reference on the shared control block rather than
    // transferring ownership - `source` keeps its own reference and is torn
    // down separately by its caller.
    destination->mMeshInstance = source.mMeshInstance.clone_retained();

    destination->mOrientationHint = source.mOrientationHint;
    destination->mPreviousCentroid = source.mPreviousCentroid;
    destination->mUnitCountScale = source.mUnitCountScale;
    destination->mCompletionTick = source.mCompletionTick;

    // The two lane copies: `fastvector_n<CommandGraphEdge*, 2>`'s copy constructor
    // (0x0082E5E0, cited on FastVector.h) into the raw destination slots.
    ::new (static_cast<void*>(&destination->mLaneA)) gpg::fastvector_n<CommandGraphEdge*, 2>(source.mLaneA);
    ::new (static_cast<void*>(&destination->mLaneB)) gpg::fastvector_n<CommandGraphEdge*, 2>(source.mLaneB);

    return destination;
  }

  /**
   * Address: 0x00831AB0 (FUN_00831AB0, sub_831AB0)
   */
  void* UICommandGraph::AllocateHashListNode88Storage(const std::size_t count)
  {
    if ((0xFFFFFFFFu / static_cast<std::uint32_t>(count)) < sizeof(HashListNode88)) {
      throw std::bad_alloc();
    }
    return ::operator new(sizeof(HashListNode88) * count);
  }

  /**
   * Address: 0x00831D80 (FUN_00831D80, sub_831D80)
   */
  UICommandGraph::HashListNode88Value* UICommandGraph::ConstructHashListNode88Value(
    HashListNode88Value* const destination, HashListNode88Value& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    destination->mKey = source.mKey;
    RelocateDrawNode(&destination->mDraw, source.mDraw);
    return destination;
  }

  /**
   * Address: 0x008304D0 (FUN_008304D0, sub_8304D0)
   */
  UICommandGraph::HashListNode88* UICommandGraph::ConstructHashListNode88(
    HashListNode88* const next, HashListNode88* const prev, HashListNode88Value& valueSource
  )
  {
    auto* const node = static_cast<HashListNode88*>(AllocateHashListNode88Storage(1));
    node->mNext = next;
    node->mPrev = prev;
    try {
      ConstructHashListNode88Value(reinterpret_cast<HashListNode88Value*>(&node->mKey), valueSource);
    } catch (...) {
      ::operator delete(node);
      throw;
    }
    return node;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   */
  template <typename TNode>
  std::uint32_t UICommandGraph::HashKeyToBucketIndex(const HashTable<TNode>& table, const std::uint32_t key) noexcept
  {
    const std::ldiv_t split = std::ldiv(static_cast<long>(key ^ 0xDEADBEEFu), 127773L);
    long scrambled = 16807L * split.rem - 2836L * split.quot;
    if (scrambled < 0) {
      scrambled += 0x7FFFFFFFL;
    }
    std::uint32_t bucketIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;
    if (table.mBucketCount <= bucketIndex) {
      bucketIndex += static_cast<std::uint32_t>(-1) - (table.mBucketMask >> 1u);
    }
    return bucketIndex;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   * Address: 0x0082D960 (FUN_0082D960, sub_82D960, the pair-key combine step).
   */
  template <typename TNode>
  std::uint32_t UICommandGraph::HashKeyToBucketIndex(
    const HashTable<TNode>& table, const std::uint32_t keyLow, const std::uint32_t keyHigh
  ) noexcept
  {
    const std::ldiv_t split =
      std::ldiv(static_cast<long>(3863u * keyLow + 7919u * keyHigh + 53849u * (keyLow ^ keyHigh)), 127773L);
    long scrambled = 16807L * split.rem - 2836L * split.quot;
    if (scrambled < 0) {
      scrambled += 0x7FFFFFFFL;
    }
    std::uint32_t bucketIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;
    if (table.mBucketCount <= bucketIndex) {
      bucketIndex += static_cast<std::uint32_t>(-1) - (table.mBucketMask >> 1u);
    }
    return bucketIndex;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   * Shared scalar-key find shape (`FindHashListNode10` = 0x0082C950).
   */
  template <typename TNode>
  TNode* UICommandGraph::FindHashListNode(HashTable<TNode>& table, const std::uint32_t key) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key);
    auto* const bucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
    TNode* node = bucketSlots[bucketIndex];
    TNode* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node == bucketEnd) {
      return table.mListHead;
    }
    while (node->mKey < key) {
      node = node->mNext;
      if (node == bucketEnd) {
        return table.mListHead;
      }
    }
    return (key >= node->mKey) ? node : table.mListHead;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   * Shared pair-key find shape (`FindHashListNode2C` = 0x0082C750).
   */
  template <typename TNode>
  TNode* UICommandGraph::FindHashListNode(
    HashTable<TNode>& table, const std::uint32_t keyLow, const std::uint32_t keyHigh
  ) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, keyLow, keyHigh);
    auto* const bucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
    TNode* node = bucketSlots[bucketIndex];
    TNode* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node == bucketEnd) {
      return table.mListHead;
    }

    const auto lexicographicLessEqual = [](const std::uint32_t lhsLow, const std::uint32_t lhsHigh,
                                            const std::uint32_t rhsLow, const std::uint32_t rhsHigh) {
      return lhsLow < rhsLow || (lhsLow == rhsLow && lhsHigh <= rhsHigh);
    };

    while (!lexicographicLessEqual(keyLow, keyHigh, node->mKeyLow, node->mKeyHigh)) {
      node = node->mNext;
      if (node == bucketEnd) {
        return table.mListHead;
      }
    }
    return lexicographicLessEqual(node->mKeyLow, node->mKeyHigh, keyLow, keyHigh) ? node : table.mListHead;
  }

  /**
   * Address: 0x0082C240 (FUN_0082C240, sub_82C240)
   *
   * The hash bucket vector stores one boundary pointer per bucket index
   * plus one trailing sentinel-adjacent boundary (N+1 slots for N buckets):
   * bucket[i]'s range is `[mBuckets.mStart[i], mBuckets.mStart[i+1])`, so
   * adjacent buckets share a slot (bucket i's end is bucket i+1's begin).
   * Confirmed directly from this function's own disassembly
   * (`lea ecx,[ecx+eax*4]` - single dword stride per bucket index, not
   * doubled).
   */
  UICommandGraph::HashListNode88* UICommandGraph::FindHashListNode88(
    HashTable<HashListNode88>& table, const std::uint32_t key
  ) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* node = bucketSlots[bucketIndex];
    HashListNode88* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node == bucketEnd) {
      return table.mListHead;
    }
    while (node->mKey < key) {
      node = node->mNext;
      if (node == bucketEnd) {
        return table.mListHead;
      }
    }
    return (key >= node->mKey) ? node : table.mListHead;
  }

  /**
   * Address: 0x0082C2E0 (FUN_0082C2E0, sub_82C2E0)
   */
  std::pair<UICommandGraph::HashListNode88*, UICommandGraph::HashListNode88*> UICommandGraph::EqualRangeHashListNode88(
    HashTable<HashListNode88>& table, const std::uint32_t key
  ) noexcept
  {
    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, key);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* node = bucketSlots[bucketIndex];
    HashListNode88* const bucketEnd = bucketSlots[bucketIndex + 1u];

    if (node != bucketEnd) {
      while (node->mKey < key) {
        node = node->mNext;
        if (node == bucketEnd) {
          break;
        }
      }
    }

    if (node == bucketEnd) {
      return {table.mListHead, table.mListHead};
    }

    HashListNode88* const first = node;
    do {
      if (key < node->mKey) {
        break;
      }
      node = node->mNext;
    } while (node != bucketEnd);

    if (first == node) {
      return {table.mListHead, table.mListHead};
    }
    return {first, node};
  }

  /**
   * Address: 0x0082B450 (FUN_0082B450, sub_82B450)
   */
  std::uint32_t UICommandGraph::CountHashListNode88(HashTable<HashListNode88>& table, const std::uint32_t key) noexcept
  {
    const auto [first, last] = EqualRangeHashListNode88(table, key);
    std::uint32_t count = 0u;
    for (HashListNode88* node = first; node != last; node = node->mNext) {
      ++count;
    }
    return count;
  }

  /**
   * Address: 0x0082F050 (FUN_0082F050, sub_82F050)
   */
  std::uint32_t UICommandGraph::CheckedIncrementListSize(const std::uint32_t count, std::uint32_t& sizeField)
  {
    if ((0x1FFFFFFu - sizeField) < count) {
      EngineThrowContainerTooLong("list<T> too long");
    }
    sizeField += count;
    return sizeField;
  }

  /**
   * Address: 0x0082BFB0 (FUN_0082BFB0, sub_82BFB0)
   */
  UICommandGraph::HashListNode88* UICommandGraph::InsertOrFindHashListNode88(
    HashTable<HashListNode88>& table, HashListNode88Value& valueSource, bool& outInserted
  )
  {
    if (table.mBucketCount <= (table.mListSize >> 2u)) {
      // Load factor exceeded: grow the bucket boundary array (or just the
      // mask, when slack already covers it) and redistribute exactly one
      // old bucket's nodes between it and the newly-available bucket - the
      // binary's incremental (split-one-bucket-per-insert) rehash, not a
      // full rebuild.
      const auto bucketVectorLength = static_cast<std::uint32_t>(table.mBuckets.size());

      if ((bucketVectorLength - 1u) > table.mBucketCount) {
        if (table.mBucketMask < table.mBucketCount) {
          table.mBucketMask = 2u * table.mBucketMask + 1u;
        }
      } else {
        const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
        table.mBucketMask = newMask;
        table.mBuckets.resize(newMask + 2u, table.mListHead);
      }

      auto* const rehashBucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
      const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
      HashListNode88* node = rehashBucketSlots[splitBucketIndex];
      // The loop condition re-reads the split bucket's END slot on every pass:
      // 0x0082C0F1 is `while (*(int**)(4 * v11 + a1[5] + 4) != v12)`, a
      // do-while whose test is a fresh load of `bucketSlots[split + 1]`. Fresh
      // is the point -- the splice below rewrites those slots.
      //
      // Hoisting it into a `const` and running `for (;;)` instead left the
      // `rehashedIndex == splitBucketIndex` arm, which only advances `node`,
      // with no way out: once a run of keys all rehashed back into the split
      // bucket, `node` walked past the sentinel and around the circular list
      // forever. Queueing several buildings in one shift-drag is exactly that
      // burst, and it hung the main thread inside `CreateMeshes`.
      if (rehashBucketSlots[splitBucketIndex + 1u] != node) {
        do {
          // Raw masked hash WITHOUT the wraparound adjustment
          // HashKeyToBucketIndex applies elsewhere: the binary compares
          // this directly against splitBucketIndex, which by construction
          // is always already within [0, mask] on this path.
          const std::ldiv_t split = std::ldiv(static_cast<long>(node->mKey ^ 0xDEADBEEFu), 127773L);
          long scrambled = 16807L * split.rem - 2836L * split.quot;
          if (scrambled < 0) {
            scrambled += 0x7FFFFFFFL;
          }
          const std::uint32_t rehashedIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;

          if (rehashedIndex == splitBucketIndex) {
            node = node->mNext;
          } else {
            HashListNode88* const next = node->mNext;
            if (next != table.mListHead) {
              if (rehashBucketSlots[splitBucketIndex] == node) {
                std::uint32_t walkIndex = splitBucketIndex;
                for (;;) {
                  rehashBucketSlots[walkIndex] = next;
                  if (walkIndex == 0u) {
                    break;
                  }
                  --walkIndex;
                  if (rehashBucketSlots[walkIndex] != node) {
                    break;
                  }
                }
              }

              // Splice `node` out of its current position and onto the
              // tail of the table's global list, immediately before the
              // sentinel - exactly where the newly-available bucket's
              // range belongs.
              HashListNode88* const sentinel = table.mListHead;
              HashListNode88* const oldTail = sentinel->mPrev;
              node->mPrev->mNext = next;
              next->mPrev = node->mPrev;
              node->mNext = sentinel;
              node->mPrev = oldTail;
              oldTail->mNext = node;
              sentinel->mPrev = node;
            }

            // Cascade: any bucket boundary between the split point and the
            // new bucket that still holds the sentinel as its own begin
            // (hasn't been individually established yet) is retargeted to
            // this node's new tail position too.
            std::uint32_t cascadeIndex = table.mBucketCount;
            while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
              rehashBucketSlots[cascadeIndex] = node;
              --cascadeIndex;
            }

            if (next == table.mListHead) {
              break;
            }
            node = next;
          }
        } while (rehashBucketSlots[splitBucketIndex + 1u] != node);
      }

      ++table.mBucketCount;
    }

    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, valueSource.mKey);
    auto* const bucketSlots = reinterpret_cast<HashListNode88**>(table.mBuckets.data());
    HashListNode88* insertionPoint = bucketSlots[bucketIndex + 1u];

    if (bucketSlots[bucketIndex] != insertionPoint) {
      bool reachedBegin = false;
      for (;;) {
        insertionPoint = insertionPoint->mPrev;
        if (insertionPoint->mKey <= valueSource.mKey) {
          break;
        }
        if (bucketSlots[bucketIndex] == insertionPoint) {
          reachedBegin = true;
          break;
        }
      }

      if (!reachedBegin) {
        if (insertionPoint->mKey >= valueSource.mKey) {
          outInserted = false;
          return insertionPoint;
        }
        insertionPoint = insertionPoint->mNext;
      }
    }

    HashListNode88* const newNode = ConstructHashListNode88(insertionPoint, insertionPoint->mPrev, valueSource);
    CheckedIncrementListSize(1u, table.mListSize);

    HashListNode88* const oldPrev = newNode->mPrev;
    insertionPoint->mPrev = newNode;
    oldPrev->mNext = newNode;

    if (bucketSlots[bucketIndex] == insertionPoint) {
      std::uint32_t cascadeIndex = bucketIndex;
      for (;;) {
        bucketSlots[cascadeIndex] = newNode;
        if (cascadeIndex == 0u) {
          break;
        }
        --cascadeIndex;
        if (bucketSlots[cascadeIndex] != insertionPoint) {
          break;
        }
      }
    }

    outInserted = true;
    return newNode;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   * Shared scalar-key rehash/insert-point-walk shape
   * (`ObtainHashListNode10` = 0x0082B5E0). Direct generalisation of
   * `InsertOrFindHashListNode88`'s body above over `TNode`, with the two
   * genuinely per-node-type steps (allocate+link a fresh node, bump the
   * checked list-size counter) passed in as function pointers rather than
   * duplicated.
   */
  template <typename TNode, typename TValue>
  TNode* UICommandGraph::ObtainHashListNode(
    HashTable<TNode>& table, TValue& valueSource, bool& outInserted,
    TNode* (*const constructNode)(TNode*, TNode*, TValue&),
    std::uint32_t (*const incrementListSize)(std::uint32_t, std::uint32_t&)
  )
  {
    if (table.mBucketCount <= (table.mListSize >> 2u)) {
      const auto bucketVectorLength = static_cast<std::uint32_t>(table.mBuckets.size());

      if ((bucketVectorLength - 1u) > table.mBucketCount) {
        if (table.mBucketMask < table.mBucketCount) {
          table.mBucketMask = 2u * table.mBucketMask + 1u;
        }
      } else {
        const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
        table.mBucketMask = newMask;
        table.mBuckets.resize(newMask + 2u, table.mListHead);
      }

      auto* const rehashBucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
      const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
      TNode* node = rehashBucketSlots[splitBucketIndex];
      // The loop condition re-reads the split bucket's END slot on every pass:
      // 0x0082C0F1 is `while (*(int**)(4 * v11 + a1[5] + 4) != v12)`, a
      // do-while whose test is a fresh load of `bucketSlots[split + 1]`. Fresh
      // is the point -- the splice below rewrites those slots.
      //
      // Hoisting it into a `const` and running `for (;;)` instead left the
      // `rehashedIndex == splitBucketIndex` arm, which only advances `node`,
      // with no way out: once a run of keys all rehashed back into the split
      // bucket, `node` walked past the sentinel and around the circular list
      // forever. Queueing several buildings in one shift-drag is exactly that
      // burst, and it hung the main thread inside `CreateMeshes`.
      if (rehashBucketSlots[splitBucketIndex + 1u] != node) {
        do {
          const std::ldiv_t split = std::ldiv(static_cast<long>(node->mKey ^ 0xDEADBEEFu), 127773L);
          long scrambled = 16807L * split.rem - 2836L * split.quot;
          if (scrambled < 0) {
            scrambled += 0x7FFFFFFFL;
          }
          const std::uint32_t rehashedIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;

          if (rehashedIndex == splitBucketIndex) {
            node = node->mNext;
          } else {
            TNode* const next = node->mNext;
            if (next != table.mListHead) {
              if (rehashBucketSlots[splitBucketIndex] == node) {
                std::uint32_t walkIndex = splitBucketIndex;
                for (;;) {
                  rehashBucketSlots[walkIndex] = next;
                  if (walkIndex == 0u) {
                    break;
                  }
                  --walkIndex;
                  if (rehashBucketSlots[walkIndex] != node) {
                    break;
                  }
                }
              }

              TNode* const sentinel = table.mListHead;
              TNode* const oldTail = sentinel->mPrev;
              node->mPrev->mNext = next;
              next->mPrev = node->mPrev;
              node->mNext = sentinel;
              node->mPrev = oldTail;
              oldTail->mNext = node;
              sentinel->mPrev = node;
            }

            std::uint32_t cascadeIndex = table.mBucketCount;
            while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
              rehashBucketSlots[cascadeIndex] = node;
              --cascadeIndex;
            }

            if (next == table.mListHead) {
              break;
            }
            node = next;
          }
        } while (rehashBucketSlots[splitBucketIndex + 1u] != node);
      }

      ++table.mBucketCount;
    }

    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, valueSource.mKey);
    auto* const bucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
    TNode* insertionPoint = bucketSlots[bucketIndex + 1u];

    if (bucketSlots[bucketIndex] != insertionPoint) {
      bool reachedBegin = false;
      for (;;) {
        insertionPoint = insertionPoint->mPrev;
        if (insertionPoint->mKey <= valueSource.mKey) {
          break;
        }
        if (bucketSlots[bucketIndex] == insertionPoint) {
          reachedBegin = true;
          break;
        }
      }

      if (!reachedBegin) {
        if (insertionPoint->mKey >= valueSource.mKey) {
          outInserted = false;
          return insertionPoint;
        }
        insertionPoint = insertionPoint->mNext;
      }
    }

    TNode* const newNode = constructNode(insertionPoint, insertionPoint->mPrev, valueSource);
    incrementListSize(1u, table.mListSize);

    TNode* const oldPrev = newNode->mPrev;
    insertionPoint->mPrev = newNode;
    oldPrev->mNext = newNode;

    if (bucketSlots[bucketIndex] == insertionPoint) {
      std::uint32_t cascadeIndex = bucketIndex;
      for (;;) {
        bucketSlots[cascadeIndex] = newNode;
        if (cascadeIndex == 0u) {
          break;
        }
        --cascadeIndex;
        if (bucketSlots[cascadeIndex] != insertionPoint) {
          break;
        }
      }
    }

    outInserted = true;
    return newNode;
  }

  /**
   * Not a distinct binary function - see the declaration's doc comment.
   * Shared pair-key rehash/insert-point-walk shape
   * (`ObtainHashListNode2C` = 0x0082C480). Same structure as
   * `ObtainHashListNode` above; only the rehash split-index hash and the
   * insertion-point comparisons switch from scalar `<` to lexicographic
   * `(lo, hi)` ordering.
   */
  template <typename TNode, typename TValue>
  TNode* UICommandGraph::ObtainHashListNodePair(
    HashTable<TNode>& table, TValue& valueSource, bool& outInserted,
    TNode* (*const constructNode)(TNode*, TNode*, TValue&),
    std::uint32_t (*const incrementListSize)(std::uint32_t, std::uint32_t&)
  )
  {
    const auto lexicographicLessEqual = [](const std::uint32_t lhsLow, const std::uint32_t lhsHigh,
                                            const std::uint32_t rhsLow, const std::uint32_t rhsHigh) {
      return lhsLow < rhsLow || (lhsLow == rhsLow && lhsHigh <= rhsHigh);
    };

    if (table.mBucketCount <= (table.mListSize >> 2u)) {
      const auto bucketVectorLength = static_cast<std::uint32_t>(table.mBuckets.size());

      if ((bucketVectorLength - 1u) > table.mBucketCount) {
        if (table.mBucketMask < table.mBucketCount) {
          table.mBucketMask = 2u * table.mBucketMask + 1u;
        }
      } else {
        const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
        table.mBucketMask = newMask;
        table.mBuckets.resize(newMask + 2u, table.mListHead);
      }

      auto* const rehashBucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
      const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
      TNode* node = rehashBucketSlots[splitBucketIndex];
      // The loop condition re-reads the split bucket's END slot on every pass:
      // 0x0082C0F1 is `while (*(int**)(4 * v11 + a1[5] + 4) != v12)`, a
      // do-while whose test is a fresh load of `bucketSlots[split + 1]`. Fresh
      // is the point -- the splice below rewrites those slots.
      //
      // Hoisting it into a `const` and running `for (;;)` instead left the
      // `rehashedIndex == splitBucketIndex` arm, which only advances `node`,
      // with no way out: once a run of keys all rehashed back into the split
      // bucket, `node` walked past the sentinel and around the circular list
      // forever. Queueing several buildings in one shift-drag is exactly that
      // burst, and it hung the main thread inside `CreateMeshes`.
      if (rehashBucketSlots[splitBucketIndex + 1u] != node) {
        do {
          const std::ldiv_t split = std::ldiv(
            static_cast<long>(3863u * node->mKeyLow + 7919u * node->mKeyHigh + 53849u * (node->mKeyLow ^ node->mKeyHigh)),
            127773L
          );
          long scrambled = 16807L * split.rem - 2836L * split.quot;
          if (scrambled < 0) {
            scrambled += 0x7FFFFFFFL;
          }
          const std::uint32_t rehashedIndex = static_cast<std::uint32_t>(scrambled) & table.mBucketMask;

          if (rehashedIndex == splitBucketIndex) {
            node = node->mNext;
          } else {
            TNode* const next = node->mNext;
            if (next != table.mListHead) {
              if (rehashBucketSlots[splitBucketIndex] == node) {
                std::uint32_t walkIndex = splitBucketIndex;
                for (;;) {
                  rehashBucketSlots[walkIndex] = next;
                  if (walkIndex == 0u) {
                    break;
                  }
                  --walkIndex;
                  if (rehashBucketSlots[walkIndex] != node) {
                    break;
                  }
                }
              }

              TNode* const sentinel = table.mListHead;
              TNode* const oldTail = sentinel->mPrev;
              node->mPrev->mNext = next;
              next->mPrev = node->mPrev;
              node->mNext = sentinel;
              node->mPrev = oldTail;
              oldTail->mNext = node;
              sentinel->mPrev = node;
            }

            std::uint32_t cascadeIndex = table.mBucketCount;
            while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
              rehashBucketSlots[cascadeIndex] = node;
              --cascadeIndex;
            }

            if (next == table.mListHead) {
              break;
            }
            node = next;
          }
        } while (rehashBucketSlots[splitBucketIndex + 1u] != node);
      }

      ++table.mBucketCount;
    }

    const std::uint32_t bucketIndex = HashKeyToBucketIndex(table, valueSource.mKeyLow, valueSource.mKeyHigh);
    auto* const bucketSlots = reinterpret_cast<TNode**>(table.mBuckets.data());
    TNode* insertionPoint = bucketSlots[bucketIndex + 1u];

    if (bucketSlots[bucketIndex] != insertionPoint) {
      bool reachedBegin = false;
      for (;;) {
        insertionPoint = insertionPoint->mPrev;
        if (lexicographicLessEqual(insertionPoint->mKeyLow, insertionPoint->mKeyHigh, valueSource.mKeyLow, valueSource.mKeyHigh)) {
          break;
        }
        if (bucketSlots[bucketIndex] == insertionPoint) {
          reachedBegin = true;
          break;
        }
      }

      if (!reachedBegin) {
        if (lexicographicLessEqual(valueSource.mKeyLow, valueSource.mKeyHigh, insertionPoint->mKeyLow, insertionPoint->mKeyHigh)) {
          outInserted = false;
          return insertionPoint;
        }
        insertionPoint = insertionPoint->mNext;
      }
    }

    TNode* const newNode = constructNode(insertionPoint, insertionPoint->mPrev, valueSource);
    incrementListSize(1u, table.mListSize);

    TNode* const oldPrev = newNode->mPrev;
    insertionPoint->mPrev = newNode;
    oldPrev->mNext = newNode;

    if (bucketSlots[bucketIndex] == insertionPoint) {
      std::uint32_t cascadeIndex = bucketIndex;
      for (;;) {
        bucketSlots[cascadeIndex] = newNode;
        if (cascadeIndex == 0u) {
          break;
        }
        --cascadeIndex;
        if (bucketSlots[cascadeIndex] != insertionPoint) {
          break;
        }
      }
    }

    outInserted = true;
    return newNode;
  }

  /**
   * Addresses: 0x00831BA0 (FUN_00831BA0) and 0x00831C90 (FUN_00831C90) -
   * see the declaration's doc comment.
   */
  template <typename TNode>
  void* UICommandGraph::NewHashListNodeStorage(const std::size_t count)
  {
    if ((0xFFFFFFFFu / static_cast<std::uint32_t>(count)) < sizeof(TNode)) {
      throw std::bad_alloc();
    }
    return ::operator new(sizeof(TNode) * count);
  }

  /**
   * Address: 0x00830700 (FUN_00830700, sub_830700)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::MakeHashListNode2C(
    HashListNode2C* const next, HashListNode2C* const prev, HashListNode2CValue& valueSource
  )
  {
    auto* const node = static_cast<HashListNode2C*>(NewHashListNodeStorage<HashListNode2C>(1));
    node->mNext = next;
    node->mPrev = prev;
    node->mKeyLow = valueSource.mKeyLow;
    node->mKeyHigh = valueSource.mKeyHigh;
    node->mEdge = valueSource.mEdge;
    return node;
  }

  /**
   * Address: 0x0082FB10 (FUN_0082FB10, sub_82FB10)
   */
  UICommandGraph::HashListNode10* UICommandGraph::MakeHashListNode10(
    HashListNode10* const next, HashListNode10* const prev, HashListNode10Value& valueSource
  )
  {
    auto* const node = static_cast<HashListNode10*>(NewHashListNodeStorage<HashListNode10>(1));
    node->mNext = next;
    node->mPrev = prev;
    node->mKey = valueSource.mKey;
    node->mWidth = valueSource.mWidth;
    return node;
  }

  /**
   * Address: 0x0082F5D0 (FUN_0082F5D0, sub_82F5D0)
   */
  std::uint32_t UICommandGraph::CheckedIncrementListSize2C(const std::uint32_t count, std::uint32_t& sizeField)
  {
    if ((119304647u - sizeField) < count) {
      EngineThrowContainerTooLong("list<T> too long");
    }
    sizeField += count;
    return sizeField;
  }

  /**
   * Address: 0x0082DD60 (FUN_0082DD60, sub_82DD60)
   */
  std::uint32_t UICommandGraph::CheckedIncrementListSize10(const std::uint32_t count, std::uint32_t& sizeField)
  {
    if ((0x1FFFFFFFu - sizeField) < count) {
      EngineThrowContainerTooLong("list<T> too long");
    }
    sizeField += count;
    return sizeField;
  }

  /**
   * Address: 0x0082C750 (FUN_0082C750, sub_82C750)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::FindHashListNode2C(
    HashTable<HashListNode2C>& table, const std::uint32_t keyLow, const std::uint32_t keyHigh
  ) noexcept
  {
    return FindHashListNode(table, keyLow, keyHigh);
  }

  /**
   * Address: 0x0082C480 (FUN_0082C480, sub_82C480)
   */
  UICommandGraph::HashListNode2C* UICommandGraph::ObtainHashListNode2C(
    HashTable<HashListNode2C>& table, HashListNode2CValue& valueSource, bool& outInserted
  )
  {
    return ObtainHashListNodePair(table, valueSource, outInserted, &MakeHashListNode2C, &CheckedIncrementListSize2C);
  }

  /**
   * Address: 0x0082C950 (FUN_0082C950, sub_82C950)
   */
  UICommandGraph::HashListNode10* UICommandGraph::FindHashListNode10(
    HashTable<HashListNode10>& table, const std::uint32_t key
  ) noexcept
  {
    return FindHashListNode(table, key);
  }

  /**
   * Address: 0x0082B5E0 (FUN_0082B5E0, sub_82B5E0)
   */
  UICommandGraph::HashListNode10* UICommandGraph::ObtainHashListNode10(
    HashTable<HashListNode10>& table, HashListNode10Value& valueSource, bool& outInserted
  )
  {
    return ObtainHashListNode(table, valueSource, outInserted, &MakeHashListNode10, &CheckedIncrementListSize10);
  }

  /**
   * Address: 0x0082B490 (FUN_0082B490, sub_82B490)
   */
  UICommandGraph::CommandGraphEdge* UICommandGraph::FindOrInsertCommandGraphEdge(
    UICommandGraphDrawNode* const fromNode, UICommandGraphDrawNode* const toNode, HashTable<HashListNode2C>& table
  )
  {
    const auto fromKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(fromNode));
    const auto toKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(toNode));

    HashListNode2C* found = FindHashListNode2C(table, fromKey, toKey);
    if (found != table.mListHead) {
      return &found->mEdge;
    }

    // Miss: the binary zero-initializes the value composite before the
    // insert (sub_82B490's memset), matching `CommandGraphEdge`'s in-class
    // default member initializers - a fresh edge has no source line of its
    // own, so a value-initialized temporary is the natural expression.
    HashListNode2CValue insertValue{};
    insertValue.mKeyLow = fromKey;
    insertValue.mKeyHigh = toKey;

    bool inserted = false;
    HashListNode2C* const resultNode = ObtainHashListNode2C(table, insertValue, inserted);
    return &resultNode->mEdge;
  }

  /**
   * Address: 0x0082B300 (FUN_0082B300, sub_82B300)
   */
  UICommandGraph::UICommandGraphDrawNode* UICommandGraph::FindOrInsertCommandGraphDrawNode(
    const std::uint32_t key, HashTable<HashListNode88>& table
  )
  {
    HashListNode88* const found = FindHashListNode88(table, key);
    if (found != table.mListHead) {
      return &found->mDraw;
    }

    // Miss: build a default draw node (its constructor, 0x00824600),
    // relocate-copy it into a second temporary, and insert a real node built
    // from `{key, temporary}`. The temporaries die as locals on the way out;
    // the explicit destructor calls this used to make ran `tempRelocated`'s
    // destructor twice, and the default node used to be a padded 0x78-byte
    // view reinterpreted as this type.
    UICommandGraphDrawNode tempDefault;
    UICommandGraphDrawNode tempRelocated;
    RelocateDrawNode(&tempRelocated, tempDefault);

    HashListNode88Value insertValue{};
    insertValue.mKey = key;
    RelocateDrawNode(&insertValue.mDraw, tempRelocated);

    bool inserted = false;
    HashListNode88* const resultNode = InsertOrFindHashListNode88(table, insertValue, inserted);
    return &resultNode->mDraw;
  }

  /**
   * Address: 0x008300D0 (FUN_008300D0)
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AllocateTreeSentinelNode()
  {
    auto* const node = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    std::memset(node, 0, sizeof(CommandGraphTreeNode));
    node->mColorOrAllocated = 1u;
    node->mIsSentinel = 0u;
    return node;
  }

  void UICommandGraph::InitTree(CommandGraphTree& tree)
  {
    tree.mAllocProxy = nullptr;
    tree.mHead = AllocateTreeSentinelNode();
    tree.mHead->mIsSentinel = 1u;
    tree.mHead->mLeft = tree.mHead;
    tree.mHead->mParent = tree.mHead;
    tree.mHead->mRight = tree.mHead;
    tree.mSize = 0u;
  }

  /**
   * Address: 0x0082BEE0 (FUN_0082BEE0, sub_82BEE0)
   */
  void UICommandGraph::ReleaseCommandGraphTreeBucket(CommandGraphTreeBucket& bucket) noexcept
  {
    if (bucket.mEdges.data() != nullptr) {
      ::operator delete(bucket.mEdges.data());
    }
    bucket.mEdges.release_storage_without_free();
    bucket.mTexture.release();
  }

  /**
   * Address: 0x0082CDE0 (FUN_0082CDE0, sub_82CDE0, `DestroyTree`'s copy of this walk)
   */
  void UICommandGraph::DestroyCommandGraphTreeSubtree(CommandGraphTreeNode* const sentinelHead, CommandGraphTreeNode* node)
  {
    if (node == nullptr || node == sentinelHead || node->mIsSentinel != 0u) {
      return;
    }

    DestroyCommandGraphTreeSubtree(sentinelHead, node->mRight);
    CommandGraphTreeNode* const left = node->mLeft;
    ReleaseCommandGraphTreeBucket(node->mBucket);
    ::operator delete(node);
    DestroyCommandGraphTreeSubtree(sentinelHead, left);
  }

  /**
   * Address: 0x00824B50 (FUN_00824B50, sub_824B50)
   *
   * What it does:
   * Destroys command-graph runtime tree nodes rooted at `mHead->mParent`,
   * releasing each node's bucket resources first, then releases the head
   * sentinel and clears head/size lanes.
   */
  void UICommandGraph::DestroyTree(CommandGraphTree& tree)
  {
    if (tree.mHead) {
      DestroyCommandGraphTreeSubtree(tree.mHead, tree.mHead->mParent);
      ::operator delete(tree.mHead);
    }

    tree.mHead = nullptr;
    tree.mSize = 0u;
    tree.mAllocProxy = nullptr;
  }

  // Forward declarations: reopens the same file-scope anonymous namespace
  // that defines these two sentinel-headed RB-tree walkers further below,
  // so `AttachCommandGraphNodeUnique`/`AttachCommandGraphNodeHinted`
  // below - the first command-graph callers that need them - can call them
  // here, ahead of their point of definition (mirrors the later reopening
  // for `DrawCommandGraphMesh`'s own needs).
  namespace
  {
    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node);
  }

  /**
   * Address: 0x0082D330 (FUN_0082D330, sub_82D330) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeBucket* UICommandGraph::InitCommandGraphTreeBucketValue(
    CommandGraphTreeBucket* const destination, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    ::new (static_cast<void*>(destination)) CommandGraphTreeBucket();
    destination->mTexture = texture.clone_retained();
    return destination;
  }

  /**
   * Address: 0x00830010 (FUN_00830010) - see the declaration's doc comment.
   */
  void UICommandGraph::PivotCommandGraphTreeLeft(CommandGraphTree& tree, CommandGraphTreeNode* const n) noexcept
  {
    CommandGraphTreeNode* const pivot = n->mRight;
    n->mRight = pivot->mLeft;
    if (pivot->mLeft->mIsSentinel == 0u) {
      pivot->mLeft->mParent = n;
    }
    pivot->mParent = n->mParent;

    if (n == tree.mHead->mParent) {
      tree.mHead->mParent = pivot;
    } else if (n == n->mParent->mLeft) {
      n->mParent->mLeft = pivot;
    } else {
      n->mParent->mRight = pivot;
    }

    pivot->mLeft = n;
    n->mParent = pivot;
  }

  /**
   * Address: 0x00830080 (FUN_00830080) - see the declaration's doc comment.
   */
  void UICommandGraph::PivotCommandGraphTreeRight(CommandGraphTree& tree, CommandGraphTreeNode* const n) noexcept
  {
    CommandGraphTreeNode* const pivot = n->mLeft;
    n->mLeft = pivot->mRight;
    if (pivot->mRight->mIsSentinel == 0u) {
      pivot->mRight->mParent = n;
    }
    pivot->mParent = n->mParent;

    if (n == tree.mHead->mParent) {
      tree.mHead->mParent = pivot;
    } else if (n == n->mParent->mRight) {
      n->mParent->mRight = pivot;
    } else {
      n->mParent->mLeft = pivot;
    }

    pivot->mRight = n;
    n->mParent = pivot;
  }

  /**
   * Address: 0x0082E320 (FUN_0082E320, sub_82E320) - see the declaration's
   * doc comment. `0xAAAAAA9u` is this map's own `max_size() - 1u` bound for
   * its 0x18-byte `pair<shared_ptr<ID3DTextureSheet>, vector<CommandGraphEdge*>>`
   * value_type (`0xFFFFFFFF / 0x18 - 1 == 0xAAAAAA9`), already confirmed
   * against this exact instantiation in `legacy/containers/RbTree.h`'s
   * `insert_at` citation.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeAt(
    CommandGraphTree& tree, const bool addLeft, CommandGraphTreeNode* const where,
    const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    if (0xAAAAAA9u <= tree.mSize) {
      EngineThrowContainerTooLong("map/set<T> too long");
    }

    auto* const fresh = static_cast<CommandGraphTreeNode*>(::operator new(sizeof(CommandGraphTreeNode)));
    fresh->mLeft = tree.mHead;
    fresh->mParent = tree.mHead;
    fresh->mRight = tree.mHead;
    fresh->mColorOrAllocated = 0u; // kRbRed
    fresh->mIsSentinel = 0u;
    try {
      InitCommandGraphTreeBucketValue(&fresh->mBucket, texture);
    } catch (...) {
      ::operator delete(fresh);
      throw;
    }

    ++tree.mSize;
    if (where == tree.mHead) {
      tree.mHead->mParent = fresh;
      tree.mHead->mLeft = fresh;
      tree.mHead->mRight = fresh;
    } else if (addLeft) {
      where->mLeft = fresh;
      if (where == tree.mHead->mLeft) {
        tree.mHead->mLeft = fresh;
      }
    } else {
      where->mRight = fresh;
      if (where == tree.mHead->mRight) {
        tree.mHead->mRight = fresh;
      }
    }
    fresh->mParent = where;

    for (CommandGraphTreeNode* n = fresh; n->mParent->mColorOrAllocated == 0u;) {
      CommandGraphTreeNode* const parent = n->mParent;
      CommandGraphTreeNode* const grand = parent->mParent;

      if (parent == grand->mLeft) {
        CommandGraphTreeNode* const uncle = grand->mRight;
        if (uncle->mColorOrAllocated == 0u) {
          parent->mColorOrAllocated = 1u;
          uncle->mColorOrAllocated = 1u;
          grand->mColorOrAllocated = 0u;
          n = grand;
        } else {
          if (n == parent->mRight) {
            n = parent;
            PivotCommandGraphTreeLeft(tree, n);
          }
          n->mParent->mColorOrAllocated = 1u;
          n->mParent->mParent->mColorOrAllocated = 0u;
          PivotCommandGraphTreeRight(tree, n->mParent->mParent);
        }
      } else {
        CommandGraphTreeNode* const uncle = grand->mLeft;
        if (uncle->mColorOrAllocated == 0u) {
          parent->mColorOrAllocated = 1u;
          uncle->mColorOrAllocated = 1u;
          grand->mColorOrAllocated = 0u;
          n = grand;
        } else {
          if (n == parent->mLeft) {
            n = parent;
            PivotCommandGraphTreeRight(tree, n);
          }
          n->mParent->mColorOrAllocated = 1u;
          n->mParent->mParent->mColorOrAllocated = 0u;
          PivotCommandGraphTreeLeft(tree, n->mParent->mParent);
        }
      }
    }

    tree.mHead->mParent->mColorOrAllocated = 1u; // root()->color = black
    return fresh;
  }

  /**
   * Address: 0x0082E170 (FUN_0082E170, sub_82E170) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeUnique(
    CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    CommandGraphTreeNode* where = tree.mHead;
    bool addLeft = true;
    for (CommandGraphTreeNode* node = tree.mHead->mParent; node->mIsSentinel == 0u;) {
      where = node;
      addLeft = texture.pi < node->mBucket.mTexture.pi;
      node = addLeft ? node->mLeft : node->mRight;
    }

    CommandGraphTreeNode* probe = where;
    if (addLeft) {
      if (where == tree.mHead->mLeft) {
        return AttachCommandGraphNodeAt(tree, true, where, texture);
      }
      probe = PrevTreeNode(where);
    }

    if (probe->mBucket.mTexture.pi < texture.pi) {
      return AttachCommandGraphNodeAt(tree, addLeft, where, texture);
    }
    return probe;
  }

  /**
   * Address: 0x0082CC80 (FUN_0082CC80, sub_82CC80) - see the declaration's
   * doc comment.
   */
  UICommandGraph::CommandGraphTreeNode* UICommandGraph::AttachCommandGraphNodeHinted(
    CommandGraphTree& tree, CommandGraphTreeNode* const hint, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    if (tree.mSize == 0u) {
      return AttachCommandGraphNodeAt(tree, true, tree.mHead, texture);
    }

    if (hint == tree.mHead->mLeft) {
      if (texture.pi < hint->mBucket.mTexture.pi) {
        return AttachCommandGraphNodeAt(tree, true, hint, texture);
      }
    } else if (hint->mIsSentinel != 0u) {
      CommandGraphTreeNode* const rightmost = tree.mHead->mRight;
      if (rightmost->mBucket.mTexture.pi < texture.pi) {
        return AttachCommandGraphNodeAt(tree, false, rightmost, texture);
      }
    } else if (texture.pi < hint->mBucket.mTexture.pi) {
      CommandGraphTreeNode* const before = PrevTreeNode(hint);
      if (before->mBucket.mTexture.pi < texture.pi) {
        return (before->mRight->mIsSentinel != 0u) ? AttachCommandGraphNodeAt(tree, false, before, texture)
                                                     : AttachCommandGraphNodeAt(tree, true, hint, texture);
      }
    } else if (hint->mBucket.mTexture.pi < texture.pi) {
      CommandGraphTreeNode* const after = NextTreeNode(hint);
      if (after->mIsSentinel != 0u || texture.pi < after->mBucket.mTexture.pi) {
        return (hint->mRight->mIsSentinel != 0u) ? AttachCommandGraphNodeAt(tree, false, hint, texture)
                                                  : AttachCommandGraphNodeAt(tree, true, after, texture);
      }
    }

    return AttachCommandGraphNodeUnique(tree, texture);
  }

  /**
   * Address: 0x0082B8B0 (FUN_0082B8B0, sub_82B8B0) - see the declaration's
   * doc comment.
   */
  msvc8::vector<UICommandGraph::CommandGraphEdge*>& UICommandGraph::FindOrInsertCommandGraphBucket(
    CommandGraphTree& tree, const boost::SharedPtrRaw<ID3DTextureSheet>& texture
  )
  {
    CommandGraphTreeNode* candidate = tree.mHead;
    for (CommandGraphTreeNode* node = tree.mHead->mParent; node->mIsSentinel == 0u;) {
      if (texture.pi <= node->mBucket.mTexture.pi) {
        candidate = node;
        node = node->mLeft;
      } else {
        node = node->mRight;
      }
    }

    if (candidate != tree.mHead && !(texture.pi < candidate->mBucket.mTexture.pi)) {
      return candidate->mBucket.mEdges;
    }

    CommandGraphTreeNode* const inserted = AttachCommandGraphNodeHinted(tree, candidate, texture);
    return inserted->mBucket.mEdges;
  }

  /**
   * Address: 0x00824740 (FUN_00824740, func_OnCommandGraphShow)
   */
  void UICommandGraph::OnCommandGraphShow(LuaPlus::LuaState* const state, const bool visible)
  {
    try {
      const LuaPlus::LuaObject commandGraph = SCR_Import(state, "/lua/ui/game/commandgraph.lua");
      const LuaPlus::LuaFunction<> onShow{commandGraph["OnCommandGraphShow"]};
      onShow.Call_Bool(visible);
    } catch (const std::exception& error) {
      gpg::Warnf("Error running '/lua/ui/game/commandgraph.lua:OnCommandGraphShow': %s", error.what());
    }
  }

  /**
   * Address: 0x00824D50 (FUN_00824D50, Moho::UICommandGraph::LoadPathParams)
   *
   * IDA signature:
   * void __stdcall Moho::UICommandGraph::LoadPathParams(Moho::UICommandGraph *a1);
   *
   * What it does:
   * Imports `/lua/ui/game/commandgraphparams.lua` on the UI Lua state, builds
   * one node from its `default` entry, then gives every command type its own
   * node: the default is copied in first, and the per-type entry (keyed
   * `<enum prefix><lexical name>`, e.g. `UNITCOMMAND_Attack`) is layered over
   * it. A command type with no entry in the table keeps the default.
   */
  void UICommandGraph::LoadPathParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandgraphparams.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandGraphParams"];
    if (!params.IsTable()) {
      return;
    }

    // 0x00824DE9 open-codes the node constructor here rather than calling it.
    UICommandGraphNode defaults{};
    defaults.LoadTextures(params, "default", state);

    for (std::int32_t index = 0; index < static_cast<std::int32_t>(std::size(mNodes)); ++index) {
      (void)mNodes[index].CopyFrom(defaults);

      auto commandType = static_cast<EUnitCommandType>(index);
      gpg::RRef commandTypeRef{};
      commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&commandType);

      // The reflected type is always the EUnitCommandType enum descriptor, so
      // the binary reads `mPrefix` straight off it at 0x00824F3E rather than
      // going through the IsEnumType() virtual.
      const auto* const enumType = static_cast<const gpg::REnumType*>(commandTypeRef.mType);
      const msvc8::string lexicalName = commandTypeRef.GetLexical();
      const msvc8::string key = gpg::STR_Printf("%s%s", enumType->mPrefix, lexicalName.c_str());

      mNodes[index].LoadTextures(params, key.c_str(), state);
    }
  }

  /**
   * Address: 0x00825150 (FUN_00825150, func_LoadCommandGraphWaypointParams)
   *
   * IDA signature:
   * LuaPlus::LuaObject *sub_825150();
   *
   * What it does:
   * Imports `/lua/ui/game/commandwaypoint.lua` on the UI Lua state and copies
   * its `CommandWaypointParams` table into the seven command-waypoint globals.
   * Each key is optional: a missing or nil entry leaves the global at whatever
   * the previous import (or image load) left there.
   */
  void UICommandGraph::LoadWaypointParams()
  {
    LuaPlus::LuaState* const state = g_UIManager != nullptr ? g_UIManager->mLuaState : nullptr;
    const LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/commandwaypoint.lua");
    if (module.IsNil()) {
      return;
    }

    const LuaPlus::LuaObject params = module["CommandWaypointParams"];
    if (!params.IsTable()) {
      return;
    }

    // The binary re-reads each key after the nil test rather than reusing the
    // probe object, and tests every key even once one is missing.
    if (!params["ui_CurveSegments"].IsNil()) {
      ui_CurveSegments = static_cast<std::int32_t>(params["ui_CurveSegments"].GetNumber());
    }
    if (!params["ui_CurveSmoothness"].IsNil()) {
      ui_CurveSmoothness = static_cast<float>(params["ui_CurveSmoothness"].GetNumber());
    }
    if (!params["ui_PathSmoothness"].IsNil()) {
      ui_PathSmoothness = static_cast<float>(params["ui_PathSmoothness"].GetNumber());
    }
    if (!params["ui_CommandGraphMaxNodeUnits"].IsNil()) {
      ui_CommandGraphMaxNodeUnits =
        static_cast<std::int32_t>(params["ui_CommandGraphMaxNodeUnits"].GetNumber());
    }
    if (!params["ui_MinWaypointSize"].IsNil()) {
      ui_MinWaypointSize = static_cast<float>(params["ui_MinWaypointSize"].GetNumber());
    }
    if (!params["ui_MaxWaypointSize"].IsNil()) {
      ui_MaxWaypointSize = static_cast<float>(params["ui_MaxWaypointSize"].GetNumber());
    }
    if (!params["ui_WaypointLineScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_WaypointLineScale"].GetNumber());
    }

    // Not a transcription slip: 0x00825524 stores the `ui_CommandClickScale`
    // value into `ui_WaypointLineScale` (0x00F57CDC), the same global the
    // block above writes. There is no `ui_CommandClickScale` symbol in the
    // image at all, so whichever of the two keys the Lua table defines last
    // wins the line scale. Preserved because the original does it.
    if (!params["ui_CommandClickScale"].IsNil()) {
      ui_WaypointLineScale = static_cast<float>(params["ui_CommandClickScale"].GetNumber());
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::CreateBuildPreviewMesh(UICommandGraphDrawNode& drawNode, UICommandGraph& graph)
  {
    // 0x008274D7 hands CreateMeshInstance an opaque green, then 0x008274FB
    // immediately overwrites the instance's own colour lane with the
    // alpha-0xD8 shade the placement ghost actually draws in.
    constexpr std::int32_t kPreviewCreateColor = static_cast<std::int32_t>(0xFF00FF00u);
    constexpr std::int32_t kPreviewTranslucentGreen = static_cast<std::int32_t>(0xD800D800u);

    // Already has its ghost - the mesh outlives the rebuild that made it.
    if (drawNode.mMeshInstance.px != nullptr) {
      return;
    }

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    // Only a queued mobile build produces a unit to preview; every other order
    // type draws with waypoint markers and orderlines alone.
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile) {
      return;
    }

    const REntityBlueprint* const entityBlueprint = helper->mConstantData.blueprint;
    if (entityBlueprint == nullptr) {
      return;
    }

    const RUnitBlueprint* const unitBlueprint = entityBlueprint->IsUnitBlueprint();
    if (unitBlueprint == nullptr) {
      return;
    }

    RMeshBlueprint* const meshBlueprint =
      graph.mSession->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
    if (meshBlueprint == nullptr) {
      return;
    }

    const float uniformScale = unitBlueprint->Display.UniformScale;
    const Wm3::Vec3f previewScale{uniformScale, uniformScale, uniformScale};

    // 0x008273F1 loads `mLods.first_` once and addresses the LOD's texture
    // names off it (+0x1C/+0x38/+0x54) with no empty-vector guard - a mesh
    // blueprint that resolved this far always carries at least one LOD.
    const RMeshBlueprintLOD* const lod = meshBlueprint->mLods.begin();

    // The ghost keeps the LOD's real albedo/normals/specular maps but swaps the
    // shader for "UnitPlace"; the lookup and secondary slots stay empty. This
    // is why the six-string Create overload is called directly instead of the
    // `Create(const RMeshBlueprintLOD&, ...)` one, which would carry
    // `lod->mShaderName` through.
    const msvc8::string shaderName("UnitPlace");
    const msvc8::string emptyLookupName;
    const msvc8::string emptySecondaryName;
    const boost::shared_ptr<MeshMaterial> material = MeshMaterial::Create(
      shaderName,
      lod->mAlbedoName,
      lod->mNormalsName,
      lod->mSpecularName,
      emptyLookupName,
      emptySecondaryName,
      nullptr
    );

    MeshInstance* const meshInstance = MeshRenderer::GetInstance()->CreateMeshInstance(
      graph.mSession->mGameTick, kPreviewCreateColor, meshBlueprint, previewScale, false, material
    );

    boost::ResetSharedPtrRawOwning(drawNode.mMeshInstance, meshInstance);
    drawNode.mMeshInstance.px->color = kPreviewTranslucentGreen;

    // The binary builds the stance at the origin (0x00827514..0x00827532) and
    // only afterwards divides the node's accumulated position by its weight,
    // storing the centroid straight into the transform's translation lane - so
    // the zero vector here is the constructor argument the original passed, not
    // a placeholder.
    VTransform stance{Wm3::Vec3f{0.0f, 0.0f, 0.0f}, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
    const float invWeight = 1.0f / drawNode.mWeight;
    stance.pos_ = Wm3::Vec3f{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    // Same transform as both start and end: the placement ghost snaps to the
    // order's position rather than interpolating toward it.
    drawNode.mMeshInstance.px->SetStance(stance, stance);
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::CreateMeshes()
  {
    bool rebuilt = false;
    if (mNeedsRebuild != 0u) {
      mNeedsRebuild = 0u;
      RebuildCommandQueueNodes();
      RecomputeAllDrawNodeOrientations();
      rebuilt = true;
    }

    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      UICommandGraphDrawNode& drawNode = node->mDraw;

      // Commands retire and are re-issued between frames while their draw node
      // survives, so a node that is currently chained to *some* helper is
      // re-pointed at whichever helper owns its command id right now. A node
      // with no chain membership at all is left alone - it never had an owner
      // and the rebuild pass is what gives it one.
      if (drawNode.mHelperLink.HasValue()) {
        drawNode.mHelperLink.ResetFromObject(FindCommandIssueHelperInSession(mSession, drawNode.mCommandId));
      }

      // First time this node resolves to a live command, seed its anchor from
      // the command's own history. `mWeight` becomes 1 because this table keys
      // one node per command - the centroid is that single position, unlike the
      // queue-head table where the weight counts the units sharing the queue.
      if (drawNode.mHelperLink.HasValue() && drawNode.mHasResolvedPosition == 0u) {
        drawNode.mPositionSum = ResolveCommandGraphAnchorWorldPosition(*drawNode.mHelperLink.GetObjectPtr());
        drawNode.mWeight = 1.0f;
      }
    }

    if (rebuilt) {
      for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
        ResolveDrawNodeCompletionTick(node->mDraw);
      }

      for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
        CreateBuildPreviewMesh(node->mDraw, *this);
      }
    }

    // The binary inlines `MAUI_KeyIsDown` (0x0079CB70) here in full - the
    // foreground test, the focus-owner guard and the `wxCharCodeWXToMSW` +
    // `GetKeyState` sign test at 0x0082911C..0x0082915D are that function's
    // three steps, in its order.
    if (ui_PathPreview) {
      CON_Executef("path_GeneratePreview %s", MAUI_KeyIsDown(MKEY_SHIFT) ? "end" : "start");
    }
  }

  /**
   * `LinkCommandGraphEdge` (0x00826960) and `AddCommandQueueToCommandGraph`
   * (0x00826140) are both defined later in this file, after
   * `LowerBoundWeakEntitySetNode`/`ResolveCommandIssueTarget`/
   * `ResolveCommandGraphAnchorWorldPosition` and the rest of the
   * command-issue-history helper cluster they call - see the doc comment on
   * `AddCommandQueueToCommandGraph`'s real definition for the full address
   * decomposition. `RebuildCommandQueueNodes` below still calls
   * `AddCommandQueueToCommandGraph` by name; that resolves through the
   * `friend` declarations on `UICommandGraph` (found via ADL on the
   * `UICommandGraph&` argument), so textual order here does not matter.
   */

  /**
   * Address: 0x00826C50 (FUN_00826C50, sub_826C50)
   *
   * IDA signature:
   * int __stdcall sub_826C50(Moho::UICommandGraph::CommandGraphEdge *edge);
   *
   * What it does:
   * Travel time in game ticks along one orderline: the distance between the two
   * endpoint centroids divided by the slowest speed among the units the command
   * targets (air units use `Air.MaxAirspeed`, everything else
   * `Physics.MaxSpeed`), at 10 ticks per second, rounded up. Returns 0 for
   * command types that do not involve movement.
   *
   * Body below, after the anonymous-namespace helpers it uses.
   */
  [[nodiscard]] std::int32_t EstimateEdgeTravelTicks(const UICommandGraph::CommandGraphEdge& edge);

  /**
   * Address: 0x00826F10 (FUN_00826F10, sub_826F10)
   *
   * IDA signature:
   * int __stdcall sub_826F10(Moho::UICommandGraph *graph,
   *                          Moho::UICommandGraph::UICommandGraphDrawNode *drawNode);
   *
   * What it does:
   * Build time in game ticks for one order: asks `/lua/game.lua`'s
   * `GetConstructEconomyModel` for each assisting engineer/factory's build rate,
   * sums their reciprocals, and divides the remaining work fraction (derived
   * from the part-built unit's health ratio) by that combined rate. Returns 0
   * for any command that is not a `BuildMobile`/`BuildFactory`.
   *
   * Body below, after the anonymous-namespace helpers it uses.
   */
  [[nodiscard]] std::int32_t EstimateDrawNodeWorkTicks(
    UICommandGraph& graph, UICommandGraph::UICommandGraphDrawNode& drawNode
  );

  /**
   * What it does: see the header.
   */
  void UICommandGraph::RebuildCommandQueueNodes()
  {
    PrepareForRebuild();

    // Heap-backed on purpose, like every other `Collect` site - see the note in
    // `DoBeat` for the full reasoning. The binary's local here really is a
    // 400-byte inline stack buffer, but `Collect` takes its destination by the
    // `gpg::fastvector<T>` base, and the base's grow path frees `start_`
    // unconditionally because it has no `originalVec_` word to test against.
    // An inline `FastVectorN` therefore hands `operator delete` a stack address
    // the first time more than 100 units are on screen - observed as
    // push_back -> PushBack -> Reserve -> FreeElements -> free faulting while
    // the Shift command graph rebuilt its nodes. The inline lane can come back
    // once the binary's per-vector-type collect template is restored.
    gpg::fastvector<UserEntity*> entities;
    (void)mSession->GetEntitySpatialDbStorage()
      ->Collect(entities, ENTITYTYPE_Unit);

    for (UserEntity* const entity : entities) {
      if (entity == nullptr) {
        continue;
      }

      // Wall segments, walls and other decorative units never contribute an
      // order line even when they carry a queue.
      if (entity->IsInCategory(msvc8::string{"INSIGNIFICANTUNIT", 17u})) {
        continue;
      }

      AddCommandQueueToCommandGraph(*entity, *this, entity->GetCommandQueue());

      // A stationary factory's build queue is a second, separate order chain -
      // mobile factories (engineers, hives) carry theirs on the normal queue
      // above and must not be folded in twice.
      const bool isFactory = entity->IsInCategory(msvc8::string{"FACTORY", 7u});
      const bool isMobileFactory = isFactory && entity->IsInCategory(msvc8::string{"MOBILE", 6u});
      if (isFactory && !isMobileFactory) {
        AddCommandQueueToCommandGraph(*entity, *this, entity->GetFactoryCommandQueue());
      }
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::ResolveDrawNodeCompletionTick(UICommandGraphDrawNode& drawNode)
  {
    // Non-zero means "already solved this pass". Seeding it with the current
    // tick before recursing is what makes a cyclic order graph terminate: a
    // node reached again while it is still being solved returns immediately.
    if (drawNode.mCompletionTick != 0u) {
      return;
    }

    drawNode.mCompletionTick = static_cast<std::uint32_t>(mSession->mGameTick);

    std::uint32_t startTick = static_cast<std::uint32_t>(mSession->mGameTick);
    const std::int32_t incomingCount = static_cast<std::int32_t>(drawNode.mLaneA.Size());
    for (std::int32_t index = 0; index < incomingCount; ++index) {
      auto* const edge = drawNode.mLaneA[static_cast<std::size_t>(index)];
      UICommandGraphDrawNode* const predecessor = edge->mFromNode;
      if (predecessor != nullptr) {
        ResolveDrawNodeCompletionTick(*predecessor);
        const std::uint32_t readyTick =
          predecessor->mCompletionTick + static_cast<std::uint32_t>(EstimateEdgeTravelTicks(*edge));
        if (startTick < readyTick) {
          startTick = readyTick;
        }
      }
    }

    const std::uint32_t finishTick =
      startTick + static_cast<std::uint32_t>(EstimateDrawNodeWorkTicks(*this, drawNode));

    // The already-stored tick winning means this order costs nothing and has no
    // unfinished predecessor; the binary still steps it back by one so the node
    // sorts before whatever depends on it.
    if (drawNode.mCompletionTick >= finishTick) {
      drawNode.mCompletionTick = drawNode.mCompletionTick - 1u;
    } else {
      drawNode.mCompletionTick = finishTick;
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::PrepareForRebuild()
  {
    // Edge table: drop every node, then put the bucket vector back to the
    // one-bucket starting state. `ClearHashListNodes` is 0x0082C840 here - the
    // 0x2C node carries no owning payload, so it frees without destroying.
    ClearHashListNodes(mMapC);
    mMapC.mBuckets.assign(9u, mMapC.mListHead);
    mMapC.mBucketMask = 1u;
    mMapC.mBucketCount = 1u;

    // Texture-keyed orderline tree: free every bucket, then re-empty the
    // sentinel in place. Unlike `DestroyTree` the head survives - the rebuild
    // pass immediately refills the tree through it.
    DestroyCommandGraphTreeSubtree(mCommandGraphTree.mHead, mCommandGraphTree.mHead->mParent);
    mCommandGraphTree.mHead->mParent = mCommandGraphTree.mHead;
    mCommandGraphTree.mSize = 0u;
    mCommandGraphTree.mHead->mLeft = mCommandGraphTree.mHead;
    mCommandGraphTree.mHead->mRight = mCommandGraphTree.mHead;

    // Draw nodes survive a rebuild; only the edge lanes they own are dropped,
    // back to inline storage so the common single-edge case never re-allocates.
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      node->mDraw.mLaneA.ResetStorageToInline();
      node->mDraw.mLaneB.ResetStorageToInline();
    }

    // Queue-head nodes additionally lose their accumulated centroid: the
    // rebuild re-adds one weighted position per unit sharing the queue, so
    // leaving the old sum in place would double-count every frame.
    for (HashListNode88* node = mMapAB1.mListHead->mNext; node != mMapAB1.mListHead; node = node->mNext) {
      node->mDraw.mLaneA.ResetStorageToInline();
      node->mDraw.mLaneB.ResetStorageToInline();
      node->mDraw.mPositionSum = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
      node->mDraw.mWeight = 0.0f;
    }
  }

  /**
   * What it does: see the header.
   */
  void UICommandGraph::RecomputeAllDrawNodeOrientations()
  {
    for (HashListNode88* node = mMapAB1.mListHead->mNext; node != mMapAB1.mListHead; node = node->mNext) {
      RecomputeDrawNodeOrientation(node->mDraw);
    }

    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      RecomputeDrawNodeOrientation(node->mDraw);
    }
  }

  namespace
  {
    /**
     * One lane's contribution to a draw node's orderline tangent.
     *
     * Both lanes accumulate the same way - the only differences are which
     * endpoint of each edge is the "far" one and which distribution field
     * records the ribbon offset - so the shared mechanic is lifted here rather
     * than written twice. `lengthSquared` is supplied by the caller because the
     * binary sums the three squares in a different component order per lane and
     * float addition is not associative.
     */
    struct DrawNodeOrientationAccumulator
    {
      Wm3::Vector3f mDirectionSum{0.0f, 0.0f, 0.0f};
      std::int32_t mUnitTotal = 0;
    };

    /**
     * The node's centroid: draw nodes accumulate a position *sum* plus a weight
     * so several units sharing one queue average into a single anchor.
     */
    [[nodiscard]] Wm3::Vector3f DrawNodeCentroid(
      const moho::UICommandGraph::UICommandGraphDrawNode& drawNode
    ) noexcept
    {
      const float inverseWeight = 1.0f / drawNode.mWeight;
      return Wm3::Vector3f{
        drawNode.mPositionSum.x * inverseWeight,
        drawNode.mPositionSum.y * inverseWeight,
        drawNode.mPositionSum.z * inverseWeight
      };
    }

    /**
     * Where one edge sits across its lane's ribbon bundle, in [-0.5, +0.5].
     * A lane of one edge yields -0.5 rather than 0 because the binary clamps
     * the divisor, not the result.
     */
    [[nodiscard]] float LaneBundleDistribution(const std::int32_t index, const float laneSpan) noexcept
    {
      const float divisor = (laneSpan < 1.0f) ? 1.0f : laneSpan;
      return (static_cast<float>(index) / divisor) - 0.5f;
    }
  } // namespace

  /**
   * What it does: see the header.
   */
  void UICommandGraph::RecomputeDrawNodeOrientation(UICommandGraphDrawNode& drawNode)
  {
    const std::int32_t maxNodeUnits = ui_CommandGraphMaxNodeUnits;
    const Wm3::Vector3f centroid = DrawNodeCentroid(drawNode);

    // Lane A holds the edges this node is the *destination* of, so the far
    // endpoint is each edge's `mFromNode` and the direction points inbound.
    DrawNodeOrientationAccumulator laneA{};
    {
      const std::int32_t count = static_cast<std::int32_t>(drawNode.mLaneA.Size());
      const float laneSpan = static_cast<float>(count) - 1.0f;
      for (std::int32_t index = 0; index < count; ++index) {
        auto* const edge = drawNode.mLaneA[static_cast<std::size_t>(index)];
        const Wm3::Vector3f farCentroid = DrawNodeCentroid(*edge->mFromNode);

        float dx = centroid.x - farCentroid.x;
        float dy = centroid.y - farCentroid.y;
        float dz = centroid.z - farCentroid.z;

        const std::int32_t edgeUnits =
          (static_cast<std::int32_t>(edge->mTouchCount) >= maxNodeUnits)
            ? maxNodeUnits
            : static_cast<std::int32_t>(edge->mTouchCount);

        const float lengthSquared = ((dx * dx) + (dy * dy)) + (dz * dz);
        if (lengthSquared > 0.0f) {
          const float scale = static_cast<float>(edgeUnits) / std::sqrt(lengthSquared);
          dx = dx * scale;
          dy = dy * scale;
          dz = scale * dz;
        }

        laneA.mDirectionSum.x += dx;
        laneA.mDirectionSum.y += dy;
        laneA.mDirectionSum.z += dz;
        laneA.mUnitTotal += edgeUnits;

        edge->mLaneADistribution = LaneBundleDistribution(index, laneSpan);
      }
    }

    // Lane B holds the edges leaving this node, so the far endpoint is each
    // edge's `mToNode` and the direction points outbound.
    DrawNodeOrientationAccumulator laneB{};
    {
      const std::int32_t count = static_cast<std::int32_t>(drawNode.mLaneB.Size());
      const float laneSpan = static_cast<float>(count) - 1.0f;
      for (std::int32_t index = 0; index < count; ++index) {
        auto* const edge = drawNode.mLaneB[static_cast<std::size_t>(index)];
        const Wm3::Vector3f farCentroid = DrawNodeCentroid(*edge->mToNode);

        float dx = farCentroid.x - centroid.x;
        float dy = farCentroid.y - centroid.y;
        float dz = farCentroid.z - centroid.z;

        const std::int32_t edgeUnits =
          (static_cast<std::int32_t>(edge->mTouchCount) >= maxNodeUnits)
            ? maxNodeUnits
            : static_cast<std::int32_t>(edge->mTouchCount);

        // Component order differs from lane A's sum above; preserved because
        // float addition is not associative and this is the binary's order.
        const float lengthSquared = ((dz * dz) + (dy * dy)) + (dx * dx);
        if (lengthSquared > 0.0f) {
          const float scale = static_cast<float>(edgeUnits) / std::sqrt(lengthSquared);
          dx = dx * scale;
          dy = dy * scale;
          dz = scale * dz;
        }

        laneB.mDirectionSum.x += dx;
        laneB.mDirectionSum.y += dy;
        laneB.mDirectionSum.z += dz;
        laneB.mUnitTotal += edgeUnits;

        edge->mLaneBDistribution = LaneBundleDistribution(index, laneSpan);
      }
    }

    const float totalX = laneB.mDirectionSum.x + laneA.mDirectionSum.x;
    const float totalY = laneB.mDirectionSum.y + laneA.mDirectionSum.y;
    const float totalZ = laneB.mDirectionSum.z + laneA.mDirectionSum.z;

    const float length = std::sqrt(((totalZ * totalZ) + (totalY * totalY)) + (totalX * totalX));
    if (length <= kCommandGraphOrientationEpsilon) {
      drawNode.mOrientationHint = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    } else {
      const float inverseLength = 1.0f / length;
      drawNode.mOrientationHint =
        Wm3::Vector3f{totalX * inverseLength, totalY * inverseLength, totalZ * inverseLength};
    }

    const std::int32_t busierLaneUnits =
      (laneA.mUnitTotal < laneB.mUnitTotal) ? laneB.mUnitTotal : laneA.mUnitTotal;
    drawNode.mUnitCountScale = std::sqrt(static_cast<float>(busierLaneUnits));
  }

  /**
   * What it does: see the header.
   */
  UICommandGraph::ECommandNodeHighlightState UICommandGraph::ResolveDrawNodeHighlightState(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = drawNode.mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return ECommandNodeHighlightState::Normal;
    }

    if (UserEntity* const hoveredEntity = mSession->GetHoveredUserEntity(); hoveredEntity != nullptr) {
      if (UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit(); hoveredUnit != nullptr) {
        WeakSet<UserUnit>* const cursorEntities = ResolveCommandIssueCursorEntities(*ownerHelper);
        if (cursorEntities->Find(hoveredUnit) != cursorEntities->end()) {
          return ECommandNodeHighlightState::Highlighted;
        }
      }
    }

    if (ownerHelper->mConstantData.cmd == mSession->GetCursorInfo().mIsDragger) {
      return ECommandNodeHighlightState::Highlighted;
    }

    if (DrawNodeSharesLiveEntityWithSelection(drawNode)) {
      return ECommandNodeHighlightState::Selected;
    }

    return ECommandNodeHighlightState::Normal;
  }

  namespace
  {
    /**
     * Address: 0x00831110 (FUN_00831110)
     *
     * IDA signature:
     * bool __usercall sub_831110@<al>(Moho::WeakSet_UserUnit *units@<eax>,
     *     Moho::WeakSet_UserEntity *entities@<ecx>);
     *
     * What it does:
     * Whether a unit set and an entity set share a live member. Both are ordered
     * by address, so it walks them together: the lower front steps (`++`
     * 0x0066ADD0 + 0x0066A330 on the entities, 0x007B4D90 + 0x007B29C0 on the
     * units), an equal pair is a hit, and either set running out is a miss.
     * Callers `DrawNodeSharesLiveEntityWithSelection` (0x00828280) and
     * `ResolveCursorHighlightCommandId` (0x00829800).
     */
    [[nodiscard]] bool SharesALiveEntity(const WeakSet<UserEntity>& entities, const WeakSet<UserUnit>& units)
    {
      auto entity = entities.begin();
      if (entity == entities.end()) {
        return false;
      }
      auto unit = units.begin();
      if (unit == units.end()) {
        return false;
      }

      for (;;) {
        UserEntity* const left = *entity;
        UserEntity* const right = *unit;
        if (left < right) {
          if (++entity == entities.end()) {
            return false;
          }
        } else if (right < left) {
          if (++unit == units.end()) {
            return false;
          }
        } else {
          return true;
        }
      }
    }
  } // namespace

  /**
   * Address: 0x00828280 (FUN_00828280, sub_828280)
   *
   * IDA signature:
   * bool __userpurge sub_828280@<al>(int a1@<eax>, int a2);
   *
   * What it does:
   * Reports whether the draw node's command is aimed at anything the player
   * currently has selected. See the declaration for why the null-helper guard
   * is repeated here.
   */
  bool UICommandGraph::DrawNodeSharesLiveEntityWithSelection(
    const UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const ownerHelper = drawNode.mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return false;
    }

    return SharesALiveEntity(mSession->GetSelection(), *ResolveCommandIssueCursorEntities(*ownerHelper));
  }

  /**
   * Address: 0x008282B0 (FUN_008282B0, sub_8282B0)
   *
   * IDA signature:
   * void __thiscall sub_8282B0(UICommandGraph *this, GeomCamera3 *camera,
   *   CD3DPrimBatcher *batcher, UICommandGraphDrawNode *drawNode);
   *
   * What it does:
   * Draws one command node's waypoint marker: a flat quad centered on the
   * node's averaged position, colored/scaled by
   * `ResolveDrawNodeHighlightState`, sized to a roughly-constant apparent
   * screen size via the camera viewport's perspective-width row
   * (`ProjectViewportWidthRow2`, the same shape as the already-recovered
   * `ProjectViewportDepthRow1`, one row over) and clamped to
   * `[ui_MinWaypointSize, ui_MaxWaypointSize]`.
   */
  void UICommandGraph::DrawWaypointMarker(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, UICommandGraphDrawNode& drawNode
  ) const
  {
    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    boost::shared_ptr<CD3DBatchTexture> texture = boost::SharedPtrFromRawRetained(
      reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(node.mWaypointTexture)
    );

    std::uint32_t color = 0;
    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(drawNode)) {
    case ECommandNodeHighlightState::Normal:
      color = node.mWaypointColor;
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      color = node.mWaypointHighlightColor;
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      color = node.mWaypointSelectedColor;
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    if (!texture) {
      texture = CD3DBatchTexture::FromSolidColor(0xFF30F030u);
    }

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);

    // The clamp is in SCREEN units, the quad is in world units. 0x008282B0
    // divides the style scale by the projected depth, clamps that against
    // `ui_MinWaypointSize`/`ui_MaxWaypointSize` (7 and 100 pixels, from
    // `/lua/ui/game/commandwaypoint.lua`), and then multiplies the clamped
    // value BACK by the same depth to get the world half-extent
    // (`v21 * v20` at 0x0082838E..0x008283C4). Without that second multiply
    // the marker was drawn at its pixel size in world units, so the minimum
    // clamp alone made every waypoint tens of map units across.
    const float screenSize =
      std::clamp((drawNode.mUnitCountScale * styleScale) / depthW, ui_MinWaypointSize, ui_MaxWaypointSize);
    const float size = screenSize * depthW;

    batcher.SetTexture(texture);

    const CD3DPrimBatcher::Vertex topLeft{avg.x - size, avg.y, avg.z + size, color, 0.0f, 1.0f};
    const CD3DPrimBatcher::Vertex topRight{avg.x - size, avg.y, avg.z - size, color, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomRight{avg.x + size, avg.y, avg.z - size, color, 1.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomLeft{avg.x + size, avg.y, avg.z + size, color, 1.0f, 1.0f};
    batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  /**
   * Address: 0x00829800 (FUN_00829800, sub_829800)
   *
   * IDA signature:
   * float *__userpurge sub_829800@<eax>(Moho::GeomCamera3 *a1@<esi>,
   *   Moho::UICommandGraph *a2, _DWORD *a3, float *a4);
   *
   * What it does: see the declaration.
   */
  CmdId UICommandGraph::ResolveCursorHighlightCommandId(
    const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  ) const
  {
    if (mMapAB0.mListHead->mNext == mMapAB0.mListHead) {
      return -1;
    }

    float bestScaledDistance = gpg::pInf;
    CmdId bestCommandId = -1;

    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      const UICommandGraphDrawNode& drawNode = node->mDraw;

      const float invWeight = 1.0f / drawNode.mWeight;
      const Wm3::Vector3f avg{
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };

      // Frustum-cull the averaged anchor against the camera's view solid
      // before spending a projection + hit test on it.
      //
      // `CGeomSolid3` carries *outward*-facing plane normals, so a point is
      // outside the solid when its signed distance is positive - the same
      // convention `SolidContainsAabb` (moho/mesh/Mesh.cpp) rejects on, and
      // exactly what 0x008298B2..0x008298BE spells:
      //
      //   0x008298B2  subss  xmm0, [edx+0Ch]        ; d = n.X - constant
      //   0x008298B7  comiss xmm0, ds:dword_E4F6E0  ; the .rdata word is 0.0f
      //   0x008298BE  ja     loc_829B12             ; d > 0 -> next node
      //
      // Testing `<= 0` here instead inverted the whole predicate: every
      // command node actually on screen was discarded, the walk always fell
      // through to `bestCommandId == -1`, and so `CUIWorldView::
      // UpdateSelection` never wrote a real `CmdId` into `MouseInfo::
      // mIsDragger`. With that sentinel permanently -1, `DefaultModeFromDrag`
      // only ever answered COMMOD_Move, the "grab this command node" arm that
      // builds a `UICommandDragger` never ran, and no issued order could be
      // picked up and dragged anywhere.
      bool culledByFrustum = false;
      for (const Wm3::Plane3f& plane : camera.solid2.planes_) {
        const float signedDistance =
          ((plane.Normal.x * avg.x) + (plane.Normal.y * avg.y) + (plane.Normal.z * avg.z)) - plane.Constant;
        if (signedDistance > 0.0f) {
          culledByFrustum = true;
          break;
        }
      }
      if (culledByFrustum) {
        continue;
      }

      const Wm3::Vector2f screenPos = camera.Project(avg);
      const float dx = screenPos.x - cursorScreenPos.x;
      const float dy = screenPos.y - cursorScreenPos.y;
      const float pixelDistance = std::sqrt((dx * dx) + (dy * dy));

      const float depthW = camera.viewport.ProjectViewportWidthRow2(avg);
      float worldTolerance = drawNode.mUnitCountScale / depthW;
      worldTolerance = std::clamp(worldTolerance, ui_MinWaypointSize, ui_MaxWaypointSize);

      const float scaledTolerance = worldTolerance * depthW;
      float scaledDistance = depthW * pixelDistance;

      auto* const helper = drawNode.mHelperLink.GetObjectPtr();
      if (helper != nullptr && ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_Ferry) {
        // Ferry waypoints get a small extra tolerance bonus so a ferry order's
        // markers are easier to pick back up under the cursor.
        scaledDistance -= 0.1f;
      }

      // `ui_CommandClickScale` (the decompiled global name at this read) is
      // not a real symbol - see the `ui_WaypointLineScale` doc comment in
      // `UICommandGraph::LoadPathParams` above: both the `ui_WaypointLineScale`
      // and `ui_CommandClickScale` Lua keys write the same global
      // (0x00F57CDC), and that is what this address reads.
      if ((ui_WaypointLineScale * scaledTolerance) < scaledDistance) {
        continue;
      }

      bool preemptsByLiveSelection = false;
      if (helper != nullptr) {
        preemptsByLiveSelection = SharesALiveEntity(mSession->GetSelection(), *ResolveCommandIssueCursorEntities(*helper));
      }

      if (bestScaledDistance > scaledDistance || preemptsByLiveSelection) {
        bestScaledDistance = scaledDistance;
        bestCommandId = drawNode.mCommandId;
      }
    }

    return bestCommandId;
  }

  /**
   * Address: 0x00828DD0 (FUN_00828DD0, sub_828DD0)
   *
   * IDA signature:
   * void __usercall sub_828DD0(UICommandGraphDrawNode *drawNode@<?>,
   *   UICommandGraph *graph, CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Poses the node's owned mesh instance at its resolved position (the
   * averaged `mPositionSum/mWeight` anchor when `mHasResolvedPosition`,
   * otherwise the anchor `ResolveCommandGraphAnchorWorldPosition` resolves
   * from the owning command's history) with identity orientation (a snap,
   * not an interpolated move - `SetStance` is called with the same
   * transform as both its start and end). When the anchor came from a real
   * unit blueprint, additionally draws that unit's footprint skirt there.
   *
   * The decompile carries the documented "positive sp value has been
   * detected" reliability warning; the temporary `VTransform` construction
   * it mis-attributes to a stack slot 24 bytes off was re-derived from the
   * raw x86 (0x00828E19..0x00828E3A) instead. The observable geometry
   * (position = averaged anchor, orientation = identity,
   * `SetStance(anchor, anchor)`) matches for both branches regardless.
   */
  void UICommandGraph::DrawPositionNodeMesh(UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher) const
  {
    if (!drawNode.mMeshInstance.px) {
      return;
    }
    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return;
    }

    Wm3::Vector3f anchor{};
    const RUnitBlueprint* unitBlueprint = nullptr;

    if (drawNode.mHasResolvedPosition) {
      const REntityBlueprint* const blueprint = helper->mConstantData.blueprint;
      if (blueprint == nullptr || !blueprint->IsUnitBlueprint()) {
        return;
      }
      unitBlueprint = static_cast<const RUnitBlueprint*>(blueprint);

      const float invWeight = 1.0f / drawNode.mWeight;
      anchor = {
        drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
      };
    } else {
      anchor = ResolveCommandGraphAnchorWorldPosition(*helper);
    }

    const VTransform transform{anchor, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
    drawNode.mMeshInstance.px->SetStance(transform, transform);

    if (unitBlueprint == nullptr) {
      return;
    }

    CHeightField* const heightField = mSession->mWldMap->mTerrainRes->GetHeightField();
    CameraImpl* const camera = CAM_GetCamera(gpg::StrArg("WorldCamera"));
    // 0x00828F09..0x00828F1A picks the skirt colour branchlessly:
    //
    //   mov  cl, [edi+1Eh]        ; mIsVisible
    //   neg  cl                   ; CF set when it is non-zero
    //   sbb  ecx, ecx             ; ecx = -1 when visible, 0 when not
    //   and  ecx, 0FF28D800h
    //   add  ecx, 0D8D80000h
    //
    // so a placeable node gets 0xFF28D800 + 0xD8D80000 = 0xD800D800 (ARGB:
    // 84% alpha, pure green) and a rejected one gets 0xD8D80000 (same alpha,
    // pure red). The two constants here had lost their colour bytes
    // entirely - 0xD8000000 is transparent black, which is exactly how the
    // footprint outline drew under a dragged building: visible, but with no
    // indication of whether the drop would be accepted.
    const std::uint32_t color = drawNode.mIsVisible ? 0xD800D800u : 0xD8D80000u;
    DrawUnitSkirt(heightField, unitBlueprint, camera->CameraGetView(), anchor, mSession, &batcher, color);
  }

  /**
   * Address: 0x00828610 (FUN_00828610, Moho::DisplayCommandNode)
   *
   * IDA signature:
   * void __userpurge Moho::DisplayCommandNode(UICommandGraph *this@<ecx>,
   *   GeomCamera3 *camera@<ebx>, UICommandGraphDrawNode *drawNode@<esi>,
   *   CD3DPrimBatcher *batcher);
   *
   * What it does:
   * Draws the "ETA: mm:ss" text label above one command-graph draw node,
   * gated by the "display_eta" option, the command not yet being due
   * (`drawNode.mCompletionTick - mSession->mGameTick < 0` skips), and - only for
   * the non-highlighted/non-selected state - an LOD distance test against
   * `ui_MaxTextLOD` using the camera viewport's depth row (the same
   * `ProjectViewportDepthRow1` shape used throughout this file).
   *
   * Glyph size is `mUnitCountScale * (style scale for the resolved highlight
   * state)`; the label anchors at the node's averaged position offset by
   * that glyph size in X/-Z, then is projected to screen space and nudged
   * by `mDebugFont->mDescent + 1` pixels vertically.
   */
  void UICommandGraph::DisplayCommandNode(
    const GeomCamera3& camera, const UICommandGraphDrawNode& drawNode, CD3DPrimBatcher& batcher
  ) const
  {
    if (!drawNode.mHelperLink.HasValue()) {
      return;
    }

    const std::int32_t beatsUntilDue = static_cast<std::int32_t>(drawNode.mCompletionTick) - mSession->mGameTick;
    if (beatsUntilDue < 0) {
      return;
    }

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    const float invWeight = 1.0f / drawNode.mWeight;
    const Wm3::Vector3f avg{
      drawNode.mPositionSum.x * invWeight, drawNode.mPositionSum.y * invWeight, drawNode.mPositionSum.z * invWeight
    };

    float styleScale = 0.0f;
    switch (ResolveDrawNodeHighlightState(const_cast<UICommandGraphDrawNode&>(drawNode))) {
    case ECommandNodeHighlightState::Normal:
      if (camera.viewport.ProjectViewportDepthRow1(avg) >= ui_MaxTextLOD) {
        return;
      }
      styleScale = node.mWaypointScale;
      break;
    case ECommandNodeHighlightState::Highlighted:
      styleScale = node.mWaypointHighlightScale;
      break;
    case ECommandNodeHighlightState::Selected:
      styleScale = node.mWaypointSelectedScale;
      break;
    }

    const float glyphScale = drawNode.mUnitCountScale * styleScale;

    if (!OPTIONS_GetBool("display_eta")) {
      return;
    }

    const float seconds = static_cast<float>(beatsUntilDue) * 0.1f;
    const auto truncSeconds = static_cast<std::int32_t>(std::trunc(seconds));
    const msvc8::string label = gpg::STR_Printf("ETA: %d.%02d", truncSeconds / 60, truncSeconds % 60);

    const Wm3::Vector3f textAnchor{avg.x + glyphScale, avg.y, avg.z - glyphScale};
    const Wm3::Vector2f projected = camera.Project(textAnchor);
    const Wm3::Vector2f screenPos{
      static_cast<float>(static_cast<std::int32_t>(projected.x + 1.0f)),
      static_cast<float>(static_cast<std::int32_t>(projected.y - (mDebugFont->mDescent + 1.0f)))
    };

    // Color/scale/maxAdvance are elided register args at this callsite the
    // decompile doesn't show explicitly; `NAN` for maxAdvance is the one
    // value the raw decompile states literally, preserved as-is (an
    // unclipped label). Color/scale use this file's other text-draw
    // defaults (opaque white, unscaled) pending a dedicated re-verification.
    mDebugFont->Render2D(gpg::StrArg(label.c_str()), &batcher, screenPos, 0xFFFFFFFFu, 1.0f, std::numeric_limits<float>::quiet_NaN());
  }

  /**
   * Address: 0x008288D0 (FUN_008288D0, sub_8288D0)
   *
   * IDA signature:
   * void __thiscall sub_8288D0(GeomCamera3 *this, UICommandGraph *graph,
   *   CD3DPrimBatcher *batcher, int tick, float tickFraction,
   *   CommandGraphEdge *edge, char isGlow);
   *
   * What it does:
   * Draws one command-graph "orderline" ribbon segment between two draw
   * nodes' averaged positions via `EmitHermiteRibbonSegments`.
   *
   * Verified against the raw x86 (every `*0.0` term in the endpoint-offset
   * block resolves to a hardware-confirmed zero, exactly the pattern
   * already documented on `EmitHermiteRibbonSegments`): the spline's two
   * control points are the *unmodified* averaged from/to positions, and the
   * two tangents fed to the Hermite blend are each endpoint's own tangent
   * (its `mOrientationHint` when non-zero, else the normalized from-to
   * direction) scaled by a smoothness radius
   * (`min(segmentLength * 0.25, ui_CurveSmoothness * width)`).
   *
   * Color/glow selection: when `edge.mForceHighlightStyle` is set, this
   * skips `ResolveDrawNodeHighlightState` entirely and uses the owning
   * node's `mOrderlineHighlightColor`/`mOrderlineHighlightGlow` directly -
   * i.e. the flag forces the "highlighted" appearance, it does not carry a
   * per-edge custom color (see the field's own doc comment). Otherwise the
   * usual 0/1/2 dispatch picks Normal/Highlighted/Selected colors. For the
   * glow pass (`isGlow`), the color's alpha byte is replaced by the style's
   * glow scalar.
   */
  void UICommandGraph::DrawCommandOrderline(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction,
    const CommandGraphEdge& edge, const bool isGlow
  ) const
  {
    UICommandGraphDrawNode* const fromNode = edge.mFromNode;
    if (fromNode == nullptr) {
      return;
    }
    UICommandGraphDrawNode* const toNode = edge.mToNode;
    if (toNode == nullptr) {
      return;
    }
    auto* const ownerHelper = toNode->mHelperLink.GetObjectPtr();
    if (ownerHelper == nullptr) {
      return;
    }

    const float fromInvWeight = 1.0f / fromNode->mWeight;
    const Wm3::Vector3f fromPos{
      fromNode->mPositionSum.x * fromInvWeight, fromNode->mPositionSum.y * fromInvWeight,
      fromNode->mPositionSum.z * fromInvWeight
    };
    const float toInvWeight = 1.0f / toNode->mWeight;
    const Wm3::Vector3f toPos{
      toNode->mPositionSum.x * toInvWeight, toNode->mPositionSum.y * toInvWeight, toNode->mPositionSum.z * toInvWeight
    };

    const float widthFromDepth = camera.viewport.ProjectViewportWidthRow2(fromPos) * 2.0f;
    const float widthToDepth = camera.viewport.ProjectViewportWidthRow2(toPos) * 2.0f;
    const float width = (edge.mBaseWidth + std::max(widthFromDepth, widthToDepth)) * ui_WaypointLineScale;

    Wm3::Vector3f direction{toPos.x - fromPos.x, toPos.y - fromPos.y, toPos.z - fromPos.z};
    direction.Normalize();

    Wm3::Vector3f fromTangent = direction;
    if (fromNode->mOrientationHint.x != 0.0f || fromNode->mOrientationHint.y != 0.0f
        || fromNode->mOrientationHint.z != 0.0f) {
      fromTangent = fromNode->mOrientationHint;
    }
    Wm3::Vector3f toTangent = direction;
    if (toNode->mOrientationHint.x != 0.0f || toNode->mOrientationHint.y != 0.0f
        || toNode->mOrientationHint.z != 0.0f) {
      toTangent = toNode->mOrientationHint;
    }

    const float segmentLength = std::sqrt(
      ((toPos.x - fromPos.x) * (toPos.x - fromPos.x) + (toPos.y - fromPos.y) * (toPos.y - fromPos.y))
      + (toPos.z - fromPos.z) * (toPos.z - fromPos.z)
    );
    const float smoothRadius = std::min(segmentLength * 0.25f, ui_CurveSmoothness * width);

    const auto commandType = ResolveCommandIssueHelperCommandType(*ownerHelper);
    const CommandGraphNode& node = mNodes[static_cast<std::size_t>(commandType)];

    std::uint32_t color;
    float glow;
    if (edge.mForceHighlightStyle) {
      color = node.mOrderlineHighlightColor;
      glow = node.mOrderlineHighlightGlow;
    } else {
      switch (ResolveDrawNodeHighlightState(*toNode)) {
      case ECommandNodeHighlightState::Selected:
        color = node.mOrderlineSelectedColor;
        glow = node.mOrderlineSelectedGlow;
        break;
      case ECommandNodeHighlightState::Highlighted:
        color = node.mOrderlineHighlightColor;
        glow = node.mOrderlineHighlightGlow;
        break;
      case ECommandNodeHighlightState::Normal:
      default:
        color = node.mOrderlineColor;
        glow = node.mOrderlineGlow;
        break;
      }
    }
    if (isGlow) {
      color &= static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24;
    }

    const float uStart = 1.0f - std::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    EmitHermiteRibbonSegments(
      batcher, fromPos, toPos, Wm3::Vector3f{fromTangent.x * smoothRadius, fromTangent.y * smoothRadius, fromTangent.z * smoothRadius},
      Wm3::Vector3f{toTangent.x * smoothRadius, toTangent.y * smoothRadius, toTangent.z * smoothRadius}, width, color,
      uStart, node.mOrderlineAspectRatio
    );
  }

  // Forward declarations: reopens the same file-scope anonymous namespace
  // that defines these two sentinel-headed RB-tree walkers further below (by
  // the selection/save-tree helpers), so `DrawCommandGraphMesh` below - the
  // only command-graph draw method that needs them - can call them here,
  // ahead of their point of definition.
  namespace
  {
    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node);
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node);
  }

  /**
   * Address: 0x00829190 (FUN_00829190, sub_829190)
   *
   * What it does:
   * The per-frame command-graph render pass. Six sub-passes, each under its
   * own primbatcher technique:
   *   A) "TCommand"        - opaque orderlines, walking `mCommandGraphTree`
   *      (a texture-bucketed red-black tree; each node's payload is a
   *      `{texture, msvc8::vector<CommandGraphEdge*>}` pair) and drawing
   *      every edge in every bucket with `isGlow=false`.
   *   B) "TCommandGlow"    - the same tree walk again with `isGlow=true`.
   *   C) "TAlphaBlendLinearSampleNoDepth" - waypoint marker billboards,
   *      walking `mMapAB0` (the sentinel-headed draw-node list).
   *   D) "TAlphaBlendLinearSample" - position-node meshes/skirts, same
   *      `mMapAB0` walk, with a flat white texture bound first.
   *   E) "TCommandOther"   - the optional path-preview overlay (gated on
   *      `ui_DrawPathPreview`), then a screen-space pixel projection.
   *   F) (still under TCommandOther) - per-node ETA text labels, a third
   *      `mMapAB0` walk.
   *
   * The two tree walks and three list walks are the decompiler's
   * `boost::shared_ptr`-shaped traversal of `mCommandGraphTree`/`mMapAB0`
   * respectively (IDA mistyped both containers as chains of
   * `boost::detail::sp_counted_base_vtbl`/`CD3DBatchTexture` because their
   * node layouts happen to alias those types' field shapes at the read
   * offsets) - recovered here as the same typed RB-tree/list walks every
   * sibling command-graph function already uses.
   *
   * IDA's `__userpurge` signature adds two register arguments (typed
   * `CRenderWorldView*` and `boost::shared_ptr<UICommandGraph>&` in the
   * analyst database) that are only the caller's leftover `ecx`/`edx`
   * (`CWldSession::RenderCommandGraph`, 0x0085AF40); this body never reads
   * either.
   */
  void UICommandGraph::DrawCommandGraphMesh(
    const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick, const float tickFraction
  )
  {
    batcher.Flush();

    // Pass A: opaque orderlines, bucketed by texture.
    (void)batcher.Setup("TCommand");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mCommandGraphTree.mHead->mLeft;
         node != nullptr && node != mCommandGraphTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = node->mBucket;
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/false);
      }
    }
    batcher.Flush();

    // Pass B: glow overlay for the same orderlines.
    (void)batcher.Setup("TCommandGlow");
    batcher.SetViewProjMatrix(camera);
    for (CommandGraphTreeNode* node = mCommandGraphTree.mHead->mLeft;
         node != nullptr && node != mCommandGraphTree.mHead; node = NextTreeNode(node)) {
      CommandGraphTreeBucket& bucket = node->mBucket;
      batcher.SetTexture(boost::SharedPtrFromRawRetained(bucket.mTexture));
      for (CommandGraphEdge* const edge : bucket.mEdges) {
        DrawCommandOrderline(camera, batcher, tick, tickFraction, *edge, /*isGlow=*/true);
      }
    }
    batcher.Flush();

    // Pass C: waypoint marker billboards.
    (void)batcher.Setup("TAlphaBlendLinearSampleNoDepth");
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DrawWaypointMarker(camera, batcher, node->mDraw);
    }
    batcher.Flush();

    // Pass D: position-node meshes/skirts, over a flat white texture.
    (void)batcher.Setup("TAlphaBlendLinearSample");
    batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DrawPositionNodeMesh(node->mDraw, batcher);
    }
    batcher.Flush();

    // Pass E: optional path-preview overlay, then switch to a screen-space
    // pixel projection for the ETA text pass below.
    (void)batcher.Setup("TCommandOther");
    if (ui_DrawPathPreview) {
      DrawPathPreview(*this, camera, batcher, tick, tickFraction);
    }

    batcher.SetProjectionMatrix(MakeViewportPixelProjection(camera));
    batcher.SetViewMatrix(VMatrix4::Identity());

    // Pass F: per-node ETA text labels, in the screen-space projection just set.
    for (HashListNode88* node = mMapAB0.mListHead->mNext; node != mMapAB0.mListHead; node = node->mNext) {
      DisplayCommandNode(camera, node->mDraw, batcher);
    }
    batcher.Flush();
  }

  /**
   * Not a distinct binary function - `UICommandGraph` is only a complete
   * type in this file, so `UICommandGraph::ResolveCursorHighlightCommandId`
   * needs a wrapper here. `Moho::CUIWorldView::UpdateSelection` (UiRuntimeTypes.cpp)
   * calls this through the bare `UICommandGraph*` its `mComGraph` holds.
   * Returns -1 (no highlighted command) when `graph` is null.
   */
  CmdId ResolveCommandGraphCursorHighlightIfPresent(
    UICommandGraph* const graph, const GeomCamera3& camera, const Wm3::Vector2f& cursorScreenPos
  )
  {
    if (graph == nullptr) {
      return -1;
    }
    return graph->ResolveCursorHighlightCommandId(camera, cursorScreenPos);
  }

  // Forward declarations for functions `DrawPathPreview` below needs whose
  // own out-of-line definitions live later in this TU (`func_
  // GetRightMouseButtonAction`, at global scope, is referenced by the linker
  // at global scope so its definition stays there) or that this codebase
  // conventionally forward-declares per-TU rather than sharing a header for
  // (`MultQuadVec`, matching the same one-line declaration already repeated
  // in a dozen other .cpp files that call it).
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);

  /**
   * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
   *
   * Defined in Sim.cpp; declared here rather than pulling in Sim.h for one
   * symbol.
   */
  [[nodiscard]] EUnitCommandType UnitCommandCapToCommandType(ERuleBPUnitCommandCaps commandCap);

  /**
   * Address: 0x0082A380 (FUN_0082A380, sub_82A380)
   *
   * What it does:
   * Draws the active move-command's path-preview ribbon: either the
   * Ramer-Douglas-Peucker-simplified world-space path sampled from the
   * previewed army's runtime cell-position scratch buffer
   * (`ui_PathPreview` on), or a straight two-point line from the cursor to
   * the deepest selected unit's current/queued anchor position
   * (`ui_PathPreview` off). Both converge on the same ribbon-emission walk
   * used by `UICommandGraph::DrawCommandOrderline`, styled from the
   * command-graph node matching the pending right-click command, with an
   * arrowhead billboard capping the last segment when the node has one.
   *
   * `arg0`, the IDA-declared first parameter, is not a real argument - see
   * this function's declaration in CWldSession.h.
   *
   * The runtime cell-position buffer's trailing "meta" dword
   * (`SArmyVectorWithMeta::mMetaWord`, modeled as a plain pointer-sized word
   * because different consumers reuse the same bytes differently) is read here
   * as a pointer to a 3-byte `{sizeX, sizeZ, layer}` footprint descriptor -
   * confirmed against the raw disassembly, not just the decompile, so the
   * reinterpret is applied at this call site rather than changing the
   * field's canonical type.
   */
  void DrawPathPreview(
    UICommandGraph& graph, const GeomCamera3& camera, CD3DPrimBatcher& batcher, const std::int32_t tick,
    const float tickFraction
  )
  {
    CWldSession* const session = graph.mSession;

    const std::int32_t focusArmy = session->FocusArmy;
    if (focusArmy < 0) {
      return;
    }
    UserArmy* const army = session->userArmies[focusArmy];
    if (army == nullptr) {
      return;
    }

    SArmyVectorWithMeta& scratch = army->mVarDat.mWordVectorWithMeta;
    const std::size_t cellCount = scratch.mWords.size();
    // The meta dword is only ever a real descriptor pointer once the army's
    // scratch buffer has been populated for STI/path-preview display; a
    // fresh/never-populated army leaves it null.
    const auto* const footprintDescriptor = reinterpret_cast<const std::uint8_t*>(scratch.mMetaWord);

    msvc8::list<Wm3::Vector3f> simplifiedPath{};
    float capWidthSeed = 0.0f;

    if (ui_PathPreview) {
      if (footprintDescriptor == nullptr || cellCount < 2) {
        return;
      }

      capWidthSeed = static_cast<float>(footprintDescriptor[0]);

      STIMap* const stiMap = session->GetSTIMap();
      const auto* const cellPositions = reinterpret_cast<const SOCellPos*>(scratch.mWords.begin());

      // This count-only constructor call is FUN_0082A46C's `call sub_7E3730`
      // in the raw disassembly (Moho::DrawPathPreview is FUN_0082A380) --
      // VC8's `vector(size_type)` materialises a default `Wm3::Vector3f()`
      // temporary and forwards into the same allocate-then-fill path as
      // `vector(count, value)` (FUN_007E3730 -> FUN_007E4370 -> FUN_007E6460,
      // Vector.h). Every slot is overwritten by the loop immediately below,
      // so the broadcast fill value never survives to be observed.
      msvc8::vector<Wm3::Vector3f> worldPts(cellCount);
      for (std::size_t i = 0; i < cellCount; ++i) {
        worldPts[i] = COORDS_ToWorldPos(
          stiMap, cellPositions[i], static_cast<ELayer>(footprintDescriptor[2]), footprintDescriptor[0],
          footprintDescriptor[1]
        );
      }

      simplifiedPath.push_back(worldPts.front());
      simplifiedPath.push_back(worldPts.back());
      SimplifyPathSpan(
        worldPts, 0, static_cast<std::int32_t>(cellCount) - 1, simplifiedPath, --simplifiedPath.end(),
        ui_PathSmoothness
      );
    } else {
      if (!session->CursorInfo().mHitValid) {
        return;
      }

      UserUnit* const subject = PickPathPreviewSubject(const_cast<WeakSet<UserEntity>&>(session->GetSelection()));
      if (subject == nullptr) {
        return;
      }

      IUnit* const subjectBridge = GetIUnitBridge(subject);
      // 0x0082A60D..0x0082A62A: `GetBlueprint()` (IUnit slot 7), `add eax,
      // 0D8h` / `movzx eax, byte ptr [eax]` -- the first byte of the
      // blueprint's inline `REntityBlueprint::mFootprint` (+0xD8), i.e. the
      // same footprint `mSizeX` the ui_PathPreview branch above reads from
      // its descriptor. It was a raw `[216]` byte index into the blueprint.
      capWidthSeed = static_cast<float>(subjectBridge->GetBlueprint()->mFootprint.mSizeX);

      Wm3::Vector3f endPos = subjectBridge->GetPosition();
      if (MAUI_KeyIsDown(MKEY_SHIFT)) {
        // `GetLastQueuedUserCommandAnchor` and `ResolveCommandGraphAnchorWorldPosition`
        // both ultimately view the same binary object (the unit's most
        // recently queued command-issue helper) through different recovered
        // type lanes - see the former's doc comment in UserUnit.cpp.
        const auto* const anchorHelper =
          reinterpret_cast<const UserCommandIssueHelper*>(GetLastQueuedUserCommandAnchor(subject));
        if (anchorHelper != nullptr) {
          endPos = ResolveCommandGraphAnchorWorldPosition(const_cast<UserCommandIssueHelper&>(*anchorHelper));
        }
      }

      simplifiedPath.push_back(session->CursorInfo().mMouseWorldPos);
      simplifiedPath.push_back(endPos);
    }

    // Two distinct distance-based scale terms, both read off the camera's
    // world/view-matrix row via the front preview point - confirmed distinct
    // (not the same term reused) by their different scale constants and by
    // `capDivisor` alone folding in `capWidthSeed` as a floor:
    //   capDivisor - denominator for the arrowhead cap offset below.
    //   maxWidthTerm - the ribbon half-width term, maxed against the back
    //     point too (matching `DrawCommandOrderline`'s sibling formula)
    //     rather than the single-point read the raw decompile's redundant
    //     reloads collapse to.
    const float frontProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.front());
    const float capDivisor = std::max(capWidthSeed, frontProjected * 3.0f) * 0.2f;

    float maxWidthTerm = frontProjected * 2.0f;
    const float backProjected = camera.viewport.ProjectViewportWidthRow2(simplifiedPath.back()) * 2.0f;
    if (backProjected > maxWidthTerm) {
      maxWidthTerm = backProjected;
    }

    const LuaPlus::LuaObject waypointModule = SCR_Import(g_UIManager->mLuaState, "/lua/ui/game/commandwaypoint.lua");
    LuaPlus::LuaFunction<float> calculateWaypointLineWidth{waypointModule["CalculateWaypointLineWidth"]};
    const float luaWidth = calculateWaypointLineWidth(static_cast<unsigned int>(session->GetSelection().Size()));

    const float finalWidth = (maxWidthTerm + luaWidth) * ui_WaypointLineScale;

    // Side-effect-only: the binary re-fills a scratch SCommandModeData via
    // GetLeftMouseButtonAction, then immediately overwrites it with a copy of
    // the resolved commandData and destroys it - net zero data effect, since
    // neither commandData nor anything outside this scratch's own lifetime is
    // touched. Mode 7 is `COMMOD_CancelCommandMode`, the value
    // `func_GetRightMouseButtonAction` writes at 0x0081ED4E when a UI command
    // mode is already engaged - this comparison is how that value was first
    // sighted, and it was dead until the writer was restored.
    CommandModeData commandData{};
    (void)func_GetRightMouseButtonAction(&commandData, &session->CursorInfo(), 0, session);
    if (commandData.mMode == COMMOD_CancelCommandMode) {
      CommandModeData scratch{};
      (void)session->GetLeftMouseButtonAction(&scratch, &session->CursorInfo(), 0);
    }

    const ERuleBPUnitCommandCaps caps =
      (commandData.mMode == COMMOD_Order) ? commandData.mCommandCaps : RULEUCC_Move;
    UICommandGraph::CommandGraphNode& node = graph.mNodes[static_cast<std::size_t>(UnitCommandCapToCommandType(caps))];

    if (node.mOrderlineTexture.px != nullptr) {
      batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
        node.mOrderlineTexture
      )));
    } else {
      batcher.SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    }

    const bool hasArrowhead = node.mArrowheadTexture.px != nullptr;
    const float uStart = 1.0f - std::fmod((static_cast<double>(tick) + tickFraction) * node.mOrderlineAnimRate, 1.0);

    for (auto it = simplifiedPath.begin(); it != simplifiedPath.end(); ++it) {
      auto next = it;
      ++next;
      if (next == simplifiedPath.end()) {
        break;
      }

      Wm3::Vector3f p0 = *it;
      Wm3::Vector3f p1 = *next;
      const bool isLastSegment = [&] {
        auto afterNext = next;
        ++afterNext;
        return afterNext == simplifiedPath.end();
      }();

      if (isLastSegment && hasArrowhead) {
        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        p1 = Wm3::Vector3f{p1.x + direction.x * finalWidth, p1.y + direction.y * finalWidth, p1.z + direction.z * finalWidth};
      }

      auto prevOfIt = it;
      const bool hasPrevOfIt = (it != simplifiedPath.begin());
      if (hasPrevOfIt) {
        --prevOfIt;
      }
      auto afterNext = next;
      ++afterNext;
      const bool hasAfterNext = (afterNext != simplifiedPath.end());

      Wm3::Vector3f t0{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasPrevOfIt) {
        t0 = Wm3::Vector3f{p1.x - prevOfIt->x, p1.y - prevOfIt->y, p1.z - prevOfIt->z};
      }
      const float t0Len = std::sqrt(t0.x * t0.x + t0.y * t0.y + t0.z * t0.z);
      if (t0Len > ui_PathSmoothness && t0Len > 0.0f) {
        const float scale = ui_PathSmoothness / t0Len;
        t0 = Wm3::Vector3f{t0.x * scale, t0.y * scale, t0.z * scale};
      }

      Wm3::Vector3f t1{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
      if (hasAfterNext) {
        t1 = Wm3::Vector3f{afterNext->x - p0.x, afterNext->y - p0.y, afterNext->z - p0.z};
      }
      const float t1Len = std::sqrt(t1.x * t1.x + t1.y * t1.y + t1.z * t1.z);
      if (t1Len > ui_PathSmoothness && t1Len > 0.0f) {
        const float scale = ui_PathSmoothness / t1Len;
        t1 = Wm3::Vector3f{t1.x * scale, t1.y * scale, t1.z * scale};
      }

      EmitHermiteRibbonSegments(
        batcher, p0, p1, t0, t1, finalWidth, node.mOrderlineSelectedColor, uStart, node.mOrderlineAspectRatio
      );

      if (isLastSegment && hasArrowhead) {
        const float capOffset = (finalWidth / capDivisor) * node.mArrowheadCapOffset;
        batcher.Flush();
        batcher.SetTexture(boost::SharedPtrFromRawRetained(reinterpret_cast<const boost::SharedPtrRaw<CD3DBatchTexture>&>(
          node.mArrowheadTexture
        )));

        Wm3::Vector3f direction{p1.x - p0.x, p1.y - p0.y, p1.z - p0.z};
        direction.Normalize();
        const Wm3::Vector3f capCenter{
          p1.x + direction.x * capOffset, p1.y + direction.y * capOffset, p1.z + direction.z * capOffset};
        const Wm3::Quaternionf orient = COORDS_Orient(direction);

        Wm3::Vector3f corners[4] = {
          {-finalWidth, 0.0f, -finalWidth}, {-finalWidth, 0.0f, finalWidth}, {finalWidth, 0.0f, finalWidth},
          {finalWidth, 0.0f, -finalWidth}};
        for (Wm3::Vector3f& corner : corners) {
          Wm3::Vector3f rotated{};
          (void)MultQuadVec(&rotated, &corner, &orient);
          corner = Wm3::Vector3f{capCenter.x + rotated.x, capCenter.y + rotated.y, capCenter.z + rotated.z};
        }

        batcher.DrawQuad(
          CD3DPrimBatcher::Vertex{corners[0].x, corners[0].y, corners[0].z, 0xFFFFFFFFu, 0.0f, 1.0f},
          CD3DPrimBatcher::Vertex{corners[1].x, corners[1].y, corners[1].z, 0xFFFFFFFFu, 0.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[2].x, corners[2].y, corners[2].z, 0xFFFFFFFFu, 1.0f, 0.0f},
          CD3DPrimBatcher::Vertex{corners[3].x, corners[3].y, corners[3].z, 0xFFFFFFFFu, 1.0f, 1.0f}
        );
      }
    }
  }

  /**
   * Address: 0x00824810 (FUN_00824810, ??0UICommandGraph@Moho@@QAE@@Z)
   */
  UICommandGraph::UICommandGraph(CWldSession* const session)
    : mNeedsRebuild(1u)
    , pad_0001{0, 0, 0}
    , mNodes{}
    , mSession(session)
    , mSessionRes1(session ? session->mCommandManager : nullptr)
    , mDebugFont(nullptr)
    , mMapAB0{}
    , mMapAB1{}
    , mMapC{}
    , mMapD{}
    , mCommandGraphTree{}
  {
    InitMapAB(mMapAB0, this);
    InitMapAB(mMapAB1, this);
    InitMapC(mMapC, this);
    InitMapD(mMapD, this);
    InitTree(mCommandGraphTree);

    boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(10, "Andale Mono");
    AssignIntrusive(mDebugFont, createdFont.px);
    createdFont.release();

    LoadPathParams();
    LoadWaypointParams();
    CreateMeshes();
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, true);
  }

  /**
   * Address: 0x00824B80 (FUN_00824B80, ??1UICommandGraph@Moho@@QAE@XZ) cleanup chain.
   */
  UICommandGraph::~UICommandGraph()
  {
    OnCommandGraphShow(mSession ? mSession->mState : nullptr, false);
    DestroyTree(mCommandGraphTree);
    DestroyMap(mMapD);
    DestroyMap(mMapC);
    DestroyMap(mMapAB1);
    DestroyMap(mMapAB0);
    ReleaseIntrusive(mDebugFont);
    mSessionRes1 = nullptr;
    mSession = nullptr;
    mNeedsRebuild = 0u;
  }

  namespace
  {
    // The orphan and visibility sets are `CWldSession::mOrphans` (+0x42C) and
    // `CWldSession::mVizUpdates` (+0x438), two bare 12-byte `WeakSet<UserEntity>`
    // headers; they were reached through two padded overlays here that laid a
    // 16-byte `WeakSet<UserEntity>` over each. The cursor snapshot at
    // +0x4B0 is `CWldSession::CursorInfo()`, not a third padded overlay.

    template <typename TNode>
    [[nodiscard]] bool IsSentinelNode(const TNode* const node)
    {
      return !node || node->mIsSentinel != 0u;
    }

    template <typename TNode>
    [[nodiscard]] TNode* NextTreeNode(TNode* node)
    {
      if (!node || IsSentinelNode(node)) {
        return node;
      }

      if (!IsSentinelNode(node->mRight)) {
        node = node->mRight;
        while (!IsSentinelNode(node->mLeft)) {
          node = node->mLeft;
        }
        return node;
      }

      TNode* parent = node->mParent;
      while (!IsSentinelNode(parent) && node == parent->mRight) {
        node = parent;
        parent = parent->mParent;
      }
      return parent;
    }

    /**
     * Predecessor mirror of `NextTreeNode` above - not separately confirmed
     * against a `mCommandGraphTree`-specific `rb_decrement` address (only
     * its increment sibling, 0x0082EC10, is directly cited for this tree in
     * `legacy/containers/RbTree.h`), but the shape is the generic VC8
     * `_Dec` walk every other instantiation in that file uses - left
     * subtree's rightmost node, or the nearest ancestor whose right
     * subtree contains `node`. Used only by
     * `AttachCommandGraphNodeHinted`'s straddle checks below, which
     * never call it on the header sentinel itself, so the `_Dec`-specific
     * "`--end()` yields rightmost" header case does not apply here.
     */
    template <typename TNode>
    [[nodiscard]] TNode* PrevTreeNode(TNode* node)
    {
      if (!node || IsSentinelNode(node)) {
        return node;
      }

      if (!IsSentinelNode(node->mLeft)) {
        node = node->mLeft;
        while (!IsSentinelNode(node->mRight)) {
          node = node->mRight;
        }
        return node;
      }

      TNode* parent = node->mParent;
      while (!IsSentinelNode(parent) && node == parent->mLeft) {
        node = parent;
        parent = parent->mParent;
      }
      return parent;
    }

    /**
     * Address: 0x0081FD2B..0x0081FD4E (inlined into
     * `Moho::SCommandModeData::HandleEvent`, FUN_0081FCD0)
     *
     * What it does:
     * Resolves the entity a command-mode drag snapshot is hovering.
     * `MouseInfo::mUnitHover` is an intrusive weak-link slot rather than a
     * live pointer (the same lane `CWldSession::GetHoveredUserEntity` decodes
     * for the session's own cursor), and an entity the session has already
     * orphaned (`mMarkedForDeletion`) counts as "nothing hovered".
     */
    [[nodiscard]] UserEntity* DecodeHoveredDragEntity(const MouseInfo& cursor) noexcept
    {
      UserEntity* const entity = cursor.HoveredEntity();
      if (entity == nullptr || entity->mMarkedForDeletion != 0u) {
        return nullptr;
      }
      return entity;
    }

    // GetHoveredUserEntity is now CWldSession::GetHoveredUserEntity, a public
    // member (declared near GetCursorInfo() in the header) - promoted so the
    // command-graph render pass in CUIWorldView.cpp can call it too.

    // ResolveIUnitBridge was a duplicate of UserUnit.h's GetIUnitBridge -
    // callers below now use that instead.

    [[nodiscard]] bool ContainsUnitPtr(const msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      return std::find(units.begin(), units.end(), unit) != units.end();
    }

    void AppendUnitUnique(msvc8::vector<UserUnit*>& units, UserUnit* const unit)
    {
      if (unit == nullptr || ContainsUnitPtr(units, unit)) {
        return;
      }
      units.push_back(unit);
    }

    void RemoveUnitIfPresent(msvc8::vector<UserUnit*>& units, const UserUnit* const unit)
    {
      msvc8::vector<UserUnit*> filteredUnits{};
      filteredUnits.reserve(units.size());
      for (UserUnit* const candidate : units) {
        if (candidate != unit) {
          filteredUnits.push_back(candidate);
        }
      }
      units = filteredUnits;
    }

    [[nodiscard]] bool ContainsEntityPtr(const msvc8::vector<UserEntity*>& entities, const UserEntity* const entity)
    {
      return std::find(entities.begin(), entities.end(), entity) != entities.end();
    }

    void CollectSelectionEntities(const WeakSet<UserEntity>& selection, msvc8::vector<UserEntity*>& outEntities)
    {
      outEntities.clear();

      for (UserEntity* const entity : selection) {
        if (ContainsEntityPtr(outEntities, entity)) {
          continue;
        }
        outEntities.push_back(entity);
      }
    }

    /**
     * Address: 0x0081D160 (FUN_0081D160)
     *
     * What it does:
     * Returns true when at least one live entity in the current selection is in
     * the `TELEPORTATION` category.
     */
    [[nodiscard]] bool SelectionContainsTeleportationUnit(WeakSet<UserEntity>& selection)
    {
      msvc8::string teleportationCategory("TELEPORTATION");
      for (UserEntity* const entity : selection) {
        if (entity != nullptr && entity->IsInCategory(teleportationCategory)) {
          return true;
        }
      }

      return false;
    }

    /**
     * Address: 0x0081DB40 (FUN_0081DB40, func_CoordinatedAttack)
     *
     * What it does:
     * Returns true when the dragged command is an attack/form-attack command
     * and no live selected user-unit already has that command helper queued.
     *
     * Invocation: sole caller in the binary is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * `RULEUCC_Attack` hovered-target arm at 0x0081FEBD - recovered below and
     * calling this by name.
     */
    [[nodiscard]] bool CanStartCoordinatedAttack(CWldSession& session, const CmdId commandId)
    {
      UserCommandIssueHelper* const helper = FindCommandIssueHelperInSession(&session, commandId);
      if (helper == nullptr) {
        return false;
      }

      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (commandType != EUnitCommandType::UNITCOMMAND_Attack &&
          commandType != EUnitCommandType::UNITCOMMAND_FormAttack) {
        return false;
      }

      WeakSet<UserEntity>& selection = session.mSelection;
      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);
        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
            return false;
          }
        }
      }

      return true;
    }

    /**
     * Address: 0x0081DD00 (FUN_0081DD00)
     *
     * IDA signature:
     * char __cdecl sub_81DD00(Moho::WeakSet_UserEntity *a1, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Tests whether a just-issued Move/FormMove drag command (`helper`) may
     * be silently restarted in place as Patrol/FormPatrol instead of being
     * queued as a brand-new order. Returns false when `helper` is null, the
     * selection is empty, or `helper`'s resolved command type is neither
     * Move nor FormMove. Otherwise walks the live selection: any live,
     * non-dead, non-destroy-queued `UserUnit` with a command queue that is
     * in the "POD" category vetoes the restart outright. For every such
     * unit whose queue already contains `helper` at a position other than
     * the last entry (queue depth over 1 and `helper` is not the tail),
     * every queued command in that unit's whole resolved queue must
     * resolve to `helper`'s own command type, or the restart is rejected;
     * units whose queue doesn't meet that depth/position/membership gate
     * are simply skipped. Returns true once every live selected entity has
     * been scanned without a rejection.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, 2167 instructions, owned by this file), from the
     * drag-move patrol-restart arm (0x008207E6) - on success the caller
     * skips issuing a new command and instead calls
     * `RestartMoveCommandAsPatrol` below with the same selection and helper.
     * `HandleEvent` is recovered below and calls this by name.
     */
    [[nodiscard]] bool CanRestartMoveCommandAsPatrol(
      WeakSet<UserEntity>& selection,
      UserCommandIssueHelper* const helper
    )
    {
      if (helper == nullptr) {
        return false;
      }


      const EUnitCommandType commandType = ResolveCommandIssueHelperCommandType(*helper);
      if (selection.Empty() ||
          (commandType != EUnitCommandType::UNITCOMMAND_Move &&
           commandType != EUnitCommandType::UNITCOMMAND_FormMove)) {
        return false;
      }

      const msvc8::string podCategory("POD");

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          UserCommandQueue* const manager = userUnit->GetCommandQueue();
          if (manager != nullptr) {
            if (userUnit->IsInCategory(podCategory)) {
              return false;
            }

            if (GetUserUnitManagerQueueSize(manager) <= 1
                || GetUserUnitManagerQueueTailHelperRaw(manager) == helper
                || !UserUnitManagerContainsCommandIssueHelper(manager, helper)) {
              return false;
            }

            if (!UserUnitManagerQueueHasUniformCommandType(manager, commandType)) {
              return false;
            }
          }
        }
      }

      return true;
    }

    /**
     * Address: 0x0081DEF0 (FUN_0081DEF0)
     *
     * IDA signature:
     * std::map *__usercall sub_81DEF0@<eax>(Moho::WeakSet_UserEntity *ebx0@<ebx>, struct_CommandIssueHelper *a2);
     *
     * What it does:
     * Companion to `CanRestartMoveCommandAsPatrol`, invoked only once that
     * gate has confirmed the restart is safe. Resolves `helper`'s own
     * command type (Move -> Patrol, FormMove -> FormPatrol) then walks
     * every live selected entity's command queue via
     * `RestartQueuedCommandsFromHelper`, which reissues every queue entry
     * from `helper` onward (inclusive) that still shares its original
     * command type.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008207F7), called with the same weak
     * selection set still live in a register from the
     * `CanRestartMoveCommandAsPatrol` call immediately before it.
     */
    void RestartMoveCommandAsPatrol(WeakSet<UserEntity>& selection, UserCommandIssueHelper* const helper)
    {
      const EUnitCommandType originalCommandType = ResolveCommandIssueHelperCommandType(*helper);
      const EUnitCommandType restartCommandType =
        (originalCommandType == EUnitCommandType::UNITCOMMAND_Move)
          ? EUnitCommandType::UNITCOMMAND_Patrol
          : EUnitCommandType::UNITCOMMAND_FormPatrol;

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            RestartQueuedCommandsFromHelper(manager, helper, originalCommandType, restartCommandType);
          }
        }
      }
    }

    /**
     * Address: 0x0081E050 (FUN_0081E050)
     *
     * IDA signature:
     * char __cdecl sub_81E050(Moho::WeakSet_UserEntity *arg0, float *a2, char a3);
     *
     * What it does:
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has a
     * command queue, not dead, not destroy-queued), accumulating their live
     * `IUnit::GetPosition()` into `outAnchor` for a running average. Unless
     * `skipPatrolCheck` is set, also inspects each eligible unit's
     * most-recently-queued command helper - taken from its factory command
     * queue when the unit is immobile (`IUnit::IsMobile()` false), otherwise
     * its regular command queue - and returns true immediately the moment
     * that command resolves to Patrol/FormPatrol (the caller then reissues
     * the drag command as-is, using the existing target, with no new
     * anchor). Otherwise, when that command's own command-graph anchor
     * position (`ResolveCommandGraphAnchorWorldPosition`, 0x0081CFD0)
     * resolves to a valid (non-NaN) position, `outAnchor` is overwritten
     * with it (last live match wins). After the scan: if `outAnchor` ended
     * up anything other than the zero vector (an anchor override was
     * found), it is kept as-is; otherwise `outAnchor` is replaced by the
     * running position average. Returns false on both of those paths - only
     * the early Patrol/FormPatrol detection returns true.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called twice from the `RULEUCC_Patrol`
     * arm (0x00820BD7 and 0x00820CED): once for the plain-selection drag and
     * once for the paired rally-point `ISSUE_FactoryCommand` drag, each time
     * immediately followed by `Moho::STIMap::GetSurface` snapping `outAnchor`
     * to the terrain when this returns false.
     */
    [[nodiscard]] bool ResolveGroupMoveAnchorOrDetectPatrol(
      WeakSet<UserEntity>& selection,
      Wm3::Vector3f& outAnchor,
      const bool skipPatrolCheck
    )
    {
      outAnchor = Wm3::Vector3f::Zero();


      std::int32_t eligibleCount = 0;
      Wm3::Vector3f anchorOverride = Wm3::Vector3f::Zero();

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;
              const Wm3::Vec3f& position = iunit->GetPosition();
              outAnchor.x += position.x;
              outAnchor.y += position.y;
              outAnchor.z += position.z;

              if (!skipPatrolCheck) {
                UserCommandIssueHelper* lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
                if (!iunit->IsMobile()) {
                  if (UserCommandQueue* const factoryManager = userUnit->GetFactoryCommandQueue();
                      factoryManager != nullptr) {
                    lastHelper = GetUserUnitManagerLastQueuedHelper(factoryManager);
                  }
                }

                if (lastHelper != nullptr) {
                  const EUnitCommandType lastCommandType = ResolveCommandIssueHelperCommandType(*lastHelper);
                  if (lastCommandType == EUnitCommandType::UNITCOMMAND_Patrol ||
                      lastCommandType == EUnitCommandType::UNITCOMMAND_FormPatrol) {
                    return true;
                  }

                  if (const Wm3::Vector3f resolvedAnchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                      IsValidVector3f(resolvedAnchor)) {
                    anchorOverride = resolvedAnchor;
                  }
                }
              }
            }
          }
        }
      }

      if (const Wm3::Vector3f zero = Wm3::Vector3f::Zero(); anchorOverride != zero) {
        outAnchor = anchorOverride;
        return false;
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return false;
    }

    /**
     * Address: 0x0081E2E0 (FUN_0081E2E0)
     *
     * IDA signature:
     * char __cdecl sub_81E2E0(Moho::WeakSet_UserEntity *a1, float *a2);
     *
     * What it does:
     * Ferry-command sibling of `ResolveGroupMoveAnchorOrDetectPatrol`.
     * Scans the live selection for eligible `UserUnit`s (`IsUserUnit`, has
     * a command queue, not dead, not destroy-queued). For each: resolves
     * its most-recently-queued command helper; when one exists, accumulates
     * that command's own command-graph anchor position
     * (`ResolveCommandGraphAnchorWorldPosition`) into `outAnchor` and clears
     * the "all still ferrying" flag unless that command is itself
     * `UNITCOMMAND_Ferry`; when none exists, accumulates the unit's live
     * `IUnit::GetPosition()` instead and always clears the flag. After the
     * scan, `outAnchor` is divided by the eligible-unit count (left
     * untouched when there were none). Returns true when every eligible
     * unit's queued command was already `UNITCOMMAND_Ferry` (including the
     * vacuous case of no eligible units at all - the caller then reissues
     * the ferry command as-is), false otherwise (`outAnchor` now holds the
     * averaged anchor/position for the caller to snap to the terrain
     * surface).
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x008216BD), from the `RULEUCC_Ferry`
     * command-capability arm.
     */
    [[nodiscard]] bool ResolveGroupFerryAnchorOrDetectFerry(
      WeakSet<UserEntity>& selection,
      Wm3::Vector3f& outAnchor
    )
    {

      std::int32_t eligibleCount = 0;
      bool allFerrying = true;

      for (UserEntity* const entity : selection) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (UserCommandQueue* const manager = userUnit->GetCommandQueue(); manager != nullptr) {
            IUnit* const iunit = GetIUnitBridge(userUnit);
            if (iunit != nullptr && !iunit->IsDead() && !iunit->DestroyQueued()) {
              ++eligibleCount;

              UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
              if (lastHelper != nullptr) {
                const Wm3::Vector3f anchor = ResolveCommandGraphAnchorWorldPosition(*lastHelper);
                outAnchor.x += anchor.x;
                outAnchor.y += anchor.y;
                outAnchor.z += anchor.z;

                if (ResolveCommandIssueHelperCommandType(*lastHelper) != EUnitCommandType::UNITCOMMAND_Ferry) {
                  allFerrying = false;
                }
              } else {
                const Wm3::Vec3f& position = iunit->GetPosition();
                outAnchor.x += position.x;
                outAnchor.y += position.y;
                outAnchor.z += position.z;
                allFerrying = false;
              }
            }
          }
        }
      }

      if (eligibleCount > 0) {
        const float invCount = 1.0f / static_cast<float>(eligibleCount);
        outAnchor.x *= invCount;
        outAnchor.y *= invCount;
        outAnchor.z *= invCount;
      }

      return allFerrying;
    }

    /**
     * Address: 0x0081E4E0 (FUN_0081E4E0)
     *
     * IDA signature:
     * int __usercall sub_81E4E0@<eax>(Moho::WeakSet_UserEntity *eax0@<eax>, Wm3::Vector3f a2, int a3);
     *
     * What it does:
     * Returns the already-queued command-issue helper (if any) whose
     * blueprint pointer exactly matches `candidateBlueprint` AND whose own
     * command-graph anchor world position snaps to the same footprint cell
     * as `dragPosition` - i.e. detects "about to queue a second build order
     * for the same structure at the same spot". Only runs when the
     * selection holds exactly one live, eligible `UserUnit` (`IsUserUnit`,
     * has a command queue, not dead, not destroy-queued); returns null for
     * every other case, including a selection with zero or more than one
     * entity.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00821E8A), from the
     * `COMMOD_Build`/`COMMOD_BuildAnchored` arm: when the drag position is
     * not a legal build spot, the existing colocated order is decremented
     * (`ISSUE_DecreaseCommandCount`) instead of a duplicate being stacked.
     */
    [[nodiscard]] UserCommandIssueHelper* FindColocatedQueuedBuildOrder(
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragPosition,
      const REntityBlueprint* const candidateBlueprint
    )
    {
      if (selection.Size() != 1) {
        return nullptr;
      }

      UserEntity* const entity = *selection.begin();
      UserUnit* const userUnit = entity->IsUserUnit();
      if (userUnit == nullptr) {
        return nullptr;
      }

      UserCommandQueue* const manager = userUnit->GetCommandQueue();
      if (manager == nullptr) {
        return nullptr;
      }

      IUnit* const iunit = GetIUnitBridge(userUnit);
      if (iunit == nullptr || iunit->IsDead() || iunit->DestroyQueued()) {
        return nullptr;
      }

      return FindColocatedQueuedBuildOrderInManager(manager, dragPosition, candidateBlueprint);
    }

    /**
     * Address: 0x0081E610 (FUN_0081E610)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__usercall sub_81E610@<eax>(
     *     int a1@<eax>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3, Moho::WeakSet_UserEntity *a4);
     *
     * What it does:
     * Splits the live entities of `source` into `rallyPointSet` (entities
     * in the "RALLYPOINT" category) and `otherSet` (everything else). The
     * binary inlines the same category-bitset test
     * `Moho::UserEntity::IsInCategory` (0x008B97C0) already performs -
     * verified field-for-field against that recovered body - so this calls
     * it directly per entity rather than re-inlining the raw bitset index
     * math. `a1` (the binary's category-lookup-resolver source) is not a
     * separate parameter here: `IsInCategory` resolves it from the
     * entity's own `mSession`, which is always the same session this
     * selection belongs to. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), called three times - from the
     * `RULEUCC_Move` (0x0082069A), `RULEUCC_Patrol` (0x0082095E) and
     * `RULEUCC_CallTransport` (0x00820F49) arms - to split the current
     * selection ahead of a rally-point-aware factory command.
     */
    void SplitSelectionByRallyPointCategory(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& rallyPointSet,
      WeakSet<UserEntity>& otherSet
    )
    {
      const msvc8::string rallyPointCategory("RALLYPOINT");


      for (UserEntity* const entity : source) {
        if (entity->IsInCategory(rallyPointCategory)) {
          (void)rallyPointSet.Add(entity);
        } else {
          (void)otherSet.Add(entity);
        }
      }
    }

    /**
     * Address: 0x0081E700 (FUN_0081E700)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E700(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live, mobile (`IUnit::IsMobile()`), `UserUnit` entities of
     * `source` for a ferry-command drag: units in the "TRANSPORTATION"
     * category that are also "AIR" or "AIRSTAGINGPLATFORM" go into
     * `airTransportSet` (the candidate ferriers); every other mobile unit
     * that is in the "LAND" category goes into `landUnitSet` (the
     * candidate passengers). Non-mobile units, non-`UserUnit` entities, and
     * mobile units that are neither an eligible air transport nor LAND are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below), from the `RULEUCC_Ferry` arm
     * (0x0082162F) - `airTransportSet` becomes the selection fed into
     * `ResolveGroupFerryAnchorOrDetectFerry` immediately afterward - and from
     * the `RULEUCC_Transport` arm's no-extra-selection branch (0x008213D6).
     */
    void SplitSelectionForFerryCommand(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& airTransportSet,
      WeakSet<UserEntity>& landUnitSet
    )
    {
      const msvc8::string transportationCategory("TRANSPORTATION");
      const msvc8::string airCategory("AIR");
      const msvc8::string airStagingCategory("AIRSTAGINGPLATFORM");
      const msvc8::string landCategory("LAND");

      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;
        IUnit* const iunit = GetIUnitBridge(userUnit);

        if (userUnit != nullptr && iunit != nullptr && iunit->IsMobile()) {
          const bool isAirTransport = entity->IsInCategory(transportationCategory) &&
            (entity->IsInCategory(airCategory) || entity->IsInCategory(airStagingCategory));

          if (isAirTransport) {
            (void)airTransportSet.Add(entity);
          } else if (entity->IsInCategory(landCategory)) {
            (void)landUnitSet.Add(entity);
          }
        }
      }
    }

    /**
     * Address: 0x0081E9E0 (FUN_0081E9E0)
     *
     * IDA signature:
     * std::map_uint_WeakPtr_UserEntity::_Node *__cdecl sub_81E9E0(
     *     Moho::WeakSet_UserEntity *a1, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` by the "REBUILDER"
     * category: units in that category go into `rebuilderSet`, every other
     * `UserUnit` goes into `nonRebuilderSet`. Non-`UserUnit` entities are
     * left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x00820222), splitting the selection
     * ahead of issuing a guard-style command at a hovered "STRUCTURE"
     * target - `nonRebuilderSet` is issued the command immediately after
     * with the hovered entity as its direct target, `rebuilderSet` gets the
     * same command aimed at the structure's world position instead.
     */
    void SplitSelectionByRebuilderCategory(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& nonRebuilderSet,
      WeakSet<UserEntity>& rebuilderSet
    )
    {
      const msvc8::string rebuilderCategory("REBUILDER");

      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          if (userUnit->IsInCategory(rebuilderCategory)) {
            (void)rebuilderSet.Add(entity);
          } else {
            (void)nonRebuilderSet.Add(entity);
          }
        }
      }
    }

    /**
     * Address: 0x0081EB20 (FUN_0081EB20)
     *
     * IDA signature:
     * _Iterator_base **__usercall sub_81EB20@<eax>(
     *     Moho::WeakSet_UserEntity *a1@<ebx>, Moho::WeakSet_UserEntity *a2, Moho::WeakSet_UserEntity *a3);
     *
     * What it does:
     * Splits the live `UserUnit` entities of `source` for an attack-move-
     * to-ground drag: units that are both mobile (`IUnit::IsMobile()`) and
     * set to `FIRESTATE_ReturnFire` go into `aggressiveMoveSet` (eligible
     * for AggressiveMove); every other live `UserUnit` (immobile, or on a
     * different fire state) goes into `otherSet`. Non-`UserUnit` entities
     * are left out of both sets. The binary's own return value is raw
     * find-iterator debris from the last loop step; no caller inspects it.
     *
     * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
     * (0x0081FCD0, recovered below, 0x0081FF48), from the `RULEUCC_Attack`
     * no-hover ground-target arm: `aggressiveMoveSet` is issued
     * `UNITCOMMAND_AggressiveMove` immediately afterward when non-empty.
     */
    void SplitSelectionForAggressiveMove(
      WeakSet<UserEntity>& source,
      WeakSet<UserEntity>& aggressiveMoveSet,
      WeakSet<UserEntity>& otherSet
    )
    {
      for (UserEntity* const entity : source) {
        UserUnit* const userUnit = entity != nullptr ? entity->IsUserUnit() : nullptr;

        if (userUnit != nullptr) {
          IUnit* const iunit = GetIUnitBridge(userUnit);
          const bool eligible = iunit != nullptr && iunit->IsMobile() &&
            userUnit->mUnitVarDat.mFireState == FIRESTATE_ReturnFire;

          if (eligible) {
            (void)aggressiveMoveSet.Add(entity);
          } else {
            (void)otherSet.Add(entity);
          }
        }
      }
    }

    [[nodiscard]] bool
    AreEntitySetsEqual(const msvc8::vector<UserEntity*>& lhs, const msvc8::vector<UserEntity*>& rhs)
    {
      if (lhs.size() != rhs.size()) {
        return false;
      }

      for (const UserEntity* const entity : lhs) {
        if (!ContainsEntityPtr(rhs, entity)) {
          return false;
        }
      }

      return true;
    }

    void BuildSelectionSyncMask(const WeakSet<UserEntity>& selection, SSyncFilterMaskBlock& outMask)
    {
      BVIntSet selectionIds{};
      for (UserEntity* const entity : selection) {
        if (entity->IsUserUnit() != nullptr) {
          (void)selectionIds.Add(static_cast<unsigned int>(entity->mParams.mEntityId));
        }
      }

      outMask = selectionIds;
    }

    // `UserTarget` (UserTarget.h) is what the three padded "anchor" views that
    // used to live here described: `{kind, weak entity link, position}` at
    // +0x00/+0x04/+0x0C is `UserTarget` member for member, the "history" was
    // the whole `UserCommandIssueHelper` (its local event queue at +0xB8, the
    // replicated entity ids at +0x40 and target at +0x5C), and a "history
    // entry" was one `UserCommandIssueLocalEvent`.

    /**
     * Address: 0x008BEC40 (FUN_008BEC40)
     *
     * What it does:
     * Converts one replicated command target (`SSTITarget`: kind, entity id,
     * ground position) into the UI-side `UserTarget`. An entity target is
     * resolved through the active session's entity map (the id is the one
     * dword at +0x04, 0x008BEC5F) and linked weakly; a ground target copies
     * its position, which sits at +0x08 in the source and +0x0C in the
     * destination (0x008BEC94..0x008BECAA). Any other kind sets only the kind.
     */
    [[nodiscard]] UserTarget MakeUserTargetFromSSTITarget(const SSTITarget& source)
    {
      UserTarget target{};
      target.targetType = static_cast<UserTargetType>(source.mType);

      if (target.targetType == UserTargetType::Entity) {
        UserEntity* entity = nullptr;
        if (CWldSession* const activeSession = moho::WLD_GetActiveSession(); activeSession != nullptr) {
          entity = activeSession->LookupEntityId(static_cast<moho::EntId>(source.mEnt));
        }
        target.targetEntity.ResetFromObject(entity);
      } else if (target.targetType == UserTargetType::Position) {
        target.position = source.mPos;
      }

      return target;
    }

    /**
     * Address: 0x008B4080 (FUN_008B4080)
     * Address: 0x008B40F0 (FUN_008B40F0 -- `UserTarget`'s implicit copy
     * constructor: the kind, the `targetEntity` weak link re-linked at its
     * owner's chain head, the position. Returned out of here for the event's
     * target, and run per event by `UserCommandIssueLocalEvent`'s own copy
     * constructor 0x008B56F0.)
     * Address: 0x0081D010 (FUN_0081D010 -- `UserTarget`'s implicit destructor:
     * `targetEntity`'s unlink from its owner chain, without clearing the two
     * link words. Every transient `UserTarget` below dies through it.)
     *
     * What it does:
     * The helper's current target: the newest unconfirmed `SetTarget` edit in
     * `mLocalQueue`, walked from the back (block size 1, so the map slot is
     * `off + i`, less `_Mapsize` once it wraps), else the replicated
     * `mVariableData.mTarget1`. An empty queue goes straight to the fallback,
     * which is how a command with no local edits gets its sim-side target.
     */
    [[nodiscard]] UserTarget ResolveCommandIssueTarget(const UserCommandIssueHelper& helper)
    {
      for (std::size_t index = helper.mLocalQueue.size(); index != 0u; --index) {
        const UserCommandIssueLocalEvent& event = helper.mLocalQueue[index - 1u];
        if (event.mType == ECommandIssueEvent::SetTarget) {
          return event.mTarget;
        }
      }

      return MakeUserTargetFromSSTITarget(helper.mVariableData.mTarget1);
    }

    /**
     * Address: 0x00824550 (FUN_00824550, sub_824550)
     *
     * Misclassified `external_dependency` by an earlier automated pass (its
     * sole callee `sub_8B4080` walks the helper's own event queue, not
     * external runtime state).
     *
     * What it does:
     * The live entity the helper's current target names, or null for a
     * ground target or an entity that has gone away. The transient target is
     * released before returning. Callers: `func_ProcessCommandDrag`
     * (0x00829B40) and `EstimateDrawNodeWorkTicks` (0x00826F10).
     */
    [[nodiscard]] UserEntity* ResolveCommandTargetEntity(const UserCommandIssueHelper& helper)
    {
      const UserTarget target = ResolveCommandIssueTarget(helper);
      return target.targetType == UserTargetType::Entity ? target.targetEntity.GetObjectPtr() : nullptr;
    }

    /**
     * Address: 0x008B4300 (FUN_008B4300, sub_8B4300)
     *
     * What it does:
     * Whether `candidateUnit` belongs to the helper's command, reading the
     * unconfirmed local edits first: walking `mLocalQueue` from the back, the
     * newest `SelectUnit` edit that lists the unit answers `true` and the
     * newest `DeselectUnit` edit that lists it answers `false`
     * (0x008B4346..0x008B439D). With no such edit it answers whether the unit's
     * entity id is in the replicated `mVariableData.mEntIds` (0x008B43B7..).
     *
     * The per-event lookup is `WeakSet<UserUnit>::find(candidateUnit)` over the
     * event's `mUnits` (`WeakSet<UserUnit>::Find`, 0x0082CEA0, which takes the
     * unit in `eax` from the second stack argument at 0x008B4363/0x008B438D and
     * runs the set's `find` 0x0082E560 on it). It used to be keyed with the dword at
     * `helper+0xB8` instead -- the local queue's own first word, read through
     * a padded view -- so no local select/deselect edit ever matched and every
     * answer came from the replicated id list.
     *
     */
    [[nodiscard]] bool IsCandidateExcludedByCachedRelation(
      const UserCommandIssueHelper& helper, UserUnit* const candidateUnit
    ) noexcept
    {
      for (std::size_t index = helper.mLocalQueue.size(); index != 0u; --index) {
        const UserCommandIssueLocalEvent& event = helper.mLocalQueue[index - 1u];
        if (event.mType != ECommandIssueEvent::SelectUnit && event.mType != ECommandIssueEvent::DeselectUnit) {
          continue;
        }

        // 0x008B4370/0x008B439A: the binary runs this lookup twice for a
        // `SelectUnit` edit (an early "listed" exit, then the shared gate);
        // nothing observable happens in between, so it is computed once.
        const bool listed = event.mUnits.Find(candidateUnit) != event.mUnits.end();
        if (!listed) {
          continue;
        }
        return event.mType == ECommandIssueEvent::SelectUnit;
      }

      for (const EntId entityId : helper.mVariableData.mEntIds) {
        if (entityId == candidateUnit->mParams.mEntityId) {
          return true;
        }
      }
      return false;
    }

  } // namespace

  /**
   * Ten sim ticks a second - the rate both order-graph estimators below convert
   * their real-time answer into the tick numbers `ResolveDrawNodeCompletionTick`
   * propagates. Folded into 0x00826C50 and 0x00826F10 as the literal 10.0f at
   * `ds:dword_DFF31C`.
   */
  constexpr float kCommandGraphTicksPerSecond = 10.0f;

  /**
   * Address: 0x00826C50 (FUN_00826C50, sub_826C50)
   *
   * IDA signature:
   * int __stdcall sub_826C50(Moho::UICommandGraph::CommandGraphEdge *edge);
   *
   * What it does: see the declaration above `RebuildCommandQueueNodes`.
   *
   * The edge takes its command from the order it leads *to*, not the one it
   * leaves: 0x00826C79 pins `esi` to `edge+0x0C` (`mToNode`) and every later
   * `[esi+4]` reads that node's helper head.
   *
   * The successor step inside the walk is the `map<EntId, WeakPtr<UserEntity>>`
   * `_Inc` emission at 0x007B4D90 (carried on `msvc8::detail::rb_increment`).
   * It is spelled with this file's `WeakSet<UserEntity>::Iterator_inc`
   * shape, which is the same body over the same node type and matches the
   * binary's `_Node**` out-parameter call at 0x00826DE8.
   */
  std::int32_t EstimateEdgeTravelTicks(const UICommandGraph::CommandGraphEdge& edge)
  {
    // Both endpoints accumulate a position *sum* plus a weight so several units
    // sharing one queue average into a single anchor; each side divides by its
    // own weight before the separation is taken.
    const Wm3::Vector3f fromCentroid = DrawNodeCentroid(*edge.mFromNode);
    const Wm3::Vector3f toCentroid = DrawNodeCentroid(*edge.mToNode);

    const float deltaX = fromCentroid.x - toCentroid.x;
    const float deltaY = fromCentroid.y - toCentroid.y;
    const float deltaZ = fromCentroid.z - toCentroid.z;
    const float distance = std::sqrt(((deltaX * deltaX) + (deltaY * deltaY)) + (deltaZ * deltaZ));

    // Unguarded exactly as the binary is (0x00826CFB feeds `[esi+4]` straight
    // into the type resolver): an edge only exists because `LinkCommandGraphEdge`
    // published it from two draw nodes that already carry a helper.
    auto* const helper = edge.mToNode->mHelperLink.GetObjectPtr();

    switch (ResolveCommandIssueHelperCommandType(*helper)) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
        break;

      default:
        // Nothing else walks a unit across the map, so it costs no travel time.
        // This is the binary's jump-table default at 0x00826D1A.
        return 0;
    }

    // The walk runs over a copy of the helper's units rather than the live
    // cache: the copy constructor (the set's range constructor 0x00831310)
    // drops the source's dead entries as it reads. The copy's destructor is
    // the erase-range + `operator delete(mHead)` pair at 0x00826E6D/0x00826EC0,
    // which runs on both the answered and the gave-up exit.
    const WeakSet<UserUnit> liveTargets(*ResolveCommandIssueCursorEntities(*helper));

    float slowestSpeed = std::numeric_limits<float>::max();
    for (UserUnit* const unit : liveTargets) {
      // Air units are held to their airspeed and everything else to its ground
      // speed. A unit with no positive speed of either kind is skipped rather
      // than making the whole orderline infinitely slow.
      const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();
      const float unitSpeed =
        (blueprint->Air.CanFly != 0u) ? blueprint->Air.MaxAirspeed : blueprint->Physics.MaxSpeed;
      if (unitSpeed > 0.0f && slowestSpeed > unitSpeed) {
        slowestSpeed = unitSpeed;
      }
    }

    // A set with nothing movable in it leaves the seed untouched, and the
    // binary re-tests both ends of the range before dividing by it.
    if (slowestSpeed >= std::numeric_limits<float>::max() || slowestSpeed <= 0.0f) {
      return 0;
    }

    // Rounded up: the binary spells the ceiling as `(int)rint(t) + (t > rint(t))`
    // (0x00826E4C..0x00826E5F), which agrees with `ceil` on every finite value
    // because the correction only fires when round-to-nearest went down.
    return static_cast<std::int32_t>(
      std::ceil((distance * kCommandGraphTicksPerSecond) / slowestSpeed)
    );
  }

  /**
   * Address: 0x00829B40 (FUN_00829B40, func_ProcessCommandDrag)
     *
     * What it does:
     * The click-and-drag command redirect keystone both `UICommandDragger::
     * DragMove` and `DragRelease` (UiRuntimeTypes.h/.cpp) funnel into. Looks
     * the dragged command's live helper up by id; if the mouse position is
     * invalid or the command isn't found, does nothing. Otherwise updates
     * (or creates) the command's `mMapAB0` draw-node with the current mouse
     * position (keyed by the helper's own pointer identity - see
     * `sub_82C2E0`'s asm), and, for a factory-build command
     * (`ResolveCommandIssueHelperCommandType == 8`) whose draw node was
     * already resolved, re-validates build placement via
     * `USERUNIT_CanBeBuiltAt` and updates the node's visibility flag
     * (honoring `CWldSession::mShowInvalidBuildPlacementPreview`'s
     * override). On release, unless the drag just ended over an invalid
     * build placement, dispatches the new target: when the command already
     * follows a live cached target entity
     * (`ResolveCommandTargetEntity`), searches nearby
     * collected entities for the closest live unit sharing the cached
     * target's army and not excluded by `IsCandidateExcludedByCachedRelation`,
     * and issues that entity as the new target; otherwise, for a live
     * factory-build command, snaps to the blueprint's resolved-footprint
     * world position; otherwise clamps the raw mouse position to the map's
     * playable rect and issues that as a `Position` target. All three paths
     * converge on `Moho::ISSUE_SetCommandTarget`.
     */
    void ProcessCommandDrag(
      const Wm3::Vector3f& mouse, UICommandGraph& graph, const CmdId cmdId, const bool released
    )
    {
      CommandManager* const commandManager = graph.mSession->mCommandManager;

      UserCommandIssueHelper* helper = nullptr;
      if (const auto found = commandManager->mCommands.find(cmdId); found != commandManager->mCommands.end()) {
        helper = found->second;
      }
      if (helper == nullptr) {
        return;
      }

      if (!IsValidVector3f(mouse)) {
        return;
      }

      // mMapAB0's draw-node hash is keyed by the helper's own pointer
      // identity, not its command id (0x0082C2E3: sub_82C2E0 dereferences
      // its "key" arg once via [esi]; this function's own call passes
      // &result where result held the helper pointer's raw value).
      const auto drawNodeKey = reinterpret_cast<std::uint32_t>(helper);

      bool suppressDispatch = false;
      if (UICommandGraph::CountHashListNode88(graph.mMapAB0, drawNodeKey) != 0) {
        UICommandGraph::UICommandGraphDrawNode* const drawNode =
          UICommandGraph::FindOrInsertCommandGraphDrawNode(drawNodeKey, graph.mMapAB0);

        drawNode->mPositionSum = mouse;
        drawNode->mWeight = 1.0f;

        if (drawNode->mHasResolvedPosition != 0 &&
            ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8)) {
          if (const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
              genericBlueprint != nullptr) {
            // 0x00829C48..0x00829C4D is a plain virtual dispatch through slot
            // 5 of the blueprint's own vtable - `REntityBlueprint::
            // IsUnitBlueprint` - not a reflection upcast.
            if (const RUnitBlueprint* const unitBlueprint = genericBlueprint->IsUnitBlueprint();
                unitBlueprint != nullptr) {
              const float inverseWeight = 1.0f / drawNode->mWeight;
              const SCoordsVec2 buildCenter{
                drawNode->mPositionSum.x * inverseWeight, drawNode->mPositionSum.z * inverseWeight
              };
              SOccupationResult buildInfo{};
              const bool canBuild = USERUNIT_CanBeBuiltAt(
                *graph.mSession, unitBlueprint, buildCenter, false, &buildInfo,
                reinterpret_cast<const UserCommand*>(helper)
              );
              drawNode->mIsVisible = (canBuild || !graph.mSession->mShowInvalidBuildPlacementPreview) ? 1u : 0u;
            }
          }
        }

        const bool wasInvalidPlacement = (drawNode->mIsVisible == 0);
        drawNode->mHasResolvedPosition = released ? 0u : 1u;
        if (wasInvalidPlacement && released) {
          suppressDispatch = true;
        }
      }

      if (!released || suppressDispatch) {
        return;
      }

      // The playable-rect clamp runs once, here, ahead of all three dispatch
      // arms - 0x00829CF4..0x00829D7D sits between the `released` gate and
      // the cached-target search, and every later read (the distance loop's
      // `var_200`/`result`, the factory arm's `ToCellPos` input, and the
      // default arm's position target) is of the clamped vector, never of the
      // raw mouse. Clamping only inside the default arm let the other two
      // arms act on an off-map cursor.
      const STIMap* const map = graph.mSession->mWldMap->mTerrainRes->mMap;
      Wm3::Vector3f clampedPos = mouse;
      clampedPos.x = std::clamp(
        clampedPos.x, static_cast<float>(map->mPlayableRect.x0 + 1), static_cast<float>(map->mPlayableRect.x1 - 1)
      );
      clampedPos.z = std::clamp(
        clampedPos.z, static_cast<float>(map->mPlayableRect.z0 + 1), static_cast<float>(map->mPlayableRect.z1 - 1)
      );

      if (UserEntity* const cachedTargetEntity = ResolveCommandTargetEntity(*helper);
          cachedTargetEntity != nullptr) {
        // Cached-target reacquire: search nearby collected entities for the
        // closest live unit sharing the cached target's army.
        gpg::fastvector<UserEntity*> candidates{};
        auto* const spatialDb = graph.mSession->GetEntitySpatialDbStorage();
        (void)spatialDb->Collect(candidates, ENTITYTYPE_Unit);

        UserEntity* closest = nullptr;
        float closestDistanceSq = gpg::pInf;
        for (UserEntity* const candidate : candidates) {
          if (candidate == nullptr || candidate->IsBeingBuilt()) {
            continue;
          }

          if (UserUnit* const candidateUnit = candidate->IsUserUnit(); candidateUnit != nullptr) {
            if (IsCandidateExcludedByCachedRelation(*helper, candidateUnit)) {
              continue;
            }
          }

          if (candidate->mArmy != cachedTargetEntity->mArmy) {
            continue;
          }

          const Wm3::Vec3f& candidatePos = candidate->mVariableData.mCurTransform.pos_;
          const float deltaX = clampedPos.x - candidatePos.x;
          const float deltaZ = clampedPos.z - candidatePos.z;
          const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
          if (distanceSq < closestDistanceSq) {
            closestDistanceSq = distanceSq;
            closest = candidate;
          }
        }

        if (closest != nullptr) {
          const UserTarget entityTarget(closest);
          ISSUE_SetCommandTarget(helper, entityTarget);
        }
        return;
      }

      const REntityBlueprint* const genericBlueprint = helper->mConstantData.blueprint;
      if (ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(8) &&
          genericBlueprint != nullptr) {
        // Factory-build command: re-snap the dropped cursor onto the
        // blueprint's own footprint grid.
        //
        // 0x00829F0D..0x00829F40 copies the sixteen bytes at
        // `REntityBlueprint+0xD8` - the blueprint's inline `mFootprint` - into
        // a stack `SFootprint`; there is no reflection upcast and no
        // `Physics.ResolvedFootprint` indirection anywhere in this arm. The
        // upcast-and-deref version this replaces dropped the whole drag
        // silently whenever either step yielded null, so a queued building
        // could not be moved at all.
        const SFootprint& footprint = genericBlueprint->mFootprint;
        const SOCellPos cell = footprint.ToCellPos(clampedPos);

        // 0x00829F5E calls the `(STIMap const*, SOCellPos const&, SFootprint
        // const&)` overload, which re-centres the origin cell over the *full*
        // footprint (`cell + size/2`). Passing `1, 1` instead re-centred every
        // structure as if it were one cell across, displacing the re-issued
        // build position by `((1 - sizeX) / 2, (1 - sizeZ) / 2)` - i.e. toward
        // -X/-Z, up and to the left on screen, by a whole cell for a 3-cell
        // footprint - so the dropped order and its green placement ghost
        // landed off the structure they belonged to.
        const Wm3::Vector3f worldPos = COORDS_ToWorldPos(map, cell, footprint);

        UserTarget positionTarget{};
        positionTarget.targetType = UserTargetType::Position;
        positionTarget.position = worldPos;
        ISSUE_SetCommandTarget(helper, positionTarget);
        return;
      }

      // Default: issue the clamped cursor position as a `Position` target.
      UserTarget positionTarget{};
      positionTarget.targetType = UserTargetType::Position;
      positionTarget.position = clampedPos;
      ISSUE_SetCommandTarget(helper, positionTarget);
    }

  namespace
  {
    /**
     * Address: 0x0081CFD0 (FUN_0081CFD0)
     *
     * What it does:
     * The world position of the helper's current target
     * (`ResolveCommandIssueTarget`, then `ResolvePositionFromTarget`,
     * 0x008BED50): the named entity's position, the ground position, or the
     * invalid vector. The transient target is released on the way out.
     */
    [[nodiscard]] Wm3::Vector3f* ResolveCommandIssueTargetPosition(
      Wm3::Vector3f* const outPosition, const UserCommandIssueHelper& helper
    )
    {
      if (outPosition == nullptr) {
        return nullptr;
      }

      *outPosition = ResolvePositionFromTarget(ResolveCommandIssueTarget(helper));
      return outPosition;
    }

    /**
     * Address: 0x00824500 (FUN_00824500, sub_824500)
     *
     * IDA signature:
     * Moho::UserEntity *__usercall sub_824500@<eax>(Moho::UserUnit *unit@<eax>);
     *
     * What it does:
     * Resolves the entity `unit` is currently focused on (building, repairing,
     * assisting): reads the replicated focus id at `unit+0x210` --
     * `mUnitVarDat` (+0x198) `.mFocusUnit` (+0x78) -- and looks it up in the
     * active session's entity map (0x00898DC0), null when absent. The only
     * caller, `EstimateDrawNodeWorkTicks` (0x008270DA), passes the assisting
     * unit in `eax`; it was typed here as an anonymous "command owner" with a
     * padded overlay over the +0x210 dword.
     */
    [[nodiscard]] UserEntity* ResolveUnitFocusEntity(const UserUnit* const unit)
    {
      CWldSession* const session = moho::WLD_GetSession();
      if (unit == nullptr || session == nullptr) {
        return nullptr;
      }

      return session->LookupEntityId(unit->mUnitVarDat.mFocusUnit);
    }

    void CollectSessionUserUnits(CWldSession* const session, msvc8::vector<UserUnit*>& outUnits)
    {
      outUnits.clear();
      if (session == nullptr) {
        return;
      }

      for (const auto& [entityId, entity] : session->mEntities) {
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr) {
          continue;
        }

        AppendUnitUnique(outUnits, unit);
      }
    }

    [[nodiscard]] bool ApplyTerrainPlayableRect(IWldTerrainRes* const terrainRes, const gpg::Rect2i& playableRect)
    {
      if (terrainRes == nullptr) {
        return false;
      }
      return terrainRes->SetPlayableMapRect(VisibilityRect::FromRect2i(playableRect));
    }

    /**
     * Address: 0x0089A970 (FUN_0089A970) allocation path (FUN_0089A970) for insert-node creation.
     *
     * Source-side typed helper used to keep node allocation/layout explicit.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* AllocateSaveDataMapNode()
    {
      auto* const raw = ::operator new(sizeof(SSessionSaveNodeMapNode));
      auto* const node = new (raw) SSessionSaveNodeMapNode{};
      node->mColor = 0u;
      node->mIsSentinel = 0u;
      return node;
    }

    /**
     * Address: 0x0089AC40 (FUN_0089AC40) cleanup chain (FUN_008971A0 -> FUN_0089AC40 call path).
     */
    void DestroySaveDataMapNode(SSessionSaveNodeMapNode* const node)
    {
      if (!node) {
        return;
      }

      node->~SSessionSaveNodeMapNode();
      ::operator delete(node);
    }

    /**
     * Address: 0x0089A930 (FUN_0089A930) sentinel header-node allocation/init path.
     */
    [[nodiscard]] SSessionSaveNodeMapNode* CreateSaveDataMapHead()
    {
      SSessionSaveNodeMapNode* const head = AllocateSaveDataMapNode();
      head->mColor = 1u;
      head->mIsSentinel = 1u;
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      return head;
    }

    /**
     * Address: 0x00897140 (FUN_00897140)
     *
     * What it does:
     * Initializes one session save-node map header lane (sentinel self-links)
     * and clears entry count.
     */
    SSessionSaveNodeMap* InitializeSessionSaveNodeMapHeader(
      SSessionSaveNodeMap* const outMap
    )
    {
      SSessionSaveNodeMapNode* const head = CreateSaveDataMapHead();
      outMap->mHead = head;
      head->mIsSentinel = 1u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      outMap->mSize = 0u;
      return outMap;
    }

    /**
     * Address: 0x0089A8E0 (FUN_0089A8E0).
     */
    void RotateSaveDataLeft(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mRight;
      node->mRight = pivot->mLeft;
      if (!IsSentinelNode(pivot->mLeft)) {
        pivot->mLeft->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mLeft) {
        node->mParent->mLeft = pivot;
      } else {
        node->mParent->mRight = pivot;
      }

      pivot->mLeft = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x0089A880 (FUN_0089A880).
     */
    void RotateSaveDataRight(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* const node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* const pivot = node->mLeft;
      node->mLeft = pivot->mRight;
      if (!IsSentinelNode(pivot->mRight)) {
        pivot->mRight->mParent = node;
      }

      pivot->mParent = node->mParent;
      if (node == head->mParent) {
        head->mParent = pivot;
      } else if (node == node->mParent->mRight) {
        node->mParent->mRight = pivot;
      } else {
        node->mParent->mLeft = pivot;
      }

      pivot->mRight = node;
      node->mParent = pivot;
    }

    /**
     * Address: 0x00899DC0 (FUN_00899DC0) RB-tree insert rebalance sequence.
     *
     * Source-side typed split of the original monolithic helper body.
     */
    void FixupSaveDataInsert(SSessionSaveNodeMap& map, SSessionSaveNodeMapNode* node)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      while (node->mParent->mColor == 0u) {
        SSessionSaveNodeMapNode* const parent = node->mParent;
        SSessionSaveNodeMapNode* const grand = parent->mParent;
        if (parent == grand->mLeft) {
          SSessionSaveNodeMapNode* const uncle = grand->mRight;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mRight) {
              node = parent;
              RotateSaveDataLeft(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataRight(map, node->mParent->mParent);
          }
        } else {
          SSessionSaveNodeMapNode* const uncle = grand->mLeft;
          if (uncle->mColor == 0u) {
            parent->mColor = 1u;
            uncle->mColor = 1u;
            grand->mColor = 0u;
            node = grand;
          } else {
            if (node == parent->mLeft) {
              node = parent;
              RotateSaveDataRight(map, node);
            }
            node->mParent->mColor = 1u;
            node->mParent->mParent->mColor = 0u;
            RotateSaveDataLeft(map, node->mParent->mParent);
          }
        }
      }

      head->mParent->mColor = 1u;
    }

    /**
      * Alias of FUN_008992D0 (non-canonical helper lane).
     * (FUN_008992D0 -> FUN_00899DC0 -> FUN_0089A970 chain).
     *
     * Source-side typed split around search/insert/fixup stages.
     */
    void InsertSaveDataLabelNode(SSessionSaveNodeMap& map, const SSessionSaveNodeLabel& label)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      SSessionSaveNodeMapNode* parent = head;
      SSessionSaveNodeMapNode* current = head->mParent;
      bool insertLeft = true;

      while (!IsSentinelNode(current)) {
        parent = current;
        insertLeft = (label.mCommandSourceId < current->mLabel.mCommandSourceId);
        current = insertLeft ? current->mLeft : current->mRight;
      }

      SSessionSaveNodeMapNode* const node = AllocateSaveDataMapNode();
      node->mLabel.mCommandSourceId = label.mCommandSourceId;
      node->mLabel.mSaveNodeName = label.mSaveNodeName;
      node->mLeft = head;
      node->mRight = head;
      node->mParent = parent;

      ++map.mSize;
      if (parent == head) {
        head->mParent = node;
        head->mLeft = node;
        head->mRight = node;
      } else if (insertLeft) {
        parent->mLeft = node;
        if (parent == head->mLeft) {
          head->mLeft = node;
        }
      } else {
        parent->mRight = node;
        if (parent == head->mRight) {
          head->mRight = node;
        }
      }

      FixupSaveDataInsert(map, node);
    }

    /**
      * Alias of FUN_008971A0 (non-canonical helper lane).
     *
     * Source-side typed cleanup helper equivalent.
     */
    void DestroySaveDataSubtree(SSessionSaveNodeMapNode* const node, SSessionSaveNodeMapNode* const head)
    {
      if (!node || node == head || node->mIsSentinel != 0u) {
        return;
      }

      DestroySaveDataSubtree(node->mLeft, head);
      DestroySaveDataSubtree(node->mRight, head);
      DestroySaveDataMapNode(node);
    }

    /**
      * Alias of FUN_008971A0 (non-canonical helper lane).
     */
    void ClearSaveDataMap(SSessionSaveNodeMap& map)
    {
      SSessionSaveNodeMapNode* const head = map.mHead;
      if (!head) {
        map.mSize = 0u;
        return;
      }

      DestroySaveDataSubtree(head->mParent, head);
      head->mLeft = head;
      head->mParent = head;
      head->mRight = head;
      map.mSize = 0u;
    }

    [[nodiscard]] ECommandMode DefaultModeFromDrag(const std::int32_t dragWord) noexcept
    {
      const std::uint32_t dragMask = static_cast<std::uint32_t>(dragWord) & 0xFF000000u;
      return (dragMask != 0xFF000000u) ? COMMOD_Reclaim : COMMOD_Move;
    }

    // ===================================================================
    // Right-mouse-button command resolution helpers (FUN_0081EC00 family)
    // ===================================================================
    //
    // These file-static helpers back the global right-click dispatcher
    // `func_GetRightMouseButtonAction` (FUN_0081EC00). They are only ever
    // called from that dispatcher inside this translation unit, so they stay
    // in this anonymous namespace next to the selection-iteration helpers they
    // reuse (DecodeSelectedUserEntity / ResolveIUnitBridge / IsSentinelNode).

    // The pending command the cursor drags is looked up through the session
    // command manager's own `mCommands` map (`CommandManager::mCommands`,
    // +0xCB4) with `FindCommandIssueHelper` below, and its type is read
    // through `ResolveCommandIssueHelperCommandType` -- see the no-hover arm
    // of `func_GetRightMouseButtonAction`.

    /**
     * Address: 0x0081D080 (FUN_0081D080, sub_81D080)
     *
     * IDA signature:
     * char __cdecl sub_81D080(Moho::UserEntity *a1, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true when the hovered target `hoverEntity` is a live, non-destroy-
     * queued entity that at least one currently selected unit can attack (range-
     * checked). Backs the enemy-hover Attack decision in the right-click
     * dispatcher.
     */
    [[nodiscard]] bool AnySelectedUnitCanAttackHover(UserEntity* const hoverEntity, CWldSession* const session)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }

      if (UserUnit* const hoverUnit = hoverEntity->IsUserUnit(); hoverUnit != nullptr) {
        IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
        if (hoverBridge != nullptr && hoverBridge->DestroyQueued()) { // IUnit subobject slot +0x2C
          return false;
        }
      }

      WeakSet<UserEntity>& selection = session->mSelection;
      for (UserEntity* const selectedEntity : selection) {
        if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit(); selectedUnit != nullptr) {
          if (selectedUnit->CanAttackTarget(hoverEntity, true)) {
            return true;
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0081D280 (FUN_0081D280, func_RightClickWithTransport)
     *
     * IDA signature:
     * char __cdecl func_RightClickWithTransport(Moho::WeakSet_UserEntity *a1, Moho::UserUnit *arg4);
     *
     * What it does:
     * Scans the current selection for any live transporter that may pick up or
     * interact with the hovered entity `hoverEntity`, honoring the transport-
     * eligibility category rules (CANTRANSPORTCOMMANDER / FERRYBEACON / COMMAND
     * / TRANSPORTATION / TELEPORTATION / AIRSTAGINGPLATFORM / CANNOTUSEAIRSTAGING).
     * Returns true on the first eligible transporter. `arg4` is declared
     * `UserUnit*` by the decompiler but only ever used through UserEntity
     * members, so the recovered parameter is typed as the base `UserEntity*`.
     */
    [[nodiscard]] bool SelectionHasTransportForTarget(WeakSet<UserEntity>* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u) {
        return false;
      }
      if (hoverEntity->mVariableData.mLayerMask == static_cast<std::uint32_t>(LAYER_Seabed)) {
        return false;
      }
      if (hoverEntity->IsBeingBuilt()) { // arg4 vtable slot +0x34
        return false;
      }

      for (UserEntity* const selectedEntity : *selection) {
        UserUnit* const transporter = selectedEntity ? selectedEntity->IsUserUnit() : nullptr;
        if (transporter != nullptr) {
          IUnit* const transporterBridge = GetIUnitBridge(transporter);
          if (transporterBridge != nullptr && !transporterBridge->IsDead() // slot +0x28
              && !transporter->IsBeingBuilt()                              // v6 vtable slot +0x34
              && !transporterBridge->DestroyQueued())                      // slot +0x2C
          {
            // Group 1: decide whether to skip this selected unit.
            // CANTRANSPORTCOMMANDER(hover) or FERRYBEACON(hover) -> never a
            // skip; otherwise skip iff the selected unit IS the commander,
            // because a transport not flagged CANTRANSPORTCOMMANDER cannot
            // carry it.
            //
            // The binary spells this as
            //   if (IsInCategory(hover,"CANTRANSPORTCOMMANDER")) goto accept;
            //   if (IsInCategory(hover,"FERRYBEACON")
            //       || (skip = 1, !IsInCategory(selected,"COMMAND"))) { accept: skip = 0; }
            // so `skip` survives as 1 only when the selected unit IS COMMAND.
            bool skip;
            if (hoverEntity->IsInCategory(msvc8::string("CANTRANSPORTCOMMANDER"))) {
              skip = false;
            } else if (hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"))) {
              skip = false;
            } else {
              skip = reinterpret_cast<const UserEntity*>(transporter)->IsInCategory(msvc8::string("COMMAND"));
            }

            if (!skip) {
              // Group 2: does the hovered entity want air transport?
              bool wantsAir;
              if (hoverEntity->IsInCategory(msvc8::string("TRANSPORTATION"))) {
                wantsAir = true;
              } else if (hoverEntity->IsInCategory(msvc8::string("TELEPORTATION"))) {
                wantsAir = true;
              } else {
                wantsAir = hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"));
              }

              if (wantsAir) {
                // Non-flying transporter for an air-transport request -> accept.
                // GetBlueprint() on the transporter IUnit subobject (slot +0x1C),
                // then Air.CanFly (blueprint + 0x368).
                if (transporterBridge->GetBlueprint()->Air.CanFly == 0u) {
                  return true;
                }
              } else if (hoverEntity->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"))) {
                // An air staging platform docks aircraft, so accept only a
                // selected unit that can fly and is not CANNOTUSEAIRSTAGING.
                //
                // Same short-circuit shape as group 1: the binary's
                //   if (!CanFly || (ok = 1, IsInCategory(sel,"CANNOTUSEAIRSTAGING"))) ok = 0;
                //   if (ok) return 1;
                // leaves `ok` set only on the can-fly / not-excluded path.
                if (transporterBridge->GetBlueprint()->Air.CanFly != 0u
                    && !reinterpret_cast<const UserEntity*>(transporter)->IsInCategory(msvc8::string("CANNOTUSEAIRSTAGING"))) {
                  return true;
                }
              }
            }
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0081D660 (FUN_0081D660, func_RightClickTransport)
     *
     * IDA signature:
     * char __usercall func_RightClickTransport@<al>(int a1, Moho::UserEntity *a2@<ecx>);
     *
     * What it does:
     * Scans the current selection for any selected unit that the hovered
     * transporter `hoverEntity` is allowed to carry, honoring the transport
     * category rules (TELEPORTATION / EXPERIMENTAL / TRANSPORTFOCUS /
     * CANTRANSPORTCOMMANDER / COMMAND / TRANSPORTATION / FERRYBEACON /
     * AIRSTAGINGPLATFORM) against the hovered unit's air capability. Returns
     * true on the first accepted selected unit.
     */
    [[nodiscard]] bool HoverTransportAcceptsSelection(WeakSet<UserEntity>* const selection, UserEntity* const hoverEntity)
    {
      if (hoverEntity == nullptr) {
        return false;
      }
      if (hoverEntity->mVariableData.mIsDead != 0u || hoverEntity->IsBeingBuilt()) {
        return false;
      }

      UserUnit* const hoverUnit = hoverEntity->IsUserUnit();
      if (hoverUnit == nullptr) {
        return false;
      }
      IUnit* const hoverBridge = GetIUnitBridge(hoverUnit);
      if (hoverBridge == nullptr) {
        return false;
      }

      for (UserEntity* const candidate : *selection) {
        if (candidate != nullptr) {
          // Group 1: TELEPORTATION(candidate) or EXPERIMENTAL(hover).
          bool teleOrExperimental;
          if (candidate->IsInCategory(msvc8::string("TELEPORTATION"))) {
            teleOrExperimental = true;
          } else {
            teleOrExperimental = reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(msvc8::string("EXPERIMENTAL"));
          }

          if (!teleOrExperimental
              && candidate->mVariableData.mLayerMask != static_cast<std::uint32_t>(LAYER_Seabed)) {
            // Group 2: TRANSPORTFOCUS(candidate).
            if (candidate->IsInCategory(msvc8::string("TRANSPORTFOCUS"))) {
              // Group 3: CANTRANSPORTCOMMANDER(candidate) -> never a skip;
              // otherwise skip iff the hovered unit IS the commander, which a
              // transport without that flag cannot pick up. Same
              // `|| (skip = 1, !cond)` shape as the two groups above.
              bool skip;
              if (candidate->IsInCategory(msvc8::string("CANTRANSPORTCOMMANDER"))) {
                skip = false;
              } else {
                skip = reinterpret_cast<const UserEntity*>(hoverUnit)->IsInCategory(msvc8::string("COMMAND"));
              }

              if (!skip) {
                // Group 4: TRANSPORTATION(candidate) or FERRYBEACON(candidate).
                bool wantsAir;
                if (candidate->IsInCategory(msvc8::string("TRANSPORTATION"))) {
                  wantsAir = true;
                } else {
                  wantsAir = candidate->IsInCategory(msvc8::string("FERRYBEACON"));
                }

                if (wantsAir) {
                  // Non-flying hover unit for an air-transport request -> accept.
                  if (hoverBridge->GetBlueprint()->Air.CanFly == 0u) {
                    return true;
                  }
                } else if (candidate->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"))
                           && hoverBridge->GetBlueprint()->Air.CanFly != 0u) {
                  // Air-staging platform docking a flying hover unit -> accept.
                  return true;
                }
              }
            }
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0081DA20 (FUN_0081DA20, sub_81DA20)
     *
     * IDA signature:
     * char __usercall sub_81DA20@<al>(int a1@<ebx>, Moho::CWldSession *a2);
     *
     * What it does:
     * Returns true only when every currently selected entity is in the FACTORY
     * category. Used by the ferry-beacon right-click path to allow a
     * CallTransport order when the whole selection is factories. The binary
     * snapshots the FACTORY category's bit-vector and tests each selected
     * entity's blueprint ordinal against it; `EntityCategory::HasBlueprint`
     * expresses that same membership test.
     */
    [[nodiscard]] bool AllSelectedAreFactories(WeakSet<UserEntity>* const selection, CWldSession* const session)
    {
      const EntityCategorySet* const factoryCategory =
        static_cast<RRuleGameRules*>(session->mRules)->GetEntityCategory("FACTORY");

      for (UserEntity* const selectedEntity : *selection) {
        if (selectedEntity == nullptr
            || !EntityCategory::HasBlueprint(selectedEntity->mParams.mBlueprint, factoryCategory)) {
          return false;
        }
      }

      return true;
    }
  } // namespace

  /**
   * Address: 0x00826F10 (FUN_00826F10, sub_826F10)
   *
   * IDA signature:
   * int __stdcall sub_826F10(Moho::UICommandGraph *graph,
   *                          Moho::UICommandGraph::UICommandGraphDrawNode *drawNode);
   *
   * What it does: see the declaration above `RebuildCommandQueueNodes`.
   *
   * It sits here rather than beside `EstimateEdgeTravelTicks` because it needs
   * `ResolveUnitFocusEntity` from the anonymous namespace above.
   *
   * Two shapes worth keeping honest, both read off the disassembly rather than
   * the decompiler, which renders them misleadingly:
   *
   * - the blueprint fetch at 0x0082708A takes no argument. The decompiler shows
   *   a stale `v33` (the FACTORY category) riding along; the actual instructions
   *   are `lea ecx,[esi+148h]` + `call [vptr+1Ch]`, i.e. plain
   *   `IUnit::GetBlueprint()` through the `UserUnit+0x148` bridge.
   * - the loop body is wrapped in a real `try`/`catch`. The decompiler hides it
   *   entirely; the funclet at 0x008271C9 pulls the message off the caught
   *   object and warns "Error estimating work time: %s", then resumes at
   *   0x008271EE, which is the iterator advance - so one unit whose Lua model
   *   throws is skipped rather than abandoning the whole estimate.
   */
  std::int32_t EstimateDrawNodeWorkTicks(
    UICommandGraph& graph, UICommandGraph::UICommandGraphDrawNode& drawNode
  )
  {
    LuaPlus::LuaState* const state = GetUiManagerGlobalLaneA()->mLuaState;

    auto* const helper = drawNode.mHelperLink.GetObjectPtr();
    if (helper == nullptr) {
      return 0;
    }

    // Kept at two calls exactly as 0x00826F52/0x00826F5E emit them, and the
    // virtual's result really is dropped at 0x00826F6A (slot 3, `IsUserUnit`).
    // The resolver is not pure - it unlinks the transient anchor sample from
    // whatever weak-entity chain the lookup joined it to - so collapsing the
    // pair would drop a side effect the original source performs twice.
    if (ResolveCommandTargetEntity(*helper) != nullptr) {
      (void)ResolveCommandTargetEntity(*helper)->IsUserUnit();
    }

    REntityBlueprint* const orderedBlueprint = helper->mConstantData.blueprint;

    // Seeds: a command nobody is working on yet still has all of its work left,
    // and no assisting unit means no build rate at all.
    float remainingWorkFraction = 1.0f;
    float combinedBuildRate = 0.0f;

    // Only the two build orders carry work; the order graph treats everything
    // else as costing no time. The binary re-resolves the type for the second
    // test rather than reusing the first result.
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile
      && ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildFactory) {
      return 0;
    }

    LuaPlus::LuaObject gameModule = SCR_Import(state, "/lua/game.lua");
    LuaPlus::LuaObject constructEconomyModelObject = gameModule["GetConstructEconomyModel"];
    LuaPlus::LuaFunction<> getConstructEconomyModel(constructEconomyModelObject);

    // Engineers and factories are the two things that can pour build power into
    // an order, so the walk below tests membership of their union once per unit.
    const EntityCategorySet* const factoryCategory =
      graph.mSession->mRules->GetEntityCategory("FACTORY");
    const EntityCategorySet* const engineerCategory =
      graph.mSession->mRules->GetEntityCategory("ENGINEER");
    EntityCategorySet assistingCategory{};
    (void)func_EntityCategoryAdd(engineerCategory, &assistingCategory, factoryCategory);

    for (UserUnit* const unit : *ResolveCommandIssueCursorEntities(*helper)) {
      const RUnitBlueprint* const blueprint = GetIUnitBridge(unit)->GetBlueprint();

      if (assistingCategory.ContainsBit(blueprint->mCategoryBitIndex) && orderedBlueprint != nullptr) {
        // How much of the job is left is read off whatever this unit is
        // currently working on, and only while it is working on *this* order -
        // an engineer queued to help later must not shorten the estimate.
        if (UserEntity* const workTarget = ResolveUnitFocusEntity(unit);
            workTarget != nullptr) {
          if (ResolveUserUnitFrontCommandIssueHelper(unit->GetCommandQueue()) == helper) {
            const float maxHealth = workTarget->mVariableData.mMaxHealth;
            if (maxHealth > 0.0f) {
              const float remaining = 1.0f - (workTarget->mVariableData.mHealth / maxHealth);
              if (remainingWorkFraction > remaining) {
                remainingWorkFraction = remaining;
              }
            }
          }
        }

        // Rates add as reciprocals: each assister contributes 1/buildTime, and
        // the combined rate is what the remaining fraction is divided by below.
        try {
          LuaPlus::LuaObject luaBlueprint = orderedBlueprint->GetLuaBlueprint(state);
          const auto buildRate = static_cast<float>(getConstructEconomyModel.Call_UserunitObject_Num(
            unit != nullptr ? &unit->mLuaObj : nullptr, luaBlueprint["Economy"]
          ));
          if (buildRate > 0.0f) {
            combinedBuildRate += 1.0f / buildRate;
          }
        } catch (const std::exception& exception) {
          gpg::Warnf("Error estimating work time: %s", exception.what());
        }
      }
    }

    if (combinedBuildRate <= 0.0f) {
      return 0;
    }

    // Truncated, not rounded: 0x0082725F ORs 0xC00 into the x87 control word
    // (round toward zero) for the one `fistp` and restores it straight after.
    return static_cast<std::int32_t>(
      (remainingWorkFraction * kCommandGraphTicksPerSecond) / combinedBuildRate
    );
  }

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker: resolves the world
   * position of one unit's last-queued command. `QueuedUserCommandRecord` is
   * the opaque cross-TU name `GetLastQueuedUserCommandAnchor` (UserUnit.cpp)
   * hands out for that command's `UserCommandIssueHelper`; the handle points at
   * the helper itself, so this is a pointer conversion, not an offset. Forwards
   * to `ResolveCommandIssueTargetPosition` (FUN_0081CFD0).
   */
  Wm3::Vector3f ResolveLastQueuedCommandAnchorPosition(const QueuedUserCommandRecord* const record)
  {
    Wm3::Vector3f out{};
    (void)ResolveCommandIssueTargetPosition(&out, *reinterpret_cast<const UserCommandIssueHelper*>(record));
    return out;
  }

  MouseInfo& CWldSession::CursorInfo() noexcept
  {
    static_assert(
      offsetof(CWldSession, CursorWorldPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseWorldPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, mCursorUnitHover) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mUnitHover),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, HighlightCommandId) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mIsDragger),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    static_assert(
      offsetof(CWldSession, CursorScreenPos) - offsetof(CWldSession, mCursorWorldState)
        == offsetof(MouseInfo, mMouseScreenPos),
      "CWldSession's flattened cursor snapshot must line up with MouseInfo"
    );
    return *reinterpret_cast<MouseInfo*>(&mCursorWorldState[0]);
  }

  const MouseInfo& CWldSession::CursorInfo() const noexcept
  {
    return *reinterpret_cast<const MouseInfo*>(&mCursorWorldState[0]);
  }

  /**
   * Bridge for `Moho::DrawAllUnitSkirts` (FUN_0085AD80): resolves the world
   * position a pending command-issue helper is anchored at. The binary inlines
   * FUN_0081CFD0's resolve-target / target-to-position / release trio straight
   * into the skirt loop (asm 0x0085AE88..0x0085AEB7).
   */
  Wm3::Vector3f ResolveCommandIssueHelperAnchorPosition(UserCommandIssueHelper& helper)
  {
    Wm3::Vector3f out{};
    (void)ResolveCommandIssueTargetPosition(&out, helper);
    return out;
  }

  /**
   * Address: 0x0082A030 (FUN_0082A030, sub_82A030)
   *
   * IDA signature:
   * void __userpurge sub_82A030(Moho::UICommandGraph *graph@<eax>, unsigned int a2);
   *
   * What it does:
   * Looks the dragged command up in the session's command manager; a command
   * with no live helper (already retired) is left alone. `mMapAB0` keys its
   * draw nodes by the helper's own pointer identity, not the command id
   * (0x0082A039/0x0082A051, the same convention `ProcessCommandDrag` uses) -
   * a node only exists here if the drag actually moved the mouse at least
   * once, so a helper with no existing node is also left alone
   * (0x0082A085..0x0082A0AE: an inlined equal-range walk over
   * `EqualRangeHashListNode88`'s `[first,last)`, exactly what
   * `CountHashListNode88` already does). Otherwise finds that node
   * (0x0082A0BD, `FindOrInsertCommandGraphDrawNode`) and snaps it back to a
   * single-contributor anchor at the command's own real position
   * (0x0082A0D2, `ResolveCommandIssueHelperAnchorPosition`), replacing
   * `mPositionSum`, forcing `mWeight` back to `1.0f`, and clearing
   * `mHasResolvedPosition` so the next per-tick rebuild recomputes the node
   * from real queue data rather than leaving the drag preview position
   * sitting there. This is "drop the dragged command's highlight": the
   * only thing `OnCurrentDraggerReplaced` (0x00824290) does before
   * `delete this`.
   */
  void ReanchorCommandGraphDrawNode(UICommandGraph& graph, const CmdId cmdId)
  {
    CommandManager* const commandManager = graph.mSession->mCommandManager;

    UserCommandIssueHelper* helper = nullptr;
    if (const auto found = commandManager->mCommands.find(cmdId); found != commandManager->mCommands.end()) {
      helper = found->second;
    }
    if (helper == nullptr) {
      return;
    }

    // Same keying convention as ProcessCommandDrag's own note: mMapAB0's
    // draw-node hash is keyed by the helper's own pointer identity.
    const auto drawNodeKey = reinterpret_cast<std::uint32_t>(helper);

    if (UICommandGraph::CountHashListNode88(graph.mMapAB0, drawNodeKey) != 0) {
      UICommandGraph::UICommandGraphDrawNode* const drawNode =
        UICommandGraph::FindOrInsertCommandGraphDrawNode(drawNodeKey, graph.mMapAB0);

      drawNode->mPositionSum = ResolveCommandIssueHelperAnchorPosition(*helper);
      drawNode->mWeight = 1.0f;
      drawNode->mHasResolvedPosition = 0u;
    }
  }

  std::uint32_t EvaluateBuildTemplatePlacementPreview(
    const Wm3::Vector3f& worldPosition,
    const RUnitBlueprint* const buildBlueprint,
    CWldSession& session,
    VTransform& previewTransform
  )
  {
    std::uint32_t previewColor = 0u;
    return ApplyBuildTemplatePlacementPreviewStatus(
      worldPosition,
      buildBlueprint,
      previewTransform,
      session,
      previewColor
    );
  }

  std::uint32_t EvaluateCommandModeBuildPlacementPreview(
    const CommandModeData& commandMode,
    const Wm3::Vector3f& worldPosition,
    CWldSession& session,
    VTransform& previewTransform
  )
  {
    std::uint32_t previewColor = 0u;
    (void)ApplyCommandModeBuildPlacementPreviewStatus(
      commandMode,
      worldPosition,
      session,
      previewTransform,
      previewColor
    );
    return previewColor;
  }

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker (FUN_00840A70):
   * walks the whole session entity map in id order and appends every live
   * `UserUnit*`. Wraps the CWldSession.cpp-local `CollectSessionUserUnits`,
   * matching the binary's inline `mEntityMap` in-order scan (entity ids are
   * unique keys, so the collection order equals the binary's iteration order).
   */
  void GetSessionUserUnits(CWldSession* const session, msvc8::vector<UserUnit*>& outUnits)
  {
    CollectSessionUserUnits(session, outUnits);
  }

  /**
   * Address: 0x00896F00 (FUN_00896F00) init path (FUN_00896F00 -> sub_89A930).
   */
  SSessionSaveData::SSessionSaveData()
  {
    mNodeMap.mAllocProxy = nullptr;
    (void)InitializeSessionSaveNodeMapHeader(&mNodeMap);
  }

  /**
   * Address: 0x008971A0 cleanup path (FUN_008971A0 + sub_89AC40).
   */
  SSessionSaveData::~SSessionSaveData()
  {
    ClearSaveDataMap(mNodeMap);
    DestroySaveDataMapNode(mNodeMap.mHead);
    mNodeMap.mHead = nullptr;
    mNodeMap.mAllocProxy = nullptr;
    mNodeMap.mSize = 0u;
  }

  /**
   * Address: 0x008992D0 (FUN_008992D0)/0x00899DC0/0x0089A970 helper chain.
   */
  void SSessionSaveData::InsertNodeLabel(const std::uint32_t commandSourceId, const msvc8::string& saveNodeName)
  {
    SSessionSaveNodeLabel label{};
    label.mCommandSourceId = commandSourceId;
    label.mSaveNodeName = saveNodeName;
    InsertSaveDataLabelNode(mNodeMap, label);
  }

  /**
   * Address: 0x00893160 (FUN_00893160,
   * ??0CWldSession@Moho@@QAE@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@3@AAV?$auto_ptr@VCWldMap@Moho@@@3@AAUSWldSessionInfo@1@@Z)
   */
  CWldSession::CWldSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& rulesOwner,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    // Partial lift of 0x00893160: ownership transfers + proven field initialization.
    // Remaining helper-heavy initialization chain (vision/task/lua options/spatial builders)
    // is tracked for subsequent recovery pass.
    mState = state.release();
    mCurThread = nullptr;
    mRules = static_cast<RRuleGameRulesImpl*>(rulesOwner.release());
    mWldMap = wldMap.release();
    mLaunchInfo = sessionInfo.mLaunchInfo;

    mMapName = sessionInfo.mMapName;

    // 0x00893160 line 84: `SpatialDB_MeshInstance::SpatialDB_MeshInstance(&mSpatialDB)`
    // (0x00501D80) runs right after the entity map's head sentinel is built.
    // It allocates the map-tree head sentinel and the root shard-data lane;
    // without it every `Register` from a UserEntity ctor finds a null tree
    // head and silently drops the entry, so unit picking, band-box
    // selection and every area query see an empty database. That is
    // `mEntitySpatialDb`'s own constructor, run as a member in that order.
    // 0x00893214-0x0089323D, immediately after that ctor, is `mExtraSelection`'s
    // own constructor (the head bought through 0x007B08D0, self-linked, count
    // zero).
    // mBuildTemplates (gpg::fastvector_n<SBuildTemplateInfo, 16>) already rebound
    // itself to inline storage via its own default constructor, which runs
    // implicitly before this body -- matching the binary's per-member subobject
    // construction ahead of the constructor body. No manual lane wiring needed.
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;

    // Address: 0x008B58A0 (FUN_008B58A0, CommandManager ctor - IdPool +
    //   command-map head sentinel allocation). The manager type is modeled
    //   now (moho/command/CommandManager.h) but its constructor is not lifted
    //   yet, so the field is still left null here.
    // 0x008932C0: the session owns one command manager, stamped with the
    // command source it issues under.
    mCommandManager = new CommandManager(sessionInfo.mSourceId);

    // Current build/move formation (0x00893529: `new CFormation` @0x64). The
    // session frame calls into it unconditionally through
    // `CFormation::UpdateOrientation`, so leaving it null faults on the first
    // frame after the session starts playing.
    mCurFormation = new CFormation();
    mUnknownShared40C = {};
    mDebugCanvas = {};
    mBeatDebugCanvas = {};
    mSimResources = {};
    // `mOrphans` and `mVizUpdates` are constructed as members (0x00893358 /
    // 0x0089338C).

    mGameTick = 0;
    mLastBeatWasTick = 0;
    mTimeSinceLastTick = 0.0f;
    mSessionPauseStateA = 0;
    mRequestingPauseState = 0;
    mRequestingPause = 0;
    mPauseRequester = 0;
    mReplayIsPaused = 0;

    ourCmdSource = static_cast<std::int32_t>(sessionInfo.mSourceId);
    IsReplay = sessionInfo.mIsReplay;
    IsBeingRecorded = sessionInfo.mIsBeingRecorded;
    IsMultiplayer = sessionInfo.mIsMultiplayer;
    IsGameOver = 0;

    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      // One null army slot per launch-info army (0x008932A7): the run has to
      // exist before the first beat, because `DoBeat` addresses it by army
      // index (`userArmies[army->mArmyIndex] = army`) rather than appending,
      // and every consumer indexes it the same way - `cfunc_IsObserverL`
      // dereferences `userArmies[FocusArmy]` the moment the in-game UI asks
      // whether the local player is an observer.
      // FUN_00899880 / FUN_00898EC0 are the two halves of
      // msvc8::vector<UserArmy*>::assign(count, nullptr) -- see the address
      // block on that member in legacy/containers/Vector.h.
      userArmies.assign(launchInfo->mArmyLaunchInfo.size(), nullptr);

      // Command sources and the focus army come off the same launch info.
      (void)CopyConstructCommandSourceVector(launchInfo->mCommandSources.mSrcs, &cmdSources);
      FocusArmy = launchInfo->mCommandSources.mOriginalSource;
      IsCheatsEnabled = launchInfo->mCheatsEnabled;
    } else {
      FocusArmy = -1;
      IsCheatsEnabled = false;
    }

    // `mSelection` is constructed as a member (0x00893465..0x00893491); the
    // word after it is zeroed at 0x00893497.
    mSelectionSize = 0;

    // 0x0089349D..0x008934D9 is `MouseInfo`'s default constructor, inlined
    // over the cursor lane this class still spells out field by field
    // (`mCursorWorldState` / `CursorWorldPos` / `mCursorUnitHover` /
    // `HighlightCommandId` / `CursorScreenPos` - see `CursorInfo()`):
    //
    //   0x0089349D  mov  [ebp+4B0h], bl    ; mHitValid   = 0
    //   0x008934A3  movss [ebp+4B4h], xmm0 ; mMouseWorldPos = (0,0,0)
    //   0x008934BB  mov  [ebp+4C0h], ebx   ; mUnitHover.ownerLinkSlot = null
    //   0x008934C1  mov  [ebp+4C4h], ebx   ; mUnitHover.nextInOwner   = null
    //   0x008934C7  mov  [ebp+4C8h], -1    ; mIsDragger  = -1
    //   0x008934D1  movss [ebp+4CCh], xmm0 ; mMouseScreenPos = (0,0)
    //
    // The two weak-link stores were missing, so the cursor's hovered-unit
    // `WeakPtr` began life pointing at whatever heap bytes this allocation
    // happened to contain. The first thing to touch it is
    // `CWldSession::GetLeftMouseButtonAction`'s `mode.mMouseDragStart =
    // *mouseInfo`, which relinks through `other.ownerLinkSlot` - so on any
    // run where those bytes were not already zero, the very first frame
    // walked a garbage owner chain and faulted in
    // `WeakPtr<UserEntity>::ResetFromOwnerLinkSlot`. Whether a given build
    // survived startup came down to heap layout. The two stores are now
    // `mCursorUnitHover`'s own default constructor, run as a member.
    mCursorWorldState[0] = 0u;

    // 0x00893160 line ~288-293: seeds the initial cursor world position from
    // the map's own bounds midpoint, not the origin - matters because
    // nothing else writes CursorWorldPos until the first real mouse-move
    // event, so any UI/camera code reading it on the first frame otherwise
    // sees world-origin instead of a point actually on the map.
    if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
      const Wm3::AxisAlignedBox3f mapBounds = stiMap->GetBounds3D();
      CursorWorldPos.x = (mapBounds.Min.x + mapBounds.Max.x) * 0.5f;
      CursorWorldPos.y = (mapBounds.Min.y + mapBounds.Max.y) * 0.5f;
      CursorWorldPos.z = (mapBounds.Min.z + mapBounds.Max.z) * 0.5f;
    } else {
      CursorWorldPos.x = 0.0f;
      CursorWorldPos.y = 0.0f;
      CursorWorldPos.z = 0.0f;
    }
    CursorScreenPos.x = 0.0f;
    CursorScreenPos.y = 0.0f;
    HighlightCommandId = -1;

    // 0x008934F1: `mov byte ptr [ebp+4D5h], 1`. Shipping this false made
    // `SelectBuildPreviewColor` return the valid colour unconditionally, so a
    // placement ghost stayed green everywhere -- a mass extractor looked
    // buildable on bare ground, and the per-node gate in the build-drag
    // preview (`canBuild || !mShowInvalidBuildPlacementPreview`) kept every
    // rejected node visible too.
    mShowInvalidBuildPlacementPreview = true;
    DisplayEconomyOverlay = false;
    mTeamColorMode = false;

    // Session task stage. The binary allocates it, swaps it into `mCurThread`
    // destroying whatever was there, and then publishes it on the session Lua
    // state: for a root state `LuaState::m_luaTask` carries the owning
    // `CTaskStage`, not a `CLuaTask`, and `cfunc_ForkThreadL` reads it back
    // that way. Without this, every session script calling `ForkThread` dies
    // with "Lua state has not been set up for multiple threads".
    {
      auto* const sessionStage = new CTaskStage();
      CTaskStage* const previousStage = mCurThread;
      mCurThread = sessionStage;
      delete previousStage;
    }
    mState->m_luaTask = reinterpret_cast<CLuaTask*>(mCurThread);

    // Disk-watcher task, staged on the session task stage so reloaded script
    // files reach the session state's `__diskwatch` callbacks.
    (void)CTask::CreateTaskThread(new ScrDiskWatcherTask(mState), mCurThread, true);

    ClearBuildTemplates();

    // Scenario table. The lobby hands the session its scenario as a serialized
    // Lua value on the launch info (`LaunchInfoBase::mScenarioInfo`, +0x28) and
    // the session parses it into its own Lua universe. Leaving `mScenarioInfo`
    // default-constructed gives it a null owning state, so every
    // `SessionGetScenarioInfo` call from the in-game UI throws inside
    // `LuaObject::PushStack` before it can even compare global states.
    if (const LaunchInfoBase* const launchInfo = mLaunchInfo.get(); launchInfo != nullptr) {
      LuaPlus::LuaObject parsedScenario;
      (void)SCR_FromString(&parsedScenario, launchInfo->mScenarioInfo, mState);
      mScenarioInfo = parsedScenario;
    }

    // Observers are unconditionally allowed while watching a replay; otherwise
    // the scenario's own Options table decides, and a scenario without one
    // means no observers.
    if (IsReplay) {
      IsObservingAllowed = true;
    } else if (mScenarioInfo.IsTable()) {
      const LuaPlus::LuaObject options = mScenarioInfo["Options"];
      IsObservingAllowed = options.IsTable() && options["AllowObservers"].GetBoolean();
    } else {
      IsObservingAllowed = false;
    }

    // 0x00893160 line ~317: size the vision quadtree from the height field.
    //
    //     v36    = this->mWldMap->mTerrainRes->mMap;
    //     field  = v36->mHeightField.field;
    //     Moho::VisionDB::Init(&this->mVisionDB,
    //                          (float)(field->width  - 1),
    //                          (float)(field->height - 1));
    //
    // `VisionDB::Init` is what allocates `rootNode_`, and neither
    // `VisionDB::Entry::TryAdd` (0x0081B490) nor its caller
    // `func_ren_FogOfWar` (0x0081C660) null-checks that root -- the binary
    // relies on this call having run. Without it every fog-of-war frame
    // dereferenced a null root: `TryAdd` read `entry->mCurCircle` at +0x1C
    // off nullptr, faulting at address 0x1C in
    // `Cartographic::Render -> RenderFogOfWar`.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          mVisionDb.Init(
            static_cast<float>(heightField->Width() - 1),
            static_cast<float>(heightField->Height() - 1)
          );
        }
      }
    }

    // 0x00893160 line ~301-304: size the session's own entity spatial
    // database from the same height field, immediately after VisionDB. The
    // ctor is Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(height,
    // this, width) - already recovered as ResizeStorageForMap(width, height)
    // (Mesh.cpp:4161, address 0x00501F50, confirmed via that function's own
    // parameter names in its ground-truth signature). Ground truth's single
    // call here never touches SpatialShardData, so this one call is the
    // complete, faithful construction - matching the memset above, which is
    // what a fresh, never-before-sized SpatialDB_MeshInstance's storage
    // already looks like going in. Without this, every spatial query
    // (CollectInBox/CollectInSphere/CollectInView/CollectAllInVolume, used by
    // area-effect weapons, unit-selection-by-area, AI target-finding) reads
    // an object that was only memset to zero, never actually built.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          GetEntitySpatialDbStorage()
            ->ResizeForMap(heightField->Width() - 1, heightField->Height() - 1);
        }
      }
    }

    // 0x00893160 line ~324-326 (" CWldSession create 5" -> "create 6"): the
    // global MeshRenderer singleton's own spatial db gets resized to the
    // same map dimensions right after the session's. Ground truth's
    // Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance(height,
    // &Instance->bd, width) is the SAME 0x00501F50 body as the call above,
    // already recovered and NAMED (not orphaned as a raw constructor) as
    // MeshRenderer::UpdateMapSize(width, height) (Mesh.cpp:5992, address
    // 0x007DF510) - a real, fully-recovered method with zero callers
    // anywhere in src/sdk until this one.
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      if (const STIMap* const stiMap = GetSTIMap(); stiMap != nullptr) {
        if (const CHeightField* const heightField = stiMap->mHeightField.get(); heightField != nullptr) {
          MeshRenderer::GetInstance()->UpdateMapSize(heightField->Width() - 1, heightField->Height() - 1);
        }
      }
    }

    gActiveWldSession = this;
  }

  /**
   * Address: 0x00893A60 (FUN_00893A60, ??1CWldSession@Moho@@QAE@XZ)
   */
  CWldSession::~CWldSession()
  {
    // Partial lift of 0x00893A60: core owner releases + recovered shared/weak cleanup.

    // 0x00893A9E..0x00893AEE: the very first thing the session unwinds is its
    // army-mirror table. Every populated slot is deleted - `~UserArmy`
    // (0x008B1650) followed by `operator delete` (0x00893AD4) - and every slot
    // is then blanked, occupied or not.
    for (std::size_t armyIndex = 0; armyIndex < userArmies.size(); ++armyIndex) {
      if (UserArmy* const army = userArmies[armyIndex]; army != nullptr) {
        delete army;
      }
      userArmies[armyIndex] = nullptr;
    }

    mSimResources.release();
    mBeatDebugCanvas.release();
    mDebugCanvas.release();
    mUnknownShared40C.release();
    ClearBuildTemplates();

    // Drop every formation-preview ghost still parked in the session-global
    // preview vector. The binary runs the whole-range erase (FUN_0085A130)
    // here, which is exactly what `clear` compiles to.
    gFormationPreviews.clear();

    if (mRules) {
      delete mRules;
      mRules = nullptr;
    }

    if (mWldMap) {
      delete mWldMap;
      mWldMap = nullptr;
    }

    // Tear the session task stage down before the Lua state it is published
    // on: the stage owns the disk-watcher task and every ForkThread coroutine
    // still parked on it, and those hold `mState`.
    delete mCurThread;
    mCurThread = nullptr;

    if (mState) {
      delete mState;
      mState = nullptr;
    }

    if (mCurFormation) {
      delete mCurFormation;
      mCurFormation = nullptr;
    }
    mLaunchInfo.reset();
    // 0x00893A60 line 297: `~SpatialDB_MeshInstance(&mSpatialDB)` (0x00501E50)
    // runs after the extra-selection set is torn down and before the entity
    // map's storage is released -- member destruction in reverse declaration
    // order: `mExtraSelection`, then `mEntitySpatialDb`, then `mEntities`.

    if (gActiveWldSession == this) {
      gActiveWldSession = nullptr;
    }
  }

  /**
    * Alias of FUN_008B9580 (non-canonical helper lane).
   */
  bool CWldSession::TryGetPlayableMapRect(VisibilityRect& outRect) const
  {
    if (!mWldMap) {
      return false;
    }
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;
    if (!terrainRes) {
      return false;
    }
    terrainRes->GetPlayableMapRect(outRect);
    return true;
  }

  /**
   * Address: 0x007A6360 (FUN_007A6360, ?GetFocusArmy@CWldSession@Moho@@QBEPAVUserArmy@2@XZ)
   *
   * What it does:
   * Returns the focused army slot when focus is active, otherwise `nullptr`.
   */
  UserArmy* CWldSession::GetFocusArmy() const
  {
    const int focusArmy = FocusArmy;
    if (focusArmy < 0) {
      return nullptr;
    }

    return userArmies[static_cast<std::size_t>(focusArmy)];
  }

  /**
   * Address: 0x00896590 (FUN_00896590, ?IsObserver@CWldSession@Moho@@QBE_NXZ)
   *
   * What it does:
   * Returns true when focus army is disabled (`FocusArmy < 0`) or when the
   * focused army lane has no live `UserArmy*` owner.
   */
  bool CWldSession::IsObserver() const
  {
    const int focusArmy = FocusArmy;
    return focusArmy < 0 || userArmies[static_cast<std::size_t>(focusArmy)] == nullptr;
  }

  /**
   * Address: 0x00896570 (FUN_00896570, ?SetCursorInfo@CWldSession@Moho@@QAEXABUUICursorInfo@2@@Z)
   *
   * What it does:
   * Copies one cursor-info payload into the session cursor-info lane.
   */
  void CWldSession::SetCursorInfo(const MouseInfo& cursorInfo)
  {
    CursorInfo() = cursorInfo;
  }

  /**
   * Address: 0x00895FF0 (FUN_00895FF0, ?GetSelection@CWldSession@Moho@@QBEABV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * Returns the current world-session selection weak-set.
   */
  const WeakSet<UserEntity>& CWldSession::GetSelection() const
  {
    return mSelection;
  }

  /**
   * Address: 0x00896730 (FUN_00896730, ?GetExtraSelectList@CWldSession@Moho@@QBE?AV?$WeakSet@VUserEntity@Moho@@@2@XZ)
   *
   * What it does:
   * A copy of the extra-select list: `WeakSet`'s copy constructor inlined,
   * `begin()` pruning the source and the set's range constructor (0x00822C50)
   * adding the live entries.
   */
  WeakSet<UserEntity> CWldSession::GetExtraSelectList() const
  {
    return mExtraSelection;
  }

  /**
   * Address: 0x00896580 (FUN_00896580, ?GetCursorInfo@CWldSession@Moho@@QBEABUUICursorInfo@2@XZ)
   *
   * What it does:
   * Returns the current cursor-info payload stored by this world session.
   */
  const MouseInfo& CWldSession::GetCursorInfo() const
  {
    return CursorInfo();
  }

  /**
   * Not a distinct binary function - every caller inlines the same
   * `mCursorInfo.mUnitHover` weak-link decode (0x0086ECE8's own body plus
   * three call sites already in this file). Promoted to a public accessor
   * so callers outside this TU (`sub_8281E0`'s recovered form in the
   * command-graph render pass) don't need their own copy.
   *
   * `MouseInfo::mUnitHover` is the intrusive `WeakPtr<UserEntity>` the binary
   * stores there, so the decode is `MouseInfo::HoveredEntity()`.
   */
  UserEntity* CWldSession::GetHoveredUserEntity() const noexcept
  {
    return GetCursorInfo().HoveredEntity();
  }

  /**
   * Not a distinct binary function - promotes the file-private
   * `ResolveCommandIssueTargetPosition` (= FUN_0081CFD0) so
   * `UICommandGraph::DrawPositionNodeMesh` (a different TU) can resolve a
   * command's world-space anchor.
   */
  Wm3::Vector3f ResolveCommandGraphAnchorWorldPosition(UserCommandIssueHelper& helper) noexcept
  {
    Wm3::Vector3f position{};
    (void)ResolveCommandIssueTargetPosition(&position, helper);
    return position;
  }

  /**
   * Address: 0x00826960 (FUN_00826960, sub_826960)
   *
   * IDA signature:
   * void __fastcall sub_826960(int a1, int a2, int a3, int a4);
   * (a1@ecx = toNode, a2@edx = fromNode, a3 = graph, a4 = forceHighlight)
   *
   * What it does:
   * Finds-or-creates the `{fromNode, toNode}` edge in `graph.mMapC`
   * (`FindOrInsertCommandGraphEdge`, 0x0082B490), and on first touch wires
   * its `mFromNode`/`mToNode`, appends it into both endpoints' dword lanes
   * (`fromNode.mLaneB`, `toNode.mLaneA`), retains its owning command's
   * per-command-type orderline texture (`graph.mNodes[commandType]`) into
   * `graph.mCommandGraphTree[texture]`'s edge bucket
   * (`FindOrInsertCommandGraphBucket`, 0x0082B8B0) and pushes the edge
   * into it. Every call bumps the edge's touch count and (re)prices its
   * orderline width: `graph.mMapD` caches `CalculateWaypointLineWidth`'s
   * Lua result keyed by touch count, so repeat visits within the same
   * rebuild skip the Lua round-trip.
   *
   * Recovered by generalising `FindHashListNode88`/`InsertOrFindHashListNode88`
   * into the `FindHashListNode`/`ObtainHashListNode` templates in
   * `UICommandGraph`'s class body (RULE ONE: `HashListNode2C`/`HashListNode10`
   * are emissions of the same hash-list template, not bespoke containers -
   * 0x0082C480 diffed byte-for-byte against 0x0082BFB0's
   * rehash/insert-point-walk shape, differing only in the pair-key hash and
   * lexicographic compare), and by transcribing
   * `legacy/containers/RbTree.h`'s already-cited `insert_at` / `insert_hint`
   * / `insert_unique` / `rotate_left` / `rotate_right` shape against
   * `CommandGraphTreeNode`'s own field names for
   * `AttachCommandGraphNodeAt`/`AtHint`/`Unique` and
   * `PivotLeft`/`PivotCommandGraphTreeRight` (also in the class body;
   * kept as a transcription rather than a literal `detail::rb_tree<Traits>`
   * instantiation because `boost::SharedPtrRaw<T>` is an explicit-retain,
   * non-owning view by design - see `BoostWrappers.h` - so `rb_tree`'s
   * generic value-type copy construction would silently skip the add-ref
   * the binary performs explicitly via 0x0082D330).
   *
   * Two decompiler artifacts that must not be transcribed literally, both
   * MSVC stack-slot reuse rather than real aliasing:
   *  - the 4th parameter looks like it is both a `bool` and a dereferenced
   *    pointer in the decompile. It is a `bool` by value; the callee reuses
   *    that incoming stack slot as a local `HashListNode10*`
   *    (0x00826AA5 passes `&arg_4` to the `mMapD` find, which overwrites
   *    it) - expressed here as an ordinary local instead.
   *  - `graph.mNodes[commandType]`'s texture retain/release around the
   *    tree-bucket lookup (`_InterlockedExchangeAdd`/vtable-dispatched
   *    release in the binary) is expressed as a scoped
   *    `boost::shared_ptr<CD3DBatchTexture>` (RAII), matching
   *    `DrawWaypointMarker`'s already-established
   *    `boost::SharedPtrFromRawRetained` pattern for the same
   *    `SharedPtrRaw<void>`-typed style-table field.
   */
  void LinkCommandGraphEdge(
    UICommandGraph::UICommandGraphDrawNode& toNode, UICommandGraph::UICommandGraphDrawNode& fromNode,
    UICommandGraph& graph, const bool forceHighlight
  )
  {
    UICommandGraph::CommandGraphEdge* const edge =
      UICommandGraph::FindOrInsertCommandGraphEdge(&fromNode, &toNode, graph.mMapC);

    if (edge->mToNode == nullptr) {
      edge->mFromNode = &fromNode;
      edge->mToNode = &toNode;

      // `fastvector_n<CommandGraphEdge*, 2>::push_back` on both endpoints.
      fromNode.mLaneB.push_back(edge);
      toNode.mLaneA.push_back(edge);

      auto* const helper = toNode.mHelperLink.GetObjectPtr();
      const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
      const UICommandGraph::CommandGraphNode& style = graph.mNodes[static_cast<std::size_t>(commandType)];

      const boost::shared_ptr<ID3DTextureSheet> texture = boost::SharedPtrFromRawRetained(
        reinterpret_cast<const boost::SharedPtrRaw<ID3DTextureSheet>&>(style.mOrderlineTexture)
      );
      if (texture) {
        msvc8::vector<UICommandGraph::CommandGraphEdge*>& bucket = UICommandGraph::FindOrInsertCommandGraphBucket(
          graph.mCommandGraphTree, boost::SharedPtrRawFromSharedBorrow(texture)
        );
        bucket.push_back(edge);
      }
    }

    ++edge->mTouchCount;
    edge->mForceHighlightStyle = forceHighlight;

    UICommandGraph::HashListNode10* const cached =
      UICommandGraph::FindHashListNode10(graph.mMapD, edge->mTouchCount);
    float width;
    if (cached == graph.mMapD.mListHead) {
      const LuaPlus::LuaObject waypointModule = SCR_Import(g_UIManager->mLuaState, "/lua/ui/game/commandwaypoint.lua");
      LuaPlus::LuaFunction<float> calculateWaypointLineWidth{waypointModule["CalculateWaypointLineWidth"]};
      width = calculateWaypointLineWidth(edge->mTouchCount);

      UICommandGraph::HashListNode10Value insertValue{};
      insertValue.mKey = edge->mTouchCount;
      insertValue.mWidth = width;
      bool inserted = false;
      (void)UICommandGraph::ObtainHashListNode10(graph.mMapD, insertValue, inserted);
    } else {
      width = cached->mWidth;
    }
    edge->mBaseWidth = width;
  }

  /**
   * The command-graph rebuild frontier: `CreateMeshes`'s chain calls this.
   *
   * Address: 0x00826140 (FUN_00826140, sub_826140)
   *
   * IDA signature:
   * void __thiscall sub_826140(Moho::UserEntity *this, Moho::UICommandGraph *graph,
   *                            Moho::UserCommandQueue *queue);
   *
   * What it does:
   * Folds one entity's command queue into the graph: walks the queue's resolved
   * command-issue helpers, finds-or-creates a draw node per command, adds this
   * entity's position into the queue-head node's centroid accumulator, and
   * chains consecutive orders together through `LinkCommandGraphEdge`
   * (0x00826960, recovered above).
   *
   * `CWldSession+0x4C0`'s former layout gap - `0x0082624C`'s
   * load/subtract-8/vtable-slot-3 dispatch - is `CWldSession::GetHoveredUserEntity()`
   * (already promoted to a public accessor "so the command-graph render pass
   * can call it too" - its own doc comment already anticipated this exact
   * call site).
   *
   * The queue pre-scan (0x00826295-0x008262E2) walks the queue's entries,
   * asking each command's helper for its entities-under-cursor set
   * (`GetEntitiesUnderCursor`) and testing the hovered entity against it with
   * `WeakSet<UserUnit>::Find` (0x0082CEA0, set `find` 0x0082E560).
   *
   * A draw node that has no helper yet joins the one it was just found for
   * (0x008261B0-0x00826200): the unlink the binary runs first is a no-op on
   * the empty `WeakPtr`, so it is `ResetFromObject(helper)`.
   *
   * The Attack/FormAttack anchor test reads the kind of the helper's current
   * `UserTarget` (`ResolveCommandIssueTarget`, 0x008B4080) and releases that
   * transient target (`~UserTarget`, 0x0081D010) before testing it.
   */
  void AddCommandQueueToCommandGraph(UserEntity& entity, UICommandGraph& graph, UserCommandQueue* const queue)
  {
    if (queue == nullptr) {
      return;
    }

    // 0x00826173 / 0x008261A2: the binary asks the queue for its live link run
    // twice -- `struct_UserUnitManager::Get(a3)` -- once for the emptiness test
    // and once for the head entry. That accessor answers `primaryLinks` while
    // no issue is pending and only falls back to the rebuilt `resolvedLinks`
    // view when the pending-issue ring has something in it. Reading
    // `resolvedLinks` directly, as this did, sees an empty run in the steady
    // state, so no unit ever contributed a node and the whole shift-held
    // command graph drew nothing.
    auto* const queueLinks = GetUserUnitManagerQueueLinks(queue);
    if (queueLinks == nullptr || queueLinks->empty()) {
      return;
    }

    UserUnit* const asUnit = entity.IsUserUnit();
    IUnit* const iunit = asUnit != nullptr ? GetIUnitBridge(asUnit) : nullptr;
    if (asUnit != nullptr && iunit != nullptr && iunit->IsUnitState(UNITSTATE_BeingUpgraded)) {
      return;
    }

    // Queue-head node: keyed by the first resolved link's helper pointer,
    // accumulates every unit sharing this queue's centroid.
    const auto queueHeadKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(queueLinks->front().GetObjectPtr()));
    UICommandGraph::UICommandGraphDrawNode* queueHeadNode =
      UICommandGraph::FindOrInsertCommandGraphDrawNode(queueHeadKey, graph.mMapAB1);
    queueHeadNode->mPositionSum.x += entity.mVariableData.mCurTransform.pos_.x;
    queueHeadNode->mPositionSum.y += entity.mVariableData.mCurTransform.pos_.y;
    queueHeadNode->mPositionSum.z += entity.mVariableData.mCurTransform.pos_.z;
    queueHeadNode->mWeight += 1.0f;

    UserEntity* const hoveredEntity = graph.mSession->GetHoveredUserEntity();

    // Pre-scan: does any queued command's entities-under-cursor set contain
    // the hovered entity, or does any command's id match the session's
    // currently-highlighted command? Either forces every edge in this
    // queue's chain to render highlighted, until the matching command is
    // reached.
    bool anyHighlight = false;
    for (const WeakPtr<UserCommandIssueHelper>& link : *queueLinks) {
      UserCommandIssueHelper* const helper = link.GetObjectPtr();
      if (helper == nullptr) {
        continue;
      }

      if (hoveredEntity != nullptr) {
        WeakSet<UserUnit>* const cursorEntities = ResolveCommandIssueCursorEntities(*helper);
        if (cursorEntities->Find(static_cast<UserUnit*>(hoveredEntity)) != cursorEntities->end()) {
          anyHighlight = true;
          break;
        }
      }
      if (helper->mConstantData.cmd == graph.mSession->HighlightCommandId) {
        anyHighlight = true;
        break;
      }
    }

    // Command types this graph never draws an order node for.
    constexpr std::uint64_t kExcludedCommandTypeMask = 0x2D80000EAULL;

    UICommandGraph::UICommandGraphDrawNode* previousNode = queueHeadNode;
    std::int32_t previousCommandType = 0;
    UICommandGraph::UICommandGraphDrawNode* anchorNode = nullptr;

    for (const WeakPtr<UserCommandIssueHelper>& link : *queueLinks) {
      UserCommandIssueHelper* const helper = link.GetObjectPtr();
      if (helper == nullptr) {
        continue;
      }

      const auto commandType = ResolveCommandIssueHelperCommandType(*helper);
      const std::uint64_t typeBit = std::uint64_t{1} << static_cast<std::int32_t>(commandType);
      if ((typeBit & kExcludedCommandTypeMask) != 0u) {
        continue;
      }

      const auto helperKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(helper));
      UICommandGraph::UICommandGraphDrawNode* const currentNode =
        UICommandGraph::FindOrInsertCommandGraphDrawNode(helperKey, graph.mMapAB0);

      if (!currentNode->mHelperLink.HasValue()) {
        // First touch: publish the command id, join the owning helper's
        // draw-node chain, and seed the node's own anchor position/weight
        // from the helper's command history.
        currentNode->mCommandId = static_cast<CmdId>(helper->mConstantData.cmd);
        currentNode->mHelperLink.ResetFromObject(helper);
        currentNode->mPositionSum = ResolveCommandGraphAnchorWorldPosition(*helper);
        currentNode->mWeight = 1.0f;
      }

      currentNode->mIsChainBoundary = 0u;
      if (previousCommandType != 0 && previousCommandType != static_cast<std::int32_t>(commandType)) {
        previousNode->mIsChainBoundary = 1u;
      }
      previousCommandType = static_cast<std::int32_t>(commandType);

      const float invWeight = 1.0f / previousNode->mWeight;
      currentNode->mPreviousCentroid.x = previousNode->mPositionSum.x * invWeight;
      currentNode->mPreviousCentroid.y = previousNode->mPositionSum.y * invWeight;
      currentNode->mPreviousCentroid.z = previousNode->mPositionSum.z * invWeight;

      if (anchorNode == nullptr) {
        switch (commandType) {
        case EUnitCommandType::UNITCOMMAND_Attack:
        case EUnitCommandType::UNITCOMMAND_FormAttack: {
          // The transient target is released at the end of this full
          // expression, before the kind test, as the binary orders it.
          const bool targetsGround = ResolveCommandIssueTarget(*helper).targetType == UserTargetType::Position;
          if (targetsGround) {
            anchorNode = currentNode;
          }
          break;
        }
        case EUnitCommandType::UNITCOMMAND_Guard:
        case EUnitCommandType::UNITCOMMAND_Patrol:
        case EUnitCommandType::UNITCOMMAND_FormPatrol:
          anchorNode = currentNode;
          break;
        default:
          break;
        }
      }

      if (anyHighlight && helper->mConstantData.cmd == graph.mSession->HighlightCommandId) {
        anyHighlight = false;
      }
      LinkCommandGraphEdge(*currentNode, *previousNode, graph, anyHighlight);

      previousNode = currentNode;
    }

    previousNode->mIsChainBoundary = 1u;
    if (anchorNode != nullptr && anchorNode != previousNode) {
      LinkCommandGraphEdge(*anchorNode, *previousNode, graph, anyHighlight);
    }
  }

  /**
   * Address: 0x008965C0 (FUN_008965C0, ?BecomeObserver@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Validates observer focus request (`-1`) and applies it to the active sim
   * driver when allowed.
   */
  void CWldSession::BecomeObserver()
  {
    if (!ValidateFocusArmyRequest(-1)) {
      return;
    }

    if (ISTIDriver* const activeDriver = sSimDriver.get()) {
      activeDriver->SetArmyIndex(-1);
    }
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  UserArmy* CWldSession::GetFocusUserArmy()
  {
    return GetFocusArmy();
  }

  /**
   * Address context: compatibility wrapper lane used by recovered callsites.
   */
  const UserArmy* CWldSession::GetFocusUserArmy() const
  {
    return GetFocusArmy();
  }

  /**
   * Address: 0x008965E0 (FUN_008965E0, ?RequestFocusArmy@CWldSession@Moho@@QAEXH@Z)
   *
   * What it does:
   * Validates one zero-based focus-army index (`-1` allowed) and forwards
   * accepted changes to the active sim driver.
   */
  void CWldSession::RequestFocusArmy(const int index)
  {
    const int maxArmyIndex = static_cast<int>(userArmies.size()) - 1;
    if (index < -1 || index > maxArmyIndex) {
      gpg::Logf(
        "CWldSession::RequestFocusArmy(): invalid army index %d.  Must be between -1 and %d inclusive",
        index,
        maxArmyIndex
      );
      return;
    }

    if (!ValidateFocusArmyRequest(index)) {
      return;
    }

    if (ISTIDriver* const activeDriver = sSimDriver.get()) {
      activeDriver->SetArmyIndex(index);
    }
  }

  /**
   * Address: 0x00896670 (FUN_00896670, ?ValidateFocusArmyRequest@CWldSession@Moho@@AAE_NH@Z)
   *
   * What it does:
   * Returns whether one focus-army switch is allowed for the current command
   * source/session observation state.
   */
  bool CWldSession::ValidateFocusArmyRequest(const int index)
  {
    const unsigned int localCommandSource = static_cast<unsigned int>(ourCmdSource);

    bool hasDirectCommandSourceAccess = false;
    if (index != -1 && index >= 0) {
      const std::size_t focusIndex = static_cast<std::size_t>(index);
      if (focusIndex < userArmies.size()) {
        const UserArmy* const targetArmy = userArmies[focusIndex];
        if (targetArmy != nullptr) {
          hasDirectCommandSourceAccess = targetArmy->mVarDat.mValidCommandSources.Contains(localCommandSource);
        }
      }
    }

    if (localCommandSource == 0xFFu || IsCheatsEnabled || hasDirectCommandSourceAccess || IsGameOver != 0u) {
      return true;
    }

    if (!IsObservingAllowed) {
      return false;
    }

    for (UserArmy* const army : userArmies) {
      if (army == nullptr) {
        continue;
      }

      if (army->mVarDat.mValidCommandSources.Contains(localCommandSource) && army->mVarDat.mIsOutOfGame == 0u) {
        return false;
      }
    }

    return true;
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver()
  {
    return const_cast<EntityCategoryLookupResolver*>(
      static_cast<const CWldSession*>(this)->GetCategoryLookupResolver()
    );
  }

  /**
    * Alias of FUN_008B97C0 (non-canonical helper lane).
   */
  const EntityCategoryLookupResolver* CWldSession::GetCategoryLookupResolver() const
  {
    if (!mRules) {
      return nullptr;
    }

    // RRuleGameRulesImpl exposes the category-lookup contract in the same primary
    // vtable; this is a typed interface view, not a separate base subobject.
    return reinterpret_cast<const EntityCategoryLookupResolver*>(mRules);
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  SpatialDB<UserEntity>* CWldSession::GetEntitySpatialDbStorage()
  {
    return &mEntitySpatialDb;
  }

  /**
    * Alias of FUN_008B85E0 (non-canonical helper lane).
   */
  const SpatialDB<UserEntity>* CWldSession::GetEntitySpatialDbStorage() const
  {
    return &mEntitySpatialDb;
  }

  /**
   * Address: 0x00896780 (FUN_00896780, ?AddToExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Starts transport order command mode and inserts one entity into the
   * world-session extra-selection weak-set.
   */
  void CWldSession::AddToExtraSelectList(UserEntity* const entity)
  {
    UnloadDragDiagLine("[XSEL] Add entity=%p sizeBefore=%u", static_cast<void*>(entity), static_cast<unsigned>(mExtraSelection.Size()));
    UICommandModeData commandModeData{};
    commandModeData.mMode = msvc8::string("order", 5u);
    commandModeData.mPayload.AssignNewTable(mState, 0, 0);
    commandModeData.mPayload.SetString("name", "RULEUCC_Transport");
    UI_StartCommandMode(commandModeData);

    (void)mExtraSelection.Add(entity);
    UnloadDragDiagLine("[XSEL] Add done sizeAfter=%u", static_cast<unsigned>(mExtraSelection.Size()));
  }

  /**
   * Address: 0x00896830 (FUN_00896830, ?RemoveFromExtraSelectList@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity from the world-session extra-selection weak-set and
   * exits command mode when the set becomes empty.
   */
  void CWldSession::RemoveFromExtraSelectList(UserEntity* const entity)
  {
    UnloadDragDiagLine("[XSEL] Remove entity=%p size=%u", static_cast<void*>(entity), static_cast<unsigned>(mExtraSelection.Size()));

    // 0x00896844 `call sub_8676E0` -- the erase's result is pushed nowhere and
    // never tested. The emptiness re-check that follows is unconditional:
    //
    //   0x00896849: mov  ebx, [esi+4]      ; head
    //   0x0089684C: mov  eax, [ebx]        ; head->left
    //   0x00896853: call find
    //   0x00896858: cmp  [eax], ebx
    //   0x0089685A: jnz  ret               ; still non-empty -> keep the mode
    //   0x0089685C: call UI_EndCommandMode
    //
    // Returning early when the erase reports "not found" strands the
    // RULEUCC_Transport command mode `AddToExtraSelectList` started: every
    // later right-click then issues a transport order instead of the default
    // attack/move, which is why clicking an enemy unit appeared to do nothing.
    (void)mExtraSelection.Remove(entity);

    if (mExtraSelection.Empty()) {
      UI_EndCommandMode();
    }
  }

  /**
   * Address: 0x00896870 (FUN_00896870, ?ClearExtraSelectList@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears world-session extra selection weak-set and exits command mode when
   * any entries were present.
   */
  void CWldSession::ClearExtraSelectList()
  {
    UnloadDragDiagLine("[XSEL] Clear size=%u", static_cast<unsigned>(mExtraSelection.Size()));
    // 0x00896881-0x00896896: `Empty()`, which prunes, so a set holding only
    // dead entries counts as empty. Then the whole-tree erase (0x008968A1..)
    // and the end of command mode. The word after the set (+0xEC) is not
    // touched; this used to store the count there.
    if (mExtraSelection.Empty()) {
      return;
    }

    mExtraSelection.Clear();
    UI_EndCommandMode();
  }

  /**
   * Address: 0x0081DC70 (FUN_0081DC70, Moho::CWldSession::UnitFirstInSelection)
   *
   * What it does:
   * Returns true when selection is empty or every live selected entity
   * resolves to the supplied user-unit pointer.
   */
  bool CWldSession::UnitFirstInSelection(const UserUnit* const unit) const
  {
    for (UserEntity* const selectedEntity : mSelection) {
      if (selectedEntity->IsUserUnit() != unit) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00894120 (FUN_00894120, ?GetTerrainRes@CWldSession@Moho@@QBEPAVIWldTerrainRes@2@XZ)
   *
   * What it does:
   * Returns the world-map terrain resource lane owned by this world session.
   */
  IWldTerrainRes* CWldSession::GetTerrainRes() const
  {
    return mWldMap->mTerrainRes;
  }

  /**
   * Address: 0x00894130 (FUN_00894130, ?GetSTIMap@CWldSession@Moho@@QBEPAVSTIMap@2@XZ)
   *
   * What it does:
   * Returns the terrain STI map lane from the world-map terrain resource.
   */
  STIMap* CWldSession::GetSTIMap() const
  {
    return mWldMap->mTerrainRes->mMap;
  }

  /**
   * Address: 0x00894140 (FUN_00894140, ?AddEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Inserts one `(entityId, entity*)` mapping into the world-session entity map.
   */
  void CWldSession::AddEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.insert({static_cast<std::uint32_t>(entity->mParams.mEntityId), entity});
  }

  /**
   * Address: 0x00894170 (FUN_00894170, ?RemoveEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the world-session entity map.
   */
  void CWldSession::RemoveEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.erase(static_cast<std::uint32_t>(entity->mParams.mEntityId));
  }

  /**
   * Address: 0x008941B0 (FUN_008941B0, ?OrphanEntity@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Removes one entity-id mapping from the session entity map, marks the
   * entity as pending deletion, and inserts it into the orphan weak-set lane.
   */
  void CWldSession::OrphanEntity(UserEntity* const entity)
  {
    if (entity == nullptr) {
      return;
    }

    (void)mEntities.erase(static_cast<std::uint32_t>(entity->mParams.mEntityId));

    // The flag is what keeps the render side from treating the entity as live
    // while it finishes its death animation; 0x008941FA writes it right before
    // the weak-set insert.
    entity->mMarkedForDeletion = 1;

    (void)mOrphans.Add(entity);
  }

  /**
   * Address: 0x00894210 (FUN_00894210, ?AddToVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * `WeakSet<UserEntity>::Add` (0x007AE1B0) of `entity` into the visibility
   * set at `this+0x438` -- the same insert `OrphanEntity` runs on the orphan
   * set.
   */
  void CWldSession::AddToVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    (void)mVizUpdates.Add(entity);
  }

  /**
   * Address: 0x00894230 (FUN_00894230, ?RemoveFromVizUpdate@CWldSession@Moho@@QAEXPAVUserEntity@2@@Z)
   *
   * What it does:
   * Finds `entity` in the visibility set under the owner-link guard
   * (0x00867780) and, when present, erases that node (0x0066A550) and prunes
   * forward from the successor (0x0066A330) -- `set.erase(set.find(entity))`.
   */
  void CWldSession::RemoveFromVizUpdate(UserEntity* const entity)
  {
    if (!entity) {
      return;
    }

    const WeakSet<UserEntity>::iterator found = mVizUpdates.Find(entity);
    if (found != mVizUpdates.end()) {
      (void)mVizUpdates.Erase(found);
    }
  }

  /**
   * Address: 0x008942B0 (FUN_008942B0, ?RequestPause@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::RequestPause()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = sSimDriver.get();
    if (IsReplay) {
      if (mReplayIsPaused == 0u) {
        mReplayIsPaused = 1;
        simDriver->IncrementOutstandingRequests();
      }
    } else {
      simDriver->RequestPause(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 1;
      mPauseRequester = commandCookie;
    }

    mPauseBroadcaster.BroadcastEvent(SPauseEvent{true});
  }

  /**
   * Address: 0x00894330 (FUN_00894330, ?Resume@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::Resume()
  {
    std::int32_t commandCookie = 0;
    ISTIDriver* const simDriver = sSimDriver.get();
    if (IsReplay) {
      if (mReplayIsPaused != 0u) {
        mReplayIsPaused = 0;
        simDriver->DecrementOutstandingRequestsAndSignal();
      }
    } else {
      simDriver->Resume(&commandCookie);
      mRequestingPauseState = 1;
      mRequestingPause = 0;
      mPauseRequester = commandCookie;
    }

    mPauseBroadcaster.BroadcastEvent(SPauseEvent{false});
  }

  /**
   * Address: 0x008943E0 (FUN_008943E0, ?CheckForNecessaryUIRefresh@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the current selection when stale/dead weak entries are detected
   * or selected entities requested a UI refresh during beat processing.
   */
  void CWldSession::CheckForNecessaryUIRefresh()
  {
    const std::size_t selectionSize = mSelection.Size();
    bool needsRefresh = false;

    // Every live, not-dead entry is kept; an entry that asks for a UI refresh
    // (vtable +0x2C) or decodes to nothing flags one.
    WeakSet<UserEntity> keptSelection;
    for (UserEntity* const entity : mSelection) {
      if (entity == nullptr) {
        needsRefresh = true;
        continue;
      }
      if (entity->RequiresUIRefresh()) {
        needsRefresh = true;
      }
      if (entity->mVariableData.mIsDead == 0u) {
        (void)keptSelection.Add(entity);
      }
    }

    // 0x008944BC..0x008944DB, then `SetSelection` 0x008944E7. `SetSelection`
    // works out what changed and broadcasts it; this only decides whether to
    // call it.
    if (needsRefresh || selectionSize < mSelectionSize || keptSelection.Size() < selectionSize) {
      SetSelection(keptSelection);
    }
  }

  /**
   * Address: 0x00896A40 (FUN_00896A40, ?GetActiveBuildTemplate@CWldSession@Moho@@QBE?AV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@AAH0@Z)
   *
   * IDA signature:
   * gpg::fastvector_n16_SBuildTemplateInfo *__thiscall sub_896A40(
   *     Moho::CWldSession *this, float *a2, float *a3,
   *     gpg::fastvector_n16_SBuildTemplateInfo *a4);
   *
   * What it does:
   * Copies the active build-template buffer into one caller-owned inline
   * fastvector lane and returns the current template X/Z extents. The
   * binary's hidden-return-slot ABI copy-constructs directly into `a4`
   * (`sub_898E50(&this->mBuildTemplate, a4)`, cited on `FastVectorN`'s copy
   * ctor in FastVector.h at 0x00898E50) because at the true ABI level `a4` is
   * raw, not-yet-constructed return-slot storage. Every recovered caller in
   * this tree instead declares `result` as an ordinary local first (so it is
   * already a live, default-constructed `gpg::fastvector_n<SBuildTemplateInfo, 16>` by the time
   * this runs) -- placement-constructing over that would skip its destructor.
   * Assignment (`ResetFrom`, the same machinery the copy ctor delegates to)
   * gives the identical end state without that hazard.
   */
  gpg::fastvector_n<SBuildTemplateInfo, 16>* CWldSession::GetActiveBuildTemplate(
    float* const outTemplateSpanZ,
    float* const outTemplateSpanX,
    gpg::fastvector_n<SBuildTemplateInfo, 16>* const result
  ) const
  {
    *outTemplateSpanX = mBuildTemplateArg1;
    *outTemplateSpanZ = mBuildTemplateArg2;
    *result = mBuildTemplates;
    return result;
  }

  /**
   * Address: 0x00896AA0 (FUN_00896AA0, ?GenerateBuildTemplates@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::GenerateBuildTemplates()
  {
    std::int32_t selectableTemplateUnitCount = 0;

    for (UserEntity* const selectedEntity : mSelection) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        ++selectableTemplateUnitCount;
      }
    }

    if (selectableTemplateUnitCount <= 0) {
      return;
    }

    ClearBuildTemplates();

    float minX = 10000.0f;
    float minY = 10000.0f;
    float maxX = -10000.0f;
    float maxY = -10000.0f;

    for (UserEntity* const selectedEntity : mSelection) {
      UserUnit* const selectedUnit = selectedEntity->IsUserUnit();
      IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
      if (selectedBridge != nullptr && !selectedBridge->IsMobile() && !selectedBridge->IsDead()) {
        SBuildTemplateInfo templateInfo{};

        const auto& position = selectedBridge->GetPosition();
        templateInfo.mPos.x = position.x;
        templateInfo.mPos.y = 0.0f;
        templateInfo.mPos.z = position.z;
        templateInfo.mBuildOrder = selectedUnit->mUnitVarDat.mCreationTick;

        const RUnitBlueprint* const blueprint = selectedBridge->GetBlueprint();
        templateInfo.mBlueprintId.assign(blueprint->mBlueprintId, 0u, 0xFFFFFFFFu);

        const SCoordsVec2 unitCoords{
          selectedEntity->mVariableData.mCurTransform.pos_.x,
          selectedEntity->mVariableData.mCurTransform.pos_.z
        };
        const gpg::Rect2f skirtRect = blueprint->GetSkirtRect(unitCoords);
        minX = std::min(minX, skirtRect.x0);
        minY = std::min(minY, skirtRect.z0);
        maxX = std::max(maxX, skirtRect.x1);
        maxY = std::max(maxY, skirtRect.z1);

        mBuildTemplates.push_back(templateInfo);
      }
    }

    SortBuildTemplateRangeByOrder(mBuildTemplates.begin(), mBuildTemplates.end());
    mBuildTemplateArg1 = maxX - minX;
    mBuildTemplateArg2 = maxY - minY;

    const Wm3::Vector3f origin = mBuildTemplates.front().mPos;
    for (SBuildTemplateInfo& entry : mBuildTemplates) {
      entry.mPos.x -= origin.x;
      entry.mPos.y -= origin.y;
      entry.mPos.z -= origin.z;
    }
  }

  /**
   * Address: 0x008969E0 (FUN_008969E0, ?ClearBuildTemplates@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * Destroys every build-template entry and rebinds storage back to the
   * inline buffer, discarding any spilled heap allocation --
   * `FastVectorN::ResetStorageToInline` (FastVector.h), the same lane every
   * `gpg::fastvector_n<T, N>` instantiation resets through.
   */
  void CWldSession::ClearBuildTemplates()
  {
    mBuildTemplates.ResetStorageToInline();
    mBuildTemplateArg1 = 0.0f;
    mBuildTemplateArg2 = 0.0f;
  }

  /**
   * Address: 0x00896A70 (FUN_00896A70,
   *   ?SetActiveBuildTemplate@CWldSession@Moho@@QAEXABV?$fastvector_n@USBuildTemplateInfo@Moho@@$0BA@@gpg@@HH@Z)
   *
   * What it does:
   * Replaces the active build-template fastvector buffer with `templates`
   * and records the placement preview anchor as (`templateSpanX`,
   * `templateSpanZ`). The buffer copy is
   * `gpg::fastvector_n<SBuildTemplateInfo, 16>::operator=`, cited at
   * 0x00899790 on `FastVectorN::operator=` in FastVector.h.
   */
  void CWldSession::SetActiveBuildTemplate(
    const gpg::fastvector_n<SBuildTemplateInfo, 16>& templates,
    const float templateSpanX,
    const float templateSpanZ
  )
  {
    mBuildTemplates = templates;
    mBuildTemplateArg1 = templateSpanX;
    mBuildTemplateArg2 = templateSpanZ;
  }

  /**
   * Address: 0x00895EB0 (FUN_00895EB0,
   * ?GetCommandGraph@CWldSession@Moho@@QAE?AV?$shared_ptr@VUICommandGraph@Moho@@@boost@@_N@Z)
   *
   * What it does:
   * `lock()` into the return slot (0x00895EE5); when that is empty and
   * `allowCreate` is set, `new UICommandGraph(this)` (0x00895F05, 0x00895F20),
   * `reset` onto it (0x00895F2D) and the weak reference re-pointed at it
   * (0x00895F34). The three calls are boost's own `weak_ptr::lock`,
   * `shared_ptr::reset(Y*)` and `weak_ptr::operator=`, emitted for
   * `UICommandGraph` (cited in BoostWrappers.h).
   */
  boost::shared_ptr<UICommandGraph> CWldSession::GetCommandGraph(const bool allowCreate)
  {
    boost::shared_ptr<UICommandGraph> graph = mCommandGraph.lock();
    if (!graph && allowCreate) {
      graph.reset(new UICommandGraph(this));
      mCommandGraph = graph;
    }
    return graph;
  }

  /**
   * Address: 0x0085AF40 (FUN_0085AF40, sub_85AF40)
   *
   * What it does:
   * Peeks at the command graph - `GetCommandGraph(false)` (0x0085AF61), so
   * this never creates one - and draws its mesh when one is alive
   * (0x0085AF8E), releasing the temporary afterwards (0x0085AF9B..0x0085AFCB).
   */
  void CWldSession::RenderCommandGraph(
    const GeomCamera3& camera, CD3DPrimBatcher* const batcher, const std::int32_t gameTick, const float tickFraction
  )
  {
    if (const boost::shared_ptr<UICommandGraph> graph = GetCommandGraph(false)) {
      graph->DrawCommandGraphMesh(camera, *batcher, gameTick, tickFraction);
    }
  }

  /**
   * Address: 0x00895DC0 (FUN_00895DC0, ?HandleFogEdge@CWldSession@Moho@@AAEXABV?$Rect2@H@gpg@@HH@Z)
   *
   * What it does:
   * Clears edge-fog rows when focus army is invalid and marks every edge lane
   * outside the visible rectangle as blocked (`0xFF`).
   */
  void CWldSession::HandleFogEdge(const gpg::Rect2i& visibleRect, const int width, const int height)
  {
    if (FocusArmy < 0 || userArmies[static_cast<std::size_t>(FocusArmy)] == nullptr) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y) {
        std::memset(row, 0, static_cast<std::size_t>(width));
        row += width;
      }
    }

    if (visibleRect.x0 > 0 || visibleRect.z0 > 0 || visibleRect.x1 < width || visibleRect.z1 < height) {
      char* row = mEdgeFog.GetPtr(0u, 0u);
      for (int y = 0; y < height; ++y, row += width) {
        if (y < visibleRect.z0 || y >= visibleRect.z1) {
          std::memset(row, 0xFF, static_cast<std::size_t>(width));
          continue;
        }

        if (visibleRect.x0 <= 0) {
          *row = static_cast<char>(0xFF);
        } else {
          std::memset(row, 0xFF, static_cast<std::size_t>(visibleRect.x0));
        }

        if (visibleRect.x1 >= (width - 1)) {
          row[width - 1] = static_cast<char>(0xFF);
        } else {
          std::memset(row + visibleRect.x1, 0xFF, static_cast<std::size_t>(width - visibleRect.x1));
        }
      }
    }
  }

  /**
   * Address: 0x00895F70 (FUN_00895F70, ?DirtyCommandGraph@CWldSession@Moho@@QAEXXZ)
   *
   * What it does:
   * `lock()` on the weak reference (0x00895F7F), a byte store into the graph's
   * dirty flag when one is alive (0x00895F8C), and the temporary's release.
   */
  void CWldSession::DirtyCommandGraph()
  {
    if (const boost::shared_ptr<UICommandGraph> graph = mCommandGraph.lock()) {
      graph->MarkDirty();
    }
  }

  /**
   * Address: 0x008958B0 (FUN_008958B0, ?ApplyPendingSaveData@CWldSession@Moho@@AAEXXZ)
   *
   * What it does:
   * Replays save-data selection-set labels onto live user units, groups those
   * units by selection-set name in Lua, calls
   * `/lua/ui/game/selection.lua:ResetSelectionSets`, then releases the pending
   * save-data shared pointer.
   */
  void CWldSession::ApplyPendingSaveData()
  {
    LuaPlus::LuaObject selectionSetsByName;
    selectionSetsByName.AssignNewTable(mState, 0, 0);

    SSessionSaveData& saveData = *mPendingSaveData;
    SSessionSaveNodeMapNode* const head = saveData.mNodeMap.mHead;
    for (SSessionSaveNodeMapNode* node = head->mLeft; node != nullptr && node != head; node = NextTreeNode(node)) {
      UserEntity* const entity = LookupEntityId(static_cast<EntId>(node->mLabel.mCommandSourceId));
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      const char* const selectionSetName = node->mLabel.mSaveNodeName.c_str();
      unit->AddSelectionSet(selectionSetName);

      LuaPlus::LuaObject setUnits = selectionSetsByName[selectionSetName];
      if (setUnits.IsNil()) {
        setUnits.AssignNewTable(mState, 0, 0);
        selectionSetsByName.SetObject(selectionSetName, setUnits);
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
      setUnits.Insert(setUnits.GetN() + 1, unitObject);
    }

    try {
      LuaPlus::LuaObject selectionModule = SCR_Import(mState, "/lua/ui/game/selection.lua");
      LuaPlus::LuaFunction<> resetSelectionSets(selectionModule["ResetSelectionSets"]);
      resetSelectionSets.Call_Object(selectionSetsByName);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Unable to reset selection sets: %s",
        exception.what() != nullptr ? exception.what() : ""
      );
    }

    mPendingSaveData.reset();
  }

  namespace
  {
    /**
     * Address: 0x008945C1..0x008945D8 (inside FUN_00894530)
     *
     * What it does:
     * Resolves one army slot for the sound listener, treating a negative focus
     * army (observer, or not yet assigned) as "no listener".
     */
    [[nodiscard]] UserArmy* ArmyAtIndexOrNull(const msvc8::vector<UserArmy*>& armies, const std::int32_t index)
    {
      if (index < 0) {
        return nullptr;
      }
      return armies[static_cast<std::size_t>(index)];
    }

    /**
     * Address: 0x00894E11..0x00894E45 (inside FUN_00894530)
     *
     * What it does:
     * Looks one live command-issue helper up by id, returning null when the
     * manager's map has no entry (the walk lands on the sentinel head).
     */
    [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelper(CommandManager& manager, const CmdId commandId)
    {
      const auto found = manager.mCommands.find(commandId);
      return found == manager.mCommands.end() ? nullptr : found->second;
    }

    /**
     * Address: 0x00895097..0x0089511F and three siblings (inside FUN_00894530)
     *
     * What it does:
     * Re-seats one raw shared-pointer lane onto the beat payload's owner. The
     * raw pointer is copied unconditionally; the control block is only swapped
     * when it actually changes, taking the new reference before dropping the
     * old one so a self-assignment cannot free what it is about to keep.
     *
     * (Stranded note: the helper this documented is no longer in this file.
     * The pruning cursor that sat under it, 0x008955F2..0x00895667, is now
     * `WeakSet<UserEntity>::begin()` over `mOrphans`/`mVizUpdates`.)
     */
  } // namespace

  /**
   * Address: 0x007F6390 (FUN_007F6390, Moho::CWldSession::GetTickDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetTickDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mDebugCanvas` (+0x0414/+0x0418) - the tick
   * debug canvas `DoBeat` re-seats every beat from `beat.mTickDebugCanvas`.
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetTickDebugCanvas() const
  {
    return mDebugCanvas.clone_retained();
  }

  /**
   * Address: 0x007F63C0 (FUN_007F63C0, Moho::CWldSession::GetBeatDebugCanvas)
   *
   * IDA signature:
   * boost::shared_ptr_CDebugCanvas *__usercall Moho::CWldSession::GetBeatDebugCanvas(
   *   boost::shared_ptr_CDebugCanvas *result, Moho::CWldSession *this);
   *
   * What it does:
   * Returns a retained copy of `mBeatDebugCanvas` (+0x041C/+0x0420).
   */
  boost::SharedPtrRaw<CDebugCanvas> CWldSession::GetBeatDebugCanvas() const
  {
    return mBeatDebugCanvas.clone_retained();
  }

  /**
   * Address: 0x00894530 (FUN_00894530,
   * ?DoBeat@CWldSession@Moho@@QAEXV?$auto_ptr@USSyncData@Moho@@@std@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::CWldSession::DoBeat(Moho::CWldSession *this, std::auto_ptr<SSyncData> sdata);
   *
   * What it does:
   * Applies one sim beat to the client world, in the packet's own lane order.
   * This is the sole consumer of the driver's sync queue - without it the queue
   * fills, the issue thread stops issuing, and the game clock never advances.
   */
  void CWldSession::DoBeat(msvc8::auto_ptr<SSyncData> syncData)
  {
    const CTimeBarSection beatSection("Sync");

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const worldCamera = cameraManager->GetCamera("WorldCamera");
    IWldTerrainRes* const terrainRes = mWldMap->mTerrainRes;

    const SSyncData& beat = *syncData;

    mGameTick = beat.mCurTick;
    mLastBeatWasTick = beat.mAdvanced;

    // A focus-army change moves the listener, and the outgoing selection belongs
    // to an army we may no longer be allowed to see - so it is dropped wholesale.
    if (beat.mFocusArmy != FocusArmy) {
      FocusArmy = beat.mFocusArmy;
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));

      SetSelection(WeakSet<UserEntity>());
    }

    USER_GetSound()->UpdateSoundRequests(beat.mAudioRequests);

    if (beat.mAdvanced) {
      sWorldParticles.AdvancementBeat();
    }
    if (beat.mParticleBuffer) {
      sWorldParticles.AddParticles(*static_cast<const SParticleBuffer*>(beat.mParticleBuffer.get()));
    }

    auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());
    decalManager->AddDecals(beat.mAddDecals);
    decalManager->RemoveDecals(beat.mRemoveDecals);
    decalManager->ProcessRemovals(beat.mCurTick);

    // Camera shakes reach every live camera, not just the world one.
    {
      const msvc8::vector<CameraImpl*> allCameras = CAM_GetAllRCamCameras();
      for (const SCamShakeParams& shake : beat.mCamShakeParams) {
        for (CameraImpl* const camera : allCameras) {
          if (camera != nullptr) {
            camera->CameraShake(shake);
          }
        }
      }
    }

    if (worldCamera != nullptr) {
      terrainRes->UpdateWaveSystem(worldCamera->CameraGetView(), worldCamera->CameraGetTargetZoom(), mGameTick);
    }

    for (const gpg::Rect2i& playableRect : beat.mPlayableRectUpdates) {
      terrainRes->NotifyMapChange(playableRect);
    }

    // A new army grid means new armies; each lands in its own index slot, and
    // the listener is re-seated afterwards because the focus army may now exist.
    if (!beat.mNewGrids.empty()) {
      for (const SSTIArmyConstantData& armyConstantData : beat.mNewGrids) {
        UserArmy* const army = new UserArmy(this, armyConstantData);
        userArmies[static_cast<std::size_t>(army->mArmyIndex)] = army;
      }
      USER_GetSound()->SetListenerArmy(ArmyAtIndexOrNull(userArmies, FocusArmy));
    }

    // Army updates are positional: the Nth record belongs to the Nth army.
    {
      std::size_t armyIndex = 0;
      for (const SSTIArmyVariableData& armyUpdate : beat.mArmyUpdates) {
        (void)AssignArmyVariableData(armyUpdate, &userArmies[armyIndex]->mVarDat);
        ++armyIndex;
      }
    }

    for (const SCreateEntityParams& createParams : beat.mNewEntities) {
      AddEntity(new UserEntity(*this, createParams));
    }

    for (const SCreateUnitParams& createParams : beat.mNewUnits) {
      AddEntity(new UserUnit(this, createParams));
    }

    for (const SSTICommandConstantData& commandConstantData : beat.mPublishedCommandDescriptors) {
      (void)FindOrCreateCommandIssueHelper(*mCommandManager, commandConstantData, 0u, 0);
    }

    for (const SUnitVariableUpdateEntry& unitUpdate : beat.mUnitUpdates) {
      auto* const unit = static_cast<UserUnit*>(LookupEntityId(unitUpdate.mEntityId));
      unit->UpdateUnitData(unitUpdate.mVariableData, unitUpdate.mReconFlags);
    }

    for (const SEntityVariableUpdateEntry& entityUpdate : beat.mEntityUpdates) {
      LookupEntityId(entityUpdate.mEntityId)->UpdateEntityData(entityUpdate.mVariableData);
    }

    // Erase means "the sim is done with this entity but the client may still be
    // animating it": drop it from the id map and park it in the orphan set.
    for (const EntId erasedId : beat.mEraseIds) {
      OrphanEntity(LookupEntityId(erasedId));
    }

    // TEMPORARY PROBE -- input-free attack-order harness, delete when resolved.
    // The game window is not enumerable from the agent's session, so synthetic
    // clicks never arrive; this issues the order the test needs from inside the
    // sim instead, at fixed beats, so the attack path can be measured headlessly.
    {
      static int sHarnessBeat = 0;
      ++sHarnessBeat;
      if (sHarnessBeat == 150 && std::getenv("FAF_HARNESS") != nullptr) {
        const STIMap* const playableMap =
          (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr)
            ? mWldMap->mTerrainRes->mMap
            : nullptr;
        gpg::Warnf("[HARNESS] rect=(%d,%d)-(%d,%d) map=%p",
                   playableMap != nullptr ? playableMap->mPlayableRect.x0 : -1,
                   playableMap != nullptr ? playableMap->mPlayableRect.z0 : -1,
                   playableMap != nullptr ? playableMap->mPlayableRect.x1 : -1,
                   playableMap != nullptr ? playableMap->mPlayableRect.z1 : -1,
                   static_cast<const void*>(playableMap));

        gpg::fastvector<UserEntity*> allEntities{};
        auto* const spatialDb = GetEntitySpatialDbStorage();
        (void)spatialDb->Collect(allEntities, ENTITYTYPE_Unit);

        UserUnit* ownUnit = nullptr;
        for (UserEntity* const entity : allEntities) {
          if (entity == nullptr) {
            continue;
          }
          if (UserUnit* const asUnit = entity->IsUserUnit(); asUnit != nullptr) {
            ownUnit = asUnit;
            break;
          }
        }

        if (ownUnit != nullptr) {
          const Wm3::Vec3f unitPos = reinterpret_cast<UserEntity*>(ownUnit)->mVariableData.mCurTransform.pos_;
          SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_Attack);
          issueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
          issueData.mTarget.mPos.x = unitPos.x + 12.0f;
          issueData.mTarget.mPos.y = unitPos.y;
          issueData.mTarget.mPos.z = unitPos.z;

          gpg::fastvector<UserUnit*> orderUnits{};
          orderUnits.push_back(ownUnit);
          gpg::Warnf("[HARNESS] issuing attack-ground unit=%p from=(%.1f,%.1f,%.1f) to=(%.1f,%.1f,%.1f)",
                     static_cast<void*>(ownUnit), unitPos.x, unitPos.y, unitPos.z,
                     issueData.mTarget.mPos.x, issueData.mTarget.mPos.y, issueData.mTarget.mPos.z);
          ISSUE_Command(orderUnits, issueData, true);
        } else {
          gpg::Warnf("[HARNESS] no own unit found among %u entities",
                     static_cast<unsigned>(allEntities.size()));
        }
      }
    }
    for (const SEntityPoseUpdateEntry& poseUpdate : beat.mPoseUpdates) {
      UserEntity* const entity = LookupEntityId(poseUpdate.mEntityId);
      if (entity == nullptr) {
        gpg::Logf("CWldSession::DoBeat() unknown entity id (0x%08x) supplied in a pose update.", poseUpdate.mEntityId);
        continue;
      }
      entity->SetPose(poseUpdate.mPose);
    }

    // Delete means gone for good.
    for (const EntId deletedId : beat.mDeleteIds) {
      UserEntity* const entity = LookupEntityId(deletedId);
      RemoveEntity(entity);
      delete entity;
    }

    for (const SSyncPublishedCommandPacket& commandPacket : beat.mPublishedCommandPackets) {
      UserCommandIssueHelper* const helper = FindCommandIssueHelper(*mCommandManager, commandPacket.commandId);
      helper->mVariableData = commandPacket.variableData;
      helper->mVariableDataDirty = 1u;
    }

    { static int c = 0; if ((!beat.mPendingCommandEventRemovals.empty() || !beat.mPendingReleasedCommandIds.empty()) && c++ < 200) gpg::Warnf("[GHOST] DoBeat removals=%u released=%u mCommands=%u", static_cast<unsigned>(beat.mPendingCommandEventRemovals.size()), static_cast<unsigned>(beat.mPendingReleasedCommandIds.size()), static_cast<unsigned>(mCommandManager->mCommands.size())); } // TEMPORARY PROBE (do not commit)
    for (const CmdId removedCommandId : beat.mPendingCommandEventRemovals) {
      { static int c = 0; if (c++ < 200) gpg::Warnf("[GHOST]   removal id=0x%08X helper=%p", static_cast<unsigned>(removedCommandId), static_cast<void*>(FindCommandIssueHelper(*mCommandManager, removedCommandId))); } // TEMPORARY PROBE (do not commit)
      delete FindCommandIssueHelper(*mCommandManager, removedCommandId);
    }

    { static int c = 0; for (const CmdId rid : beat.mPendingReleasedCommandIds) { if (c++ < 200) gpg::Warnf("[GHOST]   release id=0x%08X helper=%p", static_cast<unsigned>(rid), static_cast<void*>(FindCommandIssueHelper(*mCommandManager, rid))); } } // TEMPORARY PROBE (do not commit)
    DeleteCommandIssueHelpers(*mCommandManager, beat.mPendingReleasedCommandIds);
    { static int c = 0; if ((!beat.mPendingCommandEventRemovals.empty() || !beat.mPendingReleasedCommandIds.empty()) && c++ < 200) gpg::Warnf("[GHOST] DoBeat after mCommands=%u", static_cast<unsigned>(mCommandManager->mCommands.size())); } // TEMPORARY PROBE (do not commit)

    // The command graph only gets marked here (`DirtyCommandGraph`, inlined:
    // the `lock()` at 0x00894F02 and the byte store at 0x00894F17); the mesh
    // rebuild it implies runs back in `SessionFrame`.
    DirtyCommandGraph();

    if (worldCamera != nullptr) {
      for (const SCamFollowParams& follow : beat.mFollowCameras) {
        worldCamera->CameraFollow(follow);
      }
    }

    // Hand the sim's Lua payload to the UI: last beat's table becomes
    // `PreviousSync`, this beat's stream becomes `Sync`, then `OnSync()` runs.
    {
      const LuaPlus::LuaObject previousSync = SCR_Copy(mState->GetGlobal("Sync"), mState);
      mState->GetGlobals().SetObject("PreviousSync", previousSync);

      // The binary takes the stream by reference and never checks it: every
      // beat carries one, because `Sim::Sync` installs a fresh
      // `MemBufferStream` before serialising the table into it. That tail was
      // an unrecovered gap here, which left `mStream` null and forced a guard
      // that skipped the deserialize on every single beat - the sim wrote the
      // `Sync` table and the UI never saw any of it. The tail is recovered
      // now and `Sim::Sync` is the only producer of an `SSyncData`, so the
      // guard is dead and the unchecked binary shape is restored.
      gpg::BinaryReader syncReader(beat.mStream);
      LuaPlus::LuaObject currentSync;
      currentSync.SCR_FromByteStream(currentSync, mState, &syncReader);
      mState->GetGlobals().SetObject("Sync", currentSync);
    }
    (void)SCR_LuaDoString("OnSync()", mState);

    mSessionPauseStateA = static_cast<std::uint8_t>(beat.mPausedBy != -1);
    mDebugCanvas.reset_from(beat.mTickDebugCanvas);
    mBeatDebugCanvas.reset_from(beat.mBeatDebugCanvas);
    ren_FogOfWar = beat.mFogOfWar;
    terrainRes->SyncTerrain(beat.mTerrainUpdate.px);
    mSimResources.reset_from(beat.mSimResources);

    // `msvc8::vector<SExtraUnitData>::operator=` (0x00895214, FUN_007530C0,
    // `legacy/containers/Vector.h`). Previously mis-wired through
    // `AssignSyncInlineVectors` (a per-element `SyncInlineVector` scratch-run
    // copy) at this exact call site -- `FUN_007530C0`'s callee chain
    // (`FUN_00755DE0`/`FUN_00750A80`, `>>3` nested 8-byte-pair-vector copy at
    // +0x00 plus one trailing scalar dword at +0x18) only matches
    // `SExtraUnitData::pairs`/`unitEntityId`, never a flat `int32_t[4]`
    // element; removed the wrong helper and call directly.
    mSyncExtraUnitData = beat.mSyncExtraUnitData;

    for (const msvc8::string& printLine : beat.mPrintField) {
      CON_Printf("%s", printLine.c_str());
    }

    if (!beat.mDesyncs.empty()) {
      msvc8::vector<msvc8::string> desyncArmyNames(beat.mDesyncs.size());

      std::size_t desyncIndex = 0;
      for (const SDesyncInfo& desync : beat.mDesyncs) {
        desyncArmyNames[desyncIndex].assign(
          cmdSources[static_cast<std::size_t>(desync.army)].mName, 0, msvc8::string::npos
        );
        GPGNET_ReportDesync(desync.beat, desync.army, desync.hash2.ToString(), desync.hash1.ToString());
        ++desyncIndex;
      }

      UI_ShowDesyncDialog(mGameTick, desyncArmyNames);
    }

    if (beat.mGameOver && IsGameOver == 0u) {
      IsGameOver = 1u;
      UI_NoteGameOver();
      if (CFG_GetArgOption("/exitongameover", 0u, nullptr)) {
        wxTheApp->ExitMainLoop();
      }
    }

    if (mPendingSaveData) {
      ApplyPendingSaveData();
    }

    // Every registered unit gets its beat. The stat is what the profiler reads
    // as "how much work is one beat", so it is published even for an empty list.
    {
      // Heap-backed on purpose. `Collect` takes the vector by its
      // `gpg::fastvector<T>` base, and the base's grow path frees `start_`
      // unconditionally - it has no `originalVec_` word to test against. Hand
      // it an inline `FastVectorN` and the first push past the inline capacity
      // calls `delete[]` on the inline buffer, which here would be a stack
      // address. The binary gets away with an inline lane because its collect
      // family is templated on the concrete vector type, so the grow helper it
      // emits (sub_505BA0) reads `originalVec_` at +0x0C and skips the free.
      // Until that template is restored, the base-typed API must be handed a
      // vector that really does own its storage.
      gpg::fastvector<UserEntity*> tickers;
      auto* const spatialDb = GetEntitySpatialDbStorage();
      (void)spatialDb->Collect(tickers, ENTITYTYPE_Unit);

      const auto tickerCount = static_cast<std::int32_t>(tickers.size());
      if (sEngineStat_UserSync_SessionTick_NumTickers == nullptr) {
        sEngineStat_UserSync_SessionTick_NumTickers =
          GetEngineStats()->GetItem("UserSync_SessionTick_NumTickers", true);
        (void)sEngineStat_UserSync_SessionTick_NumTickers->Release(0);
      }
      (void)sEngineStat_UserSync_SessionTick_NumTickers->SetInt(&tickerCount);

      for (std::int32_t i = 0; i < tickerCount; ++i) {
        UserEntity* const ticker = tickers[static_cast<std::size_t>(i)];
        // TEMPORARY GUARD -- spatial-db triage, delete when resolved: a
        // collected owner whose vtable is unreadable or whose Tick slot is
        // null is reported and skipped rather than called.
        {
          const void* const* const vtable =
            ticker != nullptr && ::IsBadReadPtr(ticker, sizeof(void*)) == FALSE
              ? *reinterpret_cast<const void* const* const*>(ticker) : nullptr;
          const bool ok = vtable != nullptr && ::IsBadReadPtr(vtable, sizeof(void*) * 4) == FALSE
            && vtable[0] != nullptr && vtable[1] != nullptr;
          if (!ok) {
            gpg::Warnf("[TICKBAD] idx=%d/%d owner=%p vtable=%p", i, tickerCount, static_cast<void*>(ticker),
                       static_cast<const void*>(vtable));
            continue;
          }
        }
        ticker->Tick(beat.mCurBeat);
      }
    }

    // Both weak-set drains prune as they go. The orphan walk steps the cursor
    // before it calls out, because `OrphanUpdate` can unlink the entity it was
    // just handed; the visibility walk steps after, because `UpdateVisibility`
    // leaves the set alone.
    //
    // 0x008955F2..0x00895641: `find` from `mOrphans.mHead->mLeft`, then per
    // entry decode (0x0066A300), advance (0x007AE7E0) and `OrphanUpdate`.
    // 0x0089564A..0x008956D8: the same walk over `mVizUpdates`, with the
    // successor step inlined after the `UpdateVisibility` call.
    for (auto orphan = mOrphans.begin(); orphan != mOrphans.end();) {
      UserEntity* const entity = *orphan;
      ++orphan;
      if (entity != nullptr) {
        entity->OrphanUpdate();
      }
    }

    for (UserEntity* const entity : mVizUpdates) {
      if (entity != nullptr) {
        entity->UpdateVisibility();
      }
    }

    AdvanceCommandIssueHelpersToBeat(*mCommandManager, beat.mCurBeat);

    if (mRequestingPauseState != 0u && beat.mCurBeat - mPauseRequester >= 0) {
      mRequestingPauseState = 0u;
    }

    CheckForNecessaryUIRefresh();

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      (void)uiManager->DoBeat();
    }

    if (!beat.mSubmitArmyStats.empty()) {
      GPGNET_SubmitArmyStats(beat.mSubmitArmyStats);
    }

    if (dbg_Metronome && USER_GetSound() != nullptr) {
      USER_GetSound()->Play(msvc8::string("Tick", 4u), msvc8::string("TestBank", 8u));
    }
  }

  /**
   * Address: 0x00895B40 (FUN_00895B40, ?SessionFrame@CWldSession@Moho@@QAEXM@Z)
   */
  void CWldSession::SessionFrame(const float deltaSeconds)
  {
    static_cast<RRuleGameRules*>(mRules)->UpdateLuaState(mState);

    ISTIDriver* const simDriver = sSimDriver.get();

    // Interpolation between ticks. Running with the wind means "do not
    // interpolate, just consume beats", so the fraction is pinned at a whole
    // tick and the drain below never waits for the clock.
    if (mLastBeatWasTick == 0 || wld_RunWithTheWind) {
      mTimeSinceLastTick = 1.0f;
    } else {
      mTimeSinceLastTick += WLD_GetSimRate() * deltaSeconds * 10.0f;
    }

    CFormation::UpdateOrientation(CursorInfo().mMouseWorldPos, mCurFormation);

    const std::int32_t tickAtFrameStart = mGameTick;
    const std::int32_t targetTick = mGameTick + static_cast<std::int32_t>(std::floor(mTimeSinceLastTick));

    // Drain the driver's sync queue. Bounded at 100 beats so a burst after a
    // stall cannot make one frame arbitrarily long.
    std::int32_t beatsApplied = 0;
    for (; beatsApplied < 100; ++beatsApplied) {
      if (mReplayIsPaused) {
        // A paused replay still applies beats until it lands on a tick.
        if (mLastBeatWasTick != 0) {
          break;
        }
      } else if (mGameTick >= targetTick && !wld_RunWithTheWind) {
        break;
      }

      if (!simDriver->HasSyncData()) {
        break;
      }

      SSyncData* packet = nullptr;
      simDriver->GetSyncData(packet);
      DoBeat(msvc8::auto_ptr<SSyncData>(packet));
    }

    if (sEngineStat_Sync_Count == nullptr) {
      sEngineStat_Sync_Count = GetEngineStats()->GetItem("Sync_Count", true);
      (void)sEngineStat_Sync_Count->Release(0);
    }
    (void)sEngineStat_Sync_Count->SetInt(&beatsApplied);

    // Whatever the drain consumed comes back off the interpolation fraction, so
    // the render clock does not run ahead of the sim clock.
    if (!wld_RunWithTheWind) {
      const float remainder = mTimeSinceLastTick - static_cast<float>(mGameTick - tickAtFrameStart);
      mTimeSinceLastTick = std::max(0.0f, std::min(remainder, 1.0f));
    }

    if (const boost::shared_ptr<UICommandGraph> commandGraph = GetCommandGraph(false)) {
      commandGraph->CreateMeshes();
    }

    // 0x00409AC0 - the binary names this `CTaskStage::DoFrame`; it is the same
    // body the rest of the tree already calls `UserFrame`.
    mCurThread->UserFrame();
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   */
  void CWldSession::GetSelectionUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    for (UserEntity* const entity : mSelection) {
      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (std::find(outUnits.begin(), outUnits.end(), userUnit) == outUnits.end()) {
        outUnits.push_back(userUnit);
      }
    }
  }

  /**
   * Address: 0x00896000 (FUN_00896000, ?GetSelectionUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Adds every selected unit to `outUnits` (`WeakSet<UserUnit>::Add`
   * 0x00822270). The walk prunes the selection's dead entries as it goes, so
   * this `QBE` (const) member does change the tree.
   */
  void CWldSession::GetSelectionUnits(WeakSet<UserUnit>& outUnits) const
  {
    for (UserEntity* const entity : mSelection) {
      if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
        (void)outUnits.Add(unit);
      }
    }
  }

  /**
   * Address: 0x00896090 (FUN_00896090, ?GetValidAttackingUnits@CWldSession@Moho@@QBEXAAV?$WeakSet@VUserUnit@Moho@@@2@@Z)
   *
   * What it does:
   * Walks selected units and keeps only those that can attack the currently
   * hovered entity.
   */
  void CWldSession::GetValidAttackingUnits(msvc8::vector<UserUnit*>& outUnits) const
  {
    outUnits.clear();

    const UserEntity* const hoveredTarget = this->GetHoveredUserEntity();
    for (UserEntity* const entity : mSelection) {
      UserUnit* const userUnit = entity->IsUserUnit();
      if (!userUnit) {
        continue;
      }

      if (userUnit->CanAttackTarget(hoveredTarget, true)) {
        AppendUnitUnique(outUnits, userUnit);
      }
    }

  }
  /**
   * Address: 0x008B0C80 (FUN_008B0C80)
   * Mangled: ?ISSUE_IncreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_IncreaseCommandCount(Moho::UserCommand* helper, int count);
   *
   * What it does:
   * Re-issues one factory-build command `count` extra times. Early-outs unless the
   * helper's resolved command type is `UNITCOMMAND_BuildFactory`. Reconstructs a
   * `SSTICommandIssueData` carrying the helper's constant command index and target
   * blueprint, decodes the helper's cached cursor-entity weak-set into live
   * `UserUnit*` lanes with a tombstone-pruning tree walk, then calls `ISSUE_Command`
   * once per requested count (the command payload is passed by value each call).
   */
  void ISSUE_IncreaseCommandCount(UserCommandIssueHelper* const helper, const int count)
  {
    // Gate: only factory-build commands are re-issued this way (asm 0x008B0CA2).
    if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildFactory) {
      return;
    }

    // Rebuild the issue payload from the helper's constant command descriptor: seed
    // an empty payload, then stamp BuildFactory + the command index (+0x04) and the
    // target blueprint pointer (+0x20) straight from the constant data.
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_None);
    commandIssueData.mCommandType = EUnitCommandType::UNITCOMMAND_BuildFactory;
    commandIssueData.mIndex = helper->mConstantData.cmd;
    commandIssueData.mBlueprint = reinterpret_cast<RUnitBlueprint*>(helper->mConstantData.blueprint);

    // The command's units: a copy of the helper's cursor set (rebuilt first if
    // dirty, 0x008B43F0; copied through the range constructor 0x00831310),
    // then every unit of the copy into a vector sized by its `Size()`
    // (0x00838AE0). The copy is destroyed on the way out (0x008B0E61).
    const WeakSet<UserUnit> cursorUnits(*ResolveCommandIssueCursorEntities(*helper));
    gpg::fastvector<UserUnit*> selectedUnits{};
    selectedUnits.reserve(cursorUnits.Size());
    for (UserUnit* const unit : cursorUnits) {
      selectedUnits.push_back(unit);
    }

    // Issue the reconstructed factory-build command once per requested count;
    // clearQueue is always false here (asm push ebx==0 at 0x008B0E12).
    for (int remaining = count; remaining > 0; --remaining) {
      ISSUE_Command(selectedUnits, commandIssueData, false);
    }
  }

  // ---------------------------------------------------------------------
  // The ISSUE_FactoryCommand / ISSUE_RemoveLastCommand /
  // ISSUE_RemoveCommandFromUnitQueue family. Both of the binary callers this
  // family exists for are now recovered and call into it by name:
  //   - Moho::SCommandModeData::HandleEvent (0x0081FCD0) is defined further
  //     down this file and calls the `WeakSet<UserEntity>` overload of
  //     ISSUE_RemoveLastCommand from its RULEUCC_Attack arm;
  //   - Moho::CUIWorldView::HandleEvent (0x008704B0, moho/ui/UiRuntimeTypes.cpp)
  //     calls ISSUE_RemoveCommandFromUnitQueue from its shift+ctrl
  //     right-button-release arm, through the declaration in CWldSession.h.
  // ---------------------------------------------------------------------

  /**
   * Address: 0x008B5B50 (FUN_008B5B50, struct_CommandManager::NextCmdId)
   *
   * Recovered in Sim.cpp as a file-scope helper (no header declaration, so
   * it cannot be called from this translation unit as written - same
   * cross-TU gap as `func_OnCommandDragEnd`/moho/ui/CommandDragger.cpp).
   * Declared here to document the real call `ISSUE_FactoryCommand` makes.
   * Allocates one next command low-id from the manager's id-pool (released
   * set first, then sequential cursor), packs the active source byte into
   * the high byte, and writes the result to `outCommandId` (also returned).
   */
  // The top-level `const` on both parameters is load-bearing, not style:
  // MSVC decorates a `T* const` parameter as `QA...` and a plain `T*` as
  // `PA...`, so a declaration that drops it does not name the definition in
  // Sim.cpp. That mismatch is what left this call unresolved -
  // `?...@moho@@YAPAIPAUCommandManager@1@PAI@Z` wanted here against
  // `?...@moho@@YAPAIQAUCommandManager@1@QAI@Z` defined there.
  [[nodiscard]] std::uint32_t* AllocatePackedCommandIdFromManager(
    CommandManager* const commandManager, std::uint32_t* const outCommandId
  ) noexcept;

  /**
   * Address: 0x008B00A0 (FUN_008B00A0, func_DecodeEntIdSet)
   *
   * Recovered in Sim.cpp as a file-scope helper - same cross-TU gap as
   * `AllocatePackedCommandIdFromManager` above. Declared here to document
   * the real call `ISSUE_FactoryCommand` makes: builds an entity-id set from
   * a list of selected user units.
   */
  void func_DecodeEntIdSet(BVSet<EntId, EntIdUniverse>& out, const gpg::fastvector<UserUnit*>& units);

  /**
   * Address: 0x008B0730 (FUN_008B0730,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z)
   *
   * IDA note: the decompiler flags this function's own local-variable
   * allocation as failed ("the output may be wrong!"), so its pseudocode is
   * lower-confidence than usual. The structure below is cross-checked
   * against the already-recovered sibling `ISSUE_Command(const
   * gpg::fastvector<UserUnit*>&, SSTICommandIssueData, bool)` (Sim.cpp),
   * which shares the same no-rush gate, id-allocation, and per-unit queue
   * bookkeeping shape almost verbatim - factory commands go through
   * `GetFactoryCommandQueue()`/`IssueFactoryCommand` instead of the plain
   * command queue/`IssueCommand`. The `struct_UserUnitManager::add` call
   * passes the issue data's `mIndex` as its 4th argument, exactly as
   * `ISSUE_Command`'s does (0x008B0566 pushes `data+0x08`); -1 appends.
   *
   * What it does:
   * Client/UI-side factory-command issue keystone over an explicit
   * `UserUnit*` list (factories): allocates a command id, runs the no-rush
   * gate against the resolved target, dispatches to the sim driver's
   * `IssueFactoryCommand`, publishes/reuses the command-issue helper, and
   * enqueues it into each unit's *factory* command queue (capped at 500
   * queued entries unless `clearQueue` forces a reset).
   */
  void ISSUE_FactoryCommand(
    const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData commandIssueData, const bool clearQueue
  )
  {
    CWldSession* const session = WLD_GetActiveSession();
    CommandManager* const commandManager = session->mCommandManager;
    STIMap* const playableMap = session->mWldMap->mTerrainRes->mMap;

    std::uint32_t packedCommandId = 0u;
    commandIssueData.nextCommandId =
      static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(commandManager, &packedCommandId));
    if ((static_cast<std::uint32_t>(commandIssueData.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
      return; // id-pool exhausted for this command source; nothing to issue.
    }

    // No-rush / playability gate - identical shape to ISSUE_Command's own
    // gate (Sim.cpp) and Moho::ISSUE_SetCommandTarget's (Sim.cpp).
    if (commandIssueData.mTarget.mType != EAiTargetType::AITARGET_None) {
      constexpr float kInvalidLane = std::numeric_limits<float>::quiet_NaN();
      Wm3::Vec3f targetPoint{kInvalidLane, kInvalidLane, kInvalidLane};

      if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
        if (UserEntity* const targetEntity = session->LookupEntityId(static_cast<EntId>(commandIssueData.mTarget.mEnt))) {
          targetPoint = targetEntity->mVariableData.mCurTransform.pos_;
        }
      } else {
        targetPoint = commandIssueData.mTarget.mPos;
      }

      const std::int32_t focusArmyIndex = session->FocusArmy;
      if (IsValidVector3f(targetPoint) && focusArmyIndex >= 0 &&
          session->userArmies[static_cast<std::size_t>(focusArmyIndex)] != nullptr) {
        const UserArmy* const focusArmy = session->GetFocusArmy();
        const bool insidePlayableArea =
          focusArmy->mVarDat.mUseWholeMap != 0u || playableMap == nullptr || playableMap->IsPlayable(targetPoint);

        if (!insidePlayableArea) {
          return;
        }
        if (focusArmy->mVarDat.mNoRushTimer > 0) {
          const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPoint.x;
          const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPoint.z;
          const float noRushDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (noRushDistance > focusArmy->mVarDat.mNoRushRadius) {
            return;
          }
        }
      }
    }

    BVSet<EntId, EntIdUniverse> issuedEntitySet{};
    func_DecodeEntIdSet(issuedEntitySet, units);
    if (ISTIDriver* const simDriver = sSimDriver.get()) {
      simDriver->IssueFactoryCommand(issuedEntitySet, commandIssueData, clearQueue);
    }

    SSTICommandConstantData commandConstantData{};
    InitializePublishedCommandDescriptorFromIssueData(&commandConstantData, &commandIssueData);

    const CmdId commandId = static_cast<CmdId>(commandIssueData.nextCommandId);
    UserCommandIssueHelper* const commandHelper =
      FindOrCreateCommandIssueHelper(*commandManager, commandConstantData, 1u, commandId);
    commandHelper->mVariableData = SSTICommandVariableData(commandIssueData);
    commandHelper->mVariableDataDirty = 1u;

    for (UserUnit* const unit : units) {
      UserCommandQueue* const factoryQueue = unit->GetFactoryCommandQueue();
      if (factoryQueue == nullptr) {
        continue;
      }

      if (GetUserUnitManagerQueueSize(factoryQueue) <= 500) {
        if (clearQueue) {
          ResetUserUnitManagerState(factoryQueue, commandId);
        }
        UserUnitManagerAdd(factoryQueue, commandHelper, commandId, commandIssueData.mIndex);
      } else if (clearQueue) {
        ResetUserUnitManagerState(factoryQueue, commandId);
        UserUnitManagerAdd(factoryQueue, commandHelper, commandId, commandIssueData.mIndex);
      }
    }

    UI_OnCommandIssued(units, commandIssueData, clearQueue);
    session->DirtyCommandGraph();
  }

  /**
   * Address: 0x008B0B30 (FUN_008B0B30,
   * ?ISSUE_FactoryCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes (inline-buffered fastvector, capacity pre-reserved from the set
   * size) and forwards to the explicit-unit `ISSUE_FactoryCommand`
   * overload, which takes the command payload by value (copy-constructed on
   * the stack here). Identical shape to `ISSUE_Command`'s own weak-set
   * overload (CWldSession.cpp).
   */
  void ISSUE_FactoryCommand(
    const WeakSet<UserEntity>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    ISSUE_FactoryCommand(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x008B1270 (FUN_008B1270,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_RemoveLastCommand(gpg::fastvector<Moho::UserUnit *> const &);
   *
   * What it does:
   * For each unit in `units`: resolves its command queue's most-recently
   * queued command helper (backward null-skip scan via
   * `GetUserUnitManagerLastQueuedHelper`), skipping units with no queue or
   * no queued helper at all. For each match: tells the active sim driver
   * to remove that command from the unit's server-side queue (by CmdId +
   * EntId), then records the removal locally via
   * `RecordUnitManagerCommandHelperRemoval` (UserUnit.h) - see that
   * declaration's doc comment for the `unitCount` tag-value oddity both
   * call sites here share. Finally marks the session's UI command graph
   * dirty so the graph overlay redraws.
   *
   * Invocation: sole caller is the `WeakSet<UserEntity>` overload of
   * `Moho::ISSUE_RemoveLastCommand` (FUN_008B1390, below), which calls it by
   * name a few lines down; that overload is in turn called by
   * `Moho::SCommandModeData::HandleEvent` (FUN_0081FCD0, recovered in this
   * file) from its `RULEUCC_Attack` arm.
   */
  void ISSUE_RemoveLastCommand(const gpg::fastvector<UserUnit*>& units)
  {
    const std::int32_t unitCount = static_cast<std::int32_t>(units.Size());

    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      UserCommandQueue* const manager = unit->GetCommandQueue();
      UserCommandIssueHelper* const lastHelper = GetUserUnitManagerLastQueuedHelper(manager);
      if (lastHelper == nullptr) {
        continue;
      }

      const EntId entityId = unit->mParams.mEntityId;
      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        (void)simDriver->RemoveCommandFromUnitQueue(lastHelper->mConstantData.cmd, entityId);
      }

      RecordUnitManagerCommandHelperRemoval(lastHelper, manager, unitCount);
    }

    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      session->DirtyCommandGraph();
    }
  }

  /**
   * Address: 0x008B1390 (FUN_008B1390,
   * ?ISSUE_RemoveLastCommand@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveLastCommand(Moho::WeakSet_UserEntity *a1@<ebx>);
   *
   * What it does:
   * Collects every live `UserUnit` in `entities` into a
   * `gpg::fastvector<UserUnit*>` (reserving up front for the weak-set's
   * live size) and forwards to the `gpg::fastvector<UserUnit*>` overload
   * of `ISSUE_RemoveLastCommand` (FUN_008B1270, above).
   *
   * Invocation: sole caller is `Moho::SCommandModeData::HandleEvent`
   * (FUN_0081FCD0, recovered in this file), from the `RULEUCC_Attack` arm
   * at 0x0081FDB9 when the event replaces a command the same drag issued.
   */
  void ISSUE_RemoveLastCommand(WeakSet<UserEntity>& entities)
  {
    gpg::fastvector<UserUnit*> units{};
    units.reserve(entities.Size());

    for (UserEntity* const entity : entities) {
      if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
        units.push_back(unit);
      }
    }

    ISSUE_RemoveLastCommand(units);
  }

  /**
   * Address: 0x008B1220 (FUN_008B1220)
   * Mangled: ?ISSUE_RemoveCommandFromUnitQueue@Moho@@YAXPAVUserCommand@1@PAVUserUnit@1@@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_RemoveCommandFromUnitQueue(
   *     Moho::UserCommand *command@<ebx>, Moho::UserUnit *unit@<esi>);
   *
   * What it does:
   * Removes exactly one queued command from exactly one unit. Null-tolerant on
   * both arguments (0x008B1223 / 0x008B1228). Tells the active sim driver to
   * drop `command`'s constant command id from `unit`'s server-side queue
   * (`ISTIDriver` vtable +0x80, 0x008B123C-0x008B1247), then records the local
   * removal against the unit's own command queue.
   *
   * Two details differ from the `ISSUE_RemoveLastCommand` sibling above and are
   * preserved verbatim:
   *   - the driver pointer is dereferenced unguarded (0x008B1232 loads the
   *     global and immediately reads its vptr); the sibling's null check is a
   *     property of that function, not of this one;
   *   - the tag handed to `RecordUnitManagerCommandHelperRemoval` is the `CmdId`
   *     the driver call returned through its sret slot (read back at
   *     0x008B1249 and pushed at 0x008B124F), not a unit count. The push
   *     happens *before* `GetCommandQueue` is dispatched (0x008B1255), so the
   *     evaluation order below matches the binary's.
   *
   * Invocation: sole call site in the image is `Moho::CUIWorldView::HandleEvent`
   * (0x008704B0) at 0x00871082, inside the shift+ctrl right-button-release loop
   * that strips the hovered command from every unit under the cursor. That
   * caller is recovered in moho/ui/UiRuntimeTypes.cpp and calls this by name.
   */
  void ISSUE_RemoveCommandFromUnitQueue(UserCommandIssueHelper* const command, UserUnit* const unit)
  {
    if (command == nullptr || unit == nullptr) {
      return;
    }

    const CmdId removedCommandId =
      sSimDriver.get()->RemoveCommandFromUnitQueue(command->mConstantData.cmd, unit->mParams.mEntityId);

    UserCommandQueue* const manager = unit->GetCommandQueue();
    RecordUnitManagerCommandHelperRemoval(command, manager, removedCommandId);
  }

  /**
   * Address: 0x008B4300 (FUN_008B4300, sub_8B4300)
   *
   * What it does:
   * Header-visible bridge over `IsCandidateExcludedByCachedRelation` (the
   * anonymous-namespace body earlier in this file), so callers outside this
   * translation unit can run the command-graph participant gate.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008706C6 while scanning the selection for a participant of the hovered
   * command.
   */
  bool IsCommandCandidateExcludedByCachedRelation(
    UserCommandIssueHelper& command,
    UserUnit* const candidateUnit
  ) noexcept
  {
    return IsCandidateExcludedByCachedRelation(command, candidateUnit);
  }

  /**
   * Address: 0x0081DD00 (FUN_0081DD00, sub_81DD00)
   *
   * What it does:
   * Header-visible bridge over `CanRestartMoveCommandAsPatrol` (the
   * anonymous-namespace body earlier in this file). Both parameter types are
   * already public, so this only lifts the linkage.
   *
   * Invocation: `Moho::CUIWorldView::HandleEvent` (0x008704B0) calls it at
   * 0x008707FC to gate the "convert moves into patrol" cursor banner; the
   * in-file caller `SCommandModeData::HandleEvent` keeps calling the
   * anonymous-namespace body directly.
   */
  bool CanRestartSelectionMoveCommandAsPatrol(
    WeakSet<UserEntity>& selection,
    UserCommandIssueHelper* const helper
  )
  {
    return CanRestartMoveCommandAsPatrol(selection, helper);
  }

  namespace
  {
    /// The `EntId` sentinel every ground-targeted command payload carries
    /// (`mov [target+4], 0F0000000h` at every ground-target site in
    /// `SCommandModeData::HandleEvent`).
    constexpr std::uint32_t kGroundTargetEntityId = 0xF0000000u;

    /// Cursor-banner lifetime shared by both banners this dispatcher raises
    /// (`flt_E4F718`, pushed at 0x0081FEC6 and 0x008207FC).
    constexpr float kCursorBannerSeconds = 3.0f;
    /// ARGB red (0x0081FED2).
    constexpr std::uint32_t kCoordinatedAttackBannerColor = 0xFFFF0000u;
    /// ARGB green (0x0082080B).
    constexpr std::uint32_t kPatrolInitiatedBannerColor = 0xFF00FF00u;

    /**
     * A `CmdId` packs the issuing command source into its high byte, and the
     * `(MouseInfo, modifiers)` command-mode constructor (0x0081CEA0) seeds
     * `mIsDragged` with an all-ones id. `HandleEvent` therefore tests only the
     * source byte for the "this drag is not editing a live command" sentinel
     * (0x0081FEA6 and 0x0082078E), not the whole word.
     */
    [[nodiscard]] bool HasDraggedCommand(const CommandModeData& commandMode) noexcept
    {
      constexpr std::uint32_t kCommandSourceMask = 0xFF000000u;
      return (static_cast<std::uint32_t>(commandMode.mIsDragged) & kCommandSourceMask) != kCommandSourceMask;
    }

    /// `SCommandModeData::mModifiers` bit lanes, unpacked in one block at
    /// 0x0081FD00-0x0081FD24 before the mode switch runs.
    enum ECommandModeModifier : std::int32_t
    {
      /// Append to the existing command queue instead of replacing it.
      COMMODMOD_Queue = 0x1,
      /// Force the formation ("form") variant of the issued command.
      COMMODMOD_Formation = 0x2,
      /// Turn a plain move order into an aggressive-move order.
      COMMODMOD_AttackMove = 0x4,
    };

    /**
     * The drag snapshot stores the cursor in screen space as a plain
     * `Wm3::Vector2f`; the cursor-banner API names the same two floats
     * `SMauiMousePos` (the binary just hands `&mMouseScreenPos` over in `ecx`
     * at 0x0081FEDA / 0x00820813).
     */
    [[nodiscard]] SMauiMousePos ToMauiMousePos(const Wm3::Vector2f& screenPos) noexcept
    {
      return SMauiMousePos{screenPos.x, screenPos.y};
    }

    void SetEntityTarget(SSTICommandIssueData& data, const UserEntity& target) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Entity;
      data.mTarget.mEntityId = static_cast<std::uint32_t>(target.mParams.mEntityId);
      data.mTarget.mPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    }

    void SetGroundTarget(SSTICommandIssueData& data, const Wm3::Vector3f& worldPos) noexcept
    {
      data.mTarget.mType = EAiTargetType::AITARGET_Ground;
      data.mTarget.mEntityId = kGroundTargetEntityId;
      data.mTarget.mPos = worldPos;
    }

    /**
     * Copies the drag formation's chosen script index, heading quaternion and
     * spacing scale into the payload's formation lanes - the same
     * `unk38`/`mOri`/`unk4C` triple `CPlatoon`'s own Form* command builders
     * fill (CPlatoon.cpp).
     */
    void ApplyFormationLanes(SSTICommandIssueData& data, const CFormation& formation) noexcept
    {
      data.unk38 = formation.mBestFormation;
      data.mOri = formation.mDirection;
      data.unk4C = formation.mDirectionScale;
    }

    /// The drag formation has settled on a usable script and stopped ticking.
    [[nodiscard]] bool IsFormationSettled(const CFormation& formation) noexcept
    {
      return formation.mReady && formation.mTimeLeft == 0.0f;
    }

    /// Issues `commandType` at the hovered entity for the whole selection.
    void IssueOrderAtEntity(
      WeakSet<UserEntity>& selection,
      const EUnitCommandType commandType,
      const UserEntity& target,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetEntityTarget(commandData, target);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /// Issues `commandType` at a world position for the whole selection.
    void IssueOrderAtGround(
      WeakSet<UserEntity>& selection,
      const EUnitCommandType commandType,
      const Wm3::Vector3f& worldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(commandType);
      SetGroundTarget(commandData, worldPos);
      ISSUE_Command(selection, commandData, clearQueue);
    }

    /**
     * The "snap the group anchor to the terrain, then re-issue at the drag
     * position" tail both the `RULEUCC_Patrol` and `RULEUCC_Ferry` arms run
     * when their anchor resolver reports the group is not already doing this
     * exact thing. The second issue always passes `clearQueue == false` so it
     * appends behind the first.
     */
    template <typename TIssueFn>
    void IssueAnchoredThenDragPosition(
      SSTICommandIssueData& commandData,
      const CWldSession& session,
      const Wm3::Vector3f& groupAnchor,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue,
      TIssueFn&& issue
    )
    {
      const float anchorSurface = session.GetSTIMap()->GetSurface(groupAnchor);
      SetGroundTarget(commandData, Wm3::Vector3f(groupAnchor.x, anchorSurface, groupAnchor.z));
      issue(commandData, clearQueue);

      SetGroundTarget(commandData, dragWorldPos);
      issue(commandData, false);
    }

    /**
     * Address: 0x0081FF17-0x0082012A (the `RULEUCC_Attack` no-hover arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into units eligible for an attack-move
     * (mobile + `FIRESTATE_ReturnFire`) and everything else, then issues an
     * AggressiveMove at the drag position to the first group and a plain
     * ground Attack to the second.
     */
    void IssueAttackMoveToGround(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool formationModifier,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity> otherUnits;
      WeakSet<UserEntity> aggressiveMoveUnits;
      SplitSelectionForAggressiveMove(selection, aggressiveMoveUnits, otherUnits);

      if (!aggressiveMoveUnits.Empty()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_AggressiveMove);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        if (aggressiveMoveUnits.Size() > 1 && formationModifier) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAggressiveMove;
          destination = formation.mFinish;
        }

        SetGroundTarget(commandData, destination);
        ISSUE_Command(aggressiveMoveUnits, commandData, clearQueue);
      }

      if (!otherUnits.Empty()) {
        IssueOrderAtGround(otherUnits, EUnitCommandType::UNITCOMMAND_Attack, dragWorldPos, clearQueue);
      }
    }

    /**
     * Address: 0x00820661-0x00820B37 (the `RULEUCC_Move` arm of
     * `Moho::SCommandModeData::HandleEvent`, also entered from the
     * `RULEUCC_Guard` arm once the drag formation has settled)
     *
     * What it does:
     * Splits the selection into rally-point holders and everything else, then
     * issues Move/AggressiveMove (or their Form* variants once the drag
     * formation has settled and more than one unit is moving) to the plain
     * units and the same order as a *factory* command to the rally-point
     * holders. Before issuing the plain order it offers the "keep dragging an
     * already-queued move to convert it into a patrol" shortcut: when the drag
     * is editing a live command whose queue passes
     * `CanRestartMoveCommandAsPatrol`, the queued commands are restarted as
     * Patrol/FormPatrol in place, a cursor banner is shown and **nothing** is
     * issued - not even the rally-point half.
     */
    void IssueMoveOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const EUnitCommandType moveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_AggressiveMove
        : EUnitCommandType::UNITCOMMAND_Move;
      const EUnitCommandType formMoveCommand = attackMoveModifier
        ? EUnitCommandType::UNITCOMMAND_FormAggressiveMove
        : EUnitCommandType::UNITCOMMAND_FormMove;

      if (!otherUnits.Empty()) {
        const CFormation& formation = *session.mCurFormation;
        SSTICommandIssueData commandData(moveCommand);
        ApplyFormationLanes(commandData, formation);

        Wm3::Vector3f destination = dragWorldPos;
        // The stock build short-circuits this on the formation modifier the
        // way the RULEUCC_Attack arm above does; in the shipped FAF binary the
        // `jnz` that did so is NOP'd out at 0x0082074D-0x0082074E, leaving only
        // the settled-formation test. Recovered as shipped.
        if (otherUnits.Size() > 1 && IsFormationSettled(formation)) {
          commandData.mCommandType = formMoveCommand;
          destination = formation.mFinish;
        }
        SetGroundTarget(commandData, destination);

        if (HasDraggedCommand(commandMode)) {
          UserCommandIssueHelper* const draggedCommand =
            FindCommandIssueHelperInSession(&session, commandMode.mIsDragged);
          if (CanRestartMoveCommandAsPatrol(selection, draggedCommand)) {
            RestartMoveCommandAsPatrol(selection, draggedCommand);
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0012>Patrol Initiated to location!",
              kPatrolInitiatedBannerColor,
              kCursorBannerSeconds,
              true
            );
            return;
          }
        }

        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.Empty()) {
        SSTICommandIssueData rallyCommandData(moveCommand);
        SetGroundTarget(rallyCommandData, dragWorldPos);
        ISSUE_FactoryCommand(rallyPointUnits, rallyCommandData, clearQueue);
      }
    }

    /**
     * Address: 0x008203CE-0x0082065C (the `RULEUCC_Guard` arm of
     * `Moho::SCommandModeData::HandleEvent`, reached once the drag formation
     * is *not* settled)
     *
     * What it does:
     * Guarding a hovered unit targets it directly, except when it is a
     * STRUCTURE: then the selection is split by the REBUILDER category so the
     * rebuilders are aimed at the structure's own world position (they can
     * rebuild the wreck in place) while everybody else guards the entity, both
     * halves carrying the structure's blueprint. With nothing hovered the
     * order becomes a guard-this-spot for every mobile selected entity, in
     * formation when more than one of them takes it.
     */
    void IssueGuardOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const EUnitCommandType guardCommand = UnitCommandCapToCommandType(commandMode.mCommandCaps);

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const RUnitBlueprint* const hoveredBlueprint = GetIUnitBridge(hoveredUnit)->GetBlueprint();

        bool hoveredIsStructure = false;
        if (hoveredBlueprint != nullptr) {
          const msvc8::string structureCategory("STRUCTURE");
          hoveredIsStructure = hovered->IsInCategory(structureCategory);
        }

        if (!hoveredIsStructure) {
          IssueOrderAtEntity(selection, guardCommand, *hovered, clearQueue);
          return;
        }

        WeakSet<UserEntity> nonRebuilders;
        WeakSet<UserEntity> rebuilders;
        SplitSelectionByRebuilderCategory(selection, nonRebuilders, rebuilders);

        {
          SSTICommandIssueData commandData(guardCommand);
          SetEntityTarget(commandData, *hovered);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(nonRebuilders, commandData, clearQueue);
        }
        {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, hovered->mVariableData.mCurTransform.pos_);
          commandData.mBlueprint = const_cast<RUnitBlueprint*>(hoveredBlueprint);
          ISSUE_Command(rebuilders, commandData, clearQueue);
        }
        return;
      }

      WeakSet<UserUnit> formationUnits;
      WeakSet<UserEntity> guardTargets;

      for (UserEntity* const entity : selection) {
        const REntityBlueprint* const blueprint = entity != nullptr ? entity->mParams.mBlueprint : nullptr;
        if (blueprint != nullptr && blueprint->IsMobile()) {
          (void)guardTargets.Add(entity);

          if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
            (void)formationUnits.Add(unit);
          }
        }
      }

      CFormation& formation = *session.mCurFormation;
      if (guardTargets.Size() > 1) {
        formation.ChooseFormation(dragWorldPos, formationUnits, queueModifier);
        if (formation.mBestFormation >= 0) {
          SSTICommandIssueData commandData(UnitCommandCapToCommandType(commandMode.mCommandCaps));
          SetGroundTarget(commandData, dragWorldPos);
          ApplyFormationLanes(commandData, formation);
          ISSUE_Command(guardTargets, commandData, clearQueue);
          formation.Reset();
        }
        return;
      }

      if (!guardTargets.Empty()) {
        IssueOrderAtGround(
          guardTargets, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
        );
      }
    }

    /**
     * Address: 0x00820923-0x00820B37 (the `RULEUCC_Patrol` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Splits the selection into rally-point holders and everybody else, picks
     * Patrol or FormPatrol (the latter only once the drag formation has
     * settled; otherwise a fresh formation is chosen from the selected units
     * around the hovered unit, or around the drag position when nothing is
     * hovered, and the whole arm is abandoned if no formation script fits),
     * then issues that command to both halves. Each half first asks
     * `ResolveGroupMoveAnchorOrDetectPatrol` whether the group is already
     * patrolling: if it is, the drag position is used as-is; if not, the
     * resolved group anchor is snapped to the terrain and issued first so the
     * patrol runs anchor -> drag position.
     */
    void IssuePatrolOrderForDrag(
      CommandModeData& commandMode,
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      CFormation& formation = *session.mCurFormation;
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Patrol);
      SetGroundTarget(commandData, dragWorldPos);

      if (selection.Size() > 1) {
        if (IsFormationSettled(formation)) {
          commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormPatrol;
          ApplyFormationLanes(commandData, formation);
        } else {
          WeakSet<UserUnit> formationUnits;

          for (UserEntity* const entity : selection) {
            if (UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr; unit != nullptr) {
              (void)formationUnits.Add(unit);
            }
          }

          const Wm3::Vector3f& formationAnchor =
            hovered != nullptr ? hovered->mVariableData.mCurTransform.pos_ : dragWorldPos;
          formation.ChooseFormation(formationAnchor, formationUnits, queueModifier);
          if (formation.mBestFormation < 0) {
            return;
          }

          ApplyFormationLanes(commandData, formation);
          formation.Reset();
        }
      }

      if (!otherUnits.Empty()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_Command(otherUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&otherUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_Command(otherUnits, data, clear);
            }
          );
        }
      }

      if (!rallyPointUnits.Empty()) {
        Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
        if (ResolveGroupMoveAnchorOrDetectPatrol(selection, groupAnchor, !queueModifier)) {
          ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
        } else {
          IssueAnchoredThenDragPosition(
            commandData, session, groupAnchor, dragWorldPos, clearQueue,
            [&rallyPointUnits](const SSTICommandIssueData& data, const bool clear) {
              ISSUE_FactoryCommand(rallyPointUnits, data, clear);
            }
          );
        }
      }
    }

    /**
     * Address: 0x008215FD-0x008217CA (the `RULEUCC_Ferry` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Keeps only the air transports out of the selection and gives them a
     * ferry route. When every one of them is already ferrying, the drag
     * position is appended as-is; otherwise their averaged current route
     * anchor is snapped to the terrain and issued first so the ferry runs
     * anchor -> drag position. The land-unit half of the split is built (the
     * binary builds it too) but this arm never consumes it.
     */
    void IssueFerryOrderForDrag(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity> airTransports;
      WeakSet<UserEntity> landUnits;
      SplitSelectionForFerryCommand(selection, airTransports, landUnits);

      if (airTransports.Empty()) {
        return;
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Ferry);
      SetGroundTarget(commandData, dragWorldPos);

      Wm3::Vector3f groupAnchor(0.0f, 0.0f, 0.0f);
      if (ResolveGroupFerryAnchorOrDetectFerry(airTransports, groupAnchor)) {
        ISSUE_Command(airTransports, commandData, clearQueue);
        return;
      }

      IssueAnchoredThenDragPosition(
        commandData, session, groupAnchor, dragWorldPos, clearQueue,
        [&airTransports](const SSTICommandIssueData& data, const bool clear) {
          ISSUE_Command(airTransports, data, clear);
        }
      );
    }

    /**
     * Address: 0x00821014-0x008215BC (the `RULEUCC_Transport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Four separate transport gestures, in the order the binary tests them:
     *   1. drop on a TELEPORTBEACON while a teleport-capable unit is selected
     *      -> unload onto the beacon;
     *   2. drop on a unit that itself has the CallTransport capability
     *      -> reverse-load into it;
     *   3. otherwise, when the session's extra-select list names specific
     *      units, unload exactly those at the drag position (as a plain Move
     *      when every one of them is a POD, since pods are not cargo);
     *   4. otherwise split the selection into air transports and land units:
     *      if either half is empty the whole selection is told to unload at
     *      the drag position, else the transports are folded into the land
     *      group and the group is given an AssistMove there.
     * Every path ends by re-applying the current selection, which is what
     * refreshes the extra-select overlay.
     */
    void IssueTransportOrderForDrag(
      CWldSession& session,
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      if (hovered != nullptr) {
        const msvc8::string teleportBeaconCategory("TELEPORTBEACON");
        if (hovered->IsInCategory(teleportBeaconCategory) && SelectionContainsTeleportationUnit(selection)) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      if (UserUnit* const hoveredUnit = hovered != nullptr ? hovered->IsUserUnit() : nullptr;
          hoveredUnit != nullptr) {
        const std::uint32_t hoveredCaps = GetIUnitBridge(hoveredUnit)->GetAttributes().commandCapsMask;
        if ((hoveredCaps & static_cast<std::uint32_t>(RULEUCC_CallTransport)) != 0u) {
          IssueOrderAtEntity(
            selection, EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits, *hovered, clearQueue
          );
          return;
        }
      }

      WeakSet<UserEntity> extraSelection = session.GetExtraSelectList();

      if (!extraSelection.Empty()) {
        WeakSet<UserEntity> unloadTargets(selection);

        bool onlyPods = true;
        for (UserEntity* const entity : extraSelection) {
          if (entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
            (void)unloadTargets.Add(entity);

            const msvc8::string podCategory("POD");
            if (!entity->IsInCategory(podCategory)) {
              onlyPods = false;
            }
          }
        }

        const EUnitCommandType unloadCommand = onlyPods
          ? EUnitCommandType::UNITCOMMAND_Move
          : EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits;
        // TEMPORARY PROBE -- unload-subset triage, delete when resolved.
        UnloadDragDiagLine(
          "[UNLOADDRAG] specific-branch: extraSelectionEmpty=0 onlyPods=%d cmd=%d pos=(%.1f,%.1f)",
          onlyPods ? 1 : 0, static_cast<int>(unloadCommand), dragWorldPos.x, dragWorldPos.z
        );
        IssueOrderAtGround(unloadTargets, unloadCommand, dragWorldPos, clearQueue);
      } else {
        WeakSet<UserEntity> airTransports;
        WeakSet<UserEntity> landUnits;
        SplitSelectionForFerryCommand(selection, airTransports, landUnits);

        if (airTransports.Empty() || landUnits.Empty()) {
          // TEMPORARY PROBE -- unload-subset triage, delete when resolved. This
          // is the arm that unloads EVERYTHING; reaching it means the extra
          // selection (the cargo the player picked) came back empty.
          UnloadDragDiagLine(
            "[UNLOADDRAG] unload-ALL branch: extraSelectionEmpty=1 airEmpty=%d landEmpty=%d pos=(%.1f,%.1f) "
            "cloneSize=%u",
            airTransports.Empty() ? 1 : 0, landUnits.Empty() ? 1 : 0,
            dragWorldPos.x, dragWorldPos.z, static_cast<unsigned>(extraSelection.Size())
          );
          IssueOrderAtGround(
            selection, EUnitCommandType::UNITCOMMAND_TransportUnloadUnits, dragWorldPos, clearQueue
          );
        } else {
          for (UserEntity* const entity : airTransports) {
            if (entity->mVariableData.mIsDead == 0u && entity->IsUserUnit() != nullptr) {
              (void)landUnits.Add(entity);
            }
          }

          IssueOrderAtGround(landUnits, EUnitCommandType::UNITCOMMAND_AssistMove, dragWorldPos, clearQueue);
        }
      }

      session.SetSelection(selection);
    }

    /**
     * Address: 0x00820E01-0x0082100F (the `RULEUCC_CallTransport` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Tells the selection to load into the hovered transport, splitting the
     * rally-point holders off into a factory command as every other move-like
     * arm does. The hovered transport is added to whichever half is being
     * ordered unless it is a ferry beacon or an air staging platform - a
     * carrier overrides that and is always loaded along with its cargo.
     */
    void IssueCallTransportOrderForDrag(
      WeakSet<UserEntity>& selection,
      UserEntity& hovered,
      const bool clearQueue
    )
    {
      const bool hoveredIsAirStaging = hovered.IsInCategory(msvc8::string("AIRSTAGINGPLATFORM"));
      const bool hoveredIsCarrier = hovered.IsInCategory(msvc8::string("CARRIER"));
      const bool hoveredIsFerryBeacon = hovered.IsInCategory(msvc8::string("FERRYBEACON"));

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
      SetEntityTarget(commandData, hovered);

      WeakSet<UserEntity> rallyPointUnits;
      WeakSet<UserEntity> otherUnits;
      SplitSelectionByRallyPointCategory(selection, rallyPointUnits, otherUnits);

      const bool loadHoveredTransportToo = (!hoveredIsFerryBeacon && !hoveredIsAirStaging) || hoveredIsCarrier;

      if (!otherUnits.Empty()) {
        if (loadHoveredTransportToo) {
          (void)otherUnits.Add(&hovered);
        }
        ISSUE_Command(otherUnits, commandData, clearQueue);
      }

      if (!rallyPointUnits.Empty()) {
        if (loadHoveredTransportToo) {
          (void)rallyPointUnits.Add(&hovered);
        }
        ISSUE_FactoryCommand(rallyPointUnits, commandData, clearQueue);
      }
    }

    /**
     * Address: 0x00821AC0-0x00821CFA (the `RULEUCC_Script` arm of
     * `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * Hands the pending script command to
     * `/lua/user/UserScriptCommand.lua:VerifyScriptCommand` and, when the
     * script sets `UserValidated`, re-issues it to exactly the units the
     * script listed in `AuthorizedUnits`. The verified descriptor rides along
     * on the payload's Lua-object lane (minus `AuthorizedUnits`, which is
     * nilled out first so the sim never sees it).
     */
    void IssueScriptCommandForDrag(
      WeakSet<UserEntity>& selection,
      UserEntity* const hovered,
      const Wm3::Vector3f& dragWorldPos,
      const bool clearQueue
    )
    {
      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Script);
      if (hovered != nullptr) {
        SetEntityTarget(commandData, *hovered);
      } else {
        SetGroundTarget(commandData, dragWorldPos);
      }

      LuaPlus::LuaObject verifyResult = UI_VerifyScriptCommand(selection, commandData, clearQueue);
      if (!verifyResult["UserValidated"].GetBoolean()) {
        return;
      }

      commandData.mObject = verifyResult;
      LuaPlus::LuaState* const state = verifyResult.m_state;

      gpg::fastvector_n<UserUnit*, 1> authorizedUnits{};
      {
        // The binary lets the `operator[]` temporary die right after the
        // iterator is constructed (0x00821C2D) and keeps iterating the freed
        // slot; the table object is held for the whole walk here instead,
        // which is the same traversal without the dangling read.
        LuaPlus::LuaObject authorizedTable = verifyResult["AuthorizedUnits"];
        for (LuaPlus::LuaTableIterator entry(authorizedTable, 1); !entry.m_isDone; entry.Next()) {
          authorizedUnits.push_back(SCR_FromLua_UserUnit(entry.GetValue(), state));
        }
      }

      verifyResult.SetNil("AuthorizedUnits");
      ISSUE_Command(authorizedUnits, commandData, clearQueue);
    }

    /**
     * Address: 0x00821DEE-0x00821EA2 (the `COMMOD_Build`/`COMMOD_BuildAnchored`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * While the session is previewing invalid build placements, validates the
     * drag spot (an anchored build additionally has to be inside the builder's
     * build radius). A legal spot - or a session that is not previewing at all
     * - just notifies the UI script layer that a command was issued; an
     * illegal one instead takes one build off an order this selection already
     * has queued on that same footprint, which is what makes dragging a
     * queued structure back onto itself cancel it.
     */
    void DispatchBuildCommandMode(CommandModeData& commandMode, CWldSession& session, const bool clearQueue)
    {
      WeakSet<UserEntity>& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;
      const auto* const buildBlueprint = static_cast<const RUnitBlueprint*>(commandMode.mBlueprint);

      if (session.mShowInvalidBuildPlacementPreview) {
        const SCoordsVec2 buildPosition{dragWorldPos.x, dragWorldPos.z};

        const bool withinBuildDistance = commandMode.mMode != COMMOD_BuildAnchored
          || USERUNIT_WithinBuildDistance(session, buildBlueprint, buildPosition);

        bool placeable = false;
        if (withinBuildDistance) {
          SOccupationResult occupation{};
          placeable = USERUNIT_CanBeBuiltAt(session, buildBlueprint, buildPosition, false, &occupation, nullptr);
        }

        if (!placeable) {
          if (UserCommandIssueHelper* const queuedOrder =
                FindColocatedQueuedBuildOrder(selection, dragWorldPos, buildBlueprint);
              queuedOrder != nullptr) {
            ISSUE_DecreaseCommandCount(queuedOrder, 1);
          }
          return;
        }
      }

      SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_None);
      UI_OnCommandIssued(selection, commandData, clearQueue);
    }

    /**
     * Address: 0x0081FD6D-0x00821CFA plus the shared tails (the `COMMOD_Order`
     * arm of `Moho::SCommandModeData::HandleEvent`)
     *
     * What it does:
     * The command-capability switch: one arm per `ERuleBPUnitCommandCaps`
     * value the world view can put the cursor into. Everything that is not
     * called out below reduces to "issue this capability's command at the drag
     * position", and `RULEUCC_Invalid` is swallowed outright.
     */
    void DispatchOrderCommandMode(
      CommandModeData& commandMode,
      CWldSession& session,
      UserEntity* const hovered,
      const bool isDragUpdate,
      const bool formationModifier,
      const bool attackMoveModifier,
      const bool queueModifier,
      const bool clearQueue
    )
    {
      WeakSet<UserEntity>& selection = session.mSelection;
      const Wm3::Vector3f& dragWorldPos = commandMode.mMouseDragStart.mMouseWorldPos;

      switch (commandMode.mCommandCaps) {
        case RULEUCC_Move:
          IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
          return;

        case RULEUCC_Attack: {
          // A drag that re-targets the order it already issued withdraws that
          // order first, so the queue never grows while the cursor moves.
          if (isDragUpdate) {
            ISSUE_RemoveLastCommand(selection);
          }

          if (hovered == nullptr) {
            // Deliberate deviation, on by default (ui_AttackGroundIgnoresFireState):
            // retail sends Return Fire mobile units an attack-move here and only
            // the rest a ground Attack. With the switch on, the whole selection
            // attacks the position.
            if (ui_AttackGroundIgnoresFireState) {
              IssueOrderAtGround(selection, EUnitCommandType::UNITCOMMAND_Attack, dragWorldPos, clearQueue);
            } else {
              IssueAttackMoveToGround(session, selection, dragWorldPos, formationModifier, clearQueue);
            }
            return;
          }

          const CFormation& formation = *session.mCurFormation;
          SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_Attack);
          ApplyFormationLanes(commandData, formation);
          if (selection.Size() > 1 && (formationModifier || IsFormationSettled(formation))) {
            commandData.mCommandType = EUnitCommandType::UNITCOMMAND_FormAttack;
          }
          SetEntityTarget(commandData, *hovered);

          // Several players attacking the same target with one drag get the
          // "coordinated attack" banner and share the dragged order's id.
          if (isDragUpdate && HasDraggedCommand(commandMode)
              && CanStartCoordinatedAttack(session, commandMode.mIsDragged)) {
            UI_StartCursorText(
              ToMauiMousePos(commandMode.mMouseDragStart.mMouseScreenPos),
              "<LOC Engine0011>Coordinated Attack!",
              kCoordinatedAttackBannerColor,
              kCursorBannerSeconds,
              true
            );
            commandData.unk04 = commandMode.mIsDragged;
          }

          ISSUE_Command(selection, commandData, clearQueue);
          return;
        }

        case RULEUCC_Guard:
          // A settled drag formation turns a guard gesture into a formation
          // move (0x0082013F-0x0082014F).
          if (IsFormationSettled(*session.mCurFormation)) {
            IssueMoveOrderForDrag(commandMode, session, selection, attackMoveModifier, queueModifier, clearQueue);
            return;
          }
          IssueGuardOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Patrol:
          IssuePatrolOrderForDrag(commandMode, session, selection, hovered, queueModifier, clearQueue);
          return;

        case RULEUCC_Ferry:
          IssueFerryOrderForDrag(session, selection, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Transport:
          IssueTransportOrderForDrag(session, selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_CallTransport:
          if (hovered == nullptr) {
            return;
          }
          IssueCallTransportOrderForDrag(selection, *hovered, clearQueue);
          return;

        case RULEUCC_Script:
          IssueScriptCommandForDrag(selection, hovered, dragWorldPos, clearQueue);
          return;

        case RULEUCC_Reclaim: {
          if (hovered == nullptr) {
            return;
          }

          bool reclaimable = false;
          {
            const msvc8::string reclaimableCategory("RECLAIMABLE");
            reclaimable = hovered->IsInCategory(reclaimableCategory) || hovered->IsBeingBuilt();
          }
          if (!reclaimable) {
            return;
          }

          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;
        }

        // Sacrifice is its own emitted block in the binary (0x008217CF) but the
        // same source shape as the repair/capture/overcharge group below.
        case RULEUCC_Sacrifice:
        case RULEUCC_Repair:
        case RULEUCC_Capture:
        case RULEUCC_Overcharge:
          if (hovered == nullptr) {
            return;
          }
          IssueOrderAtEntity(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
          );
          return;

        case RULEUCC_Nuke:
        case RULEUCC_Tactical:
        case RULEUCC_SpecialAction:
          if (hovered != nullptr) {
            IssueOrderAtEntity(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), *hovered, clearQueue
            );
          } else {
            IssueOrderAtGround(
              selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
            );
          }
          return;

        case RULEUCC_Invalid:
          return;

        default:
          IssueOrderAtGround(
            selection, UnitCommandCapToCommandType(commandMode.mCommandCaps), dragWorldPos, clearQueue
          );
          return;
      }
    }
  } // namespace

  /**
   * Address: 0x0081FCD0 (FUN_0081FCD0, Moho::SCommandModeData::HandleEvent)
   *
   * IDA signature:
   * void __thiscall Moho::SCommandModeData::HandleEvent(
   *     Moho::SCommandModeData *this, Moho::CWldSession *a2, char a3);
   *
   * What it does:
   * Turns one committed world-view mouse gesture into command traffic for the
   * session's current selection. The drag snapshot this object carries
   * (`mMouseDragStart`) supplies both the world position and the hovered
   * entity; `mModifiers` supplies the three keyboard modifier lanes; `mMode`
   * and `mCommandCaps` select the arm:
   *
   *   - `COMMOD_Order` -> `DispatchOrderCommandMode`, one arm per command
   *     capability (move / attack / guard / patrol / ferry / transport /
   *     call-transport / reclaim / sacrifice+repair+capture+overcharge /
   *     nuke+tactical+special-action / script), each of them documented on its
   *     own helper above;
   *   - `COMMOD_Build`, `COMMOD_BuildAnchored` -> `DispatchBuildCommandMode`,
   *     the build-placement validator;
   *   - `COMMOD_Ping` (and the unnamed mode 7 the binary's jump table routes
   *     to the same entry) -> just leave command mode;
   *   - `COMMOD_Move` and `COMMOD_Reclaim` are *not* handled here (the jump
   *     table sends them to the default arm): those modes are cursor states
   *     the world view resolves into a `COMMOD_Order` before committing.
   *
   * Every arm shares one derived flag: `clearQueue` is the inverse of the
   * queue modifier, so holding shift appends the new order instead of
   * replacing the queue.
   */
  void CommandModeData::HandleEvent(CWldSession& session, const bool isDragUpdate)
  {
    const bool queueModifier = (mModifiers & COMMODMOD_Queue) != 0;
    const bool formationModifier = (mModifiers & COMMODMOD_Formation) != 0;
    const bool attackMoveModifier = (mModifiers & COMMODMOD_AttackMove) != 0;
    const bool clearQueue = !queueModifier;

    UserEntity* const hovered = DecodeHoveredDragEntity(mMouseDragStart);

    switch (mMode) {
      case COMMOD_Order:
        DispatchOrderCommandMode(
          *this, session, hovered, isDragUpdate, formationModifier, attackMoveModifier, queueModifier, clearQueue
        );
        return;

      case COMMOD_Build:
      case COMMOD_BuildAnchored:
        DispatchBuildCommandMode(*this, session, clearQueue);
        return;

      case COMMOD_Ping:
      // The jump table at 0x00821F04 routes mode 7 to the same entry as
      // `COMMOD_Ping`.
      case COMMOD_CancelCommandMode:
        UI_EndCommandMode();
        return;

      default:
        return;
    }
  }

  /**
   * Address: 0x0083E150 (FUN_0083E150, func_UserScriptCommandObj)
   *
   * What it does:
   * Builds one Lua command-issue descriptor table (`Units`, `Blueprint`,
   * `Target`, optional `LuaParams`, `CommandType`, `Clear`) used by UI script
   * command callbacks.
   */
  LuaPlus::LuaObject* BuildUserScriptCommandObject(
    LuaPlus::LuaObject* const outCommandObject,
    LuaPlus::LuaState* const state,
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    if (outCommandObject == nullptr || state == nullptr) {
      return outCommandObject;
    }

    outCommandObject->AssignNewTable(state, 0, 0);

    LuaPlus::LuaObject unitsTable;
    unitsTable.AssignNewTable(state, 0, 0);
    std::int32_t unitIndex = 1;
    for (UserUnit* const unit : units) {
      if (unit == nullptr) {
        ++unitIndex;
        continue;
      }

      IUnit* const iunitBridge = GetIUnitBridge(unit);
      if (iunitBridge == nullptr) {
        ++unitIndex;
        continue;
      }

      const LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      unitsTable.SetObject(unitIndex, unitLuaObject);
      ++unitIndex;
    }
    outCommandObject->SetObject("Units", unitsTable);

    const char* blueprintId = "";
    if (commandIssueData.mBlueprint != nullptr) {
      blueprintId = commandIssueData.mBlueprint->mBlueprintId.c_str();
    }
    outCommandObject->SetString("Blueprint", blueprintId);

    LuaPlus::LuaObject targetTable;
    targetTable.AssignNewTable(state, 0, 0);

    ESTITargetType targetType = static_cast<ESTITargetType>(static_cast<std::int32_t>(commandIssueData.mTarget.mType));
    gpg::RRef targetTypeRef{};
    targetTypeRef = gpg::MakeRRef<moho::ESTITargetType>(&targetType);
    const msvc8::string targetTypeLexical = targetTypeRef.GetLexical();
    targetTable.SetString("Type", targetTypeLexical.c_str());

    if (commandIssueData.mTarget.mType == EAiTargetType::AITARGET_Entity) {
      const EntId targetEntityId = static_cast<EntId>(commandIssueData.mTarget.mEntityId);
      if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
        if (UserEntity* const targetEntity = session->LookupEntityId(targetEntityId); targetEntity != nullptr) {
          const msvc8::string entityIdLexical = gpg::STR_Printf("%d", static_cast<std::int32_t>(targetEntityId));
          targetTable.SetString("EntityId", entityIdLexical.c_str());

          const LuaPlus::LuaObject targetPositionObject =
            SCR_ToLua<Wm3::Vector3<float>>(state, targetEntity->mVariableData.mCurTransform.pos_);
          targetTable.SetObject("Position", targetPositionObject);
        }
      }
    } else {
      const LuaPlus::LuaObject targetPositionObject =
        SCR_ToLua<Wm3::Vector3<float>>(state, commandIssueData.mTarget.mPos);
      targetTable.SetObject("Position", targetPositionObject);
    }

    outCommandObject->SetObject("Target", targetTable);

    if (commandIssueData.mObject.m_state != nullptr) {
      const LuaPlus::LuaObject luaParams = SCR_Copy(commandIssueData.mObject, state);
      outCommandObject->SetObject("LuaParams", luaParams);
    }

    EUnitCommandType commandType = commandIssueData.mCommandType;
    gpg::RRef commandTypeRef{};
    commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&commandType);
    const msvc8::string commandTypeLexical = commandTypeRef.GetLexical();
    outCommandObject->SetString("CommandType", commandTypeLexical.c_str());
    outCommandObject->SetBoolean("Clear", doClear);
    return outCommandObject;
  }

  /**
   * Address: 0x0083E640 (FUN_0083E640,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one script command descriptor from explicit `UserUnit*` lanes,
   * calls `/lua/user/UserScriptCommand.lua:VerifyScriptCommand`, and returns
   * the Lua result object (or the command descriptor on callback failure).
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    if (state == nullptr) {
      return commandObject;
    }

    LuaPlus::LuaObject commandModule = SCR_Import(state, "/lua/user/UserScriptCommand.lua");
    LuaPlus::LuaObject verifyScriptCommand = commandModule["VerifyScriptCommand"];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> verifyScriptCommandFn(verifyScriptCommand);
    try {
      return verifyScriptCommandFn.Call_Object_Obj(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/user/UserScriptCommand.lua:VerifyScriptCommand': %s", "<unknown>");
    }

    return commandObject;
  }

  /**
   * Address: 0x0083E500 (FUN_0083E500,
   * ?UI_VerifyScriptCommand@Moho@@YA?AVLuaObject@LuaPlus@@ABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_VerifyScriptCommand` overload.
   */
  LuaPlus::LuaObject UI_VerifyScriptCommand(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    return UI_VerifyScriptCommand(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x0083E770 (FUN_0083E770,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Builds one Lua command descriptor table from explicit `UserUnit*` lanes and
   * invokes `/lua/ui/game/commandmode.lua:OnCommandIssued`.
   */
  void UI_OnCommandIssued(
    const gpg::fastvector<UserUnit*>& units,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = (uiManager != nullptr) ? uiManager->mLuaState : nullptr;
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject commandObject{};
    (void)BuildUserScriptCommandObject(&commandObject, state, units, commandIssueData, doClear);

    LuaPlus::LuaObject commandModeModule = SCR_Import(state, "/lua/ui/game/commandmode.lua");
    LuaPlus::LuaObject onCommandIssued = commandModeModule["OnCommandIssued"];
    LuaPlus::LuaFunction callback(onCommandIssued);

    try {
      callback.Call_Object(commandObject);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/game/commandmode.lua:OnCommandIssued': %s", "<unknown>");
    }
  }

  /**
   * Address: 0x0083E870 (FUN_0083E870,
   * ?UI_OnCommandIssued@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*`
   * lanes and forwards to the explicit-unit `UI_OnCommandIssued` overload.
   */
  void UI_OnCommandIssued(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool doClear
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    UI_OnCommandIssued(selectedUnits, commandIssueData, doClear);
  }

  /**
   * Address: 0x008B05E0 (FUN_008B05E0,
   * ?ISSUE_Command@Moho@@YAXABV?$WeakSet@VUserEntity@Moho@@@1@ABUSSTICommandIssueData@1@_N@Z)
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_Command(WeakSet_UserEntity *entities@<ebx>,
   *     SSTICommandIssueData *data, BOOL clearQueue);
   *
   * What it does:
   * Converts one selected weak-set of user entities into live `UserUnit*` lanes
   * (inline-buffered fastvector, capacity pre-reserved from the set size) and
   * forwards to the explicit-unit `ISSUE_Command(fastvector)` overload, which
   * takes the command payload by value (copy-constructed on the stack here).
   */
  void ISSUE_Command(
    const WeakSet<UserEntity>& entities,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    gpg::fastvector_n<UserUnit*, 2> selectedUnits{};
    const std::int32_t entityCount = static_cast<std::int32_t>(entities.Size());
    if (entityCount > 0) {
      selectedUnits.reserve(static_cast<std::size_t>(entityCount));
    }

    for (UserEntity* const selectedEntity : entities) {
      UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
      if (selectedUnit != nullptr) {
        selectedUnits.push_back(selectedUnit);
      }
    }

    ISSUE_Command(selectedUnits, commandIssueData, clearQueue);
  }

  /**
   * Address: 0x00894280 (FUN_00894280, ?LookupEntityId@CWldSession@Moho@@QAEPAVUserEntity@2@VEntId@2@@Z)
   *
   * What it does:
   * Performs one ordered entity-id lookup in the world-session entity map and
   * returns the live `UserEntity*` when the key is present.
   */
  UserEntity* CWldSession::LookupEntityId(const EntId entityId)
  {
    // 0x00894282..0x0089429C: `find`, compare against `end()` (+0x48), return
    // the mapped value.
    const auto it = mEntities.find(static_cast<std::uint32_t>(entityId));
    return it != mEntities.end() ? it->second : nullptr;
  }

  /**
   * Address: 0x00896140 (FUN_00896140, ?SetSelection@CWldSession@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@@Z)
   *
   * What it does:
   * Replaces the active selection set from `selection`, broadcasts one
   * `{previous,current,added,removed}` selection-event payload, updates
   * max-selection bookkeeping, and refreshes sync-filter mask B when changed.
   */
  void CWldSession::SetSelection(const WeakSet<UserEntity>& selection)
  {
    bool selectionChanged = false;

    // What the new selection adds (`Find` 0x00867780 on the current one) and
    // what it drops (`Find` 0x007FDD50 on the new one).
    WeakSet<UserEntity> addedEntities;
    for (UserEntity* const entity : selection) {
      if (mSelection.Find(entity) == mSelection.end()) {
        selectionChanged = true;
        (void)addedEntities.Add(entity);
      }
    }

    WeakSet<UserEntity> removedEntities;
    for (UserEntity* const entity : mSelection) {
      if (selection.Find(entity) == selection.end()) {
        selectionChanged = true;
        (void)removedEntities.Add(entity);
      }
    }

    mSelectionBroadcaster.BroadcastEvent(SSelectionEvent{&mSelection, &selection, &addedEntities, &removedEntities});

    // 0x00896357..0x00896370: the set's assignment (self test, whole-tree
    // erase 0x007AF740, `_Copy` 0x00867B20), then the live count at +0x4AC.
    mSelection = selection;
    mSelectionSize = static_cast<std::uint32_t>(mSelection.Size());

    if (selectionChanged) {
      if (ISTIDriver* const activeDriver = sSimDriver.get(); activeDriver != nullptr) {
        SSyncFilterMaskBlock selectionMask{};
        BuildSelectionSyncMask(mSelection, selectionMask);
        activeDriver->SetSyncFilterMaskB(selectionMask);
      }

      UI_EndCommandMode();
    }
  }

  void CWldSession::SetSelectionUnits(const msvc8::vector<UserUnit*>& units)
  {
    WeakSet<UserEntity> nextSelection;
    for (UserUnit* const unit : units) {
      if (unit != nullptr) {
        (void)nextSelection.Add(unit);
      }
    }

    SetSelection(nextSelection);
  }

  /**
   * Address: 0x00865830 (FUN_00865830, ?CanSelectUnit@CWldSession@Moho@@QBE_NPAVUserUnit@2@@Z)
   */
  bool CWldSession::CanSelectUnit(UserUnit* const unit) const
  {
    const UserEntity* const entity = reinterpret_cast<const UserEntity*>(unit);
    const bool selectableByArmy = entity != nullptr && entity->IsSelectable() && entity->mArmy == GetFocusUserArmy();
    return selectableByArmy || (UI_SelectAnything && this != nullptr && IsCheatsEnabled);
  }

  /**
   * Address: 0x00865920 (FUN_00865920, ?ReleaseDrag@CWldSession@Moho@@QAEXW4EMauiEventModifier@2@@Z)
   */
  void CWldSession::ReleaseDrag(const EMauiEventModifier modifiers)
  {
    constexpr std::uint32_t kShiftMask = static_cast<std::uint32_t>(MEM_Shift);
    constexpr std::uint32_t kCtrlMask = static_cast<std::uint32_t>(MEM_Ctrl);
    constexpr std::uint32_t kAltMask = static_cast<std::uint32_t>(MEM_Alt);
    constexpr std::uint32_t kShiftCtrlMask = kShiftMask | kCtrlMask;

    const std::uint32_t modifierBits = static_cast<std::uint32_t>(modifiers);
    msvc8::vector<UserUnit*> nextSelection{};

    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    UserUnit* const hoveredUnit = hoveredEntity != nullptr ? hoveredEntity->IsUserUnit() : nullptr;

    if (ui_DebugAltClick && (modifierBits & kAltMask) != 0u && hoveredEntity != nullptr) {
      UserArmy* const hoveredArmy = hoveredEntity->mArmy;
      if (hoveredArmy != nullptr && hoveredArmy != GetFocusUserArmy()) {
        SetSelectionUnits(nextSelection);
        RequestFocusArmy(static_cast<int>(hoveredArmy->mArmyIndex));
        return;
      }
    }

    if (!CanSelectUnit(hoveredUnit)) {
      if ((modifierBits & kShiftCtrlMask) == 0u) {
        SetSelectionUnits(nextSelection);
      }
      return;
    }

    if ((modifierBits & kCtrlMask) != 0u) {
      msvc8::vector<UserUnit*> currentSelection{};
      GetSelectionUnits(currentSelection);

      const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
      const RUnitBlueprint* const targetBlueprint = hoveredBridge != nullptr ? hoveredBridge->GetBlueprint() : nullptr;

      if ((modifierBits & kShiftMask) != 0u) {
        if (ContainsUnitPtr(currentSelection, hoveredUnit)) {
          for (UserUnit* const selectedUnit : currentSelection) {
            const IUnit* const selectedBridge = GetIUnitBridge(selectedUnit);
            if (selectedBridge == nullptr || selectedBridge->GetBlueprint() != targetBlueprint) {
              AppendUnitUnique(nextSelection, selectedUnit);
            }
          }

          SetSelectionUnits(nextSelection);
          return;
        }

        nextSelection = currentSelection;
      }

      msvc8::vector<UserUnit*> allSessionUnits{};
      CollectSessionUserUnits(this, allSessionUnits);
      const UserArmy* const focusArmy = GetFocusUserArmy();
      for (UserUnit* const sessionUnit : allSessionUnits) {
        if (sessionUnit == nullptr || sessionUnit->IsBeingBuilt()) {
          continue;
        }

        const IUnit* const sessionBridge = GetIUnitBridge(sessionUnit);
        if (sessionBridge == nullptr || sessionBridge->IsDead()) {
          continue;
        }

        const UserEntity* const sessionEntity = reinterpret_cast<const UserEntity*>(sessionUnit);
        if (sessionEntity == nullptr || sessionEntity->mArmy != focusArmy) {
          continue;
        }

        if (sessionBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        AppendUnitUnique(nextSelection, sessionUnit);
      }

      SetSelectionUnits(nextSelection);
      return;
    }

    if ((modifierBits & kShiftMask) != 0u) {
      GetSelectionUnits(nextSelection);
      if (ContainsUnitPtr(nextSelection, hoveredUnit)) {
        RemoveUnitIfPresent(nextSelection, hoveredUnit);
      } else {
        AppendUnitUnique(nextSelection, hoveredUnit);
      }
    } else {
      AppendUnitUnique(nextSelection, hoveredUnit);
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00865E20 (FUN_00865E20, ?HandleDoubleClickSelection@CWldSession@Moho@@QAEXPAVCameraImpl@2@@Z)
   */
  void CWldSession::HandleDoubleClickSelection(CameraImpl* const camera)
  {
    UserEntity* const hoveredEntity = this->GetHoveredUserEntity();
    if (hoveredEntity == nullptr) {
      return;
    }

    UserUnit* const hoveredUnit = hoveredEntity->IsUserUnit();
    if (hoveredUnit == nullptr) {
      return;
    }

    if (hoveredEntity->IsInCategory(msvc8::string("WALL"))) {
      return;
    }

    if (hoveredEntity->mArmy != GetFocusUserArmy()) {
      return;
    }

    const IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
    if (hoveredBridge == nullptr) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = hoveredBridge->GetBlueprint();
    msvc8::vector<UserUnit*> nextSelection{};
    GetSelectionUnits(nextSelection);

    auto* const frustumUnits = camera != nullptr ? camera->GetArmyUnitsInFrustum() : nullptr;
    if (frustumUnits != nullptr) {
      for (const WeakPtr<UserEntity>& weakRef : *frustumUnits) {
        UserEntity* const entity = weakRef.GetObjectPtr();
        if (entity == nullptr) {
          continue;
        }

        UserUnit* const unit = entity->IsUserUnit();
        if (unit == nullptr || unit == hoveredUnit) {
          continue;
        }

        IUnit* const unitBridge = GetIUnitBridge(unit);
        if (unitBridge == nullptr || unitBridge->IsDead() || unitBridge->DestroyQueued()) {
          continue;
        }

        if (!CanSelectUnit(unit)) {
          continue;
        }

        if (unitBridge->GetBlueprint() != targetBlueprint) {
          continue;
        }

        if (unitBridge->IsUnitState(UNITSTATE_BeingUpgraded)) {
          continue;
        }

        AppendUnitUnique(nextSelection, unit);
      }
    }

    SetSelectionUnits(nextSelection);
  }

  /**
   * Address: 0x00896900 (FUN_00896900, ?GetDelayToNextBeat@CWldSession@Moho@@QBEMXZ)
   */
  float CWldSession::GetDelayToNextBeat() const
  {
    if (mReplayIsPaused != 0u && mLastBeatWasTick != 0) {
      return (std::numeric_limits<float>::infinity)();
    }

    if (mTimeSinceLastTick < 1.0f) {
      return (1.0f - mTimeSinceLastTick) / (WLD_GetSimRate() * 10.0f);
    }

    return 0.0f;
  }

  /**
   * Address: 0x00895FD0 (FUN_00895FD0, ?GetGameTime@CWldSession@Moho@@QBEMXZ)
   *
   * What it does:
   * Returns current game time in seconds.
   */
  float CWldSession::GetGameTime() const
  {
    return (static_cast<float>(mGameTick) + mTimeSinceLastTick) * 0.1f;
  }

  /**
   * Address: 0x00896960 (FUN_00896960, ?SyncPlayableRect@CWldSession@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
   *
   * What it does:
   * Applies one playable rectangle to terrain and updates user-entity mesh
   * hidden flags to match whether each entity lies inside that rectangle.
   */
  void CWldSession::SyncPlayableRect(const gpg::Rect2i& playableRect)
  {
    if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr) {
      (void)ApplyTerrainPlayableRect(mWldMap->mTerrainRes, playableRect);
    }

    for (const auto& [entityId, entity] : mEntities) {
      if (entity == nullptr) {
        continue;
      }

      MeshInstance* const meshInstance = entity->mMeshInstance;
      if (meshInstance == nullptr) {
        continue;
      }

      const int mapX = static_cast<int>(entity->mVariableData.mCurTransform.pos_.x);
      const int mapZ = static_cast<int>(entity->mVariableData.mCurTransform.pos_.z);
      const bool insidePlayableRect = mapX >= playableRect.x0 && mapX < playableRect.x1 && mapZ >= playableRect.z0 &&
        mapZ < playableRect.z1;
      meshInstance->isHidden = insidePlayableRect ? 0u : 1u;
    }
  }

  /**
    * Alias of FUN_00896F00 (non-canonical helper lane).
   * ?GetSaveData@CWldSession@Moho@@QBE?AV?$shared_ptr@USSessionSaveData@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<SSessionSaveData> CWldSession::GetSaveData() const
  {
    boost::shared_ptr<SSessionSaveData> saveData{new SSessionSaveData()};
    // Every unit's named selection sets, keyed by the unit's entity id. This
    // walked the entity map through a third private node layout, called
    // vtable +0x0C through an invented `ISessionSaveSourceProvider` -- that
    // slot is `UserEntity::IsUserUnit` -- and read a tree head at +0x3D4 of the
    // result through `SessionSaveNodeOwnerView`, which is
    // `UserUnit::mSelectionSets` (+0x3D0, head at +0x3D4, 0x2C string nodes).
    for (const auto& [entityId, entity] : mEntities) {
      UserUnit* const unit = entity != nullptr ? entity->IsUserUnit() : nullptr;
      if (unit == nullptr) {
        continue;
      }

      for (const msvc8::string& selectionSet : unit->mSelectionSets) {
        saveData->InsertNodeLabel(entityId, selectionSet);
      }
    }

    return saveData;
  }

  /**
   * Address: 0x0087FC90 (FUN_0087FC90,
   * ?GetScenarioInfo@CWldSession@Moho@@QBE?AVLuaObject@LuaPlus@@XZ)
   *
   * What it does:
   * Returns one value-copy of the session scenario-info Lua object.
   */
  LuaPlus::LuaObject CWldSession::GetScenarioInfo() const
  {
    return LuaPlus::LuaObject(mScenarioInfo);
  }

  /**
   * Address: 0x0081F7B0 (FUN_0081F7B0,
   * ?GetLeftMouseButtonAction@CWldSession@Moho@@QAEAAUCommandModeData@2@PAU32@PBUstruct_MouseInfo@@H@Z)
   */
  CommandModeData* CWldSession::GetLeftMouseButtonAction(
    CommandModeData* const outMode, const MouseInfo* const mouseInfo, const int modifiers
  )
  {
    if (!outMode) {
      return nullptr;
    }

    CommandModeData mode{};
    mode.mMode = COMMOD_None;
    mode.mCommandCaps = RULEUCC_None;
    mode.mBlueprint = nullptr;
    mode.mModifiers = modifiers;
    mode.mIsDragged = -1;
    mode.mReserved5C = -1;
    mode.mMouseDragEnd = MouseInfo{};
    mode.mMouseDragEnd.mIsDragger = -1;

    if (mouseInfo) {
      mode.mMouseDragStart = *mouseInfo;
      mode.mIsDragged = mouseInfo->mIsDragger;

      if (mouseInfo->mHitValid != 0u) {
        bool resolvedByUi = false;
        if (mState && FocusArmy >= 0) {
          const std::size_t focusIndex = static_cast<std::size_t>(FocusArmy);
          if (focusIndex < userArmies.size() && userArmies[focusIndex] != nullptr) {
            UICommandModeData uiMode{};
            UI_GetCommandMode(uiMode);
            {
              if (uiMode.mMode.empty()) {
                resolvedByUi = false;
              } else if (uiMode.mMode == "order") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Order;

                // 0x0081F91C-0x0081F965: the command name is never compared
                // against a fixed list. It is decoded through reflection
                // straight into `mode.mCommandCaps`:
                //
                //   0x0081F947  call LuaObject::GetString      ; the "name" field
                //   0x0081F94E  lea  eax, [esp+mode.mCommandCaps]
                //   0x0081F956  call gpg::RRef_ERuleBPUnitCommandCaps
                //   0x0081F962  mov  eax, [edx+14h]            ; RType::SetLexical
                //   0x0081F965  call eax
                //
                // The enum registers its lexicals as "RULEUCC_Move",
                // "RULEUCC_Repair", ... (RUnitBlueprintEnumTypeInfo.cpp), which
                // is exactly what the UI sends. The previous two strcmps looked
                // for bare "Transport"/"CallTransport" and so matched nothing at
                // all: every command-panel order - repair, reclaim, guard,
                // patrol, move - resolved with mCommandCaps left at
                // RULEUCC_None and was silently dropped.
                LuaPlus::LuaObject commandName = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (const char* const commandCapsName = commandName ? commandName.GetString() : nullptr;
                    commandCapsName != nullptr) {
                  gpg::RRef capsRef{};
                  capsRef = gpg::MakeRRef<moho::ERuleBPUnitCommandCaps>(&mode.mCommandCaps);
                  if (capsRef.mType != nullptr) {
                    (void)capsRef.mType->SetLexical(capsRef, commandCapsName);
                  }
                }
              } else if (uiMode.mMode == "build" || uiMode.mMode == "buildanchored") {
                resolvedByUi = true;
                LuaPlus::LuaObject blueprintNameField = moho::SCR_GetLuaTableField(mState, uiMode.mPayload, "name");
                if (blueprintNameField && blueprintNameField.IsString()) {
                  const char* const blueprintName = blueprintNameField.GetString();
                  RResId blueprintId{};
                  blueprintId.name = blueprintName ? blueprintName : "";

                  void* const blueprint =
                    mRules ? static_cast<RRuleGameRules*>(mRules)->GetUnitBlueprint(blueprintId) : nullptr;
                  if (blueprint) {
                    mode.mMode = (uiMode.mMode == "build") ? COMMOD_Build : COMMOD_BuildAnchored;
                    mode.mBlueprint = blueprint;
                  }
                }
              } else if (uiMode.mMode == "ping") {
                resolvedByUi = true;
                mode.mMode = COMMOD_Ping;
              } else if (!uiMode.mMode.empty()) {
                resolvedByUi = true;
                gpg::Warnf("CWldSession::GetLeftMouseButtonAction invalid command mode: %s", uiMode.mMode.c_str());
              }
            }
          }
        }

        if (!resolvedByUi) {
          mode.mMode = DefaultModeFromDrag(mouseInfo->mIsDragger);
        }
      }
    }

    *outMode = mode;
    return outMode;
  }

  namespace
  {
    /** `TELEPORTBEACON` category the teleport-beacon splat/icon branch tests for (0x00851C5D). */
    const msvc8::string kCommandSplatTeleportBeaconCategory("TELEPORTBEACON", 14u);

    /** Default (non-teleport) command-splat line colour, `0x80800000` (0x00851D22). */
    constexpr std::uint32_t kCommandSplatDefaultColor = 0x80800000u;

    /** Same-army teleport-beacon command-splat line colour, `0x809040A0` (0x00851CF1). */
    constexpr std::uint32_t kCommandSplatTeleportColor = 0x809040A0u;

    /** Half-width of the beveled command-splat line ribbon, in world units (`0.1`, 0x00851B9E..0x00851BA6). */
    constexpr float kCommandSplatLineHalfWidth = 0.1f;

    /** Half-extent of the flat command-splat icon billboard, in world units (`1.0`, 0x00851E38..0x00851E42). */
    constexpr float kCommandSplatIconHalfExtent = 1.0f;

    /**
     * Resolves the world-space anchor `CWldSession::DrawCommandSplats` draws
     * one command-link line endpoint from/to for `entity`: either its own
     * interpolated position (`boneIndex < 0`, 0x008519D9..0x00851A11) or the
     * composite-transform position of bone `boneIndex` on its freshly
     * refreshed debug pose (0x00851929..0x00851994, the same
     * `MeshInstance::ComputeDebugPose` + `CAniPoseBone::GetCompositeTransform`
     * chain `MeshRenderer::RenderSkeleton` issues for the skeleton-debug
     * overlay). The interpolation alpha is `0.0f`: the incoming stack slot
     * the binary reads for it is never written by the sole call site (which
     * pushes only the session, camera and prim-batcher), so it resolves
     * whatever was left on the caller's frame - the same "phantom
     * interpolant" shape already documented and resolved to a hard `0.0f`
     * on the sibling `DrawEconomyOverlay` above.
     *
     * The binary calls `CAniPoseBone::GetCompositeTransform` unconditionally
     * even when `boneIndex` is out of range for the refreshed pose's bone
     * array, leaving the bone pointer null (0x00851961..0x00851971) - a
     * latent null-dereference crash on out-of-range data. Preserved here as
     * a defensive `false` return instead of reproducing the crash.
     */
    [[nodiscard]] bool ResolveCommandSplatAnchorPosition(
      UserEntity& entity, const std::int32_t boneIndex, Wm3::Vector3f& outPosition
    )
    {
      if (boneIndex < 0) {
        outPosition = entity.GetInterpolatedTransform(0.0f).pos_;
        return true;
      }

      if (entity.mMeshInstance == nullptr) {
        return false;
      }

      const boost::shared_ptr<CAniPose> pose = entity.mMeshInstance->ComputeDebugPose();
      if (!pose) {
        return false;
      }

      const std::ptrdiff_t boneCount = pose->mBones.end() - pose->mBones.begin();
      if (boneIndex >= boneCount) {
        return false;
      }

      outPosition = pose->mBones.begin()[boneIndex].GetCompositeTransform().pos_;
      return true;
    }

    /**
     * Binds one texture resource by path for the command-splat icon
     * batches, matching 0x00851DB8..0x00851DF1 (attack icon) /
     * 0x00851F3C..0x00851FAA (teleport icon):
     * `CD3DDevice::GetResources()->GetTexture(handle, path, nullptr, true)`
     * followed by `CD3DPrimBatcher::SetTexture` on the dynamic-sheet
     * overload (the resolved `TextureResourceHandle` - a
     * `shared_ptr<RD3DTextureResource>` - upcasts to the
     * `shared_ptr<ID3DTextureSheet>` the overload wants, since
     * `RD3DTextureResource` derives from `ID3DTextureSheet`).
     */
    void BindCommandSplatIconTexture(CD3DPrimBatcher& batcher, const char* const path)
    {
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      ID3DDeviceResources::TextureResourceHandle textureHandle{};
      (void)resources->GetTexture(textureHandle, path, nullptr, true);
      batcher.SetTexture(boost::shared_ptr<ID3DTextureSheet>(textureHandle));
    }

    /**
     * Draws one flat, ground-aligned 2x2-world-unit icon billboard at
     * `worldPosition` (0x00851E30..0x00851F27 / 0x00851FE0..0x008520D2 -
     * the attack- and teleport-icon batch loops share this exact shape).
     * The `+-1.0` X/Z corner offsets with no Y offset and the opaque-white
     * vertex colour (`-1`, written repeatedly at 0x00851E55..0x00851F19 and
     * its teleport-branch twin) come straight from the binary; the precise
     * corner-to-UV pairing was not independently bit-verified (the source
     * locals the binary reuses for this pass were, earlier in the same
     * function, a `std::string` and two unrelated `Vertex` scratch buffers,
     * which makes a byte-exact reconstruction of just this block
     * impractical) - the standard 0..1 UV wrap used here reproduces the
     * visible quad shape and opaque-white tint and is not expected to read
     * any differently.
     */
    void DrawCommandSplatIcon(CD3DPrimBatcher& batcher, const Wm3::Vector3f& worldPosition)
    {
      constexpr std::uint32_t kIconColor = 0xFFFFFFFFu;

      const CD3DPrimBatcher::Vertex topLeft{
        worldPosition.x - kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{
        worldPosition.x - kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomRight{
        worldPosition.x + kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z - kCommandSplatIconHalfExtent,
        kIconColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{
        worldPosition.x + kCommandSplatIconHalfExtent, worldPosition.y, worldPosition.z + kCommandSplatIconHalfExtent,
        kIconColor, 1.0f, 0.0f};
      batcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  } // namespace

  /**
   * Address: 0x008515B0 (FUN_008515B0, ?DrawCommandSplats@CWldSession@Moho@@QAEXXZ)
   */
  void CWldSession::DrawCommandSplats(GeomCamera3* const camera, CD3DPrimBatcher* const primBatcher)
  {
    // Walk the selection weak-set and collect the distinct army indices of
    // every live selected unit (0x008515D4..0x00851696, `WeakSet_UserEntity`
    // `find`/`Iterator::inc` over `mSelection`; the per-entity value added to
    // the set is that unit's owning army index).
    BVIntSet selectedArmies{};
    for (UserEntity* const entity : mSelection) {
      if (entity->mArmy != nullptr) {
        (void)selectedArmies.Add(static_cast<unsigned int>(entity->mArmy->mArmyIndex));
      }
    }

    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return;
    }

    // Always publish the selection's army mask to the sync filter, even when
    // the rest of this overlay is not drawn this frame (0x008516A6..0x008516F5).
    simDriver->SetSyncFilterMaskA(selectedArmies);

    // The rest of the overlay only draws while Shift is held with no UI
    // control focused and the game window foreground - `MAUI_KeyIsDown`
    // already implements exactly that gate (0x00851704..0x00851742).
    if (!MAUI_KeyIsDown(MKEY_SHIFT)) {
      return;
    }

    primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");
    primBatcher->SetViewProjMatrix(*camera);
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    msvc8::vector<Wm3::Vector3f> attackIconPositions{};
    msvc8::vector<Wm3::Vector3f> teleportIconPositions{};

    // `mSyncExtraUnitData` is the per-beat extra-unit-data run
    // `CWldSession::DoBeat` copies wholesale from `beat.mSyncExtraUnitData`
    // (see its declaration above) - this is that lane's reader. Each record
    // is one source unit's queued command-link run: `unitEntityId` holds
    // the source `EntId`, and `pairs` holds `(boneIndex, targetEntId)`
    // records, one per weapon (`Unit::GetExtraData`'s `AiAttacker` branch)
    // or teleport-beacon link (its `key == -1` sentinel branch, 0x006ACB20)
    // (0x008518A4..0x0085189A).
    for (const SExtraUnitData& record : mSyncExtraUnitData) {
      UserEntity* const source = LookupEntityId(record.unitEntityId);
      if (source == nullptr) {
        continue;
      }

      for (const SExtraUnitDataPair& pair : record.pairs) {
        const std::int32_t boneIndex = pair.key;
        const EntId targetId = pair.value;

        UserEntity* const target = LookupEntityId(targetId);
        if (target == nullptr) {
          continue;
        }

        Wm3::Vector3f sourcePosition{};
        if (!ResolveCommandSplatAnchorPosition(*source, boneIndex, sourcePosition)) {
          continue;
        }

        const Wm3::Vector3f targetPosition = target->GetInterpolatedTransform(0.0f).pos_;

        // Direction from source to target, normalized (zero vector when the
        // two points coincide) - 0x00851A37..0x00851AE9.
        Wm3::Vector3f direction{
          targetPosition.x - sourcePosition.x, targetPosition.y - sourcePosition.y,
          targetPosition.z - sourcePosition.z};
        const float distance =
          std::sqrt(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
        if (distance > 0.0f) {
          const float inverseDistance = 1.0f / distance;
          direction = Wm3::Vector3f{
            direction.x * inverseDistance, direction.y * inverseDistance, direction.z * inverseDistance};
        } else {
          direction = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
        }

        // Perpendicular bevel offset: the direction rotated 90 degrees
        // about Y, scaled to the ribbon half-width (0x00851B8C..0x00851BA6).
        const Wm3::Vector3f bevel{
          direction.z * kCommandSplatLineHalfWidth, 0.0f, -direction.x * kCommandSplatLineHalfWidth};

        // The line ribbon runs from one unit short of the source to one
        // unit short of the target (0x00851AE9..0x00851C50), offset to one
        // side by `bevel`.
        const Wm3::Vector3f nearSource{
          sourcePosition.x + direction.x, sourcePosition.y + direction.y, sourcePosition.z + direction.z};
        const Wm3::Vector3f nearTarget{
          targetPosition.x - direction.x, targetPosition.y - direction.y, targetPosition.z - direction.z};

        const Wm3::Vector3f topLeft{nearSource.x + bevel.x, nearSource.y + bevel.y, nearSource.z + bevel.z};
        const Wm3::Vector3f& topRight = nearSource;
        const Wm3::Vector3f& bottomRight = nearTarget;
        const Wm3::Vector3f bottomLeft{nearTarget.x + bevel.x, nearTarget.y + bevel.y, nearTarget.z + bevel.z};

        const bool sameArmy = source->mArmy != nullptr && source->mArmy == target->mArmy;
        const bool isTeleportBeacon = sameArmy && target->IsInCategory(kCommandSplatTeleportBeaconCategory);
        const std::uint32_t lineColor = isTeleportBeacon ? kCommandSplatTeleportColor : kCommandSplatDefaultColor;

        primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft, lineColor);

        if (isTeleportBeacon) {
          teleportIconPositions.push_back(targetPosition);
        } else {
          attackIconPositions.push_back(targetPosition);
        }
      }
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/attack_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : attackIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    BindCommandSplatIconTexture(*primBatcher, "/textures/ui/common/game/waypoints/teleport_btn_up.dds");
    for (const Wm3::Vector3f& iconPosition : teleportIconPositions) {
      DrawCommandSplatIcon(*primBatcher, iconPosition);
    }

    primBatcher->Flush();
  }

  namespace
  {
    /**
     * Tint every formation-placement ghost is stamped with, written straight
     * into `MeshInstance::color` at 0x00859E0B as the literal `0D8D8D800h`.
     */
    constexpr std::int32_t kFormationPreviewTint = static_cast<std::int32_t>(0xD8D8D800u);
  }

  /**
   * Address: 0x008599D0 (FUN_008599D0, ?RenderMeshPreviews@CWldSession@Moho@@QAEHXZ)
   *
   * IDA signature:
   * int __usercall sub_8599D0@<eax>(Moho::CWldSession *this);
   *
   * What it does:
   * Rebuilds this frame's formation-placement ghosts. Last frame's previews are
   * dropped unconditionally; then, only while the pending formation is ready,
   * still has a live instance, and its placement timer has run out, every
   * participant unit gets one translucent copy of its own mesh - reshaded with
   * the "UnitFormationPreview" shader - parked on the terrain at the slot the
   * formation assigned it and turned to face the formation heading.
   */
  void CWldSession::RenderMeshPreviews()
  {
    MeshRenderer* const renderer = MeshRenderer::GetInstance();

    // 0x008599EF..0x00859A0A: the whole-range erase runs before every early-out
    // below, so a formation that is no longer placeable clears its ghosts.
    gFormationPreviews.clear();

    CFormation* const formation = mCurFormation;
    if (!formation->mReady || formation->mCurInstance == nullptr || formation->mTimeLeft > 0.0f) {
      return;
    }

    // 0x00859AB1 / 0x00859AF8 dispatch instance slots 16 and 6, which only
    // `CAiFormationInstance` declares - `mCurInstance` is typed as the bare
    // `IFormationInstance` interface. Same reinterpret_cast the rest of the
    // tree already uses to reach the concrete instance (Unit.cpp).
    CAiFormationInstance* const instance =
      reinterpret_cast<CAiFormationInstance*>(formation->mCurInstance);
    WeakSet<UserUnit>& participants = formation->mParticipants;

    for (UserUnit* const unit : participants) {
      {
        // The unit's `IUnit` bridge sub-object at +0x148 is what every
        // formation-side call below is handed.
        IUnit* const bridge = GetIUnitBridge(unit);
        Unit* const formationUnit = reinterpret_cast<Unit*>(bridge);

        if (!bridge->IsDead() && instance->Contains(formationUnit, false)
            && unit->GetAttachmentParent() == nullptr) {
          const RUnitBlueprint* const blueprint = bridge->GetBlueprint();
          const RMeshBlueprint* const meshBlueprint = unit->mVariableData.mMeshBlueprint;
          if (!meshBlueprint->mLods.empty()) {
            SCoordsVec2 slot{};
            instance->GetFormationPosition(&slot, formationUnit, nullptr);

            // 0x00859B12 builds the basis for the formation heading and then
            // never reads it back - a dead local in the 2007 source, kept
            // because the constructor call is a real emission.
            [[maybe_unused]] const VAxes3 heading{formation->mDirection};

            // Park the ghost on the terrain: surface height under the slot,
            // plus the unit's own half-height and its blueprint elevation.
            Wm3::Vec3f position{slot.x, 0.0f, slot.z};
            position.y =
              GetSTIMap()->GetSurface(position) + blueprint->mSizeY + blueprint->Physics.Elevation;

            gFormationPreviews.push_back(SFormationPreviewGhost{});
            SFormationPreviewGhost& preview = gFormationPreviews.back();

            // Only the top LOD is previewed, and only its three texture lanes -
            // the shader is forced to "UnitFormationPreview" and the lookup and
            // secondary maps are left empty (0x00859C3F..0x00859C71).
            const RMeshBlueprintLOD& lod = *meshBlueprint->mLods.begin();
            preview.mMaterial = MeshMaterial::Create(
              msvc8::string{"UnitFormationPreview"},
              lod.mAlbedoName,
              lod.mNormalsName,
              lod.mSpecularName,
              msvc8::string{},
              msvc8::string{},
              nullptr
            );

            const float uniformScale = blueprint->Display.UniformScale;
            preview.mMesh = boost::shared_ptr<MeshInstance>(renderer->CreateMeshInstance(
              0, 0, meshBlueprint, Wm3::Vec3f{uniformScale, uniformScale, uniformScale}, false,
              preview.mMaterial
            ));

            if (preview.mMesh) {
              VTransform stance{Wm3::Vec3f{0.0f, 0.0f, 0.0f}, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
              stance.orient_ = formation->mDirection;
              stance.pos_ = position;

              // Start and end stance are the same transform - the ghost does
              // not interpolate.
              //
              // Not reproduced here: 0x00859DE4 zero-fills an 8-byte slot that
              // EH state 5 covers for exactly this call plus the tint store,
              // and 0x00859E1D hands it to the shared-count teardown
              // (FUN_0055B7A0). Both halves are null for its whole lifetime, so
              // the teardown returns on its first branch and the pair is
              // observably a no-op - a default-constructed shared handle the
              // 2007 source declared and never used. Behaviour is identical
              // without it; inventing a variable to carry it would not be.
              preview.mMesh->SetStance(stance, stance);
              preview.mMesh->color = kFormationPreviewTint;
            } else {
              // 0x00859E26: the renderer refused the instance, so the slot
              // that was just appended is retired again.
              gFormationPreviews.pop_back();
            }
          }
        }
      }
    }
  }

  namespace
  {
    /**
     * Gap between two stacked bars, in screen pixels (`flt_DFEB0C` added twice
     * per row at 0x0085D22F / 0x0085D23E).
     */
    constexpr float kLifebarRowGap = 2.0f;

    /** Every bar sits on an opaque black backdrop (`0FF000000h`, 0x0085D285). */
    constexpr std::uint32_t kLifebarBackdropColor = 0xFF000000u;

    /**
     * A filled bar never gets thinner than this even when the bar itself is
     * (`comiss` against `flt_DFEB0C` at 0x0085D55D / 0x0085D581).
     */
    constexpr float kLifebarMinFillHeight = 2.0f;

    /** The drop shadow under a label is offset one pixel down-right (0x0085E2A3). */
    constexpr float kLabelShadowOffset = 1.0f;

    /** Label drop shadow colour (`0FF000000h` pushed at 0x0085E2AB). */
    constexpr std::uint32_t kLabelShadowColor = 0xFF000000u;

    /**
     * Address: 0x004EAA50 (FUN_004EAA50)
     *
     * What it does:
     * Returns the shared "no screen position" sentinel - a `Wm3::Vector2f`
     * whose components are both NaN. The binary keeps it in a
     * function-local static (storage 0x010C7AB4/0x010C7AB8 behind the
     * one-bit init guard at 0x010C7ABC) and both of
     * `DrawUnitCustomNameLabel`'s early-outs hand it back: the first inlines
     * the guard (0x0085E33F), the second calls this body (0x0085E0F5).
     */
    [[nodiscard]] const Wm3::Vector2f& InvalidScreenPoint()
    {
      static const Wm3::Vector2f sentinel{
        std::numeric_limits<float>::quiet_NaN(), std::numeric_limits<float>::quiet_NaN()
      };
      return sentinel;
    }

    /**
     * Address: 0x005657B0 (FUN_005657B0, sub_5657B0)
     *
     * IDA signature:
     * BOOL __usercall sub_5657B0@<eax>(float *a1@<esi>);
     *
     * What it does:
     * Reports whether a screen point carries a real position, i.e. neither
     * component is NaN. This is the read side of `InvalidScreenPoint()`.
     */
    [[nodiscard]] bool IsValidScreenPoint(const Wm3::Vector2f& point)
    {
      return !std::isnan(point.X()) && !std::isnan(point.Y());
    }

    /**
     * Address: 0x010C4284 (the cached custom-name font)
     *
     * What it does:
     * Returns the process-wide font the custom-name labels render with,
     * creating it on first use from the `ui_CustomNameFont` /
     * `ui_CustomNameFontSize` console variables (0x0085E11B..0x0085E171).
     * The binary keeps exactly one reference for the life of the process -
     * the temporary handle `CD3DFont::Create` returns is assigned into the
     * global and then released - so the static below deliberately never
     * releases either.
     */
    [[nodiscard]] CD3DFont* CustomNameFont()
    {
      static boost::SharedPtrRaw<CD3DFont> font{};
      if (font.px == nullptr) {
        font = CD3DFont::Create(ui_CustomNameFontSize, ui_CustomNameFont.c_str());
      }
      return font.px;
    }

    /**
     * Emits one axis-aligned screen-space bar.
     *
     * All six quads in `DrawUnitLifebars` hand their corners to
     * `CD3DPrimBatcher::DrawQuad` in the same rotation - top-left, down the
     * left edge, across the bottom, back up the right edge - so the corner
     * mechanics are lifted here instead of being open-coded six times. That
     * rotation is the binary's own: at 0x0085D317 the `topLeft` argument
     * (the vector pushed first, read from the callee frame at +8 in
     * 0x00438DD0) is `(left, top)` while `topRight` (the `ecx` argument,
     * read at 0x00438DA3) is `(left, bottom)`.
     */
    void DrawLifebarQuad(
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float top,
      const float right,
      const float bottom,
      const std::uint32_t color
    )
    {
      primBatcher.DrawQuad(
        Wm3::Vector3f(left, top, 0.0f),
        Wm3::Vector3f(left, bottom, 0.0f),
        Wm3::Vector3f(right, bottom, 0.0f),
        Wm3::Vector3f(right, top, 0.0f),
        color
      );
    }

    /**
     * Phase of the shared "empty fuel" blink, in [0,1)
     * (0x0085D107..0x0085D11B and the identical block at
     * 0x0085D18E..0x0085D1A2).
     *
     * Driven by the sim clock rather than the wall clock so every warning bar
     * on screen blinks in step: the whole-tick counter plus this frame's
     * sub-tick interpolant, scaled by the console rate and wrapped.
     */
    [[nodiscard]] float FuelWarningBlinkPhase(const StrategicIconAux& aux)
    {
      const double simTime = static_cast<double>(aux.mSession->mGameTick) + static_cast<double>(aux.mTickFraction);
      return static_cast<float>(std::fmod(simTime * static_cast<double>(ui_FuelEmptyBlinkRate), 1.0));
    }

    /**
     * Address: 0x0085CD40 (FUN_0085CD40, sub_85CD40)
     *
     * IDA signature:
     * float *__usercall sub_85CD40@<eax>(UnitIconData *icon@<eax>,
     *   Wm3::Vector2f *labelCursor, struct_IconAux *aux);
     *
     * What it does:
     * Draws one unit's stacked status bars in the strategic view and reports
     * where a text label under them would start.
     *
     * Row one is always the health bar. Row two and three are conditional: a
     * unit with a shield puts the shield on row two and fuel (or, when the
     * unit carries no fuel at all, build progress) on row three; a unit
     * without a shield collapses to a single second row showing whichever of
     * fuel and build progress is further along. Fuel at or below empty - but
     * not the "no fuel lane at all" sentinel of -1 - swaps that bar to the
     * warning colour and fills it completely on alternate blink phases.
     *
     * Each row is an opaque black backdrop with a coloured fill inset one
     * pixel, the fill running `fraction` of the way across.
     *
     * `labelCursor` receives the horizontal centre of the bar stack and the
     * bottom edge of the last row actually drawn, which is what
     * `DrawUnitCustomNameLabel` hangs its text off.
     */
    void DrawUnitLifebars(const UnitIconData& icon, Wm3::Vector2f& labelCursor, const StrategicIconAux& aux)
    {
      CD3DPrimBatcher& primBatcher = *aux.mBatcher;
      primBatcher.SetTexture(aux.mWhiteTexture);

      const GeomCamera3& camera = *aux.mCamera;
      const REntityBlueprint& blueprint = *icon.mBlueprint;
      const Wm3::Vector3f worldPosition{icon.mWorldX, icon.mWorldY, icon.mWorldZ};

      // Row 2 of the viewport matrix is the perspective-correct width factor;
      // dividing by it keeps the bar a constant on-screen size as the camera
      // pulls back (0x0085CD6A..0x0085CDAF).
      const float widthScale = camera.viewport.ProjectViewportWidthRow2(worldPosition);

      // A blueprint may override either bar extent; a non-positive value means
      // "use the console default" (0x0085CDA8 / 0x0085CDC6).
      const float barWidthSource = (blueprint.mLifeBarSize > 0.0f) ? blueprint.mLifeBarSize : ui_LifebarWidth;
      const float barHeightSource = (blueprint.mLifeBarHeight > 0.0f) ? blueprint.mLifeBarHeight : ui_lifebarHeight;
      const float barWidth = (1.0f / widthScale) * barWidthSource;
      const float barHeight = (1.0f / widthScale) * barHeightSource;

      // The anchor is not the unit's screen position: the world point is taken
      // into VIEW space first so the stack can be dropped straight down the
      // camera's own up axis by the blueprint's lifebar offset, and only then
      // projected. That is why this cannot go through `GeomCamera3::Project` -
      // the offset is applied mid-pipeline (0x0085CDFF..0x0085CFA1).
      const VMatrix4& view = camera.view;
      const float viewX = (view.r[0].x * worldPosition.X()) + (view.r[1].x * worldPosition.Y()) +
        (view.r[2].x * worldPosition.Z()) + view.r[3].x;
      const float viewY = (view.r[0].y * worldPosition.X()) + (view.r[1].y * worldPosition.Y()) +
        (view.r[2].y * worldPosition.Z()) + view.r[3].y;
      const float viewZ = (view.r[0].z * worldPosition.X()) + (view.r[1].z * worldPosition.Y()) +
        (view.r[2].z * worldPosition.Z()) + view.r[3].z;
      const float viewW = (view.r[0].w * worldPosition.X()) + (view.r[1].w * worldPosition.Y()) +
        (view.r[2].w * worldPosition.Z()) + view.r[3].w;

      const float inverseViewW = 1.0f / viewW;
      const float anchorX = viewX * inverseViewW;
      const float anchorY = (viewY * inverseViewW) - (blueprint.mLifeBarOffset + ui_LifebarOffset);
      const float anchorZ = viewZ * inverseViewW;

      const VMatrix4& projection = camera.projection;
      const float clipX = (projection.r[0].x * anchorX) + (projection.r[1].x * anchorY) +
        (projection.r[2].x * anchorZ) + projection.r[3].x;
      const float clipY = (projection.r[0].y * anchorX) + (projection.r[1].y * anchorY) +
        (projection.r[2].y * anchorZ) + projection.r[3].y;
      const float clipW = (projection.r[0].w * anchorX) + (projection.r[1].w * anchorY) +
        (projection.r[2].w * anchorZ) + projection.r[3].w;

      // NDC to whole pixels, Y flipped, same mapping the resource splats use.
      const float inverseClipW = 1.0f / clipW;
      const float anchorScreenX =
        std::floor(((clipX * inverseClipW) - -1.0f) * aux.mViewportWidth * 0.5f);
      const float anchorScreenY = std::floor(
        ((((clipY * inverseClipW) - -1.0f) * (-0.0f - aux.mViewportHeight)) * 0.5f) + aux.mViewportHeight
      );

      const float halfBarWidth = barWidth * 0.5f;
      const float barLeft = anchorScreenX - halfBarWidth;
      const float barRight = barLeft + barWidth;
      const float barTop = anchorScreenY - (barHeight * 0.5f);

      const UserEntity& entity = *icon.mUnit;
      float healthFraction = entity.mVariableData.mHealth / entity.mVariableData.mMaxHealth;
      // Written as the binary's inverted compares so a NaN ratio (a unit with
      // zero max health) clamps to full rather than propagating.
      if (!(1.0f > healthFraction)) {
        healthFraction = 1.0f;
      }
      if (0.0f > healthFraction) {
        healthFraction = 0.0f;
      }

      std::uint32_t healthColor = ui_LifeBarBadColor;
      if (healthFraction > ui_LifeBarGoodCutoff) {
        healthColor = ui_LifeBarGoodColor;
      } else if (healthFraction > ui_LifeBarBadCutoff) {
        healthColor = ui_LifeBarMedColor;
      }

      // Rows two and three stay at zero for anything that is not a unit, which
      // is what suppresses them below.
      float secondRowFraction = 0.0f;
      float thirdRowFraction = 0.0f;
      std::uint32_t secondRowColor = 0u;
      std::uint32_t thirdRowColor = 0u;

      // Slot 3 (`[vftable+0x0C]`, the non-const overload) is the one the
      // binary dispatches at 0x0085D091, matching the caller's own test.
      if (const UserUnit* const unit = icon.mUnit->IsUserUnit(); unit != nullptr) {
        const float fuelRatio = unit->mUnitVarDat.mFuelRatio;
        const float shieldRatio = unit->mUnitVarDat.mShieldRatio;
        const float workProgress = unit->mUnitVarDat.mWorkProgress;
        // -1 is the "this unit has no fuel lane" sentinel, distinct from an
        // empty tank at 0 (0x0085D0D3 / 0x0085D180).
        constexpr float kNoFuelLaneSentinel = -1.0f;

        if (shieldRatio > 0.0f) {
          secondRowColor = ui_ShieldBarColor;
          secondRowFraction = shieldRatio;

          if (!(fuelRatio > kNoFuelLaneSentinel)) {
            thirdRowColor = ui_ProgressBarColor;
            thirdRowFraction = workProgress;
          } else {
            thirdRowColor = ui_FuelBarColor;
            thirdRowFraction = fuelRatio;
            if (!(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
              thirdRowColor = ui_FuelWarningColor;
              thirdRowFraction = 1.0f;
            }
          }
        } else {
          if (fuelRatio > workProgress) {
            secondRowColor = ui_FuelBarColor;
            secondRowFraction = fuelRatio;
          } else {
            secondRowColor = ui_ProgressBarColor;
            secondRowFraction = workProgress;
          }

          if (fuelRatio > kNoFuelLaneSentinel && !(0.0f < fuelRatio) && FuelWarningBlinkPhase(aux) > 0.5f) {
            secondRowColor = ui_FuelWarningColor;
            secondRowFraction = 1.0f;
          }
        }

        if (!(1.0f > secondRowFraction)) {
          secondRowFraction = 1.0f;
        }
        if (0.0f > secondRowFraction) {
          secondRowFraction = 0.0f;
        }
        if (!(1.0f > thirdRowFraction)) {
          thirdRowFraction = 1.0f;
        }
        if (0.0f > thirdRowFraction) {
          thirdRowFraction = 0.0f;
        }
      }

      const float secondRowTop = barTop + (barHeight + kLifebarRowGap);
      const float thirdRowTop = secondRowTop + (barHeight + kLifebarRowGap);

      // Backdrops first, one row at a time, each row gated on the row above
      // having something to show.
      DrawLifebarQuad(primBatcher, barLeft, barTop, barRight, barTop + barHeight, kLifebarBackdropColor);

      float lastRowTop = barTop;
      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(
          primBatcher, barLeft, secondRowTop, barRight, secondRowTop + barHeight, kLifebarBackdropColor
        );
        lastRowTop = secondRowTop;

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(
            primBatcher, barLeft, thirdRowTop, barRight, thirdRowTop + barHeight, kLifebarBackdropColor
          );
          lastRowTop = thirdRowTop;
        }
      }

      labelCursor = Wm3::Vector2f(barLeft + halfBarWidth, lastRowTop + barHeight);

      // Then the coloured fills, inset one pixel inside their backdrops.
      const float fillTrackWidth = barWidth - 1.0f;
      const float fillHeight = (barHeight - kLifebarRowGap) + 1.0f;
      const float fillBottomOffset = (fillHeight < kLifebarMinFillHeight) ? kLifebarMinFillHeight : fillHeight;

      DrawLifebarQuad(
        primBatcher,
        barLeft + 1.0f,
        barTop + 1.0f,
        barLeft + (healthFraction * fillTrackWidth),
        barTop + fillBottomOffset,
        healthColor
      );

      if (secondRowFraction > 0.0f) {
        DrawLifebarQuad(
          primBatcher,
          barLeft + 1.0f,
          secondRowTop + 1.0f,
          barLeft + (secondRowFraction * fillTrackWidth),
          secondRowTop + fillBottomOffset,
          secondRowColor
        );

        if (thirdRowFraction > 0.0f) {
          DrawLifebarQuad(
            primBatcher,
            barLeft + 1.0f,
            thirdRowTop + 1.0f,
            barLeft + (thirdRowFraction * fillTrackWidth),
            thirdRowTop + fillBottomOffset,
            thirdRowColor
          );
        }
      }
    }

    /**
     * Address: 0x0085E0A0 (FUN_0085E0A0, sub_85E0A0)
     *
     * IDA signature:
     * Wm3::Vector2f *__cdecl sub_85E0A0(Wm3::Vector2f *result, UnitIconData *icon,
     *   struct_IconAux *aux, Wm3::Vector2f *labelCursor, char isMiniMap);
     *
     * What it does:
     * Draws one unit's player-assigned custom name under its status bars and
     * returns where the text was placed, so the next label down can stack
     * beneath it. Returns `InvalidScreenPoint()` when nothing was drawn -
     * labels are off, this is the minimap, or the unit has no custom name -
     * which is the caller's signal to leave its cursor untouched.
     *
     * The label is centred on `labelCursor` when the bar pass gave it one;
     * otherwise it falls back to projecting the unit itself and applying the
     * same blueprint + console lifebar offset the bars use. Either way the
     * text is snapped to whole pixels and drawn twice, an opaque black copy
     * one pixel down-right first so it stays readable over terrain.
     */
    [[nodiscard]] Wm3::Vector2f DrawUnitCustomNameLabel(
      const UnitIconData& icon,
      const StrategicIconAux& aux,
      const Wm3::Vector2f& labelCursor,
      const bool isMiniMap
    )
    {
      if (!ui_RenderCustomNames || isMiniMap) {
        return InvalidScreenPoint();
      }

      UserUnit* const unit = icon.mUnit->IsUserUnit();

      // `UserUnit::GetCustomName` (vtable slot 24, `[vftable+0x60]`) hands back
      // the address of the unit's `msvc8::string`, not a C string - the binary
      // reads `_Mysize` at +0x14 and picks the inline buffer or heap pointer off
      // `_Myres` at +0x18. Same reinterpret the console command family uses.
      const auto& customName = *reinterpret_cast<const msvc8::string*>(unit->GetCustomName());
      if (customName.empty()) {
        return InvalidScreenPoint();
      }

      CD3DFont* const font = CustomNameFont();

      // The second `GetAdvance` argument is not materialised at this call site
      // (0x0085E196 sets up only the string); zero is the neutral flag value.
      const float textWidth = font->GetAdvance(customName.c_str(), 0);
      const float lineHeight = font->mHeight;

      float textLeft = 0.0f;
      float textBaseline = 0.0f;
      if (IsValidScreenPoint(labelCursor)) {
        textLeft = labelCursor.X() - (textWidth * 0.5f);
        textBaseline = labelCursor.Y();
      } else {
        const Wm3::Vector2f projected = aux.mCamera->Project(
          Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ),
          0.0f,
          aux.mViewportWidth,
          aux.mViewportHeight,
          0.0f
        );
        textLeft = projected.X() - (textWidth * 0.5f);
        textBaseline = (icon.mBlueprint->mLifeBarOffset + projected.Y()) + ui_LifebarOffset;
      }
      textBaseline += lineHeight;

      const float snappedLeft = std::floor(textLeft);
      const float snappedBaseline = std::floor(textBaseline);

      const Wm3::Vector2f shadowOrigin{snappedLeft + kLabelShadowOffset, snappedBaseline + kLabelShadowOffset};
      const Wm3::Vector2f textOrigin{snappedLeft, snappedBaseline};

      // The trailing glyph-scale / max-advance pair is not passed at either
      // call site - `Render2D` materialises its own axis constants on entry
      // (0x00426583..0x004265AB) - so both draws use the file's established
      // unscaled / unclipped defaults.
      font->Render2D(
        customName.c_str(),
        aux.mBatcher,
        shadowOrigin,
        kLabelShadowColor,
        1.0f,
        gpg::NaN
      );
      font->Render2D(
        customName.c_str(),
        aux.mBatcher,
        textOrigin,
        ui_CustomNameColor,
        1.0f,
        gpg::NaN
      );

      return textOrigin;
    }

    /**
     * Address: 0x0085E3A0 (FUN_0085E3A0, sub_85E3A0)
     *
     * IDA signature:
     * Wm3::Vector2f *__cdecl sub_85E3A0(Wm3::Vector2f *result, UnitIconData *icon,
     *   struct_IconAux *aux, Wm3::Vector2f *labelCursor, char isMiniMap);
     *
     * What it does:
     * Draws the space-joined list of every named selection set this unit
     * belongs to (`UserUnit::mSelectionSets`), stacked directly under the
     * custom name label, and returns where the text was placed so a
     * still-deferred label could stack under this one in turn. Returns
     * `InvalidScreenPoint()` when nothing was drawn - labels are off, this
     * is the minimap (inlined guard at 0x0085E796, byte-identical to
     * `DrawUnitCustomNameLabel`'s first early-out), or the unit belongs to
     * no selection set (`mSelectionSets.empty()`, 0x0085E3EF calls the
     * shared sentinel body directly) - which is the caller's signal to
     * leave its cursor untouched.
     *
     * Positioning mirrors `DrawUnitCustomNameLabel` exactly: centred on
     * `labelCursor` when the bar/name pass gave it one, otherwise projected
     * from the unit itself through `aux.mCamera->Project` plus the
     * blueprint and console lifebar offsets (0x0085E415..0x0085E48A is the
     * same `viewProjection`-matrix `Project` math, confirmed against
     * `GeomCamera3::viewProjection`'s `+0x9C` offset). Snapped to whole
     * pixels and drawn twice, an opaque black shadow copy one pixel
     * down-right first, same as the custom name label.
     *
     * The joined string is built by walking `unit->mSelectionSets` in its
     * own key order (`msvc8::set<msvc8::string>`'s `begin()`/`end()`/
     * `operator++`, i.e. the already-recovered `rb_increment` at
     * FUN_004DDD30 - also reached from `UserUnit::AddToSelectionSet` and
     * `cfunc_UserUnitGetSelectionSetsL`, confirming this is the same
     * `mSelectionSets` instantiation) and appending each name followed by a
     * literal space, including after the last one (0x0085E4A8..0x0085E4C5)
     * - the binary does not trim the trailing separator, so this preserves
     * that exactly rather than "fixing" it.
     */
    [[nodiscard]] Wm3::Vector2f DrawUnitSelectionSetNameLabel(
      const UnitIconData& icon,
      const StrategicIconAux& aux,
      const Wm3::Vector2f& labelCursor,
      const bool isMiniMap
    )
    {
      if (!ui_RenderSelectionSetNames || isMiniMap) {
        return InvalidScreenPoint();
      }

      // Slot 3 (`[vftable+0x0C]`), same dispatch as `DrawUnitLifebars`/
      // `DrawUnitCustomNameLabel` - relies on the lifebar loop above having
      // already proven `icon.mUnit` is a real `UserUnit` this frame, so this
      // is not re-null-checked here either (matches the binary).
      UserUnit* const unit = icon.mUnit->IsUserUnit();
      if (unit->mSelectionSets.empty()) {
        return InvalidScreenPoint();
      }

      CD3DFont* const font = CustomNameFont();

      msvc8::string joinedNames{};
      for (const msvc8::string& name : unit->mSelectionSets) {
        joinedNames.append(name.view());
        joinedNames.append(" ", 1);
      }

      // The second `GetAdvance` argument is not materialised at this call
      // site either (0x0085E491), same neutral-flag convention as
      // `DrawUnitCustomNameLabel`.
      const float textWidth = font->GetAdvance(joinedNames.c_str(), 0);
      const float lineHeight = font->mHeight;

      float textLeft = 0.0f;
      float textBaseline = 0.0f;
      if (IsValidScreenPoint(labelCursor)) {
        textLeft = labelCursor.X() - (textWidth * 0.5f);
        textBaseline = labelCursor.Y();
      } else {
        const Wm3::Vector2f projected = aux.mCamera->Project(
          Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ),
          0.0f,
          aux.mViewportWidth,
          aux.mViewportHeight,
          0.0f
        );
        textLeft = projected.X() - (textWidth * 0.5f);
        textBaseline = (icon.mBlueprint->mLifeBarOffset + projected.Y()) + ui_LifebarOffset;
      }
      textBaseline += lineHeight;

      const float snappedLeft = std::floor(textLeft);
      const float snappedBaseline = std::floor(textBaseline);

      const Wm3::Vector2f shadowOrigin{snappedLeft + kLabelShadowOffset, snappedBaseline + kLabelShadowOffset};
      const Wm3::Vector2f textOrigin{snappedLeft, snappedBaseline};

      font->Render2D(
        joinedNames.c_str(),
        aux.mBatcher,
        shadowOrigin,
        kLabelShadowColor,
        1.0f,
        gpg::NaN
      );
      font->Render2D(
        joinedNames.c_str(),
        aux.mBatcher,
        textOrigin,
        ui_SelectionSetNamesColor,
        1.0f,
        gpg::NaN
      );

      return textOrigin;
    }

    /**
     * Draws one centered, screen-aligned strategic-icon quad sized to
     * `texture`'s own pixel dimensions (halved to radii). `RenderUnitIcon`
     * repeats this exact corner-building shape at all four of its
     * quad-draw sites - 0x0085DC96 (identified underlay), 0x0085DDAA (base
     * icon), 0x0085DEA7 (paused overlay), 0x0085DFA3 (stunned overlay) -
     * each computing `texture->mWidth >> 1` / `mHeight >> 1` then the same
     * four corners, so it is lifted here once instead of four times.
     */
    void DrawStrategicIconQuad(
      CD3DPrimBatcher& primBatcher,
      const float centerX,
      const float centerY,
      const CD3DBatchTexture& texture,
      const std::uint32_t color
    )
    {
      const float halfWidth = static_cast<float>(texture.mWidth >> 1);
      const float halfHeight = static_cast<float>(texture.mHeight >> 1);

      primBatcher.DrawQuad(
        Wm3::Vector3f(centerX - halfWidth, centerY - halfHeight, 0.0f),
        Wm3::Vector3f(centerX + halfWidth, centerY - halfHeight, 0.0f),
        Wm3::Vector3f(centerX + halfWidth, centerY + halfHeight, 0.0f),
        Wm3::Vector3f(centerX - halfWidth, centerY + halfHeight, 0.0f),
        color
      );
    }

    /**
     * Address: 0x0085DBD9..0x0085DC02 (inline in FUN_0085D9A0)
     *
     * What it does:
     * Halves an ARGB color's R/G/B channels while leaving alpha untouched:
     * each channel's top 7 bits (`channel >> 1`) are repacked into the same
     * byte position with the low bit cleared. Used to darken a strategic
     * icon's tint for units whose intel carries bit 0x40.
     */
    [[nodiscard]] std::uint32_t DarkenRgbPreserveAlpha(const std::uint32_t argb)
    {
      const std::uint32_t alpha = argb & 0xFF000000u;
      const std::uint32_t red = ((argb >> 16) & 0xFFu) >> 1;
      const std::uint32_t green = ((argb >> 8) & 0xFFu) >> 1;
      const std::uint32_t blue = (argb & 0xFFu) >> 1;
      return alpha | (red << 16) | (green << 8) | blue;
    }

    /**
     * Address: 0x0085D9A0 (FUN_0085D9A0, RenderUnitIcon)
     *
     * IDA signature:
     * void __cdecl RenderUnitIcon(struct_UnitIconData *a1, struct_IconAux *a2);
     *
     * What it does:
     * Draws one classified unit's strategic-icon quads. Called once per icon
     * collected into `StrategicIconAux`'s ground/air/high-priority/
     * selected runs by `RenderStrategicIcons`.
     *
     * Projects the icon's world position through the camera to a floored
     * screen point, then resolves a display color: when the unit is either
     * not a real `UserUnit` or its intel carries full blueprint data
     * (`mIntelStateFlags` bit 0x10, the same bit `PickUnitStrategicIconTexture`
     * already names), the icon's owning army's real color - `teamcolors[]`
     * in team-color mode with a focus army active, else the army's own
     * `mVarDat.mPlayerColorBgra`; otherwise the flat `aux.mUnidentifiedColor`
     * placeholder.
     *
     * A formation-preview ghost (`mIsFormationGhost`) short-circuits
     * straight to the quad stack below with that color's sign/alpha-high
     * bit cleared (`& 0x7FFFFFFF`) instead of team-colored, skipping
     * everything else in this function - no darken check, no blink gate, no
     * identified-icon draw. Otherwise, a unit whose intel carries bit 0x40
     * gets its color darkened (`DarkenRgbPreserveAlpha`).
     *
     * A friendly unit (`mIsFriendly`) that was damaged while under the local
     * player's focus within the last `ui_StrategicIconBlinkDuration * 10`
     * ticks (`UserEntity::mLastFocusDamageGameTick`) blinks: on the "off"
     * half of the `ui_StrategicIconBlinkRate` cycle the function returns
     * without drawing anything at all for this icon this frame.
     *
     * When an owning army was resolved, the unit's own strategic-underlay
     * texture (`UserEntity::GetStrategicUnderlayTexture`, itself the
     * recovered form of the `WeakPtr_CD3DBatchTexture` constructor this
     * function calls at 0x0085DC74) draws first, at full opacity with no
     * additional tint. Finally the shared quad stack draws the base icon
     * (unless `mSuppressBaseIcon`), then the paused and stunned overlay
     * badges when present - only the base icon is tinted with the
     * resolved/darkened color; the underlay and both overlays draw at their
     * own native texture color.
     */
    void RenderUnitIcon(const UnitIconData& icon, const StrategicIconAux& aux)
    {
      constexpr std::uint32_t kOverlayNoTintColor = 0xFFFFFFFFu;

      const Wm3::Vector2f screenPoint = aux.mCamera->Project(
        Wm3::Vector3f(icon.mWorldX, icon.mWorldY, icon.mWorldZ), 0.0f, aux.mViewportWidth, aux.mViewportHeight, 0.0f
      );
      const float screenX = std::floor(screenPoint.X());
      const float screenY = std::floor(screenPoint.Y());

      const UserUnit* const asUnit = icon.mUnit->IsUserUnit();

      // Same bit `PickUnitStrategicIconTexture` names `kHasBlueprintIconDataMask`
      // on `mIntelStateFlags` ("has-data"); re-declared locally for the same
      // file-private-constant reason noted there.
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool hasIdentifiedOwner = asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;

      std::uint32_t iconColor;
      if (hasIdentifiedOwner) {
        if (aux.mSession->mTeamColorMode && aux.mSession->GetFocusArmy() != nullptr) {
          iconColor = teamcolors[static_cast<std::size_t>(icon.mUnit->mArmy->mArmyIndex)];
        } else {
          iconColor = icon.mUnit->mArmy->mVarDat.mPlayerColorBgra;
        }
      } else {
        iconColor = aux.mUnidentifiedColor;
      }

      if (icon.mIsFormationGhost) {
        iconColor &= 0x7FFFFFFFu;
      } else {
        constexpr std::uint32_t kDarkenedTintMask = 0x40u;
        if (asUnit != nullptr && (asUnit->mIntelStateFlags & kDarkenedTintMask) != 0u) {
          iconColor = DarkenRgbPreserveAlpha(iconColor);
        }

        if (icon.mIsFriendly) {
          const std::int32_t lastFocusDamageTick = icon.mUnit->mLastFocusDamageGameTick;
          if (lastFocusDamageTick != 0) {
            // `* 10.0f`: 0x0085DC2A.
            constexpr float kBlinkDurationTickScale = 10.0f;
            const float ticksSinceDamage = static_cast<float>(aux.mSession->mGameTick - lastFocusDamageTick);
            if ((ui_StrategicIconBlinkDuration * kBlinkDurationTickScale) > ticksSinceDamage) {
              const double simTime =
                static_cast<double>(aux.mSession->mGameTick) + static_cast<double>(aux.mTickFraction);
              const double blinkPhase = std::fmod(simTime * static_cast<double>(ui_StrategicIconBlinkRate), 1.0);
              if (blinkPhase <= 0.5) {
                return;
              }
            }
          }
        }

        if (hasIdentifiedOwner) {
          const boost::shared_ptr<CD3DBatchTexture> identifiedTexture = icon.mUnit->GetStrategicUnderlayTexture();
          if (identifiedTexture) {
            aux.mBatcher->SetTexture(identifiedTexture);
            DrawStrategicIconQuad(*aux.mBatcher, screenX, screenY, *identifiedTexture, kOverlayNoTintColor);
          }
        }
      }

      if (!icon.mSuppressBaseIcon) {
        aux.mBatcher->SetTexture(icon.mIconTexture);
        DrawStrategicIconQuad(*aux.mBatcher, screenX, screenY, *icon.mIconTexture, iconColor);
      }

      if (icon.mShowPausedOverlay && icon.mPausedTexture) {
        aux.mBatcher->SetTexture(icon.mPausedTexture);
        DrawStrategicIconQuad(*aux.mBatcher, screenX, screenY, *icon.mPausedTexture, kOverlayNoTintColor);
      }

      if (icon.mShowStunnedOverlay && icon.mStunnedTexture) {
        aux.mBatcher->SetTexture(icon.mStunnedTexture);
        DrawStrategicIconQuad(*aux.mBatcher, screenX, screenY, *icon.mStunnedTexture, kOverlayNoTintColor);
      }
    }
  } // namespace

  /**
   * Address: 0x0085B6E0 (FUN_0085B6E0,
   * ?RenderStrategicIcons@CWldSession@Moho@@QAEXPAVCameraImpl@2@PAVCD3DPrimBatcher@2@PAVCWldMap@2@@Z)
   *
   * What it does:
   * Lazily builds the process-global icon-aux singleton, re-seats its
   * per-frame camera/batcher state and screen projection, then walks every
   * unit `CameraImpl::GetAllUnitsInFrustum()` currently sees and classifies
   * each one carrying a strategic-icon name into one of four runs (ground /
   * air / high-priority / selected), picking its icon texture through
   * `PickUnitStrategicIconTexture`.
   *
   * Blockers this pass resolved (see cited evidence at each site):
   *  - `CameraImpl` vtable slot mixup: the dispatch at 0x0085BA71 (byte
   *    offset 0xA0 from the vtable head) is slot 40 = `GetAllUnitsInFrustum`,
   *    not `GetArmyUnitsInFrustum` (slot 41, +0xA4) as an earlier pass's
   *    comment guessed - confirmed by reading the shipped vtable directly
   *    out of `bin/2025.7.1/ForgedAlliance.exe` (see `CameraImpl.h`).
   *  - `REntityBlueprint::mStrategicIconSortPriority` retyped from a 32-bit
   *    `mStrategicIconRuntimeWord` to the real single byte the classifier
   *    compares against `'A'`.
   *  - `CWldSession`'s `EntId -> UserEntity*` map was already modelled
   *    (`SessionEntityMap` / `LookupEntityId`) by a prior pass - no new work
   *    needed there.
   *  - `StrategicIconAux`'s constructor and `LoadGenericIcons` recovered
   *    (0x0085B2A0 / 0x0085E7F0); `gStrategicIconAuxiliary` retyped from a
   *    never-defined `StrategicIconAux` forward declaration to
   *    the real, complete type.
   *  - `PickUnitStrategicIconTexture` / `PickGenericStrategicIconTexture`
   *    recovered (0x0085D880 / 0x0085CBD0), which required retyping
   *    `REntityBlueprint`'s four cached icon fields from `boost::weak_ptr`
   *    to `boost::shared_ptr` (see the evidence note on those fields).
   *  - The selection-set name label (`DrawUnitSelectionSetNameLabel`,
   *    0x0085E3A0), which stacks under the custom name using the same
   *    cursor protocol, is now wired into phase 4 below.
   *  - The icon-quad draw itself (`RenderUnitIcon`, 0x0085D9A0) is now
   *    recovered and wired into phase 3.5 below, for all four of the
   *    ground/air/high-priority/selected runs: world-to-screen projection,
   *    the `Moho::teamcolors` per-army palette (`+0x0128F1C0`, read when
   *    `mTeamColorMode` is on) vs. the flat unidentified color, the
   *    formation-ghost alpha-clear and intel-bit darken tints, the
   *    recently-focus-damaged blink timer, and the identified-icon
   *    underlay / base icon / paused / stunned quad stack.
   *
   * Deferred to a follow-up pass - not drawn by this function yet:
   *  - The single dedicated "hovered unit" slot (this function's local
   *    `v148.playableRectX1` in the original binary - hovered units are
   *    excluded from all four runs below, matching the binary, but nothing
   *    collects or consumes that slot's own icon data yet).
   *  - The "toggled off a scripted ability" half of the paused-overlay flag
   *    below, which currently reflects only `mUnitVarDat.mIsPaused`.
   *  - The formation-ghost pass ("TStrategicFormationIcon"): needs
   *    `IFormationInstance::Contains`, not modelled yet - a separate,
   *    already-tracked blocker (see the `CFormationInstance` split notes).
   */
  void CWldSession::RenderStrategicIcons(
    CameraImpl* const camera, CD3DPrimBatcher* const primBatcher, const float tickFraction, const bool isMiniMap
  )
  {
    // Read once per frame, before the singleton is even built (0x0085B719).
    // An "attached" unit - one riding a transport or docked - normally has its
    // lifebar suppressed; this option puts it back.
    const bool showAttachedUnitLifebars = OPTIONS_GetBool("show_attached_unit_lifebars");

    // --- Phase 1: lazy singleton build --------------------------------
    if (gStrategicIconAuxiliary == nullptr) {
      gStrategicIconAuxiliary = new StrategicIconAux();
      gStrategicIconAuxiliary->LoadGenericIcons(this);
      gStrategicIconAuxiliary->LoadPauseAndStunnedRestTextures(this);
    }
    StrategicIconAux& aux = *gStrategicIconAuxiliary;

    // --- Phase 2: re-seat per-frame camera/batcher state, clear the four
    // implemented runs, push the pixel-exact screen projection ----------
    const GeomCamera3& view = camera->CameraGetView();
    aux.mViewportX = view.viewport.r[3].x;
    aux.mViewportY = view.viewport.r[3].y;
    aux.mViewportWidth = view.viewport.r[3].z;
    aux.mViewportHeight = view.viewport.r[3].w;
    aux.mSession = this;
    aux.mBatcher = primBatcher;
    aux.mCamera = &view;
    // aux.mTickFraction re-seat deferred alongside the lifebar pass, its
    // only reader - see the class comment above `mTickFraction`.

    aux.mGroundIcons.clear();
    aux.mAirIcons.clear();
    aux.mHighPriorityIcons.clear();
    aux.mSelectedIcons.clear();
    // The lifebar run is collected below whether or not the draw pass that
    // consumes it is wired yet, so it has to be cleared here with the other
    // four. Leaving it out made it grow by every visible unit every frame.
    aux.mLifebarIcons.clear();

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    // "Current zoom" scalar used below as the mesh-fade-in comparison
    // baseline: the camera target position projected through row 1 of the
    // viewport matrix (0x0085BA1E..0x0085BA93 in the binary).
    const Wm3::Vector3f targetPosition = camera->GetTargetPosition();
    const float currentZoomValue = (view.viewport.r[1].x * targetPosition.x) +
      (view.viewport.r[1].y * targetPosition.y) + (view.viewport.r[1].z * targetPosition.z) + view.viewport.r[1].w;

    // --- Phase 3: classify every unit in frustum ------------------------
    UserArmy* const focusArmy = GetFocusArmy();
    for (const WeakPtr<UserEntity>& ref : *camera->GetAllUnitsInFrustum()) {
      UserEntity* const entity = ref.GetObjectPtr();
      if (entity == nullptr || entity->mVariableData.mIsDead) {
        continue;
      }

      UserUnit* const asUnit = entity->IsUserUnit();

      // `mIntelStateFlags` bit 0x20: this unit renders through some other
      // path already and its strategic icon is suppressed outright
      // (`(v26->mSelectionMaskUsed & 0x20) == 0` gates entry at 0x0085BAC3).
      constexpr std::uint32_t kStrategicIconEntitySuppressedMask = 0x20u;
      if (asUnit != nullptr && (asUnit->mIntelStateFlags & kStrategicIconEntitySuppressedMask) != 0u) {
        continue;
      }

      const REntityBlueprint* const blueprint = entity->mParams.mBlueprint;
      if (blueprint == nullptr || blueprint->mStrategicIconName.empty()) {
        continue;
      }

      UnitIconData iconData{};
      iconData.mUnit = entity;
      iconData.mBlueprint = blueprint;

      const VTransform interpolated = entity->GetInterpolatedTransform(tickFraction);
      iconData.mWorldX = interpolated.pos_.x;
      iconData.mWorldY = interpolated.pos_.y;
      iconData.mWorldZ = interpolated.pos_.z;

      // `mIntelStateFlags` bit 0x08 ("health-valid") / bit 0x10
      // ("has-data"): both default true for non-`UserUnit` entities
      // (wrecks, props, ...), matching `isBusy_60`/`v49`'s init at
      // 0x0085BB60..0x0085BB74.
      constexpr std::uint32_t kIntelHealthValidMask = 0x08u;
      constexpr std::uint32_t kHasBlueprintIconDataMask = 0x10u;
      const bool selectedVariantEligible =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kIntelHealthValidMask) != 0u;
      const bool hasFullBlueprintIconData =
        asUnit == nullptr || (asUnit->mIntelStateFlags & kHasBlueprintIconDataMask) != 0u;

      iconData.mIsFriendly =
        focusArmy == nullptr || focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex));

      iconData.mShowStunnedOverlay = asUnit != nullptr && asUnit->mUnitVarDat.mStunTicks != 0;
      iconData.mShowPausedOverlay = asUnit != nullptr && asUnit->mUnitVarDat.mIsPaused;

      if (focusArmy == nullptr || entity->mArmy == focusArmy) {
        if (mWldMap != nullptr && mWldMap->mTerrainRes != nullptr &&
            !mWldMap->mTerrainRes->IsInPlayableRect(interpolated.pos_)) {
          continue;
        }
      }

      if (iconData.mIsFriendly) {
        UserEntity* const attachmentParent = entity->GetAttachmentParent();
        if (attachmentParent != nullptr && attachmentParent->IsInCategory(msvc8::string("CARRIER"))) {
          continue;
        }
      } else if (asUnit != nullptr && asUnit->mUnitVarDat.mIsBusy && asUnit->GetBlueprint()->Air.CanFly) {
        continue;
      }

      // --- Lifebar collection gate (0x0085BFDB..0x0085C09F) -------------
      // The one producer of `mLifebarIcons`. Everything below is read in the
      // binary's own order; each early-out lands on the same 0x0085C0A4
      // continue as the icon test that follows.
      if (ui_RenderUnitBars && ui_LifebarLOD > currentZoomValue && !entity->mVariableData.mIsDead &&
          blueprint->mLifeBarRender != 0) {
        // Enemy units only get bars when their health is actually known
        // (`selectedVariantEligible`, intel bit 0x08), and then only if the
        // player forced enemy bars on or is hovering this unit. Friendly units
        // skip all three tests.
        bool eligible = iconData.mIsFriendly;
        if (!eligible && selectedVariantEligible) {
          eligible = ui_ForceLifbarsOnEnemy || entity == GetHoveredUserEntity();
        }

        if (eligible && asUnit != nullptr) {
          // A unit mid-upgrade is drawn by the upgrade progress UI instead
          // (slot 15, dispatched with `push 25h` at 0x0085C06B).
          const IUnit* const unitBridge = GetIUnitBridge(asUnit);
          const bool attachedAndHidden = !showAttachedUnitLifebars && asUnit->mUnitVarDat.mIsBusy;
          if (!unitBridge->IsUnitState(UNITSTATE_BeingUpgraded) && !attachedAndHidden &&
              unitBridge->GetBlueprint()->Display.HideLifebars == 0) {
            aux.mLifebarIcons.push_back(iconData);
          }
        }
      }

      if (!ui_NisRenderIcons || (!ui_RenderIcons && !iconData.mShowPausedOverlay) || entity->IsBeingBuilt()) {
        continue;
      }

      // When the unit's own mesh is already close enough to be visible
      // without help, skip the icon entirely for units that have full
      // intel data (or belong to an immobile blueprint under a focus
      // army) and aren't paused - everyone else still gets an icon.
      const bool skipWhenMeshVisible =
        (hasFullBlueprintIconData || (focusArmy != nullptr && !blueprint->IsMobile())) &&
        !iconData.mShowPausedOverlay;

      const RMeshBlueprint* const mesh = entity->mVariableData.mMeshBlueprint;
      if (mesh != nullptr && !ui_AlwaysRenderStrategicIcons) {
        const float fadeThreshold = std::min(mesh->mIconFadeInZoom, camera->GetMaxZoom() * 0.89f);
        if (fadeThreshold <= currentZoomValue) {
          if (skipWhenMeshVisible) {
            continue;
          }
          iconData.mSuppressBaseIcon = iconData.mShowPausedOverlay || iconData.mShowStunnedOverlay;
        }
      }

      const bool isHovered = entity == GetHoveredUserEntity();

      const bool isSelected = mSelection.Find(entity) != mSelection.end();

      boost::shared_ptr<CD3DBatchTexture> icon =
        PickUnitStrategicIconTexture(aux, iconData, isSelected, selectedVariantEligible, isHovered);
      if (!icon) {
        continue;
      }
      iconData.mIconTexture = std::move(icon);

      if (iconData.mShowPausedOverlay) {
        iconData.mPausedTexture = aux.mPauseRestTexture;
      }
      if (iconData.mShowStunnedOverlay) {
        iconData.mStunnedTexture = aux.mStunnedRestTexture;
      }

      // The single dedicated "hovered unit" slot is part of the deferred
      // draw pass (see the function comment) - hovered units are excluded
      // from all four runs here, matching the binary, but nothing consumes
      // them yet.
      if (isHovered) {
        continue;
      }

      if (isSelected) {
        aux.mSelectedIcons.push_back(iconData);
        continue;
      }

      // Sort-priority byte < 'A' always wins the high-priority run
      // (0x0085C2C0..0x0085C2C7). At/above 'A' the binary default-
      // constructs a `WeakPtr_CD3DBatchTexture` and tests it - a
      // no-argument constructor is unconditionally empty, so that branch
      // is provably always false and always falls through to ground/air.
      if (blueprint->mStrategicIconSortPriority < static_cast<std::uint8_t>('A')) {
        aux.mHighPriorityIcons.push_back(iconData);
        continue;
      }

      if (asUnit != nullptr && asUnit->GetBlueprint()->Air.CanFly) {
        aux.mAirIcons.push_back(iconData);
      } else {
        aux.mGroundIcons.push_back(iconData);
      }
    }

    // --- Phase 3.5: draw the classified icon quads -----------------------
    // The four runs collected above, each drawn through `RenderUnitIcon`
    // (0x0085D9A0) under its own technique (0x0085B79D..0x0085BCCD in the
    // binary). This runs before the lifebar pass below, matching the
    // binary's own SetTexture/DrawQuad-then-Flush ordering (0x0085BBE9..
    // 0x0085BCCD then Flush at 0x0085BFA9). The single dedicated "hovered
    // unit" slot and the formation-ghost pass that follow this in the
    // binary (`v148.playableRectX1` / "TStrategicFormationIcon") are still
    // deferred - see the function comment.
    (void)primBatcher->Setup("TStrategicIcon");

    for (UnitIconData& groundIcon : aux.mGroundIcons) {
      RenderUnitIcon(groundIcon, aux);
    }
    for (UnitIconData& airIcon : aux.mAirIcons) {
      RenderUnitIcon(airIcon, aux);
    }
    for (UnitIconData& highPriorityIcon : aux.mHighPriorityIcons) {
      RenderUnitIcon(highPriorityIcon, aux);
    }
    for (UnitIconData& selectedIcon : aux.mSelectedIcons) {
      RenderUnitIcon(selectedIcon, aux);
    }

    primBatcher->Flush();

    // --- Phase 4: draw the lifebar / label stack ------------------------
    // The icon-quad runs collected above are drawn by phase 3.5's
    // `RenderUnitIcon` pass just above; this is the bar-and-label stack
    // that follows it in the binary (0x0085C890..0x0085C9DB).
    (void)primBatcher->Setup("TLifeBar");

    for (UnitIconData& lifebarIcon : aux.mLifebarIcons) {
      // The bar pass always writes both components before returning, on every
      // path; it is the label pass that may decline.
      Wm3::Vector2f labelCursor{};
      DrawUnitLifebars(lifebarIcon, labelCursor, aux);

      // Props and wrecks get bars but never labels - only a real unit can
      // carry a custom name or belong to a named selection set
      // (0x0085C915..0x0085C923).
      if (lifebarIcon.mUnit->IsUserUnit() == nullptr) {
        continue;
      }

      // A label that declined to draw returns the NaN sentinel, which leaves
      // the cursor where the bars left it so the next label still stacks
      // correctly (the caller-side isnan pair at 0x0085C973/0x0085C989).
      const Wm3::Vector2f afterCustomName = DrawUnitCustomNameLabel(lifebarIcon, aux, labelCursor, isMiniMap);
      if (IsValidScreenPoint(afterCustomName)) {
        labelCursor = afterCustomName;
      }

      // The selection-set name label stacks under the custom name label,
      // same cursor protocol (0x0085C990..0x0085C9DB).
      const Wm3::Vector2f afterSelectionSetNames =
        DrawUnitSelectionSetNameLabel(lifebarIcon, aux, labelCursor, isMiniMap);
      if (IsValidScreenPoint(afterSelectionSetNames)) {
        labelCursor = afterSelectionSetNames;
      }
    }

    primBatcher->Flush();
  }

  /**
   * Address: 0x008621B0 (FUN_008621B0, CWldSession::RenderProjectileIcons)
   *
   * What it does:
   * Draws a screen-space icon at every visible projectile and advances the
   * shared icon glow timer.
   *
   * The two floats are not interchangeable: the icon position is interpolated
   * with `tickFraction` (`movss xmm1, [ebp+0Ch]` at 0x00862491, the argument
   * of `GetInterpolatedTransform` at 0x0086249F) and the glow timer advances
   * by `frameSeconds` (`addss xmm2, [ebp+10h]` at 0x008628A6). Reading the
   * frame time for both, as this used to, placed every icon a frame-length
   * fraction past the previous tick instead of where the projectile is.
   */
  void CWldSession::RenderProjectileIcons(
    CameraImpl* const camera,
    CD3DPrimBatcher* const primBatcher,
    const float tickFraction,
    const float frameSeconds
  )
  {
    const GeomCamera3& view = camera->CameraGetView();

    // Zoomed in past the strategic threshold the projectiles are drawn as real
    // meshes, so the icon pass is skipped entirely.
    if (camera->CameraGetTargetZoom() < UI_StrategicProjectileLOD) {
      return;
    }

    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique(kProjectileIconTechnique);
    primBatcher->mRebuildComposite = 0;

    const EntityCategorySet* const projectileCategory = mRules->GetEntityCategory("PROJECTILE");
    UserArmy* const focusArmy = GetFocusArmy();

    // The binary collects into a stack fastvector with a large inline buffer;
    // the heap-backed lane is behaviourally identical for a scratch list.
    gpg::fastvector<UserEntity*> visibleEntities{};
    auto* const spatialStorage = GetEntitySpatialDbStorage();
    (void)spatialStorage->CollectInView(const_cast<GeomCamera3*>(&view), visibleEntities, ENTITYTYPE_Entity);

    for (UserEntity* const entity : visibleEntities) {
      if (entity == nullptr || entity->mVariableData.mIsDead) {
        continue;
      }

      // Entity ids are family-tagged in their top nibble; only the projectile
      // family gets an icon, which is cheaper than a category test per entity.
      if ((entity->mParams.mEntityId & kEntityFamilyMask) != kEntityFamilyProjectile) {
        continue;
      }

      const auto* const blueprint = reinterpret_cast<const RProjectileBlueprint*>(entity->mParams.mBlueprint);
      if (blueprint == nullptr) {
        continue;
      }
      if (projectileCategory == nullptr || !projectileCategory->mBits.Contains(blueprint->mCategoryBitIndex)) {
        continue;
      }

      const Wm3::Vec3f worldPosition = entity->GetInterpolatedTransform(tickFraction).pos_;

      // Own and allied projectiles are always drawn; everyone else's have to be
      // under recon cover, and an underwater projectile is checked against the
      // fog grid rather than the explored grid.
      if (focusArmy != nullptr && !focusArmy->IsAlly(static_cast<std::uint32_t>(entity->mArmy->mArmyIndex))
          && !focusArmy->CanSeePoint(
               worldPosition,
               (entity->mVariableData.mLayerMask & kLayerUnderwaterMask) != 0 ? UserArmy::EReconGridMask::Fog
                                                                 : UserArmy::EReconGridMask::Explored
             )) {
        continue;
      }

      boost::shared_ptr<CD3DBatchTexture> icon{};
      float halfWidth = 0.0f;
      float halfHeight = 0.0f;
      bool usesIconTexture = false;

      if (!blueprint->mStrategicIconName.empty()) {
        if (!UI_RenProjectileIcons) {
          continue;
        }
        icon = CD3DBatchTexture::FromFile(blueprint->mStrategicIconName.c_str(), 0u);
        if (!icon) {
          continue;
        }
        // Sized from the texture itself, so an icon is drawn at its authored
        // pixel size regardless of zoom.
        halfWidth = static_cast<float>(icon->mWidth >> 1u);
        halfHeight = static_cast<float>(icon->mHeight >> 1u);
        usesIconTexture = true;
        if (UI_RenProjectileGlow) {
          primBatcher->Flush();
          (void)primBatcher->Setup(kProjectileIconTechnique);
        }
      } else {
        UserArmy* const owningArmy = entity->mArmy;
        if (owningArmy == nullptr) {
          continue;
        }
        icon = CD3DBatchTexture::FromSolidColor(
          UI_forceWeaponsToYellow ? kProjectileForcedColor : owningArmy->mVarDat.mPlayerColorBgra
        );
        if (!icon) {
          continue;
        }
        halfWidth = blueprint->Display.StrategicIconSize * 0.5f;
        halfHeight = halfWidth;
      }

      primBatcher->SetTexture(icon);

      const Wm3::Vector2f projected = view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);
      // Snapped to whole pixels so the icon samples its texels 1:1.
      const float centerX = std::floor(projected.x);
      const float centerY = std::floor(projected.y);

      const float left = centerX - halfWidth;
      const float right = centerX + halfWidth;
      const float top = centerY - halfHeight;
      const float bottom = centerY + halfHeight;

      const CD3DPrimBatcher::Vertex topLeft{left, top, 1.0f, kProjectileIconColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex topRight{left, bottom, 1.0f, kProjectileIconColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 1.0f, kProjectileIconColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{right, top, 1.0f, kProjectileIconColor, 1.0f, 1.0f};
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);

      if (!usesIconTexture || !UI_RenProjectileGlow) {
        continue;
      }

      // Glow pass: a second quad over the icon whose alpha pulses on a shared
      // global timer, so every projectile icon on screen pulses in step.
      primBatcher->Flush();
      (void)primBatcher->Setup("TCommandGlow");

      UI_CurGlowTime =
        (UI_CurGlowTime <= UI_RenProjectileGlowPeriod) ? UI_CurGlowTime + frameSeconds : 0.0f;

      const float halfPeriod = UI_RenProjectileGlowPeriod * 0.5f;
      float glowFrom = UI_RenProjectileGlowMax;
      float glowTo = UI_RenProjectileGlowMin;
      float glowElapsed = UI_CurGlowTime;
      if (glowElapsed > halfPeriod) {
        glowFrom = UI_RenProjectileGlowMin;
        glowTo = UI_RenProjectileGlowMax;
        glowElapsed -= halfPeriod;
      }

      const float glow = (((glowFrom - glowTo) / halfPeriod) * glowElapsed) + glowTo;
      const std::uint32_t glowColor = static_cast<std::uint32_t>(static_cast<std::uint8_t>(glow * 255.0f)) << 24u;

      const CD3DPrimBatcher::Vertex glowTopLeft{right, top, 1.0f, glowColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowTopRight{left, top, 1.0f, glowColor, 0.0f, 1.0f};
      const CD3DPrimBatcher::Vertex glowBottomRight{left, bottom, 1.0f, glowColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex glowBottomLeft{right, bottom, 1.0f, glowColor, 1.0f, 0.0f};
      primBatcher->DrawQuad(glowTopLeft, glowTopRight, glowBottomRight, glowBottomLeft);
      primBatcher->Flush();
    }

    primBatcher->Flush();
  }

  namespace
  {
    /** "/env/common/splats/mass_strategic.dds" - literal at 0x00E47488. */
    constexpr const char* kMassStrategicSplat = "/env/common/splats/mass_strategic.dds";

    /** "/env/common/splats/hydrocarbon_strategic.dds" - literal at 0x00E474B0. */
    constexpr const char* kHydrocarbonStrategicSplat = "/env/common/splats/hydrocarbon_strategic.dds";

    /**
     * Splat quads are drawn unmodulated (`or eax, 0FFFFFFFFh` at 0x00862F63 /
     * 0x00863361 feeds all four vertex colour lanes); the tint lives in the
     * texture.
     */
    constexpr std::uint32_t kResourceSplatColor = 0xFFFFFFFFu;

    /**
     * A splat quad is half the texture's pixel size: both extents are the
     * dimension shifted right by two, i.e. width/4 either side of the centre
     * (`shr eax, 2` at 0x0086309D / 0x008630B9, and again at 0x00863298 /
     * 0x008632B4). The `fild` + negative fixup around each shift is the
     * unsigned-to-float conversion of the `std::uint32_t` dimension.
     */
    constexpr std::uint32_t kResourceSplatHalfExtentShift = 2u;

    /**
     * Address: 0x0086309A..0x0086325A (mass splat run, inlined)
     * Address: 0x00863295..0x00863455 (hydrocarbon splat run, inlined)
     *
     * What it does:
     * Binds one strategic-resource splat texture and emits one screen-space
     * quad per collected deposit centre. The compiler emitted this twice, once
     * per resource kind, from what was plainly one helper: both runs compute
     * the same half-extents, bind through the same `SetTexture` overload and
     * build the same four vertices, differing only in which stack slots the
     * scheduler picked for them.
     *
     * A missing texture skips the whole run (`test ecx, ecx` / `jz` at
     * 0x00863092 and 0x0086328D), but an empty point list still binds the
     * texture - the count test comes after `SetTexture` in both runs.
     */
    void DrawResourceSplats(
      CD3DPrimBatcher& primBatcher,
      const boost::shared_ptr<CD3DBatchTexture>& splat,
      const gpg::fastvector<Wm3::Vector2f>& screenPoints
    )
    {
      if (!splat) {
        return;
      }

      const float halfWidth = static_cast<float>(splat->mWidth >> kResourceSplatHalfExtentShift);
      const float halfHeight = static_cast<float>(splat->mHeight >> kResourceSplatHalfExtentShift);
      primBatcher.SetTexture(splat);

      for (const Wm3::Vector2f& centre : screenPoints) {
        const float left = centre.X() - halfWidth;
        const float right = centre.X() + halfWidth;
        const float top = centre.Y() - halfHeight;
        const float bottom = centre.Y() + halfHeight;

        const CD3DPrimBatcher::Vertex topLeft{left, top, 0.0f, kResourceSplatColor, 0.0f, 0.0f};
        const CD3DPrimBatcher::Vertex bottomLeft{left, bottom, 0.0f, kResourceSplatColor, 0.0f, 1.0f};
        const CD3DPrimBatcher::Vertex bottomRight{right, bottom, 0.0f, kResourceSplatColor, 1.0f, 1.0f};
        const CD3DPrimBatcher::Vertex topRight{right, top, 0.0f, kResourceSplatColor, 1.0f, 0.0f};
        primBatcher.DrawQuad(topLeft, bottomLeft, bottomRight, topRight);
      }
    }
  } // namespace

  /**
   * Address: 0x00862A80 (FUN_00862A80, ?RenderResources@CWldSession@Moho@@QAEXPAVGeomCamera3@2@PAVCD3DPrimBatcher@2@@Z)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::RenderResources(Moho::CWldSession *this,
   *   Moho::GeomCamera3 *camera@<ecx>, Moho::CD3DPrimBatcher *primBatcher);
   *
   * What it does:
   * Draws the strategic-view mass and hydrocarbon splats. Binds the
   * `TResourceIcon` technique of the `primbatcher` effect, pushes the wall
   * clock into that effect's `time` variable, switches the batcher to the
   * pixel-exact screen projection, then asks the sim's resource registry for
   * every deposit whose terrain AABB intersects the camera's second frustum
   * solid. Each deposit that lies wholly inside the playable rect and whose
   * terrain-height centre is nearer than `UI_ResourceLODCutoff` is projected
   * to a whole screen pixel and bucketed by resource kind; the two buckets are
   * then drawn with their respective splat textures and flushed.
   *
   * Locals map, from the frame slots the disassembly actually uses (IDA's own
   * frame naming past 0x00862D3A is shifted 0x10 low because it does not model
   * the indirect `DepositCollides` call's argument purge, which is why the
   * decompile aliases unrelated slots onto one another):
   *   ebp-0x7F8 `gpg::fastvector_n<Wm3::Vector2f, 16>` hydrocarbon points
   *             (inline window ebp-0x7E8 .. ebp-0x768 = 0x80 bytes)
   *   ebp-0x768 `gpg::fastvector_n<Wm3::Vector2f, 64>` mass points
   *             (inline window ebp-0x758 .. ebp-0x558 = 0x200 bytes)
   *   ebp-0x558 `gpg::fastvector_n<ResourceDeposit, 64>` query output
   *             (inline window ebp-0x548 .. ebp-0x48  = 0x500 bytes)
   *   ebp-0x898 .. ebp-0x88C  the playable rect, copied out of `STIMap`
   *   ebp-0x8B0 .. ebp-0x8A8  the deposit centre (x, terrain height, z)
   *   ebp-0x8B8 / ebp-0x8B4   the floored screen pixel
   *   ebp-0x848 / ebp-0x850   the mass / hydrocarbon splat handles
   */
  void CWldSession::RenderResources(GeomCamera3* const camera, CD3DPrimBatcher* const primBatcher)
  {
    // 0x00862AA6..0x00862ACC: `D3D_GetDevice()->SelectFxFile("primbatcher")`,
    // `SelectTechnique("TResourceIcon")` and the composite-matrix invalidation
    // are `CD3DPrimBatcher::Setup` (0x00438560) inlined verbatim.
    (void)primBatcher->Setup("TResourceIcon");

    // The resource-icon shader animates off the process wall clock, not off a
    // sim tick - `gpg::time::GetSystemTimer().ElapsedSeconds()` at
    // 0x00862AD3/0x00862ADA.
    const float shaderTime = gpg::time::GetSystemTimer().ElapsedSeconds();
    if (shaderVarPrimBatcherTime.Exists()) {
      shaderVarPrimBatcherTime.SetFloat(shaderTime);
    }

    // Raw viewport extents, not the whole-pixel truncation the projection
    // matrix below uses: 0x00862B18/0x00862B20 keep the untruncated floats and
    // 0x00862F42/0x00862F56 map NDC onto them.
    const float viewportWidth = camera->viewport.r[3].z;
    const float viewportHeight = camera->viewport.r[3].w;

    // `mWldMap->mTerrainRes` + 0x04 is the active `STIMap`; its playable rect
    // sits at +0x08 (0x00862B09..0x00862B4D reads all four bounds).
    const VisibilityRect& playableRect = VisibilityRect::FromRect2i(mWldMap->mTerrainRes->mMap->mPlayableRect);

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(*camera));
    primBatcher->SetViewMatrix(VMatrix4::Identity());

    IResources* const resources = mSimResources.px;
    CHeightField* const heightField = mWldMap->mTerrainRes->GetHeightField();

    // Declaration order is the binary's: the tail destroys the query output
    // first (0x008634DB), then the hydrocarbon bucket (0x00863512), then the
    // mass bucket (0x00863549).
    gpg::fastvector_n<Wm3::Vector2f, 64> massPoints;
    gpg::fastvector_n<Wm3::Vector2f, 16> hydrocarbonPoints;

    // The binary hands `DepositCollides` a 64-deposit inline fastvector. This
    // tree's `CSimResources::DepositCollides` takes the plain
    // `gpg::fastvector<T>` base and appends through that base's `PushBack`,
    // whose grow path frees `start_` unconditionally, so an inline window
    // cannot be handed across the call - heap-backed on purpose, same as the
    // projectile-arc `Collect` site.
    gpg::fastvector<ResourceDeposit> deposits;

    // Virtual dispatch through `IResources` slot 7 (`[vftable+0x1C]` at
    // 0x00862D2D..0x00862D3A). `kNone` asks for every deposit kind.
    resources->DepositCollides(&camera->solid2, heightField, &deposits, kNone);

    for (const ResourceDeposit& deposit : deposits) {
      const gpg::Rect2i& footprint = deposit.footprintRect;

      // Centre of the integer footprint, computed the binary's way: the extent
      // is differenced in integers first, then halved and re-based
      // (0x00862D8A..0x00862DC5).
      const float centreX =
        (static_cast<float>(footprint.x1 - footprint.x0) * 0.5f) + static_cast<float>(footprint.x0);
      const float centreZ =
        (static_cast<float>(footprint.z1 - footprint.z0) * 0.5f) + static_cast<float>(footprint.z0);

      // A deposit that pokes out of the playable rect is dropped whole, not
      // clipped (four signed compares at 0x00862DB1..0x00862DF4).
      if (footprint.x0 < playableRect.minX || playableRect.maxX < footprint.x1 ||
          footprint.z0 < playableRect.minZ || playableRect.maxZ < footprint.z1) {
        continue;
      }

      const Wm3::Vector3f centre{centreX, heightField->GetElevation(centreX, centreZ), centreZ};

      // Row 1 of the viewport matrix carries the renderer's LOD depth; splats
      // stop drawing past the cutoff (0x00862E15..0x00862E6F).
      if (camera->viewport.ProjectViewportDepthRow1(centre) <= UI_ResourceLODCutoff) {
        continue;
      }

      // 0x00862E75..0x00862F5F is `GeomCamera3::Project` (0x00470F60) inlined
      // over a viewport anchored at the origin with a flipped Y axis: x maps
      // onto [0, width] and y onto [height, -0]. The two zero terms fold away
      // in the emission, which is why no `sub`/`add` against them survives.
      const Wm3::Vector2f projected = camera->Project(centre, 0.0f, viewportWidth, viewportHeight, -0.0f);

      // Splats snap to whole pixels so the texture samples 1:1 (two `floor`
      // calls at 0x00862F81 / 0x00862F91).
      const Wm3::Vector2f screenPoint{std::floor(projected.X()), std::floor(projected.Y())};

      if (deposit.depositType == kMass) {
        massPoints.push_back(screenPoint);
      } else {
        hydrocarbonPoints.push_back(screenPoint);
      }
    }

    // Both handles stay alive until after the flush - the binary releases the
    // hydrocarbon one at 0x00863469 and the mass one at 0x008634A6, both past
    // `Flush`. The `1` border argument asks `FromFile` for a one-texel guard
    // band so the atlas neighbours cannot bleed into the splat.
    const boost::shared_ptr<CD3DBatchTexture> massSplat = CD3DBatchTexture::FromFile(kMassStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, massSplat, massPoints);

    const boost::shared_ptr<CD3DBatchTexture> hydrocarbonSplat =
      CD3DBatchTexture::FromFile(kHydrocarbonStrategicSplat, 1u);
    DrawResourceSplats(*primBatcher, hydrocarbonSplat, hydrocarbonPoints);

    primBatcher->Flush();
  }

  namespace
  {
    // The economy lanes below are per-tick rates and the overlay shows them per
    // second; the sim runs ten ticks a second (0x00DFF31C).
    constexpr float kEconOverlayTicksPerSecond = 10.0f;

    // Inside this magnitude the rate is printed with one decimal, outside it as
    // a whole number (0x008591FA / 0x0085927B against 0x00DFF31C / 0x00E4F910).
    constexpr float kEconOverlayDecimalCutoff = 10.0f;

    // Opaque black - the drop-shadow pass (pushed at 0x008597B9 / 0x008598A8).
    constexpr std::uint32_t kEconOverlayShadowColor = 0xFF000000u;

    // Unmodulated white - the bar slices carry their own texture colour.
    constexpr std::uint32_t kEconOverlayBarColor = 0xFFFFFFFFu;

    // The shadow pass is offset one pixel right and down (0x00DFEC20 == 1.0f).
    constexpr float kEconOverlayShadowOffset = 1.0f;

    // `/lua/ui/game/econoverlayparams.lua` lanes, in the order the import reads
    // them. Each is left at its previous value when the key is absent.
    std::uint32_t gEconOverlayPositiveColor = 0;                    // 0x00F57C00
    std::uint32_t gEconOverlayNegativeColor = 0;                    // 0x00F57BFC
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayLeftTexture{};  // 0x010C4230
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayRightTexture{}; // 0x010C4238
    boost::shared_ptr<CD3DBatchTexture> gEconOverlayMidTexture{};   // 0x010C4244
    msvc8::string gEconOverlayFontName{};                           // 0x00F5B210
    std::int32_t gEconOverlayFontSize = 0;                          // 0x00F57C04
    float gEconOverlayEnergyTopOffset = 0.0f;                       // 0x010A6458
    float gEconOverlayMassTopOffset = 0.0f;                         // 0x00F57C08

    bool gEconOverlayParamsImported = false;                        // 0x010A6449
    CD3DFont* gEconOverlayFont = nullptr;                           // 0x010C4228

    /**
     * Address: 0x00858850 (FUN_00858850, Moho::func_ImportEconOverlayParams)
     *
     * IDA signature:
     * void __cdecl func_ImportEconOverlayParams();
     *
     * What it does:
     * Imports `/lua/ui/game/econoverlayparams.lua` and copies the nine optional
     * `EconOverlayParams` fields into the lanes above. Every field is looked up
     * twice exactly as the binary does it: once for an `IsNil` probe on a
     * throwaway object, and again to read the value, so a missing key leaves
     * the previous value untouched.
     */
    void ImportEconOverlayParams()
    {
      LuaPlus::LuaState* const state = static_cast<CUIManager*>(UI_GetManager())->mLuaState;

      LuaPlus::LuaObject module = SCR_Import(state, "/lua/ui/game/econoverlayparams.lua");
      if (module.IsNil()) {
        return;
      }

      LuaPlus::LuaObject params = module["EconOverlayParams"];
      if (!params.IsTable()) {
        return;
      }

      if (!params["positiveColor"].IsNil()) {
        gEconOverlayPositiveColor = SCR_DecodeColor(state, params["positiveColor"]);
      }
      if (!params["negativeColor"].IsNil()) {
        gEconOverlayNegativeColor = SCR_DecodeColor(state, params["negativeColor"]);
      }
      if (!params["leftTexture"].IsNil()) {
        gEconOverlayLeftTexture = CD3DBatchTexture::FromFile(params["leftTexture"].GetString(), 1u);
      }
      if (!params["midTexture"].IsNil()) {
        gEconOverlayMidTexture = CD3DBatchTexture::FromFile(params["midTexture"].GetString(), 1u);
      }
      if (!params["rightTexture"].IsNil()) {
        gEconOverlayRightTexture =
          CD3DBatchTexture::FromFile(params["rightTexture"].GetString(), 1u);
      }
      if (!params["fontName"].IsNil()) {
        const char* const fontName = params["fontName"].GetString();
        (void)gEconOverlayFontName.assign(fontName, std::strlen(fontName));
      }
      if (!params["fontSize"].IsNil()) {
        gEconOverlayFontSize = static_cast<std::int32_t>(params["fontSize"].GetNumber());
      }
      if (!params["energyTopOffset"].IsNil()) {
        gEconOverlayEnergyTopOffset = static_cast<float>(params["energyTopOffset"].GetNumber());
      }
      if (!params["massTopOffset"].IsNil()) {
        gEconOverlayMassTopOffset = static_cast<float>(params["massTopOffset"].GetNumber());
      }
    }

    /**
     * What it does:
     * Formats one per-second resource rate into `out` the way the overlay does
     * it at 0x008591E3 and 0x00859275: one decimal while the magnitude stays
     * inside +/-10, a whole number outside it. NaN takes the whole-number path,
     * because the binary branches on an unordered `comiss`.
     *
     * The binary prints into a temporary and then assigns that temporary into
     * the caller's string; kept in that shape so the temporary's storage is
     * released before the draw, as in the binary.
     */
    void FormatEconomyRateInto(
      msvc8::string& out,
      const float ratePerSecond,
      const char* const wholeFormat,
      const char* const decimalFormat
    )
    {
      const bool useDecimals =
        kEconOverlayDecimalCutoff > ratePerSecond && ratePerSecond > -kEconOverlayDecimalCutoff;
      const msvc8::string formatted =
        useDecimals ? gpg::STR_Printf(decimalFormat, static_cast<double>(ratePerSecond))
                    : gpg::STR_Printf(wholeFormat, static_cast<std::int32_t>(ratePerSecond));
      (void)out.assign(formatted, 0, msvc8::string::npos);
    }

    /**
     * What it does:
     * Emits one axis-aligned, fully-mapped quad of the economy bar. The three
     * slice draws at 0x0085952E, 0x00859659 and 0x0085977F write byte-identical
     * vertex blocks apart from the x range, so they share this helper.
     */
    void DrawEconomyOverlaySlice(
      CD3DPrimBatcher& primBatcher, const float x0, const float y0, const float x1, const float y1
    )
    {
      const CD3DPrimBatcher::Vertex topLeft{x0, y0, 0.0f, kEconOverlayBarColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{x1, y0, 0.0f, kEconOverlayBarColor, 1.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{x1, y1, 0.0f, kEconOverlayBarColor, 1.0f, 1.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{x0, y1, 0.0f, kEconOverlayBarColor, 0.0f, 1.0f};
      primBatcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    /**
     * What it does:
     * Draws one economy number. `Render2D`'s two trailing floats are not
     * materialised at the binary's call sites (0x008597FB, 0x00859877,
     * 0x008598E5 and 0x00859961 push only this/text/colour and hand the origin
     * over in `eax`), and the recovered `Render2D` ignores `maxAdvance` while
     * `Render` ignores `glyphScale`, so both are passed as zero here.
     */
    void DrawEconomyOverlayLabel(
      CD3DFont& font,
      CD3DPrimBatcher& primBatcher,
      const msvc8::string& text,
      const float x,
      const float y,
      const std::uint32_t color
    )
    {
      const Wm3::Vector2f origin{x, y};
      font.Render2D(text.c_str(), &primBatcher, origin, color, 0.0f, 0.0f);
    }
  } // namespace

  /**
   * Address: 0x00858D80 (FUN_00858D80, Moho::CWldSession::DrawEconomyOverlay)
   *
   * IDA signature:
   * void __usercall Moho::CWldSession::DrawEconomyOverlay(
   *   CWldSession *session, CD3DPrimBatcher *batcher, CWldMap *map,
   *   CameraImpl *camera@<ecx>);
   *
   * What it does:
   * Draws the net energy/mass rate readout over every army unit in the camera
   * frustum - see the header for the full description.
   */
  void CWldSession::DrawEconomyOverlay(
    CameraImpl* const camera, CD3DPrimBatcher* const primBatcher, [[maybe_unused]] const float tickFraction
  )
  {
    if (!DisplayEconomyOverlay) {
      return;
    }

    if (!gEconOverlayParamsImported) {
      ImportEconOverlayParams();
      gEconOverlayParamsImported = true;
    }

    if (gEconOverlayFont == nullptr) {
      // `Create` hands back a borrowed shared lane; the overlay keeps its own
      // intrusive reference on the font and releases the lane straight away.
      boost::SharedPtrRaw<CD3DFont> created =
        CD3DFont::Create(gEconOverlayFontSize, gEconOverlayFontName.c_str());
      CD3DFont* const font = created.px;
      if (gEconOverlayFont != font) {
        if (gEconOverlayFont != nullptr) {
          (void)gEconOverlayFont->ReleaseReference();
        }
        gEconOverlayFont = font;
        if (font != nullptr) {
          font->AddReference();
        }
      }
      created.release();
    }

    (void)primBatcher->Setup("TAlphaBlendLinearSampleNoDepth");

    const GeomCamera3& view = camera->CameraGetView();

    // The binary inlines the same pixel-exact screen projection here that
    // RenderProjectileArcs inlines at 0x0086010B; it lives on GeomCamera3 now.
    const float viewportWidth = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].z));
    const float viewportHeight = static_cast<float>(static_cast<std::int32_t>(view.viewport.r[3].w));

    primBatcher->SetProjectionMatrix(MakeViewportPixelProjection(view));
    primBatcher->SetViewMatrix(VMatrix4::Identity()); // 0x00858FE6 (sIdentity)

    for (const WeakPtr<UserEntity>& weakRef : *camera->GetArmyUnitsInFrustum()) {
      UserEntity* const entity = weakRef.GetObjectPtr();
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const unit = entity->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      IUnit* const unitBridge = GetIUnitBridge(unit);
      if (unitBridge->IsDead() || unitBridge->DestroyQueued()) {
        continue;
      }

      // Only units still drawn as meshes get the readout: past the mesh's
      // icon-fade-in depth the unit is a strategic icon and the bar would
      // clutter the map.
      const RMeshBlueprint* const meshBlueprint = unit->mVariableData.mMeshBlueprint;
      if (meshBlueprint == nullptr) {
        continue;
      }
      if (view.viewport.ProjectViewportDepthRow1(unitBridge->GetPosition())
          >= meshBlueprint->mIconFadeInZoom) {
        continue;
      }

      // The binary dispatches through the blueprint accessor here and discards
      // the result (0x008590CF); kept because the virtual call is observable.
      (void)unitBridge->GetBlueprint();

      const SSTIUnitEconomyPair& produced = unit->mUnitVarDat.mProduced;
      const SSTIUnitEconomyPair& upkeep = unit->mUnitVarDat.mMaintainenceCost;
      const float energyRate = produced.ENERGY - upkeep.ENERGY;
      const float massRate = produced.MASS - upkeep.MASS;
      if (energyRate == 0.0f && massRate == 0.0f) {
        continue;
      }

      const float energyPerSecond = energyRate * kEconOverlayTicksPerSecond;
      const float massPerSecond = massRate * kEconOverlayTicksPerSecond;

      // Not a parameter: the binary reads a frame local at -4 that is stored
      // once from a zeroed ebx (0x00858DAF -> 0x00858E0E) and never rewritten,
      // so the overlay always samples the untick-interpolated position.
      const Wm3::Vector3f worldPosition = entity->GetInterpolatedPosition(0.0f);
      const Wm3::Vector2f screenPosition =
        view.Project(worldPosition, 0.0f, viewportWidth, viewportHeight, 0.0f);

      msvc8::string energyText{};
      msvc8::string massText{};
      FormatEconomyRateInto(energyText, energyPerSecond, "%+4i ", "%+4.1f ");
      FormatEconomyRateInto(massText, massPerSecond, "%+4i", "%+4.1f");

      // The bar is as wide as the wider of the two numbers and as tall as the
      // middle slice, centred on the projected position and snapped to whole
      // pixels.
      const float energyAdvance = gEconOverlayFont->GetAdvance(energyText.c_str(), 0);
      const float massAdvance = gEconOverlayFont->GetAdvance(massText.c_str(), 0);
      const float barWidth = massAdvance > energyAdvance ? massAdvance : energyAdvance;
      const float barHeight = static_cast<float>(gEconOverlayMidTexture->mHeight);

      const float barLeft = std::floor(screenPosition.x - (barWidth * 0.5f));
      const float barTop = std::floor(screenPosition.y - (barHeight * 0.5f));
      const float barRight = barLeft + barWidth;
      const float barBottom = barTop + barHeight;

      primBatcher->SetTexture(gEconOverlayMidTexture);
      DrawEconomyOverlaySlice(*primBatcher, barLeft, barTop, barRight, barBottom);

      primBatcher->SetTexture(gEconOverlayLeftTexture);
      const float leftCapWidth = static_cast<float>(gEconOverlayLeftTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barLeft - leftCapWidth, barTop, barLeft, barBottom);

      primBatcher->SetTexture(gEconOverlayRightTexture);
      const float rightCapWidth = static_cast<float>(gEconOverlayRightTexture->mWidth);
      DrawEconomyOverlaySlice(*primBatcher, barRight, barTop, barRight + rightCapWidth, barBottom);

      // Each number is drawn twice: an opaque black shadow one pixel down and
      // right, then the value itself in the sign colour.
      const float fontHeight = gEconOverlayFont->mHeight;
      const float energyBaseline = std::floor(gEconOverlayEnergyTopOffset) + fontHeight + barTop;
      const float massBaseline = std::floor(gEconOverlayMassTopOffset) + fontHeight + barTop;
      const std::uint32_t energyColor =
        energyPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;
      const std::uint32_t massColor =
        massPerSecond < 0.0f ? gEconOverlayNegativeColor : gEconOverlayPositiveColor;

      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        energyText,
        barLeft + kEconOverlayShadowOffset,
        energyBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont, *primBatcher, energyText, barLeft, energyBaseline, energyColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont,
        *primBatcher,
        massText,
        barLeft + kEconOverlayShadowOffset,
        massBaseline + kEconOverlayShadowOffset,
        kEconOverlayShadowColor
      );
      DrawEconomyOverlayLabel(
        *gEconOverlayFont, *primBatcher, massText, barLeft, massBaseline, massColor
      );
    }

    primBatcher->Flush();
  }

  namespace
  {
    /**
     * Address: 0x0088BEE0 (FUN_0088BEE0, Moho::func_DoPreload)
     *
     * IDA signature:
     * void func_DoPreload();
     *
     * What it does:
     * Drives the world-session `Preload` frame action: tears down any active
     * world-session runtime, saves user preferences, restarts the in-game UI
     * lane on the active Lua state, opens the world UI provider's loading
     * dialog, asks the session loader to prefetch the pending session's
     * scenario, installs the no-op `IClientMgrUIInterface` bootstrap on the
     * pending session's client manager, and transitions the world-frame
     * dispatch lane to `Loading`. The bracketing ` DoPreload 1` / ` DoPreload
     * 2` `std::string` temporaries match the binary's profiler-marker shape
     * (built and immediately destroyed with no consumer in the retail body).
     */
    void WLD_DoPreload()
    {
      // ` DoPreload 1` bracket marker: the retail binary constructs one
      // 12-byte `std::string` literal here purely as a profiler/log marker
      // and discards it immediately. Preserved 1:1 to keep observable
      // string-allocation side effects (operator new/delete pair when the
      // SSO threshold would be exceeded) identical to the binary.
      {
        const std::string marker(" DoPreload 1", 12u);
        (void)marker;
      }

      WLD_Teardown();
      USER_SavePreferences();

      LuaPlus::LuaState* const state = USER_GetLuaState();
      (void)UI_StartGameUI(state);

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->StartLoadingDialog();
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      SWldSessionInfo* const pendingSession = gPendingWldSessionInfo.get();
      if (loader != nullptr && pendingSession != nullptr) {
        LaunchInfoBase* const launchInfo = pendingSession->mLaunchInfo.get();
        if (launchInfo != nullptr) {
          // Binary slot 2 dispatch on `IWldSessionLoader` is
          // `GetScenarioInfo(mapName, &mGameMods, setGameData)`. The retail
          // call site at 0x0088BF52 only pushes 2 args; the third dword
          // consumed by the callee's `retn 0Ch` is whatever stale stack
          // value sits at `[esp+8]`. Recover as a 3-arg invocation with the
          // setGameData lane wired to the prefetch-then-mark semantics the
          // preload action needs (mark the requested scenario as the active
          // game-data target before the `Loading` action begins iterating
          // on it).
          (void)loader->GetScenarioInfo(
            pendingSession->mMapName.raw_data_unsafe(), &launchInfo->mGameMods, true
          );
        }
      }

      if (pendingSession != nullptr && pendingSession->mClientManager != nullptr) {
        pendingSession->mClientManager->SetUIInterface(&sCWldUiInterface);
      }

      gWldFrameAction = EWldFrameAction::Loading;

      // ` DoPreload 2` bracket marker (paired with the opening marker
      // above): same profiler/log-string discard pattern.
      {
        const std::string marker(" DoPreload 2", 12u);
        (void)marker;
      }
    }

    /**
     * Address: 0x0088C000 (FUN_0088C000, func_DoLoading)
     *
     * IDA signature:
     * void __cdecl func_DoLoading(bool *outContinue);
     *
     * What it does:
     * Drives the world-session `Loading` frame action. Every frame it beats the
     * client manager; once the loader reports the scenario in hand it takes
     * ownership of the loaded Lua state / game rules / map, builds the session,
     * gives the launch info its own copy of the playable map and the player's
     * language, opens the replay sink when the session is recorded, creates the
     * sim driver, and hands the frame machine on to `Initialize`.
     *
     * This transition is the whole point of the function. Until it was
     * recovered, `Loading` fell through to `CreateSession` - a state that in
     * the binary only exists for an explicit restart request - and
     * `WLD_CreateSessionInfo` bounced straight back to `Preload`, so a skirmish
     * cycled Preload -> Loading -> CreateSession forever, restarting the
     * in-game UI and reopening the loading movie on every lap.
     *
     * The bracketing ` DoLoading N` `std::string` temporaries are the binary's
     * profiler markers: built and immediately discarded, kept for the identical
     * allocation side effects.
     */
    void WLD_DoLoading(bool* const outContinue)
    {
      {
        const std::string marker(" DoLoading 1", 12u);
        (void)marker;
      }

      SWldSessionInfo* const sessionInfo = gPendingWldSessionInfo.get();
      if (sessionInfo != nullptr && sessionInfo->mClientManager != nullptr) {
        sessionInfo->mClientManager->DoBeat();
      }

      CWldSessionLoaderImpl* const loader = GetWldSessionLoader();
      if (loader == nullptr || !loader->IsLoaded()) {
        return;
      }

      {
        const std::string marker(" DoLoading 2", 12u);
        (void)marker;
      }

      SWldGameData gameData{};
      (void)loader->LoadGameData(&gameData);

      if (gameData.mGameRules == nullptr) {
        gpg::Warnf("map %s failed.  aborting session.", sessionInfo->mMapName.c_str());
        if (gWldFrameAction != EWldFrameAction::Inactive) {
          gWldFrameAction = EWldFrameAction::Exit;
        }
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        ReleaseWldGameDataHandles(&gameData);
        return;
      }

      // The replay sink, when this session records one. A sink that cannot be
      // opened is not fatal - the session simply stops being a recorded one.
      msvc8::auto_ptr<gpg::Stream> replayStream(nullptr);
      if (sessionInfo->mIsBeingRecorded) {
        const msvc8::string defaultReplayName = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
        replayStream = VCR_CreateReplay(sessionInfo, defaultReplayName.c_str());
        if (replayStream.get() == nullptr) {
          sessionInfo->mIsBeingRecorded = false;
        }
      }

      {
        const std::string marker(" DoLoading 3");
        (void)marker;
      }

      msvc8::auto_ptr<LuaPlus::LuaState> stateOwner(gameData.mState);
      msvc8::auto_ptr<RRuleGameRules> rulesOwner(gameData.mGameRules);
      msvc8::auto_ptr<CWldMap> mapOwner(gameData.mWldMap);
      gameData = SWldGameData{};
      CWldSession* const wldSession = WLD_CreateSession(stateOwner, rulesOwner, mapOwner, *sessionInfo);

      // The launch info keeps its own copy of the playable map so a restart can
      // rebuild the session without the terrain resource still being alive.
      auto* const playableMap =
        wldSession->mWldMap->mTerrainRes->mMap;
      STIMap* const launchMap = new STIMap(playableMap);

      LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
      launchInfo->mGameRules = wldSession->mRules;
      if (launchMap != launchInfo->mMap && launchInfo->mMap != nullptr) {
        delete launchInfo->mMap;
      }
      launchInfo->mMap = launchMap;

      launchInfo->mLanguage.assign_owned(wldSession->mState->GetGlobal("__language").ToString());

      if (!wldSession->IsMultiplayer && !wldSession->IsReplay) {
        // Single player: the session takes a shared owner on a fresh clone of
        // the launch info, which is what a mid-game save serializes.
        boost::SharedPtrRaw<void> createdLaunchInfo{};
        launchInfo->Create(createdLaunchInfo);

        boost::SharedPtrRaw<LaunchInfoBase> createdTyped{};
        createdTyped.px = static_cast<LaunchInfoBase*>(createdLaunchInfo.px);
        createdTyped.pi = createdLaunchInfo.pi;
        wldSession->mLaunchInfo = boost::SharedPtrFromRawRetained(createdTyped);
        createdLaunchInfo.release();
      }

      {
        const std::string marker(" DoLoading 4");
        (void)marker;
      }

      if (LaunchInfoNew* const newLaunchInfo = launchInfo->GetNew(); newLaunchInfo != nullptr) {
        newLaunchInfo->mProps = wldSession->mWldMap->mProps;
      }

      {
        const std::string marker(" DoLoading 5");
        (void)marker;
      }

      // Ownership of both the client manager and the replay sink moves into the
      // driver; the session info gives its client manager up here.
      IClientManager* const clientManager = sessionInfo->mClientManager;
      sessionInfo->mClientManager = nullptr;
      // 0x0088C364..0x0088C37C: the inlined `scoped_ptr::reset` - the new
      // driver is stored first, then the previous one is deleted.
      sSimDriver.reset(SIM_CreateDriver(
        static_cast<CClientManagerImpl*>(clientManager),
        replayStream.release(),
        sessionInfo->mLaunchInfo,
        sessionInfo->mSourceId
      ));

      gWldFrameAction = EWldFrameAction::Initialize;
      if (outContinue != nullptr) {
        *outContinue = true;
      }

      {
        const std::string marker(" DoLoading 6");
        (void)marker;
      }

      ReleaseWldGameDataHandles(&gameData);
    }

    /**
     * Address: 0x0088C3F0 (FUN_0088C3F0, func_DoInitializing)
     *
     * What it does:
     * Waits for the sim to publish its first sync data, then performs the whole
     * loading-to-playing handover: starts the game Lua UI, takes down the
     * loading dialog, builds the in-game interface, drops the now-consumed
     * session info, runs the loader's teardown callbacks, and finally tells the
     * client manager that this client has finished loading.
     */
    void WLD_DoInitializing(bool* const outContinue)
    {
      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        if (outContinue != nullptr) {
          *outContinue = false;
        }
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      if (!simDriver->HasSyncData()) {
        return;
      }

      CWldSession* const session = gActiveWldSession;
      if (session != nullptr && session->mState != nullptr) {
        (void)UI_StartGameUI(session->mState);
      }

      // Apply the first sync payload. This has to happen before
      // `CreateGameInterface` below: the packet carries the initial armies and
      // entities, and the in-game UI reads them as it builds.
      if (session != nullptr) {
        SSyncData* syncData = nullptr;
        simDriver->GetSyncData(syncData);
        session->DoBeat(msvc8::auto_ptr<SSyncData>(syncData));
      }

      IWldUIProvider* const wldUIProvider = ResolveWldUIProvider();
      if (wldUIProvider != nullptr) {
        wldUIProvider->StopLoadingDialog();
      }

      // TEMPORARY PROBE (do not commit). `mOutstandingRequests` stays at 1
      // forever, which means `clientManager->Cleanup()` below never runs and
      // the session sits in Waiting. `CreateGameInterface` is the one call
      // between here and there that can throw (it runs the UI's Lua
      // `CreateGameInterface`), so bracket it and report which side we reach.
      ::OutputDebugStringA("[INITDIAG] before CreateGameInterface\n");
      if (wldUIProvider != nullptr) {
        // TEMPORARY PROBE (do not commit). Confirmed: this call never returns,
        // so `clientManager->Cleanup()` below is skipped and the session is
        // stuck in Waiting forever. Catch it just long enough to print what.
        try {
          wldUIProvider->CreateGameInterface(gPendingWldSessionInfo != nullptr && gPendingWldSessionInfo->mIsReplay);
        } catch (const std::exception& ex) {
          char probe[512];
          sprintf_s(probe, "[INITDIAG] CreateGameInterface THREW std::exception: %.400s\n", ex.what());
          ::OutputDebugStringA(probe);
        } catch (...) {
          ::OutputDebugStringA("[INITDIAG] CreateGameInterface THREW non-std exception\n");
        }
      }
      ::OutputDebugStringA("[INITDIAG] after CreateGameInterface\n");

      // The session info existed only to carry launch parameters into the
      // session; the session owns everything it needed by now.
      gPendingWldSessionInfo.reset();

      (void)WLD_DispatchOnTeardownCallbacksCoreFromGlobalList();

      // Declare this client ready. `CClientManagerImpl::Cleanup` is the only
      // writer of `mWeAreReady`, which `DoBeat` needs before it will ever set
      // `mEveryoneIsReady` - so without this the session sits in Waiting
      // forever showing "waiting for other players", local game or not.
      if (CClientManagerImpl* const clientManager = simDriver->GetClientManager(); clientManager != nullptr) {
        ::OutputDebugStringA("[INITDIAG] declaring ready (Cleanup)\n");  // TEMPORARY PROBE
        clientManager->Cleanup();
      } else {
        ::OutputDebugStringA("[INITDIAG] NO client manager - ready never declared\n");  // TEMPORARY PROBE
      }

      if (outContinue != nullptr) {
        *outContinue = false;
      }
      gWldFrameAction = EWldFrameAction::PostInitialize;
    }

    /**
     * Address: 0x0088BFD0 (FUN_0088BFD0)
     *
     * What it does:
     * Signals one trailing post-init sim-driver lane, transitions world-frame
     * dispatch to `Playing`, and notifies the active world-UI provider through
     * `OnStart` when present.
     */
    int WLD_EnterPlayingAndNotifyUIProvider()
    {
      int dispatchResult = 0;
      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        simDriver->DecrementOutstandingRequestsAndSignal();
      }

      gWldFrameAction = EWldFrameAction::Playing;

      if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
        wldUIProvider->OnStart();
      }

      return dispatchResult;
    }

    /**
     * Address: 0x0088C6D0 (FUN_0088C6D0, func_DoPostInitializing)
     *
     * What it does:
     * Dispatches post-init sim/network work, transitions to playing once every
     * client is ready, and toggles waiting-dialog UI lanes during the handoff.
     */
    void WLD_DoPostInitializing(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;
        if (outContinue != nullptr) {
          *outContinue = true;
        }
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }
      } else {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StartWaitingDialog();
        }
        gWldFrameAction = EWldFrameAction::Waiting;
      }
    }

    /**
     * Address: 0x0088C750 (FUN_0088C750, func_DoWaiting)
     *
     * What it does:
     * Dispatches waiting-state sim/network work, transitions to playing when
     * all peers are ready, and fires waiting-dialog stop/start UI callbacks.
     */
    void WLD_DoWaiting(bool* const outContinue)
    {
      if (outContinue != nullptr) {
        *outContinue = false;
      }

      ISTIDriver* const simDriver = sSimDriver.get();
      if (simDriver == nullptr) {
        gWldFrameAction = EWldFrameAction::Exit;
        return;
      }

      simDriver->Dispatch();
      CClientManagerImpl* const clientManager = simDriver->GetClientManager();
      if (clientManager != nullptr && clientManager->IsEveryoneReady()) {
        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->StopWaitingDialog();
        }

        simDriver->DecrementOutstandingRequestsAndSignal();
        gWldFrameAction = EWldFrameAction::Playing;

        if (IWldUIProvider* const wldUIProvider = ResolveWldUIProvider(); wldUIProvider != nullptr) {
          wldUIProvider->OnStart();
        }

        if (outContinue != nullptr) {
          *outContinue = true;
        }
      } else {
        (void)UI_UpdateDisconnectDialogCallback();
      }
    }

    /**
     * Address: 0x0088C7C0 (FUN_0088C7C0, func_DoPlayingAction)
     *
     * What it does:
     * Dispatches one sim-driver tick, hands the current world camera set to
     * the sim driver, runs one world-session frame, fires the trailing
     * sim-driver post-frame slot, and pumps the disconnect dialog callback.
     */
    void WLD_DoPlayingAction(const float deltaSeconds)
    {
      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        simDriver->Dispatch();

        // Snapshot every active GeomCamera and forward to the sim driver so
        // visibility/projection state matches the upcoming session frame.
        const msvc8::vector<GeomCamera3> cameras = CAM_GetAllCameras();
        simDriver->SetGeomCams(cameras);
      }

      if (CWldSession* const activeSession = WLD_GetActiveSession(); activeSession != nullptr) {
        activeSession->SessionFrame(deltaSeconds);
      }

      if (ISTIDriver* const simDriver = sSimDriver.get(); simDriver != nullptr) {
        // Trailing sim-driver post-frame slot (Func1 in IDA): currently
        // a NoOp until full ISTIDriver vtable slot ownership is recovered.
        simDriver->NoOp();
      }

      (void)UI_UpdateDisconnectDialogCallback();
    }

    void WLD_CreateSessionInfo()
    {
      // Full `FUN_0088C9D0` session-info recreation still depends on
      // unrecovered LaunchInfoNew/session bootstrap ownership lanes.
      gWldFrameAction = EWldFrameAction::Preload;
    }
  } // namespace

  /**
   * Address: 0x0088BD20 (FUN_0088BD20, ?WLD_SetUIProvider@Moho@@YAXPAVIWldUIProvider@1@@Z)
   *
   * What it does:
   * Replaces the process-global world-UI provider ownership lane, deleting the
   * previous provider when it differs from the new one.
   */
  void WLD_SetUIProvider(IWldUIProvider* const provider)
  {
    if (sWldUIProvider != provider && sWldUIProvider != nullptr) {
      delete sWldUIProvider;
    }

    sWldUIProvider = provider;
  }

  EWldFrameAction WLD_GetFrameAction()
  {
    return gWldFrameAction;
  }

  void WLD_SetFrameAction(const EWldFrameAction action)
  {
    gWldFrameAction = action;
  }

  /**
   * Address: 0x0088BE80 (FUN_0088BE80, ?WLD_IsSessionActive@Moho@@YA_NXZ)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently active.
   */
  bool WLD_IsSessionActive()
  {
    return gWldFrameAction != EWldFrameAction::Inactive;
  }

  /**
   * Address: 0x0088BE90 (FUN_0088BE90, world-frame playing-state probe)
   *
   * What it does:
   * Returns whether world-frame dispatch is currently in the `Playing` state.
   */
  bool WLD_IsSessionPlaying()
  {
    return gWldFrameAction == EWldFrameAction::Playing;
  }

  /**
   * Address: 0x0088BEA0 (FUN_0088BEA0, ?WLD_RequestEndSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session exit when frame dispatch is currently active.
   */
  void WLD_RequestEndSession()
  {
    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088E6D0 (FUN_0088E6D0)
   *
   * What it does:
   * Console-command callback for `wld_ClientDebugDump`: when a sim driver is
   * active (`sSimDriver`, 0x010C4F50), asks it for its client manager
   * (`ISTIDriver` slot 3) and runs that manager's `Debug` dump (slot 25,
   * tail call, no null test). Registered by the `gCConFunc_wld_ClientDebugDump`
   * initializer 0x00BE7510 (the address is pushed at 0x00BE7536).
   */
  void CON_WLD_ClientDebugDump(const msvc8::vector<msvc8::string>& args)
  {
    (void)args;

    if (ISTIDriver* const simDriver = sSimDriver.get()) {
      simDriver->GetClientManager()->Debug();
    }
  }

  /**
   * Address: 0x0088E6F0 (FUN_0088E6F0)
   *
   * What it does:
   * Console-command callback that requests world-session exit when frame
   * dispatch is currently active.
   */
  void CON_WLD_RequestEndSession(const msvc8::vector<msvc8::string>& args)
  {
    (void)args;

    if (gWldFrameAction != EWldFrameAction::Inactive) {
      gWldFrameAction = EWldFrameAction::Exit;
    }
  }

  /**
   * Address: 0x0088BEC0 (FUN_0088BEC0, ?WLD_RequestRestartSession@Moho@@YAXXZ)
   *
   * What it does:
   * Requests world-session recreation when frame dispatch is active and the
   * active session carries restart launch info.
   */
  void WLD_RequestRestartSession()
  {
    if (gWldFrameAction == EWldFrameAction::Inactive) {
      return;
    }

    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession != nullptr && activeSession->mLaunchInfo) {
      gWldFrameAction = EWldFrameAction::CreateSession;
    }
  }

  /**
   * Address: 0x0088C9C0 (FUN_0088C9C0)
   *
   * What it does:
   * Tears down the current world session and then enters the front-end flow.
   */
  [[nodiscard]] bool WLD_TeardownAndStartFrontEnd()
  {
    WLD_Teardown();
    return UI_StartFrontEnd();
  }

  /**
   * Address: 0x0088CAE0 (FUN_0088CAE0, ?WLD_Frame@Moho@@YA_NM@Z)
   */
  bool WLD_Frame(const float deltaSeconds)
  {
    if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
      loader->Update();
    }

    for (;;) {
      bool continueDispatch = false;
      switch (gWldFrameAction) {
        case EWldFrameAction::Inactive:
          if (CWldSessionLoaderImpl* const loader = GetWldSessionLoader(); loader != nullptr) {
            loader->SetCreated();
          }
          return true;
        case EWldFrameAction::Preload:
          WLD_DoPreload();
          return true;
        case EWldFrameAction::Loading:
          WLD_DoLoading(&continueDispatch);
          break;
        case EWldFrameAction::Initialize:
          WLD_DoInitializing(&continueDispatch);
          break;
        case EWldFrameAction::PostInitialize:
          WLD_DoPostInitializing(&continueDispatch);
          break;
        case EWldFrameAction::Waiting:
          WLD_DoWaiting(&continueDispatch);
          break;
        case EWldFrameAction::Playing:
          WLD_DoPlayingAction(deltaSeconds);
          return true;
        case EWldFrameAction::CreateSession:
          WLD_CreateSessionInfo();
          return true;
        case EWldFrameAction::Exit:
          (void)WLD_TeardownAndStartFrontEnd();
          return true;
        default:
          return true;
      }

      if (continueDispatch) {
        continue;
      }

      return true;
    }
  }

  /**
   * Address: 0x00869810 (FUN_00869810, func_WldSessionLoader_GetOnTeardownCallbacks)
   * Address: 0x00C07650 (FUN_00C07650, atexit destructor of the session-listener registry)
   * Address: 0x00869A80 (FUN_00869A80, unreferenced copy of that atexit destructor)
   *
   * What it does:
   * Returns the process-global session-listener registry, a function-local
   * static constructed on first use.
   *
   * Every registrant (`SelectionListener`, `PauseListener`,
   * `IdleUnitSelector`) registers from its own translation unit's static
   * initialiser. A namespace-scope vector would be constructed in
   * static-initialisation order and could null the lanes those `push_back`s
   * already filled; the function-local static is constructed exactly when the
   * first registrant needs it, as in the binary.
   */
  WldTeardownCallbackVector* WLD_GetOnTeardownCallbacks()
  {
    static WldTeardownCallbackVector sCallbacks;
    return &sCallbacks;
  }

  /**
   * Address: 0x008699A0 (FUN_008699A0)
   *
   * What it does:
   * Resolves the process-global session-listener registry and attaches every
   * listener in it to the freshly created world session (vtable slot 0).
   */
  std::int32_t WLD_DispatchOnTeardownCallbacksCoreFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return static_cast<std::int32_t>(DispatchSessionListenerAttachAndReturnLastResult(callbacks));
  }

  /**
   * Address: 0x008699B0 (FUN_008699B0)
   *
   * What it does:
   * Resolves the process-global teardown-callback vector and runs the normal
   * teardown callback dispatch entry point.
   */
  [[nodiscard]] std::intptr_t WLD_RunTeardownCallbacksFromGlobalList()
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    return DoTeardownCallbacks(callbacks);
  }

  /**
   * Address: 0x00869950 (FUN_00869950)
   *
   * What it does:
   * Appends one teardown-callback pointer to the process-global callback
   * vector and returns that vector.
   */
  WldTeardownCallbackVector* WLD_AddOnTeardownCallback(IWldTeardownCallback* const callback)
  {
    WldTeardownCallbackVector* const callbacks = WLD_GetOnTeardownCallbacks();
    if (callbacks == nullptr) {
      return nullptr;
    }

    callbacks->push_back(callback);
    return callbacks;
  }

  /**
   * Address: 0x0088C860 (FUN_0088C860, ?WLD_Teardown@Moho@@YAXXZ)
   *
   * What it does:
   * Shuts the driver down and hands the session every sync packet it still
   * holds, then silences sound, runs the teardown callbacks, destroys the game
   * interface and its provider, clears the particle buckets, drops the UI Lua
   * state, deletes the session and finally releases the driver.
   *
   * The drain matters: packets the sim produced after the session's last beat
   * carry entity deletions and command releases the session would otherwise
   * never apply before it is destroyed.
   */
  void WLD_Teardown()
  {
    if (sSimDriver) {
      sSimDriver->ShutDown();
      CWldSession* const session = gActiveWldSession;
      while (sSimDriver->HasSyncData()) {
        SSyncData* syncData = nullptr;
        sSimDriver->GetSyncData(syncData);
        session->DoBeat(msvc8::auto_ptr<SSyncData>(syncData));
      }
    }

    USER_GetSound()->StopAllSounds();
    (void)DoTeardownCallbacks(WLD_GetOnTeardownCallbacks());

    if (sWldUIProvider != nullptr) {
      sWldUIProvider->DestroyGameInterface();
      delete sWldUIProvider;
      sWldUIProvider = nullptr;
    }

    sWorldParticles.ClearRenderBuckets();
    (void)g_UIManager->SetNewLuaState(nullptr);

    delete gActiveWldSession;
    gActiveWldSession = nullptr;
    gWldFrameAction = EWldFrameAction::Inactive;
    sSimDriver.reset();
  }

  /**
   * Address: 0x0088BD40 (FUN_0088BD40)
   */
  LuaPlus::LuaObject WLD_LoadScenarioInfo(const msvc8::string& scenarioFile, LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return {};
    }

    LuaPlus::LuaObject scenarioEnv(state);
    if (FILE_GetFileInfo(scenarioFile.c_str(), nullptr, false)) {
      // Both scripts run with `scenarioEnv` as their globals table, so the
      // scenario file's top-level `ScenarioInfo = {...}` lands in it rather
      // than in _G. This is the engine's own loader (VFS resolution + hook
      // concatenation + setfenv); routing it through the Lua-level `doscript`
      // binding instead loses the C++ error propagation the caller relies on.
      scenarioEnv.AssignNewTable(state, 0, 0);
      (void)SCR_LuaDoScript(state, "/lua/dataInit.lua", &scenarioEnv);
      (void)SCR_LuaDoScript(state, scenarioFile.c_str(), &scenarioEnv);
    }

    if (scenarioEnv.IsNil()) {
      return scenarioEnv;
    }

    return scenarioEnv["ScenarioInfo"];
  }

  /**
   * Address: 0x00897220 (FUN_00897220, ?WLD_CreateSession@Moho@@YAPAVCWldSession@1@AAV?$auto_ptr@VLuaState@LuaPlus@@@std@@AAV?$auto_ptr@VRRuleGameRules@Moho@@@4@AAV?$auto_ptr@VCWldMap@Moho@@@4@AAUSWldSessionInfo@1@@Z)
   *
   * What it does:
   * Allocates one world-session object, constructs it from transferred
   * auto_ptr lanes, and updates the global active-session pointer.
   */
  CWldSession* WLD_CreateSession(
    msvc8::auto_ptr<LuaPlus::LuaState>& state,
    msvc8::auto_ptr<RRuleGameRules>& gameRules,
    msvc8::auto_ptr<CWldMap>& wldMap,
    SWldSessionInfo& sessionInfo
  )
  {
    void* const sessionStorage = ::operator new(sizeof(CWldSession), std::nothrow);
    if (sessionStorage == nullptr) {
      gActiveWldSession = nullptr;
      return nullptr;
    }

    CWldSession* session = nullptr;
    try {
      session = new (sessionStorage) CWldSession(state, gameRules, wldMap, sessionInfo);
    } catch (...) {
      ::operator delete(sessionStorage);
      throw;
    }

    gActiveWldSession = session;
    return session;
  }

  /**
   * Address: 0x008972D0 (FUN_008972D0)
   *
   * What it does:
   * Runs one deleting teardown path for `CWldSession` and returns the original
   * pointer lane.
   */
  CWldSession* DeleteWldSessionAndReturn(CWldSession* const session) noexcept
  {
    session->~CWldSession();
    ::operator delete(session);
    return session;
  }

  /**
   * Address: 0x008972A0 (FUN_008972A0, ?WLD_DestroySession@Moho@@YAXXZ)
   *
   * What it does:
   * Destroys the active world-session object when present and clears the
   * process-global active-session pointer.
   */
  void WLD_DestroySession()
  {
    CWldSession* const activeSession = gActiveWldSession;
    if (activeSession != nullptr) {
      (void)DeleteWldSessionAndReturn(activeSession);
    }

    gActiveWldSession = nullptr;
  }

  /**
   * Address: 0x008972F0 (FUN_008972F0, ?WLD_GetSession@Moho@@YAPAVCWldSession@1@XZ)
   *
   * What it does:
   * Returns the process-global active world-session pointer.
   */
  CWldSession* WLD_GetSession()
  {
    return gActiveWldSession;
  }

  /**
   * Address: 0x0088D060 (FUN_0088D060, ?WLD_BeginSession@Moho@@YAXV?$auto_ptr@USWldSessionInfo@Moho@@@std@@@Z)
   *
   * What it does:
   * Replaces pending world-session bootstrap info and schedules preload.
   */
  void WLD_BeginSession(msvc8::auto_ptr<SWldSessionInfo> sessionInfo)
  {
    gPendingWldSessionInfo = sessionInfo;
    gWldFrameAction = EWldFrameAction::Preload;
  }

  /**
   * Address: 0x0088D0B0 (FUN_0088D0B0, ?WLD_GetSimRate@Moho@@YAMXZ)
   */
  float WLD_GetSimRate()
  {
    extern float wld_SkewRateAdjustBase;
    extern float wld_SkewRateAdjustMax;

    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return 1.0f;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager == nullptr) {
      return 1.0f;
    }

    const float requestedSimScale =
      static_cast<float>(std::pow(10.0, static_cast<double>(clientManager->GetSimRate()) * 0.1));

    const float skewRateMin = 1.0f / wld_SkewRateAdjustMax;
    const float skewRateSample =
      static_cast<float>(std::pow(static_cast<double>(wld_SkewRateAdjustBase), -simDriver->GetSimSpeed()));
    const float clampedSkewRate = std::max(skewRateMin, std::min(wld_SkewRateAdjustMax, skewRateSample));
    return clampedSkewRate * requestedSimScale;
  }

  /**
   * Address: 0x0088D170 (FUN_0088D170, session sim-rate permission probe)
   *
   * What it does:
   * Returns whether the active session context may issue local sim-rate
   * changes (`replay`, focused local army, or non-multiplayer).
   */
  bool WLD_CanAdjustSimRate()
  {
    CWldSession* const activeSession = WLD_GetActiveSession();
    if (activeSession == nullptr) {
      return false;
    }

    if (activeSession->IsReplay) {
      return true;
    }

    const int focusArmy = activeSession->FocusArmy;
    if (focusArmy >= 0 && activeSession->userArmies[static_cast<std::size_t>(focusArmy)] != nullptr) {
      return true;
    }

    return !activeSession->IsMultiplayer;
  }

  /**
   * Address: 0x0088D1B0 (FUN_0088D1B0, ?WLD_IncreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Raises requested sim rate by one step (up to +50) for authorized local
   * session contexts.
   */
  void WLD_IncreaseSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate < 50) {
      clientManager->SetSimRate(requestedSimRate + 1);
    }
  }

  /**
   * Address: 0x0088D220 (FUN_0088D220, ?WLD_ResetSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Resets requested sim rate back to neutral (`0`) for authorized local
   * session contexts.
   */
  void WLD_ResetSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    if (clientManager->GetSimRateRequested() != 0) {
      clientManager->SetSimRate(0);
    }
  }

  /**
   * Address: 0x0088D280 (FUN_0088D280, ?WLD_DecreaseSimRate@Moho@@YAXXZ)
   *
   * What it does:
   * Lowers requested sim rate by one step (down to `-10`) for authorized
   * local session contexts.
   */
  void WLD_DecreaseSimRate()
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr || !WLD_CanAdjustSimRate()) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    const int requestedSimRate = clientManager->GetSimRateRequested();
    if (requestedSimRate > -10) {
      clientManager->SetSimRate(requestedSimRate - 1);
    }
  }

  /**
   * Address: 0x0088D2F0 (FUN_0088D2F0, ?WLD_SetGameSpeed@Moho@@YAXH@Z)
   *
   * What it does:
   * Sets one requested sim-rate lane after clamping the provided game-speed
   * value to the legacy `[-10, 10]` bounds.
   */
  void WLD_SetGameSpeed(int gameSpeed)
  {
    ISTIDriver* const simDriver = sSimDriver.get();
    if (simDriver == nullptr) {
      return;
    }

    CClientManagerImpl* const clientManager = simDriver->GetClientManager();
    int clampedGameSpeed = gameSpeed;
    if (gameSpeed >= 10) {
      clampedGameSpeed = 10;
    }

    if (clampedGameSpeed < -10) {
      clampedGameSpeed = -10;
    }

    clientManager->SetSimRate(clampedGameSpeed);
  }

  /**
   * Address: 0x0088D330 (FUN_0088D330, ?WLD_GetDriver@Moho@@YAPAVISTIDriver@1@XZ)
   *
   * What it does:
   * Returns the world session's simulation driver (`sSimDriver.get()`).
   */
  ISTIDriver* WLD_GetDriver()
  {
    return sSimDriver.get();
  }

  /**
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   */
  CWldSession* WLD_GetActiveSession()
  {
    return gActiveWldSession;
  }
} // namespace moho


/**
 * Address: 0x0081EC00 (FUN_0081EC00, func_GetRightMouseButtonAction)
 * Mangled: ?func_GetRightMouseButtonAction@@... (referenced at global scope)
 *
 * IDA signature:
 * Moho::SCommandModeData *__cdecl func_GetRightMouseButtonAction(
 *     Moho::SCommandModeData *commandData, Moho::UICursorInfo *mouseInfo,
 *     int modifiers, Moho::CWldSession *wldSession);
 *
 * What it does:
 * Resolves the command a right-mouse click issues for the current selection
 * given the cursor state (hover target, drag id, modifiers). Walks the selected
 * set to accumulate the union of command-caps, then applies the attack /
 * capture / reclaim / transport / repair / guard / move precedence against the
 * hovered entity (or the pending command-manager helper when there is no hover)
 * and writes the resolved SCommandModeData into `out`. This symbol is
 * referenced by the linker at global scope (not inside namespace moho), so the
 * definition stays at global scope.
 */
moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* out, moho::MouseInfo* mouseInfo, int modifiers, moho::CWldSession* wldSession)
{
  using namespace moho;

  // Seed defaults from the cursor snapshot + modifiers (FUN_0081CEA0).
  CommandModeData commandModeData(*mouseInfo, modifiers);

  // No valid focus army (observer) -> return the default (empty) command mode.
  if (wldSession->FocusArmy < 0 || wldSession->userArmies[wldSession->FocusArmy] == nullptr) {
    *out = commandModeData;
    return out;
  }

  // An active UI command mode (a build placement, a ping, a targeting order the
  // UI started) does not resolve a right-click into an order - it resolves it
  // into "cancel the mode you are in".
  //
  //     0x0081ED4E  mov [esp+commandModeData.mMode], 7
  //     0x0081ED56  call SCommandModeData::SCommandModeData(out, &commandModeData)
  //
  // `CommandModeData::HandleEvent` routes mode 7 to `UI_EndCommandMode`, so the
  // matching right-button release tears the placement down. Returning `out`
  // untouched left it `COMMOD_None`, and the release arm skips `COMMOD_None`
  // entirely - which is why right-clicking never discarded a building you were
  // about to place.
  UICommandModeData commandMode{};
  UI_GetCommandMode(commandMode);
  if (!commandMode.mMode.empty()) {
    commandModeData.mMode = COMMOD_CancelCommandMode;
    *out = commandModeData;
    return out;
  }

  // Accumulate the union of command caps over every live selected user-unit.
  // `categoryOrdinals` collects each selected blueprint's category-bit index;
  // the binary keeps this side effect but never reads the set for a decision
  // (dead accumulation), so it is built and then destructed at scope end.
  BVIntSet categoryOrdinals;
  ERuleBPUnitCommandCaps selectionCommandCaps = RULEUCC_None;
  {
    for (UserEntity* const selectedEntity : wldSession->mSelection) {
      (void)categoryOrdinals.Add(static_cast<unsigned int>(selectedEntity->mParams.mBlueprint->mCategoryBitIndex));
      if (UserUnit* const selectedUnit = selectedEntity->IsUserUnit()) {
        selectionCommandCaps = static_cast<ERuleBPUnitCommandCaps>(
          selectionCommandCaps | GetIUnitBridge(selectedUnit)->GetAttributes().commandCapsMask
        );
      }
    }
  }

  UserEntity* const hoverEntity = mouseInfo->HoveredEntity();

  if (hoverEntity == nullptr) {
    // No hover: consult the command the cursor is dragging. An attack/form-
    // attack command with an attack-capable selection resolves to an
    // Order+Attack; otherwise fall through to the move tail.
    //
    // 0x0081F513..0x0081F565: `mCommandManager->mCommands.find(mIsDragger)`
    // (0x008B6160), then the command type through `sub_8B4140` -- called
    // twice, once per comparison -- so a pending local SetCommandType edit
    // counts, not just the replicated `mVariableData.mCmdType`.
    CommandManager* const commandManager = wldSession->mCommandManager;
    UserCommandIssueHelper* const helper =
      commandManager != nullptr ? FindCommandIssueHelper(*commandManager, mouseInfo->mIsDragger) : nullptr;
    if (helper != nullptr
        && (ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_Attack
            || ResolveCommandIssueHelperCommandType(*helper) == EUnitCommandType::UNITCOMMAND_FormAttack)
        && (selectionCommandCaps & RULEUCC_Attack) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Attack;
    } else if ((selectionCommandCaps & RULEUCC_Move) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Move;
    }
    commandModeData.mIsDragged = mouseInfo->mIsDragger;
    *out = commandModeData;
    return out;
  }

  // --- Hover branch --------------------------------------------------------
  const bool isBeingBuilt = hoverEntity->IsBeingBuilt();
  const bool isFerryBeacon = hoverEntity->IsInCategory(msvc8::string("FERRYBEACON"));
  const bool isCampaignGate = hoverEntity->IsInCategory(msvc8::string("CAMPAIGNGATE"));

  // Reclaim eligibility: RECLAIMABLE (or under-construction) targets are
  // reclaim-valid; everything else is not.
  bool reclaimTargetValid = true;
  if (hoverEntity->mParams.mBlueprint != nullptr) {
    const bool reclaimable =
      hoverEntity->IsInCategory(msvc8::string("RECLAIMABLE")) || hoverEntity->IsBeingBuilt();
    if (!reclaimable) {
      reclaimTargetValid = false;
    }
  } else {
    reclaimTargetValid = false;
  }

  bool mCapturable = false;
  if (UserUnit* const hoverUnitForCaps = hoverEntity->IsUserUnit()) {
    mCapturable = GetIUnitBridge(hoverUnitForCaps)->GetAttributes().mCapturable;
    // When the unit is busy it is neither reclaimable nor capturable via
    // right-click.
    if (hoverEntity->IsUserUnit()->mUnitVarDat.mIsBusy) {
      reclaimTargetValid = false;
      mCapturable = false;
    }
  }

  bool isEnemy = false;
  bool isAlly = false;
  UserArmy* const focusArmy =
    (wldSession->FocusArmy < 0) ? nullptr : wldSession->userArmies[wldSession->FocusArmy];
  UserArmy* const hoverArmy = hoverEntity->mArmy;
  if (hoverArmy != nullptr && focusArmy != nullptr) {
    isEnemy = focusArmy->IsEnemy(hoverArmy->mArmyIndex);
    isAlly = focusArmy->IsAlly(hoverArmy->mArmyIndex);
  }

  UserUnit* const hoverUnit = hoverEntity->IsUserUnit();

  bool resolved = false;

  if (!(isEnemy && (selectionCommandCaps & RULEUCC_Attack) != 0
        && AnySelectedUnitCanAttackHover(hoverEntity, wldSession))) {
    // Capture: a non-allied, finished, capturable target with capture-capable
    // selection resolves to Order+Capture.
    if (!isAlly && !isBeingBuilt && mCapturable && (selectionCommandCaps & RULEUCC_Capture) != 0) {
      commandModeData.mMode = COMMOD_Order;
      commandModeData.mCommandCaps = RULEUCC_Capture;
      resolved = true;
    }

    // Reclaim: enemy / ownerless / reclaim-friendly targets that are reclaim
    // valid with reclaim-capable selection resolve to Order+Reclaim.
    if (!resolved) {
      const bool reclaimEligible =
        (isEnemy || hoverArmy == nullptr || hoverEntity->IsInCategory(msvc8::string("RECLAIMFRIENDLY")))
        && reclaimTargetValid && (selectionCommandCaps & RULEUCC_Reclaim) != 0;
      if (reclaimEligible) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Reclaim;
        resolved = true;
      }
    }

    // Transport chains only apply when the hover target belongs to the focus army.
    if (!resolved && hoverArmy == focusArmy) {
      if ((selectionCommandCaps & RULEUCC_CallTransport) != 0
          && SelectionHasTransportForTarget(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      } else if (hoverUnit != nullptr
                 && (GetIUnitBridge(hoverUnit)->GetAttributes().commandCapsMask & RULEUCC_CallTransport) != 0
                 && HoverTransportAcceptsSelection(&wldSession->mSelection, hoverEntity)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Transport;
        resolved = true;
      } else if (isFerryBeacon && AllSelectedAreFactories(&wldSession->mSelection, wldSession)) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_CallTransport;
        resolved = true;
      }
    }

    const ERuleBPUnitCommandCaps selectionCommandCapsTail = selectionCommandCaps;

    if (!resolved) {
      if (isEnemy) {
        // Attack-capable but nothing in the selection can actually attack the
        // hover -> mark the order invalid (immediate 0x01000000 = RULEUCC_Invalid).
        if ((selectionCommandCaps & RULEUCC_Attack) != 0
            && !AnySelectedUnitCanAttackHover(hoverEntity, wldSession)) {
          commandModeData.mMode = COMMOD_Order;
          commandModeData.mCommandCaps = RULEUCC_Invalid;
          resolved = true;
        }
        // else: fall through to the move tail.
      } else {
        const std::int32_t guardCap = selectionCommandCaps & RULEUCC_Guard;

        if (!OPTIONS_GetBool("switch_right_click_behavior")) {
          // Normal right-click behavior.
          const std::int32_t repairCap = selectionCommandCapsTail & RULEUCC_Repair;

          // Repair-if-under-construction: repair-capable selection over an
          // under-construction target that is mobile, or neither factory nor silo.
          bool repairUnderConstruction = false;
          if (repairCap != 0 && hoverEntity->IsBeingBuilt()) {
            if (UserUnit* const builtUnit = hoverEntity->IsUserUnit()) {
              if (GetIUnitBridge(builtUnit)->IsMobile()
                  || (!hoverEntity->IsInCategory(msvc8::string("FACTORY"))
                      && !hoverEntity->IsInCategory(msvc8::string("SILO")))) {
                repairUnderConstruction = true;
              }
            }
          }
          if (repairUnderConstruction) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }

          // Guard: guard-capable selection over a non-campaign-gate hovered unit
          // that is not the first selection member, while a formation is active.
          if (!resolved && guardCap != 0 && !isCampaignGate && hoverUnit != nullptr
              && !wldSession->UnitFirstInSelection(hoverUnit)
              && wldSession->mCurFormation->mTimeLeft > 0.0f) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }

          // Repair (finished target): allied damaged target, or a hovered unit
          // that reports the upgrading unit-state.
          if (!resolved && repairCap != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          }
          // else: fall through to the move tail.
        } else {
          // Switched right-click behavior: repair is prioritised over guard.
          if ((selectionCommandCapsTail & RULEUCC_Repair) != 0
              && ((isAlly && hoverEntity->mVariableData.mMaxHealth > hoverEntity->mVariableData.mHealth)
                  || (hoverUnit != nullptr
                      && GetIUnitBridge(hoverUnit)->IsUnitState(UNITSTATE_Upgrading)))) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Repair;
            resolved = true;
          } else if (guardCap != 0) {
            commandModeData.mMode = COMMOD_Order;
            commandModeData.mCommandCaps = RULEUCC_Guard;
            resolved = true;
          }
          // else: fall through to the move tail.
        }
      }
    }

    // Move tail: a move-capable selection defaults to Order+Move.
    if (!resolved) {
      if ((selectionCommandCapsTail & RULEUCC_Move) != 0) {
        commandModeData.mMode = COMMOD_Order;
        commandModeData.mCommandCaps = RULEUCC_Move;
      }
      resolved = true;
    }
  } else {
    // Enemy target, attack-capable selection that can attack it -> Order+Attack.
    commandModeData.mMode = COMMOD_Order;
    commandModeData.mCommandCaps = RULEUCC_Attack;
    resolved = true;
  }

  // Finalize: stamp the drag id and copy the resolved state out.
  commandModeData.mIsDragged = mouseInfo->mIsDragger;
  *out = commandModeData;
  return out;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RMultiMapType_EntId_string_933d97, preregister_RMultiMapType_EntId_string)

namespace moho
{
  /**
   * What it does:
   * Loads the save-node map. Inlined into
   * `gpg::SerSaveLoadHelper<SSessionSaveData>::Deserialize` 0x00897470.
   */
  void SSessionSaveData::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    archive->Read(ResolveSessionSaveNodeMapArchiveType(), &mNodeMap, ownerRef);
  }

  /**
   * What it does:
   * Saves the save-node map. Inlined into
   * `gpg::SerSaveLoadHelper<SSessionSaveData>::Serialize` 0x008974B0.
   */
  void SSessionSaveData::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef) const
  {
    archive->Write(ResolveSessionSaveNodeMapArchiveType(), &mNodeMap, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSessionSaveData>`, vtable 0x00E4B2DC.
   *
   * Address: 0x00BE7790 (FUN_00BE7790 -- constructs the global and registers its destructor.)
   * Address: 0x00C08220 (FUN_00C08220 -- the global's destructor.)
   * Address: 0x008974F0 (FUN_008974F0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00899220 (FUN_00899220 -- `Init`.)
   * Address: 0x00897470 (FUN_00897470 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x008974B0 (FUN_008974B0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SSessionSaveDataSerializer : gpg::SerSaveLoadHelper<SSessionSaveData>
  {};
} // namespace moho

namespace
{
  // Address: 0x010C51C8 -- process-global `SSessionSaveDataSerializer` singleton.
  moho::SSessionSaveDataSerializer gSSessionSaveDataSerializer;
} // namespace
