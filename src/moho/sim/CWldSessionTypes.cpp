#include "moho/sim/CWldSessionPrivate.h"

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
   * `fa::detail::allocate_checked`), zeroes the first three dwords and marks
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
    void* const buffer = fa::detail::allocate_checked<std::uint8_t>(0xC50u);
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
}

namespace moho
{
  gpg::RType* SSessionSaveData::sType = nullptr;

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
}

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
    [[nodiscard]] fa::string GetLexical(const gpg::RRef& ref) const override;
  };
}

namespace
{
  gpg::RType* gEntIdStringMultiMapKeyType = nullptr;
  gpg::RType* gEntIdStringMultiMapValueType = nullptr;
  using EntIdStringMultiMap = moho::SSessionSaveNodeMap;

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
        "fa::string",
        "string",
      };

      for (const char* const typeName : kTypeNames) {
        if (gpg::RType* const resolved = gpg::REF_FindTypeNamed(typeName); resolved != nullptr) {
          gEntIdStringMultiMapValueType = resolved;
          break;
        }
      }

      if (gEntIdStringMultiMapValueType == nullptr) {
        gEntIdStringMultiMapValueType = gpg::LookupRType(typeid(fa::string));
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
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<EntIdStringMultiMap*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    destination->clear();
    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (unsigned int index = 0u; index < count; ++index) {
      moho::EntId key = 0;
      archive->Read(entIdType, &key, *ownerRef);

      fa::string value{};
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
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const EntIdStringMultiMap*>(objectPtr);
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);
    if (source == nullptr) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdArchiveType();

    for (const auto& entry : *source) {
      archive->Write(entIdType, &entry.first, *ownerRef);
      fa::string value = entry.second;
      archive->WriteString(&value);
    }
  }
}


/**
 * Address: 0x00899120 (FUN_00899120, gpg::RMultiMapType_EntId_string::Init)
 *
 * What it does:
 * Sets multimap size/version metadata and binds load/save serializers for
 * `multimap<EntId,std::string>`.
 */
void gpg::RMultiMapType_EntId_string::Init()
{
  static_assert(sizeof(EntIdStringMultiMap) == 0x0C, "EntIdStringMultiMap size must be 0x0C");
  size_ = sizeof(EntIdStringMultiMap);
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
  static const fa::string sName = gpg::STR_Printf(
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
fa::string gpg::RMultiMapType_EntId_string::GetLexical(const gpg::RRef& ref) const
{
  const fa::string base = gpg::RType::GetLexical(ref);
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
 * `std::multimap<moho::EntId,fa::string>`.
 */
[[nodiscard]] gpg::RType* preregister_RMultiMapType_EntId_string()
{
  static gpg::RMultiMapType_EntId_string typeInfo;
  gpg::PreRegisterRType(typeid(EntIdStringMultiMap), &typeInfo);
  return &typeInfo;
}
namespace moho
{
  // 0x00F57A8E holds 0x01 in bin/2025.7.1/ForgedAlliance.exe's .data, so the
  // resource splats are on unless a console command turns them off.
  bool UI_RenResources = true;              // 0x00F57A8E

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
    // gWldFrameAction: moho/sim/WldSessionState.cpp (WldSessionState.h).

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
    [[maybe_unused]] void DispatchSessionListenerAttach(WldTeardownCallbackVector* const callbacks)
    {
      const std::size_t callbackCount = callbacks->size();
      for (std::size_t i = 0; i < callbackCount; ++i) {
        ISessionListener* const listener = (*callbacks)[i];
        listener->AttachToSessionListenerLane(gActiveWldSession);
      }
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane0(const void* const value) noexcept
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
    [[maybe_unused]] [[nodiscard]] std::uint32_t ReadBuildTemplateHelperLane4(const void* const value) noexcept
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
  void GetSessionUserUnits(CWldSession* const session, fa::vector<UserUnit*>& outUnits)
  {
    CollectSessionUserUnits(session, outUnits);
  }

  /**
   * Address: 0x00896F00 (FUN_00896F00) init path (FUN_00896F00 -> sub_89A930).
   */
  SSessionSaveData::SSessionSaveData() = default;

  /**
   * Address: 0x008971A0 cleanup path (FUN_008971A0 + sub_89AC40).
   */
  SSessionSaveData::~SSessionSaveData() = default;

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
    archive->Read(gpg::RTypeOf<moho::SSessionSaveNodeMap>(), &mNodeMap, ownerRef);
  }

  /**
   * What it does:
   * Saves the save-node map. Inlined into
   * `gpg::SerSaveLoadHelper<SSessionSaveData>::Serialize` 0x008974B0.
   */
  void SSessionSaveData::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef) const
  {
    archive->Write(gpg::RTypeOf<moho::SSessionSaveNodeMap>(), &mNodeMap, ownerRef);
  }
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
}

namespace
{
  // Address: 0x010C51C8 -- process-global `SSessionSaveDataSerializer` singleton.
  moho::SSessionSaveDataSerializer gSSessionSaveDataSerializer;
}

