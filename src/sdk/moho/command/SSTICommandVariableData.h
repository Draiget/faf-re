#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/command/SSTITarget.h"
#include "moho/sim/SOCellPos.h"

#ifndef FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_ENFORCE_STRICT_LAYOUT_ASSERTS 0
#endif

#ifndef FAF_RUNTIME_LAYOUT_ASSERT
#if FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_RUNTIME_LAYOUT_ASSERT(...) static_assert(__VA_ARGS__)
#else
#define FAF_RUNTIME_LAYOUT_ASSERT(...)
#endif
#endif
namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  struct SSTICommandIssueData;
  using EntId = std::int32_t;

  /**
   * Both element lists are `gpg::fastvector_n`, not `msvc8::vector`. The
   * constructor at 0x00552A00 binds four pointer lanes per list to an inline
   * window that sits inside the payload:
   *
   *   lea ecx,[eax+10h]  mov [eax],ecx  mov [eax+4],ecx  mov [eax+0Ch],ecx
   *   lea edx,[ecx+8]    mov [eax+8],edx
   *
   * i.e. `start_ +0x00`, `end_ +0x04`, `capacity_ +0x08`, `originalVec_ +0x0C`
   * and two inline elements at +0x10, with the same shape repeated at +0x48 for
   * the cell list (inline window at +0x58). `MemberDeserialize` (0x00554760)
   * confirms the element type from the other side: it looks up
   * `gpg::fastvector<Moho::EntId>` and `gpg::fastvector<Moho::SOCellPos>`.
   *
   * Modelling these as `msvc8::vector` kept the struct the right SIZE while
   * shifting every lane one word: the debug-proxy word landed on `start_`, so
   * anything reading the list through the binary's own offsets -- e.g.
   * `func_GetEntitiesUnderCursor` (0x008B43F0), which iterates
   * `[helper+0x40, helper+0x44)` -- read a null begin against a live end and
   * walked from address zero.
   */
  struct SSTICommandVariableData
  {
    static gpg::RType* sType;

    gpg::fastvector_n<EntId, 2> mEntIds;    // +0x00
    EUnitCommandType mCmdType;              // +0x18
    SSTITarget mTarget1;                    // +0x1C
    SSTITarget mTarget2;                    // +0x30
    std::int32_t v14;                       // +0x44 (ctor leaves this lane unwritten)
    gpg::fastvector_n<SOCellPos, 2> mCells; // +0x48
    std::int32_t mMaxCount;                 // +0x60
    std::int32_t mCount;                    // +0x64
    std::uint32_t v23;                      // +0x68

    /**
     * Address: 0x00552A00 (FUN_00552A00, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Initializes command-variable payload lanes to default/empty command state
     * (`None` targets, empty vectors, and unset count limits).
     */
    SSTICommandVariableData();

    /**
     * Address: 0x006ECAD0 (FUN_006ECAD0, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Copy-constructs the full command-variable payload including target lanes
     * and variable cell vector storage.
     */
    SSTICommandVariableData(const SSTICommandVariableData& other);

    /**
     * Address: 0x00552A70 (FUN_00552A70, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Initializes variable-payload lanes from one command-issue payload
     * (`mCmdType`, both targets, cell list, and count limits).
     */
    explicit SSTICommandVariableData(const SSTICommandIssueData& issueData);

    /**
     * Address: 0x005603E0 (FUN_005603E0, Moho::SSTICommandVariableData::~SSTICommandVariableData)
     *
     * What it does:
     * Releases command payload vectors (`mCells`, `mEntIds`) and restores their
     * inline-storage lanes.
     */
    ~SSTICommandVariableData();

    /**
     * Address: 0x00554760 (FUN_00554760, Moho::SSTICommandVariableData::MemberDeserialize)
     *
     * What it does:
     * Loads one command-variable payload lane from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005548A0 (FUN_005548A0, Moho::SSTICommandVariableData::MemberSerialize)
     *
     * What it does:
     * Stores one command-variable payload lane to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  /**
   * Address: 0x00552C10 (FUN_00552C10, func_UnitStateIsBusy)
   *
   * What it does:
   * True for the movement/engagement command families -- `Move`, `Attack`,
   * `Patrol`, their `Form*` variants and `Guard` -- the commands that keep a
   * unit's navigation busy. `Unit::MotionTick` treats two queued busy
   * commands as a speed-through, and `CAiFormationInstance` (`FindSlotFor`,
   * `Update`) treats a busy follow-up command as a reason to keep a unit's
   * formation slot rather than snap it back to the unit's own position.
   */
  [[nodiscard]] bool IsSpeedThroughBusyCommandType(EUnitCommandType commandType) noexcept;

  class SSTICommandVariableDataSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9D00 (FUN_00BC9D00, dynamic initializer for the global
     * `SSTICommandVariableDataSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed real (RTTI class name
     * `SSTICommandVariableDataSerializer@Moho` via `vtable_writers`,
     * standalone class, not a template instantiation).
     */
    SSTICommandVariableDataSerializer();

    /**
     * Address: 0x00BF4A80 (FUN_00BF4A80) -- IDA's own demangler resolves
     * this destructor's mangled symbol to
     * `Moho::SSTICommandVariableDataSerialize::~SSTICommandVariableDataSerialize`
     * (missing the trailing "r"), while the vtable symbol
     * (`??_7SSTICommandVariableDataSerializer@Moho@@6B@`) and both member
     * functions (`Serialize`/`Deserialize`) consistently spell the class
     * name with the "r". Treated as the same class's destructor -- the
     * vtable + two independent member-function symbols outweigh the one
     * discrepant destructor symbol.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SSTICommandVariableDataSerializer();

    /**
     * Address: 0x00552B20 (FUN_00552B20, Moho::SSTICommandVariableDataSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-load callback flow into `SSTICommandVariableData::MemberDeserialize`.
     * Named `Serialize` despite taking a `ReadArchive*` and performing a
     * load -- confirmed to match the real binary's own mangled symbol
     * (`Moho::SSTICommandVariableDataSerializer::Serialize`), so this is
     * the original 2007 source's own naming, not a recovery artifact; kept
     * as-is rather than "corrected" to match its behavior.
     */
    static void Serialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00552B30 (FUN_00552B30, Moho::SSTICommandVariableDataSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-save callback flow into `SSTICommandVariableData::MemberSerialize`.
     * Named `Deserialize` despite taking a `WriteArchive*` and performing a
     * save -- see `Serialize` above; same real-binary-confirmed naming
     * inversion, preserved faithfully.
     */
    static void Deserialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00553260 (FUN_00553260, Moho::SSTICommandVariableDataSerializer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSTICommandVariableData` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  // Offsets below are read straight out of FUN_00552A00 (the ctor asm quoted
  // above); every one of them is a literal displacement in that body.
  static_assert(offsetof(SSTICommandVariableData, mEntIds) == 0x00, "SSTICommandVariableData::mEntIds offset must be 0x00");
  static_assert(sizeof(gpg::fastvector_n<EntId, 2>) == 0x18, "SSTICommandVariableData::mEntIds size must be 0x18");
  static_assert(
    offsetof(SSTICommandVariableData, mCmdType) == 0x18, "SSTICommandVariableData::mCmdType offset must be 0x18"
  );
  static_assert(
    offsetof(SSTICommandVariableData, mTarget1) == 0x1C, "SSTICommandVariableData::mTarget1 offset must be 0x1C"
  );
  static_assert(
    offsetof(SSTICommandVariableData, mTarget2) == 0x30, "SSTICommandVariableData::mTarget2 offset must be 0x30"
  );
  static_assert(offsetof(SSTICommandVariableData, v14) == 0x44, "SSTICommandVariableData::v14 offset must be 0x44");
  static_assert(
    offsetof(SSTICommandVariableData, mCells) == 0x48, "SSTICommandVariableData::mCells offset must be 0x48"
  );
  static_assert(sizeof(gpg::fastvector_n<SOCellPos, 2>) == 0x18, "SSTICommandVariableData::mCells size must be 0x18");
  static_assert(
    offsetof(SSTICommandVariableData, mMaxCount) == 0x60, "SSTICommandVariableData::mMaxCount offset must be 0x60"
  );
  static_assert(
    offsetof(SSTICommandVariableData, mCount) == 0x64, "SSTICommandVariableData::mCount offset must be 0x64"
  );
  static_assert(offsetof(SSTICommandVariableData, v23) == 0x68, "SSTICommandVariableData::v23 offset must be 0x68");
  static_assert(sizeof(SSTICommandVariableData) == 0x6C, "SSTICommandVariableData size must be 0x6C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mSerLoadFunc) == 0x0C,
    "SSTICommandVariableDataSerializer::mSerLoadFunc offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mSerSaveFunc) == 0x10,
    "SSTICommandVariableDataSerializer::mSerSaveFunc offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(SSTICommandVariableDataSerializer) == 0x14, "SSTICommandVariableDataSerializer size must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SSTICommandVariableData) == 0x70, "SSTICommandVariableData size must be 0x70");

  /**
   * Address: 0x005528C0 (FUN_005528C0, preregister_SSTICommandVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandVariableData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTICommandVariableDataTypeInfo();
} // namespace moho
