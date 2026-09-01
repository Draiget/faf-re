#include "moho/sim/ManipulatorStartupRegistrations.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAimManipulator.h"
#include "moho/ai/CAimManipulatorSerializer.h"
#include "moho/ai/CAimManipulatorTypeInfo.h"
#include "moho/animation/CSlideManipulator.h"
#include "moho/console/CConCommand.h"
#include "moho/containers/BitStorage32.h"
#include "legacy/containers/Vector.h"
#include "moho/lua/CScrLuaBaseClassSpec.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CUnitScriptTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

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

  // F59B34 (moho.manipulator_methods) is republished at a second list
  // position by register_sim_SimInits_mForms_off_F59B34_mFactory. The
  // CScrLuaClassBinder that owns that slot is already constructed (and
  // self-linked via its own ctor) by register_sim_SimInits_mForms_offVariant9
  // below, so this lane only needs to record/restore the prior list head -
  // relinking the anchor itself is deliberately suppressed, see
  // RegisterRecoveredSimInitLinkerLane.
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59B34_mFactory = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59B34_mFactory = nullptr;

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
    moho::CScrLuaInitFormSet* const simSet = FindLuaInitFormSetByName("Sim");
    if (simSet == nullptr) {
      *PrevLane = nullptr;
      return nullptr;
    }

    moho::CScrLuaInitForm* const result = simSet->mForms;
    *PrevLane = result;
    // Prepend suppressed: the binary's anchor is a statically initialised
    // form object in .data with no constructor, so it patches the list by
    // hand. Our equivalent is a real C++ object whose constructor already
    // calls AddInit, and re-doing it here published the address of a
    // CScrLuaInitForm* variable as the list head - a null vtable pointer
    // that crashed RunLuaInitFormSetIfPresent. See CPrefetchSet.cpp.
    // simSet->mForms = reinterpret_cast<moho::CScrLuaInitForm*>(AnchorLane);
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
    /**
     * Address: 0x006425F0 (FUN_006425F0, gpg::RVectorType_bool::dtr)
     */
    ~RVectorTypeBool() override;

    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00641DB0 (FUN_00641DB0, gpg::RVectorType_bool::SubscriptIndex)
     *
     * What it does:
     * Builds one reflected proxy reference to the indexed legacy
     * `vector<bool>::reference` bit lane.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  using VectorBoolStorage = moho::SBitStorage32;

  template <class TObject>
  [[nodiscard]] TObject* PointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  template <class TObject>
  [[nodiscard]] const TObject* ConstPointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<const TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  alignas(RVectorTypeBool) unsigned char gRecoveredRVectorTypeBoolStorage[sizeof(RVectorTypeBool)] = {};
  bool gRecoveredRVectorTypeBoolConstructed = false;
  thread_local msvc8::detail::vector_bool_word_cursor gRecoveredRVectorTypeBoolSubscriptCursorScratch{};
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

  /**
   * Orphan: no caller anywhere in src/sdk and no `Address:` citation of its
   * own. `CachedVectorBoolElementType()` right below does the same
   * `LookupRType(typeid(bool))` lookup (minus the `REF_FindTypeNamed`
   * fallback) and is the one with real, evidenced usage: it is called from
   * `RVectorTypeBool::GetName()` (FUN_00641C20, address-cited below). No
   * evidence ties this function's extra fallback branch to any call site, so
   * it is left undisturbed rather than merged into the evidenced one on a
   * guess.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveBoolType()
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

  RVectorTypeBool::~RVectorTypeBool() = default;

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

  /**
   * Address: 0x00641CE0 (FUN_00641CE0, gpg::RVectorType_bool::GetLexical)
   *
   * What it does:
   * Formats inherited lexical text and appends current vector<bool> size.
   */
  msvc8::string RVectorTypeBool::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* RVectorTypeBool::IsIndexed() const
  {
    return this;
  }

  void RVectorTypeBool::Init()
  {
    size_ = sizeof(VectorBoolStorage);
    version_ = 1;
    serLoadFunc_ = &RVectorTypeBool::SerLoad;
    serSaveFunc_ = &RVectorTypeBool::SerSave;
  }

  /**
   * Packed bit-iterator cursor shape matching the legacy
   * `std::vector<bool>::iterator` tuple `(word_ptr, bit_offset_within_word)`.
   * Callers compute the cursor from a bit index via
   * `base + 4*(bitIndex >> 5)` and `bitIndex & 31`; the cursor is stable
   * across payload resizes only when re-derived from the `(bitIndex, baseWord)`
   * pair after each storage growth.
   */
  struct VectorBoolBitCursor
  {
    std::uint32_t* wordPtr;   // +0x00
    std::uint32_t bitOffset;  // +0x04 (0..31)
  };

  /**
   * Address: 0x006421C0 (FUN_006421C0, gpg::RVectorType_bool::reserve_word_capacity)
   *
   * IDA signature:
   * unsigned int __thiscall sub_6421C0(int storage, unsigned int wordCount);
   *
   * What it does:
   * Ensures the packed-bit word array backing `VectorBoolStorage` has at least
   * `wordCount` words of capacity. If the requested capacity exceeds the
   * half-machine-word limit (`0x3FFFFFFF`), the legacy length-error throw
   * helper `sub_444270` is invoked. When the current word capacity already
   * satisfies the request, the call is a no-op and returns the current word
   * count. Otherwise a fresh word array is allocated via `sub_445B80`
   * (allocator stub), the current `[mWords, mWordsEnd)` run is move-copied via
   * the engine's per-word helper (`sub_642F30`), the old storage is released,
   * and the `mWords / mWordsEnd / mWordsCapacityEnd` triplet is re-seated.
   * Returns the new capacity word count on success, or the prior element
   * count if no reallocation was necessary.
   */
  std::uint32_t VectorBoolReserveWordCapacity(VectorBoolStorage& storage, const std::uint32_t wordCount)
  {
    // Length-check: matches the legacy `sub_444270` overflow throw at 0x6421EE.
    if (wordCount > 0x3FFFFFFFu) {
      // Legacy binary calls `std::_Xlen_string()` / length-error emitter here;
      // in recovered code the normal STL length_error path serves the same role.
      throw std::length_error("VectorBoolReserveWordCapacity: wordCount overflows word-span limit");
    }

    std::uint32_t* const oldWords = storage.mWords;
    std::uint32_t* const oldWordsEnd = storage.mWordsEnd;
    std::uint32_t* const oldCapacityEnd = storage.mWordsCapacityEnd;

    const std::uint32_t currentCapacity = (oldWords != nullptr && oldCapacityEnd != nullptr)
      ? static_cast<std::uint32_t>(oldCapacityEnd - oldWords)
      : 0u;
    if (currentCapacity >= wordCount) {
      return currentCapacity;
    }

    auto* const grown = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * wordCount));

    // Move current live words into the new backing (match `sub_642F30` shape):
    // zero-fill the new slab so tail words beyond the live run are predictable.
    std::uint32_t copyWords = 0u;
    if (oldWords != nullptr) {
      copyWords = static_cast<std::uint32_t>(oldWordsEnd - oldWords);
      for (std::uint32_t i = 0u; i < copyWords; ++i) {
        grown[i] = oldWords[i];
      }
    }
    for (std::uint32_t i = copyWords; i < wordCount; ++i) {
      grown[i] = 0u;
    }

    if (oldWords != nullptr) {
      ::operator delete(oldWords);
    }

    storage.mWords = grown;
    storage.mWordsEnd = grown + copyWords;
    storage.mWordsCapacityEnd = grown + wordCount;
    return wordCount;
  }

  /**
   * Address: 0x0057FB30 (FUN_0057FB30)
   *
   * IDA signature:
   * _DWORD *__userpurge sub_57FB30@<eax>(int a1@<edi>, _DWORD *a2@<esi>,
   *                                      char a3, int a4, int a5);
   *
   * What it does:
   * Inserts one boolean bit into the `vector<bool>`-style bit storage at the
   * iterator cursor `(baseWord, bitOffset)` and returns the post-insert cursor.
   * The original binary grows backing storage via the
   * `vector<bool>::_Insert_n(1, value, iter)` helper at `sub_443D90` and then
   * translates the stale iterator by advancing it by
   * `32 * ((newBase - oldBase) / 4)` bits so the returned cursor refers to the
   * same logical position in the grown storage.
   */
  VectorBoolBitCursor VectorBoolInsertOneBit(
    VectorBoolStorage& storage,
    const bool value,
    std::uint32_t* const iterBaseWord,
    const std::uint32_t iterBitOffset
  )
  {
    const std::uint32_t oldBitCount = storage.mBitCount;
    const std::uint32_t oldCapacity = (storage.mWords != nullptr && storage.mWordsCapacityEnd != nullptr)
      ? static_cast<std::uint32_t>(storage.mWordsCapacityEnd - storage.mWords)
      : 0u;
    const std::uint32_t requiredWords = ((oldBitCount + 1u) + 31u) >> 5u;

    std::uint32_t* const oldWordsBase = storage.mWords;

    // Grow capacity first if the current word window can't hold one more bit.
    if (requiredWords > oldCapacity) {
      const std::uint32_t newCapacity = std::max<std::uint32_t>(requiredWords, oldCapacity * 2u);
      auto* const grown = static_cast<std::uint32_t*>(::operator new(sizeof(std::uint32_t) * newCapacity));
      const std::uint32_t copyWords = (oldBitCount + 31u) >> 5u;
      for (std::uint32_t i = 0; i < copyWords; ++i) {
        grown[i] = oldWordsBase[i];
      }
      for (std::uint32_t i = copyWords; i < newCapacity; ++i) {
        grown[i] = 0u;
      }
      if (oldWordsBase != nullptr) {
        ::operator delete(oldWordsBase);
      }
      storage.mWords = grown;
      storage.mWordsCapacityEnd = grown + newCapacity;
    }

    storage.mBitCount = oldBitCount + 1u;
    storage.mWordsEnd = storage.mWords + requiredWords;

    // Translate the caller-supplied iterator cursor across the potential
    // reallocation using the same dword-stride math as the binary:
    //   new_word_ptr = iterBaseWord + (newBase - oldBase)
    //   new_bit = iterBitOffset
    const std::intptr_t wordDelta = (oldWordsBase != nullptr)
      ? (storage.mWords - oldWordsBase)
      : (storage.mWords - iterBaseWord);
    std::uint32_t* const translatedWord = iterBaseWord + wordDelta;

    VectorBoolBitCursor cursor{translatedWord, iterBitOffset};
    if (cursor.wordPtr != nullptr) {
      const std::uint32_t mask = 1u << cursor.bitOffset;
      if (value) {
        *cursor.wordPtr |= mask;
      } else {
        *cursor.wordPtr &= ~mask;
      }
    }

    return cursor;
  }

  /**
   * Address: 0x00641F70 (FUN_00641F70, gpg::RVectorType_bool::SerLoad)
   *
   * What it does:
   * Reads packed boolean bit-count/value lanes from archive payload and
   * replaces destination `SBitStorage32` storage in one transfer, driving the
   * insert via the canonical per-bit `VectorBoolInsertOneBit` lane to match
   * the original binary loop shape.
   */
  void RVectorTypeBool::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const storage = PointerFromArchiveInt<VectorBoolStorage>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    unsigned int bitCount = 0;
    archive->ReadUInt(&bitCount);

    VectorBoolStorage loaded{};
    // Reserve final word capacity up-front via the engine's canonical helper
    // at FUN_006421C0, matching the binary's `sub_6421C0((v8 + 31) >> 5)`
    // prologue in FUN_00641F70.
    if (bitCount != 0u) {
      const std::uint32_t requiredWordCount = (bitCount + 31u) >> 5u;
      (void)VectorBoolReserveWordCapacity(loaded, requiredWordCount);
    }

    for (unsigned int bitIndex = 0; bitIndex < bitCount; ++bitIndex) {
      bool value = false;
      archive->ReadBool(&value);

      // Compute per-iteration cursor from current (baseWord, bitCount) pair,
      // matching `v5 = v12 + 4*(v11>>5); v6 = v11 & 0x1F;` in FUN_00641F70.
      std::uint32_t* const baseWord = loaded.mWords;
      const std::uint32_t liveBitCount = loaded.mBitCount;
      std::uint32_t* const cursorWord = (baseWord != nullptr)
        ? (baseWord + (liveBitCount >> 5u))
        : nullptr;
      const std::uint32_t cursorBit = liveBitCount & 31u;

      (void)VectorBoolInsertOneBit(loaded, value, cursorWord, cursorBit);
    }

    std::uint32_t* const oldWords = storage->mWords;
    storage->mBitCount = loaded.mBitCount;
    storage->mWords = loaded.mWords;
    storage->mWordsEnd = loaded.mWordsEnd;
    storage->mWordsCapacityEnd = loaded.mWordsCapacityEnd;
    if (oldWords != nullptr) {
      ::operator delete(oldWords);
    }
  }

  /**
   * Address: 0x006420A0 (FUN_006420A0, gpg::RVectorType_bool::SerSave)
   *
   * What it does:
   * Writes packed boolean bit-count/value lanes to archive payload in index
   * order from one `SBitStorage32` source.
   */
  void RVectorTypeBool::SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    const auto* const storage = ConstPointerFromArchiveInt<VectorBoolStorage>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(storage != nullptr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int bitCount = storage->mBitCount;
    archive->WriteUInt(bitCount);
    for (unsigned int bitIndex = 0; bitIndex < bitCount; ++bitIndex) {
      archive->WriteBool(storage->TestBit(bitIndex));
    }
  }

  /**
   * Address: 0x00641DB0 (FUN_00641DB0, gpg::RVectorType_bool::SubscriptIndex)
   *
   * What it does:
   * Builds one reflected proxy reference to the indexed legacy
   * `vector<bool>::reference` bit lane.
   */
  gpg::RRef RVectorTypeBool::SubscriptIndex(void* const obj, const int ind) const
  {
    auto* const storage = static_cast<VectorBoolStorage*>(obj);
    GPG_ASSERT(storage != nullptr);

    gRecoveredRVectorTypeBoolSubscriptCursorScratch.word = storage ? storage->mWords : nullptr;
    gRecoveredRVectorTypeBoolSubscriptCursorScratch.bit = 0;
    (void)msvc8::detail::AdvanceCursorBits(&gRecoveredRVectorTypeBoolSubscriptCursorScratch, ind);

    gpg::RRef out{};
    auto* const reference = reinterpret_cast<std::vector<bool>::reference*>(&gRecoveredRVectorTypeBoolSubscriptCursorScratch);
    (void)gpg::RRef_VectorBoolReference(&out, reference);
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
  [[nodiscard]] CScrLuaInitFormSet& ClassBinderSimLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  /**
   * Address: 0x00BD1980 (FUN_00BD1980, register_sim_SimInits_mForms_offVariant1)
   * Record at 0x00F59A08.
   *
   * What it does:
   * Publishes `CUnitScriptTask`'s method table as `moho.ScriptTask_Methods`,
   * so `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant1()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.ScriptTask_Methods", &CScrLuaMetatableFactory<CUnitScriptTask>::Instance(), "CUnitScriptTask", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD21F0 (FUN_00BD21F0, register_sim_SimInits_mForms_offVariant2)
   * Record at 0x00F59A20.
   *
   * What it does:
   * Publishes `CAimManipulator`'s method table as `moho.AimManipulator`, so
   * `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it and
   * flattens in the `moho.manipulator_methods` base (e.g. `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant2()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.AimManipulator", &CScrLuaMetatableFactory<CAimManipulator>::Instance(), "CAimManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD2210 (FUN_00BD2210, sub_BD2210) -- record at 0x00F59A38
   *
   * What it does:
   * Declares `CAimManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.AimManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CAimManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CAimManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59A64.
   *
   * What it does:
   * Publishes `CBoneEntityManipulator`'s method table as
   * `moho.BoneEntityManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep
   * reaches it and flattens in the `moho.manipulator_methods` base (e.g.
   * `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant4()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.BoneEntityManipulator", &CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance(), "CBoneEntityManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD2420 (FUN_00BD2420, sub_BD2420) -- record at 0x00F59A7C
   *
   * What it does:
   * Declares `CBoneEntityManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.BoneEntityManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CBoneEntityManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CBoneEntityManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59A98.
   *
   * What it does:
   * Publishes `CBuilderArmManipulator`'s method table as
   * `moho.BuilderArmManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep
   * reaches it and flattens in the `moho.manipulator_methods` base (e.g.
   * `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant6()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.BuilderArmManipulator", &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(), "CBuilderArmManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD2570 (FUN_00BD2570, sub_BD2570) -- record at 0x00F59AB0
   *
   * What it does:
   * Declares `CBuilderArmManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.BuilderArmManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CBuilderArmManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CBuilderArmManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59ACC.
   *
   * What it does:
   * Publishes `CCollisionManipulator`'s method table as
   * `moho.CollisionManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep
   * reaches it and flattens in the `moho.manipulator_methods` base (e.g.
   * `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant7()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.CollisionManipulator", &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(), "CCollisionManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD26E0 (FUN_00BD26E0, sub_BD26E0) -- record at 0x00F59AE4
   *
   * What it does:
   * Declares `CCollisionManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.CollisionManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CCollisionManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CCollisionManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59B00.
   *
   * What it does:
   * Publishes `CFootPlantManipulator`'s method table as
   * `moho.FootPlantManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep
   * reaches it and flattens in the `moho.manipulator_methods` base (e.g.
   * `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant8()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.FootPlantManipulator", &CScrLuaMetatableFactory<CFootPlantManipulator>::Instance(), "CFootPlantManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD29E0 (FUN_00BD29E0, sub_BD29E0) -- record at 0x00F59B18
   *
   * What it does:
   * Declares `CFootPlantManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.FootPlantManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CFootPlantManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CFootPlantManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CFootPlantManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.manipulator_methods", &CScrLuaMetatableFactory<IAniManipulator>::Instance(), "IAniManipulator", ""
    );
    return &binder;
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
   * Class-binder record at 0x00F59B50 (`.rdata`), the same table region as the
   * other already-recovered class binders (e.g. `"moho.AimManipulator"` at
   * 0x00F59A20). Its fields read:
   *
   *     name  0x00E22004 -> "moho.AnimationManipulator"
   *     group 0x00E21FEC -> "CAnimationManipulator"
   *     help  0x00E00779 -> ""
   *
   * What it does:
   * Publishes `CScrLuaMetatableFactory<CAnimationManipulator>`'s method table
   * as `moho.AnimationManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches
   * it and flattens in the `moho.manipulator_methods` base (matching the
   * already-recovered `register_CAnimationManipulatorLuaBaseClass` right
   * below, which declares the same class as deriving from `IAniManipulator`
   * for that same flattening pass).
   *
   * Without this, `moho.AnimationManipulator` never names that table and every
   * `moho.AnimationManipulator.<Method>` lookup reads nil --
   * `sim/units/cybran/CAirFactoryUnit.lua:35` captures `PlayAnim` into an
   * upvalue at module load, matching the same failure shape as the
   * `moho.IEffect` gap this session already found and fixed (`f36336a0`).
   */
  CScrLuaInitForm* register_moho_AnimationManipulator_ClassBinder()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.AnimationManipulator", &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      "CAnimationManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD2D70 (FUN_00BD2D70, sub_BD2D70) -- record at 0x00F59B64
   *
   * What it does:
   * Declares `CAnimationManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.AnimationManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CAnimationManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CAnimationManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59B80.
   *
   * What it does:
   * Publishes `CRotateManipulator`'s method table as `moho.RotateManipulator`,
   * so `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it and
   * flattens in the `moho.manipulator_methods` base (e.g. `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant11()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.RotateManipulator", &CScrLuaMetatableFactory<CRotateManipulator>::Instance(), "CRotateManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD2FD0 (FUN_00BD2FD0, sub_BD2FD0) -- record at 0x00F59B98
   *
   * What it does:
   * Declares `CRotateManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.RotateManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CRotateManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CRotateManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59BB4.
   *
   * What it does:
   * Publishes `CSlaveManipulator`'s method table as `moho.SlaveManipulator`,
   * so `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it and
   * flattens in the `moho.manipulator_methods` base (e.g. `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant13()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.SlaveManipulator", &CScrLuaMetatableFactory<CSlaveManipulator>::Instance(), "CSlaveManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD31B0 (FUN_00BD31B0, sub_BD31B0) -- record at 0x00F59BCC
   *
   * What it does:
   * Declares `CSlaveManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.SlaveManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CSlaveManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CSlaveManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CSlaveManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59BE8.
   *
   * What it does:
   * Publishes `CSlideManipulator`'s method table as `moho.SlideManipulator`,
   * so `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it and
   * flattens in the `moho.manipulator_methods` base (e.g. `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant15()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.SlideManipulator", &CScrLuaMetatableFactory<CSlideManipulator>::Instance(), "CSlideManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD3480 (FUN_00BD3480, sub_BD3480) -- record at 0x00F59C00
   *
   * What it does:
   * Declares `CSlideManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.SlideManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CSlideManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CSlideManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CSlideManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59C1C.
   *
   * What it does:
   * Publishes `CStorageManipulator`'s method table as
   * `moho.StorageManipulator`, so `globalInit.lua`'s `for name, cclass in
   * moho do ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep
   * reaches it and flattens in the `moho.manipulator_methods` base (e.g.
   * `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant17()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.StorageManipulator", &CScrLuaMetatableFactory<CStorageManipulator>::Instance(), "CStorageManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD3620 (FUN_00BD3620, sub_BD3620) -- record at 0x00F59C34
   *
   * What it does:
   * Declares `CStorageManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.StorageManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CStorageManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CStorageManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CStorageManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
   * Record at 0x00F59C50.
   *
   * What it does:
   * Publishes `CThrustManipulator`'s method table as `moho.ThrustManipulator`,
   * so `globalInit.lua`'s `for name, cclass in moho do
   * ConvertCClassToLuaSimplifiedClass(cclass, name) end` sweep reaches it and
   * flattens in the `moho.manipulator_methods` base (e.g. `SetPrecedence`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant19()
  {
    static CScrLuaClassBinder binder(
      ClassBinderSimLuaInitSet(), "moho.ThrustManipulator", &CScrLuaMetatableFactory<CThrustManipulator>::Instance(), "CThrustManipulator", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BD3760 (FUN_00BD3760, sub_BD3760) -- record at 0x00F59C68
   *
   * What it does:
   * Declares `CThrustManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.ThrustManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CThrustManipulatorLuaBaseClass()
  {
    static CScrLuaBaseClassSpec spec(
      ClassBinderSimLuaInitSet(),
      &CScrLuaMetatableFactory<CThrustManipulator>::Instance(),
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      "CThrustManipulator",
      "derived from IAniManipulator"
    );
    return &spec;
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
      (void)moho::register_CAimManipulatorLuaBaseClass();
      (void)moho::register_TConVar_dbg_Ballistics();
      moho::register_CAimManipulatorTypeInfo();
      moho::register_CAimManipulatorSerializer();
      (void)moho::register_CScrLuaMetatableFactory_CAimManipulator_Index();
      (void)moho::register_CScrLuaMetatableFactory_IAniManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant4();
      (void)moho::register_CBoneEntityManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant6();
      (void)moho::register_CBuilderArmManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant7();
      (void)moho::register_CCollisionManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CCollisionManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant8();
      (void)moho::register_CFootPlantManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CFootPlantManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant9();
      (void)moho::register_sim_SimInits_mForms_off_F59B34_mFactory();
      (void)moho::register_moho_AnimationManipulator_ClassBinder();
      (void)moho::register_CAnimationManipulatorLuaBaseClass();
      (void)moho::register_RVectorType_bool();
      (void)moho::register_CScrLuaMetatableFactory_CAnimationManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant11();
      (void)moho::register_CRotateManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CRotateManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant13();
      (void)moho::register_CSlaveManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CSlaveManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant15();
      (void)moho::register_CSlideManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CSlideManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant17();
      (void)moho::register_CStorageManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CStorageManipulator_Index();
      (void)moho::register_sim_SimInits_mForms_offVariant19();
      (void)moho::register_CThrustManipulatorLuaBaseClass();
      (void)moho::register_CScrLuaMetatableFactory_CThrustManipulator_Index();
    }
  };

  [[maybe_unused]] ManipulatorStartupRegistrationsBootstrap gManipulatorStartupRegistrationsBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RVectorType_bool_324744, preregister_RVectorType_bool)
