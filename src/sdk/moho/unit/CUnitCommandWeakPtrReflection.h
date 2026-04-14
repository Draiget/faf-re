#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class CUnitCommand;

  struct WeakPtr_CUnitCommand
  {
    /**
     * Address: 0x006EA880 (FUN_006EA880, Moho::RWeakPtrType_CUnitCommand::SerLoad)
     *
     * What it does:
     * Deserializes one `WeakPtr<CUnitCommand>` payload from a tracked pointer.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EA8B0 (FUN_006EA8B0, Moho::RWeakPtrType_CUnitCommand::SerSave)
     *
     * What it does:
     * Serializes one `WeakPtr<CUnitCommand>` payload as an unowned tracked pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  template <class T>
  class RWeakPtrType;

  template <>
  class RWeakPtrType<CUnitCommand> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<CUnitCommand>) == 0x68, "RWeakPtrType<CUnitCommand> size must be 0x68");

  /**
   * Address: 0x005A2220 (FUN_005A2220, Moho::WeakPtr_CUnitCommand::move_range)
   *
   * What it does:
   * Rebinds one half-open `WeakPtr<CUnitCommand>` range onto destination
   * storage by unlinking destination nodes from old owner chains and relinking
   * them to source owners.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* MoveWeakPtrCUnitCommandRangeAndReturnEnd(
    WeakPtr<CUnitCommand>* destination,
    WeakPtr<CUnitCommand>* sourceBegin,
    WeakPtr<CUnitCommand>* sourceEnd
  );

  /**
   * Address: 0x005A1D00 (FUN_005A1D00, Moho::WeakPtr_CUnitCommand::move_range_0)
   *
   * What it does:
   * Adapter for the VC8 vector move lane that forwards end-first operand order
   * into the canonical `move_range(destination, begin, end)` ordering.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* MoveWeakPtrCUnitCommandRangeAdapter(
    WeakPtr<CUnitCommand>* sourceEnd,
    WeakPtr<CUnitCommand>* sourceBegin,
    WeakPtr<CUnitCommand>* destination
  );

  /**
   * Address: 0x005FF400 (FUN_005FF400, Moho::WeakPtr_CUnitCommand::cpy_range)
   *
   * What it does:
   * Copies one half-open `WeakPtr<CUnitCommand>` range into destination storage,
   * rebinding each copied node to the source owner link and inserting live nodes
   * at the owner-chain head.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* CopyWeakPtrCUnitCommandRangeAndReturnEnd(
    WeakPtr<CUnitCommand>* destination,
    const WeakPtr<CUnitCommand>* sourceBegin,
    const WeakPtr<CUnitCommand>* sourceEnd
  );

  /**
   * Address: 0x005FD580 (FUN_005FD580, Moho::WeakPtr_CUnitCommand::cpy_range_0)
   *
   * What it does:
   * Adapts the source-first argument order used by one vector-copy lane and
   * forwards to `cpy_range` with canonical destination-first ordering.
   */
  [[nodiscard]] WeakPtr<CUnitCommand>* CopyWeakPtrCUnitCommandRangeAdapter(
    const WeakPtr<CUnitCommand>* sourceBegin,
    const WeakPtr<CUnitCommand>* sourceEnd,
    WeakPtr<CUnitCommand>* destination
  );

  /**
   * Address: 0x005DB610 (FUN_005DB610, std::vector_WeakPtr_CUnitCommand::cpy)
   *
   * What it does:
   * Copies one legacy `vector<WeakPtr<CUnitCommand>>` payload into destination
   * storage using the VC8 vector copy semantics and explicit weak-link relinking.
   */
  [[nodiscard]] msvc8::vector<WeakPtr<CUnitCommand>>* CopyWeakPtrCUnitCommandVector(
    const msvc8::vector<WeakPtr<CUnitCommand>>& source,
    msvc8::vector<WeakPtr<CUnitCommand>>& destination
  );

  /**
   * Address: 0x005A2270 (FUN_005A2270, Moho::WeakPtr_CUnitCommand::destruct_range)
   *
   * What it does:
   * Unlinks one contiguous `WeakPtr<CUnitCommand>` range from owner intrusive
   * chains before storage is destroyed or overwritten.
   */
  void DetachWeakPtrCUnitCommandRange(WeakPtr<CUnitCommand>* begin, WeakPtr<CUnitCommand>* end);

  /**
   * Address: 0x006EBE50 (FUN_006EBE50, sub_6EBE50)
   *
   * What it does:
   * Constructs/preregisters RTTI for `WeakPtr<CUnitCommand>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_CUnitCommand_Type_00();

  /**
   * Address: 0x00BD8FF0 (FUN_00BD8FF0, sub_BD8FF0)
   *
   * What it does:
   * Registers `WeakPtr<CUnitCommand>` reflection and installs process-exit
   * teardown via `atexit`.
   */
  int register_WeakPtr_CUnitCommand_Type_AtExit();
} // namespace moho

namespace gpg
{
  template <class T>
  class RVectorType;

  template <>
  class RVectorType<moho::WeakPtr<moho::CUnitCommand>> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006E9B90 (FUN_006E9B90, gpg::RVectorType_WeakPtr_CUnitCommand::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E9C50 (FUN_006E9C50, gpg::RVectorType_WeakPtr_CUnitCommand::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006E9CE0 (FUN_006E9CE0, gpg::RVectorType_WeakPtr_CUnitCommand::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006E9C30 (FUN_006E9C30, gpg::RVectorType_WeakPtr_CUnitCommand::Init)
     */
    void Init() override;

    /**
     * Address: 0x006E9D40 (FUN_006E9D40, gpg::RVectorType_WeakPtr_CUnitCommand::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006E9CF0 (FUN_006E9CF0, gpg::RVectorType_WeakPtr_CUnitCommand::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006E9D10 (FUN_006E9D10, gpg::RVectorType_WeakPtr_CUnitCommand::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RVectorType<moho::WeakPtr<moho::CUnitCommand>>) == 0x68,
    "RVectorType<WeakPtr<CUnitCommand>> size must be 0x68"
  );
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006EBEC0 (FUN_006EBEC0, sub_6EBEC0)
   *
   * What it does:
   * Constructs/preregisters RTTI for `vector<WeakPtr<CUnitCommand>>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_CUnitCommand_VectorType_00();

  /**
   * Address: 0x00BD9010 (FUN_00BD9010, sub_BD9010)
   *
   * What it does:
   * Registers `vector<WeakPtr<CUnitCommand>>` reflection and installs process-exit
   * teardown via `atexit`.
   */
  int register_WeakPtr_CUnitCommand_VectorType_AtExit();
} // namespace moho
