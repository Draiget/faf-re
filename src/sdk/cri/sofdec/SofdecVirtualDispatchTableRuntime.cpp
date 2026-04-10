
namespace moho::cri::sofdec::detail
{
  enum class SofDecVirtualDispatchSlot : std::size_t
  {
    kResetState = 3,
    kUpdatePlayheadSample = 4,
    kCaptureLatchedSample = 5,
    kGetDefaultPhaseModulo = 6,
    kNoOpA = 7,
    kUpdateWrapPosition = 8,
    kSetSampleRate = 9,
    kGetSampleRate = 10,
    kNoOpB = 11,
    kGetOutputBitDepth = 12,
    kNoOpC = 13,
    kReturnZeroD = 14,
    kNoOpE = 15,
    kStubReturnZeroA = 16,
    kStubNoOpA = 17,
    kStubReturnZeroB = 18,
    kStubNoOpB = 19,
    kStubZeroRangeOutputs = 20,
    kStubNoOpC = 21,
    kStubNoOpD = 22,
    kStubReturnOne = 23,
    kStubSetReadyFlag = 24,
    kStubReturnZeroC = 25
  };

  template <typename FunctionPointer>
  inline void BindSofDecVirtualDispatchSlot(
    void** const table,
    const SofDecVirtualDispatchSlot slot,
    FunctionPointer functionPointer
  )
  {
    table[static_cast<std::size_t>(slot)] = reinterpret_cast<void*>(functionPointer);
  }
}

namespace
{
  [[nodiscard]] void* const* GetSofDecVirtualDispatchTable()
  {
    using moho::cri::sofdec::detail::BindSofDecVirtualDispatchSlot;
    using moho::cri::sofdec::detail::SofDecVirtualDispatchSlot;
    static const std::array<void*, 27> kSofDecVirtualDispatchTable = []() {
      std::array<void*, 27> dispatchTable{};
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kResetState, &SofDecVirtualResetStateThunk);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kUpdatePlayheadSample, &SofDecVirtualUpdatePlayheadSample
      );
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kCaptureLatchedSample, &SofDecVirtualCaptureLatchedSample
      );
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kGetDefaultPhaseModulo, &SofDecVirtualGetDefaultPhaseModulo
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kNoOpA, &SofDecVirtualNoOpSlotA);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kUpdateWrapPosition, &SofDecVirtualUpdateWrapPosition
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kSetSampleRate, &SofDecVirtualSetSampleRate);
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kGetSampleRate, &SofDecVirtualGetSampleRate);
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kNoOpB, &SofDecVirtualNoOpSlotB);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kGetOutputBitDepth, &SofDecVirtualGetOutputBitDepth
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kNoOpC, &SofDecVirtualNoOpSlotC);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kReturnZeroD, &SofDecVirtualReturnZeroSlotD
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kNoOpE, &SofDecVirtualNoOpSlotE);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubReturnZeroA, &SofDecVirtualStubReturnZeroA
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kStubNoOpA, &SofDecVirtualStubNoOpA);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubReturnZeroB, &SofDecVirtualStubReturnZeroB
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kStubNoOpB, &SofDecVirtualStubNoOpB);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubZeroRangeOutputs, &SofDecVirtualStubZeroRangeOutputs
      );
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kStubNoOpC, &SofDecVirtualStubNoOpC);
      BindSofDecVirtualDispatchSlot(dispatchTable.data(), SofDecVirtualDispatchSlot::kStubNoOpD, &SofDecVirtualStubNoOpD);
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubReturnOne, &SofDecVirtualStubReturnOne
      );
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubSetReadyFlag, &SofDecVirtualStubSetReadyFlag
      );
      BindSofDecVirtualDispatchSlot(
        dispatchTable.data(), SofDecVirtualDispatchSlot::kStubReturnZeroC, &SofDecVirtualStubReturnZeroC
      );
      return dispatchTable;
    }();

    return kSofDecVirtualDispatchTable.data();
  }
}
