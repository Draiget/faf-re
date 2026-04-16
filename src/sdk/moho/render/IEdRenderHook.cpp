#include "moho/render/IEdRenderHook.h"

namespace
{
  struct IEdRenderHookRuntimeView
  {
    void* mVtable = nullptr;
  };
  static_assert(sizeof(IEdRenderHookRuntimeView) == sizeof(moho::IEdRenderHook), "IEdRenderHook runtime view size must match");

  class EdRenderHookVTableProbe final : public moho::IEdRenderHook
  {
  public:
    void Hook0() override
    {
    }

    void Hook1() override
    {
    }
  };

  [[nodiscard]] void* RecoveredEdRenderHookVTable() noexcept
  {
    static EdRenderHookVTableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }

  void WriteEdRenderHookVTable(moho::IEdRenderHook* const hook)
  {
    auto& runtimeView = reinterpret_cast<IEdRenderHookRuntimeView&>(*hook);
    runtimeView.mVtable = RecoveredEdRenderHookVTable();
  }
}

namespace moho
{
IEdRenderHook* ed_Hook = nullptr;

/**
 * Address: 0x007B6410 (FUN_007B6410)
 *
 * IDA signature:
 * _DWORD *__usercall sub_7B6410@<eax>(_DWORD *result@<eax>)
 *
 * What it does:
 * Writes the `IEdRenderHook` vtable lane and returns the same object pointer.
 */
IEdRenderHook* InitializeEdRenderHookVTableEax(IEdRenderHook* const hook)
{
  WriteEdRenderHookVTable(hook);
  return hook;
}

/**
 * Address: 0x007B6420 (FUN_007B6420)
 *
 * IDA signature:
 * void __thiscall sub_7B6420(_DWORD *this)
 *
 * What it does:
 * Writes the `IEdRenderHook` vtable lane to one object pointer in the ECX
 * thiscall variant.
 */
void InitializeEdRenderHookVTableEcx(IEdRenderHook* const hook)
{
  WriteEdRenderHookVTable(hook);
}

/**
 * Address: 0x007B6440 (FUN_007B6440)
 *
 * IDA signature:
 * int sub_7B6440()
 *
 * What it does:
 * Returns the process-global `Moho::ed_Hook` pointer.
 */
IEdRenderHook* GetEditorRenderHook()
{
  return ed_Hook;
}
}
