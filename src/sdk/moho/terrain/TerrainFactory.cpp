#include "moho/terrain/TerrainFactory.h"

#include <new>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/terrain/HighFidelityTerrain.h"
#include "moho/terrain/LowFidelityTerrain.h"
#include "moho/terrain/MediumFidelityTerrain.h"

namespace moho
{
  namespace
  {
    struct IRenTerrainRuntimeView
    {
      void* mVtable = nullptr;
    };
    static_assert(sizeof(IRenTerrainRuntimeView) == 0x04, "IRenTerrainRuntimeView size must be 0x04");

    class IRenTerrainVTableProbe
    {
    public:
      virtual ~IRenTerrainVTableProbe() = default;
    };

    [[nodiscard]] void* RecoveredIRenTerrainVTable() noexcept
    {
      static IRenTerrainVTableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }

    void WriteIRenTerrainVTable(IRenTerrainRuntimeView* const object) noexcept
    {
      object->mVtable = RecoveredIRenTerrainVTable();
    }

    /**
     * Address: 0x007FF7D0 (FUN_007FF7D0)
     *
     * IDA signature:
     * _DWORD *__usercall sub_7FF7D0@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Writes the `IRenTerrain` base-interface vtable lane and returns the same
     * object pointer.
     */
    [[maybe_unused]] IRenTerrainRuntimeView* InitializeIRenTerrainVTableReturnLane(
      IRenTerrainRuntimeView* const object
    ) noexcept
    {
      WriteIRenTerrainVTable(object);
      return object;
    }

    template <typename T>
    [[nodiscard]] TerrainCommon* AllocateTerrainNoThrow()
    {
      void* const storage = ::operator new(sizeof(T), std::nothrow);
      if (storage == nullptr) {
        return nullptr;
      }

      return new (storage) T();
    }
  } // namespace

  /**
   * Address: 0x00809DA0 (?Create@IRenTerrain@Moho@@SAPAV12@XZ)
   * Mangled: ?Create@IRenTerrain@Moho@@SAPAV12@XZ
   *
   * What it does:
   * Allocates one terrain renderer variant from `graphics_Fidelity`,
   * logs the selected fidelity path, and returns the constructed base pointer.
   */
  TerrainCommon* IRenTerrain::Create()
  {
    TerrainCommon* result = nullptr;
    const char* selectedPath = nullptr;

    if (graphics_Fidelity == 0) {
      result = AllocateTerrainNoThrow<LowFidelityTerrain>();
      selectedPath = "creating low fidelity terrain";
    } else if (graphics_Fidelity == 1) {
      result = AllocateTerrainNoThrow<MediumFidelityTerrain>();
      selectedPath = "creating medium fidelity terrain";
    } else if (graphics_Fidelity == 2) {
      result = AllocateTerrainNoThrow<HighFidelityTerrain>();
      selectedPath = "creating high fidelity terrain";
    } else {
      return nullptr;
    }

    gpg::Logf(selectedPath);
    return result;
  }

  /**
   * Address: 0x007FF8B0 (FUN_007FF8B0, ??3IRenTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the IRenTerrain destructor lane and conditionally frees the object
   * storage when the delete flag requests heap release.
   */
  IRenTerrain* IRenTerrain::DeleteWithFlag(IRenTerrain* const object, const std::uint8_t deleteFlags) noexcept
  {
    object->~IRenTerrain();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(object);
    }
    return object;
  }
} // namespace moho
