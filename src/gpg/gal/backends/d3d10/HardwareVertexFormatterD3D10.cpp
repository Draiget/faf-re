#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    constexpr std::uint32_t kHardwareVertexFormatToken = 14U;
    constexpr std::uint32_t kHardwareVertexStrideBase = 0x48U;
}


  /**
   * Address: 0x0094D4F0 (FUN_0094D4F0, ??0HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes one D3D10 hardware-vertex formatter wrapper.
   */
  HardwareVertexFormatterD3D10::HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D500 (FUN_0094D500)
   * Address: 0x0094D8F0 (FUN_0094D8F0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
   */
  HardwareVertexFormatterD3D10::~HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D510 (FUN_0094D510)
   *
   * What it does:
   * Returns the active device context's hardware-instancing flag. Unlike the
   * D3D9 formatters it ignores the `mesh_Rebatch` switches.
   */
  bool HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    return Device::GetInstance()->GetDeviceContext()->mHWBasedInstancing;
  }

  /**
   * Address: 0x0094D960 (FUN_0094D960)
   *
   * What it does:
   * Creates vertex format 14 on the active device (slot 14, `[vtbl+0x38]`).
   */
  boost::shared_ptr<VertexFormat> HardwareVertexFormatterD3D10::CreateVertexFormat(const std::int32_t layoutVariant)
  {
    static_cast<void>(layoutVariant);
    return Device::GetInstance()->CreateVertexFormat(kHardwareVertexFormatToken);
  }

  /**
   * Address: 0x0094D530 (FUN_0094D530)
   *
   * What it does:
   * Returns packed hardware-vertex stride for the requested stream class.
   */
  std::uint32_t HardwareVertexFormatterD3D10::GetVertexStride(
    const std::int32_t streamClass,
    const std::int32_t sizeVariant
  )
  {
    static_cast<void>(sizeVariant);
    return kHardwareVertexStrideBase + ((streamClass != 0) ? 4U : 0U);
  }

  /**
   * Address: 0x0094D550 (FUN_0094D550)
   *
   * What it does:
   * Packs one mesh vertex into vertex format 14: the geometry record for
   * stream class 0 (position with w = 1), the instance record otherwise.
   */
  void HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const MeshVertex& source,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(writeVariant);

    if (streamClass != 0) {
      auto& destination = *static_cast<HardwareVertexInstance*>(destinationVertex);
      destination.instanceIndex = source.instanceIndex;
      destination.color = source.color;
      destination.shaderTime = source.shaderTime;
      static_cast<void>(CopyMatrix4x3Rows(
        destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
        source.transform
      ));
      destination.bonePaletteBase = source.bonePaletteBase;
      destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
      destination.scroll[0] = source.scroll[0];
      destination.scroll[1] = source.scroll[1];
      destination.dissolve = source.dissolve;
      destination.parameter = source.parameter;
      destination.meshColor = source.meshColor;
      return;
    }

    auto& destination = *static_cast<HardwareVertex*>(destinationVertex);
    destination.boneIndices[0] = source.boneIndices[0];
    destination.boneIndices[1] = source.boneIndices[1];
    destination.boneIndices[2] = source.boneIndices[2];
    destination.boneIndices[3] = source.boneIndices[3];
    destination.position[0] = source.position[0];
    destination.position[1] = source.position[1];
    destination.position[2] = source.position[2];
    destination.position[3] = 1.0f;
    destination.normal[0] = source.normal[0];
    destination.normal[1] = source.normal[1];
    destination.normal[2] = source.normal[2];
    destination.binormal[0] = source.binormal[0];
    destination.binormal[1] = source.binormal[1];
    destination.binormal[2] = source.binormal[2];
    destination.tangent[0] = source.tangent[0];
    destination.tangent[1] = source.tangent[1];
    destination.tangent[2] = source.tangent[2];
    destination.texCoords[0] = source.texCoord0[0];
    destination.texCoords[1] = source.texCoord0[1];
    destination.texCoords[2] = source.texCoord1[0];
    destination.texCoords[3] = source.texCoord1[1];
  }
}

