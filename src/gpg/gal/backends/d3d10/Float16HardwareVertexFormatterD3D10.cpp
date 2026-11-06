#include "gpg/gal/backends/d3d10/D3D10Private.h"
#include "gpg/gal/HalfFloat.h"

namespace gpg::gal
{
namespace
{
    constexpr std::uint32_t kFloat16VertexFormatToken = 15U;
    constexpr std::uint32_t kFloat16VertexStrideStream0 = 0x2CU;
    constexpr std::uint32_t kFloat16VertexStrideStream1 = 0x44U;
}


  /**
   * Address: 0x0094D770 (FUN_0094D770, ??0Float16HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes one D3D10 float16 hardware-vertex formatter wrapper.
   */
  Float16HardwareVertexFormatterD3D10::Float16HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D780 (FUN_0094D780)
   * Address: 0x0094D910 (FUN_0094D910, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
   */
  Float16HardwareVertexFormatterD3D10::~Float16HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D790 (FUN_0094D790)
   *
   * What it does:
   * Needs both of the active device context's flags, hardware instancing
   * (+0x11) and float16 (+0x12); ignores the `mesh_Rebatch` switches.
   */
  bool Float16HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    const DeviceContext* const context = Device::GetInstance()->GetDeviceContext();
    return context->mHWBasedInstancing && context->mSupportsFloat16;
  }

  /**
   * Address: 0x0094D930 (FUN_0094D930)
   *
   * What it does:
   * Creates vertex format 15 on the active device. Unlike the D3D9 float16
   * formatter it never picks 16: `layoutVariant` is ignored.
   */
  boost::shared_ptr<VertexFormat> Float16HardwareVertexFormatterD3D10::CreateVertexFormat(
    const std::int32_t layoutVariant
  )
  {
    static_cast<void>(layoutVariant);
    return Device::GetInstance()->CreateVertexFormat(kFloat16VertexFormatToken);
  }

  /**
   * Address: 0x0094D7C0 (FUN_0094D7C0)
   *
   * What it does:
   * Returns float16 packed stride for the requested stream class.
   */
  std::uint32_t Float16HardwareVertexFormatterD3D10::GetVertexStride(
    const std::int32_t streamClass,
    const std::int32_t sizeVariant
  )
  {
    static_cast<void>(sizeVariant);
    return (streamClass != 0) ? kFloat16VertexStrideStream1 : kFloat16VertexStrideStream0;
  }

  /**
   * Address: 0x0094D7E0 (FUN_0094D7E0)
   *
   * What it does:
   * Packs the instance half of one mesh vertex into the format 15 instance
   * record (half-precision scalars). The body never looks at `streamClass`
   * or `writeVariant` - the D3D10 float16 formatter only ever writes the
   * instance stream.
   */
  void Float16HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const MeshVertex& source,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(streamClass);
    static_cast<void>(writeVariant);

    auto& destination = *static_cast<Float16HardwareVertexInstance*>(destinationVertex);
    destination.instanceIndex = source.instanceIndex;
    destination.color = source.color;
    destination.shaderTime = FloatToHalf(source.shaderTime);
    static_cast<void>(CopyMatrix4x3Rows(
      destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
      source.transform
    ));
    destination.bonePaletteBase = source.bonePaletteBase;
    destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
    destination.scroll[1] = FloatToHalf(source.scroll[1]);
    destination.scroll[0] = FloatToHalf(source.scroll[0]);
    destination.dissolve = source.dissolve;
    destination.parameter = FloatToHalf(source.parameter);
    destination.meshColor = source.meshColor;
  }
}

