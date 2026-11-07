#include "gpg/gal/backends/d3d9/D3D9Private.h"
#include "gpg/gal/HalfFloat.h"

namespace gpg::gal
{
namespace
{
        constexpr std::uint32_t kFloat16VertexStrideTableDefault[2] = {0x2CU, 0x44U};  // Address: 0x00F3275C
        constexpr std::uint32_t kFloat16VertexStrideTableCompact[2] = {0x2CU, 0x08U}; // Address: 0x00F32764
}


    /**
     * Address: 0x00945080 (FUN_00945080)
     *
     * What it does:
     * Packs two input float lanes into two float16 lanes.
     */
    static void PackFloat2ToHalf2(std::uint16_t* const outHalf2, const float* const inFloat2)
    {
        outHalf2[0] = FloatToHalf(inFloat2[0]);
        outHalf2[1] = FloatToHalf(inFloat2[1]);
    }

    /**
     * Address: 0x009450E0 (FUN_009450E0)
     *
     * What it does:
     * Packs three input float lanes into three float16 lanes.
     */
    static void PackFloat3ToHalf3(std::uint16_t* const outHalf3, const float* const inFloat3)
    {
        outHalf3[0] = FloatToHalf(inFloat3[0]);
        outHalf3[1] = FloatToHalf(inFloat3[1]);
        outHalf3[2] = FloatToHalf(inFloat3[2]);
    }

    /**
     * Address: 0x00945380 (FUN_00945380, ??0Float16HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Initializes one D3D9 float16 hardware-vertex formatter wrapper.
     */
    Float16HardwareVertexFormatterD3D9::Float16HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x00945390 (FUN_00945390)
     * Address: 0x00945620 (FUN_00945620, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
     */
    Float16HardwareVertexFormatterD3D9::~Float16HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x009453A0 (FUN_009453A0)
     *
     * What it does:
     * Needs both switches: instancing first, then float16.
     */
    bool Float16HardwareVertexFormatterD3D9::AllowMeshInstancing()
    {
        return MeshInstancingEnabled() && MeshFloat16Enabled();
    }

    /**
     * Address: 0x00945640 (FUN_00945640)
     *
     * What it does:
     * Creates vertex format 15 on the active device, or 16 (the one with the
     * second per-vertex position stream) when `layoutVariant` is set.
     */
    boost::shared_ptr<VertexFormat> Float16HardwareVertexFormatterD3D9::CreateVertexFormat(
        const std::int32_t layoutVariant
    )
    {
        return Device::GetInstance()->CreateVertexFormat((layoutVariant != 0) ? 16U : 15U);
    }

    /**
     * Address: 0x009453C0 (FUN_009453C0)
     *
     * What it does:
     * Returns float16 packed stride from runtime stride lookup tables.
     */
    std::uint32_t Float16HardwareVertexFormatterD3D9::GetVertexStride(
        const std::int32_t streamClass,
        const std::int32_t sizeVariant
    )
    {
        const auto* const table = (sizeVariant != 0) ? kFloat16VertexStrideTableCompact : kFloat16VertexStrideTableDefault;
        return table[static_cast<std::size_t>(streamClass)];
    }

    /**
     * Address: 0x009453F0 (FUN_009453F0)
     *
     * What it does:
     * Packs one mesh vertex into vertex format 15/16 with half-precision
     * scalars. Stream class 0 gets the geometry record; with `writeVariant`
     * set, stream class 1 is format 16 second per-vertex position stream and
     * gets `position1` as three halves; any other stream class gets the
     * instance record.
     */
    void Float16HardwareVertexFormatterD3D9::WriteFormattedVertex(
        const std::int32_t streamClass,
        void* const destinationVertex,
        const MeshVertex& source,
        const std::int32_t writeVariant
    )
    {
        if (streamClass != 0)
        {
            if ((writeVariant != 0) && (streamClass == 1))
            {
                PackFloat3ToHalf3(static_cast<std::uint16_t*>(destinationVertex), source.position1);
                return;
            }

            auto& destination = *static_cast<Float16HardwareVertexInstance*>(destinationVertex);
            destination.instanceIndex = source.instanceIndex;
            destination.meshColor = source.meshColor;
            destination.color = source.color;
            destination.shaderTime = FloatToHalf(source.shaderTime);
            CopyMatrix4x3Rows(
                destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
                source.transform
            );
            destination.bonePaletteBase = source.bonePaletteBase;
            destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
            PackFloat2ToHalf2(destination.scroll, source.scroll);
            destination.dissolve = source.dissolve;
            destination.parameter = FloatToHalf(source.parameter);
            return;
        }

        auto& destination = *static_cast<Float16HardwareVertex*>(destinationVertex);
        destination.boneIndices[0] = source.boneIndices[0];
        destination.boneIndices[1] = source.boneIndices[1];
        destination.boneIndices[2] = source.boneIndices[2];
        destination.boneIndices[3] = source.boneIndices[3];

        PackFloat3ToHalf3(destination.position, source.position);
        PackFloat3ToHalf3(destination.normal, source.normal);
        PackFloat3ToHalf3(destination.binormal, source.binormal);
        PackFloat3ToHalf3(destination.tangent, source.tangent);

        destination.texCoords[0] = FloatToHalf(source.texCoord0[0]);
        destination.texCoords[1] = FloatToHalf(source.texCoord0[1]);
        destination.texCoords[2] = FloatToHalf(source.texCoord1[0]);
        destination.texCoords[3] = FloatToHalf(source.texCoord1[1]);
    }
}

