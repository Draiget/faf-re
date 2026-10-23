#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/Matrix.h"

namespace gpg::gal
{
    /**
     * One mesh vertex together with the per-instance values that ride with it:
     * what a `MeshFormatter` packs into the backend's vertex streams (the
     * formatters' source file is gpggal's `MeshVertex.cpp`, whose path the
     * binary keeps at 0x0094212C).
     *
     * Moho fills it in two halves. `HardwareMeshBatch::Initialize`
     * (0x007E7540) copies each SCM vertex into the geometry fields and packs
     * stream 0; `HardwareMeshBatch::FillBatch` fills the instance fields per
     * drawn mesh and packs stream 1. Each field is named for the shader input
     * it feeds - the D3D10 input layouts of vertex formats 14-16 spell those
     * semantics out.
     */
    struct MeshVertex
    {
        std::uint8_t instanceIndex = 0;   // +0x00 instance TEXCOORD5.x
        std::uint8_t pad01_03[3]{};
        float meshColor = 0.0f;           // +0x04 instance TEXCOORD7
        std::int32_t color = 0;           // +0x08 instance COLOR0
        float shaderTime = 0.0f;          // +0x0C instance TEXCOORD6.x
        Matrix transform{};               // +0x10 instance TEXCOORD1-4 (rows 0-3, x/y/z)
        std::uint8_t bonePaletteBase = 0; // +0x50 instance TEXCOORD5.y
        std::uint8_t boneIndices[4]{};    // +0x51 BLENDINDICES0-3
        std::uint8_t pad55_57[3]{};
        float position[3]{};              // +0x58 POSITION (w = 1)
        float position1[3]{};             // +0x64 POSITION1, format 16's per-vertex second stream
        float normal[3]{};                // +0x70 NORMAL
        float binormal[3]{};              // +0x7C BINORMAL
        float tangent[3]{};               // +0x88 TANGENT
        float texCoord0[2]{};             // +0x94 TEXCOORD0.xy
        float texCoord1[2]{};             // +0x9C TEXCOORD0.zw
        std::uint8_t useSecondaryData = 0; // +0xA4 instance TEXCOORD5.w (packed as 0x00/0xFF)
        std::uint8_t padA5_A7[3]{};
        float scroll[2]{};                // +0xA8 instance TEXCOORD6.zw
        std::uint8_t dissolve = 0;        // +0xB0 instance TEXCOORD5.z
        std::uint8_t padB1_B3[3]{};
        float parameter = 0.0f;           // +0xB4 instance TEXCOORD6.y
    };

    static_assert(offsetof(MeshVertex, meshColor) == 0x04, "MeshVertex::meshColor offset must be 0x04");
    static_assert(offsetof(MeshVertex, color) == 0x08, "MeshVertex::color offset must be 0x08");
    static_assert(offsetof(MeshVertex, shaderTime) == 0x0C, "MeshVertex::shaderTime offset must be 0x0C");
    static_assert(offsetof(MeshVertex, transform) == 0x10, "MeshVertex::transform offset must be 0x10");
    static_assert(offsetof(MeshVertex, bonePaletteBase) == 0x50, "MeshVertex::bonePaletteBase offset must be 0x50");
    static_assert(offsetof(MeshVertex, boneIndices) == 0x51, "MeshVertex::boneIndices offset must be 0x51");
    static_assert(offsetof(MeshVertex, position) == 0x58, "MeshVertex::position offset must be 0x58");
    static_assert(offsetof(MeshVertex, position1) == 0x64, "MeshVertex::position1 offset must be 0x64");
    static_assert(offsetof(MeshVertex, normal) == 0x70, "MeshVertex::normal offset must be 0x70");
    static_assert(offsetof(MeshVertex, binormal) == 0x7C, "MeshVertex::binormal offset must be 0x7C");
    static_assert(offsetof(MeshVertex, tangent) == 0x88, "MeshVertex::tangent offset must be 0x88");
    static_assert(offsetof(MeshVertex, texCoord0) == 0x94, "MeshVertex::texCoord0 offset must be 0x94");
    static_assert(offsetof(MeshVertex, texCoord1) == 0x9C, "MeshVertex::texCoord1 offset must be 0x9C");
    static_assert(offsetof(MeshVertex, useSecondaryData) == 0xA4, "MeshVertex::useSecondaryData offset must be 0xA4");
    static_assert(offsetof(MeshVertex, scroll) == 0xA8, "MeshVertex::scroll offset must be 0xA8");
    static_assert(offsetof(MeshVertex, dissolve) == 0xB0, "MeshVertex::dissolve offset must be 0xB0");
    static_assert(offsetof(MeshVertex, parameter) == 0xB4, "MeshVertex::parameter offset must be 0xB4");
    static_assert(sizeof(MeshVertex) == 0xB8, "MeshVertex size must be 0xB8");

    /**
     * Vertex format 14, stream 0: the full-precision geometry record the plain
     * hardware formatters write (stride 0x48).
     */
    struct HardwareVertex
    {
        float position[4];            // +0x00 POSITION
        float normal[3];              // +0x10 NORMAL
        float tangent[3];             // +0x1C TANGENT
        float binormal[3];            // +0x28 BINORMAL
        float texCoords[4];           // +0x34 TEXCOORD0
        std::uint8_t boneIndices[4];  // +0x44 BLENDINDICES0-3
    };

    static_assert(offsetof(HardwareVertex, normal) == 0x10, "HardwareVertex::normal offset must be 0x10");
    static_assert(offsetof(HardwareVertex, tangent) == 0x1C, "HardwareVertex::tangent offset must be 0x1C");
    static_assert(offsetof(HardwareVertex, binormal) == 0x28, "HardwareVertex::binormal offset must be 0x28");
    static_assert(offsetof(HardwareVertex, texCoords) == 0x34, "HardwareVertex::texCoords offset must be 0x34");
    static_assert(offsetof(HardwareVertex, boneIndices) == 0x44, "HardwareVertex::boneIndices offset must be 0x44");
    static_assert(sizeof(HardwareVertex) == 0x48, "HardwareVertex size must be 0x48");

    /**
     * Vertex format 14, stream 1: the full-precision per-instance record
     * (stride 0x4C).
     */
    struct HardwareVertexInstance
    {
        float transform[4][3];            // +0x00 TEXCOORD1-4
        std::uint8_t instanceIndex;       // +0x30 TEXCOORD5 (R8G8B8A8_UINT)
        std::uint8_t bonePaletteBase;     // +0x31
        std::uint8_t dissolve;            // +0x32
        std::uint8_t secondaryDataMask;   // +0x33
        float shaderTime;                 // +0x34 TEXCOORD6
        float parameter;                  // +0x38
        float scroll[2];                  // +0x3C
        std::int32_t color;               // +0x44 COLOR0
        float meshColor;                  // +0x48 TEXCOORD7
    };

    static_assert(offsetof(HardwareVertexInstance, instanceIndex) == 0x30, "HardwareVertexInstance::instanceIndex offset must be 0x30");
    static_assert(offsetof(HardwareVertexInstance, shaderTime) == 0x34, "HardwareVertexInstance::shaderTime offset must be 0x34");
    static_assert(offsetof(HardwareVertexInstance, scroll) == 0x3C, "HardwareVertexInstance::scroll offset must be 0x3C");
    static_assert(offsetof(HardwareVertexInstance, color) == 0x44, "HardwareVertexInstance::color offset must be 0x44");
    static_assert(offsetof(HardwareVertexInstance, meshColor) == 0x48, "HardwareVertexInstance::meshColor offset must be 0x48");
    static_assert(sizeof(HardwareVertexInstance) == 0x4C, "HardwareVertexInstance size must be 0x4C");

    /**
     * Vertex formats 15 and 16, stream 0: the half-precision geometry record
     * (stride 0x2C). Each vector is four halves; the formatters write the
     * first three.
     */
    struct Float16HardwareVertex
    {
        std::uint16_t position[4];    // +0x00 POSITION
        std::uint16_t normal[4];      // +0x08 NORMAL
        std::uint16_t tangent[4];     // +0x10 TANGENT
        std::uint16_t binormal[4];    // +0x18 BINORMAL
        std::uint16_t texCoords[4];   // +0x20 TEXCOORD0
        std::uint8_t boneIndices[4];  // +0x28 BLENDINDICES0-3
    };

    static_assert(offsetof(Float16HardwareVertex, normal) == 0x08, "Float16HardwareVertex::normal offset must be 0x08");
    static_assert(offsetof(Float16HardwareVertex, tangent) == 0x10, "Float16HardwareVertex::tangent offset must be 0x10");
    static_assert(offsetof(Float16HardwareVertex, binormal) == 0x18, "Float16HardwareVertex::binormal offset must be 0x18");
    static_assert(offsetof(Float16HardwareVertex, texCoords) == 0x20, "Float16HardwareVertex::texCoords offset must be 0x20");
    static_assert(offsetof(Float16HardwareVertex, boneIndices) == 0x28, "Float16HardwareVertex::boneIndices offset must be 0x28");
    static_assert(sizeof(Float16HardwareVertex) == 0x2C, "Float16HardwareVertex size must be 0x2C");

    /**
     * Vertex formats 15 and 16, per-instance stream: the transform stays full
     * precision, the four scalars go to halves (stride 0x44).
     */
    struct Float16HardwareVertexInstance
    {
        float transform[4][3];            // +0x00 TEXCOORD1-4
        std::uint8_t instanceIndex;       // +0x30 TEXCOORD5 (R8G8B8A8_UNORM)
        std::uint8_t bonePaletteBase;     // +0x31
        std::uint8_t dissolve;            // +0x32
        std::uint8_t secondaryDataMask;   // +0x33
        std::uint16_t shaderTime;         // +0x34 TEXCOORD6
        std::uint16_t parameter;          // +0x36
        std::uint16_t scroll[2];          // +0x38
        std::int32_t color;               // +0x3C COLOR0
        float meshColor;                  // +0x40 TEXCOORD7
    };

    static_assert(offsetof(Float16HardwareVertexInstance, instanceIndex) == 0x30, "Float16HardwareVertexInstance::instanceIndex offset must be 0x30");
    static_assert(offsetof(Float16HardwareVertexInstance, shaderTime) == 0x34, "Float16HardwareVertexInstance::shaderTime offset must be 0x34");
    static_assert(offsetof(Float16HardwareVertexInstance, scroll) == 0x38, "Float16HardwareVertexInstance::scroll offset must be 0x38");
    static_assert(offsetof(Float16HardwareVertexInstance, color) == 0x3C, "Float16HardwareVertexInstance::color offset must be 0x3C");
    static_assert(offsetof(Float16HardwareVertexInstance, meshColor) == 0x40, "Float16HardwareVertexInstance::meshColor offset must be 0x40");
    static_assert(sizeof(Float16HardwareVertexInstance) == 0x44, "Float16HardwareVertexInstance size must be 0x44");
} // namespace gpg::gal
