#pragma once

// Private to gpg/gal/backends/d3d9: helpers the pieces of the former D3D9Interfaces.cpp share.

#include "AdapterD3D9.hpp"
#include "AdapterModeD3D9.hpp"
#include "CubeRenderTargetD3D9.hpp"
#include "DepthStencilTargetD3D9.hpp"
#include "DeviceD3D9.hpp"
#include "EffectD3D9.hpp"
#include "EffectTechniqueD3D9.hpp"
#include "EffectVariableD3D9.hpp"
#include "Float16HardwareVertexFormatterD3D9.hpp"
#include "HardwareVertexFormatterD3D9.hpp"
#include "IndexBufferD3D9.hpp"
#include "PipelineStateD3D9.hpp"
#include "RenderTargetD3D9.hpp"
#include "StateManagerD3D9.hpp"
#include "TextureD3D9.hpp"
#include "VertexBufferD3D9.hpp"
#include "VertexFormatD3D9.hpp"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/DxgiAdapterInfo.h"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/PipelineState.hpp"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/OutputContext.hpp"

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"

#include <d3d9.h>
#include <d3dx9.h>

#include <bit>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace gpg::gal
{
namespace
{
        constexpr int kCubeFaceCount = 6;

        fa::string MakeShortString(const char* const text)
        {
            if (text == nullptr)
            {
                return fa::string();
            }

            const std::size_t length = std::strlen(text);
            return fa::string(text, length);
        }

        [[noreturn]] void ThrowGalError(const char* const file, const int line, const char* const message)
        {
            throw Error(MakeShortString(file), line, MakeShortString(message));
        }

        [[maybe_unused]] [[noreturn]] void ThrowGalErrorFromHresult(const char* const file, const int line, const HRESULT code)
        {
            throw Error(MakeShortString(file), line, MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code))));
        }

        /**
         * Makes `call`; when it fails, makes it a second time and throws with
         * the second result's text. Part of the backend checks its calls this
         * way rather than keeping the first HRESULT - `GetTexture2D` repeats
         * every failing call (0x008ECDB7, 0x008ECE6F, 0x008ECFDE, ...) -
         * which the repeat preserves.
         */
        template <class Call>
        void CheckD3DCall(const char* const file, const int line, Call&& call)
        {
            if (FAILED(call()))
            {
                ThrowGalErrorFromHresult(file, line, call());
            }
        }
}


    /**
     * Address: 0x00945160 (FUN_00945160)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from a
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    [[maybe_unused]] static void CopyMatrix4x3Rows(
        float* const outRow0,
        float* const outRow1,
        float* const outRow2,
        float* const outRow3,
        const Matrix& matrix
    )
    {
        float* const outRows[4] = {outRow0, outRow1, outRow2, outRow3};
        for (int row = 0; row < 4; ++row)
        {
            outRows[row][0] = matrix.r[row].x;
            outRows[row][1] = matrix.r[row].y;
            outRows[row][2] = matrix.r[row].z;
        }
    }
namespace
{

        static constexpr std::uint32_t kVertexFormatCount = 24U;

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_0[2] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_1[2] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_2[3] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_3[3] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_4[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 20, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_5[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_6[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_7[3] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITIONT, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_8[4] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITIONT, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_9[8] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 16, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 32, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 48, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_10[2] = {
            {0, 0, D3DDECLTYPE_SHORT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_11[7] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 16, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 32, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 48, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {0, 60, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {0, 76, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_12[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 36, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_13[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 28, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 44, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_14[15] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 16, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 28, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 40, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 68, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {1, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {1, 68, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {1, 72, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_15[15] = {
            {0, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 8, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 16, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 24, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 32, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 40, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {1, 52, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {1, 60, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {1, 64, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_16[16] = {
            {0, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 8, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 16, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 24, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 32, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 40, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {2, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {2, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {2, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {2, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {2, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {2, 52, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {2, 60, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {2, 64, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_17[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 8, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_18[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 8, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_19[9] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 24, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 40, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 68, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 80, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_20[5] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 24, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_21[7] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 28, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 36, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 44, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_22[5] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 20, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_23[1] = {
            D3DDECL_END(),
        };

        static constexpr const D3DVERTEXELEMENT9* kVertexFormatsByCode[kVertexFormatCount] = {
            kVertexFormat_0,  kVertexFormat_1,  kVertexFormat_2,  kVertexFormat_3,  kVertexFormat_4,  kVertexFormat_5,
            kVertexFormat_6,  kVertexFormat_7,  kVertexFormat_8,  kVertexFormat_9,  kVertexFormat_10, kVertexFormat_11,
            kVertexFormat_12, kVertexFormat_13, kVertexFormat_14, kVertexFormat_15, kVertexFormat_16, kVertexFormat_17,
            kVertexFormat_18, kVertexFormat_19, kVertexFormat_20, kVertexFormat_21, kVertexFormat_22, kVertexFormat_23,
        };

        /**
         * Address: 0x0094AE10 (FUN_0094AE10, func_GetVertexFormat)
         *
         * What it does:
         * Validates one vertex-format code and returns the recovered D3D vertex
         * element declaration table pointer for that format.
         */
        [[maybe_unused]] const D3DVERTEXELEMENT9* GetVertexFormatElementsOrThrow(const std::uint32_t formatCode)
        {
            if (formatCode >= kVertexFormatCount)
            {
                ThrowGalError("VertexFormatD3D9.cpp", 389, "invalid vertex format specified");
            }

            return kVertexFormatsByCode[formatCode];
        }
}

}

