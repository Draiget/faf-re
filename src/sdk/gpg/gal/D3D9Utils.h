#pragma once

#include "platform/Platform.h"

namespace gpg::gal
{
    //
	// Minimal cross-platform aliases for D3D9 state enums.
	// On Windows include <d3d9types.h>; elsewhere fall back to uint32_t.
	//
	#if defined(_WIN32)
	#include <d3d9types.h>
	    namespace d3d9 {
	        using RenderState = _D3DRENDERSTATETYPE;
	        using SamplerState = _D3DSAMPLERSTATETYPE;
	        using TextureStageState = _D3DTEXTURESTAGESTATETYPE;
	    }
	#else
	    namespace d3d9 {
	        enum class RenderState : std::uint32_t {};
	        enum class SamplerState : std::uint32_t {};
	        enum class TextureStageState : std::uint32_t {};
	    }
	#endif
}