#pragma once

// Private to moho/app: helpers the pieces of the former WxRuntimeTypes.cpp share.

#include "WxRuntimeTypes.h"
#include "gpg/core/profiling/Profiler.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <new>
#include <string>

// The Direct3D 9 backend is Windows-only (the Linux client, issue #255).
#if FAFRE_PLATFORM_WINDOWS
#include <d3d9.h>
#endif

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/RenderProfiler.h"
// The Direct3D 9 backend is Windows-only (the Linux client, issue #255).
#if FAFRE_PLATFORM_WINDOWS
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#endif
#include "moho/console/CConCommand.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/mesh/MeshThumbnailRenderer.h"
#include "moho/render/BoundaryRenderer.h"
#include "moho/render/BoxRenderer.h"
#include "moho/render/Cartographic.h"
#include "moho/render/Clutter.h"
#include "moho/render/CRenFrame.h"
#include "moho/render/MapImager.h"
#include "moho/render/IEdRenderHook.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/ID3DDepthStencil.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/RangeRendererStartupRegistrations.h"
#include "moho/render/RCamManager.h"
#include "moho/render/SelectionBracketRenderer.h"
#include "moho/render/Shadow.h"
#include "moho/render/Silhouette.h"
#include "moho/render/SimpleRenderWorldView.h"
#include "moho/render/SkyDome.h"
#include "moho/render/VisionRenderer.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/d3d/WD3DViewport.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/TimeBar.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CLobby.h"
#include "moho/net/Common.h"
#include "moho/net/INetConnector.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CWldMap.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/TerrainFactory.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/terrain/HighFidelityTerrain.h"
#include "moho/terrain/LowFidelityTerrain.h"
#include "moho/terrain/MediumFidelityTerrain.h"
#include "moho/ui/IUIManager.h"

#define EVT_LOG_ADDITION_EVENT(fn)                                                                             DECLARE_EVENT_TABLE_ENTRY(                                                                                     moho::EVT_LOG_ADDITION, -1, -1,                                                                              (wxObjectEventFunction)(wxEventFunction)(moho::CLogAdditionEventFunction)&fn, (wxObject*)NULL              ),

