#pragma once

// Private to moho/mesh: helpers the pieces of the former Mesh.cpp share.

#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include <cstdio>
#include "Mesh.h"
#include "legacy/math/X87Math.h"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <vector>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/app/UserWorkerPool.h"
#include "moho/audio/AudioEngine.h"
#include "moho/console/CConCommand.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector4f.h"
#include "moho/math/VMatrix4.h"
#include "moho/mesh/MeshBatch.h"
#include "moho/mesh/ShaderDictionary.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/Shadow.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterSurface.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/gal/Matrix.h"
#include "gpg/gal/MeshFormatter.h"
#include "gpg/core/utils/Logging.h"
#include "moho/render/d3d/CD3DRenderTarget.h"


namespace moho
{
  extern float ren_MeshDissolve;
  extern float ren_MeshDissolveCutoff;
}
