#include "StateManagerD3D9.hpp"

#include <bit>
// TEMPORARY PROBE (do not commit): log states pushed while TDecals is active (statediag.on).
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include "gpg/core/utils/Logging.h"
namespace gpg::gal { extern char gProbeCurrentTechnique[64]; }
namespace {
  bool ProbeStateDiagArmed() {
    static unsigned sCalls = 0; static bool sArmed = false;
    if ((sCalls++ % 256u) == 0u) {
      char dir[512] = {}; std::size_t length = 0; sArmed = false;
      if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u) {
        char path[600]; (void)std::snprintf(path, sizeof(path), "%s\\statediag.on", dir);
        sArmed = ::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
      }
    }
    return sArmed && std::strcmp(gpg::gal::gProbeCurrentTechnique, "TDecals") == 0;
  }
  int gProbeStateBudget = 400;
}

namespace gpg::gal
{
  namespace
  {
    // IID_ID3DXEffectStateManager, {79AAB587-6DBC-4FA7-82DE-37FA1781C5CE}
    // (d3dx9effect.h). The binary compares against its own copy at 0x00D7EEBC.
    constexpr GUID kIIDEffectStateManager = {
      0x79AAB587, 0x6DBC, 0x4FA7, {0x82, 0xDE, 0x37, 0xFA, 0x17, 0x81, 0xC5, 0xCE}
    };
  } // namespace

  /**
   * Address: 0x00948280 (FUN_00948280)
   *
   * What it does:
   * Binds the device with a zero reference count and empty caches.
   */
  StateManagerD3D9::StateManagerD3D9(IDirect3DDevice9* const device)
    : uses_(0),
      device_(device),
      activeVertexShader_(nullptr),
      activePixelShader_(nullptr),
      activeFvf_(0)
  {
  }

  /**
   * Address: 0x00948340 (FUN_00948340)
   * Mangled: ?QueryInterface@StateManagerD3D9@gal@gpg@@UAGJABU_GUID@@PAPAX@Z
   *
   * What it does:
   * Hands out `this`, add-ref'd, for IUnknown and ID3DXEffectStateManager.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::QueryInterface(REFIID riid, void** const outObject)
  {
    if (riid == IID_IUnknown || riid == kIIDEffectStateManager)
    {
      *outObject = this;
      AddRef();
      return S_OK;
    }

    *outObject = nullptr;
    return E_NOINTERFACE;
  }

  /**
   * Address: 0x009483A0 (FUN_009483A0)
   * Mangled: ?AddRef@StateManagerD3D9@gal@gpg@@UAGKXZ
   *
   * What it does:
   * Atomically increments `uses_`.
   */
  ULONG STDMETHODCALLTYPE StateManagerD3D9::AddRef()
  {
    return static_cast<ULONG>(InterlockedIncrement(&uses_));
  }

  /**
   * Address: 0x009483C0 (FUN_009483C0)
   * Mangled: ?Release@StateManagerD3D9@gal@gpg@@UAGKXZ
   *
   * What it does:
   * Atomically decrements `uses_` and deletes this object at zero.
   */
  ULONG STDMETHODCALLTYPE StateManagerD3D9::Release()
  {
    const LONG remaining = InterlockedDecrement(&uses_);
    if (remaining != 0)
    {
      return static_cast<ULONG>(remaining);
    }

    delete this;
    return 0;
  }

  /**
   * Address: 0x00949DA0 (FUN_00949DA0)
   * Mangled: ?SetRenderState@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@K@Z
   *
   * What it does:
   * Sets a render state unless the device already holds that value.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetRenderState(const D3DRENDERSTATETYPE state, const DWORD value)
  {
    const bool changed = renderStateCache_.Update(state, value);
    if (ProbeStateDiagArmed() && gProbeStateBudget > 0) { --gProbeStateBudget; gpg::Warnf("[STATEDIAG] RS state=%u value=%08X changed=%d", static_cast<unsigned>(state), static_cast<unsigned>(value), changed ? 1 : 0); } // TEMPORARY PROBE
    if (!changed)
    {
      return S_OK;
    }

    return device_->SetRenderState(state, value);
  }

  /**
   * Address: 0x00948400 (FUN_00948400)
   * Mangled: ?SetRenderStateFlt@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@M@Z
   *
   * What it does:
   * `SetRenderState` with the float's bits as the value.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetRenderStateFlt(const D3DRENDERSTATETYPE state, const float value)
  {
    return SetRenderState(state, std::bit_cast<DWORD>(value));
  }

  /**
   * Address: 0x00949DF0 (FUN_00949DF0)
   * Mangled: ?SetSamplerState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DSAMPLERSTATETYPE@@K@Z
   *
   * What it does:
   * Sets a sampler state unless the device already holds that value. Only
   * samplers 0-15 are cached; the rest always reach the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetSamplerState(
    const DWORD sampler, const D3DSAMPLERSTATETYPE type, const DWORD value
  )
  {
    const bool changed = sampler >= 16 || samplerStateCache_[sampler].Update(type, value);
    if (ProbeStateDiagArmed() && gProbeStateBudget > 0) { --gProbeStateBudget; gpg::Warnf("[STATEDIAG] SS sampler=%u state=%u value=%08X changed=%d", static_cast<unsigned>(sampler), static_cast<unsigned>(type), static_cast<unsigned>(value), changed ? 1 : 0); } // TEMPORARY PROBE
    if (!changed)
    {
      return S_OK;
    }

    return device_->SetSamplerState(sampler, type, value);
  }

  /**
   * Address: 0x00949E50 (FUN_00949E50)
   * Mangled: ?SetTextureStageState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@K@Z
   *
   * What it does:
   * Sets a texture-stage state unless the device already holds that value.
   * Only stages 0-7 are cached; the rest always reach the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTextureStageState(
    const DWORD stage, const D3DTEXTURESTAGESTATETYPE type, const DWORD value
  )
  {
    if (stage < 8 && !textureStageStateCache_[stage].Update(type, value))
    {
      return S_OK;
    }

    return device_->SetTextureStageState(stage, type, value);
  }

  /**
   * Address: 0x00948410 (FUN_00948410)
   * Mangled: ?SetTextureStageStateFlt@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@M@Z
   *
   * What it does:
   * `SetTextureStageState` with the float's bits as the value.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTextureStageStateFlt(
    const DWORD stage, const D3DTEXTURESTAGESTATETYPE type, const float value
  )
  {
    return SetTextureStageState(stage, type, std::bit_cast<DWORD>(value));
  }

  /**
   * Address: 0x00948420 (FUN_00948420)
   * Mangled: ?SetTexture@StateManagerD3D9@gal@gpg@@UAGJKPAVIDirect3DBaseTexture9@@@Z
   *
   * What it does:
   * Binds a texture straight to the device; textures are not cached.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTexture(const DWORD stage, IDirect3DBaseTexture9* const texture)
  {
    if (ProbeStateDiagArmed() && gProbeStateBudget > 0) { --gProbeStateBudget; gpg::Warnf("[STATEDIAG] TEX stage=%u texture=%p", static_cast<unsigned>(stage), static_cast<void*>(texture)); } // TEMPORARY PROBE
    { // TEMPORARY PROBE (do not commit): surface SetTexture failures (foreign-device textures etc.)
      const HRESULT hrTex = device_->SetTexture(stage, texture);
      static int sFailBudget = 40;
      if (hrTex != 0 && sFailBudget > 0) { --sFailBudget; gpg::Warnf("[SETTEXFAIL] stage=%u texture=%p hr=%08lX device=%p", static_cast<unsigned>(stage), static_cast<void*>(texture), static_cast<long>(hrTex), static_cast<void*>(device_)); }
      return hrTex;
    }
  }

  /**
   * Address: 0x00948550 (FUN_00948550)
   *
   * What it does:
   * Sets the N-patch segment count on the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetNPatchMode(const FLOAT numSegments)
  {
    return device_->SetNPatchMode(numSegments);
  }

  /**
   * Address: 0x00948440 (FUN_00948440)
   * Mangled: ?SetVertexShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DVertexShader9@@@Z
   *
   * What it does:
   * Binds a vertex shader unless it is already the active one.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShader(IDirect3DVertexShader9* const shader)
  {
    if (activeVertexShader_ == shader)
    {
      return S_OK;
    }

    activeVertexShader_ = shader;
    return device_->SetVertexShader(shader);
  }

  /**
   * Address: 0x00948570 (FUN_00948570)
   *
   * What it does:
   * Uploads float4 vertex-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantF(
    const UINT registerIndex, const FLOAT* const constantData, const UINT registerCount
  )
  {
    return device_->SetVertexShaderConstantF(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x00948590 (FUN_00948590)
   *
   * What it does:
   * Uploads int4 vertex-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantI(
    const UINT registerIndex, const INT* const constantData, const UINT registerCount
  )
  {
    return device_->SetVertexShaderConstantI(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x009485B0 (FUN_009485B0)
   *
   * What it does:
   * Uploads boolean vertex-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantB(
    const UINT registerIndex, const BOOL* const constantData, const UINT registerCount
  )
  {
    return device_->SetVertexShaderConstantB(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x00948470 (FUN_00948470)
   * Mangled: ?SetPixelShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DPixelShader9@@@Z
   *
   * What it does:
   * Binds a pixel shader unless it is already the active one.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShader(IDirect3DPixelShader9* const shader)
  {
    if (activePixelShader_ == shader)
    {
      return S_OK;
    }

    activePixelShader_ = shader;
    return device_->SetPixelShader(shader);
  }

  /**
   * Address: 0x009485D0 (FUN_009485D0)
   *
   * What it does:
   * Uploads float4 pixel-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantF(
    const UINT registerIndex, const FLOAT* const constantData, const UINT registerCount
  )
  {
    return device_->SetPixelShaderConstantF(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x009485F0 (FUN_009485F0)
   *
   * What it does:
   * Uploads int4 pixel-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantI(
    const UINT registerIndex, const INT* const constantData, const UINT registerCount
  )
  {
    return device_->SetPixelShaderConstantI(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x00948610 (FUN_00948610)
   *
   * What it does:
   * Uploads boolean pixel-shader constants.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantB(
    const UINT registerIndex, const BOOL* const constantData, const UINT registerCount
  )
  {
    return device_->SetPixelShaderConstantB(registerIndex, constantData, registerCount);
  }

  /**
   * Address: 0x009484A0 (FUN_009484A0)
   * Mangled: ?SetFVF@StateManagerD3D9@gal@gpg@@UAGJK@Z
   *
   * What it does:
   * Sets the FVF unless it is already the active one.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetFVF(const DWORD fvf)
  {
    if (activeFvf_ == fvf)
    {
      return S_OK;
    }

    activeFvf_ = fvf;
    return device_->SetFVF(fvf);
  }

  /**
   * Address: 0x009484D0 (FUN_009484D0)
   * Mangled: ?SetTransform@StateManagerD3D9@gal@gpg@@UAGJW4_D3DTRANSFORMSTATETYPE@@PBV_D3DMATRIX@@@Z
   *
   * What it does:
   * Sets a transform on the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTransform(const D3DTRANSFORMSTATETYPE state, const D3DMATRIX* const matrix)
  {
    return device_->SetTransform(state, matrix);
  }

  /**
   * Address: 0x009484F0 (FUN_009484F0)
   * Mangled: ?SetMaterial@StateManagerD3D9@gal@gpg@@UAGJPBV_D3DMATERIAL9@@@Z
   *
   * What it does:
   * Sets the material on the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetMaterial(const D3DMATERIAL9* const material)
  {
    return device_->SetMaterial(material);
  }

  /**
   * Address: 0x00948510 (FUN_00948510)
   * Mangled: ?SetLight@StateManagerD3D9@gal@gpg@@UAGJKPBV_D3DLIGHT9@@@Z
   *
   * What it does:
   * Sets one light on the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetLight(const DWORD index, const D3DLIGHT9* const light)
  {
    return device_->SetLight(index, light);
  }

  /**
   * Address: 0x00948530 (FUN_00948530)
   * Mangled: ?LightEnable@StateManagerD3D9@gal@gpg@@UAGJKH@Z
   *
   * What it does:
   * Enables or disables one light on the device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::LightEnable(const DWORD index, const BOOL enable)
  {
    return device_->LightEnable(index, enable);
  }

  /**
   * Address: 0x00949EB0 (FUN_00949EB0)
   * Address: 0x00949F60 (FUN_00949F60, scalar deleting destructor)
   * Mangled: ??_GStateManagerD3D9@gal@gpg@@UAEPAXI@Z
   *
   * What it does:
   * Destroys the caches: the texture-stage and sampler arrays through
   * `eh vector destructor iterator`, then the render-state cache.
   */
  StateManagerD3D9::~StateManagerD3D9() = default;
} // namespace gpg::gal
