#include "StateManagerD3D9.hpp"

#include <bit>
#include <mutex>
#include <type_traits>
#include <Unknwn.h>
#include <unordered_map>

namespace gpg::gal
{
  namespace
  {
    constexpr GUID kStateManagerD3D9InterfaceId = {
      0x79AAB587, 0x6DBC, 0x4FA7, {0x82, 0xDE, 0x37, 0xFA, 0x17, 0x81, 0xC5, 0xCE}
    };

    struct EnumHash
    {
      template <typename EnumT>
      std::size_t operator()(const EnumT value) const noexcept
      {
        using underlying_t = std::underlying_type_t<EnumT>;
        return static_cast<std::size_t>(static_cast<underlying_t>(value));
      }
    };

    struct StateManagerRuntimeCache
    {
      std::unordered_map<d3d9::RenderState, unsigned int, EnumHash> renderStateValues;
      std::unordered_map<d3d9::SamplerState, unsigned int, EnumHash> samplerValues[16];
      std::unordered_map<d3d9::TextureStageState, unsigned int, EnumHash> textureStageValues[8];
    };

    std::mutex gStateManagerCacheMutex;
    std::unordered_map<const StateManagerD3D9*, StateManagerRuntimeCache> gStateManagerCaches;

    template <typename MapT, typename KeyT, typename ValueT>
    bool CacheValue(MapT& map, const KeyT key, const ValueT value)
    {
      const auto it = map.find(key);
      if (it != map.end() && it->second == value) {
        return false;
      }

      map[key] = value;
      return true;
    }

    HRESULT InvokeSetRenderState(void* const device, const d3d9::RenderState state, const unsigned int value)
    {
      using set_render_state_fn = HRESULT(STDMETHODCALLTYPE*)(void*, d3d9::RenderState, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_render_state_fn>(vtable[0xE4 / sizeof(void*)]);
      return fn(device, state, value);
    }

    HRESULT InvokeSetSamplerState(
      void* const device, const unsigned int samplerIndex, const d3d9::SamplerState state, const unsigned int value
    )
    {
      using set_sampler_state_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, d3d9::SamplerState, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_sampler_state_fn>(vtable[0x114 / sizeof(void*)]);
      return fn(device, samplerIndex, state, value);
    }

    HRESULT InvokeSetTextureStageState(
      void* const device, const unsigned int stageIndex, const d3d9::TextureStageState state, const unsigned int value
    )
    {
      using set_texture_stage_state_fn =
        HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, d3d9::TextureStageState, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_texture_stage_state_fn>(vtable[0x10C / sizeof(void*)]);
      return fn(device, stageIndex, state, value);
    }

    HRESULT InvokeSetTexture(void* const device, const unsigned int stageIndex, void* const texture)
    {
      using set_texture_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_texture_fn>(vtable[0x104 / sizeof(void*)]);
      return fn(device, stageIndex, texture);
    }

    HRESULT InvokeSetTransform(void* const device, const unsigned int transformState, const void* const matrix)
    {
      using set_transform_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_transform_fn>(vtable[0xB0 / sizeof(void*)]);
      return fn(device, transformState, matrix);
    }

    HRESULT InvokeSetMaterial(void* const device, const void* const material)
    {
      using set_material_fn = HRESULT(STDMETHODCALLTYPE*)(void*, const void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_material_fn>(vtable[0xC4 / sizeof(void*)]);
      return fn(device, material);
    }

    HRESULT InvokeSetLight(void* const device, const unsigned int lightIndex, const void* const light)
    {
      using set_light_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_light_fn>(vtable[0xCC / sizeof(void*)]);
      return fn(device, lightIndex, light);
    }

    HRESULT InvokeLightEnable(void* const device, const unsigned int lightIndex, const int enabled)
    {
      using light_enable_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<light_enable_fn>(vtable[0xD4 / sizeof(void*)]);
      return fn(device, lightIndex, enabled);
    }

    HRESULT InvokeSetNPatchMode(void* const device, const float nPatchSegments)
    {
      using set_npatch_mode_fn = HRESULT(STDMETHODCALLTYPE*)(void*, float);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_npatch_mode_fn>(vtable[0x13C / sizeof(void*)]);
      return fn(device, nPatchSegments);
    }

    HRESULT InvokeSetFVF(void* const device, const unsigned int fvf)
    {
      using set_fvf_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_fvf_fn>(vtable[0x164 / sizeof(void*)]);
      return fn(device, fvf);
    }

    HRESULT InvokeSetVertexShader(void* const device, void* const vertexShader)
    {
      using set_vertex_shader_fn = HRESULT(STDMETHODCALLTYPE*)(void*, void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_vertex_shader_fn>(vtable[0x170 / sizeof(void*)]);
      return fn(device, vertexShader);
    }

    HRESULT InvokeSetVertexShaderConstantF(
      void* const device,
      const unsigned int startRegister,
      const float* const constants,
      const unsigned int vector4Count
    )
    {
      using set_vertex_shader_constant_f_fn =
        HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const float*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_vertex_shader_constant_f_fn>(vtable[0x178 / sizeof(void*)]);
      return fn(device, startRegister, constants, vector4Count);
    }

    HRESULT InvokeSetVertexShaderConstantI(
      void* const device, const unsigned int startRegister, const int* const constants, const unsigned int vector4Count
    )
    {
      using set_vertex_shader_constant_i_fn =
        HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const int*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_vertex_shader_constant_i_fn>(vtable[0x180 / sizeof(void*)]);
      return fn(device, startRegister, constants, vector4Count);
    }

    HRESULT InvokeSetVertexShaderConstantB(
      void* const device, const unsigned int startRegister, const int* const constants, const unsigned int boolCount
    )
    {
      using set_vertex_shader_constant_b_fn =
        HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const int*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_vertex_shader_constant_b_fn>(vtable[0x188 / sizeof(void*)]);
      return fn(device, startRegister, constants, boolCount);
    }

    HRESULT InvokeSetPixelShader(void* const device, void* const pixelShader)
    {
      using set_pixel_shader_fn = HRESULT(STDMETHODCALLTYPE*)(void*, void*);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_pixel_shader_fn>(vtable[0x1AC / sizeof(void*)]);
      return fn(device, pixelShader);
    }

    HRESULT InvokeSetPixelShaderConstantF(
      void* const device,
      const unsigned int startRegister,
      const float* const constants,
      const unsigned int vector4Count
    )
    {
      using set_pixel_shader_constant_f_fn =
        HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const float*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_pixel_shader_constant_f_fn>(vtable[0x1B4 / sizeof(void*)]);
      return fn(device, startRegister, constants, vector4Count);
    }

    HRESULT InvokeSetPixelShaderConstantI(
      void* const device, const unsigned int startRegister, const int* const constants, const unsigned int vector4Count
    )
    {
      using set_pixel_shader_constant_i_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const int*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_pixel_shader_constant_i_fn>(vtable[0x1BC / sizeof(void*)]);
      return fn(device, startRegister, constants, vector4Count);
    }

    HRESULT InvokeSetPixelShaderConstantB(
      void* const device, const unsigned int startRegister, const int* const constants, const unsigned int boolCount
    )
    {
      using set_pixel_shader_constant_b_fn = HRESULT(STDMETHODCALLTYPE*)(void*, unsigned int, const int*, unsigned int);
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const fn = reinterpret_cast<set_pixel_shader_constant_b_fn>(vtable[0x1C4 / sizeof(void*)]);
      return fn(device, startRegister, constants, boolCount);
    }

    /**
     * Address: 0x00949EB0 (FUN_00949EB0)
     *
     * What it does:
     * Teardown helper used by the deleting-dtor path to clear sidecar runtime
     * cache state owned by this lifted translation unit.
     */
    void DestroyStateManagerD3D9Body(StateManagerD3D9* const stateManager)
    {
      std::lock_guard<std::mutex> lock(gStateManagerCacheMutex);
      gStateManagerCaches.erase(stateManager);
    }
  } // namespace

  /**
   * Address: 0x00948280 (FUN_00948280)
   *
   * What it does:
   * Initializes state-manager bookkeeping and binds the native D3D9 device lane.
   */
  StateManagerD3D9::StateManagerD3D9(void* const device) :
    uses_(0),
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
   * Returns `this` for supported IIDs and increments refcount.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::QueryInterface(REFIID riid, void** outObject)
  {
    if (InlineIsEqualGUID(riid, IID_IUnknown) || InlineIsEqualGUID(riid, kStateManagerD3D9InterfaceId)) {
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
    if (remaining != 0) {
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
   * Emits a D3D render-state update only when cached value changes.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetRenderState(const render_state_type state, const unsigned int value)
  {
    bool changed = false;
    {
      std::lock_guard<std::mutex> lock(gStateManagerCacheMutex);
      changed = CacheValue(gStateManagerCaches[this].renderStateValues, state, value);
    }

    if (!changed) {
      return S_OK;
    }

    return InvokeSetRenderState(device_, state, value);
  }

  /**
   * Address: 0x00948400 (FUN_00948400)
   * Mangled: ?SetRenderStateFlt@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@M@Z
   *
   * What it does:
   * Reuses SetRenderState with float payload bit-preserved as DWORD.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetRenderStateFlt(const render_state_type state, const float value)
  {
    return SetRenderState(state, std::bit_cast<unsigned int>(value));
  }

  /**
   * Address: 0x00949DF0 (FUN_00949DF0)
   * Mangled: ?SetSamplerState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DSAMPLERSTATETYPE@@K@Z
   *
   * What it does:
   * Uses per-sampler cache for samplers [0,15] before forwarding to D3D9.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetSamplerState(
    const unsigned int samplerIndex, const sampler_state_type state, const unsigned int value
  )
  {
    bool changed = true;
    if (samplerIndex < 16) {
      std::lock_guard<std::mutex> lock(gStateManagerCacheMutex);
      changed = CacheValue(gStateManagerCaches[this].samplerValues[samplerIndex], state, value);
    }

    if (!changed) {
      return S_OK;
    }

    return InvokeSetSamplerState(device_, samplerIndex, state, value);
  }

  /**
   * Address: 0x00949E50 (FUN_00949E50)
   * Mangled: ?SetTextureStageState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@K@Z
   *
   * What it does:
   * Uses per-stage cache for stages [0,7] before forwarding to D3D9.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTextureStageState(
    const unsigned int stageIndex, const texture_stage_state_type state, const unsigned int value
  )
  {
    bool changed = true;
    if (stageIndex < 8) {
      std::lock_guard<std::mutex> lock(gStateManagerCacheMutex);
      changed = CacheValue(gStateManagerCaches[this].textureStageValues[stageIndex], state, value);
    }

    if (!changed) {
      return S_OK;
    }

    return InvokeSetTextureStageState(device_, stageIndex, state, value);
  }

  /**
   * Address: 0x00948410 (FUN_00948410)
   * Mangled: ?SetTextureStageStateFlt@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@M@Z
   *
   * What it does:
   * Reuses SetTextureStageState with float payload bit-preserved as DWORD.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTextureStageStateFlt(
    const unsigned int stageIndex, const texture_stage_state_type state, const float value
  )
  {
    return SetTextureStageState(stageIndex, state, std::bit_cast<unsigned int>(value));
  }

  /**
   * Address: 0x00948420 (FUN_00948420)
   * Mangled: ?SetTexture@StateManagerD3D9@gal@gpg@@UAGJKPAVIDirect3DBaseTexture9@@@Z
   *
   * What it does:
   * Forwards stage texture binding directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTexture(const unsigned int stageIndex, void* const texture)
  {
    return InvokeSetTexture(device_, stageIndex, texture);
  }

  /**
   * Address: 0x00948550 (FUN_00948550)
   *
   * What it does:
   * Forwards N-patch tessellation mode directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetNPatchMode(const float nPatchSegments)
  {
    return InvokeSetNPatchMode(device_, nPatchSegments);
  }

  /**
   * Address: 0x00948440 (FUN_00948440)
   * Mangled: ?SetVertexShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DVertexShader9@@@Z
   *
   * What it does:
   * Avoids redundant backend calls when vertex shader pointer is unchanged.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShader(void* const vertexShader)
  {
    if (activeVertexShader_ == vertexShader) {
      return S_OK;
    }

    activeVertexShader_ = vertexShader;
    return InvokeSetVertexShader(device_, vertexShader);
  }

  /**
   * Address: 0x00948570 (FUN_00948570)
   *
   * What it does:
   * Forwards float4 vertex-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantF(
    const unsigned int startRegister, const float* const constants, const unsigned int vector4Count
  )
  {
    return InvokeSetVertexShaderConstantF(device_, startRegister, constants, vector4Count);
  }

  /**
   * Address: 0x00948590 (FUN_00948590)
   *
   * What it does:
   * Forwards int4 vertex-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantI(
    const unsigned int startRegister, const int* const constants, const unsigned int vector4Count
  )
  {
    return InvokeSetVertexShaderConstantI(device_, startRegister, constants, vector4Count);
  }

  /**
   * Address: 0x009485B0 (FUN_009485B0)
   *
   * What it does:
   * Forwards boolean vertex-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetVertexShaderConstantB(
    const unsigned int startRegister, const int* const constants, const unsigned int boolCount
  )
  {
    return InvokeSetVertexShaderConstantB(device_, startRegister, constants, boolCount);
  }

  /**
   * Address: 0x00948470 (FUN_00948470)
   * Mangled: ?SetPixelShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DPixelShader9@@@Z
   *
   * What it does:
   * Avoids redundant backend calls when pixel shader pointer is unchanged.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShader(void* const pixelShader)
  {
    if (activePixelShader_ == pixelShader) {
      return S_OK;
    }

    activePixelShader_ = pixelShader;
    return InvokeSetPixelShader(device_, pixelShader);
  }

  /**
   * Address: 0x009485D0 (FUN_009485D0)
   *
   * What it does:
   * Forwards float4 pixel-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantF(
    const unsigned int startRegister, const float* const constants, const unsigned int vector4Count
  )
  {
    return InvokeSetPixelShaderConstantF(device_, startRegister, constants, vector4Count);
  }

  /**
   * Address: 0x009485F0 (FUN_009485F0)
   *
   * What it does:
   * Forwards int4 pixel-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantI(
    const unsigned int startRegister, const int* const constants, const unsigned int vector4Count
  )
  {
    return InvokeSetPixelShaderConstantI(device_, startRegister, constants, vector4Count);
  }

  /**
   * Address: 0x00948610 (FUN_00948610)
   *
   * What it does:
   * Forwards boolean pixel-shader constant uploads directly to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetPixelShaderConstantB(
    const unsigned int startRegister, const int* const constants, const unsigned int boolCount
  )
  {
    return InvokeSetPixelShaderConstantB(device_, startRegister, constants, boolCount);
  }

  /**
   * Address: 0x009484A0 (FUN_009484A0)
   * Mangled: ?SetFVF@StateManagerD3D9@gal@gpg@@UAGJK@Z
   *
   * What it does:
   * Avoids redundant backend calls when FVF is unchanged.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetFVF(const unsigned int fvf)
  {
    if (activeFvf_ == fvf) {
      return S_OK;
    }

    activeFvf_ = fvf;
    return InvokeSetFVF(device_, fvf);
  }

  /**
   * Address: 0x009484D0 (FUN_009484D0)
   * Mangled: ?SetTransform@StateManagerD3D9@gal@gpg@@UAGJW4_D3DTRANSFORMSTATETYPE@@PBV_D3DMATRIX@@@Z
   *
   * What it does:
   * Forwards transform state updates to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetTransform(const unsigned int transformState, const void* const matrix)
  {
    return InvokeSetTransform(device_, transformState, matrix);
  }

  /**
   * Address: 0x009484F0 (FUN_009484F0)
   * Mangled: ?SetMaterial@StateManagerD3D9@gal@gpg@@UAGJPBV_D3DMATERIAL9@@@Z
   *
   * What it does:
   * Forwards material updates to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetMaterial(const void* const material)
  {
    return InvokeSetMaterial(device_, material);
  }

  /**
   * Address: 0x00948510 (FUN_00948510)
   * Mangled: ?SetLight@StateManagerD3D9@gal@gpg@@UAGJKPBV_D3DLIGHT9@@@Z
   *
   * What it does:
   * Forwards indexed light updates to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::SetLight(const unsigned int lightIndex, const void* const light)
  {
    return InvokeSetLight(device_, lightIndex, light);
  }

  /**
   * Address: 0x00948530 (FUN_00948530)
   * Mangled: ?LightEnable@StateManagerD3D9@gal@gpg@@UAGJKH@Z
   *
   * What it does:
   * Forwards indexed light enable state to the backend device.
   */
  HRESULT STDMETHODCALLTYPE StateManagerD3D9::LightEnable(const unsigned int lightIndex, const int enabled)
  {
    return InvokeLightEnable(device_, lightIndex, enabled);
  }

  /**
   * Address: 0x00949F60 (FUN_00949F60)
   * Mangled: ??_GStateManagerD3D9@gal@gpg@@UAEPAXI@Z
   *
   * What it does:
   * Removes runtime cache sidecar state; member cache objects tear down via RAII.
   */
  StateManagerD3D9::~StateManagerD3D9()
  {
    DestroyStateManagerD3D9Body(this);
  }
} // namespace gpg::gal
