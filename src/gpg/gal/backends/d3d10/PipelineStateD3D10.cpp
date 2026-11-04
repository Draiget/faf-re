#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    [[noreturn]] void ThrowPipelineStateD3D10Hresult(const int line, const HRESULT code)
    {
      throw Error(MakeShortString("PipelineStateD3D10.cpp"), line, MakeD3DErrorString(code));
    }
}


  /**
   * Address: 0x00902CA0 (FUN_00902CA0)
   *
   * ID3D10Device *
   *
   * What it does:
   * Initializes one pipeline-state bundle from a native D3D10 device and
   * builds both recovered startup state packs.
   */
  PipelineStateD3D10::PipelineStateD3D10(ID3D10Device* const device)
    : device_(device)
    , samplerFilterToken_(15U)
    , rasterizerState1_(nullptr)
    , depthStencilState1_(nullptr)
    , blendState1_(nullptr)
    , samplerState1_(nullptr)
    , rasterizerState2_(nullptr)
    , depthStencilState2_(nullptr)
    , blendState2_(nullptr)
  {
    if (device_ != nullptr) {
      device_->AddRef();
    }
    CreateState1();
    CreateState2();
  }
namespace
{

    /**
     * The depth-stencil state both packs create, differing only in
     * `depthFunc`: depth test and writes on, stencil off with zero masks.
     */
    [[nodiscard]] D3D10_DEPTH_STENCIL_DESC DepthWriteDesc(const D3D10_COMPARISON_FUNC depthFunc)
    {
      D3D10_DEPTH_STENCIL_DESC depthStencilDesc{};
      depthStencilDesc.DepthEnable = TRUE;
      depthStencilDesc.DepthWriteMask = D3D10_DEPTH_WRITE_MASK_ALL;
      depthStencilDesc.DepthFunc = depthFunc;
      depthStencilDesc.StencilEnable = FALSE;
      depthStencilDesc.StencilReadMask = 0U;
      depthStencilDesc.StencilWriteMask = 0U;
      depthStencilDesc.FrontFace.StencilFailOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilDepthFailOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilPassOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilFunc = D3D10_COMPARISON_ALWAYS;
      depthStencilDesc.BackFace = depthStencilDesc.FrontFace;
      return depthStencilDesc;
    }
}


  /**
   * Address: 0x009024F0 (FUN_009024F0)
   *
   * What it does:
   * Creates the pack `SetDeviceState` binds at start-up: solid, no culling,
   * counter-clockwise front faces, no depth clipping; depth writes with an
   * ALWAYS test; opaque blending; and a linear-min/mag, point-mip wrapping
   * sampler (MaxAnisotropy 1, ALWAYS comparison, black border, full LOD
   * range).
   */
  void PipelineStateD3D10::CreateState1()
  {
    D3D10_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D10_FILL_SOLID;
    rasterizerDesc.CullMode = D3D10_CULL_NONE;
    rasterizerDesc.FrontCounterClockwise = TRUE;
    rasterizerDesc.DepthBias = 0;
    rasterizerDesc.DepthBiasClamp = 0.0f;
    rasterizerDesc.SlopeScaledDepthBias = 0.0f;
    rasterizerDesc.DepthClipEnable = FALSE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState1_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(248, createRasterizerResult);
    }

    const D3D10_DEPTH_STENCIL_DESC depthStencilDesc = DepthWriteDesc(D3D10_COMPARISON_ALWAYS);
    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState1_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(251, createDepthStencilResult);
    }

    const D3D10_BLEND_DESC blendDesc = OpaqueBlendDesc();
    const HRESULT createBlendResult = device_->CreateBlendState(&blendDesc, &blendState1_);
    if (createBlendResult < 0) {
      ThrowPipelineStateD3D10Hresult(254, createBlendResult);
    }

    D3D10_SAMPLER_DESC samplerDesc{};
    samplerDesc.Filter = D3D10_FILTER_MIN_MAG_LINEAR_MIP_POINT;
    samplerDesc.AddressU = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressV = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressW = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.MipLODBias = 0.0f;
    samplerDesc.MaxAnisotropy = 1U;
    samplerDesc.ComparisonFunc = D3D10_COMPARISON_ALWAYS;
    samplerDesc.MinLOD = 0.0f;
    samplerDesc.MaxLOD = D3D10_FLOAT32_MAX;

    const HRESULT createSamplerResult = device_->CreateSamplerState(&samplerDesc, &samplerState1_);
    if (createSamplerResult < 0) {
      ThrowPipelineStateD3D10Hresult(257, createSamplerResult);
    }
  }

  /**
   * Address: 0x00902940 (FUN_00902940)
   *
   * What it does:
   * Creates the pack every effect technique begins with (`BeginTechnique`):
   * solid, back faces culled with clockwise fronts, no depth clipping; depth
   * writes with a LESS_EQUAL test; opaque blending.
   */
  void PipelineStateD3D10::CreateState2()
  {
    D3D10_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D10_FILL_SOLID;
    rasterizerDesc.CullMode = D3D10_CULL_BACK;
    rasterizerDesc.FrontCounterClockwise = FALSE;
    rasterizerDesc.DepthBias = 0;
    rasterizerDesc.DepthBiasClamp = 0.0f;
    rasterizerDesc.SlopeScaledDepthBias = 0.0f;
    rasterizerDesc.DepthClipEnable = FALSE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState2_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(321, createRasterizerResult);
    }

    const D3D10_DEPTH_STENCIL_DESC depthStencilDesc = DepthWriteDesc(D3D10_COMPARISON_LESS_EQUAL);
    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState2_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(324, createDepthStencilResult);
    }

    const D3D10_BLEND_DESC blendDesc = OpaqueBlendDesc();
    const HRESULT createBlendResult = device_->CreateBlendState(&blendDesc, &blendState2_);
    if (createBlendResult < 0) {
      ThrowPipelineStateD3D10Hresult(327, createBlendResult);
    }
  }

  /**
   * Address: 0x00902250 (FUN_00902250)
   *
   * What it does:
   * Applies the primary recovered pipeline-state pack onto the native
   * D3D10 device.
   */
  void PipelineStateD3D10::SetDeviceState()
  {
    device_->RSSetState(rasterizerState1_);
    device_->OMSetDepthStencilState(depthStencilState1_, 0U);
    device_->OMSetBlendState(blendState1_, nullptr, 0xFFFFFFFFU);

    ID3D10SamplerState* samplerState = samplerState1_;
    for (UINT slot = 0U; slot < 16U; ++slot) {
      device_->PSSetSamplers(slot, 1U, &samplerState);
    }
  }

  /**
   * Address: 0x009022E0 (FUN_009022E0)
   *
   * What it does:
   * Unbinds all 128 pixel-shader resource slots, one call per slot. Formerly
   * the free `ClearAllTextureShaderResourceSlots`, which returned the last
   * call's value - `PSSetShaderResources` returns nothing.
   */
  void PipelineStateD3D10::ClearTextures()
  {
    ID3D10ShaderResourceView* const noView = nullptr;
    for (UINT slot = 0U; slot < D3D10_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT; ++slot) {
      device_->PSSetShaderResources(slot, 1U, &noView);
    }
  }

  /**
   * Address: 0x00902320 (FUN_00902320)
   *
   * What it does:
   * Binds the secondary state pack. Formerly the free
   * `ApplyTechniqueStateBindings` over three hand-indexed vtable calls.
   */
  void PipelineStateD3D10::BeginTechnique()
  {
    device_->RSSetState(rasterizerState2_);
    device_->OMSetDepthStencilState(depthStencilState2_, 0U);
    device_->OMSetBlendState(blendState2_, nullptr, 0xFFFFFFFFU);
  }

  /**
   * Address: 0x00902360 (FUN_00902360)
   *
   * What it does:
   * Nothing. Formerly `nullsub_3640`.
   */
  void PipelineStateD3D10::EndTechnique() {}

  /**
   * Address: 0x009023F0 (FUN_009023F0)
   * Address: 0x009024D0 (FUN_009024D0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device and both state packs, then the `PipelineState` base
   * destructor runs (inlined, 0x009024B0).
   */
  PipelineStateD3D10::~PipelineStateD3D10()
  {
    SafeRelease(device_);
    SafeRelease(rasterizerState1_);
    SafeRelease(depthStencilState1_);
    SafeRelease(blendState1_);
    SafeRelease(samplerState1_);
    SafeRelease(rasterizerState2_);
    SafeRelease(depthStencilState2_);
    SafeRelease(blendState2_);
  }
}

