// Engine addition, not in the shipped binary (see MsdfTextGpuRenderer.h).

#include "moho/render/font/MsdfTextGpuRenderer.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Texture.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/GpuPathSettings.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace moho
{
  int ren_GpuText = -1;
  bool ren_GpuUiQuads = true;
  bool gMsdfTextPending = false;

  TConVar<int> gTConVar_ren_GpuText(
    "ren_GpuText",
    "Draw MSDF text with instanced draws from a GPU buffer instead of the prim batcher. -1 (auto, the default) "
    "turns it on where the backend has verified this path, 1 wherever it can, 0 never.",
    &ren_GpuText
  );
  TConVar<bool> gTConVar_ren_GpuUiQuads(
    "ren_GpuUiQuads",
    "With ren_GpuText, the interface's image quads join the text's instanced draw (1, the default), so a pass of the "
    "interface is one draw; 0 sends them through the prim batcher, and each change between text and images is a draw.",
    &ren_GpuUiQuads
  );

  namespace
  {
    constexpr std::uint32_t kVerticesPerQuad = 6u;
    // A ring of quads: each upload goes after the last one, so a range the GPU may still read isn't
    // overwritten until the ring comes around. 6 MB; a screen of interface is a few thousand quads.
    constexpr std::uint32_t kBufferQuads = 65536u;
    constexpr std::size_t kMaxPendingQuads = 16384u;
    constexpr const char* kUiTechnique = "TAlphaBlendLinearSampleNoDepth";

    // TAlphaBlendLinearSampleNoDepth's pass: src-alpha/inv-src-alpha into RGB, no depth, no culling and
    // D3D9's alpha test.
    constexpr char kMsdfTextShaderSource[] = R"hlsl(
cbuffer MsdfTextConstants : register(b0)
{
    row_major float4x4 Composite; // CD3DPrimBatcher's view * projection
    float AlphaMultiplier;        // the batcher's alpha multiplier
    uint FirstInstance;           // where this draw's quads start: SV_InstanceID doesn't count a start offset
    float2 Unused;
};

struct QuadInstance
{
    float x[4];
    float y[4];
    float u[4];
    float v[4];
    uint color[4]; // ARGB
    float z;
    float pixelRange; // screen pixels covered by the distance range; 0 for an image quad
    float2 unused;
};

StructuredBuffer<QuadInstance> Instances : register(t0);
Texture2D MsdfPage : register(t4);
Texture2D ImageAtlas : register(t5);
SamplerState LinearSampler : register(s0);

struct QuadVertex
{
    float4 position : SV_Position;
    float4 color : COLOR0;
    float2 uv : TEXCOORD0;
    float pixelRange : TEXCOORD1;
};

QuadVertex MsdfTextVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID)
{
    // DrawQuad's two triangles: corners 0,1,2 and 2,3,0.
    static const uint kCornerOfVertex[6] = { 0, 1, 2, 2, 3, 0 };

    QuadInstance quad = Instances[instanceId + FirstInstance];
    uint corner = kCornerOfVertex[vertexId];
    uint color = quad.color[corner];

    QuadVertex output;
    output.position = mul(float4(quad.x[corner], quad.y[corner], quad.z, 1.0), Composite);
    output.color = float4((color >> 16) & 255, (color >> 8) & 255, color & 255, color >> 24) / 255.0;
    output.uv = float2(quad.u[corner], quad.v[corner]);
    output.pixelRange = quad.pixelRange;
    return output;
}

float4 MsdfTextPS(QuadVertex input) : SV_Target
{
    float4 image = ImageAtlas.Sample(LinearSampler, input.uv);
    float3 field = MsdfPage.Sample(LinearSampler, input.uv).rgb;
    float median = max(min(field.r, field.g), min(max(field.r, field.g), field.b));
    float4 color = input.color;
    if (input.pixelRange > 0.0)
    {
        color.a *= saturate(input.pixelRange * (median - 0.5) + 0.5);
    }
    else
    {
        color *= image;
    }
    color.a *= AlphaMultiplier;
    // D3D9 alpha test, AlphaFunc Greater, AlphaRef 0, on the 8-bit alpha.
    if ((uint)round(saturate(color.a) * 255.0) <= 0u)
    {
        discard;
    }
    return color;
}
)hlsl";

    struct DrawConstants
    {
      VMatrix4 composite;
      float alphaMultiplier;
      std::uint32_t firstInstance;
      float unused[2];
    };
    static_assert(sizeof(DrawConstants) % 16 == 0, "constant blocks are whole float4s");

    gpg::gal::Device* sDeviceOfResources = nullptr;
  } // namespace

  MsdfTextGpuRenderer& MsdfTextGpuRenderer::Get()
  {
    static MsdfTextGpuRenderer sRenderer;
    return sRenderer;
  }

  bool MsdfTextGpuRenderer::IsActive()
  {
    if (!GpuPathEnabled(ren_GpuText, gpg::gal::kGpuPathMsdfText, gpg::gal::kGpuFeatureVertexPulling)) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (mInitialized && device != sDeviceOfResources) {
      // A new device: everything built on the old one is gone, and so is what was pending.
      *this = MsdfTextGpuRenderer();
      gMsdfTextPending = false;
    }
    if (!mInitialized) {
      mInitialized = true;
      sDeviceOfResources = device;
      if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) != 0u) {
        gpg::gal::GpuProgramDesc desc{};
        desc.name = "MsdfText";
        desc.source = kMsdfTextShaderSource;
        desc.sourceBytes = sizeof(kMsdfTextShaderSource) - 1u;
        desc.vertexEntry = "MsdfTextVS";
        desc.pixelEntry = "MsdfTextPS";
        desc.blend = gpg::gal::GpuBlend::AlphaBlend;
        desc.colorWriteMask = 0x07u;
        desc.depthTest = false;
        desc.depthWrite = false;
        desc.cullBackFaces = false;
        desc.sampler = gpg::gal::GpuSampler::LinearClamp;
        mProgram = device->CreateGpuProgram(desc);

        gpg::gal::GpuBufferDesc bufferDesc{};
        bufferDesc.name = "MsdfUiQuads";
        bufferDesc.stride = sizeof(MsdfUiQuad);
        bufferDesc.capacity = kBufferQuads;
        mBuffer = device->CreateGpuBuffer(bufferDesc);
      }
      mSupported = mProgram != nullptr && mBuffer != nullptr;
      if (mSupported) {
        gpg::Logf("MSDF text: GPU-instanced path (ren_GpuText)");
      }
    }
    return mSupported;
  }

  void MsdfTextGpuRenderer::PrepareFor(CD3DPrimBatcher& batcher)
  {
    if (!mPending.empty() && (mBatcher != &batcher || mAlphaMultiplier != batcher.mAlphaMultiplier)) {
      Flush();
    }
    if (mPending.empty()) {
      // The batcher's matrix setters flush what's pending, so these hold for everything added until then.
      mBatcher = &batcher;
      mComposite = VMatrix4::Multiply(batcher.mViewMatrix, batcher.mProjectionMatrix);
      mAlphaMultiplier = batcher.mAlphaMultiplier;
    }
  }

  void MsdfTextGpuRenderer::Push(const MsdfUiQuad& quad)
  {
    if (mPending.size() >= kMaxPendingQuads) {
      Flush();
    }
    mPending.push_back(quad);
    gMsdfTextPending = true;
  }

  bool MsdfTextGpuRenderer::BeginString(CD3DPrimBatcher& batcher, const boost::shared_ptr<CD3DDynamicTextureSheet>& page)
  {
    ID3DTextureSheet::TextureHandle texture;
    (void)page->GetTexture(texture);
    if (texture.get() == nullptr) {
      return false;
    }

    // Quads in the batcher came after the pending ones, and its Flush draws those first. With no quads
    // the pending ones stay, so neighbouring strings merge.
    if (!batcher.mVertices.empty()) {
      batcher.Flush();
    }
    if (mPage.get() != texture.get()) {
      Flush(); // a device reset made a new page
      mPage = texture;
    }
    PrepareFor(batcher);
    return true;
  }

  void MsdfTextGpuRenderer::AddGlyph(const MsdfUiQuad& glyph)
  {
    Push(glyph);
  }

  bool MsdfTextGpuRenderer::QueueImageQuad(
    CD3DPrimBatcher& batcher, const CD3DPrimBatcher::Vertex& topLeft, const CD3DPrimBatcher::Vertex& topRight,
    const CD3DPrimBatcher::Vertex& bottomRight, const CD3DPrimBatcher::Vertex& bottomLeft
  )
  {
    if (!ren_GpuUiQuads) {
      return false;
    }
    CD3DDevice* const device = D3D_GetDevice();
    CD3DEffect* const effect = device != nullptr ? device->GetCurEffect() : nullptr;
    if (effect == nullptr) {
      return false;
    }
    if (mCheckedTechnique.get() != effect->mCurrentTechnique.get()) {
      mCheckedTechnique = effect->mCurrentTechnique;
      mCheckedTechniqueAllowsQuads = mCheckedTechnique && IsActive() && std::strcmp(effect->mName.c_str(), "primbatcher") == 0
        && std::strcmp(mCheckedTechnique->GetName()->c_str(), kUiTechnique) == 0;
    }
    if (!mCheckedTechniqueAllowsQuads) {
      return false;
    }

    PrepareFor(batcher);
    MsdfUiQuad quad;
    const CD3DPrimBatcher::Vertex* const corners[4] = {&topLeft, &topRight, &bottomRight, &bottomLeft};
    for (int corner = 0; corner < 4; ++corner) {
      const CD3DPrimBatcher::Vertex& vertex = *corners[corner];
      quad.mX[corner] = vertex.mX;
      quad.mY[corner] = vertex.mY;
      quad.mU[corner] = batcher.mP2x + batcher.mP1x * vertex.mU;
      quad.mV[corner] = batcher.mP2y + batcher.mP1y * vertex.mV;
      quad.mColor[corner] = vertex.mColor;
    }
    quad.mZ = topLeft.mZ;
    Push(quad);
    return true;
  }

  void MsdfTextGpuRenderer::Flush()
  {
    gMsdfTextPending = false;
    if (mPending.empty()) {
      return;
    }
    const auto count = static_cast<std::uint32_t>(mPending.size());
    if (mNextQuad + count > kBufferQuads) {
      mNextQuad = 0u;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    device->UpdateGpuBuffer(*mBuffer, mNextQuad, count, mPending.data());

    // The prim batcher's atlas, with what was added to it since its last upload.
    ID3DTextureSheet::TextureHandle imageAtlas;
    if (mBatcher != nullptr && mBatcher->mTextureBatcher != nullptr) {
      const boost::shared_ptr<ID3DTextureSheet> sheet = mBatcher->mTextureBatcher->GetCompositeTexture();
      if (sheet) {
        (void)sheet->GetTexture(imageAtlas);
      }
    }

    DrawConstants constants{};
    constants.composite = mComposite;
    constants.alphaMultiplier = mAlphaMultiplier;
    constants.firstInstance = mNextQuad;

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = mBuffer.get();
    // Both slots hold something: a frame can have no text yet, or no image yet.
    call.bindings.textures[0] = mPage ? mPage.get() : imageAtlas.get();
    call.bindings.textures[1] = imageAtlas ? imageAtlas.get() : mPage.get();
    call.vertexCountPerInstance = kVerticesPerQuad;
    call.instanceCount = count;
    device->DrawGpuProgram(call);

    mNextQuad += count;
    mPending.clear();
  }

  void MSDF_FlushPendingTextSlow()
  {
    MsdfTextGpuRenderer::Get().Flush();
  }
} // namespace moho
