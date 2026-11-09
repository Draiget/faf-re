#include "editor/ui/EdImGuiRenderer.h"

#include <unordered_map>

#include <algorithm>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/Texture.hpp"
#include "gpg/gal/TextureContext.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    // gal's 32-bit BGRA texture format (DXGI_FORMAT_B8G8R8A8_UNORM, backends/dxgi/DxgiFormats.cpp).
    constexpr std::uint32_t kTextureFormatBgra8 = 2U;

    // Bindings follow gpg/gal/GpuDriven.h (b0, t0..t1, t4, s0), so DXC builds the same source
    // for Direct3D 12 (DXIL) and Vulkan (SPIR-V).
    constexpr char kImGuiShaderSource[] = R"hlsl(
cbuffer ImGuiConstants : register(b0)
{
    float4 ScaleTranslate; // ImGui pixels to clip space: xy scale, zw offset
    float4 ClipRect;       // the command's clip rectangle in ImGui pixels: min xy, max zw
    uint IndexOffset;      // the command's first index in Indices
    uint VertexOffset;     // added to each index
    uint2 Unused;
};

struct ImGuiVertex
{
    float2 position;
    float2 uv;
    uint color; // RGBA8, red in the low byte
};

StructuredBuffer<ImGuiVertex> Vertices : register(t0);
StructuredBuffer<uint> Indices : register(t1);
Texture2D Atlas : register(t4);
SamplerState LinearSampler : register(s0);

struct ImGuiPixel
{
    float4 position : SV_Position;
    float4 color : COLOR0;
    float2 uv : TEXCOORD0;
    float2 pixel : TEXCOORD1;
};

ImGuiPixel ImGuiVS(uint vertexId : SV_VertexID)
{
    ImGuiVertex vertex = Vertices[Indices[IndexOffset + vertexId] + VertexOffset];
    ImGuiPixel output;
    output.position = float4(vertex.position * ScaleTranslate.xy + ScaleTranslate.zw, 0.0, 1.0);
    output.color = float4(vertex.color & 0xFF, (vertex.color >> 8) & 0xFF, (vertex.color >> 16) & 0xFF, vertex.color >> 24) / 255.0;
    output.uv = vertex.uv;
    output.pixel = vertex.position;
    return output;
}

float4 ImGuiPS(ImGuiPixel input) : SV_Target
{
    if (input.pixel.x < ClipRect.x || input.pixel.y < ClipRect.y || input.pixel.x >= ClipRect.z || input.pixel.y >= ClipRect.w)
    {
        discard;
    }
    return input.color * Atlas.Sample(LinearSampler, input.uv);
}
)hlsl";

    struct DrawConstants
    {
      float scaleTranslate[4];
      float clipRect[4];
      std::uint32_t indexOffset;
      std::uint32_t vertexOffset;
      std::uint32_t unused[2];
    };
    static_assert(sizeof(DrawConstants) % 16U == 0U, "constant blocks are whole float4s");
    static_assert(sizeof(ImDrawVert) == 20U, "the shader's ImGuiVertex is 20 bytes");
    static_assert(sizeof(ImDrawIdx) == 4U, "the shader reads 32-bit indices (cmake/deps/imgui)");

    /** One texture ImGui asked for, kept in `ImTextureData::BackendUserData`. */
    struct TextureEntry
    {
      boost::shared_ptr<gpg::gal::Texture> texture;
    };

    /** Copies ImGui's RGBA pixels into the BGRA texture, the whole level. */
    void Upload(gpg::gal::Texture& texture, ImTextureData& source)
    {
      const RECT whole{};
      const gpg::gal::TextureLockRect lock = texture.Lock(0, whole, 0);
      for (int y = 0; y < source.Height; ++y) {
        const auto* const from = static_cast<const std::uint8_t*>(source.GetPixelsAt(0, y));
        auto* const to = static_cast<std::uint8_t*>(lock.bits) + static_cast<std::ptrdiff_t>(y) * lock.pitch;
        for (int x = 0; x < source.Width; ++x) {
          to[x * 4 + 0] = from[x * 4 + 2];
          to[x * 4 + 1] = from[x * 4 + 1];
          to[x * 4 + 2] = from[x * 4 + 0];
          to[x * 4 + 3] = from[x * 4 + 3];
        }
      }
      (void)texture.Unlock(0);
    }
    /** The editor's own images (CreateImage), by their ImTextureID. */
    std::unordered_map<std::uint64_t, boost::shared_ptr<gpg::gal::Texture>>& OwnImages()
    {
      static std::unordered_map<std::uint64_t, boost::shared_ptr<gpg::gal::Texture>> images;
      return images;
    }
  } // namespace

  std::uint64_t EdImGuiRenderer::CreateImage(const int width, const int height, const std::uint32_t* const bgra)
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr || width < 1 || height < 1 || bgra == nullptr) {
      return 0U;
    }
    gpg::gal::TextureContext context{};
    context.source_ = 2U;
    context.type_ = 1U;
    context.usage_ = 0U; // written once
    context.format_ = kTextureFormatBgra8;
    context.mipmapLevels_ = 1U;
    context.width_ = static_cast<std::uint32_t>(width);
    context.height_ = static_cast<std::uint32_t>(height);
    boost::shared_ptr<gpg::gal::Texture> texture = device->CreateTexture(&context);
    if (texture.get() == nullptr) {
      return 0U;
    }
    const RECT whole{};
    const gpg::gal::TextureLockRect lock = texture->Lock(0, whole, 0);
    for (int y = 0; y < height; ++y) {
      std::memcpy(static_cast<std::uint8_t*>(lock.bits) + static_cast<std::ptrdiff_t>(y) * lock.pitch, bgra + static_cast<std::ptrdiff_t>(y) * width,
                  static_cast<std::size_t>(width) * 4U);
    }
    (void)texture->Unlock(0);
    const auto id = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(texture.get()));
    OwnImages()[id] = std::move(texture);
    return id;
  }

  void EdImGuiRenderer::DestroyImage(const std::uint64_t image)
  {
    OwnImages().erase(image);
  }

  bool EdImGuiRenderer::Init()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if ((device->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureVertexPulling) == 0U) {
      gpg::Warnf("editor UI: the device has no GPU programs");
      return false;
    }
    gpg::gal::GpuProgramDesc desc{};
    desc.name = "EditorImGui";
    desc.source = kImGuiShaderSource;
    desc.sourceBytes = sizeof(kImGuiShaderSource) - 1U;
    desc.vertexEntry = "ImGuiVS";
    desc.pixelEntry = "ImGuiPS";
    desc.blend = gpg::gal::GpuBlend::AlphaBlend;
    desc.colorWriteMask = 0x07U;
    desc.depthTest = false;
    desc.depthWrite = false;
    desc.cullBackFaces = false;
    desc.sampler = gpg::gal::GpuSampler::LinearClamp;
    mProgram = device->CreateGpuProgram(desc);
    if (mProgram == nullptr) {
      gpg::Warnf("editor UI: the ImGui program did not compile");
      return false;
    }

    ImGuiIO& io = ImGui::GetIO();
    io.BackendRendererName = "faf_gal";
    io.BackendFlags |= ImGuiBackendFlags_RendererHasVtxOffset | ImGuiBackendFlags_RendererHasTextures;
    return true;
  }

  void EdImGuiRenderer::Shutdown()
  {
    for (ImTextureData* const texture : ImGui::GetPlatformIO().Textures) {
      if (texture->RefCount == 1 && texture->BackendUserData != nullptr) {
        delete static_cast<TextureEntry*>(texture->BackendUserData);
        texture->BackendUserData = nullptr;
        texture->SetTexID(ImTextureID_Invalid);
        texture->SetStatus(ImTextureStatus_Destroyed);
      }
    }
    mProgram.reset();
    mVertices.reset();
    mIndices.reset();
    mVertexCapacity = 0U;
    mIndexCapacity = 0U;
    ImGuiIO& io = ImGui::GetIO();
    io.BackendRendererName = nullptr;
    io.BackendFlags &= ~(ImGuiBackendFlags_RendererHasVtxOffset | ImGuiBackendFlags_RendererHasTextures);
  }

  void EdImGuiRenderer::UpdateTexture(ImTextureData* const texture)
  {
    if (texture->Status == ImTextureStatus_WantCreate) {
      IM_ASSERT(texture->Format == ImTextureFormat_RGBA32);
      gpg::gal::TextureContext context{};
      context.source_ = 2U; // no file data: the engine fills it
      context.type_ = 1U;   // 2D
      context.usage_ = 2U;  // dynamic: ImGui updates its font atlas as glyphs are needed
      context.format_ = kTextureFormatBgra8;
      context.mipmapLevels_ = 1U;
      context.width_ = static_cast<std::uint32_t>(texture->Width);
      context.height_ = static_cast<std::uint32_t>(texture->Height);
      auto* const entry = new TextureEntry{gpg::gal::Device::GetInstance()->CreateTexture(&context)};
      Upload(*entry->texture, *texture);
      texture->BackendUserData = entry;
      texture->SetTexID(static_cast<ImTextureID>(reinterpret_cast<std::uintptr_t>(entry->texture.get())));
      texture->SetStatus(ImTextureStatus_OK);
    } else if (texture->Status == ImTextureStatus_WantUpdates) {
      auto* const entry = static_cast<TextureEntry*>(texture->BackendUserData);
      Upload(*entry->texture, *texture);
      texture->SetStatus(ImTextureStatus_OK);
    } else if (texture->Status == ImTextureStatus_WantDestroy && texture->UnusedFrames > 0) {
      delete static_cast<TextureEntry*>(texture->BackendUserData);
      texture->BackendUserData = nullptr;
      texture->SetTexID(ImTextureID_Invalid);
      texture->SetStatus(ImTextureStatus_Destroyed);
    }
  }

  void EdImGuiRenderer::EnsureCapacity(const std::uint32_t vertexCount, const std::uint32_t indexCount)
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (vertexCount > mVertexCapacity) {
      mVertexCapacity = std::max(vertexCount + vertexCount / 2U, 16384U);
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "EditorImGuiVertices";
      desc.stride = sizeof(ImDrawVert);
      desc.capacity = mVertexCapacity;
      mVertices = device->CreateGpuBuffer(desc);
    }
    if (indexCount > mIndexCapacity) {
      mIndexCapacity = std::max(indexCount + indexCount / 2U, 32768U);
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "EditorImGuiIndices";
      desc.stride = sizeof(std::uint32_t);
      desc.capacity = mIndexCapacity;
      mIndices = device->CreateGpuBuffer(desc);
    }
  }

  void EdImGuiRenderer::Render(ImDrawData* const drawData)
  {
    if (drawData == nullptr || drawData->DisplaySize.x <= 0.0f || drawData->DisplaySize.y <= 0.0f || mProgram == nullptr) {
      return;
    }
    if (drawData->Textures != nullptr) {
      for (ImTextureData* const texture : *drawData->Textures) {
        if (texture->Status != ImTextureStatus_OK) {
          UpdateTexture(texture);
        }
      }
    }
    if (drawData->TotalVtxCount <= 0) {
      return;
    }

    const auto vertexCount = static_cast<std::uint32_t>(drawData->TotalVtxCount);
    const auto indexCount = static_cast<std::uint32_t>(drawData->TotalIdxCount);
    mVertexStage.resize(static_cast<std::size_t>(vertexCount) * sizeof(ImDrawVert));
    mIndexStage.resize(indexCount);
    std::size_t vertexBytes = 0U;
    std::size_t indexAt = 0U;
    for (const ImDrawList* const list : drawData->CmdLists) {
      std::memcpy(mVertexStage.data() + vertexBytes, list->VtxBuffer.Data, static_cast<std::size_t>(list->VtxBuffer.Size) * sizeof(ImDrawVert));
      std::copy_n(list->IdxBuffer.Data, list->IdxBuffer.Size, mIndexStage.data() + indexAt);
      vertexBytes += static_cast<std::size_t>(list->VtxBuffer.Size) * sizeof(ImDrawVert);
      indexAt += static_cast<std::size_t>(list->IdxBuffer.Size);
    }
    EnsureCapacity(vertexCount, indexCount);
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    device->UpdateGpuBuffer(*mVertices, 0U, vertexCount, mVertexStage.data());
    device->UpdateGpuBuffer(*mIndices, 0U, indexCount, mIndexStage.data());

    // The projection of ImGui's Direct3D 9 backend, half-pixel offset included: every gal backend
    // moves its viewport by half a pixel to keep Direct3D 9's pixel centres
    // (docs/RENDERER_BACKENDS.md, "Pixel centres"), so ImGui's geometry is shifted back here.
    const float left = drawData->DisplayPos.x + 0.5f;
    const float right = drawData->DisplayPos.x + drawData->DisplaySize.x + 0.5f;
    const float top = drawData->DisplayPos.y + 0.5f;
    const float bottom = drawData->DisplayPos.y + drawData->DisplaySize.y + 0.5f;
    DrawConstants constants{};
    constants.scaleTranslate[0] = 2.0f / (right - left);
    constants.scaleTranslate[1] = 2.0f / (top - bottom);
    constants.scaleTranslate[2] = (right + left) / (left - right);
    constants.scaleTranslate[3] = (top + bottom) / (bottom - top);

    gpg::gal::GpuDrawCall call{};
    call.program = mProgram.get();
    call.bindings.constants = &constants;
    call.bindings.constantBytes = sizeof(constants);
    call.bindings.readBuffers[0] = mVertices.get();
    call.bindings.readBuffers[1] = mIndices.get();
    call.instanceCount = 1U;

    std::uint32_t listVertexBase = 0U;
    std::uint32_t listIndexBase = 0U;
    for (const ImDrawList* const list : drawData->CmdLists) {
      for (const ImDrawCmd& command : list->CmdBuffer) {
        if (command.UserCallback != nullptr) {
          if (command.UserCallback != ImDrawCallback_ResetRenderState) {
            command.UserCallback(list, &command);
          }
          continue;
        }
        if (command.ClipRect.z <= command.ClipRect.x || command.ClipRect.w <= command.ClipRect.y || command.ElemCount == 0U) {
          continue;
        }
        constants.clipRect[0] = command.ClipRect.x;
        constants.clipRect[1] = command.ClipRect.y;
        constants.clipRect[2] = command.ClipRect.z;
        constants.clipRect[3] = command.ClipRect.w;
        constants.indexOffset = listIndexBase + command.IdxOffset;
        constants.vertexOffset = listVertexBase + command.VtxOffset;
        call.bindings.textures[0] = reinterpret_cast<gpg::gal::Texture*>(static_cast<std::uintptr_t>(command.GetTexID()));
        call.vertexCountPerInstance = command.ElemCount;
        device->DrawGpuProgram(call);
      }
      listVertexBase += static_cast<std::uint32_t>(list->VtxBuffer.Size);
      listIndexBase += static_cast<std::uint32_t>(list->IdxBuffer.Size);
    }
  }
} // namespace faf::editor
