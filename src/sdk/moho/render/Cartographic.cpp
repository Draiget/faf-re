#include "moho/render/Cartographic.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

#include <d3d9.h>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "legacy/containers/String.h"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/DepthStencilTargetD3D9.hpp"
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/BoundaryRenderer.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/SelectionBracketRenderer.h"
#include "moho/render/VisionRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"

namespace
{
  constexpr std::size_t kCartographicNodeStorageSize = 0x7C;
  constexpr std::size_t kCartographicDecalNodeStorageSize = 0x30;

  /**
   * Address: 0x007D4000 (FUN_007D4000, sub_7D4000)
   *
   * What it does:
   * Allocates one or more fixed-size cartographic runtime nodes and raises
   * `std::bad_alloc` when multiplication overflows the 32-bit lane.
   */
  [[nodiscard]] void* AllocateCartographicNodeStorage(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < kCartographicNodeStorageSize) {
      throw std::bad_alloc();
    }

    return ::operator new(static_cast<std::size_t>(count) * kCartographicNodeStorageSize);
  }

  /**
   * Address: 0x007D3EC0 (FUN_007D3EC0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one cartographic node-storage
   * element through the checked allocator helper.
   */
  [[maybe_unused]] [[nodiscard]] void* AllocateSingleCartographicNodeStorageAdapter()
  {
    return AllocateCartographicNodeStorage(1u);
  }

  /**
   * Address: 0x007D3C90 (FUN_007D3C90, sub_7D3C90)
   *
   * What it does:
   * Allocates one cartographic node and resets its intrusive prev/next lanes
   * to a self-linked singleton.
   */
  [[nodiscard]] moho::CartographicListNode* CreateCartographicListSentinel()
  {
    auto* const sentinel = static_cast<moho::CartographicListNode*>(AllocateCartographicNodeStorage(1u));
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    return sentinel;
  }

  [[nodiscard]] moho::CartographicDecalBatch* CopyConstructCartographicDecalBatchIfPresent(
    moho::CartographicDecalBatch* const destination,
    const moho::CartographicDecalBatch* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) moho::CartographicDecalBatch(*source);
  }

  /**
   * Address: 0x007D3F40 (FUN_007D3F40)
   *
   * What it does:
   * Adapter lane for nullable `CartographicDecalBatch` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::CartographicDecalBatch* CopyConstructCartographicDecalBatchIfPresentAdapter(
    moho::CartographicDecalBatch* const destination,
    const moho::CartographicDecalBatch* const source
  )
  {
    return CopyConstructCartographicDecalBatchIfPresent(destination, source);
  }

  struct CartographicEffectAliasDeleter
  {
    explicit CartographicEffectAliasDeleter(const boost::shared_ptr<gpg::gal::EffectD3D9>& ownerEffect)
      : owner(ownerEffect)
    {
    }

    void operator()(gpg::gal::Effect*) const
    {
    }

    boost::shared_ptr<gpg::gal::EffectD3D9> owner;
  };

  constexpr std::array<float, 8> kCartographicQuadVertices{
    -1.0f, 1.0f,
    -1.0f, -1.0f,
    1.0f, 1.0f,
    1.0f, -1.0f,
  };

  constexpr std::array<std::uint32_t, 3> kCartographicQuadIndexWords{
    0x00010000u,
    0x00030002u,
    0x00010002u,
  };

  constexpr std::uint32_t kCartographicVertexFormatToken = 22U;
  constexpr std::uint32_t kCartographicTopologyTriangleList = 4U;
  constexpr std::uint32_t kCartographicQuadVertexCount = 4U;
  constexpr std::uint32_t kCartographicQuadPrimitiveCountInput = 6U;
  constexpr std::uint32_t kCartographicMaxDecalInstances = 1024U;
  constexpr std::uint32_t kCartographicInstanceFloatCount = 9U;

  /**
   * Address: 0x007D5B50 (FUN_007D5B50, sub_7D5B50)
   *
   * What it does:
   * Resolves the `"cartographic"` effect from device resources and returns its
   * base D3D9 GAL effect handle.
   */
  [[nodiscard]] boost::shared_ptr<gpg::gal::EffectD3D9> GetCartographicBaseEffectD3D9()
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DDeviceResources* const resources = device->GetResources();
    moho::CD3DEffect* const effect = resources->FindEffect("cartographic");
    return effect->GetBaseEffect();
  }

  /**
   * Address: 0x007D4380 (FUN_007D4380)
   *
   * What it does:
   * Clears one cartographic decal intrusive-list payload lane, relinks the
   * sentinel to itself, and deletes all detached nodes.
   */
  void ClearCartographicDecalList(moho::CartographicDecalList* const list) noexcept
  {
    if (list == nullptr || list->mDecalSentinel == nullptr) {
      return;
    }

    moho::CartographicDecalNode* const sentinel = list->mDecalSentinel;
    moho::CartographicDecalNode* node = sentinel->mNext;

    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    list->mDecalCount = 0;

    while (node != nullptr && node != sentinel) {
      moho::CartographicDecalNode* const next = node->mNext;
      node->mDecal.~CartographicDecal();
      ::operator delete(node);
      node = next;
    }
  }

  [[nodiscard]] void* AllocateCartographicDecalNodeStorage(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < kCartographicDecalNodeStorageSize) {
      throw std::bad_alloc();
    }

    return ::operator new(static_cast<std::size_t>(count) * kCartographicDecalNodeStorageSize);
  }

  [[nodiscard]] moho::CartographicDecalNode* CreateCartographicDecalSentinelNode()
  {
    auto* const sentinel = static_cast<moho::CartographicDecalNode*>(AllocateCartographicDecalNodeStorage(1u));
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    return sentinel;
  }

  /**
   * Address: 0x007D46B0 (FUN_007D46B0, sub_7D46B0)
   *
   * IDA signature:
   * int __userpurge sub_7D46B0@<eax>(Moho::CartographicDecal *a1@<esi>, int next, int prev);
   *
   * What it does:
   * Allocates a fresh CartographicDecalNode (48 bytes via the legacy
   * checked operator new[] lane), wires its `mNext`/`mPrev` link
   * fields, and copy-constructs the embedded CartographicDecal payload
   * from `decal`. The binary writes the embedded decal's vtable
   * pointer + 36-byte mVertexData buffer field-by-field; this modern
   * form delegates to CartographicDecal's implicit copy ctor through
   * placement-new which emits the same byte image with proper RAII
   * (operator-delete-on-throw rollback) the binary did not need
   * because the embedded ctor cannot fault.
   *
   * The IDA decomp's `result != -4`/`result != -8` guards are MSVC's
   * spurious null-deref defenses around the +4/+8 field writes — they
   * never trigger for valid pointers, so the modern code skips them
   * and relies on the operator-new guarantee that the returned buffer
   * is either non-null or threw.
   */
  [[nodiscard]] moho::CartographicDecalNode* CreateCartographicDecalNodeBefore(
    moho::CartographicDecalNode* const next,
    moho::CartographicDecalNode* const prev,
    const moho::CartographicDecal& decal
  )
  {
    auto* const node = static_cast<moho::CartographicDecalNode*>(AllocateCartographicDecalNodeStorage(1u));
    node->mNext = next;
    node->mPrev = prev;
    try {
      ::new (static_cast<void*>(&node->mDecal)) moho::CartographicDecal(decal);
    } catch (...) {
      ::operator delete(node);
      throw;
    }

    return node;
  }

  /**
   * Per-iteration "append one decal before the sentinel" step of the
   * cartographic decal list copy loop. Allocates one node via
   * `CreateCartographicDecalNodeBefore`, patches the sentinel's
   * intrusive `mPrev` lane and the new node's predecessor `mNext`
   * lane to close the circular-list invariant, and increments the
   * destination's `mDecalCount`.
   *
   * Note: the binary emits a discrete symbol (FUN_007D45F0,
   * `sub_7D45F0`) that combines this step with the legacy VC8
   * `std::list<T>::_Incsize`-style overflow check at count ==
   * 107374182 (=UINT32_MAX/40) which forwards into
   * `FUN_007D4720` to throw `length_error("list<T> too long")`.
   * The overflow throw is currently elided here — modern
   * std::list-equivalent ABI relies on `::operator new` exhaustion
   * to surface allocation failure. Restoring the explicit check
   * would require a typed `RuntimeIncrementListCountWithOverflowCheck`
   * helper that pairs with the throw lane at
   * `CrtRuntimeHelpers.cpp:37372`.
   */
  void AppendCartographicDecalListNodeBeforeSentinel(
    moho::CartographicDecalList& destination,
    const moho::CartographicDecal& decal
  )
  {
    moho::CartographicDecalNode* const sentinel = destination.mDecalSentinel;
    moho::CartographicDecalNode* const node =
      CreateCartographicDecalNodeBefore(sentinel, sentinel->mPrev, decal);
    sentinel->mPrev = node;
    node->mPrev->mNext = node;
    ++destination.mDecalCount;
  }

  /**
   * Address: 0x007D4620 (FUN_007D4620, sub_7D4620)
   *
   * IDA signature:
   * _DWORD *__userpurge sub_7D4620@<eax>(_DWORD *a1@<edi>, int a2@<esi>, _DWORD **a3)
   *
   * What it does:
   * Legacy VC8 `std::list<CartographicDecal>::erase(iterator)` lane: unlinks one
   * non-sentinel decal node, destroys the embedded decal, frees the node and
   * decrements the count, returning the successor. Erasing the sentinel is a
   * no-op that still returns its successor, matching the binary's guard.
   *
   * Structural twin of the batch-list lane `EraseCartographicDecalBatchNode`
   * (FUN_007D1740); the binary emits one copy per element type.
   */
  moho::CartographicDecalNode* EraseCartographicDecalNode(
    moho::CartographicDecalList& list,
    moho::CartographicDecalNode* const node
  ) noexcept
  {
    moho::CartographicDecalNode* const successor = node->mNext;
    if (node != list.mDecalSentinel) {
      node->mPrev->mNext = successor;
      successor->mPrev = node->mPrev;
      node->mDecal.~CartographicDecal();
      ::operator delete(node);
      --list.mDecalCount;
    }

    return successor;
  }

  /**
   * Address: 0x007D4550 (FUN_007D4550, sub_7D4550)
   *
   * What it does:
   * Inner copy-loop body that the binary emitted as a separate symbol.
   * Walks the source `[first, sentinel)` range and, for each source decal
   * node, creates a new decal node before the destination sentinel's
   * `mPrev` lane using the shared `CreateCartographicDecalNodeBefore`
   * helper, then patches the sentinel/new-node link pair and increments
   * the destination count.
   *
   * Wired into `CopyCartographicDecalList` to preserve the binary's per-T
   * symbol shape even when the modern compiler would inline the loop.
   */
  void CopyCartographicDecalNodesIntoSentinel(
    moho::CartographicDecalList& destination,
    const moho::CartographicDecalNode* const sourceFirst,
    const moho::CartographicDecalNode* const sourceSentinel)
  {
    // The binary brackets this loop in a C++ EH scope (SEH_7D4550): on throw the
    // funclet at 0x007D45AC erases exactly as many nodes off the destination
    // tail as source elements were consumed, then rethrows. `_Where` there is
    // the destination sentinel, because the destination is freshly self-linked
    // and empty when FUN_007D4230 evaluates it.
    std::size_t appended = 0;
    try {
      for (const moho::CartographicDecalNode* sourceNode = sourceFirst;
           sourceNode != sourceSentinel;
           sourceNode = sourceNode->mNext) {
        AppendCartographicDecalListNodeBeforeSentinel(destination, sourceNode->mDecal);
        ++appended;
      }
    } catch (...) {
      while (appended-- > 0) {
        (void)EraseCartographicDecalNode(destination, destination.mDecalSentinel->mPrev);
      }
      throw;
    }
  }

  /**
   * Address: 0x007D4230 (FUN_007D4230, sub_7D4230)
   *
   * What it does:
   * Initializes a destination cartographic decal list with a fresh sentinel
   * and deep-copies every source decal node in list order. Routes the inner
   * per-element copy loop through the canonical helper
   * `CopyCartographicDecalNodesIntoSentinel` (FUN_007D4550) to preserve the
   * binary's symbol shape.
   */
  void CopyCartographicDecalList(
    moho::CartographicDecalList& destination,
    const moho::CartographicDecalList& source
  )
  {
    destination.mAllocatorCookie = nullptr;
    destination.mDecalSentinel = CreateCartographicDecalSentinelNode();
    destination.mDecalCount = 0;

    try {
      const moho::CartographicDecalNode* const sourceSentinel = source.mDecalSentinel;
      if (sourceSentinel != nullptr) {
        CopyCartographicDecalNodesIntoSentinel(
          destination, sourceSentinel->mNext, sourceSentinel);
      }
    } catch (...) {
      ClearCartographicDecalList(&destination);
      ::operator delete(destination.mDecalSentinel);
      destination.mDecalSentinel = nullptr;
      throw;
    }
  }

  /**
   * Address: 0x007D3BC0 (FUN_007D3BC0, sub_7D3BC0)
   *
   * What it does:
   * Clears the cartographic decal-batch intrusive list, relinks the sentinel
   * to itself, destroys every batch node, and resets the owner count.
   */
  void ClearCartographicBatchList(moho::Cartographic& owner) noexcept
  {
    moho::CartographicListNode* const sentinel = owner.mListSentinel;
    if (sentinel == nullptr) {
      owner.mBatchCount = 0;
      return;
    }

    moho::CartographicListNode* node = sentinel->mNext;
    sentinel->mNext = sentinel;
    sentinel->mPrev = sentinel;
    owner.mBatchCount = 0;

    while (node != nullptr && node != sentinel) {
      moho::CartographicListNode* const next = node->mNext;
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x007D3D70 (FUN_007D3D70, sub_7D3D70)
   *
   * What it does:
   * Allocates one cartographic batch-list node, installs caller-provided
   * intrusive links, and copy-constructs the embedded decal batch.
   */
  [[nodiscard]] moho::CartographicListNode* CreateCartographicBatchNode(
    moho::CartographicListNode* const next,
    moho::CartographicListNode* const prev,
    const moho::CartographicDecalBatch& sourceBatch
  )
  {
    auto* const node = static_cast<moho::CartographicListNode*>(AllocateCartographicNodeStorage(1u));
    node->mNext = next;
    node->mPrev = prev;

    try {
      ::new (static_cast<void*>(&node->mBatch)) moho::CartographicDecalBatch(sourceBatch);
    } catch (...) {
      ::operator delete(node);
      throw;
    }

    return node;
  }

  /**
   * Address: 0x007D4A70 (FUN_007D4A70, sub_7D4A70)
   *
   * What it does:
   * Serializes one decal payload lane as five fixed write segments
   * (`8 + 4 + 8 + 8 + 8` bytes) into the writer stream.
   */
  void WriteCartographicDecalPayload(
    gpg::BinaryWriter& writer,
    const moho::CartographicDecal& decal
  )
  {
    for (const float value : decal.mVertexData) {
      writer.Write(value);
    }
  }

  // --- Cartographic terrain / frame initialization constants ---------------
  //
  // Every float below was byte-verified against the shipped image
  // (bin/2025.7.1/ForgedAlliance.exe) at the .rdata address named in its
  // trailing comment; the integers come from the immediates in the
  // corresponding `.asm` exports.

  constexpr std::uint32_t kCartographicFrameVertexFormatToken = 7U;
  constexpr std::uint32_t kCartographicTerrainVertexFormatToken = 10U;

  constexpr std::uint32_t kCartographicFrameVertexCount = 4U;
  constexpr std::uint32_t kCartographicFrameVertexStride = 24U;
  constexpr std::uint32_t kCartographicTerrainVertexCount = 4U;
  constexpr std::uint32_t kCartographicTerrainVertexStride = 8U;
  constexpr std::uint32_t kCartographicQuadIndexCount = 6U;

  constexpr std::uint32_t kCartographicBufferTypeManaged = 1U;
  constexpr std::uint32_t kCartographicBufferUsageStatic = 1U;
  constexpr std::uint32_t kCartographicBufferUsageDynamic = 2U;
  constexpr std::uint32_t kCartographicIndexFormat16Bit = 1U;

  constexpr std::uint32_t kCartographicTextureSourceDevice = 2U;
  constexpr std::uint32_t kCartographicTextureType2D = 1U;
  constexpr std::uint32_t kCartographicTextureUsageStatic = 1U;
  constexpr std::uint32_t kCartographicTextureMipLevels = 1U;

  // GAL surface-format tokens as written into TextureContext::format_.
  constexpr std::uint32_t kCartographicElevationTextureFormat = 14U;
  constexpr std::uint32_t kCartographicHypsometricTextureFormat = 2U;
  constexpr std::uint32_t kCartographicTopographicTextureFormat = 5U;

  // Both lookup ramps are one row of 256 texels indexed by normalized height.
  constexpr std::int32_t kCartographicRampTexelCount = 256;

  // The elevation map is a two-channel 16-bit surface; only the first channel
  // carries the packed height, so consecutive texels are two words apart.
  constexpr std::ptrdiff_t kCartographicElevationTexelWordStride = 2;

  // InitializeTerrainTextures clamps the requested contour count into [1, 100].
  constexpr std::int32_t kCartographicMinTopographicBands = 1;
  constexpr std::int32_t kCartographicMaxTopographicBands = 100;

  // Raw uint16 height word <-> world elevation. flt_E4F6DC = 0x3C000000.
  constexpr float kCartographicHeightWordScale = 1.0f / 128.0f;
  constexpr float kCartographicHeightWordsPerUnit = 128.0f; // dword_DFE8B4

  // Sentinel written into the elevation lanes when the map has no water.
  constexpr float kCartographicNoWaterElevation = -10000.0f; // dword_E4F6E4

  // Ramp texel index -> normalized height. dword_E41914 = 1/255.
  constexpr float kCartographicInverseRampRange = 1.0f / 255.0f;

  // Topographic contour shading maps a band ceiling onto [16, 255].
  constexpr float kCartographicContourShadeScale = 239.0f; // dword_E4F93C
  constexpr float kCartographicContourShadeBias = 16.0f;   // dword_E4F938
  constexpr std::int32_t kCartographicContourShadeMinimum = 16;
  constexpr std::int32_t kCartographicContourShadeMaximum = 255;

  /**
   * Leading layout of `Moho::CWldTerrainRes` as the cartographic init path
   * walks it: `InitializeTerrain` reads the owning `STIMap` straight out of
   * `IWldTerrainRes+0x04` (0x007D2119 `mov eax, [eax+4]`) and then chases
   * `STIMap+0x00` for the heightfield (0x007D211C `mov ebp, [eax]`).
   *
   * `IWldTerrainRes` already publishes `GetHeightField()`, `IsWaterEnabled()`
   * and `GetWaterElevation()` for exactly this chase, but not the deep-water
   * lane this function also needs, so the view is spelled out here the same
   * way the sibling consumers do it (`MapImager.cpp`, `Clutter.cpp`,
   * `CWldSplat.cpp`). It is deliberately identical to theirs so a later
   * consolidation pass can lift all four into one owning accessor.
   */
  struct CWldTerrainResRuntimeView
  {
    const void* mVftable; // +0x00
    moho::STIMap* mMap;   // +0x04
  };

  static_assert(offsetof(CWldTerrainResRuntimeView, mMap) == 0x04, "CWldTerrainResRuntimeView::mMap offset must be 0x04");
  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");

  [[nodiscard]] moho::STIMap& CartographicTerrainMap(const moho::IWldTerrainRes& terrain) noexcept
  {
    return *reinterpret_cast<const CWldTerrainResRuntimeView*>(&terrain)->mMap;
  }

  /**
   * Packs one IEEE-754 binary32 value into a binary16 word.
   *
   * The shipped elevation-texture fill loop converts each sampled height with
   * `D3DXFloat32To16Array` (direct call at 0x007D2759). D3DX is an external
   * runtime and this tree only reaches it through
   * `gpg::gal::InvokeD3DXFloat32To16Array`, which lives in an anonymous
   * namespace inside `D3D9Interfaces.cpp` and is therefore not linkable from
   * another translation unit. This helper reproduces the same conversion
   * (round-to-nearest, denormal-preserving, saturating to +/-Inf) that the
   * D3D9 backend falls back to when the D3DX export is unavailable.
   */
  [[nodiscard]] std::uint16_t PackFloat32AsHalfFloat(const float value) noexcept
  {
    std::uint32_t bits = 0U;
    static_assert(sizeof(bits) == sizeof(value), "float/uint32_t size mismatch");
    std::memcpy(&bits, &value, sizeof(bits));

    const std::uint32_t sign = (bits >> 16U) & 0x8000U;
    const std::int32_t exponent = static_cast<std::int32_t>((bits >> 23U) & 0xFFU) - 127 + 15;
    std::uint32_t mantissa = bits & 0x007FFFFFU;

    if (exponent <= 0) {
      if (exponent < -10) {
        return static_cast<std::uint16_t>(sign);
      }
      mantissa = (mantissa | 0x00800000U) >> static_cast<std::uint32_t>(1 - exponent);
      return static_cast<std::uint16_t>(sign | ((mantissa + 0x00001000U) >> 13U));
    }

    if (exponent >= 31) {
      return static_cast<std::uint16_t>(sign | 0x7C00U);
    }

    return static_cast<std::uint16_t>(
      sign | (static_cast<std::uint32_t>(exponent) << 10U) | ((mantissa + 0x00001000U) >> 13U)
    );
  }

  /**
   * Address: 0x007D0E60 (FUN_007D0E60, sub_7D0E60)
   *
   * IDA signature:
   * int __usercall sub_7D0E60@<eax>(unsigned int to@<eax>, int from@<ecx>, float t@<xmm0>);
   *
   * What it does:
   * Blends two packed 8-bit-per-channel colors channel by channel with
   * `from + (to - from) * t`, truncating each channel back to a byte. Used
   * once, by the cartographic hypsometric ramp fill, to fade the fourth
   * palette entry into the fifth across the above-water band.
   */
  [[nodiscard]] std::int32_t BlendPackedColor(
    const std::int32_t fromColor,
    const std::int32_t toColor,
    const float weight
  ) noexcept
  {
    const auto from = static_cast<std::uint32_t>(fromColor);
    const auto to = static_cast<std::uint32_t>(toColor);

    std::uint32_t blended = 0U;
    for (unsigned int channelShift = 0U; channelShift < 32U; channelShift += 8U) {
      const auto fromChannel = static_cast<std::int32_t>((from >> channelShift) & 0xFFU);
      const auto toChannel = static_cast<std::int32_t>((to >> channelShift) & 0xFFU);
      const float channel =
        (static_cast<float>(toChannel - fromChannel) * weight) + static_cast<float>(fromChannel);
      const auto packedChannel = static_cast<std::uint32_t>(static_cast<std::int32_t>(channel)) & 0xFFU;
      blended |= packedChannel << channelShift;
    }

    return static_cast<std::int32_t>(blended);
  }

  /**
   * Address: 0x007D0F70 (FUN_007D0F70)
   *
   * IDA signature:
   * float __usercall sub_7D0F70@<xmm0>(int *field@<eax>, int x@<edx>, int z@<ecx>,
   *                                    float baseline@<xmm3>, float scale@<xmm4>);
   *
   * What it does:
   * Applies the legacy 3x3 cartographic elevation kernel to one clamped
   * heightfield sample and normalizes the weighted sum by `1/7`. The weight
   * table at 0x00DFEA1C is byte-verified as `{0,1,0, 1,3,1, 0,1,0}`.
   *
   * The shipped body evaluates all nine weighted terms against the *same*
   * texel: its unrolled loop advances only the weight cursor and never the
   * clamped `(x-1, z-1)` sample coordinates, so the kernel collapses to
   * `((word / 128) - baseline) * scale`. That is what the game computes, so
   * the summation shape is preserved verbatim rather than "fixed".
   *
   * The `int*` first parameter is the leading `{data, width, height}` triple
   * of `Moho::CHeightField` - the caller passes the heightfield itself
   * (0x007D2720 `mov eax, [esp+arg_0]`).
   */
  [[nodiscard]] float SampleCartographicHeightKernel(
    const moho::CHeightField& field,
    const std::int32_t x,
    const std::int32_t z,
    const float baseline,
    const float scale
  ) noexcept
  {
    constexpr std::array<float, 9> kKernelWeights{
      0.0f, 1.0f, 0.0f,
      1.0f, 3.0f, 1.0f,
      0.0f, 1.0f, 0.0f,
    };
    constexpr float kKernelNormalize = 0.142857149f; // dword_E4F8B4

    const std::int32_t clampedX = std::max(0, std::min(x - 1, field.width - 1));
    const std::int32_t clampedZ = std::max(0, std::min(z - 1, field.height - 1));
    const std::uint16_t heightWord = field.data[(clampedZ * field.width) + clampedX];
    const float normalizedHeight =
      (static_cast<float>(heightWord) * kCartographicHeightWordScale) - baseline;

    float weightedHeight = 0.0f;
    for (const float weight : kKernelWeights) {
      weightedHeight += (normalizedHeight * weight) * scale;
    }

    return weightedHeight * kKernelNormalize;
  }

  /**
   * Locks the whole of texture level 0 and hands back the mapped bytes.
   *
   * The three cartographic lookup textures are each filled through the same
   * `Lock(&lockRect, 0, &wholeSurface, 0)` / `Unlock(0)` pair the binary
   * emits at 0x007D26C1, 0x007D28BE and 0x007D2B5A; lifting it keeps the
   * zeroed whole-surface RECT out of the three fill loops.
   */
  [[nodiscard]] void* LockWholeCartographicTexture(gpg::gal::TextureD3D9& texture)
  {
    gpg::gal::TextureLockRect lockedRect{};
    RECT wholeSurface{};
    texture.Lock(&lockedRect, 0, &wholeSurface, 0);
    return lockedRect.bits;
  }

  void FillCartographicTextureContext(
    gpg::gal::TextureContext& context,
    const std::uint32_t format,
    const std::uint32_t width,
    const std::uint32_t height
  ) noexcept
  {
    context.source_ = kCartographicTextureSourceDevice;
    context.type_ = kCartographicTextureType2D;
    context.usage_ = kCartographicTextureUsageStatic;
    context.format_ = format;
    context.mipmapLevels_ = kCartographicTextureMipLevels;
    context.width_ = width;
    context.height_ = height;
  }

  // ---------------------------------------------------------------------
  // Render-arm constants. Every float below is byte-verified out of
  // `bin/2025.7.1/ForgedAlliance.exe` rather than trusted from the IDA
  // listing.
  // ---------------------------------------------------------------------

  // Opaque black, the colour `RenderTerrainStage0` clears the offscreen
  // cartographic frame to (0x007D2ED0 pushes the immediate directly).
  constexpr std::uint32_t kCartographicFrameClearColor = 0xFF000000u;

  // Opaque white, the colour `Cartographic::Render` clears the head to just
  // before the UI pass (0x007D1B84 pushes 0FFFFFFFFh).
  constexpr std::uint32_t kCartographicHeadClearColor = 0xFFFFFFFFu;

  constexpr float kCartographicClearDepth = 1.0f;
  constexpr std::int32_t kCartographicClearStencil = 0;

  // Half-texel correction applied to both screen-quad extents so the
  // composite samples texel centres. flt_E4F724, byte-verified 0x3F000000.
  constexpr float kCartographicHalfTexel = 0.5f;

  // Top-left corner of the composite quad in screen space, i.e. the same
  // half-texel shifted to the negative side. dword_E4F8D0, byte-verified
  // 0xBF000000.
  constexpr float kCartographicScreenQuadOrigin = -0.5f;

  // The `1.0f` the composite quad uses for `z`, `rhw` and the far texture
  // coordinates. Held at 0x00DFEC20, byte-verified 0x3F800000.
  constexpr float kCartographicScreenQuadUnit = 1.0f;

  constexpr float kCartographicScreenQuadZero = 0.0f;

  // Four `(x, y, z, rhw, u, v)` corners, 24 bytes each - the 0x60 bytes the
  // shipped body locks and memcpys at 0x007D3702..0x007D3705.
  constexpr std::size_t kCartographicFrameVertexFloatCount = 24U;
  constexpr std::uint32_t kCartographicFrameVertexByteSize = 96U;

  // Head viewport depth range used by both `SetViewport` payloads.
  constexpr float kCartographicViewportMinDepth = 0.0f;
  constexpr float kCartographicViewportMaxDepth = 1.0f;

  /**
   * `Cartographic::GetEffect` (0x007D1E50) hands the cartographic effect back
   * through the abstract `gpg::gal::Effect` handle, which it builds by
   * aliasing the very `EffectD3D9` the device resources own (see
   * `Cartographic::GetEffect` further down this file). The GAL headers in this
   * tree still model `Effect` and `EffectD3D9` as two unrelated skeletons, so
   * reading the technique/variable interface back out of that handle needs the
   * matching inverse alias. Both `RenderTerrainStage0` (0x007D2EEE) and
   * `RenderTerrainStage1` (0x007D371E) call `GetEffect` and then dispatch
   * through `EffectD3D9` slot 3 (`SetMatrix`, +0x0C) and slot 4
   * (`SetTechnique`, +0x10) on the returned pointer.
   */
  [[nodiscard]] gpg::gal::EffectD3D9& CartographicEffectInterface(
    const boost::shared_ptr<gpg::gal::Effect>& effect
  ) noexcept
  {
    return *reinterpret_cast<gpg::gal::EffectD3D9*>(effect.get());
  }

  /**
   * Keeps one concrete D3D9 target alive while a `gpg::gal::OutputContext`
   * lane holds a pointer of the abstract context flavour its header declares.
   *
   * The shipped `OutputContext(SurfaceHandle, TextureHandle)` ctor
   * (0x008E77D0) simply copies the two caller words and bumps the use count -
   * the D3D9 backend parks a `RenderTargetD3D9` and a
   * `DepthStencilTargetD3D9` in those two lanes, which is exactly how
   * `D3D9Interfaces.cpp` models them in `OutputContextD3D9RuntimeView`.
   * Boost 1.34.1 predates the aliasing `shared_ptr` constructor, so crossing
   * the two handle flavours reuses the deleter-alias idiom this file already
   * applies in `Cartographic::GetEffect`.
   */
  template <class Owner>
  struct CartographicTargetAliasDeleter
  {
    explicit CartographicTargetAliasDeleter(boost::shared_ptr<Owner> ownerHandle)
      : owner(ownerHandle)
    {
    }

    template <class Aliased>
    void operator()(Aliased*) const noexcept
    {
    }

    boost::shared_ptr<Owner> owner;
  };

  [[nodiscard]] gpg::gal::OutputContext::SurfaceHandle AsOutputContextSurface(
    const boost::shared_ptr<gpg::gal::RenderTargetD3D9>& colorTarget
  )
  {
    return gpg::gal::OutputContext::SurfaceHandle(
      reinterpret_cast<gpg::gal::RenderTargetContext*>(colorTarget.get()),
      CartographicTargetAliasDeleter<gpg::gal::RenderTargetD3D9>(colorTarget)
    );
  }

  [[nodiscard]] gpg::gal::OutputContext::TextureHandle AsOutputContextDepthStencil(
    const boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9>& depthStencilTarget
  )
  {
    return gpg::gal::OutputContext::TextureHandle(
      reinterpret_cast<gpg::gal::TextureContext*>(depthStencilTarget.get()),
      CartographicTargetAliasDeleter<gpg::gal::DepthStencilTargetD3D9>(depthStencilTarget)
    );
  }

  /**
   * Returns the output context one device head renders into.
   *
   * `gpg::gal::Device::GetHead2` is slot 7 (+0x1C) and really answers with the
   * head's `gpg::gal::OutputContext`; the GAL base declaration still spells the
   * return type `Head*` because that header pair was lifted before the
   * output-context lane was identified. `moho/render/d3d/CD3DDevice.cpp`
   * (0x00650, 0x00817) already reads the result the same way.
   */
  [[nodiscard]] gpg::gal::OutputContext& CartographicHeadOutputContext(
    gpg::gal::DeviceD3D9& device,
    const unsigned int headIndex
  ) noexcept
  {
    return *reinterpret_cast<gpg::gal::OutputContext*>(device.GetHead2(headIndex));
  }

  /**
   * Returns the render-target description of one device head.
   *
   * The shipped `RenderTerrainStage1` walks
   * `GetHead2(headIndex)->surface->GetContext()` at 0x007D35C9..0x007D35D1 and
   * reads `width_` (+0x04) and `height_` (+0x08) off the result. The surface
   * lane holds the concrete `RenderTargetD3D9` whose slot-1 virtual
   * `GetContext()` returns that description.
   */
  [[nodiscard]] const gpg::gal::RenderTargetContext& CartographicHeadRenderTargetContext(
    gpg::gal::DeviceD3D9& device,
    const unsigned int headIndex
  ) noexcept
  {
    gpg::gal::OutputContext& outputContext = CartographicHeadOutputContext(device, headIndex);
    auto* const renderTarget =
      reinterpret_cast<gpg::gal::RenderTargetD3D9*>(outputContext.surface.get());
    return *renderTarget->GetContext();
  }

  /**
   * Builds the screen-space quad `RenderTerrainStage1` composites the
   * offscreen cartographic frame with: four `(x, y, z, rhw, u, v)` corners
   * spanning the whole head, shifted by half a texel on both axes so the
   * sampler lands on texel centres.
   *
   * Corner order and constants come straight from the shipped stores at
   * 0x007D3648..0x007D36F9.
   */
  [[nodiscard]] std::array<float, kCartographicFrameVertexFloatCount>
  BuildCartographicFrameQuad(const float frameWidth, const float frameHeight)
  {
    const float left = kCartographicScreenQuadOrigin;
    const float bottom = kCartographicScreenQuadOrigin;
    const float right = frameWidth - kCartographicHalfTexel;
    const float top = frameHeight - kCartographicHalfTexel;

    constexpr float one = kCartographicScreenQuadUnit;
    constexpr float zero = kCartographicScreenQuadZero;

    return {
      left,  top,    one, one, zero, one,
      left,  bottom, one, one, zero, zero,
      right, top,    one, one, one,  one,
      right, bottom, one, one, one,  zero,
    };
  }

  /**
   * Fills one D3D9 viewport payload. `gpg::gal::Device::SetViewport` (slot 34,
   * +0x88) forwards its opaque argument straight to
   * `IDirect3DDevice9::SetViewport`, so the payload is a plain
   * `D3DVIEWPORT9`; the shipped body builds the identical 24-byte block on its
   * own stack at 0x007D190A..0x007D1954.
   */
  [[nodiscard]] D3DVIEWPORT9 MakeCartographicViewport(
    const std::int32_t left,
    const std::int32_t top,
    const std::int32_t width,
    const std::int32_t height
  ) noexcept
  {
    D3DVIEWPORT9 viewport{};
    viewport.X = static_cast<DWORD>(left);
    viewport.Y = static_cast<DWORD>(top);
    viewport.Width = static_cast<DWORD>(width);
    viewport.Height = static_cast<DWORD>(height);
    viewport.MinZ = kCartographicViewportMinDepth;
    viewport.MaxZ = kCartographicViewportMaxDepth;
    return viewport;
  }
} // namespace

namespace moho
{
  /**
   * The active world session (`Moho::sWldSession`, 0x010A6470).
   * `Cartographic::Render` caches it at 0x007D1832 and gates the range-ring,
   * fog-of-war, boundary and UI passes on it being non-null. The global has no
   * owning header in this tree yet, so it is declared here where it is used.
   */
  extern CWldSession* sWldSession;

  /**
   * Address: 0x007FA730 (FUN_007FA730, Moho::REN_DebugStuff)
   * Mangled: ?REN_DebugStuff@Moho@@YAXV?$shared_ptr@VCD3DPrimBatcher@Moho@@@boost@@H@Z
   *
   * Defined in `moho/app/WxRuntimeTypes.cpp`, which declares it locally too -
   * there is no owning header for it yet. Called by `Cartographic::Render` at
   * 0x007D1BE0 with the head index in `ecx`.
   */
  void REN_DebugStuff(boost::shared_ptr<CD3DPrimBatcher> batcher, int head);

  /**
   * Address: 0x007D4A00 (FUN_007D4A00, sub_7D4A00)
   *
   * What it does:
   * Initializes one cartographic decal payload object and installs the
   * decal runtime vtable lane.
  */
  CartographicDecal::CartographicDecal() = default;

  /**
   * Address: 0x007D40E0 (FUN_007D40E0, ??0CartographicDecalBatch@Moho@@QAE@@Z)
   *
   * IDA signature:
   * int __thiscall Moho::CartographicDecalBatch::CartographicDecalBatch(int source, int destination);
   *
   * What it does:
   * Copy-constructs one cartographic decal batch, retaining shared render
   * handles and deep-copying the intrusive decal payload list.
   */
  CartographicDecalBatch::CartographicDecalBatch(const CartographicDecalBatch& other)
    : mTechniqueName(),
      mTexturePath(),
      mDecalTexture(other.mDecalTexture),
      mVertexFormat(other.mVertexFormat),
      mQuadVertexBuffer(other.mQuadVertexBuffer),
      mInstanceVertexBuffer(other.mInstanceVertexBuffer),
      mIndexBuffer(other.mIndexBuffer),
      mNeedsVertexUpload(other.mNeedsVertexUpload),
      mPadding65_67{},
      mDecals{}
  {
    mTechniqueName.reset_and_assign(other.mTechniqueName);
    mTexturePath.reset_and_assign(other.mTexturePath);
    CopyCartographicDecalList(mDecals, other.mDecals);
  }

  /**
   * Address: 0x007D4BE0 (FUN_007D4BE0, ??0CartographicDecalBatch@Moho@@QAE@IAAVBinaryReader@gpg@@@Z)
   *
   * IDA signature:
   * Moho::CartographicDecalBatch* __stdcall Moho::CartographicDecalBatch::CartographicDecalBatch(
   *   Moho::CartographicDecalBatch* a1, unsigned int a2, gpg::BinaryReader* a3);
   *
   * What it does:
   * Default-initializes the batch's empty SSO string lanes, null
   * render-resource shared-pointers, dirty vertex-upload flag, and a
   * fresh self-linked decal-list sentinel; then forwards into
   * `Read(version, reader)` to deserialize the actual batch payload
   * from the binary reader.
   *
   * Mirrors the binary's `??0CartographicDecalBatch@Moho@@QAE@IAAVBinaryReader@gpg@@@Z`
   * (mangled symbol suffix `_0` — second ctor overload alongside the
   * copy ctor at FUN_007D40E0). Called from `Cartographic::ReadDecals`
   * to construct each archived batch in turn.
   */
  CartographicDecalBatch::CartographicDecalBatch(
    const std::uint32_t version, gpg::BinaryReader& reader)
    : mTechniqueName(),
      mTexturePath(),
      mDecalTexture(),
      mVertexFormat(),
      mQuadVertexBuffer(),
      mInstanceVertexBuffer(),
      mIndexBuffer(),
      mNeedsVertexUpload(true),
      mPadding65_67{},
      mDecals{}
  {
    // The member-init list above already places both msvc8::string
    // lanes in empty-SSO state (mySize=0, myRes=15, bx.buf[0]='\0'),
    // matching the binary's explicit field writes. Initialize the
    // intrusive decal-list sentinel before forwarding into Read; the
    // first thing Read does is Shutdown() which is null-safe on the
    // list lane but the subsequent decal-append loop expects a valid
    // sentinel.
    mDecals.mAllocatorCookie = nullptr;
    mDecals.mDecalSentinel = CreateCartographicDecalSentinelNode();
    mDecals.mDecalCount = 0;

    Read(version, reader);
  }

  /**
   * Address: 0x007D4E60 (FUN_007D4E60, ?Shutdown@CartographicDecalBatch@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears both batch name/string lanes, releases retained shared resource
   * handles, clears intrusive decal nodes, and marks the vertex upload lane dirty.
   */
  void CartographicDecalBatch::Shutdown()
  {
    mTechniqueName.clear();
    mTexturePath.clear();

    mDecalTexture.reset();
    mVertexFormat.reset();
    mQuadVertexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mIndexBuffer.reset();

    ClearCartographicDecalList(&mDecals);
    mNeedsVertexUpload = true;
  }

  /**
   * Address: 0x007D4C80 (FUN_007D4C80, ??1CartographicDecalBatch@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs the shutdown lane, clears/deletes the intrusive decal sentinel, and
   * tidies both embedded legacy string lanes back to inline-empty form.
   */
  CartographicDecalBatch::~CartographicDecalBatch()
  {
    Shutdown();
    ClearCartographicDecalList(&mDecals);

    if (mDecals.mDecalSentinel != nullptr) {
      ::operator delete(mDecals.mDecalSentinel);
      mDecals.mDecalSentinel = nullptr;
    }

    mIndexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mQuadVertexBuffer.reset();
    mVertexFormat.reset();
    mDecalTexture.reset();

    mTexturePath.tidy(true, 0U);
    mTechniqueName.tidy(true, 0U);
  }

  /**
   * Address: 0x007D10C0 (FUN_007D10C0, ??0Cartographic@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes cartographic render-state defaults, color lanes, and one
   * self-linked list sentinel used by cartographic runtime storage.
   */
  Cartographic::Cartographic()
  {
    constexpr std::int32_t kOpaqueBlack = static_cast<std::int32_t>(0xFF000000u);

    mInitialized = false;

    for (float& value : mGridSizeCoeff) {
      value = 0.0f;
    }
    for (float& value : mTerrainSizeCoeff) {
      value = 0.0f;
    }
    mTerrainHeightScale = 0.0f;
    mElevMaximum = 0.0f;
    mElevMinimum = 0.0f;

    mHasElevationBounds = false;
    mSurfaceElevation = 0.0f;
    mWaterElevation = 0.0f;
    mDefaultElevation = 0.0f;

    for (std::int32_t& color : mHypsometricColors) {
      color = kOpaqueBlack;
    }

    // mUnknownLane58 is deliberately left uninitialized to match the binary
    // constructor, which skips this lane (0x54 -> 0x5C).

    mListSentinel = CreateCartographicListSentinel();
    mBatchCount = 0;

    // The eight GPU resource handles are zero-initialized empty shared_ptrs
    // (px = nullptr, pn.pi_ = nullptr) exactly as the ctor writes them; the
    // members' default constructors produce that state.
    mTopographicTexture.reset();
    mHypsometricTexture.reset();
    mElevTexture.reset();
    mTerrainVertexFormat.reset();
    mTerrainVertexBuffer.reset();
    mFrameVertexFormat.reset();
    mFrameVertexBuffer.reset();
    mQuadIndexBuffer.reset();
  }

  /**
   * Address: 0x007D11B0 (FUN_007D11B0, ??1Cartographic@Moho@@UAE@XZ)
   *
   * IDA signature:
   * void __thiscall Moho::Cartographic::~Cartographic(Moho::Cartographic* this);
   *
   * What it does:
   * Shuts down all cartographic render resources, releases retained handles,
   * clears decal-batch storage, and deletes the list sentinel.
   */
  Cartographic::~Cartographic()
  {
    Shutdown();
    ClearCartographicBatchList(*this);
    ::operator delete(mListSentinel);
    mListSentinel = nullptr;
  }

  /**
   * Address: 0x007D14B0 (FUN_007D14B0, ?Shutdown@Cartographic@Moho@@QAEXXZ)
   *
   * IDA signature:
   * void __stdcall Moho::Cartographic::Shutdown(Moho::Cartographic* this);
   *
   * What it does:
   * Clears cartographic decal batches, releases render/runtime handles, resets
   * projection state, and marks the runtime uninitialized.
   */
  void Cartographic::Shutdown()
  {
    ClearCartographicBatchList(*this);

    // Release order matches the binary exactly (FUN_007D14B0):
    // 0x6C, 0x64, 0x74, 0x94, 0x8C, 0x84, 0x7C, 0x9C.
    mHypsometricTexture.reset();
    mTopographicTexture.reset();
    mElevTexture.reset();
    mFrameVertexBuffer.reset();
    mFrameVertexFormat.reset();
    mTerrainVertexBuffer.reset();
    mTerrainVertexFormat.reset();
    mQuadIndexBuffer.reset();

    mSurfaceElevation = 0.0f;
    mWaterElevation = 0.0f;
    mDefaultElevation = 0.0f;
    mInitialized = false;
  }

  /**
   * Address: 0x007D1700 (FUN_007D1700, ?IsInitialized@Cartographic@Moho@@QBE_NXZ)
   *
   * What it does:
   * Returns whether the cartographic runtime lane has been initialized.
   */
  bool Cartographic::IsInitialized() const
  {
    return mInitialized;
  }

  /**
   * Address: 0x007D1710 (FUN_007D1710)
   *
   * What it does:
   * Builds one copied decal-batch node from source storage, then increments
   * owner count with legacy list overflow guard before relinking list heads.
   */
  std::int32_t InsertCartographicDecalBatchCopy(const CartographicDecalBatch& sourceBatch, Cartographic& owner)
  {
    CartographicListNode* const sentinel = owner.mListSentinel;
    CartographicListNode* const node = CreateCartographicBatchNode(sentinel, sentinel->mPrev, sourceBatch);

    constexpr std::int32_t kMaxNodeCountBeforeOverflow = 0x0234F72C;
    if (owner.mBatchCount == kMaxNodeCountBeforeOverflow) {
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      throw std::length_error("list<T> too long");
    }

    const std::int32_t newCount = owner.mBatchCount + 1;
    owner.mBatchCount = newCount;

    sentinel->mPrev = node;
    node->mPrev->mNext = node;
    return newCount;
  }

  /**
   * Address: 0x007D1740 (FUN_007D1740)
   *
   * What it does:
   * Unlinks and destroys one non-sentinel decal-batch node and returns the
   * successor node used by the legacy iterator-erase lane.
   */
  CartographicListNode* EraseCartographicDecalBatchNode(Cartographic& owner, CartographicListNode* const node)
  {
    CartographicListNode* const successor = node->mNext;
    if (node != owner.mListSentinel) {
      node->mPrev->mNext = successor;
      successor->mPrev = node->mPrev;
      node->mBatch.~CartographicDecalBatch();
      ::operator delete(node);
      --owner.mBatchCount;
    }

    return successor;
  }

  /**
   * Address: 0x007D1DF0 (FUN_007D1DF0, ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   * Mangled: ?WriteDecals@Cartographic@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
   *
   * What it does:
   * Writes the batch-count lane first, then serializes each intrusive
   * cartographic decal-batch node through its runtime payload view.
   */
  void Cartographic::WriteDecals(gpg::BinaryWriter& writer)
  {
    writer.Write(mBatchCount);

    CartographicListNode* const sentinel = mListSentinel;
    for (CartographicListNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      node->mBatch.Write(writer);
    }
  }

  /**
   * Address: 0x007D1D30 (FUN_007D1D30, ?ReadDecals@Cartographic@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
   * Mangled: ?ReadDecals@Cartographic@Moho@@QAEXIAAVBinaryReader@gpg@@@Z
   *
   * IDA signature:
   * void __thiscall Moho::Cartographic::ReadDecals(
   *   Moho::Cartographic* this, unsigned int a2, struct gpg::BinaryReader* a3);
   *
   * What it does:
   * Drops every existing cartographic decal-batch node, reads a fresh
   * batch count lane from the stream, and then deserializes each
   * archived batch through the
   * `CartographicDecalBatch(version, reader)` constructor. Each newly
   * constructed batch is inserted into the intrusive batch list via
   * `InsertCartographicDecalBatchCopy`, which handles the legacy VC8
   * `std::list<T>` overflow check at 0x0234F72C nodes and re-links the
   * sentinel/predecessor pair.
   *
   * The deserialize ctor allocates list-internal storage (decal
   * sentinel, copy-constructed decals from the reader) on the
   * stack-local `localBatch`; `InsertCartographicDecalBatchCopy` then
   * copy-constructs the persistent list node from `localBatch`, which
   * means the stack-local batch's storage is freed by its destructor
   * at the end of each iteration. Matches the binary's
   * `CartographicDecalBatch(&v9, a2, a3); ... ; ~CartographicDecalBatch(&v9)`
   * SEH-bracketed scope.
   *
   * Invocation chain (per caller-chain audit hook):
   *   Cartographic::ReadDecals (FUN_007D1D30)
   *     <- CWldTerrainRes::Load (FUN_008A1700, modern body not yet
   *        in src/sdk; the virtual is declared pure in CWldMap.h:311
   *        but the concrete CWldTerrainRes override is still
   *        pending). This recovery commit lands ReadDecals as the
   *        nearest-reachable layer in the chain.
   */
  void Cartographic::ReadDecals(
    const std::uint32_t version, gpg::BinaryReader& reader)
  {
    ClearCartographicBatchList(*this);

    std::int32_t batchCount = 0;
    reader.Read(reinterpret_cast<char*>(&batchCount), sizeof(batchCount));

    while (batchCount > 0) {
      CartographicDecalBatch localBatch(version, reader);
      (void)InsertCartographicDecalBatchCopy(localBatch, *this);
      --batchCount;
    }
  }

  /**
   * Address: 0x007D5650 (FUN_007D5650, ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
   * Mangled: ?Write@CartographicDecalBatch@Moho@@QAEXAAVBinaryWriter@gpg@@@Z
   *
   * What it does:
   * Writes batch header lanes, emits one decal-count dword, then serializes
   * each decal payload from the intrusive entry list.
  */
  void CartographicDecalBatch::Write(gpg::BinaryWriter& writer)
  {
    writer.Write(reinterpret_cast<const char*>(&mTechniqueName), sizeof(mTechniqueName));
    writer.Write(reinterpret_cast<const char*>(&mTexturePath), sizeof(mTexturePath));
    writer.Write(mDecals.mDecalCount);

    const CartographicDecalNode* const sentinel = mDecals.mDecalSentinel;
    for (const CartographicDecalNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      WriteCartographicDecalPayload(writer, node->mDecal);
    }
  }

  /**
   * Address: 0x007D5400 (FUN_007D5400, ?Read@CartographicDecalBatch@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
   * Mangled: ?Read@CartographicDecalBatch@Moho@@QAEXIAAVBinaryReader@gpg@@@Z
   *
   * IDA signature:
   * void __thiscall Moho::CartographicDecalBatch::Read(
   *   Moho::CartographicDecalBatch* this, unsigned int a2, gpg::BinaryReader* a3);
   *
   * What it does:
   * Deserializes one batch payload from `reader` at the given map
   * version. The wire format is:
   *
   *   - msvc8::string mTechniqueName  (NUL-terminated; absent in
   *     legacy versions below 0x3C where the field defaults to "Decal")
   *   - msvc8::string mTexturePath    (NUL-terminated)
   *   - int32         decalCount
   *   - for each decal:
   *       - 8 bytes: mVertexData[0..1]
   *       - 4 bytes (via stack temp): mVertexData[2]
   *       - 8 bytes: mVertexData[3..4]
   *       - 8 bytes: mVertexData[5..6]
   *       - 8 bytes: mVertexData[7..8]
   *
   * Each decoded decal is appended to `mDecals` via
   * `AppendCartographicDecalListNodeBeforeSentinel`, which creates a
   * new `CartographicDecalNode` linked before the list sentinel and
   * bumps `mDecalCount`. `Shutdown()` is invoked first to release any
   * prior batch state — matching the binary's leading
   * `CartographicDecalBatch::Shutdown(this)` call.
   *
   * Invocation chain (per caller-chain audit hook):
   *   CartographicDecalBatch::Read (FUN_007D5400)
   *     <- CartographicDecalBatch(version, reader) deserialize ctor
   *        (FUN_007D4BE0, this commit)
   *     <- Cartographic::ReadDecals (FUN_007D1D30, this commit)
   *     <- CWldTerrainRes::Load (FUN_008A1700, still pending modern
   *        body — the virtual is declared in CWldMap.h:311 but the
   *        concrete override body is not yet recovered, so this
   *        chain's top remains orphan until that lands).
   */
  void CartographicDecalBatch::Read(
    const std::uint32_t version, gpg::BinaryReader& reader)
  {
    Shutdown();

    // 1. Technique name (defaulted to "Decal" for legacy maps).
    msvc8::string techniqueName{};
    if (version < 0x3Cu) {
      techniqueName.assign("Decal", 5u);
    } else {
      reader.ReadString(&techniqueName);
    }
    mTechniqueName.assign(techniqueName, 0u, ~0u);

    // 2. Texture resource path.
    msvc8::string texturePath{};
    reader.ReadString(&texturePath);
    mTexturePath.assign(texturePath, 0u, ~0u);

    // 3. Decal payload count.
    std::int32_t decalCount = 0;
    reader.Read(reinterpret_cast<char*>(&decalCount), sizeof(decalCount));

    // 4. Per-decal nine-float instance payload. The binary splits the
    //    36 bytes into 8 + 4 + 8 + 8 + 8 byte reads with the middle
    //    lane (mVertexData[2]) routed through a stack temporary — that
    //    split mirrors the original named field layout (we don't have
    //    decompiled names for them yet) so we keep the same read shape
    //    for byte-faithful stream consumption.
    for (std::int32_t remaining = decalCount; remaining > 0; --remaining) {
      CartographicDecal decal{};

      reader.Read(reinterpret_cast<char*>(&decal.mVertexData[0]), 8u);

      float lane2 = 0.0f;
      reader.Read(reinterpret_cast<char*>(&lane2), 4u);
      decal.mVertexData[2] = lane2;

      reader.Read(reinterpret_cast<char*>(&decal.mVertexData[3]), 8u);
      reader.Read(reinterpret_cast<char*>(&decal.mVertexData[5]), 8u);
      reader.Read(reinterpret_cast<char*>(&decal.mVertexData[7]), 8u);

      AppendCartographicDecalListNodeBeforeSentinel(mDecals, decal);
    }
  }

  /**
   * Address: 0x007D56C0 (FUN_007D56C0, sub_7D56C0)
   *
   * What it does:
   * Lazily creates the cartographic decal vertex declaration, quad vertex
   * buffer, dynamic decal-instance buffer, and quad index buffer.
   */
  void CartographicDecalBatch::InitializeRenderResources()
  {
    if (mVertexFormat) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    boost::shared_ptr<gpg::gal::VertexFormatD3D9> vertexFormat;
    device->CreateVertexFormat(&vertexFormat, kCartographicVertexFormatToken);
    mVertexFormat = vertexFormat;

    gpg::gal::VertexBufferContext quadVertexContext{};
    quadVertexContext.type_ = 2U;
    quadVertexContext.usage_ = 1U;
    quadVertexContext.width_ = kCartographicQuadVertexCount;
    quadVertexContext.height_ = static_cast<std::uint32_t>(sizeof(float) * 2U);

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> quadVertexBuffer;
    device->CreateVertexBuffer(&quadVertexBuffer, &quadVertexContext);
    mQuadVertexBuffer = quadVertexBuffer;

    void* const quadVertexData = mQuadVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None);
    std::memcpy(quadVertexData, kCartographicQuadVertices.data(), sizeof(kCartographicQuadVertices));
    (void)mQuadVertexBuffer->Unlock();

    gpg::gal::VertexBufferContext instanceVertexContext{};
    instanceVertexContext.type_ = 3U;
    instanceVertexContext.usage_ = 2U;
    instanceVertexContext.width_ = kCartographicMaxDecalInstances;
    instanceVertexContext.height_ = static_cast<std::uint32_t>(sizeof(float) * kCartographicInstanceFloatCount);

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> instanceVertexBuffer;
    device->CreateVertexBuffer(&instanceVertexBuffer, &instanceVertexContext);
    mInstanceVertexBuffer = instanceVertexBuffer;

    gpg::gal::IndexBufferContext indexContext{};
    indexContext.type_ = 1U;
    indexContext.format_ = 1U;
    indexContext.size_ = kCartographicQuadPrimitiveCountInput;

    boost::shared_ptr<gpg::gal::IndexBufferD3D9> indexBuffer;
    device->CreateIndexBuffer(&indexBuffer, &indexContext);
    mIndexBuffer = indexBuffer;

    auto* const indexWords = reinterpret_cast<std::uint32_t*>(
      mIndexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None)
    );
    std::memcpy(indexWords, kCartographicQuadIndexWords.data(), sizeof(kCartographicQuadIndexWords));
    (void)mIndexBuffer->Unlock();
  }

  /**
   * Address: 0x007D59C0 (FUN_007D59C0, sub_7D59C0)
   *
   * What it does:
   * Lazily resolves the decal texture resource named by the texture-path
   * string lane and retains its base GAL texture handle.
   */
  void CartographicDecalBatch::ResolveDecalTexture()
  {
    if (mDecalTexture) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    ID3DDeviceResources::TextureResourceHandle textureResource;
    resources->GetTexture(textureResource, mTexturePath.c_str(), 0, true);
    if (textureResource) {
      textureResource->GetTexture(mDecalTexture);
    }
  }

  /**
   * Address: 0x007D5AD0 (FUN_007D5AD0, sub_7D5AD0)
   *
   * What it does:
   * Uploads each decal node's nine-float instance payload into the dynamic
   * decal vertex buffer when the dirty flag is set.
   */
  void CartographicDecalBatch::UploadDecalVerticesIfDirty()
  {
    if (!mNeedsVertexUpload) {
      return;
    }

    float* writeCursor = static_cast<float*>(mInstanceVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None));
    CartographicDecalNode* const sentinel = mDecals.mDecalSentinel;
    for (CartographicDecalNode* node = sentinel->mNext; node != sentinel; node = node->mNext) {
      std::memcpy(writeCursor, node->mDecal.mVertexData, sizeof(node->mDecal.mVertexData));
      writeCursor += kCartographicInstanceFloatCount;
    }

    (void)mInstanceVertexBuffer->Unlock();
    mNeedsVertexUpload = false;
  }

  /**
   * Address: 0x007D50D0 (FUN_007D50D0, sub_7D50D0)
   *
   * What it does:
   * Ensures cartographic decal GPU resources and texture state exist, uploads
   * dirty decal instance vertices, binds the cartographic effect, and draws
   * one instanced quad pass for each technique pass.
   */
  void CartographicDecalBatch::Render(const GeomCamera3& camera)
  {
    InitializeRenderResources();
    const std::int32_t decalCount = mDecals.mDecalCount;
    ResolveDecalTexture();

    if (decalCount == 0 || !mDecalTexture) {
      return;
    }

    UploadDecalVerticesIfDirty();

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = GetCartographicBaseEffectD3D9();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique(mTechniqueName.c_str());

    device->SetVertexDeclaration(mVertexFormat);
    device->SetVertexBuffer(0U, mQuadVertexBuffer, decalCount, 0);
    device->SetVertexBuffer(1U, mInstanceVertexBuffer, 1, 0);
    device->SetBufferIndices(mIndexBuffer);

    effect->SetMatrix("viewMatrix")->SetMatrix4x4(&camera.view);
    effect->SetMatrix("projMatrix")->SetMatrix4x4(&camera.projection);
    effect->SetMatrix("decalTexture")->SetTexture(mDecalTexture);

    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));
      gpg::gal::DrawIndexedContext drawContext(
        static_cast<int>(kCartographicTopologyTriangleList),
        static_cast<int>(kCartographicQuadVertexCount),
        static_cast<int>(kCartographicQuadPrimitiveCountInput),
        0,
        0
      );
      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x007D1E50 (FUN_007D1E50, ?GetEffect@Cartographic@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Looks up the `"cartographic"` D3D effect from the active device resources
   * and aliases its base effect handle into the public GAL effect type.
   */
  boost::shared_ptr<gpg::gal::Effect> Cartographic::GetEffect()
  {
    boost::shared_ptr<gpg::gal::EffectD3D9> baseEffect = GetCartographicBaseEffectD3D9();
    return boost::shared_ptr<gpg::gal::Effect>(
      reinterpret_cast<gpg::gal::Effect*>(baseEffect.get()),
      CartographicEffectAliasDeleter(baseEffect)
    );
  }

  /**
   * Address: 0x007D2E40 (FUN_007D2E40, ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z)
   * Mangled: ?RenderParticles@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
   *
   * What it does:
   * Forwards one cartographic particle pass to `sWorldParticles::RenderEffects`
   * with fixed flags `(renderWaterSurface=0, suppressTLight=1)`.
   */
  void Cartographic::RenderParticles(const std::int32_t tick, const float frameAlpha, const GeomCamera3& camera)
  {
    (void)moho::sWorldParticles.RenderEffects(const_cast<GeomCamera3*>(&camera), 0, 1, tick, frameAlpha);
  }
  /**
   * Address: 0x007D1E90 (FUN_007D1E90)
   * Mangled: ?InitializeFrame@Cartographic@Moho@@AAEXXZ
   *
   * IDA signature:
   * void __usercall Moho::Cartographic::InitializeFrame(Moho::Cartographic *this@<esi>);
   *
   * What it does:
   * Creates the cartographic frame vertex declaration (format token 7), the
   * four-vertex / 24-byte-stride frame vertex buffer, and the shared quad
   * index buffer, then uploads the same two-triangle index list the decal
   * batches use.
   */
  void Cartographic::InitializeFrame()
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    boost::shared_ptr<gpg::gal::VertexFormatD3D9> frameVertexFormat;
    device->CreateVertexFormat(&frameVertexFormat, kCartographicFrameVertexFormatToken);
    mFrameVertexFormat = frameVertexFormat;

    gpg::gal::VertexBufferContext frameVertexContext(
      kCartographicFrameVertexCount,
      kCartographicFrameVertexStride,
      kCartographicBufferTypeManaged,
      kCartographicBufferUsageDynamic
    );

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> frameVertexBuffer;
    device->CreateVertexBuffer(&frameVertexBuffer, &frameVertexContext);
    mFrameVertexBuffer = frameVertexBuffer;

    gpg::gal::IndexBufferContext quadIndexContext(
      kCartographicQuadIndexCount,
      kCartographicIndexFormat16Bit,
      kCartographicBufferUsageStatic
    );

    boost::shared_ptr<gpg::gal::IndexBufferD3D9> quadIndexBuffer;
    device->CreateIndexBuffer(&quadIndexBuffer, &quadIndexContext);
    mQuadIndexBuffer = quadIndexBuffer;

    auto* const indexWords = reinterpret_cast<std::uint32_t*>(
      mQuadIndexBuffer->Lock(0U, sizeof(kCartographicQuadIndexWords), gpg::gal::MohoD3DLockFlags::None)
    );
    std::memcpy(indexWords, kCartographicQuadIndexWords.data(), sizeof(kCartographicQuadIndexWords));
    (void)mQuadIndexBuffer->Unlock();
  }

  /**
   * Address: 0x007D24F0 (FUN_007D24F0)
   * Mangled: ?InitializeTerrainTextures@Cartographic@Moho@@AAEXABVCHeightField@2@HHH@Z
   *
   * IDA signature:
   * void __thiscall Moho::Cartographic::InitializeTerrainTextures(
   *   Moho::Cartographic *this, const struct Moho::CHeightField *a2, int a3, int a4, int a5);
   *
   * What it does:
   * Builds the three cartographic lookup textures from the elevation band
   * that `InitializeTerrain` just derived:
   *
   *   - `mElevTexture`: a `gridWidth x gridHeight` half-float surface holding
   *     the heightfield sampled through the 3x3 cartographic kernel and
   *     normalized into the tier-0 elevation band;
   *   - `mHypsometricTexture`: a 256x1 ARGB ramp that assigns the abyss, deep
   *     and shore palette entries to everything at or below the corresponding
   *     normalized water elevation and fades palette entry 3 into entry 4
   *     across the land band;
   *   - `mTopographicTexture`: a 256x1 8-bit ramp quantized into
   *     `clamp(topographicSamples, 1, 100)` equal contour bands over the land
   *     range, shaded into [16, 255] and zeroed below the water line.
   */
  void Cartographic::InitializeTerrainTextures(
    const CHeightField& heightField,
    const std::int32_t gridWidth,
    const std::int32_t gridHeight,
    const std::int32_t topographicSamples
  )
  {
    const std::int32_t bandCount = std::clamp(
      topographicSamples, kCartographicMinTopographicBands, kCartographicMaxTopographicBands
    );

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    // Everything below works in "normalized elevation": 0 at the tier box
    // floor, 1 at its ceiling. A degenerate band keeps a unit scale so the
    // ramps stay well defined.
    const float elevationSpan = mElevMaximum - mElevMinimum;
    const float inverseElevationSpan = elevationSpan > 0.0f ? 1.0f / elevationSpan : 1.0f;

    const float normalizedSurface = (mSurfaceElevation - mElevMinimum) * inverseElevationSpan;
    const float normalizedWater = (mWaterElevation - mElevMinimum) * inverseElevationSpan;
    const float normalizedDefault = (mDefaultElevation - mElevMinimum) * inverseElevationSpan;

    const float sampleStepX =
      static_cast<float>(heightField.width - 1) / static_cast<float>(gridWidth - 1);
    const float sampleStepZ =
      static_cast<float>(heightField.height - 1) / static_cast<float>(gridHeight - 1);

    // 1. Half-float elevation map at cartographic grid resolution.
    {
      gpg::gal::TextureContext elevationContext;
      FillCartographicTextureContext(
        elevationContext,
        kCartographicElevationTextureFormat,
        static_cast<std::uint32_t>(gridWidth),
        static_cast<std::uint32_t>(gridHeight)
      );

      boost::shared_ptr<gpg::gal::TextureD3D9> elevationTexture;
      device->CreateTexture(&elevationTexture, &elevationContext);
      mElevTexture = elevationTexture;

      auto* rowCursor = static_cast<std::uint16_t*>(LockWholeCartographicTexture(*mElevTexture));
      for (std::int32_t z = 0; z < gridHeight; ++z) {
        const auto sampleZ = static_cast<std::int32_t>(static_cast<float>(z) * sampleStepZ);
        std::uint16_t* texel = rowCursor;
        for (std::int32_t x = 0; x < gridWidth; ++x) {
          const auto sampleX = static_cast<std::int32_t>(static_cast<float>(x) * sampleStepX);
          const float elevation = SampleCartographicHeightKernel(
            heightField, sampleX, sampleZ, mElevMinimum, inverseElevationSpan
          );
          *texel = PackFloat32AsHalfFloat(elevation);
          texel += kCartographicElevationTexelWordStride;
        }
        rowCursor += kCartographicElevationTexelWordStride * gridWidth;
      }
      (void)mElevTexture->Unlock(0);
    }

    // 2. Hypsometric colour ramp.
    {
      gpg::gal::TextureContext hypsometricContext;
      FillCartographicTextureContext(
        hypsometricContext,
        kCartographicHypsometricTextureFormat,
        static_cast<std::uint32_t>(kCartographicRampTexelCount),
        1U
      );

      boost::shared_ptr<gpg::gal::TextureD3D9> hypsometricTexture;
      device->CreateTexture(&hypsometricTexture, &hypsometricContext);
      mHypsometricTexture = hypsometricTexture;

      auto* const rampTexels =
        static_cast<std::int32_t*>(LockWholeCartographicTexture(*mHypsometricTexture));
      for (std::int32_t texelIndex = 0; texelIndex < kCartographicRampTexelCount; ++texelIndex) {
        const float normalized = static_cast<float>(texelIndex) * kCartographicInverseRampRange;

        if (!mHasElevationBounds) {
          rampTexels[texelIndex] = BlendPackedColor(
            mHypsometricColors[3],
            mHypsometricColors[4],
            (normalized - normalizedSurface) / (1.0f - normalizedSurface)
          );
        } else if (normalizedDefault >= normalized) {
          rampTexels[texelIndex] = mHypsometricColors[0];
        } else if (normalizedWater >= normalized) {
          rampTexels[texelIndex] = mHypsometricColors[1];
        } else if (normalizedSurface >= normalized) {
          rampTexels[texelIndex] = mHypsometricColors[2];
        } else {
          rampTexels[texelIndex] = BlendPackedColor(
            mHypsometricColors[3],
            mHypsometricColors[4],
            (normalized - normalizedSurface) / (1.0f - normalizedSurface)
          );
        }
      }
      (void)mHypsometricTexture->Unlock(0);
    }

    // 3. Topographic contour ramp. The land range above the deep-water line is
    //    split into `bandCount` equal bands; each ramp texel takes the shade of
    //    the first band whose ceiling reaches it.
    const float landSpan = 1.0f - normalizedWater;
    const float bandStep = landSpan / static_cast<float>(bandCount);

    std::array<float, static_cast<std::size_t>(kCartographicMaxTopographicBands) + 1U> bandCeilings{};
    bandCeilings[0] = bandStep + normalizedWater;
    for (std::int32_t band = 1; band < bandCount; ++band) {
      bandCeilings[static_cast<std::size_t>(band)] =
        bandCeilings[static_cast<std::size_t>(band) - 1U] + bandStep;
    }

    {
      gpg::gal::TextureContext topographicContext;
      FillCartographicTextureContext(
        topographicContext,
        kCartographicTopographicTextureFormat,
        static_cast<std::uint32_t>(kCartographicRampTexelCount),
        1U
      );

      boost::shared_ptr<gpg::gal::TextureD3D9> topographicTexture;
      device->CreateTexture(&topographicTexture, &topographicContext);
      mTopographicTexture = topographicTexture;

      auto* const rampTexels =
        static_cast<std::uint8_t*>(LockWholeCartographicTexture(*mTopographicTexture));
      for (std::int32_t texelIndex = 0; texelIndex < kCartographicRampTexelCount; ++texelIndex) {
        const float normalized = static_cast<float>(texelIndex) * kCartographicInverseRampRange;

        if (mHasElevationBounds && normalizedWater >= normalized) {
          rampTexels[texelIndex] = 0U;
          continue;
        }

        std::int32_t band = 0;
        while (band < bandCount && bandCeilings[static_cast<std::size_t>(band)] < normalized) {
          ++band;
        }

        const float shade =
          (((bandCeilings[static_cast<std::size_t>(band)] - normalizedWater) / landSpan)
           * kCartographicContourShadeScale)
          + kCartographicContourShadeBias;
        rampTexels[texelIndex] = static_cast<std::uint8_t>(std::clamp(
          static_cast<std::int32_t>(shade),
          kCartographicContourShadeMinimum,
          kCartographicContourShadeMaximum
        ));
      }
      (void)mTopographicTexture->Unlock(0);
    }
  }

  /**
   * Address: 0x007D20F0 (FUN_007D20F0)
   * Mangled: ?InitializeTerrain@Cartographic@Moho@@AAEXPAVIWldTerrainRes@2@HIIIII@Z
   *
   * IDA signature:
   * int __thiscall Moho::Cartographic::InitializeTerrain(
   *   int this, int a2, int a3, int a4, int a5, int a6, int a7, int a8);
   *
   * What it does:
   * Derives every cartographic shader constant from the terrain resource's
   * heightfield and its owning map:
   *
   *   - `mGridSizeCoeff` / `mTerrainSizeCoeff` from the half-resolution
   *     cartographic grid versus the full heightfield sample span;
   *   - `mElevMinimum` / `mElevMaximum` from the tier-0 bounding box;
   *   - the three elevation lanes from the map's water configuration, falling
   *     back to the tier-box floor when the map has no water at all;
   *   - the five hypsometric palette entries straight from the caller.
   *
   * It then builds the three lookup textures and uploads the ground quad -
   * four `int16` (x, elevation, z, 1) corners spanning the whole heightfield
   * at the water-surface elevation, expressed back in raw height words.
   */
  void Cartographic::InitializeTerrain(
    IWldTerrainRes* const terrain,
    const std::int32_t topographicSamples,
    const std::uint32_t hypsometricColor0,
    const std::uint32_t hypsometricColor1,
    const std::uint32_t hypsometricColor2,
    const std::uint32_t hypsometricColor3,
    const std::uint32_t hypsometricColor4
  )
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    STIMap& map = CartographicTerrainMap(*terrain);
    const CHeightField& heightField = *map.GetHeightField();

    const std::int32_t sampleSpanX = heightField.width - 1;
    const std::int32_t sampleSpanZ = heightField.height - 1;

    // The cartographic grid is half the heightfield resolution on each axis.
    const std::int32_t gridWidth = sampleSpanX >> 1;
    const std::int32_t gridHeight = sampleSpanZ >> 1;

    // Inlined `CHeightField::GetBounds3D()` (0x00577660): tier count from
    // `mGrids`, then `GetTierBox(0, 0, tierCount)` at 0x007D215D.
    const Wm3::AxisAlignedBox3f tierBox = heightField.GetBounds3D();

    mGridSizeCoeff[0] = 1.0f / static_cast<float>(gridWidth);
    mGridSizeCoeff[1] = 1.0f / static_cast<float>(gridHeight);
    mGridSizeCoeff[2] = 0.0f;
    mGridSizeCoeff[3] = 1.0f;

    mTerrainSizeCoeff[0] = static_cast<float>(gridWidth) / static_cast<float>(heightField.width - 1);
    mTerrainSizeCoeff[1] = static_cast<float>(gridHeight) / static_cast<float>(heightField.height - 1);
    mTerrainSizeCoeff[2] = 0.0f;
    mTerrainSizeCoeff[3] = 1.0f;

    mTerrainHeightScale = kCartographicHeightWordScale;
    mElevMaximum = tierBox.Max.y;
    mElevMinimum = tierBox.Min.y;

    // The binary re-tests `mWaterEnabled` inside each of the three branches:
    // the inlined STIMap water accessors carry their own guard and MSVC could
    // not fold it against the outer test. The inner test can never fail once
    // the outer one has passed, so the sentinel is unreachable in practice -
    // it is spelled out here because the shipped code does select it.
    mHasElevationBounds = map.mWaterEnabled != 0U;
    const float waterSurfaceElevation =
      map.mWaterEnabled != 0U ? map.mWaterElevation : kCartographicNoWaterElevation;
    const float waterDeepElevation =
      map.mWaterEnabled != 0U ? map.mWaterElevationDeep : kCartographicNoWaterElevation;

    mSurfaceElevation = mHasElevationBounds ? waterSurfaceElevation : tierBox.Min.y;
    mWaterElevation = mHasElevationBounds ? waterDeepElevation : tierBox.Min.y;
    mDefaultElevation = mHasElevationBounds ? waterDeepElevation : tierBox.Min.y;

    mHypsometricColors[0] = static_cast<std::int32_t>(hypsometricColor0);
    mHypsometricColors[1] = static_cast<std::int32_t>(hypsometricColor1);
    mHypsometricColors[2] = static_cast<std::int32_t>(hypsometricColor2);
    mHypsometricColors[3] = static_cast<std::int32_t>(hypsometricColor3);
    mHypsometricColors[4] = static_cast<std::int32_t>(hypsometricColor4);

    InitializeTerrainTextures(heightField, gridWidth, gridHeight, topographicSamples);

    boost::shared_ptr<gpg::gal::VertexFormatD3D9> terrainVertexFormat;
    device->CreateVertexFormat(&terrainVertexFormat, kCartographicTerrainVertexFormatToken);
    mTerrainVertexFormat = terrainVertexFormat;

    // The ground quad lives in heightfield sample space with the elevation
    // carried as a raw height word, so it is 4 x int16 per corner.
    const auto elevationWord = static_cast<std::int16_t>(
      static_cast<std::int32_t>(mSurfaceElevation * kCartographicHeightWordsPerUnit)
    );
    const auto cornerX = static_cast<std::int16_t>(sampleSpanX);
    const auto cornerZ = static_cast<std::int16_t>(sampleSpanZ);

    const std::array<std::int16_t, 16> terrainQuadVertices{
      0, elevationWord, cornerZ, 1,
      0, elevationWord, 0, 1,
      cornerX, elevationWord, cornerZ, 1,
      cornerX, elevationWord, 0, 1,
    };

    gpg::gal::VertexBufferContext terrainVertexContext(
      kCartographicTerrainVertexCount,
      kCartographicTerrainVertexStride,
      kCartographicBufferTypeManaged,
      kCartographicBufferUsageStatic
    );

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> terrainVertexBuffer;
    device->CreateVertexBuffer(&terrainVertexBuffer, &terrainVertexContext);
    mTerrainVertexBuffer = terrainVertexBuffer;

    void* const vertexData = mTerrainVertexBuffer->Lock(
      0U, sizeof(terrainQuadVertices), gpg::gal::MohoD3DLockFlags::None
    );
    std::memcpy(vertexData, terrainQuadVertices.data(), sizeof(terrainQuadVertices));
    (void)mTerrainVertexBuffer->Unlock();
  }

  /**
   * Address: 0x007D13E0 (FUN_007D13E0)
   * Mangled: ?Initialize@Cartographic@Moho@@QAEXPAVIWldTerrainRes@2@IIIII@Z
   *
   * IDA signature:
   * int __thiscall Moho::Cartographic::Initialize(Moho::CWldTerrainRes *this, Moho::Cartographic *a2);
   *
   * What it does:
   * Brings the cartographic view up: frame resources first, then the terrain
   * pass fed with the terrain resource's own topographic sample count and
   * hypsometric palette, then the initialized flag. The whole sequence sits
   * in an EH scope whose funclet (0x007D1490) calls `Shutdown()` and rethrows,
   * so a half-built cartographic view never survives a failed initialization.
   *
   * The five `hypsometricColor*` parameters are declared by the mangled symbol
   * but the shipped body never reads them - it fetches the same five lanes
   * from `terrain` itself, after `InitializeFrame()`. Whole-program
   * optimization consequently removed them from the single call site
   * (0x007F8C45 pushes only `this` and passes the terrain resource in `ecx`).
   * Keeping the declared arity preserves the symbol; keeping the binary's own
   * reads preserves the behavior no matter what a future caller passes.
   */
  void Cartographic::Initialize(
    IWldTerrainRes* const terrain,
    [[maybe_unused]] const std::uint32_t hypsometricColor0,
    [[maybe_unused]] const std::uint32_t hypsometricColor1,
    [[maybe_unused]] const std::uint32_t hypsometricColor2,
    [[maybe_unused]] const std::uint32_t hypsometricColor3,
    [[maybe_unused]] const std::uint32_t hypsometricColor4
  )
  {
    try {
      InitializeFrame();

      // MSVC evaluates the argument list right to left, which is the order the
      // shipped code queries these lanes in: colour 4 down to colour 0, then
      // the sample count.
      InitializeTerrain(
        terrain,
        terrain->GetTopographicSamples(),
        terrain->GetHypsometricColor(0),
        terrain->GetHypsometricColor(1),
        terrain->GetHypsometricColor(2),
        terrain->GetHypsometricColor(3),
        terrain->GetHypsometricColor(4)
      );

      mInitialized = true;
    } catch (...) {
      Shutdown();
      throw;
    }
  }

  /**
   * Address: 0x007D2CB0 (FUN_007D2CB0)
   * Mangled: ?RenderMeshes@Cartographic@Moho@@AAEXHMABVGeomCamera3@2@@Z
   *
   * IDA signature:
   * void __usercall Moho::Cartographic::RenderMeshes(
   *   Moho::Cartographic *this@<edi>, int gameTick, float deltaFrame,
   *   const Moho::GeomCamera3 *camera);
   *
   * What it does:
   * Binds this view's hypsometric ramp into the shared `"mesh"` effect
   * (`ID3DDeviceResources::FindEffect`, dispatched at +0x4C, 0x007D2CEF) and
   * makes that effect current, then rebuilds the global mesh batch map for the
   * frame and draws it through the mesh renderer's cartographic pass fed with
   * the water-surface elevation and the tier elevation band.
   *
   * The batch fade plane is row 1 of the camera's viewport matrix
   * (`camera + 0x294` = `viewport@0x284 + 0x10`, 0x007D2D70), the same lane
   * `WRenViewport::Render` passes.
   */
  void Cartographic::RenderMeshes(
    const std::int32_t gameTick,
    const float deltaFrame,
    const GeomCamera3& camera
  )
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DEffect* const meshEffect = resources->FindEffect("mesh");

    const boost::shared_ptr<gpg::gal::EffectD3D9> meshBaseEffect = meshEffect->GetBaseEffect();
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> hypsometricTextureVar =
      meshBaseEffect->SetMatrix("hypsometricTexture");
    hypsometricTextureVar->SetTexture(mHypsometricTexture);

    (void)device->SetCurEffect(meshEffect);

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    meshRenderer->Batch(gameTick, deltaFrame, camera, camera.viewport.r[1]);
    meshRenderer->RenderCartographic(
      mSurfaceElevation,
      mElevMinimum,
      mElevMaximum,
      camera,
      meshRenderer->meshes
    );
  }

  /**
   * Address: 0x007D2EA0 (FUN_007D2EA0)
   * Mangled: ?RenderTerrainStage0@Cartographic@Moho@@AAEXABVGeomCamera3@2@_N@Z
   *
   * IDA signature:
   * void __usercall Moho::Cartographic::RenderTerrainStage0(
   *   Moho::Cartographic *this@<edx>, const Moho::GeomCamera3 *camera@<ecx>, bool mirrored);
   *
   * What it does:
   * Paints the cartographic terrain into whatever offscreen frame is currently
   * bound. Clears it to opaque black, resolves the `"cartographic"` effect,
   * binds the `"Terrain_Stage0"` technique together with the camera matrices,
   * the four shader coefficient / elevation scalars, the two `float4`
   * coefficient lanes and the three lookup textures, then draws the terrain
   * ground quad once per technique pass.
   *
   * `mirrored` is declared by the mangled symbol but neither passed by the
   * shipped call site (0x007D19E6..0x007D19EF pushes nothing; the body is a
   * bare `retn`) nor read by the shipped body, so it stays unread here too.
   */
  void Cartographic::RenderTerrainStage0(const GeomCamera3& camera, [[maybe_unused]] const bool mirrored)
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    device->Clear(
      true,
      true,
      true,
      kCartographicFrameClearColor,
      kCartographicClearDepth,
      kCartographicClearStencil
    );

    const boost::shared_ptr<gpg::gal::Effect> effect = GetEffect();
    gpg::gal::EffectD3D9& cartographicEffect = CartographicEffectInterface(effect);

    const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique =
      cartographicEffect.SetTechnique("Terrain_Stage0");

    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> viewMatrixVar =
      cartographicEffect.SetMatrix("viewMatrix");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> projMatrixVar =
      cartographicEffect.SetMatrix("projMatrix");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> gridSizeCoeffVar =
      cartographicEffect.SetMatrix("gridSizeCoeff");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> terrainSizeCoeffVar =
      cartographicEffect.SetMatrix("terrainSizeCoeff");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> terrainHeightScaleVar =
      cartographicEffect.SetMatrix("terrainHeightScale");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> elevMaximumVar =
      cartographicEffect.SetMatrix("elevMaximum");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> elevMinimumVar =
      cartographicEffect.SetMatrix("elevMinimum");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> elevTextureVar =
      cartographicEffect.SetMatrix("elevTexture");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> hypsometricTextureVar =
      cartographicEffect.SetMatrix("hypsometricTexture");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> topographicTextureVar =
      cartographicEffect.SetMatrix("topographicTexture");

    viewMatrixVar->SetMatrix4x4(&camera.view);
    projMatrixVar->SetMatrix4x4(&camera.projection);
    // Slot 7 (+0x1C) binds a `float4`; both coefficient lanes are four floats.
    gridSizeCoeffVar->Func4(mGridSizeCoeff);
    terrainSizeCoeffVar->Func4(mTerrainSizeCoeff);
    terrainHeightScaleVar->SetFloat(mTerrainHeightScale);
    elevMaximumVar->SetFloat(mElevMaximum);
    elevMinimumVar->SetFloat(mElevMinimum);
    elevTextureVar->SetTexture(mElevTexture);
    hypsometricTextureVar->SetTexture(mHypsometricTexture);
    topographicTextureVar->SetTexture(mTopographicTexture);

    device->SetVertexDeclaration(mTerrainVertexFormat);
    device->SetVertexBuffer(0U, mTerrainVertexBuffer, 1, 0);
    device->SetBufferIndices(mQuadIndexBuffer);

    const auto passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));
      gpg::gal::DrawIndexedContext drawContext(
        static_cast<int>(kCartographicTopologyTriangleList),
        static_cast<int>(kCartographicQuadVertexCount),
        static_cast<int>(kCartographicQuadPrimitiveCountInput),
        0,
        0
      );
      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x007D3580 (FUN_007D3580)
   * Mangled: ?RenderTerrainStage1@Cartographic@Moho@@AAEXH
   *          V?$shared_ptr@VRenderTarget@gal@gpg@@@boost@@@Z
   *
   * IDA signature:
   * void __usercall Moho::Cartographic::RenderTerrainStage1(
   *   Moho::Cartographic *this, int headIndex,
   *   boost::shared_ptr<gpg::gal::RenderTarget> colorTarget);
   *
   * What it does:
   * Composites the offscreen cartographic frame back onto the head. Clears the
   * head to opaque black, rewrites the four-corner screen quad in the frame
   * vertex buffer to cover the head's render target, then draws it once per
   * pass of the `"Terrain_Stage1"` technique with the head dimensions bound as
   * `frameWidth` / `frameHeight` and the offscreen colour target bound as
   * `frameTexture` (`EffectVariableD3D9` slot 3, +0x0C, at 0x007D38BC).
   *
   * The quad is half-texel corrected on both axes and carries `z = rhw = 1`, so
   * it is a pre-transformed full-target blit.
   */
  void Cartographic::RenderTerrainStage1(
    const std::int32_t headIndex,
    boost::shared_ptr<gpg::gal::RenderTargetD3D9> colorTarget
  )
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const gpg::gal::RenderTargetContext& headTarget =
      CartographicHeadRenderTargetContext(*device, static_cast<unsigned int>(headIndex));

    device->Clear(
      true,
      true,
      true,
      kCartographicFrameClearColor,
      kCartographicClearDepth,
      kCartographicClearStencil
    );

    const auto frameWidth = static_cast<float>(static_cast<std::int32_t>(headTarget.width_));
    const auto frameHeight = static_cast<float>(static_cast<std::int32_t>(headTarget.height_));

    const std::array<float, kCartographicFrameVertexFloatCount> frameQuad =
      BuildCartographicFrameQuad(frameWidth, frameHeight);

    void* const vertexData = mFrameVertexBuffer->Lock(
      0U, kCartographicFrameVertexByteSize, gpg::gal::MohoD3DLockFlags::Discard
    );
    std::memcpy(vertexData, frameQuad.data(), kCartographicFrameVertexByteSize);
    (void)mFrameVertexBuffer->Unlock();

    const boost::shared_ptr<gpg::gal::Effect> effect = GetEffect();
    gpg::gal::EffectD3D9& cartographicEffect = CartographicEffectInterface(effect);

    const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique =
      cartographicEffect.SetTechnique("Terrain_Stage1");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> frameWidthVar =
      cartographicEffect.SetMatrix("frameWidth");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> frameHeightVar =
      cartographicEffect.SetMatrix("frameHeight");
    const boost::shared_ptr<gpg::gal::EffectVariableD3D9> frameTextureVar =
      cartographicEffect.SetMatrix("frameTexture");

    device->SetVertexDeclaration(mFrameVertexFormat);
    device->SetVertexBuffer(0U, mFrameVertexBuffer, 1, 0);
    device->SetBufferIndices(mQuadIndexBuffer);

    frameWidthVar->SetFloat(frameWidth);
    frameHeightVar->SetFloat(frameHeight);
    frameTextureVar->Func3(colorTarget);

    const auto passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));
      gpg::gal::DrawIndexedContext drawContext(
        static_cast<int>(kCartographicTopologyTriangleList),
        static_cast<int>(kCartographicQuadVertexCount),
        static_cast<int>(kCartographicQuadPrimitiveCountInput),
        0,
        0
      );
      (void)device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x007D17C0 (FUN_007D17C0)
   * Mangled: ?Render@Cartographic@Moho@@QAEXV?$shared_ptr@VRenderTarget@gal@gpg@@@boost@@
   *          V?$shared_ptr@VDepthStencilTarget@gal@gpg@@@4@HHM
   *          V?$shared_ptr@VCD3DPrimBatcher@Moho@@@4@PAVIRenderWorldView@2@_N@Z
   *
   * IDA signature:
   * void __usercall Moho::Cartographic::Render(
   *   Moho::Cartographic *this, unsigned int headIndex, int gameTick, float deltaFrame,
   *   Moho::IRenderWorldView *worldView, Moho::RangeRenderer *rangeRenderer,
   *   Moho::VisionRenderer *visionRenderer, Moho::BoundaryRenderer *boundaryRenderer,
   *   boost::shared_ptr<gpg::gal::RenderTarget> colorTarget,
   *   boost::shared_ptr<gpg::gal::DepthStencilTarget> depthStencilTarget,
   *   boost::shared_ptr<Moho::CD3DPrimBatcher> primBatcher);
   *
   * What it does:
   * Draws one whole cartographic ("strategic") frame for one device head.
   *
   *   - forces `ui_AlwaysRenderStrategicIcons` on for the duration and restores
   *     the caller's value on the way out (0x007D17E7 / 0x007D1C0E);
   *   - clears the caller-supplied colour+depth pair and switches the device to
   *     the world view's viewport rectangle, which the camera carries as row 3
   *     of its viewport matrix, truncated to integers;
   *   - paints the terrain through `RenderTerrainStage0`, then - only while a
   *     world session exists - the weapon range rings, the fog of war and the
   *     playable boundary on top of it;
   *   - rebinds the head's own output context and viewport and composites that
   *     offscreen frame back onto it through `RenderTerrainStage1`;
   *   - draws the meshes, the world particles and every cartographic decal
   *     batch, then the UI, over the composite;
   *   - clears the head to opaque white with depth+stencil only, runs the world
   *     view's own render callback and the debug overlay, and finally restores
   *     the head's full viewport.
   *
   * See the declaration for the shipped stack layout: link-time code generation
   * moved `this` onto the stack, hoisted the three renderer lanes out of the
   * caller and pushed the three by-value handles to the tail (`retn 38h`).
   */
  void Cartographic::Render(
    const unsigned int headIndex,
    const std::int32_t gameTick,
    const float deltaFrame,
    IRenderWorldView* const worldView,
    RangeRenderer* const rangeRenderer,
    VisionRenderer* const visionRenderer,
    BoundaryRenderer* const boundaryRenderer,
    boost::shared_ptr<gpg::gal::RenderTargetD3D9> colorTarget,
    boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9> depthStencilTarget,
    boost::shared_ptr<CD3DPrimBatcher> primBatcher
  )
  {
    const bool previousAlwaysRenderStrategicIcons = ui_AlwaysRenderStrategicIcons;
    ui_AlwaysRenderStrategicIcons = true;

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const gpg::gal::Head& head = device->GetDeviceContext()->GetHead(headIndex);
    gpg::gal::OutputContext& headOutputContext = CartographicHeadOutputContext(*device, headIndex);
    (void)device->ClearTextures();

    CWldSession* const session = sWldSession;
    CameraImpl* const camera = worldView->GetCamera();
    const GeomCamera3& cameraView = *worldView->GetCameraView();

    // The world view publishes its screen rectangle as row 3 of the camera's
    // viewport matrix. The shipped body converts all four lanes with the FPU
    // rounding mode forced to truncate (0x007D1876 `or eax, 0C00h`), which is
    // what a C++ float-to-int conversion already does.
    const D3DVIEWPORT9 worldViewViewport = MakeCartographicViewport(
      static_cast<std::int32_t>(cameraView.viewport.r[3].x),
      static_cast<std::int32_t>(cameraView.viewport.r[3].y),
      static_cast<std::int32_t>(cameraView.viewport.r[3].z),
      static_cast<std::int32_t>(cameraView.viewport.r[3].w)
    );

    const D3DVIEWPORT9 fullHeadViewport = MakeCartographicViewport(
      0,
      0,
      static_cast<std::int32_t>(head.mWidth),
      static_cast<std::int32_t>(head.mHeight)
    );

    // The shipped body destroys this output context as soon as ClearTarget
    // returns (EH state 3 -> 2 at 0x007D19C8), so it is a full-expression
    // temporary rather than a function-scope local.
    {
      const gpg::gal::OutputContext cartographicTarget(
        AsOutputContextSurface(colorTarget),
        AsOutputContextDepthStencil(depthStencilTarget)
      );
      device->ClearTarget(&cartographicTarget);
    }

    device->SetViewport(&worldViewViewport);

    RenderTerrainStage0(cameraView, false);

    if (session != nullptr) {
      if (rangeRenderer != nullptr && camera != nullptr) {
        rangeRenderer->Render(session, camera, headIndex, deltaFrame);
      }

      if (visionRenderer != nullptr) {
        RenderFogOfWar(*session, *visionRenderer, headIndex, cameraView, deltaFrame);
      }

      if (boundaryRenderer != nullptr) {
        RenderPlayableBoundary(headIndex, *boundaryRenderer, *session, cameraView);
      }
    }

    device->ClearTarget(&headOutputContext);
    device->SetViewport(&worldViewViewport);

    RenderTerrainStage1(static_cast<std::int32_t>(headIndex), colorTarget);
    RenderMeshes(gameTick, deltaFrame, cameraView);

    // The shipped body inlines this one-line forwarder at 0x007D1AFB..
    // 0x007D1B20 (`sWorldParticles.RenderEffects(camera, 0, 1, tick, alpha)`),
    // which is why the out-of-line copy at 0x007D2E40 carries no xrefs of its
    // own. Calling it by name keeps both the behaviour and the symbol.
    RenderParticles(gameTick, deltaFrame, cameraView);

    const CartographicListNode* const batchSentinel = mListSentinel;
    for (CartographicListNode* node = mListSentinel->mNext; node != batchSentinel; node = node->mNext) {
      node->mBatch.Render(cameraView);
    }

    if (session != nullptr) {
      // 0x007D1B6C, __cdecl with five dword arguments and `add esp, 14h` at
      // 0x007D1B71. Argument roles decoded from the shipped pushes at
      // 0x007D1B56..0x007D1B6B:
      //   [esp+0x00] the active `CWldSession*` (the same `sWldSession` this
      //              branch is gated on),
      //   [esp+0x04] the world view's `GeomCamera3*` (ebp, from
      //              `IRenderWorldView::GetCameraView`),
      //   [esp+0x08] the raw `CD3DPrimBatcher*` out of `primBatcher` (edi,
      //              loaded at 0x007D1B4D, not an owning handle),
      //   [esp+0x0C] `deltaFrame`, forwarded unchanged,
      //   [esp+0x10] a literal `0.0f` (`fldz` at 0x007D1B56) - the cartographic
      //              pass freezes the blinky-box cycle rather than advancing
      //              it, so the world view's own pass stays the only ticker.
      RenUI(session, &cameraView, primBatcher.get(), deltaFrame, 0.0f);
    }

    device->Clear(
      false,
      true,
      true,
      kCartographicHeadClearColor,
      kCartographicClearDepth,
      kCartographicClearStencil
    );

    // 0x007D1BB2 dispatches `IRenderWorldView` slot 0 here as
    // `worldView->Render(primBatcher.get(), gameTick, deltaFrame, 0.0f)` -
    // four stack dwords, the third of which the shipped code stores with
    // `fstp` (0x007D1BAD), i.e. a float. The declaration in
    // `moho/render/IRenderWorldView.h` currently types that third parameter
    // `CWldMap*`, which no value here can satisfy; the call is left unwired
    // until that header is corrected rather than misrepresented with a cast.

    REN_DebugStuff(primBatcher, static_cast<int>(headIndex));

    device->SetViewport(&fullHeadViewport);

    ui_AlwaysRenderStrategicIcons = previousAlwaysRenderStrategicIcons;
  }
} // namespace moho
