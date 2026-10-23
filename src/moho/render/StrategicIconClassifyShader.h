#pragma once

// Engine-owned HLSL for GPU strategic-icon classification (`ren_GpuIconClassify`,
// StrategicIconClassifier).
//
// The CPU half of `CWldSession::RenderStrategicIcons` decides per frame, for
// every unit in view, whether it gets an icon, in which of the four runs
// (ground, air, high priority, selected), and builds its record (screen point,
// tint, atlas slots of its layers). Everything that decision reads per unit
// only changes when a sync beat is applied, so it sits in a persistent source
// buffer (`IconSource`); what changes per frame (interpolation fraction, zoom,
// camera, selection, hover, console variables, blink phase) comes in the
// constant block and the selection bit array.
//
// `ClassifyIconsCS` evaluates the CPU's tests in the CPU's order for one source
// and writes its record and its run to the staging buffers. `CompactIconsCS`,
// one group, writes the records run by run in source order - the order the
// CPU path draws them, so the blend is the same - and the draw arguments.
//
// The results are the CPU's bit for bit: every float operation the CPU does
// in single precision is done here once, in the same order, unfused
// (`precise`), and the one division (`GeomCamera3::Project`'s 1 / w) is the
// correctly rounded one the CPU's divss gives - D3D's float division is only
// accurate to 2.5 ulp, so it is computed exactly in integer arithmetic.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0..t3, u0..u1), so DXC builds the
// same source for D3D12 (DXIL) and Vulkan (SPIR-V).

#include <cstdint>

namespace moho
{
  /** One unit's beat data (`IconSource` below). */
  struct StrategicIconSourceRecord
  {
    enum Flags : std::uint32_t
    {
      kValid = 1U << 0U,                ///< the classifier did not drop it before the per-frame tests
      kFriendly = 1U << 1U,
      kStunned = 1U << 2U,
      kPaused = 1U << 3U,
      kCheckPlayableRect = 1U << 4U,
      kBeingBuilt = 1U << 5U,
      kSkipWhenMeshVisible = 1U << 6U,
      kHighPriority = 1U << 7U,
      kAir = 1U << 8U,
      kHasMesh = 1U << 9U,
    };

    float mLastPosition[3] = {};
    float mImpact = 0.0f;
    float mCurrentPosition[3] = {};
    std::uint32_t mFlags = 0U;
    float mIconFadeInZoom = 0.0f;       ///< the mesh's `mIconFadeInZoom` (with kHasMesh)
    std::uint32_t mColor = 0U;          ///< the base icon's tint, `PlaceUnitIcon`'s colour before the blink test
    std::uint32_t mIconSlots = 0xFFFFFFFFU; ///< atlas slot of the icon (low 16 bits) and the selected icon (high)
    std::int32_t mUnderlaySlotOrNone = -1;  ///< atlas slot of the identified underlay, -1 for none
    std::int32_t mLastFocusDamageTick = 0;  ///< `mLastFocusDamageGameTick`
    std::uint32_t mHoveredIconSlots = 0xFFFFFFFFU; ///< the hovered icon (low 16 bits) and hovered selected icon (high)
    std::uint32_t mUnused[2] = {};
  };
  static_assert(sizeof(StrategicIconSourceRecord) == 64, "StrategicIconSourceRecord must match IconSource");

  /** The per-frame constant block (`ClassifyConstants` below). */
  struct StrategicIconClassifyConstants
  {
    enum Flags : std::uint32_t
    {
      kNisRenderIcons = 1U << 0U,
      kRenderIcons = 1U << 1U,
      kAlwaysRenderIcons = 1U << 2U,
      kBlinkHidden = 1U << 3U,          ///< the shared blink phase is in its hidden half
      kHasPlayableRect = 1U << 4U,
    };

    float mViewProjection[16] = {};     ///< `GeomCamera3::viewProjection`, rows r[0]..r[3]
    float mViewport[4] = {};            ///< `Project`'s x0, x1, y0, y1
    float mPlayableRect[4] = {};        ///< x0, z0, x1, z1
    float mTickFraction = 0.0f;
    float mCurrentZoom = 0.0f;
    float mMaxZoomFade = 0.0f;          ///< `GetMaxZoom() * 0.89f`
    float mBlinkTicks = 0.0f;           ///< `ui_StrategicIconBlinkDuration * 10`
    std::uint32_t mCount = 0U;
    std::uint32_t mFlags = 0U;
    std::uint32_t mHovered = 0xFFFFFFFFU; ///< source index of the hovered unit, or none
    std::int32_t mGameTick = 0;
    std::uint32_t mPausedSlot = 0xFFFFU;
    std::uint32_t mStunnedSlot = 0xFFFFU;
    std::uint32_t mUnused[2] = {};
  };
  static_assert(sizeof(StrategicIconClassifyConstants) % 16 == 0, "constant blocks are whole float4s");

  /** Threads per group of `ClassifyIconsCS`, and of the single `CompactIconsCS` group. */
  inline constexpr std::uint32_t kIconClassifyGroupSize = 64U;
  inline constexpr std::uint32_t kIconCompactThreads = 1024U;
  /** `runOf` value of the hovered source (drawn after the four runs) and of a source that gets no icon. */
  inline constexpr std::uint32_t kIconHoveredRun = 4U;
  inline constexpr std::uint32_t kIconNoRun = 5U;

  inline constexpr char kStrategicIconClassifyShaderSource[] = R"hlsl(
cbuffer ClassifyConstants : register(b0)
{
    float4 ViewProjection[4]; // GeomCamera3::viewProjection rows
    float4 Viewport;          // x0, x1, y0, y1
    float4 PlayableRect;      // x0, z0, x1, z1
    float TickFraction;
    float CurrentZoom;
    float MaxZoomFade;
    float BlinkTicks;
    uint Count;
    uint FrameFlags;
    uint Hovered;
    int GameTick;
    uint PausedSlot;
    uint StunnedSlot;
    uint2 Unused;
};

static const uint kValid = 1u << 0;
static const uint kFriendly = 1u << 1;
static const uint kStunned = 1u << 2;
static const uint kPaused = 1u << 3;
static const uint kCheckPlayableRect = 1u << 4;
static const uint kBeingBuilt = 1u << 5;
static const uint kSkipWhenMeshVisible = 1u << 6;
static const uint kHighPriority = 1u << 7;
static const uint kAir = 1u << 8;
static const uint kHasMesh = 1u << 9;

static const uint kNisRenderIcons = 1u << 0;
static const uint kRenderIcons = 1u << 1;
static const uint kAlwaysRenderIcons = 1u << 2;
static const uint kBlinkHidden = 1u << 3;
static const uint kHasPlayableRect = 1u << 4;

static const uint kNoSlot = 0xFFFFu;
static const uint kHoveredRun = 4u;
static const uint kNoRun = 5u;

struct IconSource
{
    float3 lastPosition;
    float impact;
    float3 currentPosition;
    uint flags;
    float iconFadeInZoom;
    uint color;
    uint iconSlots;     // icon (low), selected icon (high)
    int underlaySlot;   // -1: none
    int lastFocusDamageTick;
    uint hoveredIconSlots; // hovered icon (low), hovered selected icon (high)
    uint2 unused;
};

struct IconInstance
{
    uint position;
    uint color;
    uint layers01;
    uint layers23;
};

// IEEE single-precision 1 / x, rounded to nearest even: what the CPU's divss
// returns. Exact for every normal x whose reciprocal is normal; anything else
// (zero, infinities, NaN, denormal inputs or results) falls back to the
// hardware division, where no icon lands on the screen anyway.
float ExactReciprocal(float x)
{
    uint bits = asuint(x);
    uint sign = bits & 0x80000000u;
    uint exponent = (bits >> 23) & 0xFFu;
    if (exponent == 0u || exponent >= 253u)
    {
        return 1.0 / x;
    }
    uint mantissa = (bits & 0x7FFFFFu) | 0x800000u;
    if (mantissa == 0x800000u)
    {
        return asfloat(sign | ((254u - exponent) << 23));
    }
    // 2^48 / mantissa by long division, 8 bits at a time (remainders stay below 2^24).
    uint quotient = 0u;
    uint remainder = 1u;
    [unroll] for (uint step = 0u; step < 6u; ++step)
    {
        remainder <<= 8;
        quotient = (quotient << 8) | (remainder / mantissa);
        remainder = remainder % mantissa;
    }
    // quotient is in (2^24, 2^25): 24 result bits, then the rounding bit.
    uint result = quotient >> 1;
    uint roundBit = quotient & 1u;
    if (roundBit != 0u && (remainder != 0u || (result & 1u) != 0u))
    {
        result += 1u;
    }
    return asfloat(sign | ((253u - exponent) << 23) | (result & 0x7FFFFFu));
}

uint PackPosition(float value)
{
    // StrategicIconInstance::SetPosition: clamp, truncate, 16 bits.
    float clamped = clamp(value, -32768.0, 32767.0);
    return ((uint)(int)clamped) & 0xFFFFu;
}

StructuredBuffer<IconSource> Sources : register(t0);
StructuredBuffer<uint> SelectionBits : register(t1);
RWStructuredBuffer<IconInstance> Staged : register(u0);
RWStructuredBuffer<uint> RunOf : register(u1);

[numthreads(64, 1, 1)]
void ClassifyIconsCS(uint3 thread : SV_DispatchThreadID)
{
    uint index = thread.x;
    if (index >= Count)
    {
        return;
    }
    IconSource source = Sources[index];
    RunOf[index] = kNoRun;
    if ((source.flags & kValid) == 0u)
    {
        return;
    }

    // GetInterpolatedTransform from the record's endpoints.
    precise float alpha = clamp(source.impact * TickFraction, 0.0, 1.0);
    precise float3 position = source.lastPosition + (source.currentPosition - source.lastPosition) * alpha;

    if ((source.flags & kCheckPlayableRect) != 0u && (FrameFlags & kHasPlayableRect) != 0u)
    {
        bool inside = PlayableRect.x <= position.x && PlayableRect.y <= position.z && position.x <= PlayableRect.z &&
            position.z <= PlayableRect.w;
        if (!inside)
        {
            return;
        }
    }

    bool paused = (source.flags & kPaused) != 0u;
    bool stunned = (source.flags & kStunned) != 0u;
    if ((FrameFlags & kNisRenderIcons) == 0u || ((FrameFlags & kRenderIcons) == 0u && !paused) ||
        (source.flags & kBeingBuilt) != 0u)
    {
        return;
    }

    bool suppressBase = false;
    if ((source.flags & kHasMesh) != 0u && (FrameFlags & kAlwaysRenderIcons) == 0u)
    {
        // std::min(a, b): b when b < a.
        float fadeThreshold = MaxZoomFade < source.iconFadeInZoom ? MaxZoomFade : source.iconFadeInZoom;
        if (fadeThreshold <= CurrentZoom)
        {
            if ((source.flags & kSkipWhenMeshVisible) != 0u)
            {
                return;
            }
            suppressBase = paused || stunned;
        }
    }

    // The hovered unit takes its hovered texture and goes to the one hovered slot, drawn last.
    bool hovered = index == Hovered;
    bool selected = (SelectionBits[index >> 5] & (1u << (index & 31u))) != 0u;
    uint slots = hovered ? source.hoveredIconSlots : source.iconSlots;
    uint iconSlot = selected ? (slots >> 16) : (slots & 0xFFFFu);
    if (iconSlot == kNoSlot)
    {
        return;
    }
    uint run = hovered ? kHoveredRun : selected ? 3u : (source.flags & kHighPriority) != 0u ? 2u : (source.flags & kAir) != 0u ? 1u : 0u;

    // PlaceUnitIcon and BuildStrategicIconRecord.
    IconInstance record;
    record.position = 0u;
    record.color = 0u;
    record.layers01 = 0xFFFFFFFFu;
    record.layers23 = 0xFFFFFFFFu;
    bool blinkedOut = false;
    if ((source.flags & kFriendly) != 0u && source.lastFocusDamageTick != 0 && (FrameFlags & kBlinkHidden) != 0u)
    {
        float ticksSinceDamage = (float)(GameTick - source.lastFocusDamageTick);
        blinkedOut = BlinkTicks > ticksSinceDamage;
    }
    if (!blinkedOut)
    {
        // GeomCamera3::Project, operation by operation.
        precise float w = ((ViewProjection[0].w * position.x) + (ViewProjection[1].w * position.y) +
                           (ViewProjection[2].w * position.z)) + ViewProjection[3].w;
        precise float reciprocalW = ExactReciprocal(w);
        precise float projectedX = (((ViewProjection[0].x * position.x) + (ViewProjection[1].x * position.y) +
                                     (ViewProjection[2].x * position.z)) + ViewProjection[3].x) * reciprocalW;
        precise float projectedY = (((ViewProjection[0].y * position.x) + (ViewProjection[1].y * position.y) +
                                     (ViewProjection[2].y * position.z)) + ViewProjection[3].y) * reciprocalW;
        precise float screenX = (((Viewport.y - Viewport.x) * (projectedX - -1.0)) * 0.5) + Viewport.x;
        precise float screenY = (((Viewport.w - Viewport.z) * (projectedY - -1.0)) * 0.5) + Viewport.z;
        record.position = PackPosition(floor(screenX)) | (PackPosition(floor(screenY)) << 16);
        record.color = source.color;
        uint underlay = source.underlaySlot >= 0 ? (uint)source.underlaySlot : kNoSlot;
        uint base = suppressBase ? kNoSlot : iconSlot;
        uint pausedLayer = paused ? PausedSlot : kNoSlot;
        uint stunnedLayer = stunned ? StunnedSlot : kNoSlot;
        record.layers01 = underlay | (base << 16);
        record.layers23 = pausedLayer | (stunnedLayer << 16);
    }
    Staged[index] = record;
    RunOf[index] = run;
}

StructuredBuffer<IconInstance> StagedIn : register(t0);
StructuredBuffer<uint> RunIn : register(t1);
RWStructuredBuffer<IconInstance> Output : register(u0);
RWByteAddressBuffer DrawArgs : register(u1);

groupshared uint4 sOffsets[1024];

[numthreads(1024, 1, 1)]
void CompactIconsCS(uint thread : SV_GroupIndex)
{
    uint chunk = (Count + 1023u) / 1024u;
    uint begin = min(thread * chunk, Count);
    uint end = min(begin + chunk, Count);

    uint4 counts = uint4(0u, 0u, 0u, 0u);
    for (uint i = begin; i < end; ++i)
    {
        uint run = RunIn[i];
        counts += uint4(run == 0u, run == 1u, run == 2u, run == 3u);
    }
    sOffsets[thread] = counts;
    GroupMemoryBarrierWithGroupSync();

    // Inclusive scan over the threads (Hillis-Steele), all four runs at once.
    [unroll] for (uint stride = 1u; stride < 1024u; stride <<= 1)
    {
        uint4 add = thread >= stride ? sOffsets[thread - stride] : uint4(0u, 0u, 0u, 0u);
        GroupMemoryBarrierWithGroupSync();
        sOffsets[thread] += add;
        GroupMemoryBarrierWithGroupSync();
    }

    uint4 totals = sOffsets[1023];
    uint4 runBase = uint4(0u, totals.x, totals.x + totals.y, totals.x + totals.y + totals.z);
    uint4 cursor = runBase + sOffsets[thread] - counts;
    for (uint j = begin; j < end; ++j)
    {
        uint run = RunIn[j];
        // Runs 0-3 only: the hovered record (run 4) goes to its slot below, and must not take
        // (and race for) the selected run's next slot.
        if (run < kHoveredRun)
        {
            uint slot = run == 0u ? cursor.x : run == 1u ? cursor.y : run == 2u ? cursor.z : cursor.w;
            Output[slot] = StagedIn[j];
            cursor += uint4(run == 0u, run == 1u, run == 2u, run == 3u);
        }
    }

    if (thread == 0u)
    {
        // The hovered slot after the four runs, then the DrawInstanced arguments: 24 vertices per
        // icon, one instance per record.
        uint total = totals.x + totals.y + totals.z + totals.w;
        if (Hovered < Count && RunIn[Hovered] == kHoveredRun)
        {
            Output[total] = StagedIn[Hovered];
            total += 1u;
        }
        DrawArgs.Store4(0, uint4(24u, total, 0u, 0u));
    }
}
)hlsl";
} // namespace moho
