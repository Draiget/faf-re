// Engine addition, not in the binary: the water of a river (docs/projects/RIVERS.md).
//
// Everything here is plain float arithmetic with + - * / and sqrt in a fixed order (the build pins
// -ffp-contract=off), no pow, sin, cos or atan2, so the field is the same on every machine.
#include "moho/sim/WaterRivers.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

namespace moho
{
  namespace
  {
    constexpr std::uint16_t kNoLevel = 0xFFFFu;
    constexpr float kLevelStep = 1.0f / kRiverLevelQuantum;
    constexpr float kCoordinateLimit = 100000.0f;

    [[nodiscard]] bool Finite(
      const float value
    ) noexcept
    {
      return std::isfinite(value);
    }

    /// `value` truncated toward the cell below it and clamped to `[0, count - 1]`; NaN gives 0.
    [[nodiscard]] std::int32_t ClampedCell(
      const float value,
      const std::int32_t count
    ) noexcept
    {
      if (!(value >= 0.0f)) {
        return 0;
      }
      if (value >= static_cast<float>(count - 1)) {
        return count - 1;
      }
      return static_cast<std::int32_t>(value);
    }

    /// One component of the open uniform Catmull-Rom spline between `p1` and `p2` (the formula of
    /// `WaterBodyOutlinePolygon`).
    [[nodiscard]] float CatmullRom(
      const float p0,
      const float p1,
      const float p2,
      const float p3,
      const float t,
      const float t2,
      const float t3
    ) noexcept
    {
      const float a = 2.0f * p1;
      const float b = p2 - p0;
      const float c = ((2.0f * p0) - (5.0f * p1)) + ((4.0f * p2) - p3);
      const float d = ((3.0f * p1) - p0) + (p3 - (3.0f * p2));
      return 0.5f * (((a + (b * t)) + (c * t2)) + (d * t3));
    }

    [[nodiscard]] std::int8_t SignedByte(
      const float unit
    ) noexcept
    {
      return static_cast<std::int8_t>(static_cast<std::int32_t>(std::floor(unit * 127.0f + 0.5f)));
    }

    [[nodiscard]] bool BitSet(
      const std::vector<std::uint8_t>& bits,
      const std::size_t index
    ) noexcept
    {
      return (bits[index >> 3u] & (1u << (index & 7u))) != 0u;
    }

    void SetBit(
      std::vector<std::uint8_t>& bits,
      const std::size_t index
    ) noexcept
    {
      bits[index >> 3u] = static_cast<std::uint8_t>(bits[index >> 3u] | (1u << (index & 7u)));
    }

    struct SHash
    {
      std::uint32_t value{2166136261u};

      void Bytes(
        const void* const data,
        const std::size_t size
      ) noexcept
      {
        const auto* const bytes = static_cast<const std::uint8_t*>(data);
        for (std::size_t i = 0; i < size; ++i) {
          value = (value ^ bytes[i]) * 16777619u;
        }
      }
      void Int(
        const std::int32_t number
      ) noexcept
      {
        Bytes(&number, sizeof(number));
      }
      void Float(
        const float number
      ) noexcept
      {
        std::uint32_t bits = 0;
        std::memcpy(&bits, &number, sizeof(bits));
        Bytes(&bits, sizeof(bits));
      }
    };
  } // namespace

  std::string ValidateRiver(
    const SRiverDesc& desc
  )
  {
    char line[160];
    const std::size_t count = desc.points.size();
    if (count < kRiverMinPoints || count > kRiverMaxPoints) {
      std::snprintf(
        line, sizeof(line), "River.Points needs %zu to %zu points, has %zu", kRiverMinPoints, kRiverMaxPoints, count
      );
      return line;
    }
    if (desc.steps < 1 || desc.steps > kRiverMaxSteps) {
      std::snprintf(line, sizeof(line), "River.Steps must be 1 to %d", kRiverMaxSteps);
      return line;
    }
    if (!(desc.margin >= kRiverMinMargin && desc.margin <= kRiverMaxMargin)) {
      std::snprintf(
        line,
        sizeof(line),
        "River.Margin must be %g to %g",
        static_cast<double>(kRiverMinMargin),
        static_cast<double>(kRiverMaxMargin)
      );
      return line;
    }
    if (!Finite(desc.flowScale) || desc.flowScale < 0.0f) {
      return "River.FlowScale must be a number of 0 or more";
    }

    std::size_t falls = 0;
    float lowest = std::numeric_limits<float>::max();
    float highest = std::numeric_limits<float>::lowest();
    for (std::size_t i = 0; i < count; ++i) {
      const SRiverPoint& point = desc.points[i];
      if (
        !Finite(point.x) || !Finite(point.z) || !Finite(point.level) || !Finite(point.below) ||
        !Finite(point.halfWidth) || std::fabs(point.x) > kCoordinateLimit || std::fabs(point.z) > kCoordinateLimit ||
        std::fabs(point.level) > kCoordinateLimit || std::fabs(point.below) > kCoordinateLimit
      ) {
        std::snprintf(line, sizeof(line), "point %zu has a value that is not a usable number", i + 1u);
        return line;
      }
      if (!(point.halfWidth >= kRiverMinHalfWidth && point.halfWidth <= kRiverMaxHalfWidth)) {
        std::snprintf(
          line,
          sizeof(line),
          "point %zu: HalfWidth must be %g to %g",
          i + 1u,
          static_cast<double>(kRiverMinHalfWidth),
          static_cast<double>(kRiverMaxHalfWidth)
        );
        return line;
      }
      if (point.fall) {
        if (i == 0u || i + 1u == count) {
          std::snprintf(line, sizeof(line), "point %zu: the first and the last point cannot be a Fall", i + 1u);
          return line;
        }
        ++falls;
        if (!(point.level - point.below >= kRiverFallDrop)) {
          std::snprintf(
            line,
            sizeof(line),
            "point %zu: a Fall needs Below at least %g under Level (a smaller step does not block)",
            i + 1u,
            static_cast<double>(kRiverFallDrop)
          );
          return line;
        }
      }
      // Levels do not rise downstream; a fall steps from Level down to Below.
      if (i + 1u < count) {
        const float start = point.fall ? point.below : point.level;
        if (desc.points[i + 1u].level > start) {
          std::snprintf(
            line,
            sizeof(line),
            "point %zu: Level rises downstream (it must not exceed %g)",
            i + 2u,
            static_cast<double>(start)
          );
          return line;
        }
      }
      lowest = std::min(lowest, point.fall ? point.below : point.level);
      highest = std::max(highest, point.level);
    }
    if (falls > kRiverMaxFalls) {
      std::snprintf(line, sizeof(line), "a river has at most %zu falls", kRiverMaxFalls);
      return line;
    }
    if (!(highest - lowest <= kRiverMaxLevelSpread)) {
      std::snprintf(line, sizeof(line), "the levels span more than %g", static_cast<double>(kRiverMaxLevelSpread));
      return line;
    }
    return {};
  }

  std::vector<SRiverSegment> RiverSegments(
    const SRiverDesc& desc,
    std::vector<SRiverFall>* const falls
  )
  {
    std::vector<SRiverSegment> segments;
    if (falls != nullptr) {
      falls->clear();
    }
    const std::size_t count = desc.points.size();
    if (count < 2u) {
      return segments;
    }
    segments.reserve((count - 1u) * static_cast<std::size_t>(desc.steps));
    const auto point = [&](const std::size_t index) -> const SRiverPoint& {
      return desc.points[std::min(index, count - 1u)];
    };

    float distance = 0.0f;
    for (std::size_t span = 0; span + 1u < count; ++span) {
      const SRiverPoint& p1 = desc.points[span];
      const SRiverPoint& p2 = desc.points[span + 1u];
      const SRiverPoint& p0 = span == 0u ? p1 : desc.points[span - 1u];
      const SRiverPoint& p3 = point(span + 2u);
      // The span after a fall starts below the lip.
      const float startLevel = p1.fall ? p1.below : p1.level;
      const float endLevel = p2.level;

      float lastX = p1.x;
      float lastZ = p1.z;
      float lastLevel = startLevel;
      float lastHalf = p1.halfWidth;
      for (std::int32_t step = 1; step <= desc.steps; ++step) {
        const float t = static_cast<float>(step) / static_cast<float>(desc.steps);
        const float t2 = t * t;
        const float t3 = t2 * t;
        float x = 0.0f;
        float z = 0.0f;
        if (step == desc.steps) {
          x = p2.x;
          z = p2.z;
        } else {
          x = CatmullRom(p0.x, p1.x, p2.x, p3.x, t, t2, t3);
          z = CatmullRom(p0.z, p1.z, p2.z, p3.z, t, t2, t3);
        }
        const float level = step == desc.steps ? endLevel : startLevel + ((endLevel - startLevel) * t);
        const float half = step == desc.steps ? p2.halfWidth : p1.halfWidth + ((p2.halfWidth - p1.halfWidth) * t);

        const float dx = x - lastX;
        const float dz = z - lastZ;
        const float lengthSquared = (dx * dx) + (dz * dz);
        if (lengthSquared > 0.0f) {
          SRiverSegment segment;
          segment.x0 = lastX;
          segment.z0 = lastZ;
          segment.x1 = x;
          segment.z1 = z;
          segment.level0 = lastLevel;
          segment.level1 = level;
          segment.half0 = lastHalf;
          segment.half1 = half;
          segment.s0 = distance;
          segment.length = std::sqrt(lengthSquared);
          segment.tx = dx / segment.length;
          segment.tz = dz / segment.length;
          distance += segment.length;
          segments.push_back(segment);
        }
        lastX = x;
        lastZ = z;
        lastLevel = level;
        lastHalf = half;
      }
    }

    if (falls != nullptr) {
      for (std::size_t i = 1; i + 1u < count; ++i) {
        const SRiverPoint& p = desc.points[i];
        if (!p.fall) {
          continue;
        }
        float tx = desc.points[i + 1u].x - desc.points[i - 1u].x;
        float tz = desc.points[i + 1u].z - desc.points[i - 1u].z;
        const float length = std::sqrt((tx * tx) + (tz * tz));
        if (length > 0.0f) {
          tx /= length;
          tz /= length;
        }
        falls->push_back({p.x, p.z, tx, tz, p.halfWidth, p.level, p.below});
      }
    }
    return segments;
  }

  std::shared_ptr<const CWaterRiver> CWaterRiver::Build(
    const SRiverDesc& desc,
    const std::uint16_t* const heights,
    const std::int32_t width,
    const std::int32_t height,
    const float heightScale,
    std::string* const error
  )
  {
    const auto fail = [&](const std::string& why) -> std::shared_ptr<const CWaterRiver> {
      if (error != nullptr) {
        *error = why;
      }
      return nullptr;
    };
    if (heights == nullptr || width < 2 || height < 2) {
      return fail("there is no height field");
    }
    const std::string invalid = ValidateRiver(desc);
    if (!invalid.empty()) {
      return fail(invalid);
    }

    std::shared_ptr<CWaterRiver> river(new CWaterRiver());
    river->mFlowScale = desc.flowScale;
    river->mMapVertexWidth = width;
    river->mMapVertexHeight = height;
    river->mSegments = RiverSegments(desc, &river->mFalls);
    const std::vector<SRiverSegment>& segments = river->mSegments;
    if (segments.empty()) {
      return fail("the centreline has no length");
    }

    // Levels of the river, and the rectangle the field covers: every segment padded by its half
    // width and the margin.
    float levelMin = std::numeric_limits<float>::max();
    float levelMax = std::numeric_limits<float>::lowest();
    float minX = std::numeric_limits<float>::max();
    float minZ = std::numeric_limits<float>::max();
    float maxX = std::numeric_limits<float>::lowest();
    float maxZ = std::numeric_limits<float>::lowest();
    for (const SRiverSegment& segment : segments) {
      levelMin = std::min(levelMin, std::min(segment.level0, segment.level1));
      levelMax = std::max(levelMax, std::max(segment.level0, segment.level1));
      const float pad = std::max(segment.half0, segment.half1) + desc.margin;
      minX = std::min(minX, std::min(segment.x0, segment.x1) - pad);
      maxX = std::max(maxX, std::max(segment.x0, segment.x1) + pad);
      minZ = std::min(minZ, std::min(segment.z0, segment.z1) - pad);
      maxZ = std::max(maxZ, std::max(segment.z0, segment.z1) + pad);
    }
    river->mLevelMin = levelMin;
    river->mLevelMax = levelMax;
    river->mBaseLevel = std::floor(levelMin) - 1.0f;

    const float lastX = static_cast<float>(width - 1);
    const float lastZ = static_cast<float>(height - 1);
    if (maxX < 0.0f || maxZ < 0.0f || minX > lastX || minZ > lastZ) {
      return fail("the river lies off the map");
    }
    river->mX0 = static_cast<std::int32_t>(std::clamp(std::floor(minX), 0.0f, lastX));
    river->mZ0 = static_cast<std::int32_t>(std::clamp(std::floor(minZ), 0.0f, lastZ));
    river->mX1 = static_cast<std::int32_t>(std::clamp(std::ceil(maxX), 0.0f, lastX));
    river->mZ1 = static_cast<std::int32_t>(std::clamp(std::ceil(maxZ), 0.0f, lastZ));

    const std::int32_t rectWidth = river->mX1 - river->mX0 + 1;
    const std::int32_t rectHeight = river->mZ1 - river->mZ0 + 1;
    const std::size_t rectVertices = static_cast<std::size_t>(rectWidth) * static_cast<std::size_t>(rectHeight);
    const std::size_t mapVertices = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    if (rectVertices > kRiverMaxVertices || rectVertices * 4u > mapVertices) {
      char line[160];
      std::snprintf(
        line,
        sizeof(line),
        "the river's rectangle of %d x %d vertices is larger than 4M vertices or a quarter of the map",
        rectWidth,
        rectHeight
      );
      return fail(line);
    }

    // The nearest centreline segment of every vertex of the rectangle (ties: the lower segment).
    std::vector<float> bestDistance(rectVertices, std::numeric_limits<float>::max());
    std::vector<float> bestAlong(rectVertices, 0.0f);
    std::vector<std::int32_t> bestSegment(rectVertices, -1);
    for (std::size_t index = 0; index < segments.size(); ++index) {
      const SRiverSegment& segment = segments[index];
      const float pad = std::max(segment.half0, segment.half1) + desc.margin;
      const std::int32_t x0 = std::max(
        river->mX0,
        static_cast<std::int32_t>(std::clamp(std::floor(std::min(segment.x0, segment.x1) - pad), 0.0f, lastX))
      );
      const std::int32_t x1 = std::min(
        river->mX1,
        static_cast<std::int32_t>(std::clamp(std::ceil(std::max(segment.x0, segment.x1) + pad), 0.0f, lastX))
      );
      const std::int32_t z0 = std::max(
        river->mZ0,
        static_cast<std::int32_t>(std::clamp(std::floor(std::min(segment.z0, segment.z1) - pad), 0.0f, lastZ))
      );
      const std::int32_t z1 = std::min(
        river->mZ1,
        static_cast<std::int32_t>(std::clamp(std::ceil(std::max(segment.z0, segment.z1) + pad), 0.0f, lastZ))
      );
      const float dx = segment.x1 - segment.x0;
      const float dz = segment.z1 - segment.z0;
      const float lengthSquared = (dx * dx) + (dz * dz);
      for (std::int32_t z = z0; z <= z1; ++z) {
        for (std::int32_t x = x0; x <= x1; ++x) {
          const float px = static_cast<float>(x) - segment.x0;
          const float pz = static_cast<float>(z) - segment.z0;
          const float t = std::clamp(((px * dx) + (pz * dz)) / lengthSquared, 0.0f, 1.0f);
          const float ex = px - (dx * t);
          const float ez = pz - (dz * t);
          const float distanceSquared = (ex * ex) + (ez * ez);
          const std::size_t at = river->VertexIndex(x, z);
          if (distanceSquared < bestDistance[at]) {
            bestDistance[at] = distanceSquared;
            bestAlong[at] = t;
            bestSegment[at] = static_cast<std::int32_t>(index);
          }
        }
      }
    }

    // Level, flow and wetness.
    river->mLevel.assign(rectVertices, kNoLevel);
    river->mFlow.assign(rectVertices * 2u, 0);
    river->mWet.assign((rectVertices + 7u) / 8u, 0u);
    std::vector<float> quantised(rectVertices, 0.0f);
    for (std::int32_t z = river->mZ0; z <= river->mZ1; ++z) {
      for (std::int32_t x = river->mX0; x <= river->mX1; ++x) {
        const std::size_t at = river->VertexIndex(x, z);
        if (bestSegment[at] < 0) {
          continue;
        }
        const SRiverSegment& segment = segments[static_cast<std::size_t>(bestSegment[at])];
        const float t = bestAlong[at];
        const float half = segment.half0 + ((segment.half1 - segment.half0) * t);
        const float support = half + desc.margin;
        if (bestDistance[at] > support * support) {
          continue;
        }
        const float level = segment.level0 + ((segment.level1 - segment.level0) * t);
        const float steps = std::floor(((level - river->mBaseLevel) * kRiverLevelQuantum) + 0.5f);
        const auto word = static_cast<std::uint16_t>(std::clamp(steps, 0.0f, 65534.0f));
        river->mLevel[at] = word;
        river->mFlow[at * 2u] = SignedByte(segment.tx);
        river->mFlow[at * 2u + 1u] = SignedByte(segment.tz);
        const float stored = river->mBaseLevel + (static_cast<float>(word) * kLevelStep);
        quantised[at] = stored;
        const float terrain =
          static_cast<float>(
            heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)]
          ) *
          heightScale;
        if (bestDistance[at] <= half * half && terrain < stored) {
          SetBit(river->mWet, at);
          ++river->mWetVertexCount;
        }
      }
    }
    if (river->mWetVertexCount == 0u) {
      return fail("no terrain inside its channel is below its level");
    }

    // Falls: a cell with two wet corners whose levels differ by the drop.
    const std::int32_t cellsX = rectWidth - 1;
    const std::int32_t cellsZ = rectHeight - 1;
    river->mFallBits.assign((static_cast<std::size_t>(cellsX) * static_cast<std::size_t>(cellsZ) + 7u) / 8u, 0u);
    for (std::int32_t cz = 0; cz < cellsZ; ++cz) {
      for (std::int32_t cx = 0; cx < cellsX; ++cx) {
        float low = std::numeric_limits<float>::max();
        float high = std::numeric_limits<float>::lowest();
        std::int32_t wet = 0;
        for (std::int32_t dz = 0; dz < 2; ++dz) {
          for (std::int32_t dx = 0; dx < 2; ++dx) {
            const std::size_t at = static_cast<std::size_t>(cz + dz) * static_cast<std::size_t>(rectWidth) +
              static_cast<std::size_t>(cx + dx);
            if (BitSet(river->mWet, at)) {
              ++wet;
              low = std::min(low, quantised[at]);
              high = std::max(high, quantised[at]);
            }
          }
        }
        if (wet >= 2 && high - low >= kRiverFallDrop) {
          SetBit(
            river->mFallBits,
            static_cast<std::size_t>(cz) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(cx)
          );
          ++river->mFallCellCount;
        }
      }
    }
    return river;
  }

  bool CWaterRiver::VertexLevel(
    const std::int32_t x,
    const std::int32_t z,
    float& level
  ) const noexcept
  {
    if (!InRect(x, z)) {
      return false;
    }
    const std::uint16_t word = mLevel[VertexIndex(x, z)];
    if (word == kNoLevel) {
      return false;
    }
    level = mBaseLevel + (static_cast<float>(word) * kLevelStep);
    return true;
  }

  bool CWaterRiver::IsWetVertex(
    const std::int32_t x,
    const std::int32_t z
  ) const noexcept
  {
    return InRect(x, z) && BitSet(mWet, VertexIndex(x, z));
  }

  bool CWaterRiver::LevelAt(
    const float x,
    const float z,
    float& level
  ) const noexcept
  {
    const std::int32_t cx = ClampedCell(x, mMapVertexWidth - 1);
    const std::int32_t cz = ClampedCell(z, mMapVertexHeight - 1);
    float u = x - static_cast<float>(cx);
    float v = z - static_cast<float>(cz);
    u = u >= 0.0f ? (u > 1.0f ? 1.0f : u) : 0.0f;
    v = v >= 0.0f ? (v > 1.0f ? 1.0f : v) : 0.0f;

    float corner[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    bool have[4] = {false, false, false, false};
    float sum = 0.0f;
    std::int32_t count = 0;
    for (std::int32_t i = 0; i < 4; ++i) {
      have[i] = VertexLevel(cx + (i & 1), cz + (i >> 1), corner[i]);
      if (have[i]) {
        sum += corner[i];
        ++count;
      }
    }
    if (count == 0) {
      return false;
    }
    const float mean = sum / static_cast<float>(count);
    for (std::int32_t i = 0; i < 4; ++i) {
      if (!have[i]) {
        corner[i] = mean;
      }
    }
    const float top = (corner[0] * (1.0f - u)) + (corner[1] * u);
    const float bottom = (corner[2] * (1.0f - u)) + (corner[3] * u);
    level = (top * (1.0f - v)) + (bottom * v);
    return true;
  }

  bool CWaterRiver::FlowAt(
    const float x,
    const float z,
    float& fx,
    float& fz
  ) const noexcept
  {
    if (!(x >= 0.0f) || !(z >= 0.0f)) {
      return false;
    }
    const auto vx = static_cast<std::int32_t>(std::min(std::floor(x + 0.5f), static_cast<float>(mMapVertexWidth - 1)));
    const auto vz = static_cast<std::int32_t>(std::min(std::floor(z + 0.5f), static_cast<float>(mMapVertexHeight - 1)));
    if (!InRect(vx, vz)) {
      return false;
    }
    const std::size_t at = VertexIndex(vx, vz);
    if (mLevel[at] == kNoLevel) {
      return false;
    }
    fx = static_cast<float>(mFlow[at * 2u]) / 127.0f;
    fz = static_cast<float>(mFlow[at * 2u + 1u]) / 127.0f;
    return true;
  }

  bool CWaterRiver::IsFallCell(
    const std::int32_t cx,
    const std::int32_t cz
  ) const noexcept
  {
    if (mFallCellCount == 0u || cx < mX0 || cx >= mX1 || cz < mZ0 || cz >= mZ1) {
      return false;
    }
    return BitSet(
      mFallBits,
      static_cast<std::size_t>(cz - mZ0) * static_cast<std::size_t>(mX1 - mX0) + static_cast<std::size_t>(cx - mX0)
    );
  }

  std::uint32_t CWaterRiver::Checksum() const noexcept
  {
    SHash hash;
    hash.Int(mX0);
    hash.Int(mZ0);
    hash.Int(mX1);
    hash.Int(mZ1);
    hash.Float(mBaseLevel);
    hash.Float(mLevelMin);
    hash.Float(mLevelMax);
    hash.Bytes(mLevel.data(), mLevel.size() * sizeof(std::uint16_t));
    hash.Bytes(mFlow.data(), mFlow.size());
    hash.Bytes(mWet.data(), mWet.size());
    hash.Bytes(mFallBits.data(), mFallBits.size());
    return hash.value;
  }
} // namespace moho
