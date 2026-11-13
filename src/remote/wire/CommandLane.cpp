#include "remote/wire/CommandLane.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>
#include <utility>

// Engine addition, server mode: see CommandLane.h.

namespace faf::remote::wire
{
  namespace
  {
    // Past these a lane is damaged: no command has more units than the sim's entity ids allow in a beat's packet, and
    // the Lua payload is a short table's text.
    constexpr std::uint32_t kMaxCount = 1u << 20;
    constexpr std::uint32_t kMaxScriptBytes = 1u << 16;

    constexpr std::uint8_t kTargetHasEntity = 1u;
    constexpr std::uint8_t kTargetHasPosition = 2u;

    // A command id's top byte is its source (0x80 the sim's, else a player's), its low 24 bits a serial: rotated left
    // by a byte, its varint is as short as its serial (two bytes up to 16383 a source).
    [[nodiscard]] constexpr std::uint32_t PackCommandId(
      const std::uint32_t id
    ) noexcept
    {
      return (id << 8) | (id >> 24);
    }
    [[nodiscard]] constexpr std::uint32_t UnpackCommandId(
      const std::uint32_t packed
    ) noexcept
    {
      return (packed >> 8) | (packed << 24);
    }

    class CLaneWriter
    {
    public:
      explicit CLaneWriter(
        std::vector<std::uint8_t>& out
      ) noexcept
        : mOut(out)
      {}

      void Varint(
        std::uint32_t value
      )
      {
        while (value >= 0x80u) {
          mOut.push_back(static_cast<std::uint8_t>(value | 0x80u));
          value >>= 7;
        }
        mOut.push_back(static_cast<std::uint8_t>(value));
      }
      void Int(
        const std::int32_t value
      )
      {
        const auto bits = static_cast<std::uint32_t>(value);
        Varint((bits << 1) ^ (value < 0 ? 0xFFFFFFFFu : 0u));
      }
      void Byte(
        const std::uint8_t value
      )
      {
        mOut.push_back(value);
      }
      void Float(
        const float value
      )
      {
        std::uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        for (int shift = 0; shift < 32; shift += 8) {
          mOut.push_back(static_cast<std::uint8_t>(bits >> shift));
        }
      }
      void Text(
        const std::string& text
      )
      {
        Varint(static_cast<std::uint32_t>(text.size()));
        mOut.insert(mOut.end(), text.begin(), text.end());
      }

    private:
      std::vector<std::uint8_t>& mOut;
    };

    class CLaneCursor
    {
    public:
      explicit CLaneCursor(
        const std::span<const std::uint8_t> bytes
      ) noexcept
        : mBytes(bytes)
      {}

      [[nodiscard]] bool Ok() const noexcept
      {
        return mOk;
      }
      [[nodiscard]] bool AtEnd() const noexcept
      {
        return mAt >= mBytes.size();
      }
      [[nodiscard]] std::size_t Remaining() const noexcept
      {
        return mAt < mBytes.size() ? mBytes.size() - mAt : 0u;
      }
      void Fail() noexcept
      {
        mOk = false;
      }

      std::uint8_t Byte() noexcept
      {
        if (mAt >= mBytes.size()) {
          mOk = false;
          return 0u;
        }
        return mBytes[mAt++];
      }
      std::uint32_t Varint() noexcept
      {
        std::uint32_t value = 0;
        for (int shift = 0; shift < 35; shift += 7) {
          const std::uint8_t byte = Byte();
          if (!mOk) {
            return 0u;
          }
          value |= static_cast<std::uint32_t>(byte & 0x7Fu) << shift;
          if ((byte & 0x80u) == 0u) {
            return value;
          }
        }
        mOk = false; // longer than a 32-bit varint
        return 0u;
      }
      std::int32_t Int() noexcept
      {
        const std::uint32_t bits = Varint();
        return static_cast<std::int32_t>((bits >> 1) ^ (0u - (bits & 1u)));
      }
      float Float() noexcept
      {
        std::uint32_t bits = 0;
        for (int shift = 0; shift < 32; shift += 8) {
          bits |= static_cast<std::uint32_t>(Byte()) << shift;
        }
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
      }
      /** A count of elements each at least `minBytes` long: past the lane's end is damage. */
      std::uint32_t Count(
        const std::size_t minBytes
      ) noexcept
      {
        const std::uint32_t count = Varint();
        if (count > kMaxCount || static_cast<std::size_t>(count) * minBytes > Remaining()) {
          mOk = false;
          return 0u;
        }
        return count;
      }
      void Text(
        std::string& out
      )
      {
        const std::uint32_t length = Varint();
        if (!mOk || length > kMaxScriptBytes || length > Remaining()) {
          mOk = false;
          return;
        }
        out.assign(reinterpret_cast<const char*>(mBytes.data() + mAt), length);
        mAt += length;
      }

    private:
      std::span<const std::uint8_t> mBytes;
      std::size_t mAt = 0;
      bool mOk = true;
    };

    void WriteTarget(
      CLaneWriter& writer,
      const SCommandTarget& target
    )
    {
      static constexpr std::array<float, 3> kZero{};
      const bool hasEntity = target.entity != kNoCommandEntity;
      const bool hasPosition = std::memcmp(target.position.data(), kZero.data(), sizeof(kZero)) != 0; // -0 goes
      writer.Int(target.type);
      writer.Byte(
        static_cast<std::uint8_t>((hasEntity ? kTargetHasEntity : 0u) | (hasPosition ? kTargetHasPosition : 0u))
      );
      if (hasEntity) {
        writer.Varint(target.entity);
      }
      if (hasPosition) {
        for (const float value : target.position) {
          writer.Float(value);
        }
      }
    }

    void ReadTarget(
      CLaneCursor& cursor,
      SCommandTarget& target
    )
    {
      target.type = cursor.Int();
      const std::uint8_t flags = cursor.Byte();
      if ((flags & ~(kTargetHasEntity | kTargetHasPosition)) != 0u) {
        cursor.Fail(); // a flag this build doesn't know: damage
        return;
      }
      target.entity = (flags & kTargetHasEntity) != 0u ? cursor.Varint() : kNoCommandEntity;
      target.position = {};
      if ((flags & kTargetHasPosition) != 0u) {
        for (float& value : target.position) {
          value = cursor.Float();
        }
      }
    }
  } // namespace

  std::uint32_t CommandFieldsChanged(
    const SCommandData& held,
    const SCommandData& now
  )
  {
    std::uint32_t fields = 0;
    fields |= held.units != now.units ? kCommandUnits : 0u;
    fields |= held.type != now.type ? kCommandType : 0u;
    fields |= held.target1 != now.target1 ? kCommandTarget1 : 0u;
    fields |= held.target2 != now.target2 ? kCommandTarget2 : 0u;
    fields |= held.extra != now.extra ? kCommandExtra : 0u;
    fields |= held.cells != now.cells ? kCommandCells : 0u;
    fields |= held.maxCount != now.maxCount || held.count != now.count ? kCommandCounts : 0u;
    fields |= held.flags != now.flags ? kCommandFlags : 0u;
    return fields;
  }

  void ApplyCommandFields(
    SCommandData& held,
    const SCommandUpdate& update
  )
  {
    const SCommandData& data = update.data;
    if ((update.fields & kCommandUnits) != 0u) {
      held.units = data.units;
    }
    if ((update.fields & kCommandType) != 0u) {
      held.type = data.type;
    }
    if ((update.fields & kCommandTarget1) != 0u) {
      held.target1 = data.target1;
    }
    if ((update.fields & kCommandTarget2) != 0u) {
      held.target2 = data.target2;
    }
    if ((update.fields & kCommandExtra) != 0u) {
      held.extra = data.extra;
    }
    if ((update.fields & kCommandCells) != 0u) {
      held.cells = data.cells;
    }
    if ((update.fields & kCommandCounts) != 0u) {
      held.maxCount = data.maxCount;
      held.count = data.count;
    }
    if ((update.fields & kCommandFlags) != 0u) {
      held.flags = data.flags;
    }
  }

  void EncodeCommandLane(
    const SCommandLane& lane,
    std::vector<std::uint8_t>& out
  )
  {
    out.clear();
    if (lane.Empty()) {
      return;
    }
    CLaneWriter writer(out);
    writer.Varint(lane.whole ? 1u : 0u);
    writer.Varint(static_cast<std::uint32_t>(lane.descriptors.size()));
    for (const SCommandDescriptor& descriptor : lane.descriptors) {
      writer.Varint(PackCommandId(descriptor.id));
      writer.Int(descriptor.formation);
      for (const float value : descriptor.origin) {
        writer.Float(value);
      }
      writer.Float(descriptor.scale);
      writer.Varint(descriptor.blueprint);
      writer.Text(descriptor.script);
    }
    writer.Varint(static_cast<std::uint32_t>(lane.updates.size()));
    for (const SCommandUpdate& update : lane.updates) {
      writer.Varint(PackCommandId(update.id));
      writer.Varint(update.fields & kCommandAllFields);
      const SCommandData& data = update.data;
      if ((update.fields & kCommandUnits) != 0u) {
        writer.Varint(static_cast<std::uint32_t>(data.units.size()));
        for (const std::uint32_t unit : data.units) {
          writer.Varint(unit);
        }
      }
      if ((update.fields & kCommandType) != 0u) {
        writer.Int(data.type);
      }
      if ((update.fields & kCommandTarget1) != 0u) {
        WriteTarget(writer, data.target1);
      }
      if ((update.fields & kCommandTarget2) != 0u) {
        WriteTarget(writer, data.target2);
      }
      if ((update.fields & kCommandExtra) != 0u) {
        writer.Int(data.extra);
      }
      if ((update.fields & kCommandCells) != 0u) {
        writer.Varint(static_cast<std::uint32_t>(data.cells.size()));
        for (const SCommandCell& cell : data.cells) {
          writer.Int(cell.x);
          writer.Int(cell.z);
        }
      }
      if ((update.fields & kCommandCounts) != 0u) {
        writer.Int(data.maxCount);
        writer.Int(data.count);
      }
      if ((update.fields & kCommandFlags) != 0u) {
        writer.Varint(data.flags);
      }
    }
    for (const std::vector<std::uint32_t>* const ids : {&lane.removals, &lane.releases}) {
      writer.Varint(static_cast<std::uint32_t>(ids->size()));
      for (const std::uint32_t id : *ids) {
        writer.Varint(PackCommandId(id));
      }
    }
  }

  bool DecodeCommandLane(
    const std::span<const std::uint8_t> bytes,
    SCommandLane& out
  )
  {
    out.Clear();
    if (bytes.empty()) {
      return true;
    }
    CLaneCursor cursor(bytes);
    const std::uint32_t flags = cursor.Varint();
    if (!cursor.Ok() || flags > 1u) {
      return false;
    }
    out.whole = flags == 1u;

    const std::uint32_t descriptors = cursor.Count(1u + 1u + 16u + 4u + 1u + 1u);
    out.descriptors.resize(descriptors);
    for (SCommandDescriptor& descriptor : out.descriptors) {
      descriptor.id = UnpackCommandId(cursor.Varint());
      descriptor.formation = cursor.Int();
      for (float& value : descriptor.origin) {
        value = cursor.Float();
      }
      descriptor.scale = cursor.Float();
      descriptor.blueprint = cursor.Varint();
      cursor.Text(descriptor.script);
      if (!cursor.Ok()) {
        return false;
      }
    }

    const std::uint32_t updates = cursor.Count(2u);
    out.updates.resize(updates);
    for (SCommandUpdate& update : out.updates) {
      update.id = UnpackCommandId(cursor.Varint());
      update.fields = cursor.Varint();
      if (!cursor.Ok() || (update.fields & ~kCommandAllFields) != 0u) {
        return false;
      }
      SCommandData& data = update.data;
      if ((update.fields & kCommandUnits) != 0u) {
        data.units.resize(cursor.Count(1u));
        for (std::uint32_t& unit : data.units) {
          unit = cursor.Varint();
        }
      }
      if ((update.fields & kCommandType) != 0u) {
        data.type = cursor.Int();
      }
      if ((update.fields & kCommandTarget1) != 0u) {
        ReadTarget(cursor, data.target1);
      }
      if ((update.fields & kCommandTarget2) != 0u) {
        ReadTarget(cursor, data.target2);
      }
      if ((update.fields & kCommandExtra) != 0u) {
        data.extra = cursor.Int();
      }
      if ((update.fields & kCommandCells) != 0u) {
        data.cells.resize(cursor.Count(2u));
        for (SCommandCell& cell : data.cells) {
          cell.x = static_cast<std::int16_t>(cursor.Int());
          cell.z = static_cast<std::int16_t>(cursor.Int());
        }
      }
      if ((update.fields & kCommandCounts) != 0u) {
        data.maxCount = cursor.Int();
        data.count = cursor.Int();
      }
      if ((update.fields & kCommandFlags) != 0u) {
        data.flags = cursor.Varint();
      }
      if (!cursor.Ok()) {
        return false;
      }
    }

    for (std::vector<std::uint32_t>* const ids : {&out.removals, &out.releases}) {
      ids->resize(cursor.Count(1u));
      for (std::uint32_t& id : *ids) {
        id = UnpackCommandId(cursor.Varint());
      }
    }
    return cursor.Ok() && cursor.AtEnd();
  }

  bool CCommandLaneReceiver::Apply(
    const std::span<const std::uint8_t> lane,
    SBeat& out
  )
  {
    out.Clear();
    if (lane.empty()) {
      return true;
    }
    mCounts.bytes += lane.size();
    if (!DecodeCommandLane(lane, mLane)) {
      ++mCounts.failures;
      return false;
    }
    ++mCounts.lanes;
    if (mLane.whole) {
      // The client holds only what this lane describes: the rest of its helpers go, as a removal each.
      ++mCounts.wholes;
      std::unordered_set<std::uint32_t> described;
      described.reserve(mLane.descriptors.size());
      for (const SCommandDescriptor& descriptor : mLane.descriptors) {
        described.insert(descriptor.id);
      }
      std::vector<std::uint32_t> forgotten;
      for (const auto& [id, data] : mHeld) {
        if (described.count(id) == 0u) {
          forgotten.push_back(id);
        }
      }
      std::sort(forgotten.begin(), forgotten.end());
      for (const std::uint32_t id : forgotten) {
        mHeld.erase(id);
        out.removals.push_back(id);
      }
      mCounts.forgotten += forgotten.size();
    }
    for (SCommandDescriptor& descriptor : mLane.descriptors) {
      mHeld[descriptor.id] = SCommandData{};
      out.descriptors.push_back(std::move(descriptor));
    }
    mCounts.descriptors += mLane.descriptors.size();
    for (const SCommandUpdate& update : mLane.updates) {
      const auto held = mHeld.find(update.id);
      if (held == mHeld.end()) {
        ++mCounts.droppedUpdates;
        continue;
      }
      ApplyCommandFields(held->second, update);
      out.updates.emplace_back(update.id, held->second);
      ++mCounts.updates;
    }
    for (const std::uint32_t id : mLane.removals) {
      if (mHeld.erase(id) == 0u) {
        ++mCounts.droppedRemovals;
        continue;
      }
      out.removals.push_back(id);
      ++mCounts.removals;
    }
    for (const std::uint32_t id : mLane.releases) {
      // `DeleteCommandIssueHelpers` takes any id: one with no helper only gives its number back to the client's own
      // pool when it is one of the client's.
      mHeld.erase(id);
      out.releases.push_back(id);
      ++mCounts.releases;
    }
    return true;
  }
} // namespace faf::remote::wire
