#include "remote/wire/EffectLane.h"

#include <cstring>
#include <utility>

namespace faf::remote::wire
{
  namespace
  {
    // The longest name the reader takes, and the most floats one op carries: past them a lane is damaged.
    constexpr std::uint32_t kMaxNameBytes = 4096u;
    constexpr std::uint32_t kMaxFloats = 65536u;

    class CLaneCursor
    {
    public:
      explicit CLaneCursor(
        const std::span<const std::uint8_t> bytes
      ) noexcept
        : mBytes(bytes)
      {}

      [[nodiscard]] bool AtEnd() const noexcept
      {
        return mAt >= mBytes.size();
      }
      [[nodiscard]] bool Ok() const noexcept
      {
        return mOk;
      }
      [[nodiscard]] std::size_t Remaining() const noexcept
      {
        return mAt < mBytes.size() ? mBytes.size() - mAt : 0u;
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
        return static_cast<std::int32_t>(Varint() - 1u);
      }

      const std::uint8_t* Take(
        const std::size_t count
      ) noexcept
      {
        if (count > Remaining()) {
          mOk = false;
          return nullptr;
        }
        const std::uint8_t* const at = mBytes.data() + mAt;
        mAt += count;
        return at;
      }

      void Floats(
        const std::uint32_t count,
        std::vector<float>& out
      ) noexcept
      {
        if (count > kMaxFloats || static_cast<std::size_t>(count) * 4u > Remaining()) {
          mOk = false;
          return;
        }
        out.resize(count);
        for (std::uint32_t i = 0; i < count; ++i) {
          const std::uint8_t* const bytes = Take(4u);
          const std::uint32_t bits = static_cast<std::uint32_t>(bytes[0]) |
            (static_cast<std::uint32_t>(bytes[1]) << 8) | (static_cast<std::uint32_t>(bytes[2]) << 16) |
            (static_cast<std::uint32_t>(bytes[3]) << 24);
          std::memcpy(&out[i], &bits, sizeof(float));
        }
      }

    private:
      std::span<const std::uint8_t> mBytes;
      std::size_t mAt = 0;
      bool mOk = true;
    };
  } // namespace

  const std::string* CEffectLaneReader::Name(
    const bool textures,
    const std::uint32_t ref
  ) const noexcept
  {
    const std::vector<SName>& names = mNames[textures ? 1 : 0];
    if (ref == 0u || ref - 1u >= names.size() || !names[ref - 1u].held) {
      return nullptr;
    }
    return &names[ref - 1u].text;
  }

  bool CEffectLaneReader::Read(
    const std::span<const std::uint8_t> lane,
    std::vector<SEffectLaneOp>& ops
  )
  {
    ops.clear();
    if (lane.empty()) {
      return true;
    }
    CLaneCursor cursor(lane);
    for (std::vector<SName>& names : mNames) {
      const std::uint32_t count = cursor.Varint();
      for (std::uint32_t i = 0; i < count && cursor.Ok(); ++i) {
        const std::uint32_t entry = cursor.Varint();
        const std::uint32_t length = cursor.Varint();
        if (!cursor.Ok() || length > kMaxNameBytes || entry > (1u << 24)) {
          return false;
        }
        const std::uint8_t* const text = cursor.Take(length);
        if (!cursor.Ok()) {
          return false;
        }
        if (entry >= names.size()) {
          names.resize(static_cast<std::size_t>(entry) + 1u);
        }
        names[entry].text.assign(reinterpret_cast<const char*>(text), length);
        names[entry].held = true;
        ++mNamesTaken;
      }
      if (!cursor.Ok()) {
        return false;
      }
    }

    const auto readName = [&](const bool textures) {
      const std::uint32_t ref = cursor.Varint();
      if (cursor.Ok() && ref != 0u && Name(textures, ref) == nullptr) {
        ++mUnknownNames;
      }
      return ref;
    };

    using moho::EEffectOp;
    while (!cursor.AtEnd()) {
      SEffectLaneOp op;
      const std::uint8_t kind = cursor.Byte();
      if (
        kind >= static_cast<std::uint8_t>(EEffectOp::Count) || kind == static_cast<std::uint8_t>(EEffectOp::Destroy)
      ) {
        return false;
      }
      op.op = static_cast<EEffectOp>(kind);
      if (op.op != EEffectOp::CreateLightParticle) {
        op.id = cursor.Varint();
      }
      switch (op.op) {
      case EEffectOp::CreateEmitter:
        op.blueprint = readName(false);
        op.army = cursor.Int();
        cursor.Floats(3u, op.values);
        break;
      case EEffectOp::CreateAttachedEmitter:
      case EEffectOp::CreateEmitterAtBone:
      case EEffectOp::CreateTrail:
        op.entity = cursor.Int();
        op.bone = cursor.Int();
        op.blueprint = readName(false);
        op.army = cursor.Int();
        break;
      case EEffectOp::CreateEmitterAtEntity:
      case EEffectOp::CreateEmitterOnEntity:
        op.entity = cursor.Int();
        op.blueprint = readName(false);
        op.army = cursor.Int();
        break;
      case EEffectOp::CreateBeam:
        op.blueprint = readName(false);
        if (op.blueprint == 0u) {
          op.entity = cursor.Int();
          op.bone = cursor.Int();
          op.army = cursor.Int();
          op.texture = readName(true);
          op.param = cursor.Int();
          cursor.Floats(cursor.Varint(), op.values);
        } else {
          op.army = cursor.Int();
        }
        break;
      case EEffectOp::CreateBeamEntityToEntity:
      case EEffectOp::AttachBeamEntityToEntity:
        op.entity = cursor.Int();
        op.bone = cursor.Int();
        op.entity2 = cursor.Int();
        op.bone2 = cursor.Int();
        op.blueprint = readName(false);
        op.army = cursor.Int();
        break;
      case EEffectOp::CreateLightParticle:
        op.army = cursor.Int();
        op.texture = readName(true);
        op.texture2 = readName(true);
        cursor.Floats(5u, op.values);
        break;
      case EEffectOp::SetFloat:
        op.param = cursor.Int();
        cursor.Floats(1u, op.values);
        break;
      case EEffectOp::SetVector:
      case EEffectOp::SetN:
      case EEffectOp::SetCurve:
        op.param = cursor.Int();
        cursor.Floats(cursor.Varint(), op.values);
        break;
      case EEffectOp::SetEntity:
        op.entity = cursor.Int();
        break;
      case EEffectOp::SetBone:
        op.entity = cursor.Int();
        op.bone = cursor.Int();
        break;
      case EEffectOp::DestroyByScript:
      case EEffectOp::Destroy:
      case EEffectOp::Count:
        break;
      }
      if (!cursor.Ok()) {
        return false;
      }
      ops.push_back(std::move(op));
    }
    return true;
  }
} // namespace faf::remote::wire
