#include "ReadArchive.h"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <istream>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/EAiResult.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/ai/IAiSteering.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/audio/ISoundManager.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/command/CCommandDb.h"
#include "moho/entity/Entity.h"
#include "moho/entity/Motor.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/Shield.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/PositionHistory.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/StatItem.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/sim/ReconBlip.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArmy.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SPhysBody.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskEvent.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "String.h"
#include "lua/LuaObject.h"

using namespace gpg;

namespace
{
  [[noreturn]] void ThrowSerializationError(const char* const message)
  {
    throw SerializationError(message ? message : "");
  }

  [[noreturn]] void ThrowSerializationError(const msvc8::string& message)
  {
    throw SerializationError(message.c_str());
  }

  const char* SafeTypeName(const RType* const type)
  {
    return type ? type->GetName() : "null";
  }

  [[nodiscard]] gpg::RType* CachedCSndParamsType2()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CSndParams));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintType2()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCParticleTextureType()
  {
    gpg::RType* type = moho::CParticleTexture::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CParticleTexture));
      moho::CParticleTexture::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    gpg::RType* type = moho::IFormationInstance::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IFormationInstance));
      moho::IFormationInstance::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerNavPathType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {
        "Moho::Listener<Moho::NavPath const &>",
        "Listener<Moho::NavPath const &>",
        "Moho::Listener<Moho::SNavPath const &>",
        "Listener<Moho::SNavPath const &>",
      };
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached) {
          break;
        }
      }

      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Listener<const moho::SNavPath&>));
      }
    }
    return cached;
  }

  // Per-type reflected upcasts. Each of these is a distinct function in the
  // binary that the ReadPointerOwned_* readers call rather than open-coding
  // the REF_UpcastPtr sequence; they lazily resolve the target RType, upcast
  // the reference, and hand back the pointee (null when the runtime type does
  // not derive from the requested one, which the caller turns into an error).

  // Reflected per-type upcasts. Each of these is its own function in the
  // binary that the corresponding reader calls, rather than open-coding the
  // REF_UpcastPtr sequence at the call site.

  /**
   * Address: 0x0065AF60 (FUN_0065AF60, gpg::RRef::Upcast_CParticleTexture)
   *
   * What it does:
   * Upcasts one reflected reference to `moho::CParticleTexture`, returning null when
   * the reference does not denote that type.
   */
  [[nodiscard]] moho::CParticleTexture* UpcastToCParticleTexture(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCParticleTextureType());
    return static_cast<moho::CParticleTexture*>(upcast.mObj);
  }

  class BinaryReadArchive final : public gpg::ReadArchive
  {
  public:
    explicit BinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
      : mFile(file)
      , mCachedFile(file.get())
    {
    }

    /**
     * Address: 0x00904810 (FUN_00904810)
     *
     * What it does:
     * Runs non-deleting teardown for one binary-read archive lane, releasing
     * file shared-owner state before base `ReadArchive` destruction.
     */
    ~BinaryReadArchive() override = default;

    /**
     * Address: 0x00904960 (FUN_00904960, gpg::BinaryReadArchive::ReadBytes)
     *
     * What it does:
     * Reads one contiguous byte range from the backing FILE and throws
     * serialization failure on EOF/read errors.
     */
    void ReadBytes(char* const bytes, const size_t byteCount) override
    {
      // Ground truth is exactly this shape, and the details matter:
      //
      //   if (fread(a2, a3, 1u, this->str) != 1) {
      //     if (feof(this->str))  throw runtime_error("eof");
      //     if (ferror(this->str)) throw runtime_error("noread");
      //   }
      //
      // A short read with NEITHER flag set falls out of the branch and
      // returns normally - it is not an error. A zero-length read is not
      // special-cased either: `fread(p, 0, 1, f)` returns 0, so at EOF a
      // 0-byte read throws "eof" here. Both behaviours were lost to an
      // earlier defensive rewrite (null guards, an early return on
      // `byteCount == 0`, and an unconditional throw) that this restores.
      if (std::fread(bytes, byteCount, 1, mCachedFile) == 1) {
        return;
      }

      if (std::feof(mCachedFile) != 0) {
        ThrowSerializationError("eof");
      }

      if (std::ferror(mCachedFile) != 0) {
        ThrowSerializationError("noread");
      }
    }

    /**
     * Address: 0x00905600 (FUN_00905600, BinaryReadArchive::ReadString)
     *
     * What it does:
     * Reads one length-prefixed string payload by first loading a 32-bit byte
     * count, resizing the destination string, and then reading raw bytes.
     */
    void ReadString(msvc8::string* const out) override
    {
      unsigned int byteCount = 0;
      ReadInt2(&byteCount);

      const size_t currentSize = out->size();
      if (byteCount > currentSize) {
        std::string resized = out->to_std();
        resized.resize(byteCount, '\0');
        out->assign_owned(std::string_view(resized.data(), resized.size()));
      } else {
        out->erase(byteCount);
      }

      if (byteCount != 0U) {
        ReadBytes(out->raw_data_mut_unsafe(), byteCount);
      }
    }

    /**
     * Address: 0x009055F0 (FUN_009055F0, BinaryReadArchive::ReadFloat)
     * Address: 0x0098FEC0 (FUN_0098FEC0)
     *
     * What it does:
     * Reads one 32-bit float lane from the binary archive stream.
     */
    void ReadFloat(float* const value) override
    {
      ReadFloat2(value);
    }

    /**
     * Address: 0x009055E0 (FUN_009055E0, BinaryReadArchive::ReadDouble)
     *
     * What it does:
     * Reads one 64-bit primitive lane used by this archive vtable slot.
     */
    void ReadUInt64(unsigned __int64* const value) override
    {
      ReadUInt642(value);
    }

    /**
     * Address: 0x009055D0 (FUN_009055D0, BinaryReadArchive::ReadInt64)
     *
     * What it does:
     * Reads one signed 64-bit primitive lane from the stream.
     */
    void ReadInt64(__int64* const value) override
    {
      ReadInt642(value);
    }

    /**
     * Address: 0x009055C0 (FUN_009055C0, BinaryReadArchive::ReadULong)
     *
     * What it does:
     * Reads one unsigned long lane from the stream.
     */
    void ReadULong(unsigned long* const value) override
    {
      ReadULong2(value);
    }

    /**
     * Address: 0x009055B0 (FUN_009055B0, BinaryReadArchive::ReadLong)
     *
     * What it does:
     * Reads one signed long lane from the stream.
     */
    void ReadLong(long* const value) override
    {
      ReadLong2(value);
    }

    /**
     * Address: 0x009055A0 (FUN_009055A0, BinaryReadArchive::ReadUInt)
     * Address: 0x009C6860 (FUN_009C6860)
     *
     * What it does:
     * Thunk lane that forwards 32-bit primitive reads to `ReadInt2`.
     */
    void ReadUInt(unsigned int* const value) override
    {
      ReadInt2(value);
    }

    /**
     * Address: 0x00905590 (FUN_00905590, BinaryReadArchive::ReadInt)
     *
     * What it does:
     * Thunk lane forwarding signed 32-bit reads to `ReadUInt2`.
     */
    void ReadInt(int* const value) override
    {
      ReadUInt2(value);
    }

    /**
     * Address: 0x00905580 (FUN_00905580, BinaryReadArchive::ReadUShort)
     *
     * What it does:
     * Reads one unsigned 16-bit primitive lane from the stream.
     */
    void ReadUShort(unsigned short* const value) override
    {
      ReadUShort2(value);
    }

    /**
     * Address: 0x00905570 (FUN_00905570, BinaryReadArchive::ReadShort)
     *
     * What it does:
     * Reads one signed 16-bit primitive lane from the stream.
     */
    void ReadShort(short* const value) override
    {
      ReadShort2(value);
    }

    /**
     * Address: 0x00905560 (FUN_00905560, BinaryReadArchive::ReadUByte)
     *
     * What it does:
     * Reads one unsigned byte lane through the shared one-byte read helper.
     */
    void ReadUByte(unsigned __int8* const value) override
    {
      ReadUByte2(value);
    }

    /**
     * Address: 0x00905550 (FUN_00905550, BinaryReadArchive::ReadByte)
     *
     * What it does:
     * Reads one signed byte lane through the shared one-byte read helper.
     */
    void ReadByte(__int8* const value) override
    {
      ReadByte2(value);
    }

    /**
     * Address: 0x00905540 (FUN_00905540, BinaryReadArchive::ReadBool)
     *
     * What it does:
     * Thunk lane forwarding bool reads to `ReadBool2`.
     */
    void ReadBool(bool* const value) override
    {
      ReadBool2(value);
    }

    /**
     * Address: 0x00905670 (FUN_00905670, BinaryReadArchive::NextToken)
     *
     * What it does:
     * Reads one marker byte and maps lexical archive tokens (`} N 0 * {`) to
     * runtime `ArchiveToken` integers; throws on unknown marker bytes.
     */
    int NextMarker() override
    {
      signed char marker = 0;
      ReadBool2(&marker);

      switch (marker) {
      case '}':
        return static_cast<int>(ArchiveToken::ObjectTerminator);
      case 'N':
        return static_cast<int>(ArchiveToken::NewObjectToken);
      case '0':
        return static_cast<int>(ArchiveToken::NullPointerToken);
      case '*':
        return static_cast<int>(ArchiveToken::ExistingPointerToken);
      case '{':
        return static_cast<int>(ArchiveToken::ObjectStart);
      default:
        ThrowSerializationError(
          STR_Printf("Error detected in archive: invalid marker token 0x%02x", static_cast<int>(marker))
        );
      }
    }

  private:
    /**
     * Address: 0x00904AB0 (FUN_00904AB0, BinaryReadArchive::ReadBool2)
     *
     * What it does:
     * Reads one byte lane from the backing FILE and throws
     * `SerializationError("eof")`/`SerializationError("noread")` on stream
     * failure states.
     */
    void ReadBool2(void* const outValue)
    {
      std::FILE* const file = mCachedFile;
      if (std::fread(outValue, 1u, 1u, file) != 1) {
        if (std::feof(file) != 0) {
          ThrowSerializationError("eof");
        }

        if (std::ferror(file) != 0) {
          ThrowSerializationError("noread");
        }
      }
    }

    /**
     * Address: 0x00904B40 (FUN_00904B40)
     *
     * What it does:
     * One-byte signed lane helper used by `ReadByte`.
     */
    void ReadByte2(void* const outValue)
    {
      ReadBool2(outValue);
    }

    /**
     * Address: 0x00904BD0 (FUN_00904BD0)
     *
     * What it does:
     * One-byte unsigned lane helper used by `ReadUByte`.
     */
    void ReadUByte2(void* const outValue)
    {
      ReadBool2(outValue);
    }

    /**
     * Address: 0x00904C60 (FUN_00904C60)
     *
     * What it does:
     * Two-byte signed lane helper used by `ReadShort`.
     */
    void ReadShort2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(short));
    }

    /**
     * Address: 0x00904CF0 (FUN_00904CF0)
     *
     * What it does:
     * Two-byte unsigned lane helper used by `ReadUShort`.
     */
    void ReadUShort2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(unsigned short));
    }

    /**
     * Address: 0x00904D80 (FUN_00904D80, BinaryReadArchive::ReadUInt2)
     *
     * What it does:
     * Reads one 32-bit lane directly from the backing FILE and throws
     * `SerializationError("eof")`/`SerializationError("noread")` on stream
     * failure states.
     */
    void ReadUInt2(void* const outValue)
    {
      std::FILE* const file = mCachedFile;
      if (std::fread(outValue, 4u, 1u, file) != 1) {
        if (std::feof(file) != 0) {
          ThrowSerializationError("eof");
        }

        if (std::ferror(file) != 0) {
          ThrowSerializationError("noread");
        }
      }
    }

    /**
     * Address: 0x00904E10 (FUN_00904E10, BinaryReadArchive::ReadInt2)
     *
     * What it does:
     * Thunk lane forwarding 32-bit primitive reads to `ReadUInt2`.
     */
    void ReadInt2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904EA0 (FUN_00904EA0)
     *
     * What it does:
     * Signed long lane helper used by `ReadLong`.
     */
    void ReadLong2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904F30 (FUN_00904F30)
     *
     * What it does:
     * Unsigned long lane helper used by `ReadULong`.
     */
    void ReadULong2(void* const outValue)
    {
      ReadUInt2(outValue);
    }

    /**
     * Address: 0x00904FC0 (FUN_00904FC0)
     *
     * What it does:
     * Signed 64-bit lane helper used by `ReadInt64`.
     */
    void ReadInt642(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(__int64));
    }

    /**
     * Address: 0x00905050 (FUN_00905050)
     *
     * What it does:
     * 64-bit lane helper used by the vtable slot recovered as `ReadUInt64`.
     */
    void ReadUInt642(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(unsigned __int64));
    }

    /**
     * Address: 0x009050E0 (FUN_009050E0)
     *
     * What it does:
     * 32-bit float lane helper used by `ReadFloat`.
     */
    void ReadFloat2(void* const outValue)
    {
      ReadBytes(reinterpret_cast<char*>(outValue), sizeof(float));
    }

    // `gpg::CreateBinaryReadArchive` (0x009048B0) allocates 0x44 and sets
    // three members in this order: the shared owner's `px` at +0x38 and
    // `pn.pi_` at +0x3C, then a plain duplicate of the same handle at +0x40.
    // Every read slot dereferences that duplicate rather than the smart
    // pointer -- `BinaryReadArchive::ReadBytes` (0x00904960) is
    // `fread(..., this->str)`, and its `feof`/`ferror` retries use it too.
    // Keeping it is what makes this class 0x44 rather than 0x40.
    boost::shared_ptr<std::FILE> mFile;   // +0x38
    std::FILE* mCachedFile = nullptr;     // +0x40
  };

  static_assert(sizeof(BinaryReadArchive) == 0x44, "BinaryReadArchive size must be 0x44");

  /**
   * Address: 0x00904890 (FUN_00904890)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `BinaryReadArchive`, forwarding
   * through non-deleting teardown and optional storage release.
   */
  [[nodiscard]] BinaryReadArchive* DestroyBinaryReadArchiveDeleting(
    BinaryReadArchive* const archive,
    const unsigned char deleteFlag
  )
  {
    archive->~BinaryReadArchive();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(archive));
    }
    return archive;
  }

  class TextReadArchive : public gpg::ReadArchive
  {
  public:
    /**
     * Address: 0x00939330 (FUN_00939330, ??0TextReadArchive@@QAE@ABV?$shared_ptr@Vistream@std@@@boost@@@Z)
     * Mangled: ??0TextReadArchive@@QAE@ABV?$shared_ptr@Vistream@std@@@boost@@@Z
     *
     * IDA signature:
     * TextReadArchive *__thiscall TextReadArchive::TextReadArchive(TextReadArchive *this, boost::shared_ptr_istream *a2);
     *
     * What it does:
     * Runs `gpg::ReadArchive` base construction, installs the
     * `TextReadArchive` vtable, then copies the caller's
     * `boost::shared_ptr<std::istream>` into the owning slot (retaining its
     * control block via `add_ref_copy()`) and caches the raw
     * `std::istream*` separately for the hot `Read*` accessor paths.
     * Finishes by clearing the stream's error state via
     * `std::ios_base::clear`.
     */
    explicit TextReadArchive(const boost::shared_ptr<std::istream>& stream)
      : mStream(stream)
      , mCachedStream(stream.get())
    {
      mCachedStream->clear();
    }

    /**
     * Address: 0x00939700 (FUN_00939700, ??1TextReadArchive@@QAE@@Z)
     *
     * What it does:
     * Releases the stream shared-owner lane and then runs `gpg::ReadArchive`
     * base destruction. Both halves are compiler-emitted, so the body is
     * empty: 0x0093971E-0x00939755 is `boost::detail::shared_count::
     * ~shared_count` inlined (`lock xadd [pi+4], -1`, then vtable slot 1
     * `dispose()`, then `lock xadd [pi+8], -1`, then slot 2 `destroy()`) and
     * the `call 0x952E40` at 0x00939761 is the `~ReadArchive` base chain.
     * The binary writes no member null-outs on this path.
     */
    ~TextReadArchive() override = default;

    /**
     * Address: 0x0093E770 (FUN_0093E770, TextReadArchive::ReadDouble)
     *
     * What it does:
     * Extracts one unsigned 64-bit token from the text stream lane.
     */
    void ReadUInt64(unsigned __int64* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E760 (FUN_0093E760, TextReadArchive::ReadInt64)
     *
     * What it does:
     * Extracts one signed 64-bit token from the text stream lane.
     */
    void ReadInt64(__int64* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E750 (FUN_0093E750, TextReadArchive::ReadULong)
     *
     * What it does:
     * Extracts one unsigned long token from the text stream lane.
     */
    void ReadULong(unsigned long* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E740 (FUN_0093E740, TextReadArchive::ReadLong)
     *
     * What it does:
     * Extracts one signed long primitive from the text stream lane.
     */
    void ReadLong(long* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E730 (FUN_0093E730, TextReadArchive::ReadUInt)
     *
     * What it does:
     * Extracts one unsigned 32-bit primitive from the text stream lane.
     */
    void ReadUInt(unsigned int* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E720 (FUN_0093E720, TextReadArchive::ReadInt)
     *
     * What it does:
     * Extracts one signed 32-bit primitive from the text stream lane.
     */
    void ReadInt(int* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E710 (FUN_0093E710, TextReadArchive::ReadUShort)
     *
     * What it does:
     * Extracts one unsigned 16-bit primitive from the text stream lane.
     */
    void ReadUShort(unsigned short* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E700 (FUN_0093E700, TextReadArchive::ReadShort)
     *
     * What it does:
     * Extracts one signed 16-bit primitive from the text stream lane.
     */
    void ReadShort(short* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093E6E0 (FUN_0093E6E0, TextReadArchive::ReadUByte)
     *
     * What it does:
     * Reads one integer token from the text stream and truncates it to the low
     * unsigned-byte lane.
     */
    void ReadUByte(unsigned __int8* const value) override
    {
      int parsedValue = 0;
      (*mCachedStream) >> parsedValue;
      *value = static_cast<unsigned __int8>(parsedValue);
    }

    /**
     * Address: 0x0093E6C0 (FUN_0093E6C0, TextReadArchive::ReadByte)
     *
     * What it does:
     * Reads one integer token from the text stream and truncates it to the low
     * signed-byte lane.
     */
    void ReadByte(__int8* const value) override
    {
      int parsedValue = 0;
      (*mCachedStream) >> parsedValue;
      *value = static_cast<__int8>(parsedValue);
    }

    /**
     * Address: 0x0093E6B0 (FUN_0093E6B0, TextReadArchive::ReadBool)
     *
     * What it does:
     * Extracts one bool token from the text archive stream lane.
     */
    void ReadBool(bool* const value) override
    {
      (*mCachedStream) >> *value;
    }

    /**
     * Address: 0x0093B760 (FUN_0093B760, TextReadArchive::ReadBytes)
     *
     * What it does:
     * Reads `byteCount` raw bytes from the text stream, one whitespace-separated
     * hexadecimal token per byte.
     */
    void ReadBytes(char* const bytes, const size_t byteCount) override
    {
      std::istream& stream = *mCachedStream;
      std::string token;
      for (size_t index = 0; index < byteCount; ++index) {
        stream >> token;
        bytes[index] = static_cast<char>(gpg::STR_Xtoi(token.c_str()));
      }
    }

    /**
     * Address: 0x0093ECE0 (FUN_0093ECE0, TextReadArchive::ReadFloat)
     *
     * What it does:
     * Reads one float token; the sentinel text "1.#INF" decodes to +infinity,
     * otherwise the token is parsed as a floating-point value.
     */
    void ReadFloat(float* const value) override
    {
      std::istream& stream = *mCachedStream;
      std::string token;
      stream >> token;
      if (token != "1.#INF") {
        std::istringstream parser(token);
        parser >> *value;
      } else {
        *value = std::numeric_limits<float>::infinity();
      }
    }

    /**
     * Address: 0x0093E780 (FUN_0093E780, TextReadArchive::ReadString)
     *
     * What it does:
     * Parses one double-quoted string primitive, decoding backslash escapes
     * (`\n`, `\t`, `\"`, `\\`, and up to 3-digit octal `\NNN`) into `out`.
     * Throws SerializationError on a malformed or truncated primitive.
     */
    void ReadString(msvc8::string* const out) override
    {
      std::istream& stream = *mCachedStream;
      stream >> std::ws;
      if (stream.get() != '"') {
        ThrowSerializationError("Error detected in archive: malformed string primitive.");
      }

      std::string decoded;
      int ch = stream.get();
      if (ch == std::char_traits<char>::eof()) {
        ThrowSerializationError("Error detected in archive: malformed string primitive.");
      }

      while (ch != '"') {
        if (ch == '\\') {
          const int escape = stream.get();
          switch (escape) {
            case 'n': decoded.push_back('\n'); break;
            case 't': decoded.push_back('\t'); break;
            case '"': decoded.push_back('"'); break;
            case '\\': decoded.push_back('\\'); break;
            default: {
              if (escape < '0' || escape > '7') {
                ThrowSerializationError("Error detected in archive: malformed string primitive.");
              }
              int octalValue = escape - '0';
              int extraDigits = 0;
              while (true) {
                const int next = stream.get();
                if (next < '0' || next > '7') {
                  stream.putback(static_cast<char>(next));
                  decoded.push_back(static_cast<char>(octalValue));
                  break;
                }
                octalValue = octalValue * 8 + (next - '0');
                if (++extraDigits >= 2) {
                  decoded.push_back(static_cast<char>(octalValue));
                  break;
                }
              }
              break;
            }
          }
        } else {
          decoded.push_back(static_cast<char>(ch));
        }

        ch = stream.get();
        if (ch == std::char_traits<char>::eof()) {
          ThrowSerializationError("Error detected in archive: malformed string primitive.");
        }
      }

      out->assign_owned(std::string_view(decoded.data(), decoded.size()));
    }

    /**
     * Address: 0x0093B810 (FUN_0093B810, TextReadArchive::NextMarker)
     *
     * What it does:
     * Reads one section-marker token from the text stream and maps it to the
     * archive marker code (`N`=1, `0`=2, `*`=3, `{`=4, `}`=0); throws on any
     * other character.
     */
    int NextMarker() override
    {
      std::istream& stream = *mCachedStream;
      char marker = 0;
      stream >> marker;
      switch (marker) {
        case 'N': return 1;
        case '0': return 2;
        case '*': return 3;
        case '{': return 4;
        case '}': return 0;
        default:
          ThrowSerializationError(
            gpg::STR_Printf("Error detected in archive: invalid marker token 0x%02x", marker).c_str());
      }
    }

    // The ctor at 0x00939330 fills three lanes in declaration order: the
    // shared owner's `px` at +0x38 (0x0093935E) and `pn.pi_` at +0x3C
    // (0x0093936E, retained by the `lock xadd [pi+4], 1` at 0x0093937B),
    // then a plain duplicate of the same handle at +0x40 (0x00939381).
    // Every read slot dereferences that duplicate rather than the smart
    // pointer -- exactly as the sibling `BinaryReadArchive` caches its
    // `std::FILE*`. Keeping it is what makes this class 0x44 rather than
    // 0x40, which is the size `CreateTextReadArchive` allocates.
    boost::shared_ptr<std::istream> mStream; // +0x38
    std::istream* mCachedStream = nullptr;   // +0x40
  };

  static_assert(sizeof(TextReadArchive) == 0x44, "TextReadArchive size must be 0x44");

  /**
   * Address: 0x009397E0 (FUN_009397E0, TextReadArchive::dtr)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `TextReadArchive`, forwarding
   * through non-deleting teardown and optional storage release.
   */
  [[maybe_unused]] [[nodiscard]] TextReadArchive* DestroyTextReadArchiveDeleting(
    TextReadArchive* const archive,
    const unsigned char deleteFlag
  )
  {
    archive->~TextReadArchive();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(archive));
    }
    return archive;
  }

  /**
   * Address: 0x00952C90 (FUN_00952C90)
   *
   * What it does:
   * Appends one reflected `TypeHandle` lane to the archive-local handle table,
   * preserving the in-capacity fast path and vector-growth fallback behavior.
   */
  TypeHandle* AppendTypeHandle(msvc8::vector<TypeHandle>& typeHandles, const TypeHandle& handle)
  {
    const std::size_t insertIndex = typeHandles.size();
    typeHandles.push_back(handle);
    return &typeHandles[insertIndex];
  }
} // namespace

/**
 * Address: 0x00939800 (FUN_00939800, ?CreateTextReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@Vistream@std@@@boost@@@Z)
 * Mangled: ?CreateTextReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@Vistream@std@@@boost@@@Z
 *
 * IDA signature:
 * gpg::ReadArchive *__cdecl gpg::CreateTextReadArchive(boost::shared_ptr_istream *a1);
 *
 * What it does:
 * Heap-allocates and constructs one `TextReadArchive` bound to the given
 * input stream, returning it through the polymorphic `gpg::ReadArchive*`
 * factory interface. Returns `nullptr` if allocation fails.
 */
ReadArchive* gpg::CreateTextReadArchive(const boost::shared_ptr<std::istream>& stream)
{
  // `push 44h` at 0x00939816 is sizeof(TextReadArchive) now that the class
  // declares its own stream lanes, so the size comes from the type instead of
  // a literal. The binary calls the plain `operator new` (??2@YAPAXI@Z) and
  // MSVC8 emits its own null check at 0x00939823 before running the ctor,
  // returning null on failure; `std::nothrow` is how that reads in C++20, and
  // matches the sibling `CreateBinaryReadArchive`.
  return new (std::nothrow) TextReadArchive(stream);
}

/**
 * Address: 0x00952B60 (FUN_00952B60, ??0ReadArchive@gpg@@QAE@XZ)
 *
 * What it does:
 * Initializes read-archive type/pointer tracking lanes and refreshes global
 * serializer helper registrations used by reflection load paths.
 */
ReadArchive::ReadArchive()
  : mTypeHandles()
  , mTrackedPtrs()
  , mNullTrackedPointer{}
{
  SerHelperBase::InitNewHelpers();
}

/**
 * Address: 0x00952E40 (FUN_00952E40, ??1ReadArchive@gpg@@UAE@XZ)
 * Address: 0x00953700 (FUN_00953700, scalar deleting destructor thunk)
 *
 * What it does:
 * Destroys read-archive bookkeeping state. Binary body is the compiler-emitted
 * defaulted destructor (sets vtable + member subobject teardown).
 */
ReadArchive::~ReadArchive() = default;

/**
 * Address: 0x00952F10 (FUN_00952F10)
 * Demangled: gpg::ReadArchive::ReadTypeHandle
 *
 * What it does:
 * Reads or resolves reflected type/version handle from archive token stream.
 */
TypeHandle ReadArchive::ReadTypeHandle()
{
  int index = 0;
  ReadInt(&index);

  if (index == -1) {
    msvc8::string typeName;
    ReadString(&typeName);

    RType* type = REF_FindTypeNamed(typeName.c_str());
    if (!type) {
      ThrowSerializationError(STR_Printf("No type named \"%s\"", typeName.c_str()));
    }

    int version = 0;
    ReadInt(&version);

    TypeHandle handle{};
    handle.type = type;
    handle.version = version;
    static_cast<void>(AppendTypeHandle(mTypeHandles, handle));
    return handle;
  }

  if (index < 0 || static_cast<size_t>(index) >= mTypeHandles.size()) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found a reference to type index %d, but only %d types have been mentioned.",
      index,
      static_cast<int>(mTypeHandles.size())
    ));
  }

  return mTypeHandles[static_cast<size_t>(index)];
}

/**
 * Address: 0x00953DA0 (FUN_00953DA0)
 * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const &)
 *
 * What it does:
 * Reads one typed object payload using reflection serializer callbacks.
 */
void ReadArchive::Read(const RType* const type, void* const object, const RRef& ownerRef)
{
  if (!type->serLoadFunc_) {
    const RIndexed* pointerType = type->IsPointer();
    if (pointerType) {
      const TrackedPointerInfo tracked = ReadRawPointer(this, ownerRef);
      RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      pointerType->AssignPointer(object, source);
      return;
    }

    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
      SafeTypeName(type)
    ));
  }

  const int marker = NextMarker();
  if (marker != static_cast<int>(ArchiveToken::ObjectStart)) {
    ArchiveToken tokenCopy = static_cast<ArchiveToken>(marker);
    const RRef tokenRef = RRef_ArchiveToken(&tokenCopy);
    const msvc8::string tokenLexical = tokenRef.mType ? tokenRef.GetLexical() : STR_Printf("%d", marker);
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected an OBJECT_START token marking the beginning of a \"%s\", but got a %s "
      "instead.",
      SafeTypeName(type),
      tokenLexical.c_str()
    ));
  }

  const TypeHandle handle = ReadTypeHandle();
  if (handle.type != type) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but expected one of \"%s\".",
      SafeTypeName(handle.type),
      SafeTypeName(type)
    ));
  }

  type->serLoadFunc_(this, reinterpret_cast<int>(object), handle.version, const_cast<RRef*>(&ownerRef));

  if (NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.", SafeTypeName(type)
    ));
  }
}

/**
 * Address: 0x0065A810 (FUN_0065A810, gpg::ReadArchive::ReadPointer_CParticleTexture)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
 * transition, and upcasts the pointee to `moho::CParticleTexture`.
 */
ReadArchive* ReadArchive::ReadPointer_CParticleTexture(
  moho::CParticleTexture** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state == TrackedPointerState::Unowned) {
    tracked.state = TrackedPointerState::Shared;
  }
  if (tracked.state != TrackedPointerState::Shared) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  *outValue = UpcastToCParticleTexture(source);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedCParticleTextureType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "CParticleTexture",
      actualName ? actualName : "null"
    ));
  }

  return this;
}

/**
 * Address: 0x00763C80 (FUN_00763C80, gpg::ReadArchive::ReadPointer_Listener_NavPath)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to
 * `moho::Listener<const moho::SNavPath&>`, raising `SerializationError` when
 * the pointer is not Listener<NavPath const &>-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Listener_NavPath(
  moho::Listener<const moho::SNavPath&>** const outValue,
  const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;
  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedListenerNavPathType());
  *outValue = static_cast<moho::Listener<const moho::SNavPath&>*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedListenerNavPathType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Listener<NavPath const &>",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x007638D0 (FUN_007638D0)
 *
 * What it does:
 * Repeatedly reads `Listener<const SNavPath&>` pointers from `archive` and
 * relinks each non-null listener node into the intrusive ring immediately
 * before the broadcaster sentinel `listHead`. `listHead` is the reflected
 * object (`typeid(moho::Broadcaster<const NavPath&>)`), whose ring head is
 * at offset 0 -- the FUN_007638D0 asm links each node before `listHead`
 * itself.
 */
moho::Listener<const moho::SNavPath&>* gpg::ReadAndLinkNavPathListeners(
  ReadArchive* const archive,
  moho::Broadcaster<const moho::SNavPath&>* const listHead,
  const int version,
  const gpg::RRef* const ownerRef
)
{
  (void)version;

  if (archive == nullptr || listHead == nullptr) {
    return nullptr;
  }

  moho::Listener<const moho::SNavPath&>* listener = nullptr;
  archive->ReadPointer_Listener_NavPath(&listener, ownerRef);
  while (listener != nullptr) {
    listHead->AddListener(listener);
    archive->ReadPointer_Listener_NavPath(&listener, ownerRef);
  }

  return listener;
}

/**
 * Address: 0x006EB9E0 (FUN_006EB9E0, gpg::ReadArchive::ReadPointerWeak_IFormationInstance)
 *
 * What it does:
 * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
 * transition, and upcasts the pointee to `moho::IFormationInstance`.
 */
ReadArchive* ReadArchive::ReadPointerWeak_IFormationInstance(
  moho::IFormationInstance** const outValue, const RRef* const ownerRef
)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);
  if (!tracked.object) {
    *outValue = nullptr;
    return this;
  }

  if (tracked.state == TrackedPointerState::Unowned) {
    tracked.state = TrackedPointerState::Shared;
  }
  if (tracked.state != TrackedPointerState::Shared) {
    ThrowSerializationError("Ownership conflict while loading archive");
  }

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIFormationInstanceType());
  *outValue = static_cast<moho::IFormationInstance*>(upcast.mObj);
  if (!*outValue) {
    const char* const expectedName = SafeTypeName(CachedIFormationInstanceType());
    const char* const actualName = source.GetTypeName();
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "IFormationInstance",
      actualName ? actualName : "null"
    ));
  }

  return this;
}

/**
 * Address: 0x00953B30 (FUN_00953B30)
 * Demangled: public: class gpg::ReadArchive & __thiscall gpg::ReadArchive::TrackPointer(class gpg::RRef const &)
 *
 * What it does:
 * Appends one tracked-pointer table lane for an object that already exists
 * at the time its serializer starts reading nested payload.
 */
ReadArchive& ReadArchive::TrackPointer(const RRef& objectRef)
{
  mTrackedPtrs.push_back(TrackedPointerInfo{objectRef.mObj, objectRef.mType, {}, TrackedPointerState::Owned});
  return *this;
}

/**
 * Address: 0x00952BD0 (FUN_00952BD0)
 * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
 *
 * What it does:
 * Releases tracked pointer/type-handle section state, including releasing
 * shared control blocks for tracked shared-pointer lanes.
 *
 * The state this deletes on is `Unowned`, not `Owned`, and the binary is
 * explicit about it: the loop tests `cmp dword ptr [eax+esi+10h], 1` at
 * 0x00952C03 and skips the delete on anything else, while
 * `SerConstructResult::SetUnowned` (0x0094F630) writes 1 at 0x0094F668 and
 * `SetOwned` (0x0094F5E0) writes 2 at 0x0094F614.
 *
 * The names read backwards until you take them from the construct helper's
 * point of view rather than the archive's. `SetOwned` means "this object is
 * already owned by someone else, so the archive must not free it";
 * `SetUnowned` means "nobody else has claimed this one", which makes the
 * archive responsible for it. So deleting exactly the `Unowned` entries is
 * what keeps a construct helper's cached instances alive.
 *
 * `CSndParamsConstruct::Construct` (0x004E0E10) is the case that makes this
 * load-bearing: it resolves the key through `FindOrCreateSndParamsByKey`,
 * which hands back a permanently cached, shared `CSndParams`, and then marks
 * it `SetOwned`. Deleting on `Owned` freed those out from under the cache.
 */
void ReadArchive::EndSection(const bool)
{
  for (TrackedPointerInfo& tracked : mTrackedPtrs) {
    if (tracked.state == TrackedPointerState::Unowned) {
      RRef{tracked.object, tracked.type}.Delete();
    }
  }

  mTypeHandles.clear();
  mTrackedPtrs.clear();
}

/**
 * Address: 0x009048B0 (FUN_009048B0)
 * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
 *
 * What it does:
 * Allocates one file-backed concrete `ReadArchive` (BinaryReadArchive) bound to
 * the given stdio stream for save/load serializers. The binary performs no
 * validity check on the stream: it allocates with non-throwing new (returning
 * null on allocation failure) and constructs unconditionally -- matching the
 * write-side CreateBinaryWriteArchive.
 */
ReadArchive* gpg::CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
{
  return new (std::nothrow) BinaryReadArchive(file);
}
