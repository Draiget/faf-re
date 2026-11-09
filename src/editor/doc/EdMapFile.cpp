#include "editor/doc/EdMapFile.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <exception>
#include <system_error>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/streams/Stream.h"
#include "legacy/containers/String.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"

namespace faf::editor
{
  namespace
  {
    // CWldMap.cpp's kWorldMapFileMagic and kWorldMapFileVersion: "Map" + 0x1A, version 2 (0x008911C6).
    constexpr std::uint32_t kMapMagic = 0x1A70614DU;
    constexpr std::uint32_t kMapVersion = 2U;
    constexpr std::size_t kPropFloats = 15;

    /** The real path a game path resolves to, as MapLoad finds it (0x00890DA0), or the path itself. */
    [[nodiscard]] std::string Resolved(const std::string& path)
    {
      moho::FWaitHandleSet* const files = moho::FILE_GetWaitHandleSet();
      if (files == nullptr || files->mHandle == nullptr) {
        return path;
      }
      fa::string resolved;
      (void)files->mHandle->FindFile(&resolved, path.c_str(), nullptr);
      return resolved.empty() ? path : std::string(resolved.c_str());
    }

    /** A file opened for reading (a real path, or one Resolved gives), or null: DISK_OpenFileRead throws when it isn't there. */
    [[nodiscard]] fa::auto_ptr<gpg::Stream> OpenRead(const std::string& path)
    {
      try {
        return moho::DISK_OpenFileRead(path.c_str());
      } catch (const std::exception&) {
        return fa::auto_ptr<gpg::Stream>(nullptr);
      }
    }

    /** The last `count` bytes of a file (game or disk path), or empty. */
    [[nodiscard]] std::vector<char> FileTail(const std::string& file, const std::size_t count)
    {
      fa::auto_ptr<gpg::Stream> stream = OpenRead(Resolved(file));
      if (stream.get() == nullptr) {
        return {};
      }
      (void)stream->Seek(gpg::Stream::OriginEnd, -static_cast<std::int64_t>(count));
      std::vector<char> bytes(count);
      std::size_t got = 0;
      while (got < count) {
        const std::size_t read = stream->Read(bytes.data() + got, count - got);
        if (read == 0) {
          break;
        }
        got += read;
      }
      bytes.resize(got);
      return bytes;
    }
  } // namespace

  std::vector<char> ReadPreviewRecord(const std::string& file)
  {
    // RWldMapPreviewChunk::Load's layout: magic 0xBEEFFEED, version, width and height, the name in UTF-16
    // up to a 0, a count of tag/value pairs, then (version 2 on) the payload's size and the payload.
    fa::auto_ptr<gpg::Stream> stream = OpenRead(Resolved(file));
    if (stream.get() == nullptr) {
      return {};
    }
    std::vector<char> chunk;
    const auto take = [&](const std::size_t count) {
      const std::size_t at = chunk.size();
      chunk.resize(at + count);
      std::size_t got = 0;
      while (got < count) {
        const std::size_t read = stream->Read(chunk.data() + at + got, count - got);
        if (read == 0) {
          return false;
        }
        got += read;
      }
      return true;
    };
    const auto word = [&](const std::size_t at) {
      std::uint32_t value = 0;
      std::memcpy(&value, chunk.data() + at, sizeof(value));
      return value;
    };
    if (!take(8) || word(0) != kMapMagic) {
      return {};
    }
    chunk.clear();
    if (!take(16) || word(0) != 0xBEEFFEEDU || word(4) < 2U) {
      return {};
    }
    for (;;) {
      if (!take(2)) {
        return {};
      }
      if (chunk[chunk.size() - 2] == 0 && chunk[chunk.size() - 1] == 0) {
        break;
      }
    }
    if (!take(4)) {
      return {};
    }
    const std::uint32_t tags = word(chunk.size() - 4);
    if (tags > 4096 || !take(static_cast<std::size_t>(tags) * 8U) || !take(4)) {
      return {};
    }
    const std::uint32_t payload = word(chunk.size() - 4);
    if (payload > (256u << 20) || !take(payload)) {
      return {};
    }
    return chunk;
  }

  std::vector<PropRecord> ReadPropRecords(const std::string& file, const moho::CWldMap& map)
  {
    if (map.mProps == nullptr) {
      return {};
    }
    const auto& entries = map.mProps->mEntries;
    std::size_t length = sizeof(std::int32_t);
    for (const moho::CWldPropEntry& entry : entries) {
      length += entry.mBlueprintPath.size() + 1 + kPropFloats * sizeof(float);
    }
    const std::vector<char> tail = FileTail(file, length);
    if (tail.size() != length) {
      return {};
    }
    std::int32_t count = 0;
    std::memcpy(&count, tail.data(), sizeof(count));
    if (count != static_cast<std::int32_t>(entries.size())) {
      return {};
    }
    std::vector<PropRecord> records(entries.size());
    std::size_t at = sizeof(std::int32_t);
    for (std::size_t i = 0; i < entries.size(); ++i) {
      PropRecord& record = records[i];
      record.path.assign(tail.data() + at, entries[i].mBlueprintPath.size());
      if (record.path != entries[i].mBlueprintPath.c_str() || tail[at + record.path.size()] != '\0') {
        return {};
      }
      at += record.path.size() + 1;
      std::memcpy(record.values, tail.data() + at, sizeof(record.values));
      at += sizeof(record.values);
      record.loaded = entries[i].mTransform;
    }
    return records;
  }

  bool WriteMapFile(moho::CWldMap& map, const MapFileRecords& records, const std::filesystem::path& path, std::string& error)
  {
    if (map.mMapPreviewChunk == nullptr || map.mTerrainRes == nullptr || map.mProps == nullptr) {
      error = "the map is incomplete";
      return false;
    }
    try {
      fa::auto_ptr<gpg::Stream> stream = moho::DISK_OpenFileWrite(path.string().c_str());
      if (stream.get() == nullptr) {
        error = "can't write " + path.string();
        return false;
      }
      gpg::BinaryWriter writer(stream.get());
      writer.Write(kMapMagic);
      writer.Write(kMapVersion);
      // The preview as it was read; the game would re-encode the image into other bytes.
      bool preview = true;
      if (!records.preview.empty()) {
        writer.Write(records.preview.data(), records.preview.size());
      } else {
        preview = map.mMapPreviewChunk->Save(writer);
      }
      const std::vector<PropRecord>& props = records.props;
      const bool terrain = map.mTerrainRes->Save(writer);

      // The props, in CWldProps::Save's layout (0x00891D50): count, then each path with its NUL and 15
      // floats. An unchanged prop gets its stored record back, so saving leaves it bit for bit as it was.
      const auto& entries = map.mProps->mEntries;
      writer.Write(static_cast<std::int32_t>(entries.size()));
      for (std::size_t i = 0; i < entries.size(); ++i) {
        const moho::CWldPropEntry& entry = entries[i];
        writer.Write(entry.mBlueprintPath.c_str(), entry.mBlueprintPath.size() + 1u);
        if (i < props.size() && props[i].path == entry.mBlueprintPath.c_str() &&
            std::memcmp(&props[i].loaded, &entry.mTransform, sizeof(entry.mTransform)) == 0) {
          for (const float value : props[i].values) {
            writer.Write(value);
          }
          continue;
        }
        // Moved but not turned: the new position with the rotation and scale floats as read.
        if (i < props.size() && props[i].path == entry.mBlueprintPath.c_str() &&
            std::memcmp(&props[i].loaded.orient_, &entry.mTransform.orient_, sizeof(entry.mTransform.orient_)) == 0) {
          writer.Write(entry.mTransform.pos_.x);
          writer.Write(entry.mTransform.pos_.y);
          writer.Write(entry.mTransform.pos_.z);
          for (std::size_t value = 3; value < kPropFloats; ++value) {
            writer.Write(props[i].values[value]);
          }
          continue;
        }
        writer.Write(entry.mTransform.pos_.x);
        writer.Write(entry.mTransform.pos_.y);
        writer.Write(entry.mTransform.pos_.z);
        const moho::VAxes3 matrix(entry.mTransform.orient_);
        for (const Wm3::Vector3f* const row : {&matrix.vX, &matrix.vY, &matrix.vZ}) {
          writer.Write(row->x);
          writer.Write(row->y);
          writer.Write(row->z);
        }
        writer.Write(1.0f);
        writer.Write(1.0f);
        writer.Write(1.0f);
      }
      stream->VirtClose(gpg::Stream::ModeBoth);
      if (!preview || !terrain) {
        error = std::string("writing the ") + (!preview ? "preview" : "terrain") + " failed";
        return false;
      }
      return true;
    } catch (const std::exception& exception) {
      error = exception.what();
      return false;
    }
  }

  std::unique_ptr<moho::CWldMap>
  ReadMapFile(const std::filesystem::path& path, LuaPlus::LuaState* const state, MapFileRecords& records, std::string& error)
  {
    try {
      fa::auto_ptr<gpg::Stream> stream = OpenRead(path.string());
      if (stream.get() == nullptr) {
        error = "can't read " + path.string();
        return nullptr;
      }
      gpg::BinaryReader reader(stream.get());
      std::uint32_t magic = 0;
      std::uint32_t version = 0;
      reader.ReadExact(magic);
      reader.ReadExact(version);
      if (magic != kMapMagic || version != kMapVersion) {
        error = "not a map file";
        return nullptr;
      }
      auto map = std::make_unique<moho::CWldMap>();
      moho::CBackgroundTaskControl control{nullptr};
      map->mMapPreviewChunk = new moho::RWldMapPreviewChunk();
      map->mTerrainRes = moho::WLD_CreateTerrainRes();
      map->mProps = moho::WLD_CreateProps();
      if (!map->mMapPreviewChunk->Load(reader, control) || !map->mTerrainRes->Load(reader, state, control) || !map->mProps->Load(reader, control)) {
        error = "the map file did not load";
        return nullptr;
      }
      stream.reset();
      records.preview = ReadPreviewRecord(path.string());
      records.props = ReadPropRecords(path.string(), *map);
      return map;
    } catch (const std::exception& exception) {
      error = exception.what();
      return nullptr;
    }
  }

  std::filesystem::path DiskFileOf(const std::string& virtualPath)
  {
    std::error_code ignored;
    const std::filesystem::path path(Resolved(virtualPath));
    return std::filesystem::is_regular_file(path, ignored) ? path : std::filesystem::path{};
  }

  PropRecord PropRecordFor(const std::string& path, const moho::VTransform& transform)
  {
    PropRecord record;
    record.path = path;
    const moho::VAxes3 matrix(transform.orient_);
    const float values[15] = {transform.pos_.x, transform.pos_.y, transform.pos_.z, matrix.vX.x, matrix.vX.y, matrix.vX.z, matrix.vY.x,
                              matrix.vY.y,      matrix.vY.z,      matrix.vZ.x,      matrix.vZ.y, matrix.vZ.z, 1.0f,          1.0f,
                              1.0f};
    std::copy(std::begin(values), std::end(values), record.values);
    record.loaded = transform;
    // Read back by the engine's own loader, from the same floats the writer will write.
    gpg::PipeStream pipe;
    {
      gpg::BinaryWriter writer(&pipe);
      writer.Write(std::int32_t{1});
      writer.Write("p", 2u);
      for (const float value : record.values) {
        writer.Write(value);
      }
    }
    pipe.VirtFlush();
    gpg::BinaryReader reader(&pipe);
    std::unique_ptr<moho::CWldProps> props(moho::WLD_CreateProps());
    moho::CBackgroundTaskControl control{nullptr};
    if (props != nullptr && props->Load(reader, control) && !props->mEntries.empty()) {
      record.loaded = props->mEntries[0].mTransform;
    }
    return record;
  }

  bool ReadGameFile(const std::string& virtualPath, std::string& out)
  {
    out.clear();
    fa::auto_ptr<gpg::Stream> stream = OpenRead(Resolved(virtualPath));
    if (stream.get() == nullptr) {
      return false;
    }
    char buffer[65536];
    for (std::size_t got = stream->Read(buffer, sizeof(buffer)); got != 0; got = stream->Read(buffer, sizeof(buffer))) {
      out.append(buffer, got);
    }
    return true;
  }
} // namespace faf::editor
