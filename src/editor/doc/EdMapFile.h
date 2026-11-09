#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "moho/render/camera/VTransform.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CWldMap;
} // namespace moho

namespace faf::editor
{
  /**
   * One prop as the `.scmap` stores it: its blueprint path, then 15 floats (position, a 3 x 3 rotation
   * matrix by rows, and a scale the game ignores). The game keeps a quaternion made from the matrix and
   * writes the matrix back from that quaternion, with scale 1: every save would change each prop's
   * rotation in its last bits and drop its scale. The editor keeps the stored record and writes it back
   * while the prop is as it was loaded (`loaded`, the transform the game made of it).
   */
  struct PropRecord
  {
    std::string path;
    float values[15]{};
    moho::VTransform loaded{};
  };

  /**
   * What the editor keeps of the file a map was read from, to write back unchanged: the preview chunk's
   * bytes (the game re-encodes the preview image when it writes it; the editor doesn't change the preview
   * yet) and the props' stored records.
   */
  struct MapFileRecords
  {
    std::vector<char> preview;
    std::vector<PropRecord> props;
  };

  /** The preview chunk's bytes from the start of a `.scmap` (after the 8-byte file header), or empty. */
  std::vector<char> ReadPreviewRecord(const std::string& file);

  /**
   * The stored records of `map`'s props, from the end of its `.scmap` (the props section is the file's
   * last: a count, then each prop's path and 15 floats). Empty when the tail doesn't match the props the
   * game loaded; the writer then writes them the game's way.
   */
  std::vector<PropRecord> ReadPropRecords(const std::string& file, const moho::CWldMap& map);

  /**
   * Writes `map` as a `.scmap` file at `path` on disk: the `Map\x1A` version-2 header, the preview chunk as
   * it was read (else through its own `Save`), the terrain through its own `Save` as `CWldMap::MapSave`
   * (0x00891030) does, and the props as
   * `CWldProps::Save` (0x00891D50) lays them out, each from its stored record while it is unchanged.
   * Unlike MapSave, which resolves the name through the virtual file system (so it can't write a map that
   * lives in the game's archives, or anywhere new), the path is the caller's. Terrain is written as
   * version 60, which every game version reads. False with `error` set when it can't.
   */
  bool WriteMapFile(moho::CWldMap& map, const MapFileRecords& records, const std::filesystem::path& path, std::string& error);

  /**
   * Reads a `.scmap` file from `path` on disk into a new map, through the same chunk loaders as
   * `CWldMap::MapLoad` (0x00890DA0), with its props' stored records. For checks (the save round trip);
   * null with `error` set when it can't.
   */
  std::unique_ptr<moho::CWldMap>
  ReadMapFile(const std::filesystem::path& path, LuaPlus::LuaState* state, MapFileRecords& records, std::string& error);

  /**
   * The file on disk behind a virtual path (`/maps/x/x.scmap`), or empty when there is none: a map in the
   * game's archives has no file of its own to write over.
   */
  std::filesystem::path DiskFileOf(const std::string& virtualPath);

  /**
   * The file record of a new or turned prop: its position, its rotation as a matrix (VAxes3) and scale 1,
   * with `loaded` as the engine's own CWldProps::Load (0x008918E0) reads those floats back. The prop takes
   * `loaded` as its transform and the writer writes the record's floats, so saving and reading it again
   * gives the same bits (a rotation passed through the file again and again can swing between two
   * neighbouring floats instead of settling).
   */
  PropRecord PropRecordFor(const std::string& path, const moho::VTransform& transform);

  /** A whole game file (`/maps/...`, from a folder or an archive), resolved as MapLoad does; false if it can't be read. */
  bool ReadGameFile(const std::string& virtualPath, std::string& out);
} // namespace faf::editor
