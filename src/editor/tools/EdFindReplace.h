#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Find and replace objects (Edit > Find and replace objects..., Ctrl+F): every object of one type (a marker type, a
   * unit blueprint, a prop blueprint, a decal texture) on the whole map, in the selection or in the symmetry's first
   * part, selected, deleted or changed to another type where it stands.
   */
  enum class FindKind
  {
    Marker,
    Unit,
    Prop,
    Decal,
    Count
  };

  enum class FindScope
  {
    Map,
    Selection,
    FirstPart, // the symmetry's first part: the objects the others are copies of
  };

  /** What the dialog does with the matches: Select matches, or Replace all (with a type, or deleting them). */
  enum class FindAction
  {
    Select,
    Delete,
    Replace,
  };

  struct FindObject
  {
    FindKind kind = FindKind::Prop;
    std::string type;
    int ref = -1; // the scene's own index of it (prop index, marker index, unit ref, decal mIndex)
    bool selected = false;
    bool firstPart = true;
    int group = 0; // types replace only types of their group (a decal's kind: albedo, normals, ...)
  };

  struct FindTypeCount
  {
    FindKind kind = FindKind::Prop;
    std::string type;
    int count = 0;
    int group = 0;
  };

  /** Each kind's types with how many there are: kinds in order, then the most first, then by name. */
  [[nodiscard]] std::vector<FindTypeCount> CountFindTypes(const std::vector<FindObject>& objects);

  /** The positions in `objects` of every one of this kind and type within `scope`. */
  [[nodiscard]] std::vector<int>
  FindMatches(const std::vector<FindObject>& objects, FindKind kind, const std::string& type, FindScope scope);

  /**
   * Whether (x, z) is in the symmetry's first part: no image of it comes before it (by x, then z), so each set of
   * copies has exactly one member in it. A point on a mirror line is its own image and is in it.
   */
  [[nodiscard]] bool InFirstPart(int width, int height, Symmetry symmetry, int turns, float x, float z);

  /** "marker", "unit", "prop", "decal". */
  [[nodiscard]] const char* FindKindName(FindKind kind) noexcept;
  /** A type as the dialog shows it: a path's file name without its extension (`pine06`), else the type itself. */
  [[nodiscard]] std::string FindTypeLabel(FindKind kind, const std::string& type);
} // namespace faf::editor
