#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  // The little JSON FAForeverMapEditor's preset files need (Unity's JsonUtility output): keys looked up by name,
  // vectors as {"x", "y", "z", "w"} objects.

  /** The text of `key`'s value: a number, true/false, a string's contents, or an {object} / [array] with its brackets. */
  bool JsonValue(const std::string& text, const std::string& key, std::string& out);
  /** `key`'s number into `out` (left as it was when absent). */
  bool JsonFloat(const std::string& text, const std::string& key, float& out);
  /** `key`'s {x, y, z, w} object into `out[0..n)` (each axis left as it was when absent). */
  void JsonVector(const std::string& text, const std::string& key, float* out, int n);

  /** A number as JsonUtility writes one closely enough to read back the same float. */
  std::string JsonNumber(float value);
  /** A string in quotes, with `"` and `\` escaped. */
  std::string JsonQuoted(const std::string& text);
  /** An {x, y, z, w} object of `n` axes, its closing brace at `indent`. */
  std::string JsonVectorText(const float* value, int n, const std::string& indent);
  /** The [ {...}, {...} ] array's objects, each with its braces. */
  std::vector<std::string> JsonObjects(const std::string& array);

  // FAFME's Unity conventions.

  /** A game position in FAFME's world units (a tenth, z flipped: ScmapEditor.ScmapPosToWorld), and back. */
  void GameToFafme(const float (&game)[3], float (&fafme)[3]);
  void FafmeToGame(const float (&fafme)[3], float (&game)[3]);
  /** Unity's Quaternion.Euler (degrees; z, then x, then y) and its eulerAngles back (degrees in [0, 360)). */
  void UnityEulerToQuaternion(const float (&degrees)[3], float (&quaternion)[4]);
  void UnityQuaternionToEuler(const float (&quaternion)[4], float (&degrees)[3]);
} // namespace faf::editor
