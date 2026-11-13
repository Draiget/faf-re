#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "editor/doc/EdFafApi.h"

namespace faf::editor
{
  /** Same-size cards across a width: how many a row and how wide each (the row filled, none under `minWidth`). */
  struct EdCardGrid
  {
    int columns = 1;
    float cardWidth = 0.0f;
  };
  [[nodiscard]] EdCardGrid CardGrid(float available, float minWidth, float gap, int maxColumns);

  /**
   * The maps on this computer matching the start screen's search: indices into the play list, best first (each
   * word of the query in the title or the folder, FuzzyScore), at most `max`. Empty query: none.
   */
  [[nodiscard]] std::vector<int> LocalMatches(
    const std::vector<std::string>& titles,
    const std::vector<std::string>& paths,
    std::string_view query,
    std::size_t max
  );

  /** The vault searches the start screen runs: your uploads (newest first), the most played, a typed search. */
  [[nodiscard]] VaultQuery UploadsQuery(const std::string& user);
  [[nodiscard]] VaultQuery MostPlayedQuery();
  [[nodiscard]] VaultQuery TypedQuery(const std::string& text);

  /** How long since a file changed, as a card says it: "today", "yesterday", "3 days ago", "2 weeks ago", ... */
  [[nodiscard]] std::string WhenText(double secondsAgo);

  /** What New makes (design §8: map, mission, mod, effect, material) and the command each runs. */
  struct EdNewKind
  {
    const char* command;
    const char* title;
    const char* about;
    const char* icon; // ui/EdIconFont.h
    unsigned int rgb; // its colour, 0xRRGGBB
  };
  [[nodiscard]] const std::vector<EdNewKind>& NewKinds();
} // namespace faf::editor
