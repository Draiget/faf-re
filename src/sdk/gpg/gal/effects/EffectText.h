#pragma once

// FAF addition, not in the shipped binary.
//
// Text helpers shared by the effect parser (EffectDescription) and the HLSL
// generator (ModernHlsl). Both work on preprocessed effect source, where the
// preprocessor has spaced every token, so a light scanner that matches
// brackets and skips string literals is enough.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace gpg::gal::effects::text
{
  [[nodiscard]] std::string Lower(std::string_view text);
  [[nodiscard]] std::string Trim(std::string_view text);

  /** Collapses runs of whitespace to one space and trims both ends. */
  [[nodiscard]] std::string Squeeze(std::string_view text);

  [[nodiscard]] bool IsIdentifierChar(char c) noexcept;

  /** True when `text` starts with the identifier `word` (not a longer identifier). */
  [[nodiscard]] bool StartsWithWord(std::string_view text, std::string_view word) noexcept;

  /** Index of the closer matching the opener at `open` ('{', '(', '[', '<'), or npos. Skips string literals. */
  [[nodiscard]] std::size_t Matching(std::string_view text, std::size_t open);

  /** Splits on `separator` outside (), {}, [] and string literals. */
  [[nodiscard]] std::vector<std::string> SplitTopLevel(std::string_view text, char separator);

  /** Every number in `text` ("float4 ( 1 , 0.5 , - 2 , 1 )", "{ 1 , 2 }", "true"). */
  [[nodiscard]] std::vector<float> ParseNumbers(std::string_view text);

  /**
   * Evaluates a constant expression of numbers (decimal, hex, true/false)
   * with + - * / % | & ^ ~ << >> and parentheses, as the effect compiler
   * folds `int renderStage = 0x01 + 0x02 + 0x10 + 0x04;`. False when the
   * text is not such an expression.
   */
  [[nodiscard]] bool EvaluateConstant(std::string_view text, double& value);

  /** Replaces every whole-identifier occurrence of `name`, skipping member accesses (`x.name`). */
  [[nodiscard]] std::string ReplaceIdentifier(std::string_view text, std::string_view name, std::string_view replacement);

  /** True when `text` contains the identifier `name` as a whole word. */
  [[nodiscard]] bool ContainsIdentifier(std::string_view text, std::string_view name);

  /** True when `text` has an assignment '=' outside brackets and annotation blocks. */
  [[nodiscard]] bool HasTopLevelAssignment(std::string_view text);

  /** One top-level declaration or definition of the effect source. */
  struct Item
  {
    std::size_t begin = 0; // first character of the item in the source
    std::size_t end = 0;   // one past its last character (after the ';' or '}')
    std::string head;      // the text before the top-level braces, squeezed (the whole statement when unbraced)
    std::string body;      // inside the braces; empty for a plain statement
    bool braced = false;
  };

  /**
   * Splits source into its top-level items. An annotation block (`< ... >`
   * directly after a declarator) and bracketed spans never end an item.
   */
  [[nodiscard]] std::vector<Item> SplitItems(std::string_view source);
} // namespace gpg::gal::effects::text
