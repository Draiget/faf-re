#include "editor/tools/EdFieldStack.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Trim(
      const std::string& text
    )
    {
      std::size_t a = 0;
      std::size_t b = text.size();
      while (a < b && std::isspace(static_cast<unsigned char>(text[a])) != 0) {
        ++a;
      }
      while (b > a && std::isspace(static_cast<unsigned char>(text[b - 1])) != 0) {
        --b;
      }
      return text.substr(a, b - a);
    }

    /** True when all of `text` is one number (written to `out`). */
    [[nodiscard]] bool Number(
      const std::string& text,
      double& out
    )
    {
      if (text.empty()) {
        return false;
      }
      char* end = nullptr;
      out = std::strtod(text.c_str(), &end);
      return end != nullptr && *end == '\0';
    }
  } // namespace

  void FieldStack::Start(
    field::Grid base
  )
  {
    mGrids.clear();
    mSteps.clear();
    mGrids.push_back(std::move(base));
  }

  std::expected<void, std::string> FieldStack::Apply(
    const std::string& op,
    const field::Params& params
  )
  {
    if (mGrids.empty()) {
      return std::unexpected("start from the map's heights first");
    }
    field::OpArgs args;
    args.p = params;
    const auto top = std::make_shared<const field::Grid>(mGrids.back());
    args.in["a"] = top;
    args.in["like"] = top;
    field::Grid out;
    if (auto ran = field::RunOp(op, args, out); !ran) {
      return ran;
    }
    if (out.Count() == 0) {
      return std::unexpected(op + " gave no samples");
    }
    mGrids.push_back(std::move(out));
    const std::string text = ParamsText(params);
    mSteps.push_back(text.empty() ? op : op + " (" + text + ")");
    return {};
  }

  bool FieldStack::Back()
  {
    if (mGrids.size() <= 1) {
      return false;
    }
    mGrids.pop_back();
    mSteps.pop_back();
    return true;
  }

  void FieldStack::Clear()
  {
    mGrids.clear();
    mSteps.clear();
  }

  field::Params ParseOpParams(
    const std::string& text
  )
  {
    field::Params params;
    std::size_t at = 0;
    while (at <= text.size()) {
      std::size_t end = text.find('\n', at);
      if (end == std::string::npos) {
        end = text.size();
      }
      const std::string line = Trim(text.substr(at, end - at));
      at = end + 1;
      if (line.empty() || line[0] == '#' || line.starts_with("--")) {
        continue;
      }
      const std::size_t equals = line.find('=');
      if (equals == std::string::npos) {
        continue;
      }
      const std::string key = Trim(line.substr(0, equals));
      std::string value = Trim(line.substr(equals + 1));
      if (key.empty()) {
        continue;
      }
      double number = 0.0;
      if (Number(value, number)) {
        params.num[key] = number;
        continue;
      }
      // A list of numbers, comma separated.
      if (value.contains(',')) {
        std::vector<double> list;
        bool all = true;
        std::size_t from = 0;
        while (from <= value.size()) {
          std::size_t comma = value.find(',', from);
          if (comma == std::string::npos) {
            comma = value.size();
          }
          double item = 0.0;
          if (!Number(Trim(value.substr(from, comma - from)), item)) {
            all = false;
            break;
          }
          list.push_back(item);
          from = comma + 1;
        }
        if (all) {
          params.arr[key] = std::move(list);
          continue;
        }
      }
      if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front()) {
        value = value.substr(1, value.size() - 2);
      }
      params.str[key] = value;
    }
    return params;
  }

  std::string ParamsText(
    const field::Params& params
  )
  {
    std::string out;
    const auto add = [&out](const std::string& item) {
      if (!out.empty()) {
        out += ' ';
      }
      out += item;
    };
    for (const auto& [key, value] : params.num) {
      char number[48];
      (void)std::snprintf(number, sizeof(number), "%g", value);
      add(key + "=" + number);
    }
    for (const auto& [key, value] : params.str) {
      add(key + "=" + value);
    }
    for (const auto& [key, values] : params.arr) {
      std::string list;
      for (const double value : values) {
        char number[48];
        (void)std::snprintf(number, sizeof(number), "%g", value);
        list += (list.empty() ? "" : ",") + std::string(number);
      }
      add(key + "=" + list);
    }
    return out;
  }
} // namespace faf::editor
