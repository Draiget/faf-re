#include "editor/tools/EdModalTransform.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979f;

    float Wrap(
      float a
    )
    {
      while (a > kPi) {
        a -= 2.0f * kPi;
      }
      while (a <= -kPi) {
        a += 2.0f * kPi;
      }
      return a;
    }

    bool TypedNumber(
      const std::string& typed,
      float& value
    )
    {
      if (typed.empty() || typed == "-" || typed == "." || typed == "-.") {
        return false;
      }
      value = std::strtof(typed.c_str(), nullptr);
      return true;
    }
  } // namespace

  ModalDelta ModalDeltaFor(
    const ModalInput& input
  )
  {
    ModalDelta delta;
    float typed = 0.0f;
    const bool exact = TypedNumber(input.typed, typed);
    if (input.rotate) {
      // The cursor's angle is atan2(dz, dx) on the ground; a heading turns the other way (atan2(dx, dz)).
      delta.turn = exact ? typed * (kPi / 180.0f) : -Wrap(input.nowAngle - input.startAngle);
      return delta;
    }
    if (exact) {
      (input.axis == 'Z' ? delta.dz : delta.dx) = typed;
      return delta;
    }
    delta.dx = input.axis == 'Z' ? 0.0f : input.cursorDX;
    delta.dz = input.axis == 'X' ? 0.0f : input.cursorDZ;
    return delta;
  }

  ArrangePlaces ApplyModalDelta(
    const ArrangePlaces& start,
    const float cx,
    const float cz,
    const ModalDelta& delta
  )
  {
    ArrangePlaces out = start;
    out.heading.resize(out.x.size(), 0.0f);
    if (delta.turn == 0.0f) {
      for (std::size_t i = 0; i < out.x.size(); ++i) {
        out.x[i] += delta.dx;
        out.z[i] += delta.dz;
      }
      return out;
    }
    // A heading h faces (sin h, cos h); turning it by t turns every offset from the middle the same way.
    const float c = std::cos(delta.turn);
    const float s = std::sin(delta.turn);
    for (std::size_t i = 0; i < out.x.size(); ++i) {
      const float ox = start.x[i] - cx;
      const float oz = start.z[i] - cz;
      out.x[i] = cx + ox * c + oz * s;
      out.z[i] = cz - ox * s + oz * c;
      out.heading[i] = Wrap(out.heading[i] + delta.turn);
    }
    return out;
  }

  bool TypeIntoNumber(
    std::string& typed,
    const int key
  )
  {
    if (key == 8) {
      if (!typed.empty()) {
        typed.pop_back();
      }
      return true;
    }
    if (key >= '0' && key <= '9') {
      typed.push_back(static_cast<char>(key));
      return true;
    }
    if (key == '.' && typed.find('.') == std::string::npos) {
      typed.push_back('.');
      return true;
    }
    if (key == '-') {
      // A minus flips the sign wherever it is typed.
      if (!typed.empty() && typed.front() == '-') {
        typed.erase(typed.begin());
      } else {
        typed.insert(typed.begin(), '-');
      }
      return true;
    }
    return false;
  }

  std::string ModalHudText(
    const ModalInput& input,
    const ModalDelta& delta
  )
  {
    char text[96];
    if (input.rotate) {
      (void)std::snprintf(
        text,
        sizeof(text),
        "Turn %s%.1f degrees",
        input.typed.empty() ? "" : "(typed) ",
        static_cast<double>(delta.turn * 180.0f / kPi)
      );
    } else if (input.axis != 0) {
      (void)std::snprintf(
        text,
        sizeof(text),
        "Move along %c %s%.2f",
        input.axis,
        input.typed.empty() ? "" : "(typed) ",
        static_cast<double>(input.axis == 'Z' ? delta.dz : delta.dx)
      );
    } else {
      (void)std::snprintf(
        text,
        sizeof(text),
        "Move %s%.2f, %.2f",
        input.typed.empty() ? "" : "(typed, along X) ",
        static_cast<double>(delta.dx),
        static_cast<double>(delta.dz)
      );
    }
    return text;
  }
} // namespace faf::editor
