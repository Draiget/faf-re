#include "editor/graph/EdTextureGraph.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <thread>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979323846f;

    // ---- Images and pixels ----

    float Luminance(const float (&c)[4])
    {
      return c[0] * 0.2126f + c[1] * 0.7152f + c[2] * 0.0722f;
    }

    float Clamp01(const float v)
    {
      return std::min(std::max(v, 0.0f), 1.0f);
    }

    float Lerp(const float a, const float b, const float t)
    {
      return a + (b - a) * t;
    }

    float Smoothstep(const float edge0, const float edge1, const float x)
    {
      const float t = Clamp01((x - edge0) / std::max(edge1 - edge0, 1e-6f));
      return t * t * (3.0f - 2.0f * t);
    }

    int Wrap(const int i, const int n)
    {
      const int m = i % n;
      return m < 0 ? m + n : m;
    }

    /** The image's RGBA at pixel (x, y) of a `size` image: its own pixel at the same size, else sampled at the centre. */
    void Fetch(const TexImage& image, const int x, const int y, const int size, float (&out)[4])
    {
      if (image.size == size) {
        const float* p = image.Pixel(x, y);
        if (image.channels == 4) {
          out[0] = p[0];
          out[1] = p[1];
          out[2] = p[2];
          out[3] = p[3];
        } else {
          out[0] = out[1] = out[2] = p[0];
          out[3] = 1.0f;
        }
        return;
      }
      image.Sample((static_cast<float>(x) + 0.5f) / static_cast<float>(size), (static_cast<float>(y) + 0.5f) / static_cast<float>(size), out);
    }

    float FetchGrey(const TexImage& image, const int x, const int y, const int size)
    {
      if (image.size == size && image.channels == 1) {
        return image.Pixel(x, y)[0];
      }
      float c[4];
      Fetch(image, x, y, size, c);
      return image.channels == 1 ? c[0] : Luminance(c);
    }

    /** Runs fn(y) for every row, on the machine's cores for big images. */
    template <class Fn> void ForRows(const int size, const Fn& fn)
    {
      const int threads = size >= 128 ? static_cast<int>(std::clamp(std::thread::hardware_concurrency(), 1U, 16U)) : 1;
      if (threads <= 1) {
        for (int y = 0; y < size; ++y) {
          fn(y);
        }
        return;
      }
      std::vector<std::thread> pool;
      pool.reserve(static_cast<std::size_t>(threads));
      for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&, t] {
          for (int y = t; y < size; y += threads) {
            fn(y);
          }
        });
      }
      for (std::thread& thread : pool) {
        thread.join();
      }
    }

    // ---- Tiling noise ----

    std::uint32_t Hash(std::uint32_t x, std::uint32_t y, std::uint32_t seed)
    {
      std::uint32_t h = x * 0x8DA6B343U ^ y * 0xD8163841U ^ seed * 0xCB1AB31FU;
      h ^= h >> 16;
      h *= 0x7FEB352DU;
      h ^= h >> 15;
      h *= 0x846CA68BU;
      h ^= h >> 16;
      return h;
    }

    float HashFloat(const int x, const int y, const std::uint32_t seed)
    {
      return static_cast<float>(Hash(static_cast<std::uint32_t>(x), static_cast<std::uint32_t>(y), seed) >> 8) / 16777216.0f;
    }

    float Fade(const float t)
    {
      return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
    }

    /** Gradient noise with `period` cells across the image, about -1 to 1, wrapping at the period. */
    float Perlin(const float x, const float y, const int period, const std::uint32_t seed)
    {
      const int x0 = static_cast<int>(std::floor(x));
      const int y0 = static_cast<int>(std::floor(y));
      const float fx = x - static_cast<float>(x0);
      const float fy = y - static_cast<float>(y0);
      const auto grad = [&](const int ix, const int iy, const float dx, const float dy) {
        const float a = HashFloat(Wrap(ix, period), Wrap(iy, period), seed) * 2.0f * kPi;
        return std::cos(a) * dx + std::sin(a) * dy;
      };
      const float n00 = grad(x0, y0, fx, fy);
      const float n10 = grad(x0 + 1, y0, fx - 1.0f, fy);
      const float n01 = grad(x0, y0 + 1, fx, fy - 1.0f);
      const float n11 = grad(x0 + 1, y0 + 1, fx - 1.0f, fy - 1.0f);
      const float u = Fade(fx);
      const float v = Fade(fy);
      return Lerp(Lerp(n00, n10, u), Lerp(n01, n11, u), v) * 1.41421356f;
    }

    /** Cells with one jittered point each, `period` across, wrapping: the nearest and second nearest distances and the cell. */
    void Cells(const float x, const float y, const int period, const float jitter, const std::uint32_t seed, float& f1, float& f2, float& cell)
    {
      const int cx = static_cast<int>(std::floor(x));
      const int cy = static_cast<int>(std::floor(y));
      f1 = f2 = 1e9f;
      cell = 0.0f;
      for (int dy = -1; dy <= 1; ++dy) {
        for (int dx = -1; dx <= 1; ++dx) {
          const int ix = cx + dx;
          const int iy = cy + dy;
          const int wx = Wrap(ix, period);
          const int wy = Wrap(iy, period);
          const float px = static_cast<float>(ix) + 0.5f + (HashFloat(wx, wy, seed) - 0.5f) * jitter;
          const float py = static_cast<float>(iy) + 0.5f + (HashFloat(wx, wy, seed + 7919U) - 0.5f) * jitter;
          const float d = std::hypot(px - x, py - y);
          if (d < f1) {
            f2 = f1;
            f1 = d;
            cell = HashFloat(wx, wy, seed + 104729U);
          } else if (d < f2) {
            f2 = d;
          }
        }
      }
    }

    // ---- The node types ----

    struct EvalArgs
    {
      const GraphNode& node;
      const std::vector<TexImagePtr>& inputs;
      int size;
      std::vector<std::shared_ptr<TexImage>>& outputs;
      std::string& warning;
      const std::function<std::shared_ptr<TexImage>(const std::string&)>& texture;
      const TerrainSource* terrain;

      [[nodiscard]] float F(const std::size_t param) const { return node.params[param].value[0]; }
      [[nodiscard]] int I(const std::size_t param) const { return static_cast<int>(std::lround(node.params[param].value[0])); }
      [[nodiscard]] const std::array<float, 4>& C(const std::size_t param) const { return node.params[param].value; }
      [[nodiscard]] const TexImage& In(const std::size_t pin) const { return *inputs[pin]; }
      [[nodiscard]] TexImage& Out(const std::size_t pin, const int channels) const
      {
        outputs[pin]->Reset(size, channels);
        return *outputs[pin];
      }
    };
    using EvalFn = std::function<void(const EvalArgs&)>;

    struct TextureNodes
    {
      NodeTypeRegistry registry;
      std::map<std::string, EvalFn> eval;
    };

    PinDef In(const char* name, const PinType type, const float a = 0.0f, const float b = 0.0f, const float c = 0.0f, const float d = 1.0f)
    {
      return PinDef{name, type, {a, b, c, d}};
    }

    PinDef Out(const char* name, const PinType type)
    {
      return PinDef{name, type, {}};
    }

    ParamDef Num(const char* name, const float initial, const float min, const float max, const char* help = "")
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Float;
      def.initial = {initial, 0.0f, 0.0f, 0.0f};
      def.min = min;
      def.max = max;
      def.help = help;
      return def;
    }

    ParamDef Int(const char* name, const int initial, const int min, const int max, const char* help = "")
    {
      ParamDef def = Num(name, static_cast<float>(initial), static_cast<float>(min), static_cast<float>(max), help);
      def.kind = ParamKind::Int;
      return def;
    }

    ParamDef Col(const char* name, const float r, const float g, const float b, const float a = 1.0f)
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Color;
      def.initial = {r, g, b, a};
      return def;
    }

    ParamDef Choice(const char* name, std::vector<std::string> choices, const int initial = 0)
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Choice;
      def.initial = {static_cast<float>(initial), 0.0f, 0.0f, 0.0f};
      def.choices = std::move(choices);
      return def;
    }

    ParamDef Bool(const char* name, const bool initial)
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Bool;
      def.initial = {initial ? 1.0f : 0.0f, 0.0f, 0.0f, 0.0f};
      return def;
    }

    ParamDef Text(const char* name, const char* initial, const char* help = "")
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Text;
      def.initialText = initial;
      def.help = help;
      return def;
    }

    /** A colour node of two inputs computed per channel. */
    template <class Op> EvalFn PerChannel2(Op op)
    {
      return [op](const EvalArgs& a) {
        TexImage& out = a.Out(0, 4);
        ForRows(a.size, [&](const int y) {
          for (int x = 0; x < a.size; ++x) {
            float l[4];
            float r[4];
            Fetch(a.In(0), x, y, a.size, l);
            Fetch(a.In(1), x, y, a.size, r);
            float* p = out.Pixel(x, y);
            for (int c = 0; c < 4; ++c) {
              p[c] = op(l[c], r[c]);
            }
          }
        });
      };
    }

    /** A colour node of one input computed per channel (alpha kept unless `alphaToo`). */
    template <class Op> EvalFn PerChannel1(Op op, const bool alphaToo = false)
    {
      return [op, alphaToo](const EvalArgs& a) {
        TexImage& out = a.Out(0, 4);
        ForRows(a.size, [&](const int y) {
          for (int x = 0; x < a.size; ++x) {
            float v[4];
            Fetch(a.In(0), x, y, a.size, v);
            float* p = out.Pixel(x, y);
            for (int c = 0; c < 4; ++c) {
              p[c] = (c < 3 || alphaToo) ? op(a, v[c]) : v[c];
            }
          }
        });
      };
    }

    float BlendChannel(const int mode, const float a, const float b)
    {
      switch (mode) {
      case 1: return a * b;                                                                         // multiply
      case 2: return 1.0f - (1.0f - a) * (1.0f - b);                                                // screen
      case 3: return a < 0.5f ? 2.0f * a * b : 1.0f - 2.0f * (1.0f - a) * (1.0f - b);               // overlay
      case 4: return (1.0f - 2.0f * b) * a * a + 2.0f * b * a;                                      // soft light
      case 5: return a + b;                                                                         // add
      case 6: return a - b;                                                                         // subtract
      case 7: return std::fabs(a - b);                                                              // difference
      case 8: return std::min(a, b);                                                                // darken
      case 9: return std::max(a, b);                                                                // lighten
      default: return b;                                                                            // normal
      }
    }

    void RgbToHsv(const float r, const float g, const float b, float& h, float& s, float& v)
    {
      const float mx = std::max({r, g, b});
      const float mn = std::min({r, g, b});
      const float d = mx - mn;
      v = mx;
      s = mx > 0.0f ? d / mx : 0.0f;
      if (d <= 0.0f) {
        h = 0.0f;
      } else if (mx == r) {
        h = std::fmod((g - b) / d + 6.0f, 6.0f) / 6.0f;
      } else if (mx == g) {
        h = ((b - r) / d + 2.0f) / 6.0f;
      } else {
        h = ((r - g) / d + 4.0f) / 6.0f;
      }
    }

    void HsvToRgb(float h, const float s, const float v, float& r, float& g, float& b)
    {
      h = h - std::floor(h);
      const float i = std::floor(h * 6.0f);
      const float f = h * 6.0f - i;
      const float p = v * (1.0f - s);
      const float q = v * (1.0f - s * f);
      const float t = v * (1.0f - s * (1.0f - f));
      switch (static_cast<int>(i) % 6) {
      case 0: r = v, g = t, b = p; break;
      case 1: r = q, g = v, b = p; break;
      case 2: r = p, g = v, b = t; break;
      case 3: r = p, g = q, b = v; break;
      case 4: r = t, g = p, b = v; break;
      default: r = v, g = p, b = q; break;
      }
    }

    void AddNoiseNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };

      add({"Noise", "Noise", "Noise", "Gradient (Perlin) noise that tiles: Scale cells across, Octaves layers of finer detail.",
           {},
           {Out("Out", PinType::Grey)},
           {Int("Scale", 4, 1, 64, "Cells across the image (a whole number, so it tiles)"), Int("Octaves", 5, 1, 10),
            Num("Persistence", 0.5f, 0.0f, 1.0f, "How much each finer octave adds"), Choice("Style", {"Smooth", "Ridged", "Billow", "Turbulence"}),
            Int("Seed", 0, 0, 9999)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 1);
            const int scale = std::max(a.I(0), 1);
            const int octaves = std::clamp(a.I(1), 1, 10);
            const float persistence = a.F(2);
            const int style = a.I(3);
            const auto seed = static_cast<std::uint32_t>(a.I(4));
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(a.size);
                const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size);
                float sum = 0.0f;
                float amplitude = 1.0f;
                float total = 0.0f;
                int period = scale;
                for (int o = 0; o < octaves; ++o) {
                  float n = Perlin(u * static_cast<float>(period), v * static_cast<float>(period), period, seed + static_cast<std::uint32_t>(o) * 31U);
                  if (style == 1) {
                    n = 1.0f - std::fabs(n);
                    n = n * n * 2.0f - 1.0f;
                  } else if (style == 2) {
                    n = std::fabs(n) * 2.0f - 1.0f;
                  } else if (style == 3) {
                    n = std::fabs(n);
                  }
                  sum += n * amplitude;
                  total += amplitude;
                  amplitude *= persistence;
                  period *= 2;
                }
                sum /= std::max(total, 1e-6f);
                out.Pixel(x, y)[0] = style == 3 ? Clamp01(sum) : Clamp01(sum * 0.5f + 0.5f);
              }
            });
          });

      add({"Cells", "Cells", "Noise", "Cell (Voronoi) noise that tiles: stones, cracks, scales.",
           {},
           {Out("Distance", PinType::Grey), Out("Edges", PinType::Grey), Out("Cell", PinType::Grey)},
           {Int("Scale", 8, 1, 64, "Cells across the image"), Num("Jitter", 1.0f, 0.0f, 1.0f, "0: a grid, 1: random"), Int("Seed", 0, 0, 9999)},
           false},
          [](const EvalArgs& a) {
            TexImage& distance = a.Out(0, 1);
            TexImage& edges = a.Out(1, 1);
            TexImage& cellOut = a.Out(2, 1);
            const int scale = std::max(a.I(0), 1);
            const float jitter = a.F(1);
            const auto seed = static_cast<std::uint32_t>(a.I(2));
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(scale);
                const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(scale);
                float f1 = 0.0f;
                float f2 = 0.0f;
                float cell = 0.0f;
                Cells(u, v, scale, jitter, seed, f1, f2, cell);
                distance.Pixel(x, y)[0] = Clamp01(f1);
                edges.Pixel(x, y)[0] = Clamp01((f2 - f1) * 2.0f);
                cellOut.Pixel(x, y)[0] = cell;
              }
            });
          });

      add({"WhiteNoise", "White Noise", "Noise", "A random value per pixel block (Scale blocks across).",
           {},
           {Out("Out", PinType::Grey)},
           {Int("Scale", 256, 1, 2048), Int("Seed", 0, 0, 9999)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 1);
            const int scale = std::max(a.I(0), 1);
            const auto seed = static_cast<std::uint32_t>(a.I(1));
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                out.Pixel(x, y)[0] = HashFloat(x * scale / a.size, y * scale / a.size, seed);
              }
            });
          });

      add({"Gradient", "Gradient", "Noise", "A ramp from 0 to 1: along U, along V, or out from the centre (doesn't tile).",
           {},
           {Out("Out", PinType::Grey)},
           {Choice("Kind", {"Along U", "Along V", "Radial"})},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 1);
            const int kind = a.I(0);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(a.size);
                const float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size);
                out.Pixel(x, y)[0] = kind == 0 ? u : kind == 1 ? v : Clamp01(1.0f - std::hypot(u - 0.5f, v - 0.5f) * 2.0f);
              }
            });
          });
    }

    void AddInputNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };

      add({"Constant", "Constant", "Constants", "One grey value.", {}, {Out("Out", PinType::Grey)}, {Num("Value", 0.5f, 0.0f, 1.0f)}, false},
          [](const EvalArgs& a) {
            a.outputs[0]->Reset(1, 1, a.F(0));
          });
      add({"Color", "Color", "Constants", "One colour.", {}, {Out("Out", PinType::Color)}, {Col("Color", 0.5f, 0.45f, 0.35f)}, false},
          [](const EvalArgs& a) {
            a.outputs[0]->Reset(1, 4);
            for (int c = 0; c < 4; ++c) {
              a.outputs[0]->data[static_cast<std::size_t>(c)] = a.C(0)[static_cast<std::size_t>(c)];
            }
          });

      add({"Texture", "Texture Sample", "Textures", "A texture file (any DDS the game data or the map's folder has), repeated Tiling times.",
           {},
           {Out("RGBA", PinType::Color), Out("R", PinType::Grey), Out("G", PinType::Grey), Out("B", PinType::Grey), Out("A", PinType::Grey)},
           {Text("Texture", "/env/evergreen2/layers/eg_grass001_albedo.dds", "The texture's path in the game's files"), Int("Tiling", 1, 1, 32)},
           false},
          [](const EvalArgs& a) {
            const std::shared_ptr<TexImage> source = a.texture(a.node.params[0].text);
            TexImage& rgba = a.Out(0, 4);
            TexImage* channel[4] = {&a.Out(1, 1), &a.Out(2, 1), &a.Out(3, 1), &a.Out(4, 1)};
            if (source == nullptr || source->size == 0) {
              a.warning = "Can't read " + a.node.params[0].text;
              return;
            }
            const float tiling = static_cast<float>(std::max(a.I(1), 1));
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float c[4];
                source->Sample((static_cast<float>(x) + 0.5f) / static_cast<float>(a.size) * tiling,
                               (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size) * tiling, c);
                float* p = rgba.Pixel(x, y);
                for (int i = 0; i < 4; ++i) {
                  p[i] = c[i];
                  channel[i]->Pixel(x, y)[0] = c[i];
                }
              }
            });
          });

      add({"TerrainHeight", "Map Height", "Map", "The open map's height, Low to High game units as 0 to 1 (both 0: the map's lowest to highest). "
                                                  "Covers the whole map, so it doesn't tile: for masks and the upper slot.",
           {},
           {Out("Out", PinType::Grey)},
           {Num("Low", 0.0f, 0.0f, 512.0f), Num("High", 0.0f, 0.0f, 512.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 1);
            const TerrainSource* t = a.terrain;
            if (t == nullptr || t->width < 2 || t->height < 2) {
              a.warning = "No map open";
              return;
            }
            float low = a.F(0);
            float high = a.F(1);
            if (low == 0.0f && high == 0.0f) {
              const auto [mn, mx] = std::minmax_element(t->heights.begin(), t->heights.end());
              low = *mn;
              high = *mx;
            }
            const float range = std::max(high - low, 1e-3f);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float fx = (static_cast<float>(x) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(t->width - 1);
                const float fy = (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(t->height - 1);
                const int ix = std::min(static_cast<int>(fx), t->width - 2);
                const int iy = std::min(static_cast<int>(fy), t->height - 2);
                const float tx = fx - static_cast<float>(ix);
                const float ty = fy - static_cast<float>(iy);
                const auto h = [&](const int sx, const int sy) { return t->heights[static_cast<std::size_t>(sy) * t->width + sx]; };
                const float v = Lerp(Lerp(h(ix, iy), h(ix + 1, iy), tx), Lerp(h(ix, iy + 1), h(ix + 1, iy + 1), tx), ty);
                out.Pixel(x, y)[0] = Clamp01((v - low) / range);
              }
            });
          });

      add({"TerrainSlope", "Map Slope", "Map", "The open map's steepness: 0 flat, 1 at Steepest degrees and over. Covers the whole map.",
           {},
           {Out("Out", PinType::Grey)},
           {Num("Steepest", 45.0f, 1.0f, 90.0f, "Degrees that count as 1")},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 1);
            const TerrainSource* t = a.terrain;
            if (t == nullptr || t->width < 3 || t->height < 3) {
              a.warning = "No map open";
              return;
            }
            const float steepest = std::tan(std::clamp(a.F(0), 1.0f, 89.0f) * kPi / 180.0f);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const int sx = std::clamp(static_cast<int>((static_cast<float>(x) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(t->width)), 1, t->width - 2);
                const int sy = std::clamp(static_cast<int>((static_cast<float>(y) + 0.5f) / static_cast<float>(a.size) * static_cast<float>(t->height)), 1, t->height - 2);
                const auto h = [&](const int px, const int py) { return t->heights[static_cast<std::size_t>(py) * t->width + px]; };
                const float dx = (h(sx + 1, sy) - h(sx - 1, sy)) / (2.0f * t->units);
                const float dy = (h(sx, sy + 1) - h(sx, sy - 1)) / (2.0f * t->units);
                out.Pixel(x, y)[0] = Clamp01(std::hypot(dx, dy) / steepest);
              }
            });
          });
    }

    void AddMathNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };
      const auto two = [&](const char* name, const char* help, const float bInitial, EvalFn fn) {
        add({name, name, "Math", help,
             {In("A", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("B", PinType::Color, bInitial, bInitial, bInitial, 1.0f)},
             {Out("Out", PinType::Color)},
             {},
             false},
            std::move(fn));
      };
      two("Add", "A + B, per channel.", 0.0f, PerChannel2([](const float x, const float y) { return x + y; }));
      two("Subtract", "A - B, per channel.", 0.0f, PerChannel2([](const float x, const float y) { return x - y; }));
      two("Multiply", "A times B, per channel.", 1.0f, PerChannel2([](const float x, const float y) { return x * y; }));
      two("Divide", "A / B, per channel (B near 0 gives A).", 1.0f,
          PerChannel2([](const float x, const float y) { return std::fabs(y) > 1e-5f ? x / y : x; }));
      two("Min", "The smaller of A and B.", 1.0f, PerChannel2([](const float x, const float y) { return std::min(x, y); }));
      two("Max", "The larger of A and B.", 0.0f, PerChannel2([](const float x, const float y) { return std::max(x, y); }));

      add({"Lerp", "Lerp", "Math", "A where Alpha is 0, B where it is 1, mixed between.",
           {In("A", PinType::Color, 0.0f, 0.0f, 0.0f, 1.0f), In("B", PinType::Color, 1.0f, 1.0f, 1.0f, 1.0f), In("Alpha", PinType::Grey, 0.5f)},
           {Out("Out", PinType::Color)},
           {},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float l[4];
                float r[4];
                Fetch(a.In(0), x, y, a.size, l);
                Fetch(a.In(1), x, y, a.size, r);
                const float t = FetchGrey(a.In(2), x, y, a.size);
                float* p = out.Pixel(x, y);
                for (int c = 0; c < 4; ++c) {
                  p[c] = Lerp(l[c], r[c], t);
                }
              }
            });
          });

      const auto one = [&](const char* name, const char* title, const char* help, std::vector<ParamDef> params, EvalFn fn) {
        add({name, title, "Math", help, {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)}, {Out("Out", PinType::Color)}, std::move(params), false},
            std::move(fn));
      };
      one("OneMinus", "1 - x", "Inverts: 1 - In (alpha kept).", {}, PerChannel1([](const EvalArgs&, const float v) { return 1.0f - v; }));
      one("Clamp", "Clamp", "In kept between Min and Max.", {Num("Min", 0.0f, 0.0f, 1.0f), Num("Max", 1.0f, 0.0f, 1.0f)},
          PerChannel1([](const EvalArgs& a, const float v) { return std::clamp(v, a.F(0), std::max(a.F(0), a.F(1))); }));
      one("Power", "Power", "In to the power of Exponent.", {Num("Exponent", 2.0f, 0.05f, 8.0f)},
          PerChannel1([](const EvalArgs& a, const float v) { return std::pow(std::max(v, 0.0f), a.F(0)); }));
      one("Remap", "Remap", "In Low..In High becomes Out Low..Out High.",
          {Num("In Low", 0.0f, 0.0f, 1.0f), Num("In High", 1.0f, 0.0f, 1.0f), Num("Out Low", 0.0f, 0.0f, 1.0f), Num("Out High", 1.0f, 0.0f, 1.0f)},
          PerChannel1([](const EvalArgs& a, const float v) {
            const float t = (v - a.F(0)) / std::max(a.F(1) - a.F(0), 1e-5f);
            return Lerp(a.F(2), a.F(3), t);
          }));
      one("Threshold", "Threshold", "0 below Level, 1 above, with a soft edge of Softness.", {Num("Level", 0.5f, 0.0f, 1.0f), Num("Softness", 0.05f, 0.0f, 0.5f)},
          PerChannel1([](const EvalArgs& a, const float v) { return Smoothstep(a.F(0) - a.F(1), a.F(0) + a.F(1) + 1e-5f, v); }));
    }

    void AddAdjustNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };

      add({"Levels", "Levels", "Adjust", "Photoshop's levels: input black and white points, gamma, output range.",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)},
           {Out("Out", PinType::Color)},
           {Num("In Black", 0.0f, 0.0f, 1.0f), Num("In White", 1.0f, 0.0f, 1.0f), Num("Gamma", 1.0f, 0.1f, 5.0f), Num("Out Black", 0.0f, 0.0f, 1.0f),
            Num("Out White", 1.0f, 0.0f, 1.0f)},
           false},
          PerChannel1([](const EvalArgs& a, const float v) {
            const float t = Clamp01((v - a.F(0)) / std::max(a.F(1) - a.F(0), 1e-5f));
            return Lerp(a.F(3), a.F(4), std::pow(t, 1.0f / std::max(a.F(2), 0.01f)));
          }));

      add({"HSV", "Hue / Saturation", "Adjust", "Shifts the hue, scales the saturation and brightness.",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)},
           {Out("Out", PinType::Color)},
           {Num("Hue", 0.0f, -0.5f, 0.5f), Num("Saturation", 1.0f, 0.0f, 2.0f), Num("Value", 1.0f, 0.0f, 2.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float c[4];
                Fetch(a.In(0), x, y, a.size, c);
                float h = 0.0f;
                float s = 0.0f;
                float v = 0.0f;
                RgbToHsv(c[0], c[1], c[2], h, s, v);
                float* p = out.Pixel(x, y);
                HsvToRgb(h + a.F(0), Clamp01(s * a.F(1)), v * a.F(2), p[0], p[1], p[2]);
                p[3] = c[3];
              }
            });
          });

      add({"GradientMap", "Gradient Map", "Adjust", "Colours a grey image: Low at 0, Middle at Position, High at 1.",
           {In("In", PinType::Grey, 0.5f)},
           {Out("Out", PinType::Color)},
           {Col("Low", 0.22f, 0.18f, 0.13f), Col("Middle", 0.42f, 0.36f, 0.26f), Col("High", 0.62f, 0.58f, 0.47f), Num("Position", 0.5f, 0.01f, 0.99f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const float mid = a.F(3);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float g = Clamp01(FetchGrey(a.In(0), x, y, a.size));
                const std::array<float, 4>& lo = g < mid ? a.C(0) : a.C(1);
                const std::array<float, 4>& hi = g < mid ? a.C(1) : a.C(2);
                const float t = g < mid ? g / mid : (g - mid) / (1.0f - mid);
                float* p = out.Pixel(x, y);
                for (int c = 0; c < 4; ++c) {
                  p[c] = Lerp(lo[static_cast<std::size_t>(c)], hi[static_cast<std::size_t>(c)], t);
                }
              }
            });
          });

      add({"Blur", "Blur", "Adjust", "Softens the image; Radius is a share of the image's width, so the bake looks like the preview.",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)},
           {Out("Out", PinType::Color)},
           {Num("Radius", 0.01f, 0.0f, 0.1f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const int n = a.size;
            const int radius = std::max(static_cast<int>(std::lround(a.F(0) * static_cast<float>(n))), 0);
            TexImage temp;
            temp.Reset(n, 4);
            ForRows(n, [&](const int y) {
              for (int x = 0; x < n; ++x) {
                float c[4];
                Fetch(a.In(0), x, y, n, c);
                std::copy(c, c + 4, temp.Pixel(x, y));
              }
            });
            // Three box passes each way: close to a Gaussian, wrapping at the edges.
            TexImage other;
            other.Reset(n, 4);
            TexImage* src = &temp;
            TexImage* dst = &other;
            const float scale = 1.0f / static_cast<float>(2 * radius + 1);
            for (int pass = 0; pass < 6 && radius > 0; ++pass) {
              const bool horizontal = pass % 2 == 0;
              ForRows(n, [&](const int line) {
                float sum[4] = {};
                for (int k = -radius; k <= radius; ++k) {
                  const float* p = horizontal ? src->Pixel(Wrap(k, n), line) : src->Pixel(line, Wrap(k, n));
                  for (int c = 0; c < 4; ++c) {
                    sum[c] += p[c];
                  }
                }
                for (int i = 0; i < n; ++i) {
                  float* d = horizontal ? dst->Pixel(i, line) : dst->Pixel(line, i);
                  for (int c = 0; c < 4; ++c) {
                    d[c] = sum[c] * scale;
                  }
                  const float* leave = horizontal ? src->Pixel(Wrap(i - radius, n), line) : src->Pixel(line, Wrap(i - radius, n));
                  const float* enter = horizontal ? src->Pixel(Wrap(i + radius + 1, n), line) : src->Pixel(line, Wrap(i + radius + 1, n));
                  for (int c = 0; c < 4; ++c) {
                    sum[c] += enter[c] - leave[c];
                  }
                }
              });
              std::swap(src, dst);
            }
            out.data = src->data;
          });
    }

    void AddBlendNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };

      add({"Blend", "Blend", "Blend", "B over A with a blend mode, by Opacity and the Mask.",
           {In("A", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("B", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("Mask", PinType::Grey, 1.0f)},
           {Out("Out", PinType::Color)},
           {Choice("Mode", {"Normal", "Multiply", "Screen", "Overlay", "Soft Light", "Add", "Subtract", "Difference", "Darken", "Lighten"}),
            Num("Opacity", 1.0f, 0.0f, 1.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const int mode = a.I(0);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float l[4];
                float r[4];
                Fetch(a.In(0), x, y, a.size, l);
                Fetch(a.In(1), x, y, a.size, r);
                const float t = a.F(1) * FetchGrey(a.In(2), x, y, a.size);
                float* p = out.Pixel(x, y);
                for (int c = 0; c < 3; ++c) {
                  p[c] = Lerp(l[c], BlendChannel(mode, l[c], r[c]), t);
                }
                p[3] = l[3];
              }
            });
          });

      add({"HeightBlend", "Height Blend", "Blend", "B shows where its height rises above A's: stones between grass, not a soft fade.",
           {In("A", PinType::Color, 0.3f, 0.4f, 0.2f, 1.0f), In("B", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("Height A", PinType::Grey, 0.5f),
            In("Height B", PinType::Grey, 0.5f)},
           {Out("Out", PinType::Color), Out("Height", PinType::Grey)},
           {Num("Bias", 0.0f, -1.0f, 1.0f, "Raises B (above 0) or A"), Num("Contrast", 0.8f, 0.0f, 1.0f, "1: a sharp edge")},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            TexImage& height = a.Out(1, 1);
            const float soft = (1.0f - a.F(1)) * 0.5f + 0.001f;
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float l[4];
                float r[4];
                Fetch(a.In(0), x, y, a.size, l);
                Fetch(a.In(1), x, y, a.size, r);
                const float ha = FetchGrey(a.In(2), x, y, a.size);
                const float hb = FetchGrey(a.In(3), x, y, a.size) + a.F(0);
                const float t = Smoothstep(-soft, soft, hb - ha);
                float* p = out.Pixel(x, y);
                for (int c = 0; c < 4; ++c) {
                  p[c] = Lerp(l[c], r[c], t);
                }
                height.Pixel(x, y)[0] = Clamp01(Lerp(ha, hb, t));
              }
            });
          });
    }

    void AddShapeNodes(TextureNodes& nodes)
    {
      const auto add = [&](NodeType type, EvalFn fn) {
        nodes.eval[type.name] = std::move(fn);
        nodes.registry.Add(std::move(type));
      };

      add({"Transform", "Transform", "UV", "Repeats the image Tiling times, turns it by quarter turns and shifts it (it still tiles).",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)},
           {Out("Out", PinType::Color)},
           {Int("Tiling", 2, 1, 32), Choice("Turn", {"0", "90", "180", "270"}), Num("Offset U", 0.0f, 0.0f, 1.0f), Num("Offset V", 0.0f, 0.0f, 1.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const float tiling = static_cast<float>(std::max(a.I(0), 1));
            const int turn = a.I(1) & 3;
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(a.size);
                float v = (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size);
                for (int t = 0; t < turn; ++t) {
                  const float nu = v;
                  v = 1.0f - u;
                  u = nu;
                }
                float c[4];
                a.In(0).Sample(u * tiling + a.F(2), v * tiling + a.F(3), c);
                std::copy(c, c + 4, out.Pixel(x, y));
              }
            });
          });

      add({"Warp", "Warp", "UV", "Pushes the image along Angle by the Warp image's value: wavy rock strata, smeared dirt.",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("Warp", PinType::Grey, 0.0f)},
           {Out("Out", PinType::Color)},
           {Num("Intensity", 0.05f, 0.0f, 0.5f), Num("Angle", 0.0f, 0.0f, 360.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const float du = std::cos(a.F(1) * kPi / 180.0f) * a.F(0);
            const float dv = std::sin(a.F(1) * kPi / 180.0f) * a.F(0);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                const float w = FetchGrey(a.In(1), x, y, a.size);
                float c[4];
                a.In(0).Sample((static_cast<float>(x) + 0.5f) / static_cast<float>(a.size) + du * w,
                               (static_cast<float>(y) + 0.5f) / static_cast<float>(a.size) + dv * w, c);
                std::copy(c, c + 4, out.Pixel(x, y));
              }
            });
          });

      add({"HeightToNormal", "Height to Normal", "Normal", "A normal map from a height image (tangent space, 0.5 0.5 1 flat).",
           {In("Height", PinType::Grey, 0.5f)},
           {Out("Normal", PinType::Color)},
           {Num("Strength", 1.0f, 0.0f, 10.0f), Bool("Flip Green", false)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            const int n = a.size;
            TexImage h;
            h.Reset(n, 1);
            ForRows(n, [&](const int y) {
              for (int x = 0; x < n; ++x) {
                h.Pixel(x, y)[0] = FetchGrey(a.In(0), x, y, n);
              }
            });
            // Slopes in the image's own units, so the strength reads the same at every size.
            const float k = a.F(0) * 0.05f * static_cast<float>(n) * 0.5f;
            const float flip = a.F(1) > 0.5f ? -1.0f : 1.0f;
            ForRows(n, [&](const int y) {
              for (int x = 0; x < n; ++x) {
                const float dx = (h.Pixel(Wrap(x + 1, n), y)[0] - h.Pixel(Wrap(x - 1, n), y)[0]) * k;
                const float dy = (h.Pixel(x, Wrap(y + 1, n))[0] - h.Pixel(x, Wrap(y - 1, n))[0]) * k * flip;
                const float len = std::sqrt(dx * dx + dy * dy + 1.0f);
                float* p = out.Pixel(x, y);
                p[0] = -dx / len * 0.5f + 0.5f;
                p[1] = dy / len * 0.5f + 0.5f;
                p[2] = 1.0f / len * 0.5f + 0.5f;
                p[3] = 1.0f;
              }
            });
          });

      add({"NormalBlend", "Normal Blend", "Normal", "Detail normal over a base normal (whiteout blend), by Amount.",
           {In("Base", PinType::Color, 0.5f, 0.5f, 1.0f, 1.0f), In("Detail", PinType::Color, 0.5f, 0.5f, 1.0f, 1.0f)},
           {Out("Normal", PinType::Color)},
           {Num("Amount", 1.0f, 0.0f, 1.0f)},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float b[4];
                float d[4];
                Fetch(a.In(0), x, y, a.size, b);
                Fetch(a.In(1), x, y, a.size, d);
                const float bx = b[0] * 2.0f - 1.0f;
                const float by = b[1] * 2.0f - 1.0f;
                const float bz = b[2] * 2.0f - 1.0f;
                const float dx = (d[0] * 2.0f - 1.0f) * a.F(0);
                const float dy = (d[1] * 2.0f - 1.0f) * a.F(0);
                const float dz = Lerp(1.0f, d[2] * 2.0f - 1.0f, a.F(0));
                const float nx = bx + dx;
                const float ny = by + dy;
                const float nz = bz * dz;
                const float len = std::max(std::sqrt(nx * nx + ny * ny + nz * nz), 1e-5f);
                float* p = out.Pixel(x, y);
                p[0] = nx / len * 0.5f + 0.5f;
                p[1] = ny / len * 0.5f + 0.5f;
                p[2] = nz / len * 0.5f + 0.5f;
                p[3] = 1.0f;
              }
            });
          });

      add({"Split", "Split Channels", "Channels", "A colour image's R, G, B and A as grey images.",
           {In("In", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f)},
           {Out("R", PinType::Grey), Out("G", PinType::Grey), Out("B", PinType::Grey), Out("A", PinType::Grey)},
           {},
           false},
          [](const EvalArgs& a) {
            TexImage* channel[4] = {&a.Out(0, 1), &a.Out(1, 1), &a.Out(2, 1), &a.Out(3, 1)};
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float c[4];
                Fetch(a.In(0), x, y, a.size, c);
                for (int i = 0; i < 4; ++i) {
                  channel[i]->Pixel(x, y)[0] = c[i];
                }
              }
            });
          });

      add({"Merge", "Merge Channels", "Channels", "Four grey images as one colour image's R, G, B and A.",
           {In("R", PinType::Grey, 0.0f), In("G", PinType::Grey, 0.0f), In("B", PinType::Grey, 0.0f), In("A", PinType::Grey, 1.0f)},
           {Out("Out", PinType::Color)},
           {},
           false},
          [](const EvalArgs& a) {
            TexImage& out = a.Out(0, 4);
            ForRows(a.size, [&](const int y) {
              for (int x = 0; x < a.size; ++x) {
                float* p = out.Pixel(x, y);
                for (int i = 0; i < 4; ++i) {
                  p[i] = FetchGrey(a.In(static_cast<std::size_t>(i)), x, y, a.size);
                }
              }
            });
          });
    }

    TextureNodes& Nodes()
    {
      static TextureNodes nodes = [] {
        TextureNodes made;
        made.registry.Add({"Output", "Output", "Output",
                           "What the graph makes: the stratum's albedo (alpha: its transparency or specular, by the shader), its normal map, "
                           "and a mask for painting the stratum over the map.",
                           {In("Albedo", PinType::Color, 0.5f, 0.5f, 0.5f, 1.0f), In("Normal", PinType::Color, 0.5f, 0.5f, 1.0f, 1.0f),
                            In("Mask", PinType::Grey, 1.0f)},
                           {},
                           {},
                           true});
        made.eval["Output"] = [](const EvalArgs&) {};
        AddInputNodes(made);
        AddNoiseNodes(made);
        AddMathNodes(made);
        AddAdjustNodes(made);
        AddBlendNodes(made);
        AddShapeNodes(made);
        return made;
      }();
      return nodes;
    }
  } // namespace

  void TexImage::Reset(const int newSize, const int newChannels, const float fill)
  {
    size = newSize;
    channels = newChannels;
    data.assign(static_cast<std::size_t>(newSize) * newSize * newChannels, fill);
  }

  void TexImage::Sample(const float u, const float v, float (&out)[4]) const
  {
    if (size <= 0) {
      out[0] = out[1] = out[2] = 0.0f;
      out[3] = 1.0f;
      return;
    }
    const float fx = u * static_cast<float>(size) - 0.5f;
    const float fy = v * static_cast<float>(size) - 0.5f;
    const int x0 = static_cast<int>(std::floor(fx));
    const int y0 = static_cast<int>(std::floor(fy));
    const float tx = fx - static_cast<float>(x0);
    const float ty = fy - static_cast<float>(y0);
    const int xa = Wrap(x0, size);
    const int xb = Wrap(x0 + 1, size);
    const int ya = Wrap(y0, size);
    const int yb = Wrap(y0 + 1, size);
    for (int c = 0; c < channels; ++c) {
      const float top = Lerp(Pixel(xa, ya)[c], Pixel(xb, ya)[c], tx);
      const float bottom = Lerp(Pixel(xa, yb)[c], Pixel(xb, yb)[c], tx);
      out[c] = Lerp(top, bottom, ty);
    }
    if (channels == 1) {
      out[1] = out[2] = out[0];
      out[3] = 1.0f;
    }
  }

  const NodeTypeRegistry& TextureNodeTypes()
  {
    return Nodes().registry;
  }

  void StartTextureGraph(NodeGraph& graph)
  {
    graph.Clear();
    const int output = graph.AddNode("Output", 520.0f, 0.0f);
    const int noise = graph.AddNode("Noise", 0.0f, 0.0f);
    const int colours = graph.AddNode("GradientMap", 260.0f, -60.0f);
    const int normal = graph.AddNode("HeightToNormal", 260.0f, 140.0f);
    (void)graph.Link(noise, 0, colours, 0);
    (void)graph.Link(colours, 0, output, 0);
    (void)graph.Link(noise, 0, normal, 0);
    (void)graph.Link(normal, 0, output, 1);
  }

  void TextureGraphEvaluator::SetSize(const int size)
  {
    if (size != mSize) {
      mSize = std::clamp(size, 8, 4096);
      Invalidate();
    }
  }

  void TextureGraphEvaluator::SetTextureLoader(TextureLoader loader)
  {
    mLoader = std::move(loader);
    mTextures.clear();
    Invalidate();
  }

  void TextureGraphEvaluator::SetTerrain(std::shared_ptr<const TerrainSource> terrain)
  {
    mTerrain = std::move(terrain);
    Invalidate();
  }

  void TextureGraphEvaluator::Invalidate()
  {
    mCache.clear();
  }

  int TextureGraphEvaluator::Evaluate(const int id)
  {
    int computed = 0;
    for (const int at : mGraph->OrderFor(id)) {
      const GraphNode* node = mGraph->Find(at);
      const auto found = mCache.find(at);
      if (found != mCache.end() && found->second.revision == node->revision && found->second.size == mSize) {
        continue;
      }
      if (Compute(*node)) {
        ++computed;
      }
    }
    return computed;
  }

  int TextureGraphEvaluator::EvaluateAll()
  {
    // Forget nodes the graph no longer has.
    for (auto it = mCache.begin(); it != mCache.end();) {
      it = mGraph->Find(it->first) == nullptr ? mCache.erase(it) : std::next(it);
    }
    int computed = 0;
    for (const GraphNode& node : mGraph->Nodes()) {
      computed += Evaluate(node.id);
    }
    return computed;
  }

  bool TextureGraphEvaluator::Compute(const GraphNode& node)
  {
    const auto fn = Nodes().eval.find(node.type->name);
    if (fn == Nodes().eval.end()) {
      return false;
    }
    std::vector<TexImagePtr> inputs;
    inputs.reserve(node.type->inputs.size());
    for (std::size_t pin = 0; pin < node.type->inputs.size(); ++pin) {
      inputs.push_back(Input(node.id, static_cast<int>(pin)));
    }
    std::vector<std::shared_ptr<TexImage>> outputs;
    for (std::size_t pin = 0; pin < node.type->outputs.size(); ++pin) {
      auto image = std::make_shared<TexImage>();
      image->Reset(1, node.type->outputs[pin].type == PinType::Color ? 4 : 1);
      outputs.push_back(std::move(image));
    }
    Cached cached;
    const std::function<std::shared_ptr<TexImage>(const std::string&)> texture = [this](const std::string& path) -> std::shared_ptr<TexImage> {
      if (const auto found = mTextures.find(path); found != mTextures.end()) {
        return found->second;
      }
      auto image = std::make_shared<TexImage>();
      if (!mLoader || !mLoader(path, *image) || image->size == 0) {
        image.reset();
      }
      mTextures[path] = image;
      return image;
    };
    const auto start = std::chrono::steady_clock::now();
    fn->second(EvalArgs{node, inputs, mSize, outputs, cached.warning, texture, mTerrain.get()});
    cached.millis = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    cached.revision = node.revision;
    cached.size = mSize;
    cached.outputs.assign(outputs.begin(), outputs.end());
    mCache[node.id] = std::move(cached);
    return true;
  }

  TexImagePtr TextureGraphEvaluator::Output(const int id, const int pin) const
  {
    const auto found = mCache.find(id);
    if (found == mCache.end() || pin < 0 || static_cast<std::size_t>(pin) >= found->second.outputs.size()) {
      return nullptr;
    }
    return found->second.outputs[static_cast<std::size_t>(pin)];
  }

  TexImagePtr TextureGraphEvaluator::Input(const int id, const int pin) const
  {
    if (const GraphLink* link = mGraph->InputLink(id, pin)) {
      if (TexImagePtr image = Output(link->fromNode, link->fromPin)) {
        return image;
      }
    }
    const GraphNode* node = mGraph->Find(id);
    auto constant = std::make_shared<TexImage>();
    if (node == nullptr || pin < 0 || static_cast<std::size_t>(pin) >= node->type->inputs.size()) {
      constant->Reset(1, 1);
      return constant;
    }
    const PinDef& def = node->type->inputs[static_cast<std::size_t>(pin)];
    if (def.type == PinType::Color) {
      constant->Reset(1, 4);
      std::copy(def.initial.begin(), def.initial.end(), constant->data.begin());
    } else {
      constant->Reset(1, 1, def.initial[0]);
    }
    return constant;
  }

  std::string TextureGraphEvaluator::Warning(const int id) const
  {
    const auto found = mCache.find(id);
    return found == mCache.end() ? std::string() : found->second.warning;
  }

  double TextureGraphEvaluator::Millis(const int id) const
  {
    const auto found = mCache.find(id);
    return found == mCache.end() ? 0.0 : found->second.millis;
  }

  TexImagePtr TextureGraphEvaluator::Result(const std::string& outputPin)
  {
    const int output = mGraph->OutputNode();
    const GraphNode* node = mGraph->Find(output);
    if (node == nullptr) {
      return nullptr;
    }
    int pin = -1;
    for (std::size_t i = 0; i < node->type->inputs.size(); ++i) {
      if (node->type->inputs[i].name == outputPin) {
        pin = static_cast<int>(i);
      }
    }
    if (pin < 0 || mGraph->InputLink(output, pin) == nullptr) {
      return nullptr;
    }
    (void)Evaluate(output);
    TexImagePtr image = Input(output, pin);
    const PinType type = node->type->inputs[static_cast<std::size_t>(pin)].type;
    const int channels = type == PinType::Color ? 4 : 1;
    if (image->size == mSize && image->channels == channels) {
      return image;
    }
    // At the graph's size and in the pin's type (a constant spread out, a grey image as colour or the reverse).
    auto converted = std::make_shared<TexImage>();
    converted->Reset(mSize, channels);
    for (int y = 0; y < mSize; ++y) {
      for (int x = 0; x < mSize; ++x) {
        float c[4];
        Fetch(*image, x, y, mSize, c);
        float* p = converted->Pixel(x, y);
        if (channels == 4) {
          std::copy(c, c + 4, p);
        } else {
          p[0] = image->channels == 1 ? c[0] : Luminance(c);
        }
      }
    }
    return converted;
  }
} // namespace faf::editor
