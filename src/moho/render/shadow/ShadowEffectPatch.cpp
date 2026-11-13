#include "moho/render/shadow/ShadowEffectPatch.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace moho::shadowfilter
{
  namespace
  {
    using std::size_t;
    using std::string;
    using std::string_view;

    constexpr size_t npos = string::npos;

    // The lookup both effects share. Tokens: @FILTER@ / @FILTER2@ (the parameters), @SIZE@ (shadow map size in texels,
    // the non-atlas forms only), @BIAS@ (the receiver's constant bias, in depth units), @TAPS@ (tap count expression),
    // @TILE@ (the move of the point `uv` into the texture), @TEXSIZE@ (the texture's size in texels) and @FETCH@ (one
    // point sample of the depth in the shadow map's red channel at the texture coordinates `q`).
    //
    // The shadow map holds the light-space depth of the nearest thing to the light in R (cleared to 1 = nothing in the
    // way) and 0 in G wherever that is a mesh; the ground is drawn into it as well (Shadow::RenderShadowMap, G is 1
    // there). The ground's R is a depth like a mesh's only with the terrain effect patched here (PatchTerrainEffect,
    // "the terrain depth"): the shipped TerrainDepthPS writes the clip-space z of a position its vertex shader has
    // multiplied by HeightScale (1/128), so R reads 1/128 of the depth there. Every texel is a caster: a hill shades
    // the ground behind it, and the ground against itself is held off by the receiver bias below. A lookup compares the
    // receiver's depth with the casters' depth at several points of a
    // rotated Vogel disk (equal-area spiral, golden angle). Each tap compares against the receiver depth moved along
    // the receiver's plane (derived from the screen space derivatives of the shadow coordinates), so a wide kernel on a
    // slope does not shadow its own surface. With a penumbra scale a first pass over the disk averages the depth of the
    // casters in front of the receiver; the kernel radius then grows with the receiver-to-caster distance
    // (percentage-closer soft shadows): contact shadows stay sharp, far ones soften.
    //
    // Cascades (ren_ShadowCascades): on Direct3D 12 and Vulkan the shadow texture can be an atlas of tiles, the finer
    // ones covering less of the view (gpg/gal/effects/ShadowCascades.h). The effect layer gives the lookup `tex2Dtile`,
    // `tex2Dtilesize` and `tex2Dtileload`: the lookup finds the tile that holds its centre once, and takes every tap in
    // the texels of that tile, as offsets in the texture's own coordinates. (Offsets in the whole-view map's
    // coordinates would read a finer tile at the whole-view map's texel size, and a point snap in those would miss the
    // atlas's texel centres.) Without cascades, and on Direct3D 11, the tile is the identity and the texture is the
    // map.
    //
    // The ground receives with its own, small bias (the epsilon its vertex shaders put on the shadow depth, less most
    // of it, see ShadowLookup) and the receiver-plane term: a bias as large as a unit's leaves a lit strip between a
    // unit's base and its shadow, where the caster's surface is closer to the ground than the bias.
    constexpr const char* kLookupCode = R"HLSL(
// ---- FAF shadow filter (ShadowEffectPatch): filtered shadow-map lookup, see docs/SHADOW_FILTERING.md ----
float4 @FILTER@;    // x taps (0 = shipped lookup), y radius (texels), z largest radius (texels), w penumbra scale (uv per depth unit)
float4 @FILTER2@;   // x constant bias scale, y receiver-plane bias scale

float4 ShadowFilterTile(float2 uv)
{
    return @TILE@;
}

float2 ShadowFilterTexSize()
{
    return @TEXSIZE@;
}

// The depth of the nearest thing to the light at the texel that holds the texture coordinates q (1 where nothing is drawn). The ground
// (G is 1) is moved @FILTER2@.z away from the light: the terrain the map holds is the terrain's mesh as seen from the light, not the surface
// the ground pixels are shaded on to the last triangle (the two disagree by a fraction of a triangle's height on curved ground), and
// without the margin every curved slope speckles and blocks out in shadow of itself. A hill still shades what is behind it.
float ShadowFilterFetch(float2 q)
{
    float2 size = ShadowFilterTexSize();
    q = (floor(q * size) + 0.5) / size;
    float2 texel = @FETCH@;
    return texel.x + (texel.y > 0.5 ? @FILTER2@.z : 0.0);
}

// Point i of n on a unit disk, rotated by `rot` (cos, sin).
float2 ShadowFilterDisk(float i, float n, float2 rot)
{
    float r = sqrt((i + 0.5) / n);
    float a = i * 2.39996323;
    float2 d = r * float2(cos(a), sin(a));
    return float2(d.x * rot.x - d.y * rot.y, d.x * rot.y + d.y * rot.x);
}

// The lit fraction (1 = sun, 0 = shadow) at a shadow coordinate: xy = uv in the whole-view shadow map, z = depth from the light. Needs
// screen space derivatives, so it must be reached by uniform control flow.
float ShadowFilterLookup(float4 coords)
{
    float2 uv = coords.xy;
    float z = coords.z;

    float4 tile = ShadowFilterTile(uv);
    if (tile.x <= 0.0)
    {
        return 1.0;   // past the volume the map covers: nothing is drawn for it
    }
    float2 size = ShadowFilterTexSize();
    float2 texel = 1.0 / size;          // a texel in texture coordinates
    float2 p = uv * tile.xy + tile.zw;  // the point in the texture

    // receiver plane: dz/dp from the screen space derivatives of uv and z (the tile's move is a scale and an offset, so it carries over)
    float2 duvdx = ddx(uv);
    float2 duvdy = ddy(uv);
    float2 dzdp = float2(ddx(z), ddy(z));
    float det = duvdx.x * duvdy.y - duvdx.y * duvdy.x;
    float2 slope = float2(dzdp.x * duvdy.y - dzdp.y * duvdx.y, dzdp.y * duvdx.x - dzdp.x * duvdy.x);
    slope = (abs(det) > 1e-10) ? slope / det : float2(0, 0);
    slope = clamp(slope, float2(-64, -64), float2(64, 64)) * @SLOPESCALE@ / tile.xy;

    float bias = @BIAS@;

    // a per-texel rotation of the disk (interleaved gradient noise on the shadow map texel: fixed in the world, no shimmer when the camera moves)
    float angle = 6.2831853 * frac(52.9829189 * frac(dot(floor(p * size), float2(0.06711056, 0.00583715))));
    float2 rot = float2(cos(angle), sin(angle));

    float radius = @FILTER@.y;
    if (@FILTER@.w > 0.0)
    {
        // blocker search: the average depth of the casters in front of the receiver within the largest radius
        float blockerSum = 0.0;
        float blockers = 0.0;
        for (int j = 0; j < 8; ++j)
        {
            float2 o = ShadowFilterDisk((float)j, 8.0, rot) * (@FILTER@.z * texel);
            float depth = ShadowFilterFetch(p + o);
            if (depth + bias < z + dot(slope, o))
            {
                blockerSum += depth;
                blockers += 1.0;
            }
        }
        if (blockers < 0.5)
        {
            return 1.0;
        }
        // the penumbra scale is in whole-view uv: a texel of this tile spans texel.x / tile.x of them
        radius = clamp((z - blockerSum / blockers) * @FILTER@.w * tile.x / texel.x, @FILTER@.y, @FILTER@.z);
    }

    int taps = @TAPS@;
    float lit = 0.0;
    float weights = 0.0;
    for (int i = 0; i < taps; ++i)
    {
        float2 d = ShadowFilterDisk((float)i, (float)taps, rot);
        float2 o = d * (radius * texel);
        float depth = ShadowFilterFetch(p + o);
        float w = 1.0 - 0.5 * dot(d, d);   // the rim counts less: a smoother falloff than a flat disk
        lit += (depth + bias >= z + dot(slope, o)) ? w : 0.0;
        weights += w;
    }
    return lit / weights;
}
)HLSL";

    string Replace(
      string text,
      const string_view token,
      const string_view value
    )
    {
      for (size_t p = text.find(token); p != npos; p = text.find(token, p + value.size())) {
        text.replace(p, token.size(), value);
      }
      return text;
    }

    // `tileAware`: the lookup reads through the effect layer's tile helpers (Direct3D 12 and Vulkan); otherwise the
    // texture is the map and the tile is the identity.
    string BuildLookup(
      const string_view filter,
      const string_view filter2,
      const string_view size,
      const string_view bias,
      const string_view sampler,
      const bool tileAware
    )
    {
      string code = kLookupCode;
      code = Replace(code, "@SLOPESCALE@", string(filter2) + ".y");
      code = Replace(code, "@BIAS@", string(bias));
      code = Replace(code, "@FILTER2@", filter2);
      code = Replace(code, "@FILTER@", filter);
      code = Replace(code, "@TAPS@", "(int)" + string(filter) + ".x");
      if (tileAware) {
        code = Replace(code, "@TILE@", "tex2Dtile(" + string(sampler) + ", uv)");
        code = Replace(code, "@TEXSIZE@", "tex2Dtilesize(" + string(sampler) + ")");
        code = Replace(code, "@FETCH@", "tex2Dtileload(" + string(sampler) + ", q).rg");
      } else {
        code = Replace(code, "@TILE@", "float4(1.0, 1.0, 0.0, 0.0)");
        code = Replace(code, "@TEXSIZE@", "float2(" + string(size) + ", " + string(size) + ")");
        // a gradient fetch (tex2D) must not sit inside a dynamic loop; a bilinear sampler (terrain.fx has no sampler to
        // spare: a pass of it already uses all 16 that shader model 4.1 allows) reads exactly one texel at the texel's
        // centre
        code = Replace(code, "@FETCH@", "tex2Dlod(" + string(sampler) + ", float4(q, 0, 0)).rg");
      }
      return code;
    }

    size_t CountOccurrences(
      const string& s,
      const string_view needle
    )
    {
      size_t n = 0;
      for (size_t p = s.find(needle); p != npos; p = s.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    }

    // The effect files are CRLF on disk; every anchor below is written with LF.
    void NormaliseLineEnds(
      string& s
    )
    {
      if (s.find('\r') == npos) {
        return;
      }
      string out;
      out.reserve(s.size());
      for (const char c : s) {
        if (c != '\r') {
          out.push_back(c);
        }
      }
      s = std::move(out);
    }

    // The index of the ')' that closes the '(' at `open`, or npos.
    size_t MatchParen(
      const string& s,
      const size_t open
    )
    {
      int depth = 0;
      for (size_t i = open; i < s.size(); ++i) {
        if (s[i] == '(') {
          ++depth;
        } else if (s[i] == ')' && --depth == 0) {
          return i;
        }
      }
      return npos;
    }

    string Trim(
      const string& s
    )
    {
      size_t a = 0;
      size_t b = s.size();
      while (a < b && (s[a] == ' ' || s[a] == '\t')) {
        ++a;
      }
      while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) {
        --b;
      }
      return s.substr(a, b - a);
    }
  } // namespace

  bool HandlesEffect(
    const std::string& baseName
  )
  {
    return baseName == "mesh" || baseName == "terrain";
  }

  PatchResult PatchMeshEffect(
    std::string& source,
    const bool tileAware
  )
  {
    PatchResult result;
    string s = source;
    NormaliseLineEnds(s);

    if (s.find("shadowFilter") != npos) {
      result.error = "mesh.fx: already patched";
      return result;
    }

    // the lookup goes in front of the first shadow function: the shadow samplers, shadowSize and shadowBias are
    // declared above it
    const string anchor = "// *** Standard Shadow Mapping ***\nfloat ComputeShadowStandard( float4 shadowCoords)";
    if (
      CountOccurrences(s, anchor) != 1 || s.find("sampler2D shadowSampler") == npos ||
      s.find("float       shadowBias;") == npos
    ) {
      result.error = "mesh.fx: the shadow functions moved";
      return result;
    }
    // ComputeShadow: the filtered lookup replaces the shipped one for the high-fidelity techniques
    const string hook = "        return shadowBlur ? (shadowsEnabled ? ComputeShadowPCF( shadowCoords) : 1.0f) : "
                        "ComputeShadowStandard( shadowCoords);";
    if (CountOccurrences(s, hook) != 1) {
      result.error = "mesh.fx: ComputeShadow changed";
      return result;
    }
    // one return per function (the Direct3D 9 compiler, which this text must stay acceptable to, rejects early returns)
    const string filtered = "        float fafShadow;   // FAF shadow filter\n"
                            "        if (shadowFilter.x > 0.5)\n"
                            "        {\n"
                            "            fafShadow = 1.0f;\n"
                            "            if (shadowsEnabled)\n"
                            "            {\n"
                            "                fafShadow = ComputeShadowFiltered( shadowCoords);\n"
                            "            }\n"
                            "        }\n"
                            "        else\n"
                            "        {\n"
                            "            fafShadow = shadowBlur ? (shadowsEnabled ? ComputeShadowPCF( shadowCoords) : "
                            "1.0f) : ComputeShadowStandard( shadowCoords);\n"
                            "        }\n"
                            "        return fafShadow;\n";
    s.replace(s.find(hook), hook.size(), filtered);

    string code = BuildLookup(
      "shadowFilter",
      "shadowFilter2",
      "shadowSize",
      "shadowFilter2.x * (shadowBias + 0.001)",
      "shadowSampler",
      tileAware
    );
    code += "\nfloat ComputeShadowFiltered( float4 shadowCoords)\n"
            "{\n"
            "    shadowCoords.xy /= shadowCoords.w;\n"
            "    return ShadowFilterLookup(shadowCoords);\n"
            "}\n\n";
    s.insert(s.find(anchor), code);
    result.lookups = 1;

    source = std::move(s);
    result.patched = true;
    return result;
  }

  PatchResult PatchTerrainEffect(
    std::string& source,
    const bool tileAware
  )
  {
    PatchResult result;
    string s = source;
    NormaliseLineEnds(s);

    if (s.find("ShadowFilter") != npos) {
      result.error = "terrain.fx: already patched";
      return result;
    }

    const string anchor = "float ComputeShadow( float4 vShadowCoord )";
    if (
      CountOccurrences(s, anchor) != 1 || s.find("float ShadowSize;") == npos ||
      s.find("texture ShadowTexture;") == npos || s.find("sampler2D ShadowSampler") == npos
    ) {
      result.error = "terrain.fx: the shadow functions moved";
      return result;
    }

    // every `tex2D(ShadowSampler, <coords>).g` lookup goes through ShadowLookup (done before the lookup code is
    // inserted, which has one itself)
    const string needle = "tex2D";
    int replaced = 0;
    for (size_t p = s.find(needle); p != npos; p = s.find(needle, p)) {
      size_t open = p + needle.size();
      while (open < s.size() && s[open] == ' ') {
        ++open;
      }
      if (open >= s.size() || s[open] != '(') {
        p += needle.size();
        continue;
      }
      const size_t close = MatchParen(s, open);
      if (close == npos || s.compare(close + 1, 2, ".g") != 0) {
        p += needle.size();
        continue;
      }
      const string inside = s.substr(open + 1, close - open - 1);
      const size_t comma = inside.find(',');
      if (comma == npos || Trim(inside.substr(0, comma)) != "ShadowSampler") {
        p += needle.size();
        continue;
      }
      string coords = Trim(inside.substr(comma + 1));
      if (coords.size() > 3 && coords.compare(coords.size() - 3, 3, ".xy") == 0) {
        coords.erase(coords.size() - 3); // mShadow.xy -> mShadow: the lookup wants the depth too
      }
      const string replacement = "ShadowLookup(" + coords + ")";
      s.replace(p, close + 3 - p, replacement);
      p += replacement.size();
      ++replaced;
    }
    if (replaced < 5) {
      result.error = "terrain.fx: only " + std::to_string(replaced) + " shadow lookups found";
      return result;
    }
    result.lookups = replaced;

    // The terrain depth: the shipped TerrainDepthVS multiplies the whole position, w included, by HeightScale (1/128),
    // so the clip-space z that TerrainDepthPS writes is 1/128 of the depth (the rasterised depth, z / w, is right: both
    // carry the factor). With the orthographic light w is that factor and z / w is the depth a mesh writes.
    const string depthOut = "return float4(inDepth.mDepth.z,1,0,1); // D24S8";
    if (CountOccurrences(s, depthOut) != 1) {
      result.error = "terrain.fx: TerrainDepthPS changed";
      return result;
    }
    s.replace(
      s.find(depthOut),
      depthOut.size(),
      "return float4(inDepth.mDepth.z / inDepth.mDepth.w,1,0,1); // FAF shadow filter: the depth, not 1/128 of it"
    );

    string code = BuildLookup(
      "ShadowFilter", "ShadowFilter2", "ShadowSize", "ShadowFilter2.x * 0.0003", "ShadowSampler", tileAware
    );
    code += R"HLSL(
// The sun term at a shadow coordinate (xy = uv, z = depth from the light): the filtered lookup, or the shipped one (the blurred G channel).
float ShadowLookup(float4 coords)
{
    float sun;
    if (@COND@)
    {
        // Both terrain vertex shaders move the shadow depth 0.01 towards the light ("put epsilon in vs": mShadow.z -= 0.01f), which the shipped
        // lookup never read (it takes the blurred G channel). The filtered lookup compares depths, so with it a ground point had to be 0.01
        // behind a caster to count as shadowed: a lit gap between every foot, wall and tower and the start of its shadow. The epsilon is put
        // back, leaving 0.0005 (and ShadowFilter2.x * 0.0003 in the lookup, with the receiver plane) so that the ground, which is in the map
        // as well, does not shadow itself and a caster standing on it does not speckle along the line where it touches it.
        sun = ShadowFilterLookup(float4(coords.xy, coords.z + 0.0095, coords.w));
        // Ground outside the light volume (past the shadow distance, or beyond the depth range of the map's fitted box) has no casters
        // drawn for it: it is lit. The depth comparison would otherwise read it as behind everything, a dark half-plane with a straight edge.
        float2 insideUv = step(float2(0.0, 0.0), coords.xy) * step(coords.xy, float2(1.0, 1.0));
        float insideZ = step(0.0, coords.z) * step(coords.z, 1.0);
        sun = lerp(1.0, sun, insideUv.x * insideUv.y * insideZ);
    }
    else
    {
        sun = tex2D( ShadowSampler, coords.xy ).g;
    }
    return sun;
}

)HLSL";
    code = Replace(code, "@COND@", "ShadowFilter.x > 0.5 && ShadowsEnabled == 1");
    s.insert(s.find(anchor), code);

    source = std::move(s);
    result.patched = true;
    return result;
  }
} // namespace moho::shadowfilter
