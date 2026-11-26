// Engine addition: the Options > Video entries of the image-quality features (anti-aliasing, sharpening, colour
// grading, the wide glow, texture filtering and the render scale) in the render feature registry (RenderFeatures.h),
// and of the scene effects upstream added as Lua blocks of options.lua: temporal anti-aliasing, sun shafts and height
// fog, bounce light and water reflections by ray.
//
// They are registered from one function so that their order is fixed: each entry is listed after the one it names in
// `after`. Every one keeps the option key it had as a Lua block of options.lua, with the same state keys (numbers), so
// a saved profile still selects the same state; the state's `value` is what the console variable takes (ren_Sharpen is
// a strength, ren_TextureAnisotropy a number of samples, not the index of the state).

#include "moho/render/RenderFeatures.h"

namespace moho::render
{
  namespace
  {
    void SupportOn(
      Feature& feature,
      const bool d3d11,
      const bool d3d12,
      const bool vulkan,
      const char* const reasonWhenNot = ""
    )
    {
      const auto set = [&](const Api api, const bool supported) {
        ApiSupport& support = feature.apis[static_cast<int>(api)];
        support.supported = supported;
        if (!supported) {
          support.reason = reasonWhenNot;
        }
      };
      feature.apis[static_cast<int>(Api::D3D10)].reason = "the Direct3D 10 renderer does not start";
      set(Api::D3D11, d3d11);
      set(Api::D3D12, d3d12);
      set(Api::Vulkan, vulkan);
    }

    const bool gRegistered = [] {
      {
        Feature feature;
        feature.key = "fxaa_on";
        feature.title = "Anti-aliasing";
        feature.tip = "Smooths jagged edges of the 3D world. FXAA is fast and soft; SMAA is a lightweight form of "
                      "subpixel morphological anti-aliasing (three passes) that keeps thin lines such as wires and "
                      "antennas sharper. The interface and the strategic icons are not touched.";
        feature.console = "ren_Fxaa";
        feature.after = "antialiasing";
        feature.numericKeys = true;
        feature.states = {{"<LOC _Off>", "0", "0"}, {"FXAA", "1", "1"}, {"SMAA", "2", "2"}};
        feature.defaultLevel = 1;
        SupportOn(feature, true, true, true);
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "sharpen_level";
        feature.title = "Sharpening";
        feature.tip = "Brings back edge and texture detail that anti-aliasing and scaling soften.";
        feature.console = "ren_Sharpen";
        feature.after = "fxaa_on";
        feature.numericKeys = true;
        feature.states = {
          {"<LOC _Off>", "0", "0"},
          {"<LOC _Low>", "1", "0.25"},
          {"<LOC _Medium>", "2", "0.5"},
          {"<LOC _High>", "3", "1"}
        };
        feature.defaultLevel = 2;
        SupportOn(feature, true, true, true);
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "grade_on";
        feature.title = "Colour grading";
        feature.tip = "Livelier dull colours and slightly deeper contrast; team colours stay as they are.";
        feature.console = "ren_Grade";
        feature.after = "sharpen_level";
        feature.numericKeys = true;
        feature.states = {{"<LOC _On>", "1", "1"}, {"<LOC _Off>", "0", "0"}};
        feature.defaultLevel = 0;
        SupportOn(feature, true, true, true);
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "bloom_wide_level";
        feature.title = "Wide glow";
        feature.tip =
          "A soft, wide halo around lights, explosions and shields, added to the bloom. Needs Bloom Render.";
        feature.console = "ren_BloomWide";
        feature.after = "grade_on";
        feature.numericKeys = true;
        feature.states = {{"<LOC _Off>", "0", "0"}, {"Normal", "1", "1"}, {"Strong", "2", "2"}};
        feature.defaultLevel = 0;
        SupportOn(feature, false, true, true, "needs Direct3D 12 or Vulkan");
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "texture_anisotropy";
        feature.title = "Texture filtering";
        feature.tip =
          "Keeps ground and unit textures sharp when seen at a slant (anisotropic filtering). Applies at once.";
        feature.console = "ren_TextureAnisotropy";
        feature.after = "texture_level";
        feature.numericKeys = true;
        feature.states = {{"Trilinear", "0", "0"}, {"4x", "1", "4"}, {"8x", "2", "8"}, {"16x", "3", "16"}};
        feature.defaultLevel = 2;
        SupportOn(feature, true, true, true);
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "render_scale";
        feature.title = "Render resolution";
        feature.tip =
          "Draws the 3D world at a fraction of the window size and scales it up before the interface is drawn, "
          "so the interface and text stay sharp. With temporal anti-aliasing on, the picture is rebuilt from the "
          "last frames; otherwise it is upscaled by a sharp filter. A cheap way to gain frame rate on a weak graphics "
          "card or at 4K. Render only, never affects the game. Takes effect at once.";
        feature.console = "ren_RenderScale";
        feature.numericKeys = true;
        feature.after = "texture_anisotropy";
        feature.states = {
          {"100%", "100", "1"},
          {"85%", "85", "0.85"},
          {"75%", "75", "0.75"},
          {"67%", "67", "0.67"},
          {"50%", "50", "0.5"}
        };
        feature.defaultLevel = 0;
        SupportOn(feature, true, true, true);
        RegisterFeature(feature);
      }
      // Registered last of the anti-aliasing group: each entry that names `fxaa_on` goes right after it, so this one
      // does too, ahead of sharpening and the grade, which were placed before it.
      {
        Feature feature;
        feature.key = "taa";
        feature.title = "Temporal anti-aliasing";
        feature.tip =
          "Smooths edges and stops thin lines and far detail from crawling, by blending each frame with the "
          "last ones. Replaces FXAA while on.";
        feature.console = "ren_Taa";
        feature.after = "fxaa_on";
        feature.numericKeys = true;
        feature.states = {{"<LOC _On>", "1", "1"}, {"<LOC _Off>", "0", "0"}};
        feature.defaultLevel = 1;
        SupportOn(feature, false, true, true, "needs Direct3D 12 or Vulkan");
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "atmosphere";
        feature.title = "Sun shafts and height fog";
        feature.tip = "A light haze over the low ground and water, lit by the sun, darker where hills shade it. Never "
                      "thick enough to hide units.";
        feature.console = "ren_Atmosphere";
        feature.after = "dynamic_lights_optin";
        feature.numericKeys = true;
        feature.states = {{"<LOC _On>", "1", "1"}, {"<LOC _Off>", "0", "0"}};
        feature.defaultLevel = 1;
        SupportOn(feature, false, true, true, "needs Direct3D 12 or Vulkan");
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "ray_water_optin";
        feature.title = "Ray-traced water reflections";
        feature.tip =
          "With ray-traced shadows on: lakes and the sea reflect the hills, ground and units around them, not "
          "only the sky.";
        feature.console = "ren_RayWaterReflections";
        feature.after = "ray_soft_shadows_optin";
        feature.numericKeys = true;
        feature.needsRayTracing = true;
        feature.states = {{"<LOC _On>", "1", "1"}, {"<LOC _Off>", "0", "0"}};
        feature.defaultLevel = 1;
        SupportOn(feature, false, true, true, "needs Direct3D 12 or Vulkan");
        RegisterFeature(feature);
      }
      {
        Feature feature;
        feature.key = "ray_bounce_optin";
        feature.title = "Ray-traced bounce light";
        feature.tip = "With ray-traced shadows on: light bounces once off the ground, cliffs and buildings onto what "
                      "stands next to them, in their own colour.";
        feature.console = "ren_RayBounce";
        feature.after = "ray_water_optin";
        feature.numericKeys = true;
        feature.needsRayTracing = true;
        feature.states = {{"<LOC _On>", "1", "1"}, {"<LOC _Off>", "0", "0"}};
        feature.defaultLevel = 1;
        SupportOn(feature, false, true, true, "needs Direct3D 12 or Vulkan");
        RegisterFeature(feature);
      }
      return true;
    }();
  } // namespace
} // namespace moho::render
