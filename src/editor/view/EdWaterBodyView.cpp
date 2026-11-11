// The Water tool's water bodies in the view: the scenario's bodies filled over the heights and put on the map (so the
// renderer draws them as the game does), their seeds, outlines and bounds drawn over the ground, and clicks that place
// and move them.

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

#include "editor/view/EdMapScene.h"
#include "gpg/core/utils/Logging.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/terrain/CWldTerrainRes.h"

namespace faf::editor
{
  namespace
  {
    constexpr float kHeightWordScale = 1.0f / 128.0f;

    /** The body number at the start of a "water body N ..." line, 0 when it has none. */
    std::size_t LineBody(
      const std::string& line
    )
    {
      constexpr const char kPrefix[] = "water body ";
      if (line.rfind(kPrefix, 0) != 0) {
        return 0;
      }
      return static_cast<std::size_t>(std::strtoul(line.c_str() + sizeof(kPrefix) - 1, nullptr, 10));
    }
  } // namespace

  void EdMapScene::RefreshWaterBodies()
  {
    if (mMap == nullptr || mPainting) {
      return; // during a stroke the heights move every frame: filled again when it ends
    }
    const std::string& scenario = mDocument.Scenario();
    if (!mWaterBodiesStale && scenario == mWaterBodiesScenario) {
      return;
    }
    mWaterBodiesStale = false;
    mWaterBodiesScenario = scenario;
    moho::IWldTerrainRes* const terrain = mMap->mTerrainRes;
    moho::STIMap* const map = terrain->mMap;
    const moho::CHeightField* const field = map->mHeightField.get();
    const WaterBodiesRead read = ReadWaterBodies(scenario);
    const bool had = map->HasWaterBodies();
    std::vector<std::string> perBody(read.bodies.size());
    std::vector<std::string> other;

    if (read.bodies.empty() || field == nullptr) {
      map->mWaterBodies.reset();
    } else {
      // As the game sets the shading defaults (STIMap::InstallWaterBodies): the sea's distances below its level.
      const bool seaShading = map->mWaterEnabled != 0u && map->mWaterElevation > map->mWaterElevationDeep &&
        map->mWaterElevation > map->mWaterElevationAbyss;
      const float deepBelow = seaShading ? map->mWaterElevation - map->mWaterElevationDeep : 2.5f;
      const float abyssBelow = seaShading ? map->mWaterElevation - map->mWaterElevationAbyss : 15.0f;
      std::vector<std::string> log;
      std::vector<std::size_t> bodyOf;
      const std::vector<moho::SWaterBodyDesc> descs = WaterBodyDescs(read.bodies, deepBelow, abyssBelow, log, &bodyOf);
      // The filler numbers its lines by the bodies it was given; the panel's by the scenario's.
      std::vector<std::string> fillLog;
      std::unique_ptr<moho::CWaterBodies> filled = descs.empty()
        ? nullptr
        : moho::CWaterBodies::Build(field->data, field->width, field->height, kHeightWordScale, descs, &fillLog);
      std::vector<bool> fillSkipped(descs.size(), false);
      for (std::string& line : fillLog) {
        const std::size_t desc = LineBody(line);
        if (desc >= 1 && desc <= descs.size()) {
          const std::size_t body = bodyOf[desc - 1] + 1;
          line = "water body " + std::to_string(body) + line.substr(line.find(' ', 11));
          fillSkipped[desc - 1] = fillSkipped[desc - 1] || line.find("skipped") != std::string::npos;
        }
        log.push_back(line);
      }
      for (const std::string& line : log) {
        const std::size_t body = LineBody(line);
        if (body >= 1 && body <= perBody.size()) {
          perBody[body - 1] += (perBody[body - 1].empty() ? "" : "; ") + line.substr(line.find(' ', 11) + 1);
        } else {
          other.push_back(line);
        }
      }
      std::uint8_t number = 0;
      for (std::size_t d = 0; d < descs.size(); ++d) {
        if (fillSkipped[d]) {
          continue;
        }
        std::string& line = perBody[bodyOf[d]];
        if (filled != nullptr && number < filled->BodyCount()) {
          const moho::SWaterBody& body = filled->Body(++number);
          char text[96];
          (void)std::snprintf(text, sizeof(text), "%u cells", body.cellCount);
          line = text + (line.empty() ? std::string() : "; " + line);
        }
      }
      map->mWaterBodies = std::move(filled);
    }
    for (std::size_t i = 0; i < perBody.size(); ++i) {
      gpg::Logf("editor: water body %zu: %s", i + 1, perBody[i].c_str());
    }
    for (const std::string& line : other) {
      gpg::Logf("editor: water bodies: %s", line.c_str());
    }
    if (mTools != nullptr) {
      mTools->SetWaterBodyReport(std::move(perBody), std::move(other));
    }
    // The water map (depth under each water, for its colour and the shore) follows, as the session's load does it.
    if (had || map->HasWaterBodies()) {
      if (terrain->IsInEditMode()) {
        terrain->UpdateWaterMap();
      } else {
        moho::CBackgroundTaskControl control{nullptr};
        terrain->EnterEditMode(control);
        terrain->ExitEditMode();
      }
    }
  }

  void EdMapScene::DrawWaterBodyGuides(
    moho::CD3DPrimBatcher& batcher,
    const moho::CHeightField& field
  )
  {
    if (mTools == nullptr || !mTools->WaterToolActive()) {
      return;
    }
    const std::vector<WaterBody>& bodies = mTools->EditedWaterBodies();
    const int selected = mTools->SelectedWaterBody();
    const auto ground = [&field](const float x, const float z) {
      const int sx = std::clamp(static_cast<int>(std::lround(x)), 0, field.width - 1);
      const int sz = std::clamp(static_cast<int>(std::lround(z)), 0, field.height - 1);
      return static_cast<float>(field.data[sz * field.width + sx]) * kHeightWordScale;
    };
    const auto vertex = [](const float x, const float y, const float z, const std::uint32_t color) {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = x;
      v.mY = y;
      v.mZ = z;
      v.mColor = color;
      return v;
    };
    std::vector<moho::CD3DPrimBatcher::Vertex> quads;
    const float r = std::max(1.5f, mDistance * 0.005f);
    for (std::size_t i = 0; i < bodies.size(); ++i) {
      const WaterBody& body = bodies[i];
      if (!body.raw.empty()) {
        continue;
      }
      const bool chosen = static_cast<int>(i) == selected;
      const std::uint32_t color =
        body.dry ? (chosen ? 0xFFE0B060u : 0x90E0B060u) : (chosen ? 0xFF50C8FFu : 0x9050C8FFu);
      // On the water where it is above the ground, else on the ground.
      const float level = body.dry ? -1.0e9f : body.elevation;
      const auto at = [&](const float x, const float z, const float lift) {
        return std::max(ground(x, z), level) + lift;
      };
      const auto line = [&](const float ax, const float az, const float bx, const float bz, const float lift) {
        const int steps = std::max(1, static_cast<int>(std::hypot(bx - ax, bz - az) / 3.0f));
        for (int s = 0; s < steps; ++s) {
          const float t0 = static_cast<float>(s) / steps;
          const float t1 = static_cast<float>(s + 1) / steps;
          const float x0 = ax + (bx - ax) * t0;
          const float z0 = az + (bz - az) * t0;
          const float x1 = ax + (bx - ax) * t1;
          const float z1 = az + (bz - az) * t1;
          batcher.DrawLine(vertex(x0, at(x0, z0, lift), z0, color), vertex(x1, at(x1, z1, lift), z1, color));
        }
      };
      // The outline: the curve the game fills inside; its control points on the chosen body.
      if (body.outline.size() >= 3) {
        std::vector<float> points;
        for (const auto& [x, z] : body.outline) {
          points.push_back(x);
          points.push_back(z);
        }
        const std::vector<float> polygon = moho::WaterBodyOutlinePolygon(points);
        for (std::size_t k = 0; k + 1 < polygon.size(); k += 2) {
          const std::size_t next = (k + 2) % polygon.size();
          line(polygon[k], polygon[k + 1], polygon[next], polygon[next + 1], 0.5f);
        }
      } else {
        for (std::size_t k = 1; k < body.outline.size(); ++k) {
          line(
            body.outline[k - 1].first, body.outline[k - 1].second, body.outline[k].first, body.outline[k].second, 0.5f
          );
        }
      }
      if (chosen) {
        for (std::size_t k = 0; k < body.outline.size(); ++k) {
          const auto [x, z] = body.outline[k];
          const std::uint32_t handle = static_cast<int>(k) == mWaterBodyHandle ? 0xFFFFE040u : 0xFFFFFFFFu;
          const float y = at(x, z, 0.8f);
          quads.insert(
            quads.end(),
            {vertex(x - r, y, z - r, handle),
             vertex(x + r, y, z - r, handle),
             vertex(x + r, y, z + r, handle),
             vertex(x - r, y, z + r, handle)}
          );
        }
      }
      // The seed: a pin standing on the ground, up through the water.
      if (body.hasSeed) {
        const float base = ground(body.seedX, body.seedZ);
        const float top = std::max(base, level) + std::max(4.0f, mDistance * 0.03f);
        const std::uint32_t pin = chosen && mWaterBodyHandle == -1 ? 0xFFFFE040u : color;
        batcher.DrawLine(vertex(body.seedX, base, body.seedZ, pin), vertex(body.seedX, top, body.seedZ, pin));
        quads.insert(
          quads.end(),
          {vertex(body.seedX - r, top, body.seedZ - r, pin),
           vertex(body.seedX + r, top, body.seedZ - r, pin),
           vertex(body.seedX + r, top, body.seedZ + r, pin),
           vertex(body.seedX - r, top, body.seedZ + r, pin)}
        );
      }
      // The bounds: a rectangle of vertices.
      if (body.hasBounds) {
        const float x0 = static_cast<float>(body.x0);
        const float z0 = static_cast<float>(body.z0);
        const float x1 = static_cast<float>(body.x1);
        const float z1 = static_cast<float>(body.z1);
        line(x0, z0, x1, z0, 0.3f);
        line(x1, z0, x1, z1, 0.3f);
        line(x1, z1, x0, z1, 0.3f);
        line(x0, z1, x0, z0, 0.3f);
      }
    }
    if (!quads.empty()) {
      batcher.DrawQuads(quads.data(), static_cast<std::uint32_t>(quads.size() / 4));
    }
  }

  int EdMapScene::WaterBodyHandleAt(
    const POINT at
  ) const
  {
    if (mCamera == nullptr || mTools == nullptr) {
      return -2;
    }
    const std::vector<WaterBody>& bodies = mTools->EditedWaterBodies();
    const int selected = mTools->SelectedWaterBody();
    if (
      selected < 0 || selected >= static_cast<int>(bodies.size()) ||
      !bodies[static_cast<std::size_t>(selected)].raw.empty()
    ) {
      return -2;
    }
    const WaterBody& body = bodies[static_cast<std::size_t>(selected)];
    const moho::CHeightField* const field = mMap->mTerrainRes->GetHeightField();
    const auto ground = [field](const float x, const float z) {
      const int sx = std::clamp(static_cast<int>(std::lround(x)), 0, field->width - 1);
      const int sz = std::clamp(static_cast<int>(std::lround(z)), 0, field->height - 1);
      return static_cast<float>(field->data[sz * field->width + sx]) * kHeightWordScale;
    };
    const float level = body.dry ? -1.0e9f : body.elevation;
    int best = -2;
    float bestDistance = 12.0f; // pixels
    const auto consider = [&](const int handle, const float x, const float z, const float lift) {
      const Wm3::Vector2f p = mCamera->Project(Wm3::Vec3f{x, std::max(ground(x, z), level) + lift, z});
      const float distance = std::hypot(p.x - static_cast<float>(at.x), p.y - static_cast<float>(at.y));
      if (distance < bestDistance) {
        bestDistance = distance;
        best = handle;
      }
    };
    for (std::size_t k = 0; k < body.outline.size(); ++k) {
      consider(static_cast<int>(k), body.outline[k].first, body.outline[k].second, 0.8f);
    }
    if (body.hasSeed) {
      const float base = ground(body.seedX, body.seedZ);
      const float top = std::max(base, level) + std::max(4.0f, mDistance * 0.03f);
      consider(-1, body.seedX, body.seedZ, top - std::max(base, level));
      consider(-1, body.seedX, body.seedZ, 0.0f);
    }
    return best;
  }

  bool EdMapScene::WaterBodyPress(
    const HWND window,
    const POINT at
  )
  {
    if (mTools == nullptr || !mTools->WaterToolActive()) {
      return false;
    }
    std::vector<WaterBody>& bodies = mTools->EditedWaterBodies();
    const int selected = mTools->SelectedWaterBody();
    if (selected < 0 || selected >= static_cast<int>(bodies.size())) {
      return false;
    }
    WaterBody& body = bodies[static_cast<std::size_t>(selected)];
    float groundX = 0.0f;
    float groundZ = 0.0f;
    const bool onGround = GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ);
    switch (mTools->WaterBodyPick()) {
    case EdTools::WaterPick::Seed:
      if (onGround) {
        body.hasSeed = true;
        body.seedX = std::round(groundX);
        body.seedZ = std::round(groundZ);
        if (mTools->WaterBodyIsNew()) {
          // A new lake starts a little above the ground clicked: a pond the user then raises.
          body.hasElevation = true;
          body.elevation = std::round(
                             (mMap->mTerrainRes->GetHeightAt(
                                static_cast<std::int32_t>(body.seedX), static_cast<std::int32_t>(body.seedZ)
                              ) +
                              2.0f) *
                             4.0f
                           ) /
            4.0f;
          mTools->WaterBodyIsNew() = false;
        }
        mTools->WaterBodyPick() = EdTools::WaterPick::None;
        mTools->WaterBodiesChanged(true);
        gpg::Logf(
          "editor: water body %d seed at %.0f, %.0f",
          selected + 1,
          static_cast<double>(body.seedX),
          static_cast<double>(body.seedZ)
        );
      }
      return true;
    case EdTools::WaterPick::Outline:
      if (onGround) {
        body.outline.emplace_back(std::round(groundX * 2.0f) / 2.0f, std::round(groundZ * 2.0f) / 2.0f);
        mTools->WaterBodiesChanged(true);
      }
      return true;
    default:
      break;
    }
    // A press on the chosen body's seed or one of its outline points drags it.
    mWaterBodyHandle = WaterBodyHandleAt(at);
    if (mWaterBodyHandle == -2) {
      return false;
    }
    mTools->SetWaterBodyDragging(true);
    ::SetCapture(window);
    ::SetFocus(window);
    return true;
  }

  void EdMapScene::WaterBodyDrag(
    const POINT at
  )
  {
    if (mWaterBodyHandle == -2 || mTools == nullptr) {
      return;
    }
    std::vector<WaterBody>& bodies = mTools->EditedWaterBodies();
    const int selected = mTools->SelectedWaterBody();
    float groundX = 0.0f;
    float groundZ = 0.0f;
    if (
      selected < 0 || selected >= static_cast<int>(bodies.size()) ||
      !GroundAt(static_cast<float>(at.x), static_cast<float>(at.y), groundX, groundZ)
    ) {
      return;
    }
    WaterBody& body = bodies[static_cast<std::size_t>(selected)];
    if (mWaterBodyHandle == -1) {
      body.seedX = std::round(groundX);
      body.seedZ = std::round(groundZ);
    } else if (mWaterBodyHandle < static_cast<int>(body.outline.size())) {
      body.outline[static_cast<std::size_t>(mWaterBodyHandle)] = {
        std::round(groundX * 2.0f) / 2.0f, std::round(groundZ * 2.0f) / 2.0f
      };
    }
    mTools->WaterBodiesChanged(false);
  }

  void EdMapScene::WaterBodyRelease()
  {
    if (mWaterBodyHandle == -2) {
      return;
    }
    mWaterBodyHandle = -2;
    if (mTools != nullptr) {
      mTools->SetWaterBodyDragging(false);
      mTools->WaterBodiesChanged(true);
    }
    ::ReleaseCapture();
  }
} // namespace faf::editor
