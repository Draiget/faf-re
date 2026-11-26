// The domain tests of the headless water lab (docs/WATER_SIMULATION.md, "Water bodies"): the simulation per water of a
// map with water bodies. Included by watersimlab.cpp; `watersimlab --src <WaterSimulation.cpp> --domains` runs them.
//
// Tests 6 to 8 are pure CPU (domains_cpu.h: the shore fields per domain, the window centre); 1 to 5 and 9 run the real
// compute shader of the game on WARP over synthetic maps with several waters:
//   1 parity:    domains off, and a one-domain table, give bit-identical states (and the same shore fields)
//   2 basins:    two basins at 25 and 40 with a wall between: a pulse in one leaves the other at exactly zero
//   3 touching:  two waters side by side with no land between: the border reflects, nothing crosses
//   4 dry body:  a dry polder below the sea: all land, no height, no foam, no source taken
//   5 beach:     the land contour of each basin lies on the contour of its own level; foam on both beaches
//   6 fetch:     a small lake stays calm (short fetch), the open sea keeps its fetch, the march stops at a domain
//   border 7 brute:     the shore fields per domain against a brute-force reference on random domain maps 8 centre: the
//   window centre on one level equals the plane intersection; on a lake it is on the lake 9 gate:      the CPU source
//   gate and the land test of the shader agree
#pragma once

#include "domains_cpu.h"

namespace domains
{
  struct LabSource
  {
    float x, z, radius, push, foam, kind, domain, c; // domain: the number of the water plus one (0 any)
  };

  // ---- the shader on WARP -----------------------------------------------------------------------
  struct Constants
  {
    float a[4], b[4], c[4], d[4], e[4], f[4], g[4];
  };

  struct SimLab
  {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11ComputeShader> cs;        // the step as it was before water bodies
    ComPtr<ID3D11ComputeShader> csDomains; // the step with FAF_DOMAINS defined (a map with water bodies)
    struct Buf
    {
      ComPtr<ID3D11Buffer> buffer;
      ComPtr<ID3D11ShaderResourceView> srv;
      ComPtr<ID3D11UnorderedAccessView> uav;
    };
    Buf state[2], sources, heights, shore;
    ComPtr<ID3D11Buffer> constantBuffer, staging;
    int current = 0;
    static constexpr UINT kSourceSlots = 512;

    Buf MakeBuffer(
      const UINT stride,
      const UINT count,
      const void* init,
      const bool writable
    )
    {
      Buf r;
      D3D11_BUFFER_DESC d{};
      d.ByteWidth = stride * count;
      d.Usage = D3D11_USAGE_DEFAULT;
      d.BindFlags = D3D11_BIND_SHADER_RESOURCE | (writable ? D3D11_BIND_UNORDERED_ACCESS : 0U);
      d.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
      d.StructureByteStride = stride;
      std::vector<std::uint8_t> zero;
      if (init == nullptr) {
        zero.assign(d.ByteWidth, 0);
        init = zero.data();
      }
      D3D11_SUBRESOURCE_DATA data{init, 0, 0};
      device->CreateBuffer(&d, &data, &r.buffer);
      D3D11_SHADER_RESOURCE_VIEW_DESC sv{};
      sv.Format = DXGI_FORMAT_UNKNOWN;
      sv.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
      sv.Buffer.NumElements = count;
      device->CreateShaderResourceView(r.buffer.Get(), &sv, &r.srv);
      if (writable) {
        D3D11_UNORDERED_ACCESS_VIEW_DESC uv{};
        uv.Format = DXGI_FORMAT_UNKNOWN;
        uv.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        uv.Buffer.NumElements = count;
        device->CreateUnorderedAccessView(r.buffer.Get(), &uv, &r.uav);
      }
      return r;
    }

    bool Init(
      const std::string& hlsl
    )
    {
      D3D_FEATURE_LEVEL level{};
      if (
        FAILED(D3D11CreateDevice(
          nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &device, &level, &context
        ))
      ) {
        std::fprintf(stderr, "no WARP device\n");
        return false;
      }
      for (const bool withDomains : {false, true}) {
        const std::string text = (withDomains ? std::string("#define FAF_DOMAINS 1\n") : std::string()) + hlsl;
        ComPtr<ID3DBlob> code, errors;
        if (
          FAILED(D3DCompile(
            text.data(), text.size(), "WaterSimulation.hlsl", nullptr, nullptr, "SimCS", "cs_5_0", 0, 0, &code, &errors
          ))
        ) {
          std::fprintf(
            stderr, "shader: %s\n", errors != nullptr ? static_cast<const char*>(errors->GetBufferPointer()) : "?"
          );
          return false;
        }
        device->CreateComputeShader(
          code->GetBufferPointer(), code->GetBufferSize(), nullptr, withDomains ? &csDomains : &cs
        );
      }
      const UINT cells = static_cast<UINT>(kN) * static_cast<UINT>(kN);
      sources = MakeBuffer(16, kSourceSlots * 2U, nullptr, false);
      D3D11_BUFFER_DESC cbd{};
      cbd.ByteWidth = sizeof(Constants);
      cbd.Usage = D3D11_USAGE_DEFAULT;
      cbd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
      device->CreateBuffer(&cbd, nullptr, &constantBuffer);
      D3D11_BUFFER_DESC sd{};
      sd.ByteWidth = 16U * cells;
      sd.Usage = D3D11_USAGE_STAGING;
      sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
      sd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
      sd.StructureByteStride = 16;
      device->CreateBuffer(&sd, nullptr, &staging);
      return true;
    }

    // a fresh calm state and the buffers of a world
    void Load(
      const World& w
    )
    {
      const UINT cells = static_cast<UINT>(kN) * static_cast<UINT>(kN);
      state[0] = MakeBuffer(16, cells, nullptr, true);
      state[1] = MakeBuffer(16, cells, nullptr, true);
      current = 0;
      std::vector<std::uint32_t> packed((w.raw.size() + 1U) / 2U, 0U);
      for (std::size_t i = 0; i < w.raw.size(); ++i) {
        packed[i >> 1U] |= static_cast<std::uint32_t>(w.raw[i]) << ((i & 1U) * 16U);
      }
      heights = MakeBuffer(4, static_cast<UINT>(packed.size()), packed.data(), false);
      shore = MakeBuffer(4, static_cast<UINT>(w.shore.size()), w.shore.data(), false);
    }

    void Step(
      const Constants& k,
      const std::vector<LabSource>& list
    )
    {
      const UINT count = static_cast<UINT>(std::min<std::size_t>(list.size(), kSourceSlots));
      Constants c = k;
      c.b[2] = static_cast<float>(count);
      if (count > 0) {
        D3D11_BOX box{0, 0, 0, count * 2U * 16U, 1, 1};
        context->UpdateSubresource(sources.buffer.Get(), 0, &box, list.data(), 0, 0);
      }
      context->UpdateSubresource(constantBuffer.Get(), 0, nullptr, &c, 0, 0);
      ID3D11ShaderResourceView* srvs[4] = {
        state[current].srv.Get(), sources.srv.Get(), heights.srv.Get(), shore.srv.Get()
      };
      ID3D11UnorderedAccessView* uavs[1] = {state[current ^ 1].uav.Get()};
      context->CSSetShader(k.g[2] > 0.5f ? csDomains.Get() : cs.Get(), nullptr, 0);
      context->CSSetConstantBuffers(0, 1, constantBuffer.GetAddressOf());
      context->CSSetShaderResources(0, 4, srvs);
      context->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
      context->Dispatch(static_cast<UINT>(kN / 8), static_cast<UINT>(kN / 8), 1);
      ID3D11ShaderResourceView* noSrv[4] = {};
      ID3D11UnorderedAccessView* noUav[1] = {};
      context->CSSetShaderResources(0, 4, noSrv);
      context->CSSetUnorderedAccessViews(0, 1, noUav, nullptr);
      current ^= 1;
    }

    // height, last height, foam, land tag of every cell
    std::vector<float> Read()
    {
      std::vector<float> out(static_cast<std::size_t>(kN) * kN * 4U);
      context->CopyResource(staging.Get(), state[current].buffer.Get());
      D3D11_MAPPED_SUBRESOURCE map{};
      if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
        std::memcpy(out.data(), map.pData, out.size() * sizeof(float));
        context->Unmap(staging.Get(), 0);
      }
      return out;
    }
  };

  struct Opts
  {
    bool domains = true;
    float shoreWave = 0.0f; // the factor of the shore waves (0 off)
    float damping = 1.0f;   // 1 none, the game's is 1 - kDamping
    float swell = 0.0f;
    float seed = 17.0f;
  };

  inline Constants MakeConstants(
    const World& w,
    const Opts& o,
    const float time,
    const bool landMask = true
  )
  {
    const float half = 0.5f * static_cast<float>(kN) * kCell;
    Constants k{};
    k.b[0] = kCell;
    k.b[1] = static_cast<float>(kN);
    k.b[3] = kStep;
    k.c[0] = moho::water::kWaveTerm;
    k.c[1] = o.damping;
    k.c[2] = half;
    k.c[3] = half;
    k.d[0] = half;
    k.d[1] = o.shoreWave;
    k.d[2] = o.seed;
    k.d[3] = moho::water::kCapillary;
    k.e[0] = static_cast<float>(w.hw);
    k.e[1] = static_cast<float>(w.hh);
    k.e[2] = (w.seaLevel - kMargin) * 128.0f;
    k.e[3] = landMask ? 1.0f : 0.0f;
    k.f[0] = time;
    k.f[1] = o.swell;
    k.f[2] = moho::water::kFoamKept;
    k.f[3] = o.swell > 0.0f || o.shoreWave > 0.0f ? 1.0f : 0.0f;
    k.g[0] = static_cast<float>(w.table.blocksX);
    k.g[1] = static_cast<float>(w.table.blocksZ);
    k.g[2] = o.domains ? 1.0f : 0.0f;
    return k;
  }

  // runs `steps` steps; `sourcesAt(step)` gives the sources of a step; `onStep(step, state)` may look at the state
  // (read back only where it asks for it: `wantRead(step)`)
  inline void Run(
    SimLab& lab,
    const World& w,
    const Opts& o,
    const int steps,
    const std::function<std::vector<LabSource>(int)>& sourcesAt,
    const std::function<bool(int)>& wantRead,
    const std::function<void(int, const std::vector<float>&)>& onRead
  )
  {
    lab.Load(w);
    for (int step = 0; step < steps; ++step) {
      lab.Step(
        MakeConstants(w, o, static_cast<float>(step) * kStep), sourcesAt ? sourcesAt(step) : std::vector<LabSource>{}
      );
      if (wantRead && wantRead(step)) {
        onRead(step, lab.Read());
      }
    }
  }

  inline std::uint64_t Hash(
    const std::vector<float>& v
  )
  {
    std::uint64_t h = 1469598103934665603ull;
    for (const float f : v) {
      std::uint32_t bits;
      std::memcpy(&bits, &f, 4);
      h = (h ^ bits) * 1099511628211ull;
    }
    return h;
  }

  // the cell (world position of its centre) of cell index
  inline float CellX(
    const int i
  )
  {
    return (static_cast<float>(i) + 0.5f) * kCell;
  }

  struct Stats
  {
    double energy = 0.0; // sum of height^2 + (12 speed)^2 over the cells of a predicate
    double volume = 0.0;
    double maxAbs = 0.0;
    double foam = 0.0;
    double absVolume = 0.0;
    double foamMax = 0.0;
    int land = 0;
    int cells = 0;
  };

  inline Stats Measure(
    const std::vector<float>& s,
    const std::function<bool(float, float)>& inside
  )
  {
    Stats st;
    for (int j = 0; j < kN; ++j) {
      for (int i = 0; i < kN; ++i) {
        if (!inside(CellX(i), CellX(j))) {
          continue;
        }
        const float* c = &s[(static_cast<std::size_t>(j) * kN + i) * 4U];
        ++st.cells;
        if (c[3] > 0.5f) {
          ++st.land;
          continue;
        }
        const double speed = (c[0] - c[1]) * 12.0;
        st.energy += static_cast<double>(c[0]) * c[0] + speed * speed;
        st.volume += static_cast<double>(c[0]) * kCell * kCell;
        st.absVolume += std::fabs(static_cast<double>(c[0])) * kCell * kCell;
        st.maxAbs = std::max(st.maxAbs, static_cast<double>(std::fabs(c[0])));
        st.foam += c[2];
        st.foamMax = std::max(st.foamMax, static_cast<double>(c[2]));
      }
    }
    return st;
  }

  // ---- the worlds of the tests ------------------------------------------------------------------
  // two basins, a wall of land between them: A (domain 1, level 25) at x 30 .. 110, B (domain 2, level 40) at x 150 ..
  // 226, the ground 5 units below each level, 60 on the wall. Domain 0 (the wall, no sea) is dry.
  inline World BasinsWorld()
  {
    return MakeWorld([](const float x, const float) {
      if (x >= 30.0f && x <= 112.0f) {
        return 20.0f;
      }
      if (x >= 148.0f && x <= 228.0f) {
        return 35.0f;
      }
      return 60.0f;
    }, [](const std::uint32_t bx, const std::uint32_t, float& level, std::uint8_t& body) {
      const float x = static_cast<float>(bx * 2U) + 1.0f;
      if (x >= 30.0f && x <= 112.0f) {
        level = 25.0f;
        body = 1U;
      } else if (x >= 148.0f && x <= 228.0f) {
        level = 40.0f;
        body = 2U;
      } else {
        level = moho::water::kNoWaterLevel;
        body = 0U;
      }
    });
  }

  // two waters side by side, the ground flat at 10 everywhere (no land between): A (domain 1, level 25) for x < 128, B
  // (domain 2, level 40) from 128 on
  inline World TouchingWorld(
    const bool border = true
  )
  {
    return MakeWorld([](const float, const float) {
      return 10.0f;
    }, [border](const std::uint32_t bx, const std::uint32_t, float& level, std::uint8_t& body) {
      const float x = static_cast<float>(bx * 2U);
      if (x < 128.0f || !border) { // (without the border: one water of level 25 all over, for the control)
        level = 25.0f;
        body = 1U;
      } else {
        level = 40.0f;
        body = 2U;
      }
    });
  }

  // the sea at 25 with ground at 5, and a dry polder (domain 3, no water) of 60 x 60 units with ground 5 too (as low as
  // the sea bed: only the domain keeps the sea out)
  inline World PolderWorld()
  {
    return MakeWorld([](const float, const float) {
      return 5.0f;
    }, [](const std::uint32_t bx, const std::uint32_t bz, float& level, std::uint8_t& body) {
      const float x = static_cast<float>(bx * 2U);
      const float z = static_cast<float>(bz * 2U);
      if (x >= 100.0f && x < 160.0f && z >= 100.0f && z < 160.0f) {
        level = moho::water::kNoWaterLevel;
        body = 3U;
      } else {
        level = 25.0f;
        body = 0U;
      }
    });
  }

  // two bowls with sloped beaches: A (domain 1, level 25, centre x 78) and B (domain 2, level 40, centre x 180), the
  // bed 5 below the level, rising 0.25 per unit beyond 20 units from the centre; the wall between is dry (domain 0).
  inline float BowlGround(
    const float x
  )
  {
    const auto bowl = [x](const float centre, const float level) {
      return level - 5.0f + 0.25f * std::max(std::fabs(x - centre) - 20.0f, 0.0f);
    };
    return std::min(70.0f, x < 130.0f ? bowl(78.0f, 25.0f) : bowl(180.0f, 40.0f)); // (a cliff at 130: the wall)
  }

  inline World BowlsWorld()
  {
    return MakeWorld([](const float x, const float) {
      return BowlGround(x);
    }, [](const std::uint32_t bx, const std::uint32_t, float& level, std::uint8_t& body) {
      const float x = static_cast<float>(bx * 2U) + 1.0f;
      if (x >= 33.0f && x <= 123.0f) {
        level = 25.0f;
        body = 1U;
      } else if (x >= 135.0f && x <= 225.0f) {
        level = 40.0f;
        body = 2U;
      } else {
        level = moho::water::kNoWaterLevel;
        body = 0U;
      }
    });
  }

  inline std::vector<LabSource> Pulse(
    const float x,
    const float z,
    const float radius,
    const float push,
    const float domainPlusOne,
    const float kind = 0.0f
  )
  {
    return {LabSource{x, z, radius, push, 0.0f, kind, domainPlusOne, 0.0f}};
  }

  // ---- 1 ----------------------------------------------------------------------------------------
  inline void TestParity(
    SimLab& lab,
    Check& check
  )
  {
    std::printf("1 parity: domains off, a one-domain table, and the shore fields of both\n");
    // the coast of the lab's synthetic terrain as raw samples
    World coast = MakeWorld([](const float x, const float z) {
      const float coastX = 150.0f + 22.0f * std::sin(z * 0.035f) + 10.0f * std::sin(z * 0.11f + 1.0f);
      const float s = coastX - x;
      return s > 0.0f ? 25.0f - std::min(0.07f * s + 0.2f, 12.0f) + 0.3f * std::sin(x * 0.7f + z * 0.3f)
                      : 25.0f + 0.3f * (-s) + 0.1f;
    }, [](const std::uint32_t, const std::uint32_t, float& level, std::uint8_t& body) {
      level = 25.0f;
      body = 0U;
    });
    const std::uint32_t hw = coast.hw;
    const std::vector<float> plain =
      moho::water::ComputeShoreDistance([&](const std::uint32_t x, const std::uint32_t z) {
      return coast.raw[static_cast<std::size_t>(z) * hw + x];
    }, hw, coast.hh, (25.0f - kMargin) * 128.0f, 0.0f);
    const std::size_t samples = static_cast<std::size_t>(hw) * coast.hh;
    check(
      coast.shore.size() == plain.size() + 2U * coast.table.levelRaw.size() &&
        std::memcmp(coast.shore.data(), plain.data(), plain.size() * sizeof(float)) == 0,
      "ComputeShoreDistanceDomains with one domain gives ComputeShoreDistance's array, bit for bit",
      static_cast<double>(coast.shore.size()),
      static_cast<double>(plain.size())
    );
    (void)samples;
    // two states: the plain buffer with the domains off, the buffer with the table with them on
    World plainWorld = coast;
    plainWorld.shore = plain;
    Opts off;
    off.domains = false;
    off.shoreWave = 1.0f;
    off.swell = 1.0f;
    off.damping = 1.0f - moho::water::kDamping;
    Opts on = off;
    on.domains = true;
    std::vector<std::uint64_t> hashOff, hashOn;
    const auto sources = [](const int step) {
      return step == 0 ? Pulse(100.0f, 128.0f, 6.0f, 40.0f, 0.0f) : std::vector<LabSource>{};
    };
    const auto wantRead = [](const int step) {
      return step % 60 == 59;
    };
    Run(lab, plainWorld, off, 240, sources, wantRead, [&](int, const std::vector<float>& s) {
      hashOff.push_back(Hash(s));
    });
    Run(lab, coast, on, 240, sources, wantRead, [&](int, const std::vector<float>& s) {
      hashOn.push_back(Hash(s));
    });
    bool same = hashOff.size() == hashOn.size() && !hashOff.empty();
    for (std::size_t i = 0; same && i < hashOff.size(); ++i) {
      same = hashOff[i] == hashOn[i];
    }
    std::printf("    state hashes (domains off) at 4 steps: ");
    for (const std::uint64_t h : hashOff) {
      std::printf("%016llx ", static_cast<unsigned long long>(h));
    }
    std::printf("\n");
    check(
      same,
      "240 steps of the coast (swell, shore waves, a pulse): the same state with domains off and with a one-domain "
      "table"
    );
  }

  // ---- 2 and 3 ----------------------------------------------------------------------------------
  inline void TestBasins(
    SimLab& lab,
    Check& check
  )
  {
    std::printf("2 basins: A at level 25 (x 30..112), B at level 40 (x 148..228), a wall between\n");
    const World w = BasinsWorld();
    Opts o;
    o.damping = 1.0f; // no damping: the volume of a reflecting basin is constant
    Stats a0{}, bEnd{}, aEnd{}, aMid{};
    const auto inA = [](const float x, const float) {
      return x < 130.0f;
    };
    const auto inB = [](const float x, const float) {
      return x >= 130.0f;
    };
    Run(lab, w, o, 270, [](int step) {
      return step == 0 ? Pulse(70.0f, 128.0f, 6.0f, 1.5f, 2.0f, 1.0f)
                       : std::vector<LabSource>{}; // (a crater: no volume)
    }, [](int step) {
      return step == 20 || step == 100 || step == 269;
    }, [&](int step, const std::vector<float>& s) {
      if (step == 20) {
        a0 = Measure(s, inA);
      } else if (step == 100) {
        aMid = Measure(s, inA);
      } else {
        aEnd = Measure(s, inA);
        bEnd = Measure(s, inB);
      }
    });
    check(a0.maxAbs > 0.05, "the pulse is in basin A", a0.maxAbs);
    check(
      bEnd.energy == 0.0 && bEnd.maxAbs == 0.0,
      "basin B stays at exactly zero (energy ratio < 1e-6)",
      bEnd.energy,
      aEnd.energy
    );
    check(aEnd.energy > 1e-3, "basin A is still alive after 3 s (the waves bounce off the walls)", aEnd.energy);
    check(
      std::fabs(a0.volume) <= 1e-3 * a0.absVolume && std::fabs(aMid.volume) <= 1e-3 * aMid.absVolume &&
        std::fabs(aEnd.volume) <= 1e-3 * aEnd.absVolume,
      "the volume of A stays zero (a crater has none; reflection, no leak)",
      aEnd.volume,
      aEnd.absVolume
    );
    check(aEnd.land > 0 && bEnd.land > 0, "the wall and the shores are land", aEnd.land, bEnd.land);

    std::printf("3 touching: A (level 25) and B (level 40) side by side at x = 128 on flat ground\n");
    const World t = TouchingWorld();
    Stats tb{}, ta0{}, taEnd{}, wallEnd{}, openEnd{};
    const auto inTA = [](const float x, const float) {
      return x < 128.0f;
    };
    const auto inTB = [](const float x, const float) {
      return x >= 128.0f;
    };
    Run(lab, t, o, 270, [](int step) {
      return step == 0 ? Pulse(124.0f, 128.0f, 8.0f, 40.0f, 2.0f) : std::vector<LabSource>{}; // its disc reaches into B
    }, [](int step) {
      return step == 5 || step == 269;
    }, [&](int step, const std::vector<float>& s) {
      if (step == 5) {
        ta0 = Measure(s, inTA);
        const Stats b = Measure(s, inTB);
        tb.maxAbs = std::max(tb.maxAbs, b.maxAbs);
      } else {
        taEnd = Measure(s, inTA);
        const Stats b = Measure(s, inTB);
        tb.energy = b.energy;
        tb.maxAbs = std::max(tb.maxAbs, b.maxAbs);
      }
    });
    check(ta0.maxAbs > 0.05, "the pulse is in A", ta0.maxAbs);
    check(
      tb.energy == 0.0 && tb.maxAbs == 0.0,
      "B stays at exactly zero although the disc of the source reaches into it",
      tb.maxAbs,
      tb.energy
    );
    // the border reflects: a crater 4 units from it, 2.5 s later, with the border and (control) without it
    const auto crater = [](int step) {
      return step == 0 ? Pulse(124.0f, 128.0f, 3.0f, 1.5f, 2.0f, 1.0f) : std::vector<LabSource>{};
    };
    Stats bWall{};
    Run(lab, t, o, 225, crater, [](int step) {
      return step == 224;
    }, [&](int, const std::vector<float>& s) {
      wallEnd = Measure(s, inTA);
      bWall = Measure(s, inTB);
    });
    Run(lab, TouchingWorld(false), o, 225, [](int step) {
      return step == 0 ? Pulse(124.0f, 128.0f, 3.0f, 1.5f, 2.0f, 1.0f) : std::vector<LabSource>{};
    }, [](int step) {
      return step == 224;
    }, [&](int, const std::vector<float>& s) {
      openEnd = Measure(s, inTA);
    });
    check(bWall.energy == 0.0, "B stays at exactly zero", bWall.energy);
    check(
      wallEnd.energy > 1.4 * openEnd.energy && std::fabs(wallEnd.volume) <= 2e-2 * wallEnd.absVolume,
      "the border reflects: A keeps its waves (and its zero volume); without the border they run off (control)",
      wallEnd.energy,
      openEnd.energy
    );
  }

  // ---- 4 ----------------------------------------------------------------------------------------
  inline void TestDry(
    SimLab& lab,
    Check& check
  )
  {
    std::printf("4 dry body: a polder of 60 x 60 units at the height of the sea bed, inside the sea\n");
    const World w = PolderWorld();
    Opts o;
    o.shoreWave = 1.0f;
    o.swell = 1.0f;
    o.damping = 1.0f - moho::water::kDamping;
    const auto inPolder = [](const float x, const float z) {
      return x >= 100.0f && x < 160.0f && z >= 100.0f && z < 160.0f;
    };
    const auto outside = [&](const float x, const float z) {
      return !inPolder(x, z) && (x < 90.0f || x >= 170.0f || z < 90.0f || z >= 170.0f);
    };
    Stats polder{}, sea{};
    Stats floodPolder{};
    // a pulse in the sea, one the shader is made to take in the polder (the gate would drop it, see below), two seconds
    const auto sources = [](const int step) {
      std::vector<LabSource> list;
      if (step == 0) {
        list.push_back(LabSource{60.0f, 128.0f, 6.0f, 40.0f, 0.2f, 0.0f, 1.0f, 0.0f});
        list.push_back(LabSource{130.0f, 130.0f, 8.0f, 60.0f, 1.0f, 0.0f, 4.0f, 0.0f});
      }
      return list;
    };
    Run(lab, w, o, 200, sources, [](int step) {
      return step == 199;
    }, [&](int, const std::vector<float>& s) {
      polder = Measure(s, inPolder);
      sea = Measure(s, outside);
    });
    check(
      polder.land == polder.cells && polder.cells > 0, "every cell of the polder is land", polder.land, polder.cells
    );
    check(
      polder.energy == 0.0 && polder.foam == 0.0,
      "no height and no foam in the polder, even for a source made there",
      polder.energy,
      polder.foam
    );
    check(sea.maxAbs > 0.02 && sea.land == 0, "the sea around it is alive and dry nowhere", sea.maxAbs, sea.land);
    Opts flat = o;
    flat.domains = false;
    World single = w;
    single.shore.resize(static_cast<std::size_t>(w.hw) * w.hh * 2U); // (the fields only)
    Run(lab, single, flat, 200, sources, [](int step) {
      return step == 199;
    }, [&](int, const std::vector<float>& s) {
      floodPolder = Measure(s, inPolder);
    });
    check(
      floodPolder.land == 0 && floodPolder.maxAbs > 0.0,
      "(control) without domains the sea floods the polder",
      floodPolder.land,
      floodPolder.maxAbs
    );
    // the gate of the CPU side
    const auto levelAt = [&](const float x, const float z, float& level) {
      return moho::water::LevelAtPlace(true, 25.0f, [&](const float px, const float pz) {
        return LevelOf(w, px, pz);
      }, x, z, level);
    };
    const auto ground = [&](const float x, const float z) {
      return GroundAt(w, x, z);
    };
    check(
      !moho::water::SourceOverWater(130.0f, 130.0f, levelAt, ground) &&
        moho::water::SourceOverWater(60.0f, 128.0f, levelAt, ground),
      "the source gate takes no source in the polder and one in the sea"
    );
  }

  // ---- 5 ----------------------------------------------------------------------------------------
  inline void TestBeach(
    SimLab& lab,
    Check& check,
    std::vector<float>* finalState = nullptr,
    const World* worldOut = nullptr
  )
  {
    (void)worldOut;
    std::printf("5 beach: the contour of each basin's own level, and foam on both beaches\n");
    const World w = BowlsWorld();
    Opts o;
    o.shoreWave = 1.0f;
    o.swell = 1.0f;
    o.damping = 1.0f - moho::water::kDamping;
    std::vector<float> last;
    Stats a{}, b{}, wall{};
    Run(lab, w, o, 360, nullptr, [](int step) {
      return step == 359;
    }, [&](int, const std::vector<float>& s) {
      last = s;
      a = Measure(s, [](const float x, const float) {
        return x >= 33.0f && x <= 123.0f;
      });
      b = Measure(s, [](const float x, const float) {
        return x >= 135.0f && x <= 225.0f;
      });
      wall = Measure(s, [](const float x, const float) {
        return x > 125.0f && x < 133.0f;
      });
    });
    // the contour of a basin in a row: the first and the last water cell
    const auto contour = [&](const float level, const float centre, double& worstLeft, double& worstRight, int& rows) {
      const float d = 20.0f + (level - kMargin - (level - 5.0f)) / 0.25f;
      const float left = centre - d;
      const float right = centre + d;
      worstLeft = worstRight = 0.0;
      rows = 0;
      for (int j = 160; j < 360; j += 8) { // z 80 .. 180, away from the edges of the window
        int first = -1;
        int lastWater = -1;
        for (int i = 0; i < kN; ++i) {
          const float x = CellX(i);
          if (x < centre - 60.0f || x > centre + 60.0f) {
            continue;
          }
          if (last[(static_cast<std::size_t>(j) * kN + i) * 4U + 3U] < 0.5f) {
            if (first < 0) {
              first = i;
            }
            lastWater = i;
          }
        }
        if (first < 0) {
          continue;
        }
        ++rows;
        worstLeft = std::max(worstLeft, std::fabs(static_cast<double>(CellX(first) - 0.5f * kCell - left)));
        worstRight = std::max(worstRight, std::fabs(static_cast<double>(CellX(lastWater) + 0.5f * kCell - right)));
      }
    };
    double al, ar, bl, br;
    int ra, rb;
    contour(25.0f, 78.0f, al, ar, ra);
    contour(40.0f, 180.0f, bl, br, rb);
    check(ra > 10 && rb > 10, "both basins hold water", ra, rb);
    std::printf(
      "    water edge off the contour (units): A left %.2f right %.2f, B left %.2f right %.2f\n", al, ar, bl, br
    );
    check(
      std::max(std::max(al, ar), std::max(bl, br)) <= 0.5,
      "the water edge of each basin is within a cell of its own level's contour",
      std::max(al, ar),
      std::max(bl, br)
    );
    check(a.foamMax > 0.03 && b.foamMax > 0.03, "foam on the beaches of both basins", a.foamMax, b.foamMax);
    check(
      wall.cells > 0 && wall.land == wall.cells && wall.foam == 0.0, "no foam on the wall between", wall.foam, wall.land
    );
    if (finalState != nullptr) {
      *finalState = last;
    }
  }

  // ---- 9 ----------------------------------------------------------------------------------------
  inline void TestGate(
    SimLab& lab,
    Check& check
  )
  {
    std::printf("9 gate: the CPU source gate against the land test of the shader, 10000 random places\n");
    const World w = BowlsWorld();
    Opts o;
    std::vector<float> s;
    Run(lab, w, o, 2, nullptr, [](int step) {
      return step == 1;
    }, [&](int, const std::vector<float>& state) {
      s = state;
    });
    std::uint32_t seed = 12345u;
    const auto random = [&]() {
      seed = seed * 1664525u + 1013904223u;
      return static_cast<float>(seed >> 8) * (1.0f / 16777216.0f);
    };
    const auto levelAt = [&](const float x, const float z, float& level) {
      return moho::water::LevelAtPlace(true, 25.0f, [&](const float px, const float pz) {
        return LevelOf(w, px, pz);
      }, x, z, level);
    };
    const auto ground = [&](const float x, const float z) {
      return GroundAt(w, x, z);
    };
    int mismatches = 0;
    int beyond = 0;
    int waterCount = 0;
    for (int n = 0; n < 10000; ++n) {
      const float x = 34.0f + random() * 190.0f;
      const float z = 34.0f + random() * 190.0f;
      const bool cpu = moho::water::SourceOverWater(x, z, levelAt, ground);
      const int ci = static_cast<int>(x / kCell);
      const int cj = static_cast<int>(z / kCell);
      const bool shader = s[(static_cast<std::size_t>(cj) * kN + ci) * 4U + 3U] < 0.5f;
      waterCount += shader ? 1 : 0;
      if (cpu != shader) {
        ++mismatches;
        // within a cell of the contour: the ground at the corners of the cell straddles the level of its water
        float level = 0.0f;
        const float cx = (static_cast<float>(ci) + 0.5f) * kCell;
        const float cz = (static_cast<float>(cj) + 0.5f) * kCell;
        const bool hasLevel = levelAt(cx, cz, level) || levelAt(x, z, level);
        bool above = false;
        bool below = false;
        for (int c = 0; c < 4; ++c) {
          const float g = ground(cx + ((c & 1) != 0 ? 0.3f : -0.3f), cz + ((c & 2) != 0 ? 0.3f : -0.3f));
          (g > level - kMargin ? above : below) = true;
        }
        const bool dry = !hasLevel || DomainOf(w, x, z) != DomainOf(w, cx, cz); // a block border: one cell either way
        if (!(above && below) && !dry) {
          ++beyond;
        }
      }
    }
    check(beyond == 0, "every mismatch is within one cell of a contour or a block border", mismatches, beyond);
    check(waterCount > 1000 && mismatches < 400, "both are mostly the same", waterCount, mismatches);
  }

} // namespace domains

// runs the domain tests; 0 when all pass
inline int RunDomains(
  const std::string& hlsl
)
{
  domains::Check check;
  // WATERSIMLAB_ONLY=fetch,brute,centre,parity,basins,dry,beach,gate runs a part
  const char* const only = std::getenv("WATERSIMLAB_ONLY");
  const auto wanted = [only](const char* const name) {
    return only == nullptr || std::string(only).find(name) != std::string::npos;
  };
  if (wanted("fetch")) {
    domains::TestFetch(check);
  }
  if (wanted("brute")) {
    domains::TestBrute(check);
  }
  if (wanted("centre")) {
    domains::TestCentre(check);
  }
  domains::SimLab lab;
  if (!lab.Init(hlsl)) {
    return 4;
  }
  if (wanted("parity")) {
    domains::TestParity(lab, check);
  }
  if (wanted("basins")) {
    domains::TestBasins(lab, check);
  }
  if (wanted("dry")) {
    domains::TestDry(lab, check);
  }
  if (wanted("beach")) {
    domains::TestBeach(lab, check);
  }
  if (wanted("gate")) {
    domains::TestGate(lab, check);
  }
  std::printf("  checks: %d ok, %d failed\n", check.ok, check.failed);
  return check.failed == 0 ? 0 : 1;
}
