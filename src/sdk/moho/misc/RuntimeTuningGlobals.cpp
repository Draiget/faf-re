namespace moho
{
  bool ren_Terrain = true;
  bool ren_Skirt = true;
  bool ren_Water = true;
  bool ren_Reflection = true;
  bool ren_SkyDome = true;
  bool ren_Fx = true;
  bool ren_ErrorCache = true;
  bool fog_DistanceFog = true;
  bool snd_SpewSound = false;
  bool snd_CheckDistance = true;
  bool snd_CheckLOS = true;
  bool debug_movie = false;

  // Frame-driver debug toggles read by WRenViewport::RenderAllHeads /
  // WRenViewport::Render. All three live in .bss in the shipped binary
  // (0x010A6416 / 0x010A641C / 0x010A641D), so the image default is false:
  // render normally, filled polygons, every world view.
  bool ren_RenderNothing = false;
  bool ren_ShowWireframe = false;
  bool ren_OnlyFirstView = false;

  // Shadow-map tuning latched by Shadow::Init. Both are initialized in .data in
  // the shipped image: ren_ShadowBlur @0x00F57E54 = 1, ren_ShadowSize
  // @0x00F57E58 = 0x400.
  bool ren_ShadowBlur = true;
  int ren_ShadowSize = 1024;

  // Two more of the same never-defined kind, and the worst placed of the lot.
  // `ren_Shadows` is the first thing WRenViewport::RenderShadows tests
  // (0x007F7D13), and `ren_UnitSilhouette` gates the silhouette pass inside
  // WRenViewport::Render (0x007F95EC) - so every frame read both of them
  // through a /FORCE'd null and faulted before drawing anything.
  bool ren_Shadows = true;                // 0x00F57E53 = 0x01
  bool ren_UnitSilhouette = false;        // 0x010A6422, zero-fill

  // Render/UI/editor toggles that were declared extern all over the tree but
  // never defined anywhere. The link runs with /FORCE, so each one resolved to
  // the image base instead of failing - and the first byte there is 'M' from
  // the MZ header, so every one of these bools read back as true. That is how
  // the frame-time bar HUD came to draw during startup and take an access
  // violation in CD3DPrimBatcher::SetTexture.
  //
  // Every value below is read straight out of ForgedAlliance.exe at the address
  // given. Addresses in the zero-fill tail of .data carry no bytes in the image
  // and therefore start at zero.
  bool ren_Ui = true;                     // 0x00F57DE7 = 0x01
  bool ren_NormalDecals = true;           // 0x00F57DDE = 0x01
  bool ren_Splats = true;                 // 0x00F57DDF = 0x01
  bool ren_GenerateMesh = true;           // 0x00F57DE0 = 0x01
  bool ren_Decals = true;                 // 0x00F57DDD = 0x01
  bool ren_ClipDecals = true;             // 0x00F57B7F = 0x01
  int ren_ClipDecalLevel = 2;             // 0x00F57DB4 = 2
  bool ren_IgnoreDecalLOD = false;        // 0x010A643F, zero-fill
  int ren_DecalFidelity = 0;              // 0x010A6444, zero-fill
  bool ren_bicubicnormals = true;         // 0x00F57DC1 = 0x01
  float ren_ShadowCoeff = 3.0f;           // 0x00F57E00 = 3.0f
  float ren_ShadowLOD = 250.0f;           // 0x00F57E04 = 250.0f
  bool ren_glowingDecals = true;          // 0x00F57DE1 = 0x01
  bool ren_ForceUpdateMinimapTerrain = true; // 0x00F57DE2 = 0x01
  bool ren_Bloom = true;                  // 0x00F57E51 = 0x01
  bool ed_EnableHook = true;              // 0x00F57E55 = 0x01
  bool ren_Oblivion = false;              // 0x010A6417, zero-fill
  bool ren_ShowNormals = false;           // 0x010A643C, zero-fill
  bool ren_DecalOverDraw = false;         // 0x010A6440, zero-fill
  bool ren_ShowFrameTimes = false;        // 0x010A6430, zero-fill
  bool ren_ShowNetworkStats = false;      // 0x010A6431, zero-fill
  bool ren_ShowBandwidthUsage = false;    // 0x010A6432, zero-fill
  bool UI_ShowControlUnderMouse = false;  // 0x010A6423, zero-fill

  int ren_BloomBlurCount = 2;             // 0x00F57E7C = 2
  float ren_BandwidthDisplaySeconds = 10.0f; // 0x00F57E84 = 10.0f
  float ren_BandwidthDisplayKernel = 1.0f;   // 0x00F57E88 = 1.0f

  // Session-beat toggles read by `CWldSession::DoBeat` / `SessionFrame`.
  // `ren_FogOfWar` is the only one with a byte in the image (0x00F57DC3 = 1);
  // the other two sit in the zero-fill tail of .data and therefore start false.
  bool ren_FogOfWar = true;               // 0x00F57DC3 = 0x01
  bool dbg_Metronome = false;             // 0x010A6466, zero-fill
  /// Free-runs the beat drain: the frame loop stops waiting for the tick clock
  /// and consumes every packet the sim has queued.
  bool wld_RunWithTheWind = false;        // 0x010A6467, zero-fill

  int snd_index = 0;

  float cam_NearZoom = 10.0f;
  float cam_NearPitch = 35.0f;
  float cam_ZoomAmount = 0.05f;
  float cam_ZoomSpeedLarge = 8.0f;
  float cam_ZoomSpeedSmall = 1.0f;
  float cam_NearFOV = 45.0f;
  float cam_FarFOV = 80.0f;
  float cam_FarPitch = 60.0f;
  float cam_SpinSpeed = 1.0f;
  float cam_MinSpinPitch = -89.0f;
  // Address: 0x00F57FF0 (?cam_ShakeMult@Moho@@3MA) — per-frame camera-shake scale.
  float cam_ShakeMult = 1.0f;
  // Address: 0x00F57FEC (?cam_PanSpeed@Moho@@3MA) — ground-plane pan speed scale.
  float cam_PanSpeed = 1.0f;
  float cam_EntityBoxExpand = 20.0f;
  float ren_BorderSize = 0.0f;
  float ren_SyncTerrainLOD = 200.0f;
  float ren_FrameTimeSeconds = 1.0f / 30.0f;
  float wld_SkewRateAdjustBase = 1.05f;
  float wld_SkewRateAdjustMax = 2.0f;
  float fog_OffsetMultiplier = 1.0f;
  float ren_ShoreErrorCoeff = 1.0f;
  float ren_DecalAlbedoLodCutoff = 1.0f;
  float ren_DecalNormalLodCutoff = 1.0f;
  float ren_DecalFlatTol = 0.01f;
  float ren_DecalFadeFraction = 0.75f;
  float ren_maxViewError = 1.0f;
} // namespace moho
