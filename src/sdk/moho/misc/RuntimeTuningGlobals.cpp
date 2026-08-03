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
