namespace moho
{
  bool ren_Terrain = true;
  bool ren_Skirt = true;
  bool ren_Water = true;
  bool ren_Reflection = true;
  bool ren_Fx = true;
  bool ren_ErrorCache = true;
  bool fog_DistanceFog = true;
  bool snd_SpewSound = false;
  bool snd_CheckDistance = true;
  bool snd_CheckLOS = true;
  bool debug_movie = false;

  int snd_index = 0;

  float cam_NearZoom = 10.0f;
  float cam_ZoomAmount = 0.05f;
  float cam_NearFOV = 45.0f;
  float cam_FarFOV = 80.0f;
  float cam_FarPitch = 60.0f;
  float cam_SpinSpeed = 1.0f;
  float cam_MinSpinPitch = -89.0f;
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
