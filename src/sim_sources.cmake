# Engine addition (dedicated-server plan WPL.3, WPR.11): the simulation's
# translation units, FAF_SIM_SOURCES: FAF_ENGINE_SOURCES (sources.cmake, which
# must be included first) without the ones that exist only for the client
# (window, render device, UI, audio output, movies, the wx script debugger).
# The order of what remains is the engine's, so the static-init order is the
# Windows build's.
#
# What the sim still references in the files left out is the WPL.3
# unresolved-symbol list; those references are cut by splits (WPL.4), not by
# adding the client files back.

set(FAF_SIM_SOURCES ${FAF_ENGINE_SOURCES})

set(_faf_client_only_patterns
  # Render backends, shader tooling and Effects 11.
  "^gpg/gal/"
  "/FX11/"
  # Render, UI, application shell, movies; the render-side terrain, water
  # and mesh code (the sim's map is moho/sim/STIMap, its blueprints
  # moho/resource).
  "^moho/render/"
  "^moho/ui/"
  "^moho/app/"
  "^moho/movie/"
  "^moho/terrain/"
  "^moho/mesh/"
  # Particle and beam drawing (the particle buffers the sim fills stay).
  "^moho/particles/(BeamRenderHelpers|ParticleRenderBuckets|ParticleRenderWorkItem)\\.cpp$"
  # Audio output (the sim's sound manager and parameters stay).
  "^moho/audio/(AudioEngine|CUserSoundManager|IUserSoundManager|XactClock|SofdecRuntime)\\.cpp$"
  # The wx script debugger's windows.
  "^moho/misc/(ScrDebugWindow|ScrFileCtrl|ScrSourceCtrl|ScrWatchCtrl|ScrGotoDialog)\\.cpp$"
  # D3D device resources; DirectSound and movie startup.
  "^moho/misc/(ID3DDeviceResources|StartupHelpers)\\.cpp$"
  # The user world: session, user-side armies and entities.
  "^moho/sim/(CWldSession|UserArmy)\\.cpp$"
  "^moho/entity/UserEntity\\.cpp$")

foreach(_pattern IN LISTS _faf_client_only_patterns)
  list(FILTER FAF_SIM_SOURCES EXCLUDE REGEX "${_pattern}")
endforeach()
