# Engine addition (dedicated-server plan WPL.3, WPL.4, WPR.11): the simulation's
# translation units, FAF_SIM_SOURCES: FAF_ENGINE_SOURCES (sources.cmake, which
# must be included first) without the ones that exist only for the client
# (window, render device, UI, audio output, movies, the wx script debugger,
# the user world). The order of what remains is the engine's, so the
# static-init order is the Windows build's.
#
# A source is left out when it matches a _faf_client_only_patterns entry and
# none of the _faf_sim_patterns entries (sim code that lives in a client
# folder). What the sim still references in the files left out is the
# WPL.3/WPL.4 work list; those references are cut by splits, not by adding
# the client files back.

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
  # D3D device resources.
  "^moho/misc/ID3DDeviceResources\\.cpp$"
  # The user world: session, user-side armies, entities and units.
  "^moho/sim/(CWldSession|UserArmy|UserLuaFunctions|UserCommandIssue|UserCommandLuaFunctions|UserStartupRegistrations)\\.cpp$"
  # The user's formation preview (drag orientation, preview instances).
  "^moho/sim/CFormation\\.cpp$"
  # The range-ring extractors (user entities' ranges for moho/render/RangeRenderer).
  "^moho/(misc|collision|ai|unit/core)/(Miscellaneous|Omni|Radar|CounterIntel|Intel|CombinedMilitary|Countermeasure|AirPlatform|Weapon|Range|Sonar)Extractor\\.cpp$"
  "^moho/entity/UserEntity\\.cpp$"
  "^moho/unit/core/UserUnit\\.cpp$"
  # The client's console commands and variables (CConCommand.cpp keeps the console).
  "^moho/console/ClientConCommands\\.cpp$"
  # The user world's vision (what the focus army sees, for drawing).
  "^moho/vision/VisionDB\\.cpp$"
  # The lobby, GPGNet and LAN discovery (the game connection and the
  # replay stream stay).
  "^moho/net/(CLobby|CLobbyTypeInfo|CGpgNetInterface|CDiscoveryService|CDiscoveryServiceTypeInfo)\\.cpp$"
  # The user world's client-manager UI callbacks (the interface's defaults stay).
  "^moho/net/CWldUiInterface\\.cpp$"
  # The user session's listeners (idle units, pause, selection) and its save data.
  "^moho/sim/(IdleUnitSelector|PauseListener|SelectionListener|SSessionSaveDataTypeInfo)\\.cpp$"
  # The front end's session launch, saves and replay recording (replay
  # playback setup is moho/misc/ReplaySessionSetup.cpp).
  "^moho/misc/SessionStartup\\.cpp$")

set(_faf_sim_patterns
  # Decals the sim creates and expires (CDecalBuffer::CleanupTick runs on
  # the sim thread), their reflection and serialisers.
  "^moho/render/(CDecalBuffer|CDecalBufferSerializer|CDecalBufferTypeInfo|CDecalGroup|CDecalHandle|CDecalHandleSerializer|CDecalHandleTypeInfo|CDecalTypes|IDecalGroup|SDecalInfoTypeInfo)\\.cpp$"
  # The base of the sim's debug overlays (moho/debug, RDebugCollision, ...).
  "^moho/render/RDebugOverlay\\.cpp$"
  # Transform and camera geometry the sim computes with (entity transforms,
  # effect culling against the sync filter's cameras).
  "^moho/render/camera/(VTransform|GeomCamera3)\\.cpp$"
  # SFD movie headers (MOV_GetDuration, behind the core Lua set's GetMovieDuration).
  "^moho/movie/sfd/(SfdHeaderParser|SfdHeaderInfo)\\.cpp$")

set(FAF_SIM_SOURCES "")
foreach(_src IN LISTS FAF_ENGINE_SOURCES)
  set(_keep TRUE)
  foreach(_pattern IN LISTS _faf_client_only_patterns)
    if(_src MATCHES "${_pattern}")
      set(_keep FALSE)
      break()
    endif()
  endforeach()
  if(NOT _keep)
    foreach(_pattern IN LISTS _faf_sim_patterns)
      if(_src MATCHES "${_pattern}")
        set(_keep TRUE)
        break()
      endif()
    endforeach()
  endif()
  if(_keep)
    list(APPEND FAF_SIM_SOURCES "${_src}")
  endif()
endforeach()
