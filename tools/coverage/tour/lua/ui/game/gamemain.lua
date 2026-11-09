-- faf-re coverage tour (tools/coverage/tour, tests/README.md): appended to FAF's /lua/ui/game/gamemain.lua through the
-- /covtour hook folder (init_tour.lua). While a replay plays in the coverage client it selects units and calls every
-- getter of the user-side objects, moves the camera, builds one of each UI control and runs the console commands.
-- For coverage only: nothing here is compared.
do
    local function Log(text)
        LOG('TOUR: ' .. text)
    end

    local function Try(what, fn, ...)
        local ok, result = pcall(fn, unpack(arg))
        if not ok then
            Log(what .. ' failed: ' .. tostring(result))
        end
        return result
    end

    local GetterPrefixes = { 'Get', 'Is', 'Can', 'Has', 'Should', 'Calc', 'Find', 'Test', 'Count', 'Check' }
    local function IsGetter(name)
        for i = 1, table.getn(GetterPrefixes) do
            local prefix = GetterPrefixes[i]
            if string.sub(name, 1, string.len(prefix)) == prefix then
                return true
            end
        end
        return false
    end

    -- Getters that crash the original game too, left out: ItemList:GetItem(i) indexes the item vector without a
    -- bounds check (0x0079B0C0), so an empty list reads past it; Movie:GetFrameRate() and GetNumFrames() call through
    -- the movie pointer (+0x11C, 0x0079FFA0) of a control with no movie loaded.
    local Skip = {
        itemlist = { GetItem = true },
        movie = 'all', -- FAF's Lua Movie class wraps GetNumFrames in getters of its own
    }

    -- Every getter an object's metatable (or its __index table) holds, without an argument and with 1.
    local function SweepObject(label, object)
        if not object or Skip[label] == 'all' then
            return
        end
        local methods = getmetatable(object)
        if type(methods) == 'table' and type(rawget(methods, '__index')) == 'table' then
            methods = rawget(methods, '__index')
        end
        if type(methods) ~= 'table' then
            Log('sweep ' .. label .. ': no methods')
            return
        end
        local names = {}
        for name, value in methods do
            if type(name) == 'string' and (type(value) == 'cfunction' or type(value) == 'function') and IsGetter(name)
                and not (Skip[label] and Skip[label][name]) then
                table.insert(names, name)
            end
        end
        table.sort(names)
        local failed = 0
        for i = 1, table.getn(names) do
            local fn = methods[names[i]]
            if not pcall(fn, object) then failed = failed + 1 end
            if not pcall(fn, object, 1) then failed = failed + 1 end
        end
        Log('sweep ' .. label .. ': ' .. table.getn(names) .. ' getters, ' .. failed .. ' errors')
    end

    -- The console commands to run: { name, takes a value }. The ones that quit, crash on purpose, pause or step the
    -- sim, reset the device or open a modal window are left out, and so are the ones
    -- that save to the player's Game.prefs (UI_RotateLayout, UI_RotateSkin, UI_SetSkin: a rotated layout stayed in
    -- every later game on this account).
    local Commands = {
        { 'AddBeam', true },
        { 'AddImpulse', true },
        { 'AddLightParticle', true },
        { 'AddSplat', false },
        { 'AI_DebugArmyIndex', true },
        { 'AI_DebugCollision', true },
        { 'AI_DebugIgnorePlayableRect', true },
        { 'ai_FreeBuild', true },
        { 'ai_InstaBuild', true },
        { 'AI_RenderBombDropZone', true },
        { 'AI_RenderDebugAttackVectors', true },
        { 'AI_RenderDebugPlayableRect', true },
        { 'AI_RunOpponentAI', true },
        { 'ai_SteeringAirTolerance', true },
        { 'AirLookAheadMult', true },
        { 'ANI_DumpSkeleton', false },
        { 'BeginLoggingStats', false },
        { 'BlingBling', true },
        { 'cam_DefaultLOD', true },
        { 'cam_HighLOD', true },
        { 'cam_LowLOD', true },
        { 'cam_MediumLOD', true },
        { 'cam_SetLOD', false },
        { 'ClearStats', false },
        { 'CON_Echo', false },
        { 'CON_ListCommands', false },
        { 'con_TestVar', true },
        { 'CopySelectedUnitsToClipboard', false },
        { 'CreateProp', false },
        { 'CreateUnit', false },
        { 'DamageUnit', true },
        { 'dbg', true },
        { 'dbg_Ballistics', true },
        { 'dbg_CollisionBeam', true },
        { 'dbg_EfxBeams', true },
        { 'dbg_Projectile', true },
        { 'dbg_Trail', true },
        { 'Debug_Warn', false },
        { 'DebugAIStatesOff', true },
        { 'DebugAIStatesOn', true },
        { 'DebugClearBuildTemplates', false },
        { 'DebugDumpArmyStats', true },
        { 'DebugGenerateBuildTemplateFromSelection', false },
        { 'DebugMoveCamera', true },
        { 'DebugSetConsumptionActive', true },
        { 'DebugSetConsumptionInActive', true },
        { 'DebugSetPlayableRect', true },
        { 'DebugSetProductionActive', true },
        { 'DebugSetProductionInActive', true },
        { 'DestroySelectedUnits', false },
        { 'DoSimCommand', false },
        { 'dump_Frame', false },
        { 'DumpActiveLoops', false },
        { 'DumpCamera', false },
        { 'DumpPreloadedTextures', false },
        { 'DumpUnits', true },
        { 'efx_AttachEmitter', true },
        { 'efx_NewEmitter', true },
        { 'efx_WaterOffset', true },
        { 'EndLoggingStats', false },
        { 'FindUnit', false },
        { 'GetVersion', false },
        { 'imap_debug', true },
        { 'imap_debug_grid', true },
        { 'imap_debug_grid_army', true },
        { 'imap_debug_grid_type', true },
        { 'imap_debug_path_graph', true },
        { 'IN_BindKey', false },
        { 'IN_DumpKeyBindings', false },
        { 'IN_DumpKeyNames', false },
        { 'IN_SetKeyName', false },
        { 'IssueCommand', false },
        { 'KillSelectedUnits', false },
        { 'Log', false },
        { 'LUA', false },
        { 'LUADOC', false },
        { 'mesh_Rebatch', false },
        { 'NeedRefuelThresholdRatio', true },
        { 'NeedRepairThresholdRatio', true },
        { 'net_AckDelay', true },
        { 'net_CompressionMethod', true },
        { 'net_DebugLevel', true },
        { 'net_LogPackets', true },
        { 'net_MaxBacklog', true },
        { 'net_MaxResendDelay', true },
        { 'net_MaxSendRate', true },
        { 'net_MinResendDelay', true },
        { 'net_ResendDelayBias', true },
        { 'net_ResendPingMultiplier', true },
        { 'net_SendDelay', true },
        { 'NoDamage', true },
        { 'path_ArmyBudget', true },
        { 'path_BackgroundBudget', true },
        { 'path_BackgroundUpdate', true },
        { 'path_GeneratePreview', true },
        { 'path_MaxInstantWorkUnits', true },
        { 'path_TimeoutPreview', true },
        { 'path_UnreachableTimeoutSearchSteps', true },
        { 'PathDebug', false },
        { 'PrintStats', false },
        { 'ProcessInfoPair', false },
        { 'RandomElevationOffset', true },
        { 'recon_debug', true },
        { 'ReconFlush', true },
        { 'ren_AoFadeEnd', true },
        { 'ren_AoIntensity', true },
        { 'ren_AoRadius', true },
        { 'ren_Beams', true },
        { 'ren_InfoDump', false },
        { 'ren_MapBorderAdd', false },
        { 'ren_MapBorderClear', false },
        { 'ren_MipSkipLevels', false },
        { 'ren_ShowSkeletons', false },
        { 'ren_Steering', true },
        { 'RenameUnit', false },
        { 'SallyShears', true },
        { 'SC_CameraScaleLOD', false },
        { 'ScenarioMethod', true },
        { 'SetArmyColor', true },
        { 'SetFocusArmy', false },
        { 'ShowArmyStats', false },
        { 'ShowRaisedPlatforms', true },
        { 'ShowStats', false },
        { 'sim_TestFunc', true },
        { 'sim_TestVar', true },
        { 'sim_TestVarBool', true },
        { 'sim_TestVarFloat', true },
        { 'sim_TestVarStr', true },
        { 'sim_TestVarUByte', true },
        { 'SimLog', true },
        { 'SimLua', true },
        { 'SimWarn', true },
        { 'SkipUIChecks', false },
        { 'TeleportSelectedUnits', false },
        { 'timestamp', false },
        { 'TrackStats', true },
        { 'tree_AccelFactor', true },
        { 'tree_DampFactor', true },
        { 'tree_SpringFactor', true },
        { 'tree_UprootFactor', true },
        { 'UI_ApplySelectionSet', false },
        { 'UI_DumpControls', false },
        { 'UI_DumpControlsUnderCursor', false },
        { 'UI_ExpandCurrentSelection', false },
        { 'UI_Lua', false },
        { 'UI_MakeSelectionSet', false },
        { 'UI_ResetView', false },
        { 'UI_SelectByCategory', false },
        { 'UI_ToggleGamePanels', false },
        { 'UI_TrackUnit', false },
        { 'WeaponTerrainBlockageTest', true },
        { 'wld_ClientDebugDump', false },
        { 'ZeroExtraStorage', true },
    }

    local function RunCommands()
        for i = 1, table.getn(Commands) do
            local name = Commands[i][1]
            Try(name, ConExecute, name)
            if Commands[i][2] then
                Try(name .. ' 1', ConExecute, name .. ' 1')
                WaitSeconds(0.1)
                Try(name .. ' 0', ConExecute, name .. ' 0')
            end
            WaitSeconds(0.02)
        end
        Log('commands done: ' .. table.getn(Commands))
    end

    local function CameraTour()
        local camera = GetCamera('WorldCamera')
        if not camera then
            Log('no world camera')
            return
        end
        SweepObject('camera', camera)
        Try('zoom', camera.SetZoom, camera, 40, 0.5)
        WaitSeconds(1)
        Try('spin', camera.Spin, camera, 1, 0.3)
        WaitSeconds(1)
        Try('hold', camera.HoldRotation, camera)
        Try('revert', camera.RevertRotation, camera)
        local settings = Try('SaveSettings', camera.SaveSettings, camera)
        Try('reset', camera.Reset, camera)
        WaitSeconds(1)
        if settings then
            Try('RestoreSettings', camera.RestoreSettings, camera, settings)
        end
        Try('EnableEaseInOut', camera.EnableEaseInOut, camera)
        Try('UseGameClock', camera.UseGameClock, camera)
        Try('UseSystemClock', camera.UseSystemClock, camera)
    end

    local function UnitTour()
        -- A replay starts as an observer, and category selection only takes the focus army's own units.
        Try('focus army', ConExecute, 'SetFocusArmy 0')
        WaitSeconds(1)
        Try('select all', UISelectionByCategory, 'ALLUNITS', false, false, false, false)
        WaitSeconds(1)
        local units = GetSelectedUnits()
        if not units then
            Log('nothing selected')
            return
        end
        Log('selected ' .. table.getn(units))
        for i = 1, math.min(6, table.getn(units)) do
            SweepObject('user unit ' .. i, units[i])
        end
        Try('select land', UISelectionByCategory, 'LAND', false, false, false, false)
        WaitSeconds(2)
        Try('select air', UISelectionByCategory, 'AIR', false, false, false, false)
        WaitSeconds(2)
        Try('select structures', UISelectionByCategory, 'STRUCTURE', false, false, false, false)
        WaitSeconds(2)
        Try('select none', SelectUnits, {})
    end

    -- One of each Maui control on the top frame, its getters swept, then destroyed.
    -- Methods the control fuzz leaves out: they end the control, take the input focus for good, or are callbacks the
    -- engine calls itself.
    local ControlFuzzSkip = {
        Destroy = true, OnDestroy = true, AcquireKeyboardFocus = true, AbandonKeyboardFocus = true, AcquireFocus = true,
        SetNeedsFrameUpdate = true, OnFrame = true, HandleEvent = true, OnKeyboardFocusChange = true,
        -- ItemList:GetItem and the movie getters crash the original game the same way (see Skip above).
        GetItem = true, GetFrameRate = true, GetNumFrames = true,
    }

    -- Every method of a control (the engine's and FAF's Lua class's) with each argument pattern: nothing, 1, a
    -- string, true, two numbers, the parent control, an empty table. The wrong patterns stop at the argument checks.
    local function FuzzControl(label, control, parent)
        if Skip[label] == 'all' then
            return
        end
        local methods = getmetatable(control)
        if type(methods) == 'table' and type(rawget(methods, '__index')) == 'table' then
            methods = rawget(methods, '__index')
        end
        if type(methods) ~= 'table' then
            return
        end
        local names = {}
        for name, value in methods do
            if type(name) == 'string' and (type(value) == 'cfunction' or type(value) == 'function')
                and not ControlFuzzSkip[name] then
                table.insert(names, name)
            end
        end
        table.sort(names)
        local calls = 0
        local failed = 0
        for i = 1, table.getn(names) do
            local fn = methods[names[i]]
            local patterns = { {}, { 1 }, { 'zoo' }, { true }, { 1, 1 }, { parent }, { {} } }
            for p = 1, table.getn(patterns) do
                local args = patterns[p]
                local ok
                if table.getn(args) == 0 then
                    ok = pcall(fn, control)
                elseif table.getn(args) == 1 then
                    ok = pcall(fn, control, args[1])
                else
                    ok = pcall(fn, control, args[1], args[2])
                end
                calls = calls + 1
                if not ok then failed = failed + 1 end
            end
        end
        Log('fuzz ' .. label .. ': ' .. calls .. ' calls, ' .. failed .. ' errors')
    end

    local function ControlTour()
        local parent = GetFrame(0)
        local made = {}
        local function Make(label, path, class, a)
            local ok, module = pcall(import, path)
            if not ok or not module or not rawget(module, class) then
                Log('control ' .. label .. ': no class')
                return
            end
            local control = Try('make ' .. label, module[class], parent, a)
            if control then
                SweepObject(label, control)
                FuzzControl(label, control, parent)
                table.insert(made, control)
            end
        end
        Make('bitmap', '/lua/maui/bitmap.lua', 'Bitmap')
        Make('text', '/lua/maui/text.lua', 'Text')
        Make('edit', '/lua/maui/edit.lua', 'Edit')
        Make('itemlist', '/lua/maui/itemlist.lua', 'ItemList')
        Make('group', '/lua/maui/group.lua', 'Group')
        Make('histogram', '/lua/maui/histogram.lua', 'Histogram')
        Make('movie', '/lua/maui/movie.lua', 'Movie')
        Make('border', '/lua/maui/border.lua', 'Border')
        Make('scrollbar', '/lua/maui/scrollbar.lua', 'Scrollbar', 'Vertical')
        WaitSeconds(1)
        for i = 1, table.getn(made) do
            Try('destroy', made[i].Destroy, made[i])
        end
    end

    -- Every global getter the engine registers in the user Lua, without an argument and with 1.
    local function SweepGlobals()
        local globals = getfenv(0)
        local names = {}
        for name, value in globals do
            if type(name) == 'string' and type(value) == 'cfunction' and IsGetter(name) then
                table.insert(names, name)
            end
        end
        table.sort(names)
        local failed = 0
        for i = 1, table.getn(names) do
            local fn = globals[names[i]]
            if not pcall(fn) then failed = failed + 1 end
            if not pcall(fn, 1) then failed = failed + 1 end
        end
        Log('sweep globals: ' .. table.getn(names) .. ' getters, ' .. failed .. ' errors')
    end

    -- The second tour (/tourvars on the command line): every console variable the first leaves out, set to 1 and to 0
    -- and then left at its end value (0 for debug and display switches, else 1). Left out: telemetry (it would send),
    -- worker counts, sim debug delays and desync tests, speed and replay controls, read-only values, and
    -- ren_ShowBandwidthUsage, which in a replay calls through the absent net connector (the original game too: 0x007F445B
    -- calls the connector's vtable unchecked), and ren_ShowDirtyTerrain, which draws with the terrain's camera
    -- before the terrain has one (0x00801EE0 uses [terrain+0x28] unchecked). (ren_UnitSilhouette crashed this engine, not
    -- the original, until 00cb00606: the pass ran after the world-view loop.)
    local Vars = {
        { 'UI_RenProectileTrailWidth', 1 },
        { 'UI_RenProjectileArcs', 1 },
        { 'UI_RenProjectileArcsSampleInterval', 1 },
        { 'UI_RenProjectileGlow', 1 },
        { 'UI_RenProjectileGlowMax', 1 },
        { 'UI_RenProjectileGlowMin', 1 },
        { 'UI_RenProjectileGlowPeriod', 1 },
        { 'UI_RenProjectileIcons', 1 },
        { 'UI_RenProjectileTrailColor', 1 },
        { 'UI_RenResources', 1 },
        { 'UI_ResourceLODCutoff', 1 },
        { 'UI_SelectAnything', 0 },
        { 'UI_ShowControlUnderMouse', 0 },
        { 'UI_StrategicProjectileLOD', 1 },
        { 'UI_forceWeaponsToYellow', 1 },
        { 'ai_InitialEnergyCurrency', 1 },
        { 'ai_InitialEnergyCurrencyMax', 1 },
        { 'ai_InitialMassCurrency', 1 },
        { 'ai_InitialMassCurrencyMax', 1 },
        { 'cam_DefaultMiniLOD', 1 },
        { 'cam_EntityBoxExpand', 1 },
        { 'cam_FarFOV', 1 },
        { 'cam_FarPitch', 1 },
        { 'cam_Free', 1 },
        { 'cam_FreeClampFocus', 1 },
        { 'cam_MinSpinPitch', 1 },
        { 'cam_NearFOV', 1 },
        { 'cam_NearPitch', 1 },
        { 'cam_NearZoom', 1 },
        { 'cam_PanSpeed', 1 },
        { 'cam_ShakeMult', 1 },
        { 'cam_SpinSpeed', 1 },
        { 'cam_TrackProjectileTimeout', 1 },
        { 'cam_ZoomAmount', 1 },
        { 'cam_ZoomSpeedLarge', 1 },
        { 'cam_ZoomSpeedSmall', 1 },
        { 'con_TestVarBool', 0 },
        { 'con_TestVarFloat', 0 },
        { 'con_TestVarStr', 0 },
        { 'con_TestVarUByte', 0 },
        { 'd3d_ForceSoftwareVP', 1 },
        { 'd3d_NoPureDevice', 1 },
        { 'd3d_PipelineCache', 1 },
        { 'd3d_PlacedResources', 1 },
        { 'd3d_SharedBuffers', 1 },
        { 'd3d_UploadIdleMB', 1 },
        { 'd3d_WindowsCursor', 1 },
        { 'dbg_Metronome', 1 },
        { 'debug_movie', 0 },
        { 'dump_Rate', 0 },
        { 'dump_outputFrameNumber', 0 },
        { 'efx_ParticleWaterSurface', 1 },
        { 'efx_WaveCutoff', 1 },
        { 'fog_DistanceFog', 1 },
        { 'fog_OffsetMultiplier', 1 },
        { 'lob_IgnoreNames', 0 },
        { 'lua_HookProbeCache', 1 },
        { 'lua_SessionSharedBlueprints', 1 },
        { 'mem_InlineTransformCopy', 1 },
        { 'net_AdaptiveLagMax', 1 },
        { 'net_CheckOrderStreams', 1 },
        { 'net_FastAckDelay', 1 },
        { 'net_FastResendPings', 1 },
        { 'net_FastRetransmit', 1 },
        { 'net_InEngineLinks', 1 },
        { 'net_LobbyPeerFeatures', 1 },
        { 'net_LogBeatWaitMs', 0 },
        { 'net_LogShownBeatMs', 0 },
        { 'net_LogTraffic', 0 },
        { 'net_NativeNet', 1 },
        { 'net_NativeNetEncrypt', 1 },
        { 'net_NativeNetRedundancy', 1 },
        { 'net_NativeNetWebRtc', 1 },
        { 'net_PeerFeatures', 1 },
        { 'net_RejoinAccept', 1 },
        { 'net_RejoinFastSave', 1 },
        { 'net_RejoinKeyframes', 1 },
        { 'net_RejoinSendRate', 1 },
        { 'net_RejoinWindow', 1 },
        { 'net_RejoinZstd', 1 },
        { 'net_ShowPanel', 0 },
        { 'net_SocketRecvBuffer', 1 },
        { 'net_SocketSendBuffer', 1 },
        { 'net_TrayIcon', 1 },
        { 'range_Fill', 1 },
        { 'range_InnerThicknessCoeff', 1 },
        { 'range_OuterThicknessCoeff', 1 },
        { 'range_RenderBuild', 1 },
        { 'range_RenderHighlighted', 1 },
        { 'range_RenderHoveredAttack', 1 },
        { 'range_RenderReclaimAtCursor', 1 },
        { 'range_RenderSelected', 1 },
        { 'range_RenderSelectedAtCursor', 1 },
        { 'range_StencilFlush', 1 },
        { 'range_ViewCull', 1 },
        { 'ren_Ao', 1 },
        { 'ren_AoBias', 1 },
        { 'ren_AoContact', 1 },
        { 'ren_AoContactLength', 1 },
        { 'ren_AoFadeStart', 1 },
        { 'ren_BackgroundShaders', 1 },
        { 'ren_BandwidthDisplayKernel', 1 },
        { 'ren_BandwidthDisplaySeconds', 1 },
        { 'ren_BgLowerBound', 1 },
        { 'ren_Bloom', 1 },
        { 'ren_BloomBlurCount', 1 },
        { 'ren_BloomBlurKernelScale', 1 },
        { 'ren_BloomGlowCopyScale', 1 },
        { 'ren_BloomWide', 1 },
        { 'ren_BloomWideThreshold', 1 },
        { 'ren_BorderSize', 1 },
        { 'ren_BuildGhostsPerBeat', 1 },
        { 'ren_CacheFogFootprint', 1 },
        { 'ren_ClipDecalLevel', 1 },
        { 'ren_ClipDecals', 1 },
        { 'ren_Clutter', 1 },
        { 'ren_ClutterRadius', 1 },
        { 'ren_DdsDirectLoad', 1 },
        { 'ren_DecalAlbedoLodCutoff', 1 },
        { 'ren_DecalFadeFraction', 1 },
        { 'ren_DecalFidelity', 1 },
        { 'ren_DecalFlatTol', 1 },
        { 'ren_DecalNormalLodCutoff', 1 },
        { 'ren_DecalOverDraw', 1 },
        { 'ren_Decals', 1 },
        { 'ren_DirectPaint', 1 },
        { 'ren_EffectFastScan', 1 },
        { 'ren_ErrorCache', 1 },
        { 'ren_FogIntensity', 1 },
        { 'ren_FogOfWar', 1 },
        { 'ren_ForceUpdateMinimapTerrain', 0 },
        { 'ren_FrameTimeSeconds', 1 },
        { 'ren_FrustumCacheLodInterval', 1 },
        { 'ren_FrustumCacheLodUnits', 1 },
        { 'ren_Fx', 1 },
        { 'ren_Fxaa', 1 },
        { 'ren_GenerateMesh', 1 },
        { 'ren_GlyphBitmapRead', 1 },
        { 'ren_GlyphCache', 1 },
        { 'ren_GpuFog', 1 },
        { 'ren_GpuFontCook', 1 },
        { 'ren_GpuFontCookCompare', 1 },
        { 'ren_GpuIconClassify', 1 },
        { 'ren_GpuIcons', 1 },
        { 'ren_GpuProjectileIcons', 1 },
        { 'ren_GpuRanges', 1 },
        { 'ren_GpuSelectBrackets', 1 },
        { 'ren_GpuShapes', 1 },
        { 'ren_GpuText', 1 },
        { 'ren_GpuUiQuads', 1 },
        { 'ren_Grade', 1 },
        { 'ren_GradeContrast', 1 },
        { 'ren_GradeVibrance', 1 },
        { 'ren_HideSecondary', 0 },
        { 'ren_IgnoreDecalLOD', 1 },
        { 'ren_LargeParticlePools', 1 },
        { 'ren_LockedRangeOnly', 1 },
        { 'ren_MeshDissolve', 1 },
        { 'ren_MeshDissolveCutoff', 1 },
        { 'ren_MeshPackedVertices', 1 },
        { 'ren_MeshPaletteUsedOnly', 1 },
        { 'ren_MeshPoseStill', 1 },
        { 'ren_MeshSkinned', 1 },
        { 'ren_MeshStatic', 1 },
        { 'ren_MinimapDebugOverlays', 0 },
        { 'ren_MinimapRanges', 1 },
        { 'ren_ModFonts', 1 },
        { 'ren_MsdfText', 1 },
        { 'ren_MsdfTextMinSize', 1 },
        { 'ren_NewFogUpdate', 1 },
        { 'ren_NewPipeline', 1 },
        { 'ren_NormalDecals', 1 },
        { 'ren_NormalMapOnLoader', 1 },
        { 'ren_Oblivion', 0 },
        { 'ren_OnlyFirstView', 0 },
        { 'ren_ParallelCull', 1 },
        { 'ren_ParticleBatch', 1 },
        { 'ren_ParticleKeyShortcut', 1 },
        { 'ren_ParticleLinearUpload', 1 },
        { 'ren_PipelineMemo', 1 },
        { 'ren_PlayableBoundary', 1 },
        { 'ren_PrepareDeviceEarly', 1 },
        { 'ren_PrepareDuringLoading', 1 },
        { 'ren_Ranges', 1 },
        { 'ren_Reflection', 1 },
        { 'ren_Refraction', 1 },
        { 'ren_RegenShore', 1 },
        { 'ren_ReleaseBufferCopies', 1 },
        { 'ren_RenderNothing', 0 },
        { 'ren_Select', 1 },
        { 'ren_SelectBoxes', 1 },
        { 'ren_SelectBracketMinPixelSize', 1 },
        { 'ren_SelectBracketSize', 1 },
        { 'ren_SelectionHeightFudge', 1 },
        { 'ren_SelectionSizeFudge', 1 },
        { 'ren_ShadowBias', 1 },
        { 'ren_ShadowBlur', 1 },
        { 'ren_ShadowCascadeSplit', 1 },
        { 'ren_ShadowCascades', 1 },
        { 'ren_ShadowCoeff', 1 },
        { 'ren_ShadowLOD', 1 },
        { 'ren_ShadowSize', 1 },
        { 'ren_ShadowStable', 1 },
        { 'ren_ShadowVolumeCache', 1 },
        { 'ren_Shadows', 1 },
        { 'ren_Sharpen', 1 },
        { 'ren_ShoreErrorCoeff', 1 },
        { 'ren_Shoreline', 1 },
        { 'ren_ShorelineCutoff', 1 },
        { 'ren_ShorelineMemo', 1 },
        { 'ren_ShowBoneNames', 0 },
        { 'ren_ShowFrameTimes', 0 },
        { 'ren_ShowNetworkStats', 0 },
        { 'ren_ShowNormals', 0 },
        { 'ren_ShowWireframe', 0 },
        { 'ren_Skirt', 1 },
        { 'ren_SkyDome', 1 },
        { 'ren_SplatAtlasFix', 1 },
        { 'ren_SplatBudgetTier', 1 },
        { 'ren_Splats', 1 },
        { 'ren_SyncTerrainLOD', 1 },
        { 'ren_TTerrainGlow', 1 },
        { 'ren_TeamColorLookupCount', 1 },
        { 'ren_TechniqueMemo', 1 },
        { 'ren_Terrain', 1 },
        { 'ren_TerrainGpuBuffers', 1 },
        { 'ren_TerrainShadows', 1 },
        { 'ren_TerrainTessellation', 1 },
        { 'ren_TextureAtlasCache', 1 },
        { 'ren_TextureDecodeCache', 1 },
        { 'ren_Trees', 1 },
        { 'ren_Ui', 1 },
        { 'ren_UnitSelectionScale', 1 },
        { 'ren_UnitSilhouette', 1 },
        { 'ren_UsedTextureTable', 1 },
        { 'ren_ViewError', 1 },
        { 'ren_VulkanDynamicConstants', 1 },
        { 'ren_VulkanPreciseBarriers', 1 },
        { 'ren_VulkanScaledPresent', 1 },
        { 'ren_Water', 1 },
        { 'ren_WorldBorder', 1 },
        { 'ren_bicubicnormals', 1 },
        { 'ren_fog', 1 },
        { 'ren_glowingDecals', 1 },
        { 'res_AfterPrefetchDelay', 1 },
        { 'res_CacheFileLookups', 1 },
        { 'res_EnablePrefetching', 1 },
        { 'res_EnumOrderFuzz', 1 },
        { 'res_LowerInPlace', 1 },
        { 'res_PrecompileScripts', 1 },
        { 'res_PrefetcherActivityDelay', 1 },
        { 'res_ScriptChunkCache', 1 },
        { 'res_SpewLoadSpam', 0 },
        { 'res_UiScriptChunkCache', 1 },
        { 'res_ZipKeepData', 1 },
        { 'res_ZipKeepOpen', 1 },
        { 'res_ZipNameCache', 1 },
        { 'rule_BlueprintReloadDelay', 1 },
        { 'rule_Paranoid', 0 },
        { 'rule_ReleaseScriptBlueprints', 1 },
        { 'save_FastKeyframeArchive', 1 },
        { 'sc_FrameTimeCarry', 1 },
        { 'sc_FrameTimeClamp', 1 },
        { 'sim_BlueprintCopyDirect', 1 },
        { 'sim_BlueprintFieldShortcuts', 1 },
        { 'sim_BlueprintLookupFast', 1 },
        { 'sim_BlueprintNameCache', 1 },
        { 'sim_BlueprintTableShortcuts', 1 },
        { 'sim_CacheScriptModuleLookups', 1 },
        { 'sim_CategoryLookupCache', 1 },
        { 'sim_CollectPrefetch', 1 },
        { 'sim_DebugCheats', 0 },
        { 'sim_DesyncRecorder', 1 },
        { 'sim_DesyncRecorderMB', 1 },
        { 'sim_ExemptCheckInPlace', 1 },
        { 'sim_FafGameVersion', 1 },
        { 'sim_FastBoneUpdates', 1 },
        { 'sim_FastEconStats', 1 },
        { 'sim_FixAimLeadOncePerTick', 1 },
        { 'sim_FixProjectileImpactBelowZero', 1 },
        { 'sim_FixProjectileMapEdgeCollision', 1 },
        { 'sim_FixRefuelUndockAboveMaxHealth', 1 },
        { 'sim_FixShieldRepair', 1 },
        { 'sim_FixTargetPointCollisionCentre', 1 },
        { 'sim_FixWaterBodies', 1 },
        { 'sim_GatherLargeBuffers', 1 },
        { 'sim_GatherPrefetch', 1 },
        { 'sim_GatherReserve', 1 },
        { 'sim_IntelRasterRows', 1 },
        { 'sim_IntelSameCellMove', 1 },
        { 'sim_Interlocked', 1 },
        { 'sim_IssueThreadDebugLevel', 0 },
        { 'sim_JobStreamPrefetch', 1 },
        { 'sim_JobStreamPublishBatch', 1 },
        { 'sim_KeepAllLogFiles', 0 },
        { 'sim_LeadOnSchedule', 1 },
        { 'sim_LocalLead', 1 },
        { 'sim_LogSize', 0 },
        { 'sim_ParallelEffects', 1 },
        { 'sim_ParallelEffectsMin', 1 },
        { 'sim_ParallelEntitySync', 1 },
        { 'sim_ParallelPose', 1 },
        { 'sim_ParallelPoseQuietAim', 1 },
        { 'sim_ParallelRecon', 1 },
        { 'sim_ParallelSync', 1 },
        { 'sim_ParallelSyncHeap', 1 },
        { 'sim_PathTraverseCache', 1 },
        { 'sim_ReconBlipHandleAssign', 1 },
        { 'sim_ReconBlipIndex', 1 },
        { 'sim_ReconFlatWalk', 1 },
        { 'sim_ReconProbeCellCache', 1 },
        { 'sim_ReconQueryCache', 1 },
        { 'sim_ReconSkipSelfAlly', 1 },
        { 'sim_RecyclePose', 1 },
        { 'sim_ReplayLead', 1 },
        { 'sim_ReportCheats', 1 },
        { 'sim_ShowDamage', 0 },
        { 'sim_SquadUnitSearch', 1 },
        { 'sim_SweptProbeEarlyOut', 1 },
        { 'sim_SyncFillsOneDispatch', 1 },
        { 'sim_SyncInPlace', 1 },
        { 'snd_CheckDistance', 1 },
        { 'snd_CheckLOS', 1 },
        { 'snd_CreateEarly', 1 },
        { 'snd_ExtraDoWorkCalls', 1 },
        { 'snd_ReadAhead', 1 },
        { 'snd_SpewSound', 0 },
        { 'ui_AlwaysRenderStrategicIcons', 1 },
        { 'ui_ArrowKeysScrollView', 1 },
        { 'ui_BuildPlaceTarmacAlpha', 1 },
        { 'ui_CommandClickScale', 1 },
        { 'ui_CommandGraphMaxNodeUnits', 1 },
        { 'ui_CurveSegments', 1 },
        { 'ui_CurveSmoothness', 1 },
        { 'ui_CustomNameFontSize', 1 },
        { 'ui_CutsomNameFont', 1 },
        { 'ui_DebugAltClick', 0 },
        { 'ui_DepositIconScale', 1 },
        { 'ui_DisableCursorFixing', 0 },
        { 'ui_DragSelect2D', 1 },
        { 'ui_DrawPathPreview', 1 },
        { 'ui_ExtractSnapTolerance', 1 },
        { 'ui_FootprintMinThickness', 1 },
        { 'ui_ForceLifbarsOnEnemy', 1 },
        { 'ui_FuelEmptyBlinkRate', 1 },
        { 'ui_IconRecords', 1 },
        { 'ui_IdleGC', 1 },
        { 'ui_KeyboardPanAccelerateMultiplier', 1 },
        { 'ui_KeyboardPanSpeed', 1 },
        { 'ui_KeyboardRotateAccelerateMultiplier', 1 },
        { 'ui_KeyboardRotateSpeed', 1 },
        { 'ui_LifeBarBadCutoff', 1 },
        { 'ui_LifeBarGoodCutoff', 1 },
        { 'ui_LifebarLOD', 1 },
        { 'ui_LifebarOffset', 1 },
        { 'ui_LifebarWidth', 1 },
        { 'ui_MaxExtractSnapPixels', 1 },
        { 'ui_MaxTextLOD', 1 },
        { 'ui_MaxWaypointSize', 1 },
        { 'ui_MinExtractSnapPixels', 1 },
        { 'ui_MinWaypointSize', 1 },
        { 'ui_NisRenderIcons', 1 },
        { 'ui_ParallelIcons', 1 },
        { 'ui_ParallelMark', 1 },
        { 'ui_ParallelSweep', 1 },
        { 'ui_PathPreview', 1 },
        { 'ui_PathSmoothness', 1 },
        { 'ui_ProjectileIconScale', 1 },
        { 'ui_RenderCustomNames', 1 },
        { 'ui_RenderIcons', 1 },
        { 'ui_RenderSelectionSetNames', 1 },
        { 'ui_RenderUnitBars', 1 },
        { 'ui_ScreenEdgeScrollView', 1 },
        { 'ui_SelectTolerance', 1 },
        { 'ui_StrategicIconBlinkDuration', 1 },
        { 'ui_StrategicIconBlinkRate', 1 },
        { 'ui_StrategicIconScale', 1 },
        { 'ui_WaypointLineScale', 1 },
        { 'ui_WindowedAlwaysShowsCursor', 0 },
        { 'ui_fuelbarHeight', 1 },
        { 'ui_lifebarHeight', 1 },
        { 'wld_EarlyCommandLineSession', 1 },
        { 'wld_FrameClock', 1 },
        { 'wld_FrameClockNetwork', 1 },
        { 'wld_FrameClockOpening', 1 },
        { 'wld_LoadMapEarly', 1 },
        { 'wld_ParallelSync', 1 },
        { 'wld_PreciseSharedStart', 1 },
        { 'wld_ReadyAfterFirstFrame', 1 },
        { 'wld_SkewCorrection', 1 },
        { 'wld_SkewLog', 0 },
        { 'wld_SkewMaxLag', 1 },
        { 'wld_SkewRateAdjustBase', 1 },
        { 'wld_SkewRateAdjustMax', 1 },
        { 'wld_StartSimEarly', 1 },
        { 'wld_VisionChainHints', 1 },
        { 'wld_VisionRepeatInsert', 1 },
    }

    local function VarTour()
        for level = 0, 2 do
            Try('graphics_Fidelity', ConExecute, 'graphics_Fidelity ' .. level)
            Try('shadow_Fidelity', ConExecute, 'shadow_Fidelity ' .. level)
            WaitSeconds(2)
        end
        for i = 1, table.getn(Vars) do
            local name = Vars[i][1]
            Log('var ' .. name)
            Try(name, ConExecute, name)
            Try(name .. ' 1', ConExecute, name .. ' 1')
            WaitSeconds(0.05)
            Try(name .. ' 0', ConExecute, name .. ' 0')
            WaitSeconds(0.05)
            Try(name .. ' end', ConExecute, name .. ' ' .. Vars[i][2])
        end
        Log('vars done: ' .. table.getn(Vars))
    end

    -- The live tour (/tourlive, in a game rather than a replay): orders through the user-side command functions, queued
    -- so the command graph has queues to draw, a factory build order, the dock command and the zoom calls.
    local LiveCommands = {
        'UNITCOMMAND_Move', 'UNITCOMMAND_Attack', 'UNITCOMMAND_AggressiveMove', 'UNITCOMMAND_Patrol',
        'UNITCOMMAND_Guard', 'UNITCOMMAND_Reclaim', 'UNITCOMMAND_Repair', 'UNITCOMMAND_Capture', 'UNITCOMMAND_Stop',
        'UNITCOMMAND_Dive', 'UNITCOMMAND_Pause', 'UNITCOMMAND_Upgrade', 'UNITCOMMAND_Script', 'UNITCOMMAND_Ferry',
        'UNITCOMMAND_FormMove', 'UNITCOMMAND_Tactical', 'UNITCOMMAND_Nuke', 'UNITCOMMAND_TransportLoadUnits',
        'UNITCOMMAND_TransportUnloadUnits', 'UNITCOMMAND_Sacrifice', 'UNITCOMMAND_Overcharge',
        'Move', 'Stop', 'Attack', 'Patrol',
    }

    local function LiveTour()
        Try('select all', UISelectionByCategory, 'ALLUNITS', false, false, false, false)
        WaitSeconds(1)
        local units = GetSelectedUnits() or {}
        Log('live: ' .. table.getn(units) .. ' units')
        for i = 1, table.getn(LiveCommands) do
            local command = LiveCommands[i]
            Try('IssueUnitCommand ' .. command, IssueUnitCommand, units, command, nil, false)
            Try('IssueCommand ' .. command, IssueCommand, command, nil, false)
            WaitSeconds(0.2)
        end
        -- A Lua dragger makes the session's command graph (CMauiLuaDragger takes GetCommandGraph(true)); held while
        -- the queued orders above are pending, the graph builds and updates their nodes. (Drawing it needs a real
        -- Shift key on a foreground window, which the tour leaves alone.)
        local ok, draggerModule = pcall(import, '/lua/maui/dragger.lua')
        local dragger = ok and draggerModule and rawget(draggerModule, 'Dragger') and Try('Dragger', draggerModule.Dragger)
        WaitSeconds(10)
        if dragger then
            Try('dragger destroy', dragger.Destroy, dragger)
        end
        -- Command mode for each kind of order, a few seconds each: a driver posting mouse clicks to the window (if one
        -- runs) issues them through the world view's command code.
        local okMode, commandMode = pcall(import, '/lua/ui/game/commandmode.lua')
        if okMode and commandMode and rawget(commandMode, 'StartCommandMode') then
            local orders = { 'RULEUCC_Move', 'RULEUCC_Attack', 'RULEUCC_Patrol', 'RULEUCC_Guard', 'RULEUCC_Reclaim',
                             'RULEUCC_Repair', 'RULEUCC_Capture', 'RULEUCC_Ferry', 'RULEUCC_Tactical', 'RULEUCC_Nuke' }
            for i = 1, table.getn(orders) do
                Try('select all for ' .. orders[i], UISelectionByCategory, 'ALLUNITS', false, false, false, false)
                Try('StartCommandMode ' .. orders[i], commandMode.StartCommandMode, 'order', { name = orders[i] })
                WaitSeconds(3)
                Try('EndCommandMode', commandMode.EndCommandMode, true)
            end
            Try('select engineers', UISelectionByCategory, 'ENGINEER', false, false, false, false)
            Try('StartCommandMode build', commandMode.StartCommandMode, 'build', { name = 'ueb1101' })
            WaitSeconds(4)
            Try('EndCommandMode', commandMode.EndCommandMode, true)
        end
        WaitSeconds(3)
        Try('select factories', UISelectionByCategory, 'FACTORY', false, false, false, false)
        Try('IssueBlueprintCommand', IssueBlueprintCommand, 'UNITCOMMAND_BuildFactory', 'uel0105', 2, false)
        Try('IssueDockCommand', IssueDockCommand, false)
        WaitSeconds(2)
        Try('select all again', UISelectionByCategory, 'ALLUNITS', false, false, false, false)
        local again = GetSelectedUnits() or {}
        if again[1] then
            Try('UIZoomTo', UIZoomTo, again, 1)
            WaitSeconds(2)
            Try('UISelectAndZoomTo', UISelectAndZoomTo, again[1], 1)
        end
        WaitSeconds(10)
        Log('live done')
    end

    local function Tour()
        if HasCommandLineArg('/tourlive') then
            -- The map's scripted AI builds the army for a minute and a half first: more units, more kinds of order.
            WaitSeconds(90)
            Log('start live')
            LiveTour()
            UnitTour()
            CameraTour()
            ControlTour()
            SweepGlobals()
            RunCommands()
            Log('done')
            if HasCommandLineArg('/tourexit') then
                ExitApplication()
            end
            return
        end
        if HasCommandLineArg('/tourvars') then
            WaitSeconds(5)
            Log('start vars')
            Try('focus army', ConExecute, 'SetFocusArmy 0')
            WaitSeconds(0.5)
            Try('select all', UISelectionByCategory, 'ALLUNITS', false, false, false, false)
            VarTour()
            Log('done')
            return
        end
        WaitSeconds(10)
        -- The parity init runs the replay at game speed 50; the tour needs the game to last while it runs.
        Try('slow down', ConExecute, 'WLD_GameSpeed 0')
        Log('start')
        UnitTour()
        CameraTour()
        ControlTour()
        SweepGlobals()
        Try('select all again', UISelectionByCategory, 'ALLUNITS', false, false, false, false)
        RunCommands()
        Try('speed up', ConExecute, 'WLD_GameSpeed 50')
        Log('done')
    end

    -- `/tourquitafter <seconds>` quits the game that long after the session starts, so a multiplayer game run by a
    -- test tool ends cleanly and writes its coverage counters; `/tournone` skips the tour itself.
    local function QuitLater()
        local args = GetCommandLineArg('/tourquitafter', 1)
        local seconds = args and tonumber(args[1])
        if seconds then
            WaitSeconds(seconds)
            Log('quitting after ' .. seconds .. ' s')
            ExitApplication()
        end
    end

    local TourOnFirstUpdate = OnFirstUpdate
    OnFirstUpdate = function()
        TourOnFirstUpdate()
        if HasCommandLineArg('/tourquitafter') then
            ForkThread(QuitLater)
        end
        if not HasCommandLineArg('/tournone') then
            ForkThread(Tour)
        end
    end
end
