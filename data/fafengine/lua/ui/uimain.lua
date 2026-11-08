-- Engine hook (data/fafengine, mounted by the engine at /fafengine and
-- registered as a hook directory): appended to /lua/ui/uimain.lua.
--
-- Issue #275: what the player taking a seat back sees. The engine calls these only
-- in a client started with /rejoin. Before the map loads there is no other screen,
-- while it loads this sits over the loading screen, and while the game so far runs
-- it covers the game, so nobody watches it run at full speed.
--
-- FAF's Lua may carry these screens itself (issue #327); its uimain.lua then defines
-- UpdateRejoinScreen and this block steps aside. Likewise Escape and the timeline. rawget on the
-- module: FAF's Lua errors on reading a global that doesn't exist.

if not rawget(getfenv(1), 'UpdateRejoinScreen') then
    local UIUtil = import("/lua/ui/uiutil.lua")
    local LayoutHelpers = import("/lua/maui/layouthelpers.lua")
    local Bitmap = import("/lua/maui/bitmap.lua").Bitmap
    local Movie = import("/lua/maui/movie.lua").Movie
    local Prefs = import("/lua/user/prefs.lua")

    local barWidth = 520
    -- A reload of this module keeps the screen that is up: while the new module loads, /lua/system/import.lua
    -- hands it the old one as `__moduleinfo.old`. Without that the old cover stayed on top and the next update made
    -- a second one over it.
    local screen = __moduleinfo.old and rawget(__moduleinfo.old, 'RejoinScreen') or false
    RejoinScreen = screen

    --- The game's loading screen as `LoadDialog` in gamemain.lua makes it, so the view doesn't
    --- change when the real one takes over for the map.
    local function CreateTransit(cover)
        local frame = GetFrame(0)
        local movieFile = '/movies/UEF_load.sfd'
        local color = 'FFbadbdb'
        local faction = import("/lua/factions.lua").Factions[Prefs.GetFromCurrentProfile('LoadingFaction')]
        if faction and faction.loadingMovie then
            movieFile = faction.loadingMovie
            color = faction.loadingColor
        end

        local movie = Movie(cover, movieFile)
        LayoutHelpers.FillParent(movie, frame)
        movie:Loop(true)
        movie:Play()

        local text = UIUtil.CreateText(movie, '::  ' .. LOC('<LOC LOAD_0000>IN TRANSIT') .. '  ::', 20, UIUtil.bodyFont)
        text:SetColor(color)
        text:SetDropShadow(true)
        LayoutHelpers.AtCenterIn(text, frame, 200)
        import("/lua/maui/effecthelpers.lua").Pulse(text, 1, 0, .8)
        return movie
    end

    local function CreateScreen()
        local frame = GetFrame(0)

        local cover = Bitmap(frame)
        cover.Depth:Set(frame:GetTopmostDepth() + 1)
        LayoutHelpers.FillParent(cover, frame)

        -- Under IN TRANSIT, which both this screen and the loading screen show at this height.
        cover.text = UIUtil.CreateText(cover, '', 18, UIUtil.bodyFont)
        cover.text:SetColor('FFbadbdb')
        cover.text:SetDropShadow(true)
        cover.text.Depth:Set(function() return cover.Depth() + 10 end)
        LayoutHelpers.AtHorizontalCenterIn(cover.text, frame)
        cover.text.Top:Set(function() return frame.Top() + 0.5 * frame.Height() + LayoutHelpers.ScaleNumber(230) end)

        cover.track = Bitmap(cover)
        cover.track:SetSolidColor('ff303030')
        cover.track.Depth:Set(function() return cover.Depth() + 10 end)
        LayoutHelpers.SetDimensions(cover.track, barWidth, 10)
        LayoutHelpers.AtHorizontalCenterIn(cover.track, frame)
        cover.track.Top:Set(function() return cover.text.Bottom() + LayoutHelpers.ScaleNumber(8) end)

        cover.fill = Bitmap(cover.track)
        cover.fill:SetSolidColor('ff4fa0e0')
        LayoutHelpers.SetDimensions(cover.fill, 1, 10)
        LayoutHelpers.AtLeftTopIn(cover.fill, cover.track, 0, 0)

        return cover
    end

    local function StageText(stage, progress)
        -- No measure: the travelling block alone says it is under way.
        local percent = ''
        if progress >= 0 then
            percent = string.format(": %d%%", math.floor(progress * 100))
        end
        if stage == 'connecting' then
            return LOC("<LOC rejoin_0010>Reconnecting to the game")
        elseif stage == 'transfer' then
            return LOC("<LOC rejoin_0011>Reconnecting: receiving the game so far") .. percent
        elseif stage == 'loading' then
            return LOC("<LOC rejoin_0012>Rejoining the game: loading the map")
        end
        return LOC("<LOC rejoin_0013>Rejoining the game: catching up") .. percent
    end

    --- `stage` is 'connecting', 'transfer', 'loading' or 'catchingUp', with `progress`
    --- 0 to 1 or negative when there is no measure; '' takes the screen away.
    function UpdateRejoinScreen(stage, progress)
        if stage == '' then
            if screen and not IsDestroyed(screen) then
                screen:Destroy()
            end
            screen = false
            RejoinScreen = screen
            return
        end

        -- A new Lua state takes over between the loading screen and the game.
        if not screen or IsDestroyed(screen) then
            screen = CreateScreen()
            RejoinScreen = screen
        end

        if screen.stage != stage then
            screen.stage = stage
            screen.stageStart = GetSystemTimeSeconds()
            LOG('REJOIN: screen says ' .. stage)
            -- The loading screen is itself what's on show during the load.
            screen:SetSolidColor(stage == 'loading' and '00000000' or 'ff000000')
            if stage == 'loading' then
                if screen.transit then
                    screen.transit:Destroy()
                    screen.transit = false
                end
            elseif not screen.transit then
                screen.transit = CreateTransit(screen)
            end
        end

        screen.text:SetText(StageText(stage, progress))

        if progress >= 0 then
            LayoutHelpers.AtLeftTopIn(screen.fill, screen.track, 0, 0)
            LayoutHelpers.SetWidth(screen.fill, math.max(1, barWidth * progress))
        else
            -- No measure: a block that travels, so it can't be read as a percentage.
            local blockWidth = 60
            local travelled = math.mod(GetSystemTimeSeconds() - screen.stageStart, 3) / 3
            LayoutHelpers.AtLeftTopIn(screen.fill, screen.track, (barWidth - blockWidth) * travelled, 0)
            LayoutHelpers.SetWidth(screen.fill, blockWidth)
        end
    end

    function StartRejoinScreen()
        UpdateRejoinScreen('connecting', -1)
    end
end

if not DiskGetFileInfo('/lua/ui/game/replay_timeline.lua') then
    local OldEscapeHandler = EscapeHandler
    function EscapeHandler()
        if not import('/fafengine/modules/lua/ui/game/replay_timeline.lua').OnEscape() then
            OldEscapeHandler()
        end
    end
end
