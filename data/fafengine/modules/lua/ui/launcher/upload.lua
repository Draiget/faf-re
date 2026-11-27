-- Uploading a map or mod of the vault to FAF's vault (FafLibrary_Upload), over the launcher: what goes up and under
-- whose name, a map's ranked flag, then the upload with its outcome (FAF's own words when it refuses).

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local current = false

--- Opens the upload of `subject` = {kind = 'map' or 'mod', folder = its folder in the vault, name}.
function Open(launcher, subject)
    if current then
        current.cover:Destroy()
        current = false
    end
    local status = launcher.lastStatus or {}
    local cover = Widgets.Modal(launcher.root, 620, 300)
    local panel = cover.panel
    local view = { cover = cover, subject = subject }
    current = view
    local x = 26
    local title = Theme.Title(panel, 'Upload to FAF\'s vault', 18, C.text)
    LayoutHelpers.AtLeftTopIn(title, panel, x, 22)
    local text = Theme.Paragraph(panel, 13, C.muted)
    text.Left:Set(title.Left)
    text.Right:Set(function() return panel.Right() - Scale(x) end)
    text.Top:Set(function() return title.Bottom() + Scale(14) end)
    text:SetText((subject.kind == 'map' and 'The map ' or 'The mod ') .. tostring(subject.name or subject.folder) ..
        ' (folder ' .. tostring(subject.folder) .. ') goes up under your FAF name' ..
        (status.login and status.login ~= '' and (', ' .. status.login) or '') ..
        ', for every FAF player to download. FAF checks it first and may refuse it, saying why.', C.muted)
    if subject.kind == 'map' then
        view.ranked = Theme.Checkbox(panel, 'Ranked: games on it count for the ratings', function() end)
        view.ranked.Left:Set(title.Left)
        view.ranked.Top:Set(function() return text.Bottom() + Scale(14) end)
        view.ranked:SetOn(true)
    end
    view.status = Theme.Cell(panel, 12, C.subtle)
    view.status.Left:Set(title.Left)
    view.status.Right:Set(function() return panel.Right() - Scale(x) end)
    view.status.Bottom:Set(function() return panel.Bottom() - Scale(70) end)
    view.upload = Theme.Button(panel, 'Upload', function() view:Upload() end, 'primary', { icon = 'upload', width = 160 })
    LayoutHelpers.AtRightIn(view.upload, panel, x)
    LayoutHelpers.AtBottomIn(view.upload, panel, 18)
    view.close = Theme.Button(panel, 'Cancel', function() view:Close() end, 'secondary', { width = 130 })
    view.close.Right:Set(function() return view.upload.Left() - Scale(10) end)
    view.close.Top:Set(view.upload.Top)

    function view:Upload()
        if not rawget(_G, 'FafLibrary_Upload') then
            self.statusText = 'This build can\'t upload.'
        else
            local id, why = FafLibrary_Upload({ kind = subject.kind, folder = subject.folder,
                ranked = self.ranked and self.ranked.on or false })
            if id then
                self.job = id
                self.statusText = 'Uploading...'
                LOG('LAUNCHER: uploading the ' .. subject.kind .. ' ' .. subject.folder)
            else
                self.statusText = 'Not uploaded: ' .. tostring(why)
            end
        end
        self:Paint()
    end

    function view:Poll()
        if not self.job then
            return
        end
        local state = FafLibrary_Job(self.job)
        if state and state.state == 'working' then
            if state.total and state.total > 0 then
                self.statusText = string.format('Uploading %.1f MB...', state.total / 1048576)
            end
        else
            self.job = nil
            self.done = state and state.state == 'done'
            self.statusText = self.done and ('Uploaded: FAF\'s vault has ' .. tostring(subject.name or subject.folder) ..
                ' now.') or ('Not uploaded: ' .. tostring(state and state.message or 'no answer'))
            LOG('LAUNCHER: upload of ' .. subject.folder .. ': ' .. self.statusText)
        end
        self:Paint()
    end

    function view:Paint()
        local signedIn = (launcher.lastStatus or {}).lobby == 'signedin'
        Theme.SetText(self.status, self.statusText or (signedIn and '' or 'Connect to FAF to upload.'))
        Theme.SetColor(self.status, (self.statusText and string.find(self.statusText, '^Not ')) and C.bad or
            (self.done and C.good or C.subtle))
        self.upload:SetEnabled(signedIn and not self.job and not self.done)
        self.close:SetLabel(self.done and 'Close' or 'Cancel')
    end

    function view:Close()
        if current == view then
            current = false
        end
        cover:Destroy()
    end

    cover:SetNeedsFrameUpdate(true)
    cover.OnFrame = function(self, delta)
        view:Poll()
    end
    view:Paint()
    return view
end

function Current()
    return current
end
