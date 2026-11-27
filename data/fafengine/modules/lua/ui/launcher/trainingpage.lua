-- The launcher's Training page (Play > Training): FAF's tutorials by category (FAF's API, /data/tutorialCategory with
-- the tutorials and their maps), the chosen one's picture, map and description, and Start: its map downloaded when
-- missing, then its scenario started offline on FAF's tutorials featured mod (the game starts again on those files
-- when it runs on others), as the FAF client starts tutorials.

local LayoutHelpers = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Theme = import('/fafengine/modules/lua/ui/launcher/theme.lua')
local Widgets = import('/fafengine/modules/lua/ui/launcher/widgets.lua')
local News = import('/fafengine/modules/lua/ui/launcher/newspage.lua')
local C = Theme.Colors
local Scale = Theme.Scale

local function Store(doc)
    local store = {}
    for _, list in { doc and doc.data or {}, doc and doc.included or {} } do
        for _, resource in list do
            if type(resource) == 'table' and resource.type and resource.id then
                store[resource.type .. ':' .. resource.id] = resource
            end
        end
    end
    return store
end

local function Rel(store, resource, name)
    local link = resource and resource.relationships and resource.relationships[name]
    local data = link and link.data
    if type(data) ~= 'table' then
        return nil
    end
    if data.type then
        return store[data.type .. ':' .. data.id] or { id = data.id, type = data.type }
    end
    local list = {}
    for _, item in data do
        table.insert(list, store[item.type .. ':' .. item.id] or { id = item.id, type = item.type })
    end
    return list
end

local function Attr(resource, name)
    return resource and resource.attributes and resource.attributes[name]
end

function Build(launcher, page)
    local view = { jobs = {}, thumbJobs = {} }
    launcher.trainingView = view

    local title = Theme.Title(page, 'Training', 24)
    LayoutHelpers.AtLeftTopIn(title, page, 0, 0)
    local subtitle = Theme.Text(page, 'FAF\'s tutorials: short games that teach one thing each.', 13, C.subtle)
    subtitle.Left:Set(function() return title.Right() + Scale(24) end)
    subtitle.Bottom:Set(function() return title.Bottom() - Scale(3) end)

    local body = Group(page)
    body.Left:Set(page.Left)
    body.Right:Set(page.Right)
    body.Top:Set(function() return title.Bottom() + Scale(22) end)
    body.Bottom:Set(page.Bottom)
    Theme.SizeFromEdges(body)

    local listArea = Group(body)
    listArea.Left:Set(body.Left)
    listArea.Top:Set(body.Top)
    listArea.Bottom:Set(body.Bottom)
    listArea.Right:Set(function() return body.Left() + math.floor(body.Width() * 0.42) end)
    Theme.SizeFromEdges(listArea)
    view.list = Widgets.VirtualList(listArea, {
        { 'Tutorial', 0.62, function(item) return item.title end },
        { 'Category', 0.38, function(item) return item.category end, C.muted },
    }, function(item, double)
        view:Choose(item)
        if double then
            view:Start()
        end
    end)
    LayoutHelpers.FillParent(view.list, listArea)
    Theme.SizeFromEdges(view.list)
    view.note = Theme.Paragraph(listArea, 13, C.subtle)
    view.note.Left:Set(listArea.Left)
    view.note.Right:Set(listArea.Right)
    view.note.Top:Set(function() return listArea.Top() + Scale(40) end)
    view.loader = Theme.Loader(listArea)
    LayoutHelpers.AtCenterIn(view.loader, listArea)

    local detail = Theme.Panel(body, C.panel, C.line)
    Theme.Brackets(detail, C.accent)
    detail.Left:Set(function() return listArea.Right() + Scale(24) end)
    detail.Right:Set(body.Right)
    detail.Top:Set(body.Top)
    detail.Bottom:Set(body.Bottom)
    Theme.SizeFromEdges(detail)
    local x = 24
    view.picture = Theme.Panel(detail, 'ff08121a', C.line)
    LayoutHelpers.SetDimensions(view.picture, 170, 170)
    LayoutHelpers.AtLeftTopIn(view.picture, detail, x, x)
    view.pictureMap = Bitmap(view.picture)
    view.pictureMap:DisableHitTest()
    LayoutHelpers.FillParentFixedBorder(view.pictureMap, view.picture, 1)
    view.pictureMap.Depth:Set(function() return view.picture.Depth() + 2 end)
    view.placeholder = Theme.Icon(view.picture, 'book', 40, C.subtle, 1.5)
    LayoutHelpers.AtCenterIn(view.placeholder, view.picture)
    view.name = Theme.Title(detail, '', 18, C.text)
    view.name.Left:Set(function() return view.picture.Right() + Scale(20) end)
    view.name.Top:Set(function() return detail.Top() + Scale(28) end)
    view.facts = Theme.Cell(detail, 13, C.muted)
    view.facts.Left:Set(view.name.Left)
    view.facts.Right:Set(function() return detail.Right() - Scale(x) end)
    view.facts.Top:Set(function() return view.name.Bottom() + Scale(8) end)
    view.startButton = Theme.Button(detail, 'Start tutorial', function() view:Start() end, 'primary',
        { icon = 'play', width = 220 })
    LayoutHelpers.AtRightIn(view.startButton, detail, x)
    LayoutHelpers.AtBottomIn(view.startButton, detail, 22)
    view.status = Theme.Cell(detail, 13, C.muted)
    view.status.Left:Set(function() return detail.Left() + Scale(x) end)
    view.status.Right:Set(function() return view.startButton.Left() - Scale(16) end)
    LayoutHelpers.AtVerticalCenterIn(view.status, view.startButton)
    view.document = Widgets.TextView(detail)
    view.document.Left:Set(function() return detail.Left() + Scale(x) end)
    view.document.Right:Set(function() return detail.Right() - Scale(16) end)
    view.document.Top:Set(function() return view.picture.Bottom() + Scale(20) end)
    view.document.Bottom:Set(function() return view.startButton.Top() - Scale(14) end)
    view.document.Width:Set(function() return view.document.Right() - view.document.Left() end)
    view.document.Height:Set(function() return view.document.Bottom() - view.document.Top() end)

    ----------------------------------------------------------------------------------------------------------------

    function view:Load()
        if not rawget(_G, 'FafLibrary_Api') then
            self.failure = 'This build has no FAF API access.'
            return
        end
        local id, why = FafLibrary_Api('/data/tutorialCategory', {
            include = 'tutorials,tutorials.mapVersion,tutorials.mapVersion.map', ['page[size]'] = '1000' })
        if not id then
            self.failure = tostring(why)
            return
        end
        self.jobs.list = { id = id, done = function(doc)
            local store = Store(doc)
            local tutorials = {}
            for _, category in (doc.data or {}) do
                local categoryName = Attr(category, 'category') or Attr(category, 'categoryKey') or ''
                for _, tutorial in (Rel(store, category, 'tutorials') or {}) do
                    if tutorial.attributes then
                        local version = Rel(store, tutorial, 'mapVersion')
                        local map = version and Rel(store, version, 'map')
                        table.insert(tutorials, {
                            key = tutorial.id, title = Attr(tutorial, 'title') or Attr(tutorial, 'titleKey') or '?',
                            category = categoryName, categoryOrder = tonumber(category.id) or 0,
                            ordinal = Attr(tutorial, 'ordinal') or 0, html = Attr(tutorial, 'description') or '',
                            launchable = Attr(tutorial, 'launchable') and true or false,
                            technicalName = Attr(tutorial, 'technicalName') or '',
                            picture = Attr(tutorial, 'imageUrl'),
                            mapName = map and Attr(map, 'displayName') or (version and Attr(version, 'folderName')) or '',
                            mapFolder = version and Attr(version, 'folderName') or '',
                            mapUrl = version and Attr(version, 'downloadUrl'),
                            mapPicture = version and (Attr(version, 'thumbnailUrlLarge') or Attr(version, 'thumbnailUrlSmall')),
                        })
                    end
                end
            end
            table.sort(tutorials, function(a, b)
                if a.categoryOrder ~= b.categoryOrder then
                    return a.categoryOrder < b.categoryOrder
                end
                return a.ordinal < b.ordinal
            end)
            view.tutorials = tutorials
            if not view.chosen and tutorials[1] then
                view:Choose(tutorials[1])
            end
            LOG('LAUNCHER: training: ' .. table.getn(tutorials) .. ' tutorials')
        end }
    end

    function view:Choose(tutorial)
        self.chosen = tutorial
        self.statusText = nil
        self.list.selectedKey = tutorial.key
        self.document:SetBlocks(News.HtmlBlocks(tutorial.html))
        self:Paint()
    end

    --- What Start does for the chosen tutorial: 'download' (its map first), 'start', 'restart' (on the tutorials
    --- featured mod), or nil and why not.
    function view:Plan(tutorial)
        tutorial = tutorial or self.chosen
        if not tutorial then
            return nil, 'Choose a tutorial.'
        end
        if not tutorial.launchable then
            return nil, 'This one is to read: it has no game to start.'
        end
        if tutorial.mapFolder ~= '' and not Widgets.LocalScenario(tutorial.mapFolder) then
            if not tutorial.mapUrl or not rawget(_G, 'FafLibrary_InstallMap') then
                return nil, 'Its map ' .. tutorial.mapName .. ' isn\'t on this computer.'
            end
            return 'download'
        end
        local status = rawget(_G, 'FafOnline_Status') and FafOnline_Status() or {}
        if status.loadedMod == 'tutorials' then
            return 'start'
        end
        if rawget(_G, 'FafOnline_FeaturedModFiles') then
            local ok, why = FafOnline_FeaturedModFiles('tutorials')
            if not ok then
                return nil, 'FAF\'s tutorials can\'t start here: ' .. tostring(why)
            end
        end
        return 'restart'
    end

    function view:Start()
        local tutorial = self.chosen
        local plan, why = self:Plan(tutorial)
        if plan == 'download' then
            local id, failure = FafLibrary_InstallMap({ url = tutorial.mapUrl })
            if not id then
                self.statusText = 'The map didn\'t download: ' .. tostring(failure)
            else
                self.statusText = 'Downloading ' .. tutorial.mapName .. '...'
                self.jobs.map = { id = id, done = function()
                    Widgets.ForgetScenario(tutorial.mapFolder)
                    view:Start() -- the map is here: on to the game
                end }
            end
        elseif plan then
            local ok, failure = launcher:StartTutorial(tutorial.technicalName)
            self.statusText = ok and ('Starting ' .. tutorial.title .. '...') or tostring(failure)
        else
            self.statusText = why
        end
        self:Paint()
    end

    function view:Poll()
        for key, job in self.jobs do
            local state = FafLibrary_Job(job.id)
            if not state or state.state ~= 'working' then
                self.jobs[key] = nil
                if state and state.state == 'done' then
                    local ok, err = pcall(job.done, state.data or {})
                    if not ok then
                        WARN('LAUNCHER: training: ' .. tostring(err))
                    end
                elseif key == 'list' then
                    self.failure = (state and state.message ~= '' and state.message) or 'FAF\'s API didn\'t answer.'
                else
                    self.statusText = 'The map didn\'t download: ' .. tostring(state and state.message)
                end
            end
        end
    end

    function view:Paint()
        Theme.SetVisible(self.loader, self.tutorials == nil and not self.failure)
        local note = ''
        if self.failure and not self.tutorials then
            note = 'The tutorials didn\'t load: ' .. self.failure
        elseif self.tutorials and table.getn(self.tutorials) == 0 then
            note = 'FAF lists no tutorials.'
        end
        self.note:SetText(note, self.failure and C.bad or C.subtle)
        if self.tutorials and self.list.items ~= self.tutorials then
            self.list:SetItems(self.tutorials)
        end
        self.list:Paint()
        local tutorial = self.chosen
        Theme.SetText(self.name, tutorial and tutorial.title or '')
        Theme.SetText(self.facts, tutorial and (tutorial.category .. (tutorial.mapName ~= '' and ('  -  map ' ..
            tutorial.mapName) or '')) or '')
        -- Its picture, else its map's, from FAF's content server.
        local picture = nil
        local url = tutorial and (tutorial.picture or tutorial.mapPicture)
        if url and rawget(_G, 'FafLibrary_Thumbnail') then
            local path, job = FafLibrary_Thumbnail(url)
            picture = path
            if not path and job and job > 0 and not self.thumbJobs[job] then
                self.thumbJobs[job] = true
            elseif not path and job == 0 then
                self.mountWanted = true
            end
        end
        for job in self.thumbJobs do
            local state = FafLibrary_Job(job)
            if not state or state.state ~= 'working' then
                self.thumbJobs[job] = nil
                self.mountWanted = true
            end
        end
        if self.mountWanted and not next(self.thumbJobs) then
            self.mountWanted = false
            FafLibrary_MountThumbnails()
        end
        if picture and self.shownPicture ~= picture then
            self.shownPicture = picture
            self.pictureMap:SetTexture(picture)
        end
        Theme.SetVisible(self.pictureMap, picture ~= nil)
        Theme.SetVisible(self.placeholder, picture == nil)
        local plan, why = self:Plan(tutorial)
        self.startButton:SetEnabled(plan ~= nil and self.jobs.map == nil)
        Theme.SetText(self.status, self.statusText or (plan == 'download' and ('Start downloads its map ' ..
            tutorial.mapName .. ' first.') or plan == 'restart' and 'Start opens the game again on FAF\'s tutorial files.' or
            plan == 'start' and '' or why or ''))
    end

    function view:Refresh()
        if not self.tutorials and not self.jobs.list and not self.failure then
            self:Load()
        end
        self:Poll()
        self:Paint()
    end

    return view
end
