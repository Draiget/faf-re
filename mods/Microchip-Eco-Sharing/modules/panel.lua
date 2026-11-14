local Sharing = import('/mods/Microchip-Eco-Sharing/modules/sharing.lua')
local Allocate = import('/mods/Microchip-Eco-Sharing/modules/allocation.lua')
local UI = import('/lua/ui/uiutil.lua')
local L = import('/lua/maui/layouthelpers.lua')
local Group = import('/lua/maui/group.lua').Group
local Bitmap = import('/lua/maui/bitmap.lua').Bitmap
local Slider = import('/lua/maui/slider.lua').IntegerSlider
local Combo = import('/lua/ui/controls/combo.lua').Combo
local Popup = import('/lua/ui/controls/popups/popup.lua').Popup
local window = false
local lime, white, grey = 'ffe1f280','ffe8e9db','ffa7b198'
local texturePath='/mods/Microchip-Eco-Sharing/textures/'
local rowsPerPage=6
local function Texture(name) return texturePath..name..'.dds' end
local function Copy(t)
    if type(t) ~= 'table' then return t end
    local n={}; for k,v in pairs(t) do n[k]=Copy(v) end; return n
end
local function Art(parent,name,x,y,w,h)
    local b=Bitmap(parent,Texture(name))
    b.Width:Set(L.ScaleNumber(w)); b.Height:Set(L.ScaleNumber(h)); L.AtLeftTopIn(b,parent,x,y)
    return b
end
local function Box(parent,x,y,w,h,colour)
    local b=Bitmap(parent); b:SetSolidColor(colour)
    b.Width:Set(L.ScaleNumber(w)); b.Height:Set(L.ScaleNumber(h)); L.AtLeftTopIn(b,parent,x,y)
    return b
end
local function Text(parent,text,size,x,y,colour,heading)
    local t=UI.CreateText(parent,text,size,heading and UI.titleFont or UI.bodyFont)
    t:SetColor(colour or white); t:SetDropShadow(true)
    L.AtLeftTopIn(t,parent,x,y); t:DisableHitTest(); return t
end
local function Button(parent,text,x,y,w,click,height,primary)
    height=height or 38
    local normal=primary and 'button-apply' or 'button-up'
    local b=Art(parent,normal,x,y,w,height)
    if text=='^' or text=='v' or text=='X' then
        local icon=Art(b,text=='^' and 'up' or text=='v' and 'down' or 'close',0,0,height-8,height-8)
        icon:DisableHitTest(); L.AtCenterIn(icon,b)
    else
        local label=Text(b,text,math.min(18,height-10),0,0,primary and 'fff2ffd4' or white,true)
        L.AtCenterIn(label,b)
    end
    b.HandleEvent=function(self,event)
        if event.Type=='MouseEnter' then self:SetTexture(Texture('button-over'))
        elseif event.Type=='MouseExit' then self:SetTexture(Texture(normal))
        elseif event.Type=='ButtonPress' then self:SetTexture(Texture('button-down')); click(); return true
        elseif event.Type=='ButtonRelease' then self:SetTexture(Texture('button-over')) end
        return false
    end
    return b
end
local function Tick(parent,x,y,checked,change)
    local b=Art(parent,checked and 'check-on' or 'check-off',x,y,30,30)
    b.HandleEvent=function(self,event)
        if event.Type=='ButtonPress' then
            checked=not checked; self:SetTexture(Texture(checked and 'check-on' or 'check-off'))
            change(checked); return true
        end
        return false
    end
    return b
end
local function ComboTextures()
    local result={button={},list={}}
    for _,part in ipairs({'left','mid','right'}) do
        result.button[part]={}
        for _,state in ipairs({'up','down','over','dis'}) do result.button[part][state]=Texture('combo-'..part..'-'..state) end
    end
    for _,part in ipairs({'ul','um','ur','l','m','r','ll','lm','lr'}) do result.list[part]=Texture('list-'..part) end
    return result
end

function Toggle()
    if window then window:Close(); return end
    local content=Group(GetFrame(0))
    content.Width:Set(L.ScaleNumber(940)); content.Height:Set(L.ScaleNumber(660))
    Art(content,'frame',0,0,940,660):DisableHitTest()
    local draft=Copy(Sharing.Settings())
    local popup=Popup(GetFrame(0),content); window=popup
    local closed=popup.OnClosed
    popup.OnClosed=function(self) window=false; closed(self) end
    Art(content,'logo',36,29,78,68):DisableHitTest()
    Text(content,'Microchip Eco Sharing',29,126,33,lime,true)
    Text(content,'Share surplus above your reserves when a selected ally runs empty.',15,127,77)
    Button(content,'X',866,34,38,function() popup:Close() end,38)

    Art(content,'reserves',30,122,880,148):DisableHitTest()
    Text(content,'Reserve Thresholds',18,49,125,lime,true)
    local function Reserve(resource,y)
        local key=string.lower(resource)..'Reserve'
        Art(content,string.lower(resource),48,y-3,28,30):DisableHitTest()
        Text(content,resource..' reserve',18,87,y)
        local display=Art(content,'button-up',796,y-6,88,35); display:DisableHitTest()
        local value=Text(content,tostring(draft[key])..'%',20,0,0,lime,true); L.AtCenterIn(value,display)
        local slider=Slider(content,false,0,100,1,Texture('thumb-up'),Texture('thumb-over'),Texture('thumb-down'))
        slider.Width:Set(L.ScaleNumber(492)); slider.Height:Set(L.ScaleNumber(34))
        L.AtLeftTopIn(slider,content,273,y-6)
        slider._background:SetSolidColor('ff4a5534')
        slider._background.Width:Set(slider.Width); slider._background.Height:Set(L.ScaleNumber(7))
        L.AtVerticalCenterIn(slider._background,slider)
        local fill=Box(slider,2,0,1,3,'ffd6ec61'); fill:DisableHitTest()
        fill.Width:Set(function() return math.max(0,(slider.Width()-L.ScaleNumber(4))*slider:GetValue()/100) end)
        L.AtVerticalCenterIn(fill,slider)
        fill.Depth:Set(function() return slider._background.Depth()+1 end)
        slider._thumb.Depth:Set(function() return fill.Depth()+1 end)
        slider:SetValue(draft[key])
        slider.OnValueChanged=function(self,n)
            draft[key]=math.max(0,math.min(100,math.floor(n+0.5))); value:SetText(tostring(draft[key])..'%')
        end
    end
    Reserve('Energy',168); Reserve('Mass',218)

    Art(content,'allies',30,286,425,282):DisableHitTest()
    Art(content,'priority',475,286,435,282):DisableHitTest()
    Text(content,'Share To Allies',18,49,289,lime,true)
    Text(content,'When Multiple Allies Are Empty',17,494,289,lime,true)
    Text(content,'Ally',15,49,326)
    Art(content,'energy',292,322,17,20):DisableHitTest(); Text(content,'Energy',14,314,325)
    Art(content,'mass',373,322,17,20):DisableHitTest(); Text(content,'Mass',14,394,325)
    Text(content,'Sharing mode:',16,495,327)
    local combo=Combo(content,17,2,false,ComboTextures())
    combo.Width:Set(L.ScaleNumber(204)); L.AtLeftTopIn(combo,content,681,318)
    combo:AddItems({'Equal','Rank'},draft.mode=='Rank' and 2 or 1)
    combo:SetTitleTextColor(lime)
    local explanation=Text(content,'',13,495,366,grey)
    local priorityHeading=Text(content,'',14,495,398,lime,true)
    local rowGroup,priorityGroup,page=false,false,1
    local pageText=Text(content,'',12,169,545,grey)
    local refresh
    local function Move(name,delta)
        local list=Allocate.Ordered(Sharing.Allies(),draft.order)
        for i,ally in ipairs(list) do
            if ally.name==name then
                local target=i+delta
                if target<1 or target>table.getn(list) then return end
                list[i],list[target]=list[target],list[i]; break
            end
        end
        draft.order={}; for _,ally in ipairs(list) do table.insert(draft.order,ally.name) end
        refresh()
    end
    refresh=function()
        if rowGroup then rowGroup:Destroy() end
        if priorityGroup then priorityGroup:Destroy() end
        rowGroup=Group(content); L.FillParent(rowGroup,content)
        priorityGroup=Group(content); L.FillParent(priorityGroup,content)
        local allies=Sharing.Allies(); local count=table.getn(allies)
        page=math.max(1,math.min(page,math.max(1,math.ceil(count/rowsPerPage))))
        local first=(page-1)*rowsPerPage+1
        for row=1,rowsPerPage do
            local ally=allies[first+row-1]
            if ally then
                local y=352+(row-1)*29
                Box(rowGroup,49,y+6,17,18,ally.colour):DisableHitTest()
                local name=ally.name
                Text(rowGroup,string.sub(name,1,23),16,77,y+4)
                draft.targets[name]=draft.targets[name] or {}
                for column,key in ipairs({'ENERGY','MASS'}) do
                    -- Lua 5.0 reuses generic-for variables after the loop ends.
                    local resource=key
                    Tick(rowGroup,313+(column-1)*81,y-1,draft.targets[name][resource],function(on) draft.targets[name][resource]=on end)
                end
            end
        end
        if count==0 then Text(rowGroup,'No active allies available.',15,49,367,grey) end
        explanation:SetText(draft.mode=='Rank' and 'Rank fills higher-priority allies first.' or 'Equal shares surplus equally, up to storage limits.')
        priorityHeading:SetText(table.getn(draft.order)>0 and 'Priority: manual override' or 'Priority: highest FAF rating')
        local ordered=Allocate.Ordered(allies,draft.order)
        for row=1,rowsPerPage do
            local ally=ordered[first+row-1]
            if ally then
                local y=423+(row-1)*23
                local name=ally.name
                local rating=ally.rating and tostring(math.floor(ally.rating+0.5)) or 'unrated'
                Text(priorityGroup,tostring(first+row-1)..'.',14,495,y)
                Box(priorityGroup,517,y+4,12,13,ally.colour):DisableHitTest()
                Text(priorityGroup,string.sub(name,1,20),14,539,y)
                Text(priorityGroup,rating,12,740,y+1,grey)
                Button(priorityGroup,'^',825,y-2,28,function() Move(name,-1) end,22)
                Button(priorityGroup,'v',863,y-2,28,function() Move(name,1) end,22)
            end
        end
        pageText:SetText(count>0 and ('Allies '..first..'-'..math.min(first+rowsPerPage-1,count)..' of '..count) or '')
    end
    combo.OnClick=function(self,index) draft.mode=index==2 and 'Rank' or 'Equal'; refresh() end
    Button(content,'<',48,539,34,function() page=page-1; refresh() end,24)
    Button(content,'>',404,539,34,function() page=page+1; refresh() end,24)
    Tick(content,42,570,draft.enabled,function(on) draft.enabled=on end)
    Text(content,'Enable automatic sharing',16,83,575,lime)
    local status=Text(content,string.sub(Sharing.Status(),1,66),12,390,577,grey)
    Button(content,'Reset to rank',40,604,190,function() draft.order={}; refresh() end,30)
    Button(content,'Apply',650,604,118,function()
        if draft.enabled and Sharing.SelectionCount(draft)==0 then
            status:SetText('Tick Energy or Mass for an ally before applying.')
            status:SetColor('ffffc06a')
            return
        end
        Sharing.Save(Copy(draft)); popup:Close()
    end,30,true)
    Button(content,'Close',786,604,118,function() popup:Close() end,30)
    refresh()
end
