local ecoPosition=table.getn(buttons.overlays)+1
for i, data in ipairs(buttons.overlays) do
    if data.id=='economy' then ecoPosition=i+1; break end
end
table.insert(buttons.overlays,ecoPosition, {
    id='microchip_eco_sharing', bitmap='economy', button=true, disableInReplay=true,
    tooltip={text='Microchip Eco Sharing',body='Share surplus above your reserves. Choose allies and Equal or Rank priority.'},
    OnClick=function() import('/mods/Microchip-Eco-Sharing/modules/panel.lua').Toggle() end,
})

local originalEcoSetLayout=SetLayout
function SetLayout(layout)
    originalEcoSetLayout(layout)
    -- Size the existing faction frame to its contents instead of letting added buttons escape it.
    local last=controls.overlayBtns[table.getn(controls.overlayBtns)]
    local ping=controls.pingBtns[table.getn(controls.pingBtns)]
    if last and controls.bg and controls.bg.panel then
        controls.bg.panel.Width:Set(function()
            local right=last.Right()
            for _, control in ipairs(controls.overlayBtns) do
                right=math.max(right,control.Right())
                if control.dropout then right=math.max(right,control.dropout.Right()) end
            end
            if ping then right=math.max(right,ping.Right()) end
            return right-controls.bg.panel.Left()+LayoutHelpers.ScaleNumber(14)
        end)
        controls.bg.Width:Set(controls.bg.panel.Width)
        if controls.collapseArrow:IsChecked() then
            controls.bg.Left:Set(function() return savedParent.Left()-controls.bg.Width()-LayoutHelpers.ScaleNumber(10) end)
        end
    end
end

local originalEcoCreate=Create
function Create(parent)
    originalEcoCreate(parent)
    local button=GetButton('microchip_eco_sharing')
    if button then
        local path='/mods/Microchip-Eco-Sharing/textures/'
        local width,height=button.Width(),button.Height()
        button:SetNewTextures(path..'button-up.dds',path..'button-down.dds',path..'button-over.dds',path..'button-up.dds')
        button:ApplyTextures()
        button.Width:Set(width); button.Height:Set(height)
        local logo=Bitmap(button,path..'logo.dds')
        logo.Width:Set(LayoutHelpers.ScaleNumber(25)); logo.Height:Set(LayoutHelpers.ScaleNumber(22))
        logo:DisableHitTest(); LayoutHelpers.AtTopIn(logo,button,3); LayoutHelpers.AtHorizontalCenterIn(logo,button)
        logo.Depth:Set(function() return button.Depth()+1 end)
        local label=UIUtil.CreateText(button,'ECO',9,UIUtil.bodyFont)
        label:SetColor('ffdeef72'); label:DisableHitTest()
        LayoutHelpers.AtBottomIn(label,button,3); LayoutHelpers.AtHorizontalCenterIn(label,button)
        label.Depth:Set(function() return button.Depth()+2 end)
        if IsObserver() then button:Disable() end
    end
end
