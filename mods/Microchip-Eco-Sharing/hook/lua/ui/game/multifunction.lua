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
        local label=UIUtil.CreateText(button,'ECO',10,UIUtil.bodyFont)
        label:SetColor('ffdeef72'); label:DisableHitTest()
        LayoutHelpers.AtBottomIn(label,button,3); LayoutHelpers.AtHorizontalCenterIn(label,button)
        label.Depth:Set(function() return button.Depth()+2 end)
        if IsObserver() then button:Disable() end
    end
end
