local UIUtil=import('/lua/ui/uiutil.lua')
local Layout=import('/lua/maui/layouthelpers.lua')
local Bitmap=import('/lua/maui/bitmap.lua').Bitmap
local Stamp=import('/mods/Microchip-Evil-Stamp/modules/stamp.lua')
local window

function Close()
    if window then
        RemoveInputCapture(window)
        window:Destroy()
        window=nil
    end
end

function Toggle()
    if window and not IsDestroyed(window) then Close(); return end
    local mouse=GetMouseScreenPos()
    -- Capture terrain positions before the menu takes focus or the camera moves.
    local prepared={mc=Stamp.Prepare('mc',mouse),husky=Stamp.Prepare('husky',mouse)}
    if not prepared.mc and not prepared.husky then return end
    window=Bitmap(GetFrame(0),UIUtil.UIFile('/scx_menu/panel-brd/panel_brd_m.dds'))
    local panel=window
    panel.Width:Set(410); panel.Height:Set(240)
    panel.Depth:Set(GetFrame(0):GetTopmostDepth()+10)
    panel.cover=UIUtil.CreateWorldCover(panel)
    panel.border=UIUtil.CreateSCXMenuPanelBorder(panel)
    local function text(value,size,y)
        local label=UIUtil.CreateText(panel,value,size,UIUtil.bodyFont)
        Layout.AtTopIn(label,panel,y); Layout.AtHorizontalCenterIn(label,panel)
        return label
    end
    text('Player Logo Stamps',22,8)
    text('Stamp at your original cursor position',14,40)
    local function button(label,y,callback)
        local control=UIUtil.CreateButtonStd(panel,'/scx_menu/small-btn/small',label,16,2)
        Layout.AtTopIn(control,panel,y); Layout.AtHorizontalCenterIn(control,panel)
        control.OnClick=callback
        return control
    end
    for _,choice in ipairs({{id='mc',label='MC Chip',y=70},{id='husky',label='Drunk Husky',y=120}}) do
        local id=choice.id
        local control=button(choice.label,choice.y,function()
            local drawing=prepared[id]
            Close()
            Stamp.Publish(drawing)
        end)
        if not prepared[id] then control:Disable() end
    end
    button('Cancel',180,Close)
    panel.HandleEvent=function(self,event)
        if event.Type=='KeyDown' and event.KeyCode==UIUtil.VK_ESCAPE then Close(); return true end
    end
    Layout.AtCenterIn(panel,GetFrame(0))
    AddInputCapture(panel)
end
