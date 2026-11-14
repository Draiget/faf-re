-- Keep FAF's FPS sampling and toggle; adjust only its local display.
local originalShowFPS = ShowFPS
function ShowFPS()
    originalShowFPS()
    if not fps then return end

    fps:SetFont('Arial Black', 24)
    LayoutHelpers.AtLeftTopIn(fps, GetFrame(0), 10, 8)
    fps.Right:Set(function() return fps.Left() + fps.Width() end)

    if stdPanel then
        stdPanel:SetFont('Arial Black', 24)
        stdPanel.Left:Set(function() return fps.Right() + LayoutHelpers.ScaleNumber(12) end)
        stdPanel.Top:Set(function() return fps.Top() end)
        stdPanel.Right:Set(function() return stdPanel.Left() + stdPanel.Width() end)
    end
end
