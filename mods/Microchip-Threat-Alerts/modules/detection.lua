-- Pure detector. Inputs must already be filtered to current direct enemy vision.
function Threat(bp)
    local cats = {}
    for _, category in ipairs(bp.Categories or {}) do cats[category] = true end
    if cats.NUKE and cats.STRATEGIC then return 'Strategic nuke', 1 end
    if cats.EXPERIMENTAL then return 'Experimental', 2 end
    if cats.STRUCTURE and cats.TECH3 and cats.ARTILLERY then return 'T3 artillery', 3 end
    if cats.STRUCTURE and cats.TECH3 and cats.ANTIMISSILE then return 'Strategic missile defence', 4 end
end
function New()
    local detector = {seen = {}, last = -100, count = 0}
    function detector:Update(visible, now)
        if now < self.last then self.seen, self.last, self.count = {}, -100, 0 end
        if now - self.last < 8 or self.count >= 2048 then return nil end
        local best
        for _, item in ipairs(visible or {}) do
            local kind, priority = Threat(item.blueprint or {})
            local pos = item.position
            if kind and item.id and not self.seen[item.id] and type(pos) == 'table'
                and type(pos[1]) == 'number' and type(pos[2]) == 'number' and type(pos[3]) == 'number'
                and pos[1] == pos[1] and pos[2] == pos[2] and pos[3] == pos[3]
                and math.abs(pos[1]) < 1000000 and math.abs(pos[2]) < 1000000 and math.abs(pos[3]) < 1000000 then
                if not best or priority < best.priority or (priority == best.priority and tostring(item.id) < tostring(best.id)) then
                    best = {id = item.id, kind = kind, priority = priority, position = {pos[1],pos[2],pos[3]},
                        name = (item.blueprint.General or {}).UnitName or item.blueprint.Description or kind}
                end
            end
        end
        if best then self.seen[best.id] = true; self.last = now; self.count = self.count + 1 end
        return best
    end
    return detector
end
return {New = New, Threat = Threat}
