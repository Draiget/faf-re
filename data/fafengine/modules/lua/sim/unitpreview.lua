-- The changelog's game preview: a unit as it is now ("after") beside a copy with the changed values put back
-- ("before"), shooting at targets, each with its weapon's range drawn on the ground. The launcher starts a sandbox
-- skirmish with the game option FafrePreview = { unit = id, name =, version =, changes = { {label, old, new}, ... } };
-- the sim hook (fafengine/lua/simInit.lua) runs Run here, and the game UI's hook (fafengine/lua/ui/game/gamemain.lua)
-- lists what the preview shows (modules/lua/ui/game/unitpreview.lua).
--
-- Plan is shared by both: which changes the sim can put back on one unit, and which it can't (a cost isn't seen in a
-- fight; a value changed again later doesn't match the changelog's new value any more).

local kTolerance = 0.001

local function Normal(label)
    local text = string.gsub(string.lower(label or ''), '[^a-z]', '')
    return text
end

local function Same(a, b)
    return a ~= nil and b ~= nil and math.abs(a - b) <= kTolerance * math.max(1, math.abs(b))
end

local function MaxSpeed(bp)
    if bp.Air and bp.Air.MaxAirspeed and bp.Air.MaxAirspeed > 0 then
        return bp.Air.MaxAirspeed
    end
    return bp.Physics and bp.Physics.MaxSpeed
end

--- What the sim can put back, by the changelog's label (lower case, letters only): `weapon` reads a weapon
--- blueprint's value, `unit` the unit blueprint's; apply(unit, weapon, old, new) puts the old value on one unit.
local kRules = {
    range = { weapon = function(w) return w.MaxRadius end,
        apply = function(unit, weapon, old) weapon:ChangeMaxRadius(old) end },
    minimumrange = { weapon = function(w) return w.MinRadius end,
        apply = function(unit, weapon, old) weapon:ChangeMinRadius(old) end },
    damage = { weapon = function(w) return w.Damage end,
        apply = function(unit, weapon, old, new) weapon:AddDamageMod(old - new) end },
    rateoffire = { weapon = function(w) return w.RateOfFire end,
        apply = function(unit, weapon, old) weapon:ChangeRateOfFire(old) end },
    damageradius = { weapon = function(w) return w.DamageRadius end,
        apply = function(unit, weapon, old, new) weapon:AddDamageRadiusMod(old - new) end },
    turretyawspeed = { weapon = function(w) return w.TurretYawSpeed end,
        apply = function(unit, weapon, old) weapon:SetTurretYawSpeed(old) end },
    muzzlevelocity = { weapon = function(w) return w.MuzzleVelocity end,
        apply = function(unit, weapon, old)
            -- Each projectile leaves at the old speed (it is aimed for the new one, as the change made it).
            local create = weapon.CreateProjectileForWeapon
            weapon.CreateProjectileForWeapon = function(self, bone)
                local projectile = create(self, bone)
                if projectile and not projectile:BeenDestroyed() then
                    projectile:SetVelocity(old)
                end
                return projectile
            end
        end },
    speed = { unit = MaxSpeed, apply = function(unit, weapon, old, new) unit:SetSpeedMult(old / new) end },
    turnrate = { unit = function(bp) return bp.Physics and bp.Physics.TurnRate end,
        apply = function(unit, weapon, old, new) unit:SetTurnMult(old / new) end },
    acceleration = { unit = function(bp) return bp.Physics and bp.Physics.MaxAcceleration end,
        apply = function(unit, weapon, old, new) unit:SetAccMult(old / new) end },
    health = { unit = function(bp) return bp.Defense and bp.Defense.MaxHealth end,
        apply = function(unit, weapon, old)
            unit:SetMaxHealth(old)
            unit:SetHealth(unit, old)
        end },
    visionradius = { unit = function(bp) return bp.Intel and bp.Intel.VisionRadius end,
        apply = function(unit, weapon, old) unit:SetIntelRadius('Vision', old) end },
}
kRules.maxradius = kRules.range
kRules.minradius = kRules.minimumrange
kRules.aoe = kRules.damageradius
kRules.maxspeed = kRules.speed
kRules.maxhealth = kRules.health
kRules.hp = kRules.health
kRules.vision = kRules.visionradius
kRules.muzzlespeed = kRules.muzzlevelocity
kRules.projectilespeed = kRules.muzzlevelocity

local kCosts = {
    buildtime = true, masscost = true, energycost = true, buildcostmass = true, buildcostenergy = true,
    powercost = true, energymaintenance = true, powerdrain = true, energydrain = true, buildpower = true,
    buildrate = true,
}

--- Whether the preview can show a change named `label` at all (the launcher's cards offer it only then).
function Showable(label)
    return kRules[Normal(label)] ~= nil
end

--- The changes of `preview` against blueprint `bp`: { label, old, new, shown, why, rule, weapons = {labels} } each.
function Plan(preview, bp)
    local plan = {}
    for _, change in (preview.changes or {}) do
        local key = Normal(change.label)
        local rule = kRules[key]
        local item = { label = change.label, old = change.old, new = change.new, oldText = change.oldText,
            newText = change.newText, shown = false }
        if kCosts[key] then
            item.why = 'a cost or build time: not seen in a fight'
        elseif not rule then
            item.why = 'not put back in the preview'
        elseif rule.weapon then
            item.weapons = {}
            local now = nil
            for _, weapon in (bp.Weapon or {}) do
                local value = rule.weapon(weapon)
                now = now or value
                if Same(value, change.new) and weapon.Label then
                    table.insert(item.weapons, weapon.Label)
                end
            end
            if table.getn(item.weapons) > 0 then
                item.shown = true
                item.rule = rule
            else
                item.why = now and ('changed again later: now ' .. string.format('%.4g', now)) or 'the unit has no such weapon value'
            end
        else
            local now = rule.unit(bp)
            if Same(now, change.new) then
                item.shown = true
                item.rule = rule
            else
                item.why = now and ('changed again later: now ' .. string.format('%.4g', now)) or 'the unit has no such value'
            end
        end
        table.insert(plan, item)
    end
    return plan
end

--- The longest range of the unit's weapons that hit things (not its death or defence weapons), old and new.
local function Ranges(bp, plan)
    local new = 0
    local label = nil
    for _, weapon in (bp.Weapon or {}) do
        local category = weapon.WeaponCategory
        if weapon.MaxRadius and weapon.MaxRadius > new and category ~= 'Death' and category ~= 'Defense' and
            category ~= 'Teleport' and (weapon.Damage or 0) > 0 and not weapon.EnabledByEnhancement then
            new = weapon.MaxRadius
            label = weapon.Label
        end
    end
    local old = new
    for _, item in plan do
        if item.shown and item.rule == kRules.range then
            for _, weaponLabel in item.weapons do
                if weaponLabel == label then
                    old = item.old
                end
            end
        end
    end
    return old, new
end

------------------------------------------------------------------------------------------------------------------------
-- The sim's side.

local scene = { units = {}, targets = {} }

local function LandNear(x, z)
    for radius = 0, 60, 6 do
        for step = 0, 7 do
            local angle = step * math.pi / 4
            local px, pz = x + radius * math.cos(angle), z + radius * math.sin(angle)
            if GetSurfaceHeight(px, pz) <= GetTerrainHeight(px, pz) + 0.01 then
                return px, pz
            end
            if radius == 0 then
                break
            end
        end
    end
    return x, z
end

local function Clear()
    for _, list in { scene.units, scene.targets } do
        for _, unit in list do
            if unit and not unit.Dead and not unit:BeenDestroyed() then
                unit:Destroy()
            end
        end
    end
    scene.units, scene.targets = {}, {}
end

--- A target that takes hits for a while: a structure without weapons, its health raised so a fight lasts.
local function Target(x, z)
    local target = CreateUnitHPR('ueb1101', 'ARMY_2', x, GetTerrainHeight(x, z), z, 0, 0, 0)
    if target then
        target:SetMaxHealth(20000)
        target:SetHealth(target, 20000)
        target:SetCustomName('TARGET')
    end
    return target
end

--- The camera on the scene (again after the game's own start-up sequence, which moves it to the start position).
function MoveCamera()
    if scene.region then
        import('/lua/simcamera.lua').SimCamera('WorldCamera'):MoveTo(scene.region, 0)
    end
end

local function Build(preview)
    Clear()
    local id = preview.unit
    local bp = __blueprints[id]
    if not bp then
        WARN('UNIT PREVIEW: no blueprint ' .. tostring(id))
        return
    end
    local plan = Plan(preview, bp)
    local oldRange, newRange = Ranges(bp, plan)
    local reach = math.max(oldRange, newRange)
    local size = ScenarioInfo.size or { 256, 256 }
    local cx, cz = LandNear(size[1] / 2, size[2] / 2)
    -- Half the distance between the copies: about a range, so their rings overlap only a little.
    local apart = math.max(14, (bp.SizeX or 2) * 4, math.min(reach * 0.9, size[2] / 2 - 30))
    local left = cx - math.min(reach * 0.6, size[1] / 2 - 20)
    local copies = { { z = cz - apart, name = 'BEFORE', old = true }, { z = cz + apart, name = 'AFTER', old = false } }
    for _, copy in copies do
        local unit = CreateUnitHPR(id, 'ARMY_1', left, GetTerrainHeight(left, copy.z), copy.z, 0, math.pi / 2, 0)
        if unit then
            unit:SetCustomName(copy.name .. (copy.old and (preview.version and ('  (before ' .. preview.version .. ')') or '') or ''))
            if copy.old then
                for _, item in plan do
                    if item.shown then
                        if item.weapons then
                            for _, label in item.weapons do
                                local weapon = unit:GetWeaponByLabel(label)
                                if weapon then
                                    local ok, why = pcall(item.rule.apply, unit, weapon, item.old, item.new)
                                    if not ok then
                                        WARN('UNIT PREVIEW: ' .. item.label .. ': ' .. tostring(why))
                                    end
                                end
                            end
                        else
                            local ok, why = pcall(item.rule.apply, unit, nil, item.old, item.new)
                            if not ok then
                                WARN('UNIT PREVIEW: ' .. item.label .. ': ' .. tostring(why))
                            end
                        end
                    end
                end
            end
            table.insert(scene.units, unit)
            -- Its range ring, drawn by the game UI around the unit where it stands (Sync.FafrePreviewScene).
            copy.ring = { id = unit:GetEntityId(), range = copy.old and oldRange or newRange, before = copy.old }
            if reach > 0 then
                -- Within both ranges, so both fire; the rings show which reaches farther.
                local distance = math.max(6, math.min(oldRange, newRange) * 0.8)
                copy.target = { x = left + distance, z = copy.z }
                table.insert(scene.targets, Target(copy.target.x, copy.target.z) or false)
            end
        end
    end
    scene.copies = copies
    local rings = {}
    for _, copy in copies do
        if copy.ring then
            table.insert(rings, copy.ring)
        end
    end
    Sync.FafrePreviewScene = { rings = rings }
    -- The camera on the scene, with room on the left for the overlay's list (it covers about a third of the screen).
    local margin = 12
    local width = 2 * (reach + margin)
    local x0, x1 = left - reach - margin - width * 0.6, left + reach + margin
    local z0, z1 = cz - apart - reach - margin * 3, cz + apart + reach + margin * 3 -- the camera fits the width first
    scene.region = Rect(x0, z0, x1, z1)
    MoveCamera()
    local shown = 0
    for _, item in plan do
        shown = shown + (item.shown and 1 or 0)
    end
    LOG('UNIT PREVIEW: scene ready: ' .. id .. ' at ' .. math.floor(left) .. ', ' .. math.floor(cz) .. ', range ' ..
        tostring(oldRange) .. ' -> ' .. tostring(newRange) .. ', ' .. shown .. ' of ' .. table.getn(plan) .. ' changes put back')
end

--- Run(preview): the scene, then targets back up as they fall. No commanders: the preview's units only.
function Run(preview)
    scene.preview = preview
    WaitSeconds(0.5)
    Build(preview)
    local since = 0
    while true do
        WaitSeconds(1)
        since = since + 1
        if since == 3 or since == 6 then
            MoveCamera()
        end
        -- The commander warps in after the start (off the camera, at its start position): taken off once its warp-in
        -- thread is done with it, as that thread errors on a commander destroyed under it.
        if since >= 5 and since < 15 then
            local brain = GetArmyBrain('ARMY_1')
            for _, unit in (brain and brain:GetListOfUnits(categories.COMMAND, false) or {}) do
                local ours = false
                for _, mine in scene.units do
                    ours = ours or mine == unit
                end
                if not ours and not unit.Dead then
                    unit:Destroy()
                end
            end
        end
        for i, copy in (scene.copies or {}) do
            local target = scene.targets[i]
            if copy.target and (not target or target.Dead or target:BeenDestroyed()) then
                scene.targets[i] = Target(copy.target.x, copy.target.z) or false
            end
        end
    end
end

--- The fight again from the start (the overlay's Restart).
function Restart()
    if scene.preview then
        Build(scene.preview)
    end
end
