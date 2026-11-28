-- Dynamic lights for scripts (sim side). Purely visual: nothing here changes the simulation, and every call behaves the same on every
-- client (a handle is always returned), so using lights cannot desync a game. Lights are not saved with a game.
--
--     local Light = import('/fafengine/lua/dynlights/light.lua')   -- a module: its functions are Light.Create, Light.Headlight
--
--     local lamp = Light.Create(unit, 'Turret', 1.0, 0.8, 0.5, 30, 1.0)  -- entity (or nil), bone (name, number, or nil = entity), r, g, b, radius, intensity
--     lamp:SetOffset(0, 1.5, 0)                                          -- in bone space
--     lamp:SetColour(0.2, 0.6, 1.0)                                      -- 0..1
--     lamp:SetRadius(50)                                                 -- world units
--     lamp:SetIntensity(1.5)                                             -- 0..100, 1 = a fully lit surface at the light
--     lamp:SetSpot(0, -0.1, 1, 35)                                       -- a spotlight along a bone-space direction, 35 degrees half angle
--     lamp:SetPosition(x, y, z)                                          -- world position of a light without an entity
--     lamp:Destroy()
--
--     Light.Headlight(unit)                                              -- a spotlight on the front of a vehicle
--
-- A light ends with its entity. The numbers are the same as the engine uses for the lights it makes from effects: the radius is where the
-- light fades out, the intensity is about the brightness of a muzzle flash at 1 and of a big explosion at 1.1 (the model never goes higher
-- than that for a flash, scripts may).
--
-- (An imported Moho module is its own global table: Create and Headlight below are what `import` hands back.)

local Methods = {}
Methods.__index = Methods

--- A light on a bone of an entity (or, with a nil entity, at a world position: see SetPosition).
function Create(entity, bone, r, g, b, radius, intensity)
    r, g, b = r or 1, g or 1, b or 1
    radius, intensity = radius or 20, intensity or 1
    local light = setmetatable({}, Methods)
    light.id = CreateLight(entity, bone, r, g, b, radius, intensity)
    light.r, light.g, light.b = r, g, b
    light.radius, light.intensity = radius, intensity
    return light
end

function Methods:SetColour(r, g, b)
    self.r, self.g, self.b = r, g, b
    return SetLight(self.id, r, g, b, self.radius, self.intensity)
end

function Methods:SetRadius(radius)
    self.radius = radius
    return SetLight(self.id, self.r, self.g, self.b, radius, self.intensity)
end

function Methods:SetIntensity(intensity)
    self.intensity = intensity
    return SetLight(self.id, self.r, self.g, self.b, self.radius, intensity)
end

function Methods:SetOffset(x, y, z)
    return SetLightOffset(self.id, x, y, z)
end

function Methods:SetPosition(x, y, z)
    return SetLightPosition(self.id, x, y, z)
end

--- A spotlight: it shines along (dx, dy, dz) in bone space and fades out at coneDegrees from that axis. coneDegrees <= 0 makes it a point light.
function Methods:SetSpot(dx, dy, dz, coneDegrees)
    return SetLightSpot(self.id, dx, dy, dz, coneDegrees)
end

function Methods:Destroy()
    local ok = DestroyLight(self.id)
    self.id = 0
    return ok
end

--- Headlights for a unit: a warm spotlight at the front, tilted slightly down. Options (all optional): bone, offset = {x, y, z} in bone space,
--- colour = {r, g, b}, radius, intensity, cone (degrees), tilt (how far the beam points down, 0 = level).
function Headlight(unit, options)
    options = options or {}
    local blueprint = unit:GetBlueprint()
    local length = (blueprint.SizeZ or 1.5)
    local height = (blueprint.SizeY or 1)
    local offset = options.offset or { 0, height * 0.6, length * 0.5 + 0.2 }
    local colour = options.colour or { 1.0, 0.93, 0.75 }
    local lamp = Create(unit, options.bone, colour[1], colour[2], colour[3], options.radius or 40, options.intensity or 1.2)
    lamp:SetOffset(offset[1], offset[2], offset[3])
    lamp:SetSpot(0, -(options.tilt or 0.12), 1, options.cone or 32)
    return lamp
end
