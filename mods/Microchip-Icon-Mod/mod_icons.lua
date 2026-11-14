
UnitIconAssignments = {

    { BlueprintId = "xsl0303", IconSet = "icon_Othuum" }, ---- LAND T3
    { BlueprintId = "ual0303", IconSet = "icon_harb" },

    { BlueprintId = "xal0203", IconSet = "icon_hover2" }, ---- LAND T2
    { BlueprintId = "uel0203", IconSet = "icon_hover2" },
    { BlueprintId = "xsl0203", IconSet = "icon_hover2" },
    { BlueprintId = "url0203", IconSet = "icon_wagner" },
    { BlueprintId = "xel0209", IconSet = "icon_spark" },
    { BlueprintId = "drl0204", IconSet = "icon_range2" },
    { BlueprintId = "del0204", IconSet = "icon_range2" },

    { BlueprintId = "uaa0107", IconSet = "icon_aeontrans1" },   ---- Air

    { BlueprintId = "ueb1106", IconSet = "icon_MS1" },    ---- T1 Mass Storage
    { BlueprintId = "uab1106", IconSet = "icon_MS1" },
    { BlueprintId = "urb1106", IconSet = "icon_MS1" },
    { BlueprintId = "xsb1106", IconSet = "icon_MS1" },

    { BlueprintId = "ueb1303", IconSet = "icon_Fab3" },   ---- T3 Mass Fabricators
    { BlueprintId = "uab1303", IconSet = "icon_Fab3" },
    { BlueprintId = "urb1303", IconSet = "icon_Fab3" },
    { BlueprintId = "xsb1303", IconSet = "icon_Fab3" },

    { BlueprintId = "ueb1104", IconSet = "icon_Fab2" },   ---- T2 Mass Fabricators
    { BlueprintId = "uab1104", IconSet = "icon_Fab2" },
    { BlueprintId = "urb1104", IconSet = "icon_Fab2" },
    { BlueprintId = "xsb1104", IconSet = "icon_Fab2" },

    { BlueprintId = "uea0001", IconSet = "icon_drone" },    ---- UEF Drones
    { BlueprintId = "uea0003", IconSet = "icon_drone" },

    { BlueprintId = "ueb3101", IconSet = "icon_radar1" },   ----- T1, T2, T3. Radars
    { BlueprintId = "ueb3201", IconSet = "icon_radar2" },
    { BlueprintId = "ueb3104", IconSet = "icon_radar3" },
    { BlueprintId = "uab3101", IconSet = "icon_radar1" },
    { BlueprintId = "uab3201", IconSet = "icon_radar2" },
    { BlueprintId = "uab3104", IconSet = "icon_radar3" },
    { BlueprintId = "urb3101", IconSet = "icon_radar1" },
    { BlueprintId = "urb3201", IconSet = "icon_radar2" },
    { BlueprintId = "urb3104", IconSet = "icon_radar3" },
    { BlueprintId = "xsb3101", IconSet = "icon_radar1" },
    { BlueprintId = "xsb3201", IconSet = "icon_radar2" },
    { BlueprintId = "xsb3104", IconSet = "icon_radar3" },

    { BlueprintId = "xes0307", IconSet = "icon_neptune" },   ---- T3 Navy

    { BlueprintId = "urs0201", IconSet = "icon_destroyer" }, ---- T2 Navy
    { BlueprintId = "ues0201", IconSet = "icon_destroyer" },
    { BlueprintId = "uas0201", IconSet = "icon_destroyer" },
    { BlueprintId = "xss0201", IconSet = "icon_destroyer" },

    { BlueprintId = "xsl0401", IconSet = "icon_chicken" },      ----- Land Experimentals
    { BlueprintId = "xrl0403", IconSet = "icon_mega" },
    { BlueprintId = "url0402", IconSet = "icon_spider" },
    { BlueprintId = "uel0401", IconSet = "icon_fat" },
    { BlueprintId = "ual0401", IconSet = "icon_col" },
    { BlueprintId = "xsl0402", IconSet = "icon_storm" },

    { BlueprintId = "url0401", IconSet = "icon_scathis" },

    { BlueprintId = "xab1401", IconSet = "icon_para" },   ---- Game Enders
    { BlueprintId = "xab2307", IconSet = "icon_salvo" },
    { BlueprintId = "xsb2401", IconSet = "icon_yolo" },
    { BlueprintId = "ueb2401", IconSet = "icon_mavor" },

    { BlueprintId = "xea0002", IconSet = "icon_sat" },        ---- Other
    { BlueprintId = "xeb2402", IconSet = "icon_sat_station" },

    { BlueprintId = "ura0401", IconSet = "icon_bug" },       ---- Air EXP
    { BlueprintId = "uaa0310", IconSet = "icon_zar" },
    { BlueprintId = "xsa0402", IconSet = "icon_awasa" },

    { BlueprintId = "ues0401", IconSet = "icon_Atlantis" },    --- Navy EXP
    { BlueprintId = "uas0401", IconSet = "icon_tempest" },

 }

--- Entry point for scripted assignments. This function has a limited scope and any changes to the
-- units and / or the projectiles do not affect the game as they are deep-copied of the originals.
-- Functionality that is available:
--  - moho-log interaction: LOG, WARN, _ALERT, SPEW, error, assert
--  - debugging: repr
--  - iterators: pairs, ipairs, next
--  - typical statements: table, math (excluding math.random), string, tonumber, type, unpack, tostring
-- @param units All available unit blueprints.
-- @param projectiles All available projectile blueprints.
-- @param icons All the file names of the icons part of this mod.
function ScriptedIconAssignments (units, projectiles, icons)

    -- for performance
    local StringSub = string.sub
    local StringFind = string.find

    -- this is where we store the results
    local IconAssignments = {}
    -- loop over all the units
    for id, bp in units do

        -- retrieve the original strategic icon name
        local strategicIconName = bp.StrategicIconName
        -- this can be nil
        if strategicIconName then
            -- compute this once for all icons
            local target = "/" .. strategicIconName .. "_rest.dds"

            -- check if we have the same identifier in our icon folder
            local partOfIconsMod = false
            for k, icon in icons do
                if StringSub(icon, -9) == '_rest.dds' and StringFind(icon, target) then
                    partOfIconsMod = true
                    break
                end
            end

            -- if we do, use that instead
            if partOfIconsMod then
                IconAssignments[id] = { BlueprintId = id, IconSet = bp.StrategicIconName }
            end
        end
    end

    return IconAssignments
end
