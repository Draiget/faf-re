-- Engine hook on /lua/userInit.lua (appended to FAF's file).
--
-- FAF's userInit.lua wraps DiskGetFileInfo with a cache that keeps every answer for the session, "no such file"
-- included. The launcher mounts maps and mods while the game runs (and takes them out again), so a map downloaded
-- after its scenario file was looked up stayed missing until a restart. This keeps the same cache, emptied by
-- DiskForgetFileInfo(), which the engine calls after each mount change; FafDisk_FileInfo is the engine's own lookup.

do
    local raw = rawget(_G, 'FafDisk_FileInfo')
    if raw then
        local cache = {}

        ---@param file FileName
        ---@return FileInfo | false
        function DiskGetFileInfo(file)
            if type(file) ~= 'string' then error('string expected but got ' .. type(file), 2) end
            local info = cache[file]
            if info == nil then
                info = raw(file) or false
                cache[file] = info
            end
            return info
        end

        function DiskForgetFileInfo()
            cache = {}
        end
    end
end
