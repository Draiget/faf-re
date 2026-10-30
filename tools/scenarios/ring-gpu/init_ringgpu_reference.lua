-- Init file for tools/scenarios/1p-ringgpu-retail.yaml: init_ringgpu.lua plus hook-reference,
-- which puts the hook in reference mode (one screenshot per scene, no switches, no timing).
-- Copy this file and init_ringgpu.lua into C:\ProgramData\FAForever\bin; adjust the path below if
-- the repository is elsewhere.
dofile(InitFileDir .. '/init_ringgpu.lua')

table.insert(hook, '/ringgpuref')
table.insert(path, { dir = 'G:/projects/faf-main/tools/scenarios/ring-gpu/hook-reference', mountpoint = '/ringgpuref' })
