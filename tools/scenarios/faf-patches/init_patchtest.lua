-- Init file for tools/scenarios/1p-faf-patches.yaml: the local-vault mpemu init
-- (init_mpemu_localvault.lua, next to this file in C:\ProgramData\FAForever\bin, where mpemu
-- reads init files from) plus the test's UI hook, tools/scenarios/faf-patches/hook, mounted at
-- /patchtest. Copy this file into C:\ProgramData\FAForever\bin; adjust the path below if the
-- repository is elsewhere.
dofile(InitFileDir .. '/init_mpemu_localvault.lua')

table.insert(hook, '/patchtest')
table.insert(path, { dir = 'G:/projects/faf-main/tools/scenarios/faf-patches/hook', mountpoint = '/patchtest' })
