-- Init file for tools/scenarios/1p-uifix-main.yaml: the local-vault mpemu init plus the test's UI
-- hook, tools/scenarios/ui-fixes/hook, mounted at /uifix. Copy this file into
-- C:\ProgramData\FAForever\bin; adjust the path below if the repository is elsewhere.
dofile(InitFileDir .. '/init_mpemu_localvault.lua')

table.insert(hook, '/uifix')
table.insert(path, { dir = 'G:/projects/faf-main/tools/scenarios/ui-fixes/hook', mountpoint = '/uifix' })
