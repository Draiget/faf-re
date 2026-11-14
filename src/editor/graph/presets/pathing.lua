-- Rough hills made pathable by the slope limit; the passable ground is labelled into connected regions and measured (select the Regions node and press Mask view or look at its numbers).
Graph = {
    ['name'] = 'Pathing check (slope limit, passable regions)',
    ['nextId'] = 7,
    ['nodes'] = {
        {
            ['id'] = 1,
            ['params'] = {
                ['basis'] = 'perlin',
                ['octaves'] = 5,
                ['persistence'] = 0.5,
                ['scale'] = 90,
                ['seed'] = 1,
            },
            ['type'] = 'ridged',
            ['x'] = 0,
            ['y'] = 0,
        },
        {
            ['id'] = 2,
            ['params'] = {
                ['hi'] = 35.69415,
                ['lo'] = 25,
            },
            ['type'] = 'range',
            ['x'] = 224,
            ['y'] = 0,
        },
        {
            ['id'] = 3,
            ['params'] = {
                ['balance'] = 0.5,
                ['limit'] = 0.75,
                ['margin'] = 0.02,
                ['mode'] = 'lower',
                ['strength'] = 1,
            },
            ['type'] = 'slope_limit',
            ['x'] = 448,
            ['y'] = 0,
        },
        {
            ['id'] = 4,
            ['params'] = {
                ['gain'] = 1,
                ['mode'] = 'replace',
                ['strength'] = 1,
            },
            ['type'] = 'out_height',
            ['x'] = 672,
            ['y'] = 0,
        },
        {
            ['id'] = 5,
            ['params'] = {
                ['class'] = '1',
                ['soft'] = 0.05,
                ['which'] = 'passable',
            },
            ['type'] = 'unit_slope',
            ['x'] = 672,
            ['y'] = 152,
        },
        {
            ['id'] = 6,
            ['params'] = {
                ['connectivity'] = '8',
                ['mode'] = 'size',
            },
            ['type'] = 'regions',
            ['x'] = 896,
            ['y'] = 152,
        },
    },
    ['seed'] = 15,
    ['version'] = 1,
    ['view'] = {
        ['x'] = 20,
        ['y'] = 20,
        ['zoom'] = 0.8,
    },
    ['wires'] = {
        {
            1,
            'out',
            2,
            'a',
        },
        {
            2,
            'out',
            3,
            'a',
        },
        {
            3,
            'out',
            4,
            'a',
        },
        {
            3,
            'out',
            5,
            'a',
        },
        {
            5,
            'out',
            6,
            'a',
        },
    },
}
