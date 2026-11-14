-- Hills whose steep parts are smoothed away, plus a view of the ground land units cannot cross (Mask view on the last node).
Graph = {
    ['name'] = 'Gentle hills made pathable (slope check)',
    ['nextId'] = 6,
    ['nodes'] = {
        {
            ['id'] = 1,
            ['params'] = {
                ['octaves'] = 5,
                ['persistence'] = 0.5,
                ['scale'] = 120,
                ['seed'] = 1,
            },
            ['type'] = 'simplex',
            ['x'] = 0,
            ['y'] = 0,
        },
        {
            ['id'] = 2,
            ['params'] = {
                ['hi'] = 47.61559,
                ['lo'] = 30,
            },
            ['type'] = 'range',
            ['x'] = 224,
            ['y'] = 0,
        },
        {
            ['id'] = 3,
            ['params'] = {
                ['preset'] = 'blocked',
            },
            ['type'] = 'mask_preset',
            ['x'] = 672,
            ['y'] = 152,
        },
        {
            ['id'] = 4,
            ['params'] = {
                ['radius'] = 2,
            },
            ['type'] = 'blur',
            ['x'] = 448,
            ['y'] = 0,
        },
        {
            ['id'] = 5,
            ['params'] = {
                ['gain'] = 1,
                ['mode'] = 'replace',
                ['strength'] = 1,
            },
            ['type'] = 'out_height',
            ['x'] = 672,
            ['y'] = 0,
        },
    },
    ['seed'] = 13,
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
            4,
            'a',
        },
        {
            4,
            'out',
            5,
            'a',
        },
        {
            4,
            'out',
            3,
            'a',
        },
    },
}
