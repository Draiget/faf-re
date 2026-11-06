-- Appended to the game's tooltip definitions by the existing engine hook loader.
-- The options dialog looks up options_<key>; an item's tip field is not used.
if Tooltips then
    Tooltips.options_splat_budget_tier = {
        title = 'Ground splat limit',
        description = 'Maximum ground splats drawn in each view, including tread marks. '
            .. 'At Medium/High fidelity: Original 2,499; Enhanced 10,000; Very high 25,000; Extreme 50,000. '
            .. 'At Low fidelity: 249; 1,000; 2,500; 5,000. '
            .. 'Applies after pressing Apply or OK, without restarting. '
            .. 'Higher limits use more memory and rendering time. Marks can still disappear when the selected limit '
            .. 'or available memory is exceeded. This does not change splat lifetime or every type of decal.',
    }
end
