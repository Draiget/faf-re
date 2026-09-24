"""Adds the FAF_BONE_TEXTURE path to FAF's mesh.fx.

    python make_bonetex_meshfx.py <mesh.fx in> <mesh.fx out>

Every change is either inside `#ifdef FAF_BONE_TEXTURE` or a macro whose
non-FAF_BONE_TEXTURE expansion is the exact text it replaces, so an engine that
does not define the macro compiles the same shaders as before
(check_bonetex_meshfx.ps1 verifies that on the compiled listings).

The engine side is `HardwareMeshBatch`'s bone palette texture and
`CD3DEffect::InitEffectFromFile`, which defines FAF_BONE_TEXTURE for an effect
that mentions it on a device that can read float4 textures in a vertex
shader.

With FAF_BONE_TEXTURE defined the effect reads the skinning palette from a
vertex texture instead of the 80-entry constant arrays. That needs shader model
3 for every pass, which brings two fixed-function behaviours the shaders must
now reproduce themselves: linear table fog (not applied to 3.0 pixel shaders)
and the [0,1] clamp on vertex colour outputs (not applied by 3.0 vertex
shaders).
"""
import re
import sys

src_path, dst_path = sys.argv[1], sys.argv[2]
src = open(src_path, encoding='latin-1', newline='').read()
assert '\r\n' not in src, 'expected LF line endings'


def mask_comments(text):
    """Blanks out comments (keeping newlines) so offsets still match `text`."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith('//', i):
            j = text.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 1
            i = j + 1
        else:
            i += 1
    return ''.join(out)


def match_brace(text, open_index):
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    raise ValueError('unbalanced braces')


def split_top_level(params):
    parts, depth, cur = [], 0, ''
    for ch in params:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts]


mask = mask_comments(src)

# --- structs -----------------------------------------------------------------
structs = {}
for m in re.finditer(r'\bstruct\s+(\w+)\s*\{', mask):
    name = m.group(1)
    close = match_brace(mask, m.end() - 1)
    body = mask[m.end():close]
    members = re.findall(r'(\w+)\s+(\w+)\s*(?:\[\s*\d+\s*\])?\s*:\s*(\w+)\s*;', body)
    semi = mask.index(';', close)
    structs[name] = dict(open=m.end() - 1, close=close, end=semi + 1, members=members)

# --- functions ---------------------------------------------------------------
functions = {}
for m in re.finditer(
        r'(?m)^[ \t]*(\w+)[ \t]+(\w+)[ \t]*\(([^;{}]*?)\)[ \t\n]*(?::[ \t]*(\w+)[ \t\n]*)?\{', mask):
    rtype, name, params, sem = m.group(1), m.group(2), m.group(3), m.group(4)
    if rtype in ('return', 'else', 'if', 'for', 'while', 'switch', 'do', 'technique', 'pass'):
        continue
    open_index = m.end() - 1
    close = match_brace(mask, open_index)
    functions.setdefault(name, []).append(
        dict(rtype=rtype, params=params, sem=sem, open=open_index, close=close, start=m.start()))

vs_entries = set(re.findall(r'VertexShader\s*=\s*compile\s+\w+\s+(\w+)\s*\(', mask))
ps_entries = set(re.findall(r'PixelShader\s*=\s*compile\s+\w+\s+(\w+)\s*\(', mask))


def single(name):
    defs = functions.get(name)
    assert defs, 'no definition for ' + name
    assert len(defs) == 1, 'overloaded entry function ' + name
    return defs[0]


# Entry functions must not be called from other functions: wrapping a pixel
# shader's returns would fog its output twice if another shader reused it.
for name in ps_entries:
    for other, defs in functions.items():
        if other == name:
            continue
        for d in defs:
            if re.search(r'\b%s\s*\(' % re.escape(name), mask[d['open']:d['close']]):
                raise SystemExit('pixel shader %s is called from %s' % (name, other))

vs_output_structs = set()
vs_input_structs = set()
for name in vs_entries:
    d = single(name)
    assert d['rtype'] in structs, 'VS %s returns %s' % (name, d['rtype'])
    vs_output_structs.add(d['rtype'])
    for p in split_top_level(d['params']):
        words = p.replace('uniform', '').split()
        if words and words[0] in structs:
            vs_input_structs.add(words[0])

ps_input = {}
for name in ps_entries:
    d = single(name)
    assert d['rtype'] in ('float4', 'half4'), 'PS %s returns %s' % (name, d['rtype'])
    names = []
    for p in split_top_level(d['params']):
        words = p.replace('uniform', '').split()
        if words and words[0] in structs:
            names.append((words[0], words[1]))
    assert len(names) == 1, 'PS %s has %d struct inputs' % (name, len(names))
    ps_input[name] = names[0]

fog_structs = vs_output_structs | {t for t, _ in ps_input.values()}
assert not (fog_structs & vs_input_structs), 'struct used as a VS input: %s' % (fog_structs & vs_input_structs)
for s in fog_structs:
    sems = [sem.upper() for _, _, sem in structs[s]['members']]
    assert 'TEXCOORD8' not in sems, s
    assert any(sem.startswith('POSITION') for sem in sems), 'no position in ' + s

# --- edits -------------------------------------------------------------------
edits = []  # (start, end, replacement)


def replace_span(start, end, text):
    edits.append((start, end, text))


def insert_at(pos, text):
    edits.append((pos, pos, text))


def line_end(pos):
    return src.index('\n', pos) + 1


HEADER = r'''
/// Bone palette texture
///
/// An engine that can read textures in the vertex shader defines FAF_BONE_TEXTURE
/// when it compiles this effect and uploads the skinning palette as a texture
/// instead of the transPalette/rotPalette constants. The constants hold 80 bones,
/// which caps how many skinned meshes a draw call can instance (four ACUs, for
/// example); the texture has no such cap. Without FAF_BONE_TEXTURE the effect is
/// compiled exactly as before.
///
/// Vertex texture reads need shader model 3, and Direct3D 9 pairs a 3.0 vertex
/// shader only with a 3.0 pixel shader, so every pass is compiled as 3.0. That
/// loses two things the fixed-function pipeline did for the 2.0 shaders, which
/// the shaders do themselves instead: the linear distance fog (ApplyDistanceFog)
/// and the clamp of vertex colour outputs to [0,1] (the Finish<struct>
/// functions, one per vertex output struct, since the compiler cannot overload
/// on structs that share a layout).
#if defined(FAF_BONE_TEXTURE) && defined(DIRECT3D10)
    #undef FAF_BONE_TEXTURE
#endif

#ifdef FAF_BONE_TEXTURE
    #define vs_1_1 vs_3_0
    #define vs_2_0 vs_3_0
    #define ps_2_0 ps_3_0
    #define ps_2_a ps_3_0
    #define ps_2_b ps_3_0

    /// The engine splits each instance's 16-bit palette base over anim.x (high
    /// byte) and anim.y (low byte).
    #define BONE_INDEX_T float
    #define BONE_INDEX(anim, boneIndex) ((anim).x * 256 + (anim).y + (boneIndex)[0])
    #define PALETTE_SCALE(index) FetchBoneTranslation(index).w
    #define FOG_DEPTH_MEMBER float2 fogDepth : TEXCOORD8;
    #define FINISH_VERTEX(type, vertex) Finish##type(vertex)
    #define FINISH_PIXEL(color, vertex) ApplyDistanceFog((color), (vertex).fogDepth)
    #define NULL_PIXEL_SHADER compile ps_3_0 NoColorPS()
#else
    #define BONE_INDEX_T int
    #define BONE_INDEX(anim, boneIndex) (anim.y + boneIndex[0])
    #define PALETTE_SCALE(index) transPalette[index].w
    #define FOG_DEPTH_MEMBER
    #define FINISH_VERTEX(type, vertex) (vertex)
    #define FINISH_PIXEL(color, vertex) (color)
    #define NULL_PIXEL_SHADER null
#endif
'''

PARAMETERS = r'''
#ifdef FAF_BONE_TEXTURE
/// The skinning palette, two texels per bone - translation (w = scale), then
/// the rotation quaternion - packed row after row.
texture     boneTexture;
/// 1 / width, 1 / height, width; set by the engine along with the texture.
float4      boneTextureSize = float4(1.0 / 1024.0, 1.0, 1024.0, 0.0);
/// The engine's distance fog, as the fixed-function pipeline would apply it:
/// end / (end - start), 1 / (end - start), and 1 when the fog distance is the
/// eye distance (w) rather than the depth. (1, 0, 1) is no fog.
float4      fogParams = float4(1.0, 0.0, 1.0, 0.0);
float3      fogColor = float3(0.0, 0.0, 0.0);

sampler2D boneSampler = sampler_state
{
    Texture   = (boneTexture);
    MipFilter = NONE;
    MinFilter = POINT;
    MagFilter = POINT;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
#endif
'''

PALETTE_FUNCTIONS = r'''/// ComputePaletteMatrix
///
/// Compute matrix from an index into the bone palette.
#ifdef FAF_BONE_TEXTURE
float4 BoneTexcoord( float index)
{
    float texel = index * 2;
    float row = floor( texel * boneTextureSize.x);
    return float4(( texel - row * boneTextureSize.z + 0.5) * boneTextureSize.x, ( row + 0.5) * boneTextureSize.y, 0, 0);
}

float4 FetchBoneTranslation( float index)
{
    return tex2Dlod( boneSampler, BoneTexcoord( index));
}

float4x4 ComputePaletteMatrix( float index)
{
    float4 texcoord = BoneTexcoord( index);
    float4 translation = tex2Dlod( boneSampler, texcoord);
    texcoord.x += boneTextureSize.x;
    return ComputeMatrix( translation.w, translation.xyz, tex2Dlod( boneSampler, texcoord));
}

/// ApplyDistanceFog
///
/// Linear table fog, which Direct3D 9 applies after 2.0 pixel shaders but not
/// after 3.0 ones: blend towards the fog colour by eye distance (or by depth
/// when the projection is not w-based).
float4 ApplyDistanceFog( float4 color, float2 fogDepth)
{
    float distance = ( fogParams.z > 0.5) ? fogDepth.y : fogDepth.x / fogDepth.y;
    color.rgb = lerp( fogColor, color.rgb, saturate( fogParams.x - distance * fogParams.y));
    return color;
}

/// NoColorPS
///
/// Stands in for the null pixel shader of the stencil and depth-only passes;
/// Direct3D 9 does not allow a null pixel shader with a 3.0 vertex shader.
float4 NoColorPS() : COLOR0
{
    return float4( 0, 0, 0, 0);
}
#else
float4x4 ComputePaletteMatrix( int index)
{
    float4 translation = transPalette[index];
    return ComputeMatrix( translation.w, translation.xyz, rotPalette[index]);
}
#endif
'''

# a. feature macros after the BONE_MAXIMUM define
m = re.search(r'(?m)^#define BONE_MAXIMUM[^\n]*\n', src)
insert_at(m.end(), HEADER)

# b. texture, fog constants and sampler after the palette constants
m = re.search(r'(?m)^float4\s+rotPalette\[BONE_MAXIMUM\];\n', src)
insert_at(m.end(), PARAMETERS)

# c. palette functions
m = re.search(
    r'/// ComputePaletteMatrix\n///\n/// Compute matrix from an index into the bone palette\.\n'
    r'float4x4 ComputePaletteMatrix\( int index\)\n\{\n'
    r'    float4 translation = transPalette\[index\];\n'
    r'    return ComputeMatrix\( translation\.w, translation\.xyz, rotPalette\[index\]\);\n\}\n', src)
assert m, 'ComputePaletteMatrix not found'
replace_span(m.start(), m.end(), PALETTE_FUNCTIONS)

m = re.search(r'float4x4 ComputeWorldMatrix\( int index,', src)
assert m
replace_span(m.start(), m.end(), 'float4x4 ComputeWorldMatrix( BONE_INDEX_T index,')

# d. palette index expressions
index_sites = [m for m in re.finditer(r'anim\.y ?\+ ?boneIndex\[0\]', mask)]
for m in index_sites:
    replace_span(m.start(), m.end(), 'BONE_INDEX(anim, boneIndex)')

# e. the two direct scale reads
bone_decls = list(re.finditer(r'int bone = (?=anim\.y ?\+ ?boneIndex\[0\];)', mask))
for m in bone_decls:
    replace_span(m.start(), m.end(), 'BONE_INDEX_T bone = ')
scale_reads = list(re.finditer(r'transPalette\[bone\]\.w', mask))
for m in scale_reads:
    replace_span(m.start(), m.end(), 'PALETTE_SCALE(bone)')
assert len(bone_decls) == len(scale_reads) == 2, (len(bone_decls), len(scale_reads))

# f/g. fog member in every shader-stage struct, FinishVertex after it
for name in sorted(fog_structs, key=lambda s: structs[s]['open']):
    s = structs[name]
    close_line = src.rindex('\n', 0, s['close']) + 1
    insert_at(close_line, '    FOG_DEPTH_MEMBER\n')
    if name not in vs_output_structs:
        continue
    color_lines = ''.join(
        '    vertex.%s = saturate( vertex.%s);\n' % (member, member)
        for _, member, sem in s['members'] if sem.upper().startswith('COLOR'))
    insert_at(line_end(s['end'] - 1),
              '\n#ifdef FAF_BONE_TEXTURE\n'
              '%s Finish%s( %s vertex)\n'
              '{\n'
              '    vertex.fogDepth = vertex.position.zw;\n'
              '%s'
              '    return vertex;\n'
              '}\n'
              '#endif\n' % (name, name, name, color_lines))

# h/i. entry-function returns
return_re = re.compile(r'\breturn\b\s*(.*?)\s*;', re.S)
vs_returns = ps_returns = 0
for name in sorted(vs_entries | ps_entries):
    d = single(name)
    body_start, body_end = d['open'] + 1, d['close']
    for r in return_re.finditer(mask, body_start, body_end):
        expr_start, expr_end = r.start(1), r.end(1)
        expr = src[expr_start:expr_end]
        assert expr and ';' not in expr
        if name in vs_entries and name in ps_entries:
            raise SystemExit('%s is both a vertex and a pixel shader' % name)
        if name in vs_entries:
            replace_span(expr_start, expr_end, 'FINISH_VERTEX(%s, %s)' % (d['rtype'], expr))
            vs_returns += 1
        else:
            replace_span(expr_start, expr_end, 'FINISH_PIXEL(%s, %s)' % (expr, ps_input[name][1]))
            ps_returns += 1

# j. null pixel shaders
null_ps = list(re.finditer(r'PixelShader\s*=\s*null\s*;', mask))
for m in null_ps:
    replace_span(m.start(), m.end(), 'PixelShader = NULL_PIXEL_SHADER;')

# --- apply -------------------------------------------------------------------
edits.sort(key=lambda e: (e[0], e[1]))
for a, b in zip(edits, edits[1:]):
    assert a[1] <= b[0], ('overlapping edits', a[:2], b[:2])
out = src
for start, end, text in reversed(edits):
    out = out[:start] + text + out[end:]
open(dst_path, 'w', encoding='latin-1', newline='').write(out)

print('structs with fog member:', len(fog_structs), sorted(fog_structs))
print('VS entries: %d (%d returns)  PS entries: %d (%d returns)' % (
    len(vs_entries), vs_returns, len(ps_entries), ps_returns))
print('palette index sites: %d  null pixel shaders: %d' % (len(index_sites), len(null_ps)))
