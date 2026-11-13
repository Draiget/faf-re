import re,sys
import os
P=os.environ.get("FAF_PREFS_DIR", os.path.expandvars("%LOCALAPPDATA%/Gas Powered Games/Supreme Commander Forged Alliance")).replace(chr(92), "/")+"/"
src=open(P+"Game_tsuser.prefs",errors='replace').read()
def patch(text, changes):
    i=text.find("graphics_api = 'd3d12'")
    s=text.rfind("options = {",0,i)
    e=text.find("\n            },",i)
    blk=text[s:e]
    for k,v in changes.items():
        pat=re.compile(r"^(\s+)"+re.escape(k)+r" = .*?(,?)$",re.M)
        if pat.search(blk): blk=pat.sub(lambda m: m.group(1)+k+" = "+v+m.group(2),blk,count=1)
        else: blk=blk.replace("[''] = '',","[''] = '',\n                "+k+" = "+v+",",1)
    return text[:s]+blk+text[e:]
base={'vsync':'0','fps_limit':"'off'"}
user=dict(base)
off=dict(base); off.update({'dynlights_quality':"'off'",'particle_quality':"'full'",'soft_particles':"'off'",'ambient_occlusion':"'0'",
 'fxaa_on':'0','post_aa':"'off'",'sharpen_level':'0','sharpen_quality':"'off'",'grade_on':'0','bloom_wide_level':'0','render_scale':"'x100'",
 'taa':'0','atmosphere':'0','shadow_filter':"'off'",'water_quality':"'off'",'water_caustics':'0'})
# default profile: the engine defaults (feature keys removed would need a different mechanism; use registry defaults explicitly)
dflt=dict(base); dflt.update({'dynlights_quality':"'off'",'particle_quality':"'half'",'soft_particles':"'low'",'ambient_occlusion':"'-1'",'fxaa_on':'1','post_aa':"'fxaa'",
 'sharpen_level':'2','sharpen_quality':"'medium'",'grade_on':'1','bloom_wide_level':'0','texture_anisotropy':'2','render_scale':"'x100'",'taa':'0','atmosphere':'0','shadow_filter':"'off'"})
off_base=dict(off); off_base['ambient_occlusion']='0'  # placeholder
for name,ch in (('user',user),('off',off),('default',dflt),('off_base',off_base)):
    open(P+"Game_perf_%s.prefs"%name,'w',errors='replace').write(patch(src,ch))
print('ok')
