import sys, perf_parse as pp
# passdiff.py <logA> <logB> [label] : per-pass CPU/GPU of the label step in two logs (B - A)
a,b=sys.argv[1],sys.argv[2]; lab=sys.argv[3] if len(sys.argv)>3 else 'meas1'
ra=pp.by_label(pp.parse(a)[0])[lab][0]; rb=pp.by_label(pp.parse(b)[0])[lab][0]
rows=[]
for n in set(ra['passes'])|set(rb['passes']):
    x=ra['passes'].get(n,(0,0)); y=rb['passes'].get(n,(0,0)); rows.append((y[1]-x[1],y[0]-x[0],n,x,y))
rows.sort(key=lambda r:-abs(r[0])-abs(r[1])*0.3)
for r in rows[:int(sys.argv[4]) if len(sys.argv)>4 else 12]: print('%-24s dGPU %+.3f dCPU %+.3f | A gpu %.3f cpu %.3f | B gpu %.3f cpu %.3f'%(r[2],r[0],r[1],r[3][1],r[3][0],r[4][1],r[4][0]))
for k in ('gpu','cpu','wall','draws','sc','kb'): print(k, round(ra[k],3), round(rb[k],3))
