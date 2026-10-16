import re,sys,json
def q(s): return json.dumps(s,ensure_ascii=False)
def split_top(s):
    out=[];d=0;cur=''
    for ch in s:
        if ch=='(' :d+=1
        if ch==')' :d-=1
        if ch==',' and d==0: out.append(cur.strip());cur='';continue
        cur+=ch
    if cur.strip(): out.append(cur.strip())
    return out
MAP={'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword','IP-CIDR':'ip_cidr','IP-CIDR6':'ip_cidr6','URL-REGEX':'url_regex','USER-AGENT':'user_agent'}
def cond(expr):  # "(TYPE, val)" or "(OR, (...))"
    expr=expr.strip()
    assert expr[0]=='(' and expr[-1]==')',expr
    inner=expr[1:-1]
    parts=split_top(inner)
    t=parts[0]
    if t in('AND','OR','NOT'):
        subs=split_top(parts[1].strip()[1:-1])
        return {t.lower():[cond(x) for x in subs]}
    v=parts[1].strip().strip('"')
    return {MAP[t]:v}
def dump_cond(c,ind):
    k=list(c)[0];v=c[k];p=' '*ind
    if isinstance(v,list):
        s=f"{p}- {k}:\n{p}    match:\n"
        for x in v: s+=dump_cond(x,ind+6)
        return s
    return f"{p}- {k}:\n{p}    match: {q(v)}\n"
def rxfix(rx,ci): return ('(?i)' if ci else '')+rx.replace('\\/','/').replace('\\:',':')
def convert(src,name,desc,author,icon,dedupe=True,drop=()):
    txt=open(src,encoding='utf-8').read()
    sec=None;rules=[];rw=[];body=[];scripts=[];hosts=[];seen=set();stats={'dup':0,'redundant':0,'dropped':0}
    kw=[]
    for line in txt.splitlines():
        l=line.strip()
        if not l or l.startswith('#'): continue
        m=re.match(r'^\[(.+)\]$',l)
        if m: sec=m.group(1);continue
        if sec=='Rule':
            parts=split_top(l)
            t=parts[0]
            if t in('AND','OR','NOT'):
                subs=split_top(parts[1].strip()[1:-1])
                rules.append(('logic',t.lower(),[cond(x) for x in subs],parts[2]));continue
            val=parts[1].strip().strip('"');pol=parts[2].strip();nr=len(parts)>3 and 'no-resolve' in parts[3]
            key=(t,val.lower())
            if key in seen: stats['dup']+=1;continue
            seen.add(key)
            if val in drop: stats['dropped']+=1;continue
            if t=='DOMAIN-KEYWORD' and pol=='REJECT': kw.append(val.lower())
            elif t in('DOMAIN','DOMAIN-SUFFIX') and pol=='REJECT' and any(k in val.lower() for k in kw):
                stats['redundant']+=1;continue
            rules.append(('simple',MAP[t],val,pol,nr))
        elif sec=='Rewrite':
            m=re.match(r'^request if \$\{url\} ~= /(.+)/(i?) then (reject|reject_dict|reject_array|reject_img)\((\d+)\)$',l)
            if m:
                rx,ci,act,code=m.groups()
                loc={'reject':'http://reject/','reject_dict':'http://reject-dict/','reject_array':'http://reject-array/','reject_img':'http://reject-img/'}[act]
                if act=='reject' and code=='200': loc='http://reject-200/'
                rw.append((rxfix(rx,ci),loc)); continue
            m=re.match(r'^response if \$\{url\} ~= /(.+)/(i?) then response\.json\.delete\((.+)\)$',l)
            if m:
                rx,ci,arg=m.groups(); paths=json.loads(arg); paths=[paths] if isinstance(paths,str) else paths
                body.append(('response_jq',rxfix(rx,ci),'del('+', '.join('.'+x for x in paths)+')')); continue
            m=re.match(r'^response if \$\{url\} ~= /(.+)/(i?) then response\.json\.jq\((".*")\)$',l)
            if m:
                rx,ci,arg=m.groups(); body.append(('response_jq',rxfix(rx,ci),json.loads(arg))); continue
            m=re.match(r'^response if \$\{url\} ~= /(.+)/(i?) then response\.body\.replace\(/(.+)/, (".*")\)$',l)
            if m:
                rx,ci,find,rep=m.groups(); body.append(('response_regex',rxfix(rx,ci),find,json.loads(rep))); continue
            raise SystemExit('unsupported rewrite: '+l)
        elif sec=='Script':
            m=re.match(r'^(request|response) if \$\{url\} ~= /(.+)/(i?) then script\("([^"]+)"\)(?: with (.*))?$',l)
            if not m: raise SystemExit('unsupported script: '+l)
            kind,rx,ci,url,opts=m.groups(); opts=opts or ''
            tg=re.search(r'tag="([^"]+)"',opts)
            scripts.append(('http_'+kind,(tg.group(1) if tg else url.rsplit('/',1)[-1]),rxfix(rx,ci),url,'requires_body=true' in opts))
        elif sec=='MitM':
            hosts+= [h.strip() for h in l.split('=',1)[1].split(',') if h.strip()]
    o=f"name: {q(name)}\ndescription: {q(desc)}\nauthor: {q(author)}\nicon: {q(icon)}\n"+("\nrules:\n" if rules else "")
    for r in rules:
        if r[0]=='simple':
            _,k,v,pol,nr=r
            o+=f"  - {k}:\n      match: {q(v)}\n      policy: {pol}\n"+("      no_resolve: true\n" if nr else "")
        else:
            _,k,subs,pol=r
            o+=f"  - {k}:\n      match:\n"
            for c in subs: o+=dump_cond(c,8)
            o+=f"      policy: {pol.strip()}\n"
    if rw:
        o+="\nurl_rewrites:\n"
        for rx,loc in rw: o+=f"  - match: {q(rx)}\n    location: {q(loc)}\n"
    if body:
        o+="\nbody_rewrites:\n"
        for b in body:
            if b[0]=='response_jq': o+=f"  - response_jq:\n      match: {q(b[1])}\n      filter: {q(b[2])}\n"
            else: o+=f"  - response_regex:\n      match: {q(b[1])}\n      find: {q(b[2])}\n      replace: {q(b[3])}\n"
    if scripts:
        o+="\nscriptings:\n"
        for k,nm,rx,url,rb in scripts:
            o+=f"  - {k}:\n      name: {q(nm)}\n      match: {q(rx)}\n      script_url: {q(url)}\n"+("      body_required: true\n" if rb else "")
    if hosts:
        o+="\nmitm:\n  hostnames:\n    includes:\n"+''.join(f"      - {q(h)}\n" for h in hosts)
    return o,len(rules),len(rw),stats


UA="Loon/3.5.1 CFNetwork/1568 Darwin/24.0.0"
MODULES=[
  dict(url="https://kelee.one/Tool/Loon/Lpx/Block_HTTPDNS.lpx", out="Block_HTTPDNS-hark.yaml",
       name="HTTPDNS拦截器",
       desc="拦截常见 HTTPDNS 服务，让 App 走 Egern 的 DNS，所有去广告模块的依赖，请排在最前。源自可莉 Block_HTTPDNS.lpx（{date}），每周由 GitHub Actions 自动转换并去重。",
       author="可莉, VirgilClyne（Egern 原生版由 Hark 改写）",
       icon="https://raw.githubusercontent.com/luestr/IconResource/main/Other_icon/120px/HTTPDNS.png",
       drop=("186.76.76.200/32",), min_rules=20,
       extra_hosts=("ucdc-upaas.uc.cn","ucdc1-upaas.uc.cn","ucdc2-upaas.uc.cn","gslbali.ximalaya.com","cdn.wup.huya.com")),
  dict(url="https://kelee.one/Tool/Loon/Lpx/BlockAdvertisers.lpx", out="BlockAdvertisers-hark.yaml",
       name="广告平台拦截器",
       desc="拦截腾讯、字节、快手、百度、阿里、Google、AppLovin、Unity 等广告平台的请求，去广告模块的依赖，请排在最前。源自可莉 BlockAdvertisers.lpx（{date}），每周由 GitHub Actions 自动转换并去重。",
       author="可莉（Egern 原生版由 Hark 改写）",
       icon="https://raw.githubusercontent.com/luestr/IconResource/main/Website_icon/120px/TencentAd.png",
       drop=(), extra_hosts=(), min_rules=20),
  dict(url="https://kelee.one/Tool/Loon/Lpx/TXDocs_remove_ads.lpx", out="TXDocs_remove_ads-hark.yaml",
       name="腾讯文档去广告",
       desc="移除腾讯文档开屏广告、首页横幅推广。源自可莉 TXDocs_remove_ads.lpx（{date}），每周由 GitHub Actions 自动转换。",
       author="可莉（Egern 原生版由 Hark 改写）",
       icon="https://raw.githubusercontent.com/luestr/IconResource/main/App_icon/120px/TXDocs.png",
       drop=(), extra_hosts=(), min_rules=0, min_rewrites=2),
  dict(url="https://loon.103516.xyz/Plugin/WeChat.lpx", out="WeChat-hark.yaml",
       name="微信",
       desc="微信公众号、小程序去广告以及微信外部链接解锁。源自 loon.103516.xyz WeChat.lpx（{date}，整合可莉等作者规则），每周由 GitHub Actions 自动转换。",
       author="RuCu6, zZPiglet, blackmatrix7, zirawell, 可莉（Egern 原生版由 Hark 改写）",
       icon="https://raw.githubusercontent.com/sooyaaabo/IconLibrary/main/App/WeChat.png",
       drop=(), extra_hosts=(), min_rules=5, min_rewrites=50),
]

if __name__=="__main__":
    import urllib.request,tempfile,os,yaml
    for m in MODULES:
        req=urllib.request.Request(m["url"],headers={"User-Agent":UA})
        body=urllib.request.urlopen(req,timeout=60).read().decode("utf-8")
        if not re.match(r"#!name\s*=",body) or ("[Rule]" not in body and "[Rewrite]" not in body):
            sys.exit(f"unexpected content from {m['url']}: {body[:200]!r}")
        dm=re.search(r"^#!date\s*=\s*(.+)$",body,re.M); date=dm.group(1).strip() if dm else "unknown"
        with tempfile.NamedTemporaryFile("w",suffix=".lpx",delete=False,encoding="utf-8") as f:
            f.write(body); tmp=f.name
        o,n,r,s=convert(tmp,m["name"],m["desc"].format(date=date),m["author"],m["icon"],drop=m["drop"])
        os.unlink(tmp)
        if m["extra_hosts"]:
            if "\nmitm:\n" not in o: o+="\nmitm:\n  hostnames:\n    includes:\n"
            have=set(re.findall(r'^      - "([^"]+)"$',o,re.M))
            o+="".join(f'      - "{h}"\n' for h in m["extra_hosts"] if h not in have)
        yaml.safe_load(o)
        if n<m.get("min_rules",0) or r<m.get("min_rewrites",0): sys.exit(f"too few rules ({n}/{r}) for {m['out']}, refusing to write")
        open(m["out"],"w",encoding="utf-8").write(o)
        print(m["out"],date,n,"rules",r,"rewrites",s)
