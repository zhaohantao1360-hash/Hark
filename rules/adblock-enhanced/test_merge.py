"""Offline regression, not Egern runtime. SPDX-License-Identifier: GPL-3.0-only."""
from pathlib import Path
import subprocess, json, importlib.util, tempfile, re
import yaml
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
class UniqueLoader(yaml.SafeLoader): pass
def mapping(loader,node,deep=False):
    result={}
    for k,v in node.value:
        key=loader.construct_object(k,deep=deep)
        assert key not in result, ('duplicate key',key)
        result[key]=loader.construct_object(v,deep=deep)
    return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
def load(text):return yaml.load(text,Loader=UniqueLoader)
def read_at(path,rev):return subprocess.check_output(['git','show',rev+':'+path],cwd=ROOT,text=True)
def import_path(path,name):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def cond(item,host):
    kind,value=next(iter(item.items()))
    m=value['match']
    if kind=='domain':return host==m
    if kind=='domain_suffix':return host==m or host.endswith('.'+m)
    if kind=='domain_keyword':return m in host
    if kind=='and':return all(cond(c,host) for c in m)
    if kind=='or':return any(cond(c,host) for c in m)
    if kind=='ip_cidr':return False # no IP resolution in host-only simulation
    raise AssertionError(kind)
def first_policy(rules,host):
    for r in rules:
        if cond(r,host):return next(iter(r.values()))['policy']
    return None

def main():
    manifest=json.loads((HERE/'sources.json').read_text()); rev=manifest['original_module_commit']
    before=load(read_at('BlockAdvertisers-hark.yaml',rev))
    after=load((ROOT/'BlockAdvertisers-hark.yaml').read_text())
    extra=load((ROOT/'rules/adblock-enhanced.yaml').read_text())
    assert len(before['rules'])==330 and after['rules'][:-1]==before['rules']
    assert {k:v for k,v in after.items() if k!='rules'}=={k:v for k,v in before.items() if k!='rules'}
    assert len(after['url_rewrites'])==4 and len(after['mitm']['hostnames']['includes'])==3
    tail=after['rules'][-1]['rule_set']
    assert tail['policy']=='REJECT' and tail['update_interval']==86400
    assert set(extra)=={'domain_set','domain_suffix_set'}
    entries=manifest['entries'];assert len(entries)==37 and len(extra['domain_suffix_set'])==31 and len(extra['domain_set'])==6
    assert len({(e['kind'],e['match']) for e in entries})==37
    for e in entries:
        assert e['source'] in manifest['sources']
        assert re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}',e['match'])
        assert e['match'] in extra['domain_suffix_set' if e['kind']=='domain_suffix' else 'domain_set']
    def hit(e,h):return h==e['match'] or (e['kind']=='domain_suffix' and h.endswith('.'+e['match']))
    def added(h):return any(hit(e,h) for e in entries)
    cases=0
    for e in entries:
        assert added(e['match']);assert hit(e,'test.'+e['match'])==(e['kind']=='domain_suffix')
        for h in [e['match']+'.example.org','not-'+e['match'],e['match']+'evil',e['match'].replace('.','-')]:assert not hit(e,h)
        cases+=6
    controls=['www.qq.com','login.weixin.qq.com','api.weixin.qq.com','wx.qq.com','qzs.qq.com','tpns.qq.com','www.baidu.com','pan.baidu.com','www.alipay.com','mapi.alipay.com','www.taobao.com','acs.m.taobao.com','img.alicdn.com','www.apple.com','www.icloud.com','api.bilibili.com','www.youtube.com','rr1.example.googlevideo.com','github.com','raw.githubusercontent.com','www.xiaomi.com','api.unity3d.com','x.com','api.x.com','api.twitter.com','pbs.twimg.com','www.douyin.com','www.kuaishou.com','p3-sign.byteimg.com','app.snssdk.com','init.sms.mob.com','sdkapi.sms.mob.com','code.sms.mob.com','sdk.verification.jiguang.cn','smartop-sdkapi.jiguang.cn','api.jpush.cn','sdk.openinstall.io','www.pinduoduo.com','images.pinduoduo.com','video-dsp.pddpic.com','tnc.example.snssdk.com']
    for h in controls:
        assert not added(h),('new control block',h)
        old=first_policy(before['rules'],h)
        new=old or ('REJECT' if added(h) else None)
        assert old==new
        cases+=1
    converter=import_path(ROOT/'scripts/kelee2egern.py','updated')
    original=(ROOT/'BlockAdvertisers-hark.yaml').read_text()
    assert converter.append_adblock_enhancement(original,'BlockAdvertisers-hark.yaml')==original
    oldtext=read_at('BlockAdvertisers-hark.yaml',rev)
    assert converter.append_adblock_enhancement(oldtext,'BlockAdvertisers-hark.yaml')==original
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);oldscript=td/'original.py';oldscript.write_text(read_at('scripts/kelee2egern.py',rev));oldconv=import_path(oldscript,'oldconv')
        fixture=td/'fixture.lpx';fixture.write_text('[Rule]\nDOMAIN,ads.example.org,REJECT\nDOMAIN,login.example.org,DIRECT\n[Rewrite]\nrequest if ${url} ~= /^https:\\/\\/ads.example.org\\// then reject(200)\n[MitM]\nhostname = ads.example.org\n')
        for m in converter.MODULES:
            args=(str(fixture),m['name'],m['desc'],m['author'],m['icon'])
            a=oldconv.convert(*args);b=converter.convert(*args);assert a==b
            if m['out']!='BlockAdvertisers-hark.yaml':assert converter.append_adblock_enhancement(b[0],m['out'])==a[0]
            else:
                result=converter.append_adblock_enhancement(b[0],m['out']);assert converter.append_adblock_enhancement(result,m['out'])==result
                assert load(result)['rules'][:-1]==load(a[0])['rules']
    assert load(converter.append_adblock_enhancement('name: test\n','BlockAdvertisers-hark.yaml'))['rules'][0]['rule_set']['policy']=='REJECT'
    print(f'PASS: 330 original rules/order, 4 rewrites, 3 MITM hosts and metadata preserved; 37 added conditions; {cases} matching cases incl {len(controls)} controls; 4 converter fixtures unchanged; target-only idempotent append.')
    print('NOT TESTED: Egern device/kernel or actual ad removal. Existing original blocks are retained, not endorsed as harmless.')
if __name__=='__main__':main()
