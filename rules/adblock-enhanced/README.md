# 广告平台增强规则（2026-10-20）

`BlockAdvertisers-hark.yaml` 仍是原入口，无需另装模块：

https://raw.githubusercontent.com/zhaohantao1360-hash/Hark/main/BlockAdvertisers-hark.yaml

在 Egern 更新原模块；末尾应出现“广告增强 v2.0.0”。新增引用会下载同仓库 `rules/adblock-enhanced.yaml`，缓存更新间隔为一天。首次获取需能访问 raw.githubusercontent.com；不需要额外证书。本模块原本有拼多多 URL 重写和三个 MITM 主机，这些保持原样，并未增加解密范围或启用任何设备设置。

## 合并范围

保留原330条规则及其顺序、DIRECT例外、4条URL重写、3个MITM主机和元数据。对增强版396项逐项比较，359项已被原有精确/后缀规则覆盖，不重复堆入；另以独立规则集添加37项（31个后缀、6个精确主机）。包括 Google Ad Services、腾讯广告文件、百度广告、快手广告以及阿里 Tanx / 汇川广告的补充覆盖。部分后缀扩展了原有精确主机匹配，不代表新增37个广告平台。

追加规则位于原规则之后，原有放行优先。原本已拦截的推送、统计、深链等规则没有删除，也不意味着这些原规则没有误伤风险。奖励广告、广告跳转可能受影响；功能异常可停用模块。不能保证移除与内容同域的广告，也不支持据此宣称X官方App推广已去除。

`scripts/kelee2egern.py` 仅增加广告模块的幂等引用追加步骤，使正常上游同步仍会带上增强规则。其他模块转换、工作流、调度及权限未变，未触发自动化。冻结的增强域名不会随上游可莉同步自动扩充。

## 来源与许可边界

增强内容来自 `zhaohantao1360-hash/wabi-workspace` 提交 `06d3b490f2c1287992136854df4bea48f0340e0b` 的固定来源清单。HaGeZi LIGHT部分 GPL-3.0-only；StevenBlack部分保留MIT许可。独立规则集及本目录对应增强数据采用GPL-3.0-only，完整文本见 LICENSE-GPL-3.0.txt；MIT归属见 THIRD-PARTY-LICENSE.txt，原始固定来源、哈希及逐项归属见 sources.json。没有给整个Hark仓库或原可莉转换模块重设许可。

## 验证与回退

运行 `uv run --no-project --with pyyaml==6.0.3 rules/adblock-enhanced/test_merge.py` 可作离线回归。只验证YAML结构、模拟域名匹配、原规则顺序及已知业务对照、同步追加幂等；不是Egern真机内核或实际广告效果测试。

如需回到本次合并前的原模块，可临时使用固定版本地址（之后不会自动更新）：
https://raw.githubusercontent.com/zhaohantao1360-hash/Hark/41c643fa28ad163822197098a5d0a1abdb77bdb8/BlockAdvertisers-hark.yaml
