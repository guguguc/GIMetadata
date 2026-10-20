# 去混淆名称比较工具使用说明

这里记录三个 Python 工具：

```text
tools/hook_old_name.py
tools/name_resolve.py
tools/name_stats.py
```

它们用于把旧 dump 的**真实名字**和当前 dump 的**混淆名字**做比较、候选匹配。
默认不需要 IDA 导出。

---

## 1. `hook_old_name.py`

### 作用

输入 7.1 hook 列表：

```text
hk.json
  hooks[].method   语义 hook 名
  hooks[].rva      7.1 方法 RVA
```

先在 7.1 dump 中找到真实类/方法/signature，再用它去旧 deobfuscated dump 模糊匹配。

流程：

```text
hk.json
  -> out/dump71.cs 查 RVA 对应的类/方法/shape
  -> dump/dump_deobfuscated.cs 模糊匹配类名 + 方法名 + shape
  -> 候选 JSON / TSV
```

### 用法

```bash
python3 tools/hook_old_name.py \
  --hooks hk.json \
  --structure-dump out/dump71.cs \
  --old-dump dump/dump_deobfuscated.cs \
  --out out/hk69_old_candidates.json \
  --tsv out/hk69_old_candidates.tsv
```

### 参数

```text
--hooks            hk.json
--structure-dump   7.1 dump.cs（提供 RVA 和 shape）
--old-dump         旧 deobfuscated dump.cs
--out              候选 JSON
--tsv              候选 TSV
--top              每个 hook 最多候选数，默认 5
--min-class        类名最低分，默认 0.72
--min-shape        方法 shape 最低分，默认 0.80
--class-shape      启用 REVIEW fallback
--review-tsv       输出 REVIEW-only TSV
```

`--class-shape` 包含两种 fallback：

```text
REVIEW_CLASS
  旧类名精确匹配，但旧方法名不同
  方法 shape/return 匹配

REVIEW_SHAPE
  旧类名不同，但类结构/字段/继承相似
  方法 return 必须完全一致
  参数签名允许模糊匹配
```

这些结果只写 REVIEW，不会升级成 EXACT。

示例：

```bash
python3 tools/hook_old_name.py \
  --hooks hk.json \
  --structure-dump out/dump71.cs \
  --old-dump dump/dump_deobfuscated.cs \
  --out out/hk69_old_candidates.json \
  --tsv out/hk69_old_candidates.tsv \
  --review-tsv out/hk69_old_review.tsv \
  --class-shape
```

当前 7.1 上 `REVIEW_CLASS` 有 6 条，`REVIEW_SHAPE` 为 0：

```text
InLevelMainPageContext_DoTeamCountDown_c_Iterator0__MoveNext
ItemModule_OnCheckAddItemExceedLimitNotify
LCAvatarCombat_IsSpecialEnergyMax
LCAvatarCombat_GetEnergy
InLevelCutScenePageContext_UpdateView
VCBaseSetDitherValue_set_ManagerDitherAlphaValue
```

`REVIEW_CLASS` 仍然可能语义不对，只是签名/返回类型接近。  
尤其：

```text
LCAvatarCombat_IsSpecialEnergyMax -> IsEnergyMax
LCAvatarCombat_GetEnergy          -> GetEnergyRatio
InLevelCutScenePageContext_UpdateView -> SetupView
```

必须人工确认，不能直接改成 EXACT。`REVIEW_SHAPE` 为 0 说明旧 dump 与 7.1 的类结构差异过大，没有达到阈值的异名类匹配。

### 结果说明

TSV 每行：

```text
hook
score
old_class
old_method
why
7.1 src_class
7.1 src_method
```

`score` 高不代表性语义一定正确。  
必须优先使用：

```text
旧类名 + 旧方法名精确存在
```

而不是只看分数。

---

## 2. `name_resolve.py`

### 作用

把旧 deobfuscated dump 的类/方法，映射到当前 dump 的混淆类/方法。

它使用：

```text
方法 shape 序列
字段 shape
继承/接口
方法数量
精确同名锚点
一对一 class 分配
```

### 用法

```bash
python3 tools/name_resolve.py \
  --src-dump dump/dump_deobfuscated.cs \
  --dst-dump out/dump67.cs \
  --out out/name_map67.json \
  --report out/name_map67_report.json
```

### 参数

```text
--src-dump   旧 deobfuscated dump
--dst-dump   当前版本 dump（6.7/7.0/7.1）
--anchors    已知旧类/旧方法 -> 目标类/方法的固定锚点 JSON
--out        完整映射 JSON
--report     统计报告 JSON
--assignment greedy / hungarian（默认 global max-weight）
--jobs       并行评分 worker 数
```

### 输出状态

```text
EXACT/assigned
  旧类名精确存在，或类/方法结构足够明确

REVIEW
  类或方法只有一个接近，需人工确认

UNRESOLVED
  当前旧 dump 没有可靠对应
```

注意：`name_resolve.py` 的第一版 shape 结果会包含误配，不能直接批量改名。
例如旧的 `Miscs` 里没有 `GetNyxCDLeft`，不能因为字符串相似就映射到 `GetNetworkIP`。

---

## 3. 审计结果

推荐先生成：

```text
out/hk69_old_candidates.tsv
out/name_map67.json
```

再生成人工审计表：

```text
out/hk69_old_audit.tsv
```

审计状态建议：

```text
EXACT       旧类 + 旧方法都明确存在
REVIEW      只有类或方法之一明确存在
UNRESOLVED  旧 dump 没有可靠对应
```

不要把 `score >= 0.9` 当成正确结论。  
当前已知的误配包括：

```text
Miscs_GetNyxCDLeft
Miscs_IsNyxSwitchAvatar
LCSelectPickup_AddInteeBtnByID
LCAvatarCombat_IsSpecialEnergyMax
LCAvatarCombat_GetEnergy
InLevelCutScenePageContext_UpdateView
```

这些应保留 `UNRESOLVED`，不要强行填一个旧名字。

---

## 4. `name_stats.py`

### 作用

统计 **7.1 源类里已经混淆、但旧 dump 有 EXACT 名字** 的类有多少。

它连接三个输入：

```text
hk.json                     hook 名 -> 7.1 rva
out/dump71.cs               7.1 rva -> 源类/方法
out/hk69_old_audit.tsv      hook -> 旧类/旧方法，状态
```

只统计 `status == EXACT` 的行。

混淆判定：

```text
类名不含 “.”
类名匹配 [A-Z]{8,}
```

例如：

```text
EEOBENOJNNN        -> 混淆
MoleMole.Miscs     -> 真名
Rewired.Player     -> 真名
```

### 用法

```bash
python3 tools/name_stats.py \
  --audit out/hk69_old_audit.tsv \
  --structure-dump out/dump71.cs \
  --hooks hk.json \
  --out out/name_stats71.json \
  --tsv out/name_stats71.tsv
```

### 输出

```text
out/name_stats71.json
out/name_stats71.tsv
```

JSON 包含：

```text
exact_hooks
rva_missing
hook_entries_obfuscated
hook_entries_real
unique_source_classes
unique_obfuscated_classes
unique_real_classes
obfuscated_classes
real_classes
```

当前 7.1 结果：

```text
EXACT hooks:                  46
RVA 缺失:                      1   (Camera_set_fieldOfView)

按 hook 条目:
  混淆源类:                   29
  真名源类:                   16

按唯一类:
  唯一源类:                   32
  混淆源类:                   22
  真名源类:                   10
```

注意：`hook_entries_real` 在 JSON 中会把「RVA 缺失、源类为空」也算成非混淆项；
看结果时要同时看 `rva_missing`。

---

## 5. 7.1 混淆类与旧 dump 的匹配统计

先跑旧 dump -> 7.1：

```bash
python3 tools/name_resolve.py \
  --src-dump dump/dump_deobfuscated.cs \
  --dst-dump out/dump71.cs \
  --out /tmp/opencode/name_map71_structural.json \
  --report /tmp/opencode/name_map71_structural_report.json
```

使用 coverage + global assignment + method anchors 后：

```text
7.1 dump 类:             96,561
其中混淆类:              45,577
其中真名类:              50,984

旧类 -> 7.1 assigned:     8,440
  -> 7.1 真名类:          7,557
  -> 7.1 混淆类:             883

assigned reason:
  exact-full:             5,833  (0 混淆)
  exact-simple:             409  (0 混淆)
  hook-anchor:               32  (22 混淆)
  shape:                  2,166  (861 混淆)

ambiguous 旧类:           6,986
unresolved 旧类:          2,761
```

已知 45 个 hook 类/方法锚点全部验证通过（Camera RVA 缺失 1 个）。
`883` 中只有 `22` 是 hook 锚点保证的；其余 `861` 是 coverage/shape 结果，仍需 REVIEW。

重要说明：

```text
88 是 structure/shape 级别 assigned，不是 exact 同名
旧真实名字不可能和 7.1 混淆名字 exact 相同
所以“旧名 -> 7.1 混淆类”的 exact 数量本质上是 0
```

`88` 只是旧类 shape 与 7.1 混淆类 shape 一对一分配后的结果，仍需 REVIEW。
`3,453` 是 ambiguous 候选里的唯一混淆目标，不是确认匹配。

旧 2023 dump 与 7.1 跨版本较远，类方法增减会导致 shape 匹配噪声明显。
要提高覆盖，需要更新的 deobfuscated dump，或对少量候选做 IDA/body 复核。

---

## 6. 不依赖 IDA

两个工具默认都只读：

```text
dump.cs
dump_deobfuscated.cs
```

不要求：

```text
IDA MCP
IDA export
sigs.json
sig gen/scan
```

只有后续需要验证调用点或函数体时，才对少量 `REVIEW/ambiguous` 项做定向 IDA 查询。

---

## 7. 旧 dump 的限制

`dump/dump_deobfuscated.cs` 是 2023 年旧版本 dump：

```text
类可能已删除、合并、改名
方法可能已拆分、内联、新增
字段布局可能变化
```

所以：

```text
EXACT 仍可能因版本差异需要复核
REVIEW/UNRESOLVED 不能靠字符串相似强行补全
```

最终目的是提供候选和人工审计依据，不是声称旧 dump 能 100% 翻译当前版本。
