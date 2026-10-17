# 无密钥反解 `typeDefinitions`（`tools/keyless.py`）—— 实测：7.1 成功，7.0 受限于基址召回

## 一、方法（不需要任何版本常量）

累计索引字段在"该类型没有这张表"时解出**哨兵**（-1 或 0），
所以 raw 列里会出现**大量重复的同一个 raw 值** `raw*`。由 `decoded = raw op K == sentinel` 反推：

```
xor : K = raw* ^ sentinel
add : K = sentinel - raw*      (mod 2^width)
sub : K = raw* - sentinel
```

**完全不需要 `slot_scan` 的候选**（绕开召回问题）。

判别用**连续性**（同表两字段自洽）：

```
fieldStart[i+1] - fieldStart[i] == field_count[i]
```

## 二、7.1 自测：成功 ✅

```
候选基址 434 个
=== 基址 0x92140  字段 5  连续性 0.729 ===      ← 真值
    +0x08 propertyStart      sub 0x76EF3A79     ✓ (= version.json)
    +0x0C methodStart        xor 0x4D8127F2     ✓
    +0x1C fieldStart         xor 0x29010897     ✓
    +0x36 nestedTypesStart   add 0x19E7         ✓
    +0x3C interfacesStart    xor 0x43DA         ✓
=== 基址 0x594846  字段 4  连续性 0.055 ===      ← 同构表，被连续性甩开 13 倍
```

**5 个密钥与 `version.json` 完全一致**，而且**没用任何版本常量**。

> 注意：`propertyStart` 同时给出 `add 0x8910C587` 和 `sub 0x76EF3A79`
> —— 二者 mod 2^32 等价；`version.json` 用的是 `sub` 形式。

## 三、7.0：失败 ✗ —— 卡在**基址召回**，不是密钥推导

```
候选基址 645 个
通过 >=2 字段的候选: 3 个，连续性全是 0
```

真 typeDefs 的基址**不在**这 645 个候选里 ✗（`slot_scan` 的 4 种形态没覆盖到它的读取点），
所以再强的推导也无从下手。

排除过的假设：

| 假设 | 实测 |
|---|---|
| 步长不是 70 | 试了 56/60/64/68/70/72/76/80/88/96，都不出现"5~6 字段 + 连续性>0.5" ✗ |
| 哨兵不是最频繁 raw | 改成 top-3 反而引入假阳性（真值掉出第一）✗ |
| 第二组连续性（methodStart×method_count）能加强 | 反而让垃圾组合也能过 ✗（已回退） |

## 四、下一步（明确的单一目标）

**把 7.0 的 typeDefs 基址找进候选**。可选：
1. 给 `slot_scan` 补**第 5 种读取形态**（用 IDA 在 7.0 上单点看它的读取点）
2. 用 `--anchor` 模式（基址必须来自 MHY 全局）在 7.0 上跑一遍
3. 从 `RuntimeInit` 的 typeDef 注册循环反推基址（消费者锚）

基址一旦进候选，`keyless.py` 在 7.1 上已验证的推导链就能直接复用 ✓

---

## 五、7.0 复盘（2026-10-17 追加）：**基址找到了，布局没解开**

### ✅ 7.0 的 `typeDefinitions` 基址 = `0x1986BEC`

用"最近签名算局部偏移"定位到 7.0 的对应代码（`0x140481F31`）：

```asm
mov   rdx, [rip + 0x5415220]          ; MHY 指针
movsxd rsi, dword ptr [rdx + 0x1a0]   ; ← slot 0x1A0
xor   rsi, 0x4ce7b502                 ; ← key
```

```
MHY[0x1A0] = 0x4D7FDEEE
^ 0x4CE7B502 = 0x1986BEC   ← typeDefinitionsOffset（7.0）
```

该值**确实在** `slot_scan` 的 645 个候选里 ✓，`keyless.py --base 0x1986BEC` 也能解出
`fieldStart add 0x98B73D5B`（span 442911）和 `eventStart add 0x66EC`（span 1085）✓

### ✗ 但 typeDef 的**字段布局变了**

按 4096 行采样做跨度匹配，初步映射像是：

```
propertyStart   0x08 -> 0x20
methodStart     0x0C -> 0x24
fieldStart      0x1C -> 0x2C
eventStart      0x34 -> 0x34   （未变）
interfacesStart 0x3C -> 0x3E
```

**但 fDV 交叉校验否决了它**：fDV 的 `fieldIndex`（7.0 在 `+8`，共 73818 个、范围 155..430272）
应全部落在某个类型的 `[fieldStart, fieldStart+field_count)` 内（预期 ~100%），实测：

| 候选 (累计,计数) | fDV 覆盖率 |
|---|---|
| `+0x2C / +0x3C` | **16.95%** |
| `+0x2C / +0x36` | 5.12% |
| `+0x24 / +0x36` | 20.90% |

→ 都远低于 100%，所以上面那张映射表**是错的**。

### 结论与下一步

- **基址已解决**（这是之前最大的堵点）✓
- **字段位移映射未解决** ✗ —— `fieldDecode.typeDef` 在 7.0 上不能沿用 7.1 的位移

下一步（明确）：
1. 用 IDA 在 `0x140481F31` 所在函数里看 `typeDef` 的**真实字段读取顺序**
   （7.1 是 +0x00/+0x08/+0x0C/+0x18/+0x1C/+0x20/+0x24/+0x28/+0x30/... ；
   7.0 很可能整体重排，需要逐字段确认）
2. 或者用 **`--all-disps` + fDV 覆盖率**做全组合搜索（累计位移 × 计数位移 × key 形式），
   覆盖率 ~100% 的那组就是 `fieldStart/field_count`
