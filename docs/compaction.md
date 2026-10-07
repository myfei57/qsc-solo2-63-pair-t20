# 命令日志分片压实（Sharded Log Compaction）设计

## 1. 要解决的问题

原持久化（`bagsort/store/store.py` + `snapshot.py`）把**整个**已提交命令日志序列化成一个 JSON
信封，每次 `persist()` 全量重写。随着命令增长：

- 启动重放越来越慢——要从头折叠全部命令；
- 快照越写越大、写放大趋近于「每命令一次全量状态拷贝」；
- 又不能直接删日志，否则无法回溯状态是怎么走到现在的。

本设计把单一增长日志改造成**分片命令日志 + 快照信封**：旧分片压实后只保留**摘要**，新命令照常追加到
活动分片；任意时点都能重放出与压实前**完全相同**的物化状态；被**取证保留**的记录绝不进压实；
每个分片都能脱离清单**单独校验**。

## 2. 磁盘布局

```
<state-dir>/
  manifest.json                 # 权威目录：分片引用 + 当前信封 + 哈希链
  manifest-history/             # 每次发布前归档的旧清单（只增审计）
  log-0000000000.shard          # 二进制分片；已密封的不可变
  log-0000000001.shard          # …
  snap-<seq>-<uuid>.env         # 快照信封（压实产物，自校验）
  holds.log                     # 取证保留登记簿（只增、哈希链）
  compaction/
    compact-<envid>.json        # 压实意图日志（崩溃恢复用；提交后删除）
```

### 2.1 分片格式（`shard.py`）

```
header  56B   magic(8) index(u64) seq_start(u64) prev_body_hash(32)
record*       magic(4) len(u32) flags(1) payload(len) crc32(4)
footer  240B  magic(8) index/seq_start/seq_end/entry_count/body_bytes(u64×5)
              body_hash prev_hash first_hash last_hash(32×4)
              state_before state_after(32×2)
```

- **记录级 CRC32**：覆盖 `flags + payload`，单帧损坏即定位；
- **分片体哈希 `body_hash`**：覆盖 header + 全部记录帧，密封时写入页脚；
- **记录哈希链**：`h_n = SHA256(h_{n-1} || SHA256(payload_n))`，页脚含 `first_hash/last_hash`；
- **分片哈希链**：每个分片 header 的 `prev_body_hash` 指向上一分片体哈希，跨分片防重排/防断裂；
- **状态锚点**：页脚保存折叠该分片前/后的 `state_before/state_after`（对 `State.as_dict()`
  规范化 JSON 取 SHA-256）。这是「压实前后状态完全一致」的逐片证明。

**已密封** = 页脚存在且 `body_bytes + FOOTER_SIZE == 文件长度` 且体哈希吻合，此后不可变。
**活动分片**没有页脚，最后一条记录允许是 *torn tail*（掉电写了一半），重开时识别并截断。

### 2.2 快照信封（`envelope.py`）

```
<canonical JSON body: 版本、信封 id、prev_envelope_id、seq_end、entry_count、
                       state_digest、hold_digest、各被压实分片的完整 summary、物化 state>
BAGSNAP1 <sha256(body)>     # 末尾一行校验尾
```

- 信封是压实**唯一新增**的数据：携带折叠后的**物化状态** + 每个被压实分片的**完整摘要**；
- 旧分片字节删除后，摘要仍在信封里（连续性、体哈希、记录链端点、状态摘要全部可核对）；
- 文件自身带校验尾，可**脱离 manifest 单独验证**（`read_envelope(...).verify()`）；
- `prev_envelope_id` 把多次压实串成链；`hold_digest` 冻结压实时刻的保留登记簿摘要。

### 2.3 清单（`manifest.py`）

原子发布（写临时文件 + fsync + `os.replace` + 目录 fsync），自身是哈希链：每次发布把
`prev_manifest_hash` 指向上一版内容哈希，旧版归档到 `manifest-history/`。它引用每个分片的完整
`ShardSummary`（`compacted` 标记 + `envelope_id`）、活动分片序号/计数、当前信封引用、以及累计写放大
统计（`total_appended_bytes`、`total_compacted_input_bytes`、`total_envelope_bytes`）。

## 3. 重放器：两条路径，一个答案（`replay.py`）

- **快路径（重启）**：校验信封体哈希与 `state_digest` → 直接取信封信物化状态为基线 →
  仅折叠 `seq_end` 之后仍存活的分片。恢复成本 = 「快照大小」+「快照后命令数」，不再随总历史线性增长。
- **全量校验（审计）**：在压实发生前可从 seq=1 折叠所有原始记录；压实后旧字节按设计删除，
  此时由信封内摘要链 + 信封状态摘要承担等价性锚点。

每次重放都会交叉核验，任何不符都抛 `Corruption`：

1. 信封外校验尾、体哈希与 manifest 引用一致；
2. 信封内摘要与 manifest 中对应分片摘要一致、`1..seq_end` 连续无空洞；
3. 每个存活分片：header magic、逐记录 CRC、记录链、体哈希、`prev` 链接；
4. 序号严格连续（`expected_seq`）；活动分片的 torn tail 被安全截断；
5. 每个密封分片折叠前/后的状态摘要与页脚一致——**逐片证明重放等价**。

「日志分片、快照信封和重放器互相印证」即指：分片自带链与状态锚点，信封固化分片摘要与终态，
manifest 同时引用两者并自链，重放器把三者逐一对账后才接受结果。

## 4. 崩溃安全（`log.py`）

状态迁移由一串**可持久化、有恢复规则**的小步骤组成，任何崩溃点都不会留下半个分片：

1. **追加**：记录帧先 fsync 落活动分片，再发布 manifest；崩溃产生的 torn tail 在打开时截断，
   manifest 的 `next_seq/active_committed_*` 据真实记录回退。
2. **滚动**：先密封旧分片（页脚 + fsync），再原子发布 manifest 声明它密封、清空活动槽。
   - 页脚在、manifest 未知 → 打开时**采纳**该密封分片并修正清单；
   - 无页脚、manifest 未知 → 滚动提交前的残留，**删除**；
   - 0 字节/不足 header 的活动残留 → 删除并把 `next_seq` 回退到密封前缀。
3. **压实（两阶段 + 意图日志）**：
   1. 严格重放待压实前缀，全部交叉校验通过后，写 `compaction/compact-<id>.json` **意图**；
   2. 信封写临时文件后原子改名；
   3. **唯一提交点**：原子发布 manifest（标记分片 `compacted`、登记信封引用）；
   4. 提交后删除输入分片字节、删除意图日志。

   恢复规则：意图在但 manifest 未指向信封且信封缺失/不自校验 → 作废清理；信封完好但未提交
   → 用意图补提交；已提交则幂等补做「删输入、删意图」。因此中途失败要么完全没发生、要么可补齐，
   **不存在半个分片**，且压实前后 `state_digest` 必须相同（`_fold_shard_indices` 逐片断言
   `state_before/state_after`）。

崩溃注入点（测试覆盖）：`before_active_create / before_frame_write / before_seal /
before_rollover_publish / before_intent / before_envelope_write / before_compact_publish /
after_commit`。

## 5. 取证保留（`holds.py`）

`holds.log` 是只增、哈希链的登记簿：`hold` / `release` 都是记录，释放也留痕，永不改写历史。

- 追加命令时可同时对某个 seq 落 hold（记录帧置 `RECORD_FLAG_HELD`，并写登记簿）；
- 压实只消费**前缀**。选择待压实分片时从最早开始，遇到第一个与任何**存活 hold** 区间相交的密封分片即
  **停止**（屏障）——因此被保留的命令及其所在分片的原始字节一定保留；
- `release` 后屏障解除，自动压实可把前缀折叠掉；`hold_digest` 进入信封，证明「压实时哪些保留生效」。

## 6. 触发策略与写放大代价（必读）

`TriggerPolicy` 同时提供两个信号，因为它们对**写放大**与**恢复时间**的影响相反：

| 信号 | 触发条件 | 恢复时间 | 写放大 |
|------|----------|----------|--------|
| `compact_bytes`（默认主信号） | 可压实密封分片累计字节达阈值 | 按字节上限约束快照后重放量 | 与实际磁盘占用挂钩，压实时批量更大，**较低** |
| `compact_entries`（默认 10000 的安全兜底） | 可压实命令数达阈值，与字节无关 | 按命令数严格约束重放预算，**稳定** | 小命令时仍按固定条数重写整份状态，**偏高** |

**写放大的本质**：每次压实都要重写**整份折叠状态**（信封），而不是增量。故单次压实的放大约为

```
WA_run ≈ envelope_bytes / compacted_input_bytes ≈ state_size / folded_shard_bytes
```

累计写放大 = `Σ envelope_bytes / Σ compacted_input_bytes`（manifest 中两个计数器直接给出）。

- **按条目数触发**：恢复预算按命令数恒定、可预测；但当命令很小、状态相对大时，压实批次按字节算很小，
  却仍重写整份状态，`state_size / input` 很大，写放大随命令变小而**无界上升**。
- **按磁盘占用触发**：等到确实攒够字节才压实，批次按字节足够大，`state_size / input` 被压低，写放大
  可控；代价是快照后可能残留较多「小命令」，恢复时要折叠的**条数**不固定（但字节量有界）。

基准（`shardlog bench` / `bench.py`，append-only 审计负载，2400 条，分片 4KB，
16KB vs 120 条两策略；下方为某次运行的示意值，`replay_ms` 随机器浮动，应看趋势）：

```
detail= 10B | bytes: runs=23 WA=10.41 replay_recs= 99 replay_ms~58 || count: runs=19 WA= 8.68 replay_recs= 24 replay_ms~28
detail=120B | bytes: runs=39 WA=19.37 replay_recs= 60 replay_ms~72 || count: runs=19 WA= 9.69 replay_recs=120 replay_ms~113
```

读数说明了权衡方向：条目触发把「重启要折多少条」钉死（小记录时恢复明显更快），但在记录变大后
恢复时间反超字节触发；字节触发把「为压实写多少字节」与真实占用绑定。注意两策略的累计 WA 在此负载下
都 >1，因为状态随审计单调增长、每次都要重写更大的整份状态——真正的差别在**触发节奏**：按条目会在
字节上尚未攒够时也强制重写。选择时应先明确「更在意重启条数预算还是写带宽/SSD 寿命」，并用 `bench`
以真实命令分布复测，而不是照搬默认值。

## 7. 与现有服务的集成

`bagsort/store/sharded_store.py` 提供与 `Store` 同接口的 `ShardedStore`：缓冲式 `Session`/提交/回滚
语义不变，提交时把每条命令镜像进分片日志，打开时从「信封 + 存活分片」重建。现有 `Plant` 与全部子系统
无需改动即可使用（见 `tests/shardlog/test_sharded_store.py`）。旧的全量 JSON `Store` 保留，二者并存。

操作 CLI（`python -m bagsort.store.shardlog`）：
`shards / snapshots / verify / replay / compact --force / hold / release / bench`。

## 8. 测试

`tests/shardlog/`（23 个用例，可在无 pytest 环境用
`python3 tools/run_shardlog_tests.py` 直接运行）：

- `test_shard.py`：分帧、CRC、密封、逐片独立校验、torn tail 截断、held 标志；
- `test_log_replay.py`：追加/滚动、多轮压实后重启等价、信封自校验、阈值阻断；
- `test_equivalence.py`：丰富命令（含墓碑/级联）压实前后状态逐位相同、摘要连续、manifest 哈希链；
- `test_holds.py`：保留屏障、释放后压实、错误案件拒绝、登记簿篡改被发现；
- `test_crash_recovery.py`：8 个崩溃点全部安全恢复、无半个分片、无残留意图；
- `test_sharded_store.py`：真实 `Plant` 持久化与重启等价、事务回滚。
