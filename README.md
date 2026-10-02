# 可验证追加日志

零第三方依赖（Python 3.11+ 标准库）的透明追加日志，包含持久化服务和独立审计命令。

## 功能

- 每条记录落盘为：魔数、64 位长度、规范化 UTF-8 JSON、SHA-256 校验值。
- Merkle 叶节点和内部节点使用不同域前缀：
  - 叶节点：`SHA256(0x00 || record_bytes)`
  - 内部节点：`SHA256(0x01 || left_hash || right_hash)`
- 树头包含记录数、已提交日志字节数和根哈希，并通过临时文件 + `fsync` + 原子 rename 发布。
- 支持批量追加、按序号读取、历史/当前树的包含证明、旧树头到新树头的连续性证明。
- 追加由全局锁串行化，并发批量请求得到互不重叠的连续序号。
- 重启恢复规则：
  - 仅当最后的帧物理上未写完时，才截去该尾记录；
  - 校验值错误、已提交区域内截断、树头记录数/偏移/根不匹配均直接报错；
  - 已经完整写入并 `fsync`、但树头尚未发布的记录会在重启后重新发布，不能丢弃。
- `audit` 命令重复实现验证数学，不导入服务端 Merkle 代码，也不接受服务端“验证通过”之类结论。

## 启动服务

```bash
python3 -m verifiable_log serve --host 127.0.0.1 --port 8080 --data ./data
```

端口传 `0` 时，服务会在标准输出打印实际端口。

## 普通操作

```bash
# 批量追加；--file 和 --json 可重复
python3 -m verifiable_log append http://127.0.0.1:8080 \
  --json '{"event":"a"}' \
  --json '{"event":"b"}'

# 按序号取记录
python3 -m verifiable_log record http://127.0.0.1:8080 --index 0

# 当前树头
python3 -m verifiable_log tree-head http://127.0.0.1:8080
```

## 独立审计

```bash
# 拉取全部记录，逐条重新计算叶哈希和树根
python3 -m verifiable_log audit root http://127.0.0.1:8080

# 验证某条记录包含在当前树中
python3 -m verifiable_log audit inclusion http://127.0.0.1:8080 --index 3

# 验证记录 3 包含在历史大小为 10 的树中
python3 -m verifiable_log audit inclusion http://127.0.0.1:8080 \
  --index 3 --tree-size 10 --root-hash <历史树头中的 root_hash>

# 保存旧树头后，验证旧树是新树的前缀
python3 -m verifiable_log audit consistency http://127.0.0.1:8080 \
  --old-size 10 \
  --old-root <旧树头中的 root_hash>

# 指定历史新树头时，同时提供新大小和新根哈希
python3 -m verifiable_log audit consistency http://127.0.0.1:8080 \
  --old-size 10 --old-root <旧根> \
  --new-size 20 --new-root <新根>
```

审计失败时 JSON 输出 `"ok": false`，进程返回非零状态。

## HTTP API

- `POST /v1/records`：`{"records":[...]}`，批量原子进入服务追加顺序。
- `GET /v1/records/{index}`：按序号取规范化记录。
- `GET /v1/tree-head`：当前记录数和根哈希。
- `GET /v1/inclusion?index=N[&tree_size=M]`：包含证明。
- `GET /v1/consistency?old_size=N[&new_size=M]`：连续性证明。

## 崩溃注入

服务进程支持以下测试用环境变量：

```bash
VLOG_CRASH_AT=records_fsynced   # 记录 fsync 后、发布树头前退出
VLOG_CRASH_AT=head_written      # 临时树头 fsync 后、rename 前退出
VLOG_CRASH_AT=head_replaced     # rename 后、目录 fsync 前退出
VLOG_CRASH_AT=head_fsynced      # 树头发布完成后退出
```

进程以退出码 `99` 退出，用于模拟真实崩溃。

## 测试

```bash
python3 -m unittest discover -v -s tests
```

测试覆盖：

- 0–100 棵小树与独立朴素建树结果对拍；
- 所有小规模包含证明和连续性证明组合；
- 篡改证明必须拒绝；
- 并发批量追加序号唯一且连续；
- 中段/尾部完整记录损坏、错误根、提交偏移切帧均报错；
- 物理不完整尾记录仅截断一次；
- 真实子进程在“记录已写入”和“树头发布”之间崩溃后的恢复。
