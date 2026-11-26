# 工作负载机密分发与吊销庭

面向平台安全团队的离线云原生控制面模拟。项目只保存合成摘要、身份和回执，不保存真实机密，也不连接 KMS 或集群。Python 3.11+ 标准库与 SQLite 即可运行。

## 业务模型

- **材料版本库**保存机密用途、父版本、密封摘要、暴露案、来源证明和再密封案。首版可直接激活；后续版本先密封，必须证明源版本暴露、用途一致、摘要改变，并完成清退后才能激活。
- **用途授权簿**保存工作负载命名空间、实例 UID 与代际、用途策略、字段范围、环境、许可租期、两个角色的审批证据及吊销代际。同名实例重建冻结旧许可。
- **投递再密封台**在一个事务内固定多个实例的许可与 UID，逐成员保存投递或清退回执。外来回执、旧包摘要和超时许可不能补足缺失成员。暴露案关闭也不会自动恢复旧许可。

一次旧版本退役要同时满足：已投递的旧实例全部清退、未登记副本已隔离、新版本对相同实例完成投递。`close_reseal` 才会把旧版本改为 `retired`、新版本改为 `active`。未满足时返回具体阻断结论并保留原状态。

## 运行

在仓库根目录：

```sh
python -m secretcourt demo --db demo.sqlite
python -m secretcourt replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个子系统可单独调用；涉及上游身份与版本的样例在同一新数据库上按以下顺序运行：

```sh
python -m secretcourt material --db state.sqlite --fixture fixtures/material_normal.json
python -m secretcourt grant --db state.sqlite --fixture fixtures/grant_normal.json
python -m secretcourt delivery --db state.sqlite --fixture fixtures/delivery_normal.json
python -m secretcourt material --db state.sqlite --fixture fixtures/material_failure.json
python -m secretcourt grant --db state.sqlite --fixture fixtures/grant_failure.json
python -m secretcourt delivery --db state.sqlite --fixture fixtures/delivery_failure.json
python -m secretcourt report --db state.sqlite
python -m secretcourt replay --db state.sqlite
```

`demo` 执行同一顺序。六个 fixture 包含正常及改变业务结果的失败场景。事件日志保存完整输入和返回结论；`replay` 在空数据库中重新执行事件，再逐表比较持久化状态。

## 关键边界

1. 同代不同摘要、跳代密封或替换为相同材料摘要均不成立；关闭暴露案仍不能复活冻结的授权。
2. 许可限定实例 UID、身份代际、字段、环境和到期时间。吊销或身份代际更新会冻结尚未完成的投递计划。
3. 再密封过程中的旧副本、孤儿副本、新版缺回执分别给出不同阻断结论；清退回执必须有既存投递证据。迟到孤儿副本会重新打开清退案，将新版标为风险状态并冻结既有授权，隔离后才能再次关闭；冻结的授权不会自动恢复。重试同一计划或回执按身份幂等，冲突内容拒绝。

## 租户选择性证据包

`secretcourt/selective_archive.py` 不导出事件原始行，而是把账上每个事件降为三种可验证视图：

- **visible**：租户自己的事件原样披露，记录哈希可离线重算，内容无法被事后替换。
- **redacted**：同计划等共享事件。其他租户的字段被压成定宽加盐承诺，纳入选择性 Merkle 式树；树根与原记录哈希共同由当局 attestation 覆盖，证明披露字段正是原决策所用字段，且隐藏值、长度、稳定编号与跨包关联都不泄露。同计划的非本租户成员整体折叠为一个承诺槽，并以 decoy 填充到固定容量，隐藏成员数不可推断。
- **anchor**：窗口外或属于其他机密/租户的事件，只给出链式记录哈希，保持序列无缺口而不披露内容。

账本是记录哈希加链哈希构成的纯哈希链，链头作为可对外发布的检查点；attestation 使用带版本的 HMAC-SHA256 密钥，密钥轮换不影响旧包验证。导出资格由 **mandate** 绑定合同主体、用途、时间窗口与两角色审批，仅凭机密标识不能下载。吊销 mandate 只阻止新下载与新版本，已签收包凭公开密钥环永久可独立验签；迟到回执产生链接前驱包的不可变更正包，绝不重写旧包。`verify_package` 不访问平台数据库，离线即可对照公开检查点校验顺序、选择性根、决策谓词与 manifest 签名。

