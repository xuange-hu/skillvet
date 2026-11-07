# skillvet · 中文说明

[English README](README.md) · Agent skill / MCP 配置的静态安全审查。

**一句话**：给 agent 的指令文件也是输入。用**确定性规则**审它们，不再调一次 LLM
去判断另一段 LLM 指令有没有问题。

## 为什么存在

`CLAUDE.md`、`AGENTS.md`、`.cursorrules`、任意 `**/SKILL.md`，以及 `.mcp.json`
这类 MCP 清单，会被 agent 当作高优先级指令读取。于是攻击面从代码移到了文本：

- 隐藏 Unicode / Trojan Source：人眼看到的和模型读到的不是同一段文字；
- 指令里要求读取 `~/.ssh`、`~/.aws`、环境变量并外发；
- MCP 配置里 `npx` 拉未固定版本的包、`bash -c` 内联载荷、明文 `http://` 端点；
- `autoApprove` 一路放行。

让模型自己判断这些文本是否安全不可靠、不可复现、也不可进 CI。skillvet 是
22 条 Python 规则 + 零依赖核心：同样的输入永远给同样的结论，每条结论带
`文件:行号` 与命中的原文。

## 三步跑通

```bash
# 1) 安装（核心零运行时依赖）
pip install git+https://github.com/xuange-hu/skillvet

# 2) 看规则 / 跑自带演示（不联网，实测写出 4 个顶层条目）
skillvet rules
skillvet demo

# 3) 扫自己的仓库并接 SARIF
skillvet scan . --sarif results.sarif --fail-on high
```

`skillvet demo` 已在干净目录实测：`rc=0`，输出 133 行，生成 `demo-workspace/`；
随后 `skillvet scan ./demo-workspace` 即可看到命中。

## 差异化

| 能力 | 说明 |
|---|---|
| **确定性** | 22 条规则，不调 LLM，同输入同结论 |
| **证据式** | `文件:行号` + 原文片段，能复核而不是被信任 |
| **隐藏字符检测** | 双向控制符、零宽字符、bidi 覆盖（Trojan Source） |
| **原生 SARIF** | 2.1.0，直接进 GitHub Code Scanning |
| **MCP 6 工具** | `uvx --from "skillvet[mcp]" skillvet-mcp` |

## 命令

| 命令 | 作用 |
|---|---|
| `skillvet scan [PATH]` | 扫目录，默认当前目录 |
| `skillvet rules` | 列出规则集 |
| `skillvet mcp` | MCP server 辅助命令 |
| `skillvet demo` | 生成合成工作区并审查 |

退出码：`0` 干净或低于阈值、`1` 达到/超过 `--fail-on`、`2` 用法错误。

## 已知边界

- 静态审查，不执行 skill 里的脚本，也不连 MCP 服务器做运行时探测；
- 高优先级的自然语言越权指令靠特征规则识别，不是语义理解，会有漏报；
- 二进制文件与压缩附件不解析。

贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。MIT。
