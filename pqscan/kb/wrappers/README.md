# Wrapper Contracts KB

## 概述

封装规则 = APIs 规则 + derived_meta，复用现有的：
- 参数抽取（func_params、semantic）
- ctx 状态追踪（ctx_write/ctx_read）
- common_profiles 判定流程

**核心设计原则**：不重复维护约束，从 common_profiles 获取量子/经典安全阈值。

## 规则分层

- `kb/apis/*.json` - 基础 API 映射（官方库/常见库）
- `kb/wrappers/*.json` - 手工预置的封装契约（**本目录**）
- `kb/derived/*.json` - 运行时自动派生的封装规则（与 wrappers 同 schema）

## Schema 定义

### APIs 同构部分（必须复用）

```json
{
  "api_id": "wrap.c.mylib.my_rsa_keygen",
  "language": "c",
  "library": "mylib",
  "function": "my_rsa_keygen",
  "func_params": ["keylen"],
  "imports": ["mylib.h"],
  "semantic": {
    "profile_id": "ALG.RSA.PKE",
    "operation": "keygen",
    "key_bits": { "from_param": "keylen", "unit": "bytes", "transform": "*8" },
    "ctx_write": [...],
    "ctx_read": [...]
  }
}
```

**关键点**：
- 不写 `classic: keylen>=256 / quantum: keylen>=512`（避免重复）
- 只写如何推导 canonical 参数（key_bits）
- 约束来自 `common_profiles.json` 的 `quantum_constraints/classic_constraints`

### derived_meta（封装特有字段）

```json
{
  "derived_meta": {
    "source": "manual",              // manual | auto
    "wraps": ["RSA_generate_key"],   // 被封装的底层 API（可多个）
    "infer_depth": 1,                // 封装层数
    "confidence": "confirmed",       // confirmed | probable | suspect
    "propagation": {                 // 局部传播证据（不含全路径）
      "local_sink_calls": [
        {"callee": "RSA_generate_key", "line": 12}
      ],
      "key_input_sources": {
        "key_bits": "Param(keylen) * 8"
      }
    },
    "conditions": [...]              // 分支/条件信息（可选）
  }
}
```

**关键点**：
- `propagation` 只存局部证据（B 内 B→A 的 callsite）
- 不存完整路径（C→B→A...），运行时通过 callers_index 重建
- 入口函数（Parameter-Entry）是运行时判定，不硬写进 KB

## 四种封装模式

### 模式 1：简单参数转换

```json
{
  "api_id": "wrap.c.mylib.my_rsa_keygen",
  "language": "c",
  "library": "mylib",
  "function": "my_rsa_keygen",
  "func_params": ["keylen"],
  "semantic": {
    "profile_id": "ALG.RSA.PKE",
    "operation": "keygen",
    "key_bits": { "from_param": "keylen", "unit": "bytes", "transform": "*8" }
  },
  "derived_meta": {
    "source": "manual",
    "wraps": ["RSA_generate_key"],
    "infer_depth": 1,
    "confidence": "confirmed",
    "propagation": {
      "local_sink_calls": [{"callee": "RSA_generate_key", "line": 3}],
      "key_input_sources": {"key_bits": "keylen*8"}
    }
  }
}
```

### 模式 2：算法选择（if-else/branches）

```json
{
  "api_id": "wrap.c.mylib.crypto_init",
  "language": "c",
  "library": "mylib",
  "function": "crypto_init",
  "func_params": ["algo_type", "key_bits"],
  "semantic": {
    "operation": "crypto_init",
    "branching": true
  },
  "derived_meta": {
    "source": "manual",
    "wraps": ["EVP_aes_128_gcm", "EVP_aes_256_gcm", "RSA_generate_key"],
    "infer_depth": 1,
    "confidence": "probable",
    "conditions": [
      {
        "when": "algo_type == 'aes128'",
        "semantic_override": {
          "profile_id": "ALG.AES",
          "operation": "encrypt_init",
          "key_bits": { "const": 128 }
        }
      },
      {
        "when": "algo_type == 'aes256'",
        "semantic_override": {
          "profile_id": "ALG.AES",
          "operation": "encrypt_init",
          "key_bits": { "const": 256 }
        }
      },
      {
        "when": "algo_type == 'rsa'",
        "semantic_override": {
          "profile_id": "ALG.RSA.PKE",
          "operation": "keygen",
          "key_bits": { "from_param": "key_bits", "unit": "bits" }
        }
      }
    ]
  }
}
```

**注意**：confidence 通常是 `probable`（除非调用点能常量传播到单一分支）

### 模式 3：工厂模式（返回对象）

```json
{
  "api_id": "wrap.c.mylib.get_cipher",
  "language": "c",
  "library": "mylib",
  "function": "get_cipher",
  "func_params": ["name"],
  "semantic": {
    "operation": "factory",
    "returns": { "kind": "cipher" },
    "algorithm_name": { "from_param": "name", "encoding": "string" }
  },
  "derived_meta": {
    "source": "manual",
    "wraps": ["EVP_aes_128_gcm", "EVP_aes_256_gcm"],
    "infer_depth": 1,
    "confidence": "probable"
  }
}
```

**说明**：后续通过 `infer_from=function_call` 或 lookup_table 推导 profile + key_bits。

### 模式 4：条件约束（同一 wrapper 不同强度）

```json
{
  "api_id": "wrap.c.mylib.secure_keygen",
  "language": "c",
  "library": "mylib",
  "function": "secure_keygen",
  "func_params": ["keylen", "high_security"],
  "semantic": {
    "profile_id": "ALG.RSA.PKE",
    "operation": "keygen",
    "key_bits": { "from_param": "keylen", "unit": "bytes", "transform": "*8" }
  },
  "derived_meta": {
    "source": "manual",
    "wraps": ["RSA_generate_key"],
    "infer_depth": 1,
    "confidence": "probable",
    "conditions": [
      { "when": "high_security == true",  "contract_override": {"key_bits_min": 4096} },
      { "when": "high_security == false", "contract_override": {"key_bits_min": 2048} }
    ]
  }
}
```

**注意**：`contract_override` 只是局部条件，最终约束仍由 common_profiles 决定。

## 敏感参数与 ctx 状态

### 参数位置表达

- **显式参数**：通过 `from_param` 体现
- **隐式状态**：通过 `ctx_write/ctx_read` 体现

示例（EVP wrapper 写入 ctx.key_bits）：

```json
{
  "semantic": {
    "profile_id": "ALG.AES",
    "operation": "encrypt_init",
    "key_bits": { "from_param": "keylen", "unit": "bytes", "transform": "*8" },
    "ctx_write": [
      {"object":"ctx","field":"key_bits","from_param":"keylen","unit":"bytes","transform":"*8"}
    ],
    "ctx_read": [
      {"object":"ctx","field":"cipher_name"}
    ]
  }
}
```

**优势**：ObjectID 能串联同一 ctx 的状态，支持多层封装且不展开。

## 规则形成流程

### 手工预定义（本目录）

- 覆盖第三方库/无源码封装
- 覆盖常见模式（md 列的 4 类）
- 性能关键路径优先

### 自动派生（kb/derived/）

当检测到 B 内部调用 A：

1. 从 A 的 api 规则获取关键输入字段（key_bits/curve...）
2. 在 B 内做参数表达式提取（literal_args/ExprIR）
3. 生成与 apis 同构的 wrapper rule（api_id 前缀用 `wrap.` 或 `drv.`）
4. 写入 `kb/derived/<lang>/<lib>.json`

**优先级策略**：
1. Direct recognition（apis）
2. Contract recognition（wrappers + derived）
3. Symbolic execution（fallback）

## 传播图设计（不写入规则）

**规则里不存传播路径**，只存局部证据：

✅ 存储：
- `wraps` - 哪些敏感函数（A）
- `key_input_sources` - 关键输入从哪里来（param/ctx/const）
- `local_sink_calls` - B 内 callsite（局部证据）

⛔ 不存：
- 从调用者到 B 的所有传播路径（会爆炸且易过期）

**传播路径在运行时构建**：

一次 Fast pass 建立：
- `callsite_table[callsite_id]` - 调用点详情
- `callers_index[callee]` - 倒排索引（O(#calls)）

Deep pass 维护：
- `prop_edges[sink_id]` - 传播子图（边集合，非路径序列）

输出：
- 可达 callsites 集合（最重要）
- 受影响函数集合
- 传播子图（用于解释/可视化）

**关键**：
- 找全调用 = 找出所有可达 callsites/函数集合
- 不等于枚举所有路径序列（指数爆炸）
- 传播子图是线性规模

## 性能优化

### SAT/UNSAT 剪枝

- SAT：满足 B 约束 → 不扩散
- UNSAT/UNKNOWN：继续向上

### Parameter-Entry 截断

关键输入在 C 固定（常量/配置/ctx 闭合）→ C 是入口（停止向上）

### Memo 缓存

对 `(callsite_id, sink_id, contract_signature)` 缓存，处理一次不再处理。

### SCC 折叠

遇到递归把强连通分量折叠，避免无限传播。

## 示例：OpenSSL 常见封装

参见 `c/openssl_wrappers.json`（待创建）。
