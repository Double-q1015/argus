# YARA 规则测试数据

此目录包含用于测试的 YARA 规则文件。

## 目录结构

- `valid_rules/` - 有效的 YARA 规则
  - 包含语法正确且可以正常编译的规则
  - 每个规则都应该有明确的测试目的
  - 规则应该尽可能简单，但要覆盖关键功能

- `invalid_rules/` - 无效的 YARA 规则
  - 包含各种语法错误的规则
  - 用于测试错误处理机制
  - 每个规则都应该有对应的错误类型说明

- `complex_rules/` - 复杂的 YARA 规则
  - 包含多个条件组合的规则
  - 包含正则表达式和字符串操作的规则
  - 用于测试性能和处理能力

## 文件命名规范

- 有效规则：`valid_<purpose>.yar`
- 无效规则：`invalid_<error_type>.yar`
- 复杂规则：`complex_<feature>.yar`

## 使用说明

1. 规则文件应该包含注释，说明：
   - 规则的用途
   - 预期的匹配结果
   - 测试场景说明

2. 示例：
```yara
/*
 * 规则名称：test_valid_basic
 * 用途：测试基本的字符串匹配
 * 预期匹配：包含 "test" 字符串的文件
 * 测试场景：基本功能测试
 */
rule test_valid_basic {
    strings:
        $test = "test"
    condition:
        $test
}
``` 