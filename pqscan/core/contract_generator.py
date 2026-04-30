import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

# 添加父目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pqscan.analysis.wrapper_summary import Expr, ExprType, Effect, Contract
from pqscan.analysis.contract_deriver import ContractDeriver


class WrapperContractGenerator:
    """封装契约自动生成器"""
    
    def __init__(self, kb_dir: Path, verbose: bool = False):
        """
        初始化生成器
        
        Args:
            kb_dir: KB 根目录
            verbose: 是否输出详细信息
        """
        self.kb_dir = Path(kb_dir)
        self.derived_dir = self.kb_dir / "derived"
        self.verbose = verbose
        
        # 派生器
        self.deriver = ContractDeriver(verbose=verbose)
        
        # 统计信息
        self.stats = {
            'total_analyzed': 0,
            'contracts_generated': 0,
            'by_language': defaultdict(int),
            'by_library': defaultdict(int)
        }
    
    def generate_contract_from_effect(
        self,
        wrapper_func: str,
        wrapper_params: List[str],
        effect: Effect,
        sink_api: str,
        sink_constraints: List[Dict[str, Any]],
        language: str,
        library: Optional[str] = None,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        从 Effect 生成封装契约
        
        Args:
            wrapper_func: 封装函数名
            wrapper_params: 封装函数参数列表
            effect: 关键输入归因结果
            sink_api: 被封装的敏感 API
            sink_constraints: 敏感 API 的约束
            language: 编程语言
            library: 库名（可选）
            file_path: 源文件路径（可选）
            line_number: 调用行号（可选）
        
        Returns:
            封装契约（wrappers KB 格式）或 None
        """
        self.stats['total_analyzed'] += 1
        
        # 1. 派生约束
        contract = self.deriver.derive_contract(
            effect=effect,
            sink_constraints=sink_constraints,
            caller_params=wrapper_params
        )
        
        if not contract or not contract.param_constraints:
            return None
        
        # 2. 构建 semantic 部分
        semantic = self._build_semantic_from_effect(effect)
        if not semantic:
            return None
        
        # 3. 构建 derived_meta 部分
        derived_meta = {
            "source": "auto",
            "wraps": [sink_api],
            "infer_depth": 1,
            "confidence": self._estimate_confidence(effect),
            "propagation": {
                "local_sink_calls": [
                    {
                        "callee": sink_api,
                        "line": line_number if line_number else None
                    }
                ],
                "key_input_sources": self._extract_input_sources(effect)
            }
        }
        
        if file_path:
            derived_meta["source_file"] = file_path
        
        # 4. 生成 api_id
        lib_part = f".{library}" if library else ""
        api_id = f"drv.{language}{lib_part}.{wrapper_func}"
        
        # 5. 组装契约
        wrapper_contract = {
            "api_id": api_id,
            "language": language,
            "function": wrapper_func,
            "func_params": wrapper_params,
            "semantic": semantic,
            "derived_meta": derived_meta
        }
        
        if library:
            wrapper_contract["library"] = library
        
        self.stats['contracts_generated'] += 1
        self.stats['by_language'][language] += 1
        if library:
            self.stats['by_library'][library] += 1
        
        if self.verbose:
            print(f"[生成] {api_id}")
            print(f"  Wraps: {sink_api}")
            print(f"  Constraints: {len(contract.param_constraints)}")
        
        return wrapper_contract
    
    def _build_semantic_from_effect(self, effect: Effect) -> Optional[Dict[str, Any]]:
        """
        从 Effect 构建 semantic 字段
        
        Args:
            effect: 关键输入归因结果
        
        Returns:
            semantic 字典
        """
        semantic = {}
        
        # ★ 提取 profile_id（从 sink_profile_id 或 effect 本身）
        if hasattr(effect, 'sink_profile_id') and effect.sink_profile_id:
            semantic['profile_id'] = effect.sink_profile_id
        elif hasattr(effect, 'profile_id') and effect.profile_id:
            semantic['profile_id'] = effect.profile_id
        
        # 提取 operation（如果有）
        if hasattr(effect, 'operation') and effect.operation:
            semantic['operation'] = effect.operation
        
        # 提取关键输入
        for key_name, expr in effect.key_inputs.items():
            input_spec = self._expr_to_input_spec(expr)
            if input_spec:
                semantic[key_name] = input_spec
        
        return semantic if semantic else None
    
    def _expr_to_input_spec(self, expr: Expr) -> Optional[Dict[str, Any]]:
        """
        将 Expr 转换为 input_spec（from_param + transform）
        
        Args:
            expr: 表达式
        
        Returns:
            input_spec 字典
        """
        # Case 1: 直接参数
        if expr.type == ExprType.PARAM:
            return {
                "from_param": expr.param
            }
        
        # Case 2: 乘法（param * const）
        if expr.type == ExprType.MUL:
            left, right = expr.left, expr.right
            
            # param * const
            if left.type == ExprType.PARAM and right.type == ExprType.CONST:
                return {
                    "from_param": left.param,
                    "transform": f"*{right.value}"
                }
            
            # const * param
            if left.type == ExprType.CONST and right.type == ExprType.PARAM:
                return {
                    "from_param": right.param,
                    "transform": f"*{left.value}"
                }
        
        # Case 3: 加法（param + const）
        if expr.type == ExprType.ADD:
            left, right = expr.left, expr.right
            
            # param + const
            if left.type == ExprType.PARAM and right.type == ExprType.CONST:
                return {
                    "from_param": left.param,
                    "transform": f"+{right.value}"
                }
            
            # const + param
            if left.type == ExprType.CONST and right.type == ExprType.PARAM:
                return {
                    "from_param": right.param,
                    "transform": f"+{left.value}"
                }
        
        # Case 4: 常量
        if expr.type == ExprType.CONST:
            return {
                "const": expr.value
            }
        
        # Case 5: 状态
        if expr.type == ExprType.STATE:
            return {
                "from_ctx": expr.obj,
                "field": expr.field
            }
        
        return None
    
    def _extract_input_sources(self, effect: Effect) -> Dict[str, str]:
        """
        提取关键输入来源的简化表达式
        
        Args:
            effect: Effect 对象
        
        Returns:
            {key_name: expr_string}
        """
        sources = {}
        
        for key_name, expr in effect.key_inputs.items():
            expr_str = self._expr_to_string(expr)
            if expr_str:
                sources[key_name] = expr_str
        
        return sources
    
    def _expr_to_string(self, expr: Expr) -> str:
        """将 Expr 转换为字符串表示"""
        if expr.type == ExprType.CONST:
            return str(expr.value)
        
        elif expr.type == ExprType.PARAM:
            return f"Param({expr.param})"
        
        elif expr.type == ExprType.MUL:
            left = self._expr_to_string(expr.left)
            right = self._expr_to_string(expr.right)
            return f"({left} * {right})"
        
        elif expr.type == ExprType.ADD:
            left = self._expr_to_string(expr.left)
            right = self._expr_to_string(expr.right)
            return f"({left} + {right})"
        
        elif expr.type == ExprType.STATE:
            return f"State({expr.obj}.{expr.field})"
        
        return "Unknown"
    
    def _estimate_confidence(self, effect: Effect) -> str:
        """
        估计约束置信度
        
        Args:
            effect: Effect 对象
        
        Returns:
            "confirmed" | "probable" | "suspect"
        """
        # 如果所有关键输入都是简单表达式（PARAM 或 简单变换），则 confirmed
        simple_count = 0
        total_count = len(effect.key_inputs)
        
        for expr in effect.key_inputs.values():
            if self._is_simple_expr(expr):
                simple_count += 1
        
        if simple_count == total_count:
            return "confirmed"
        elif simple_count >= total_count / 2:
            return "probable"
        else:
            return "suspect"
    
    def _is_simple_expr(self, expr: Expr) -> bool:
        """判断是否是简单表达式"""
        if expr.type in (ExprType.PARAM, ExprType.CONST):
            return True
        
        if expr.type == ExprType.MUL:
            left, right = expr.left, expr.right
            # param * const 或 const * param
            if (left.type == ExprType.PARAM and right.type == ExprType.CONST) or \
               (left.type == ExprType.CONST and right.type == ExprType.PARAM):
                return True
        
        return False
    
    def save_contracts(
        self,
        contracts: List[Dict[str, Any]],
        language: str,
        library: Optional[str] = None,
        overwrite: bool = False
    ) -> Path:
        """
        保存契约到 KB
        
        Args:
            contracts: 契约列表
            language: 语言
            library: 库名
            overwrite: 是否覆盖已有文件
        
        Returns:
            保存的文件路径
        """
        # 确保目录存在
        lang_dir = self.derived_dir / language
        lang_dir.mkdir(parents=True, exist_ok=True)
        
        # 确定文件名
        if library:
            filename = f"{library}_derived.json"
        else:
            filename = f"{language}_derived.json"
        
        file_path = lang_dir / filename
        
        # 检查是否已存在
        if file_path.exists() and not overwrite:
            # 合并到已有文件
            with open(file_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
            
            existing_contracts = existing_data.get('wrappers', [])
            
            # 合并（避免重复）
            existing_ids = {c.get('api_id') for c in existing_contracts}
            new_contracts = [c for c in contracts if c.get('api_id') not in existing_ids]
            
            all_contracts = existing_contracts + new_contracts
            
            if self.verbose:
                print(f"[合并] {file_path}: {len(existing_contracts)} + {len(new_contracts)} = {len(all_contracts)}")
        else:
            all_contracts = contracts
        
        # 构建完整数据
        data = {
            "version": "1.0.0",
            "description": f"自动派生的 {language} 封装契约",
            "language": language,
            "wrappers": all_contracts
        }
        
        if library:
            data["library"] = library
        
        # 保存
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        if self.verbose:
            print(f"[保存] {file_path}: {len(all_contracts)} 个契约")
        
        return file_path
    
    def print_stats(self):
        """打印统计信息"""
        print("\n" + "=" * 70)
        print("封装契约自动生成统计")
        print("=" * 70)
        print(f"分析的函数总数: {self.stats['total_analyzed']}")
        print(f"生成的契约数量: {self.stats['contracts_generated']}")
        print(f"成功率: {self.stats['contracts_generated'] / max(1, self.stats['total_analyzed']) * 100:.1f}%")
        
        if self.stats['by_language']:
            print("\n按语言统计:")
            for lang, count in sorted(self.stats['by_language'].items()):
                print(f"  {lang}: {count}")
        
        if self.stats['by_library']:
            print("\n按库统计:")
            for lib, count in sorted(self.stats['by_library'].items()):
                print(f"  {lib}: {count}")


def test_contract_generator():
    """测试契约生成器"""
    print("=" * 70)
    print("封装契约自动生成器测试")
    print("=" * 70)
    
    # 修正 KB 路径
    kb_dir = Path(__file__).parent.parent / "kb"
    if not kb_dir.exists():
        print(f"错误: KB 目录不存在: {kb_dir}")
        return
    
    generator = WrapperContractGenerator(kb_dir, verbose=True)
    
    # 测试 1: 模拟一个简单的封装函数
    print("\n[测试 1] 生成简单封装契约")
    
    # 构造 Effect（模拟 my_rsa_keygen）
    from pqscan.analysis.wrapper_summary import InputSource
    
    effect = Effect(
        sink_profile_id="ALG.RSA.PKE",
        key_inputs={
            "key_bits": Expr(
                type=ExprType.MUL,
                left=Expr(type=ExprType.PARAM, param="keylen"),
                right=Expr(type=ExprType.CONST, value=8)
            )
        },
        input_sources={}
    )
    
    # 模拟 RSA 的约束
    sink_constraints = [
        {
            "field": "key_bits",
            "min": 2048,
            "pq_min": 7680
        }
    ]
    
    contract = generator.generate_contract_from_effect(
        wrapper_func="my_rsa_keygen",
        wrapper_params=["keylen"],
        effect=effect,
        sink_api="RSA_generate_key",
        sink_constraints=sink_constraints,
        language="c",
        library="mylib",
        line_number=10
    )
    
    if contract:
        print("\n生成的契约:")
        print(json.dumps(contract, indent=2, ensure_ascii=False))
        
        # 测试 2: 保存到 KB
        print("\n[测试 2] 保存契约到 KB")
        file_path = generator.save_contracts(
            contracts=[contract],
            language="c",
            library="mylib_test",
            overwrite=True
        )
        print(f"✓ 保存成功: {file_path}")
    else:
        print("✗ 契约生成失败")
    
    # 打印统计
    generator.print_stats()
    
    print("\n" + "=" * 70)
    print("✓ 测试完成")
    print("=" * 70)


if __name__ == '__main__':
    test_contract_generator()
