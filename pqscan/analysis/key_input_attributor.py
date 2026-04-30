"""
关键输入归因器（Key Input Attributor）

分析敏感点调用的关键输入来源：
- PARAM_DEP: 来自参数
- CONST_DEP: 来自常量
- STATE_DEP: 来自状态（ctx_read）
- UNKNOWN: 未知
"""

from typing import Dict, List, Any, Optional, Tuple
from pqscan.analysis.wrapper_summary import (
    Expr, ExprType, InputSource, Effect, StateAccess
)


class KeyInputAttributor:
    """
    关键输入归因器
    
    分析函数调用的关键输入来源，生成 Effect
    """
    
    def __init__(self, object_id_manager=None, variable_tracker=None):
        """
        初始化归因器
        
        Args:
            object_id_manager: 对象ID管理器（用于状态追踪）
            variable_tracker: 变量追踪器（用于变量解析）
        """
        self.object_id_manager = object_id_manager
        self.variable_tracker = variable_tracker
    
    def attribute_key_inputs(
        self,
        candidate: Dict[str, Any],
        params: Dict[str, Any],
        profile_id: str,
        api_metadata: Dict[str, Any],
        function_params: Dict[str, List[str]]
    ) -> Optional[Effect]:
        """
        对单个候选调用进行关键输入归因
        
        Args:
            candidate: 候选调用信息
            params: 提取的参数（由 ParameterTracer 生成）
            profile_id: 算法 profile ID
            api_metadata: API 元数据（包含参数映射规则）
            function_params: 函数参数映射 {func_name: [param_names]}
        
        Returns:
            Effect 对象，描述关键输入来源
        """
        if not profile_id:
            return None
        
        # 获取调用者函数名（用于判断参数依赖）
        caller_func = candidate.get('function_name', 'global')
        
        # 关键输入字段（从 params 中提取）
        key_inputs = {}
        input_sources = {}
        state_reads = []
        state_writes = []
        
        # 1. 分析每个关键输入字段
        for field, value in params.items():
            if field.startswith('_'):  # 跳过内部字段
                continue
            
            # 归因：判断来源
            expr, source = self._attribute_single_input(
                field, value, candidate, caller_func, function_params
            )
            
            if expr:
                key_inputs[field] = expr
                input_sources[field] = source
            
            # 检查是否涉及状态读取
            if source == InputSource.STATE_DEP:
                state_reads.append(StateAccess(
                    obj=expr.obj if expr.type == ExprType.STATE else 'ctx',
                    field=field
                ))
        
        # 1.5. 特殊处理：从 API metadata 推断关键输入
        # 对于 C 语言 OpenSSL API，algorithm 通常通过参数传递
        self._infer_from_api_metadata(
            api_metadata, candidate, key_inputs, input_sources, 
            caller_func, function_params
        )
        
        # 2. 检查状态写入（从 API metadata 获取）
        semantic = api_metadata.get('semantic', {})
        ctx_writes = semantic.get('ctx_write', [])
        for write in ctx_writes:
            if isinstance(write, dict):
                field_name = write.get('field')
                value_source = write.get('value')
                
                if field_name and value_source:
                    # 解析写入值
                    write_expr, write_source = self._parse_value_source(
                        value_source, candidate, caller_func, function_params
                    )
                    
                    state_writes.append(StateAccess(
                        obj='ctx',
                        field=field_name,
                        value=write_expr
                    ))
        
        # 3. 判断触发条件
        trigger = self._determine_trigger(input_sources)
        
        # 4. 构建证据
        evidence = {
            'line': candidate.get('line'),
            'symbol': candidate.get('symbol'),
            'caller': caller_func
        }
        
        return Effect(
            sink_profile_id=profile_id,
            key_inputs=key_inputs,
            input_sources=input_sources,
            state_reads=state_reads,
            state_writes=state_writes,
            trigger=trigger,
            evidence=evidence
        )
    
    def _attribute_single_input(
        self,
        field: str,
        value: Any,
        candidate: Dict[str, Any],
        caller_func: str,
        function_params: Dict[str, List[str]]
    ) -> Tuple[Optional[Expr], InputSource]:
        """
        归因单个输入字段
        
        Returns:
            (Expr, InputSource) 元组
        """
        # 1. 检查是否是常量
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
                return (
                    Expr(type=ExprType.CONST, value=int(value) if isinstance(value, int) else int(value)),
                    InputSource.CONST_DEP
                )
            # 字符串常量（算法名等）
            return (
                Expr(type=ExprType.CONST, value=value),
                InputSource.CONST_DEP
            )
        
        # 2. 检查是否来自参数
        if isinstance(value, str):
            # 检查是否是函数参数名
            caller_params = function_params.get(caller_func, [])
            if value in caller_params:
                param_index = caller_params.index(value)
                return (
                    Expr(type=ExprType.PARAM, param=value),
                    InputSource.PARAM_DEP
                )
            
            # 检查是否是表达式（如 keylen * 8）
            expr = self._parse_expression(value, caller_params)
            if expr and expr.depends_on_param():
                return (expr, InputSource.PARAM_DEP)
            elif expr and expr.is_constant():
                return (expr, InputSource.CONST_DEP)
        
        # 3. 检查是否来自状态（ctx.field）
        if field in ['algorithm', 'cipher_name', 'hash_name']:
            # 这些字段通常来自 ctx 状态
            return (
                Expr(type=ExprType.STATE, obj='ctx', field=field),
                InputSource.STATE_DEP
            )
        
        # 4. 检查对象状态追踪器
        if self.object_id_manager and isinstance(value, str):
            # 尝试解析为对象字段
            receiver = candidate.get('receiver')
            if receiver:
                # 查找对象状态
                scope = caller_func
                obj_id = self.object_id_manager.lookup_object(receiver, scope)
                if obj_id:
                    obj_info = self.object_id_manager.objects.get(obj_id)
                    if obj_info and field in obj_info.state:
                        state_value = obj_info.state[field]
                        return (
                            Expr(type=ExprType.STATE, obj=receiver, field=field),
                            InputSource.STATE_DEP
                        )
        
        # 5. 未知来源
        return (
            Expr(type=ExprType.UNKNOWN),
            InputSource.UNKNOWN
        )
    
    def _parse_expression(self, text: str, param_names: List[str]) -> Optional[Expr]:
        """
        解析表达式（支持简单算术运算）
        
        Examples:
            "keylen * 8" -> Mul(Param(keylen), Const(8))
            "bits + 1024" -> Add(Param(bits), Const(1024))
            "2048" -> Const(2048)
        """
        text = text.strip()
        
        # 乘法
        if '*' in text:
            parts = text.split('*')
            if len(parts) == 2:
                left = self._parse_expression(parts[0].strip(), param_names)
                right = self._parse_expression(parts[1].strip(), param_names)
                if left and right:
                    return Expr(type=ExprType.MUL, left=left, right=right)
        
        # 加法
        if '+' in text:
            parts = text.split('+')
            if len(parts) == 2:
                left = self._parse_expression(parts[0].strip(), param_names)
                right = self._parse_expression(parts[1].strip(), param_names)
                if left and right:
                    return Expr(type=ExprType.ADD, left=left, right=right)
        
        # 参数
        if text in param_names:
            return Expr(type=ExprType.PARAM, param=text)
        
        # 常量
        if text.isdigit():
            return Expr(type=ExprType.CONST, value=int(text))
        
        return None
    
    def _infer_from_api_metadata(
        self,
        api_metadata: Dict[str, Any],
        candidate: Dict[str, Any],
        key_inputs: Dict[str, Expr],
        input_sources: Dict[str, InputSource],
        caller_func: str,
        function_params: Dict[str, List[str]]
    ) -> None:
        """
        从 API metadata 推断关键输入（占位实现）
        
        对于工厂函数（如 EVP_aes_256_gcm），其 profile_id 已经是具体算法，
        不需要额外推断。此方法主要用于未来的扩展。
        
        Args:
            api_metadata: API 元数据
            candidate: 候选调用
            key_inputs: 关键输入字典（可修改）
            input_sources: 输入来源字典（可修改）
            caller_func: 调用者函数名
            function_params: 函数参数映射
        """
        # 占位实现：暂时不做任何处理
        # 工厂函数的 profile_id 已经在 _identify_algorithm 中正确识别
        pass
    
    def _parse_value_source(
        self,
        value_source: str,
        candidate: Dict[str, Any],
        caller_func: str,
        function_params: Dict[str, List[str]]
    ) -> Tuple[Optional[Expr], InputSource]:
        """
        解析值来源（用于 ctx_write）
        
        value_source 格式：
        - "arg0": 来自参数0
        - "const:AES-256-GCM": 常量
        - "EVP_aes_256_gcm": 函数名（算法）
        """
        if value_source.startswith('arg'):
            # 参数引用
            try:
                arg_index = int(value_source[3:])
                args = candidate.get('args', [])
                if arg_index < len(args):
                    arg = args[arg_index]
                    arg_text = arg.get('text', '') if isinstance(arg, dict) else str(arg)
                    
                    # 检查是否是参数名
                    caller_params = function_params.get(caller_func, [])
                    if arg_text in caller_params:
                        return (
                            Expr(type=ExprType.PARAM, param=arg_text),
                            InputSource.PARAM_DEP
                        )
                    
                    # 检查是否是算法名（常量）
                    return (
                        Expr(type=ExprType.CONST, value=arg_text),
                        InputSource.CONST_DEP
                    )
            except (ValueError, IndexError):
                pass
        
        # 常量
        return (
            Expr(type=ExprType.CONST, value=value_source),
            InputSource.CONST_DEP
        )
    
    def _determine_trigger(self, input_sources: Dict[str, InputSource]) -> str:
        """
        判断触发条件
        
        - unconditional: 所有输入都是常量
        - conditional: 有参数依赖或状态依赖
        - unknown: 有未知输入
        """
        if not input_sources:
            return "unknown"
        
        sources = set(input_sources.values())
        
        if InputSource.UNKNOWN in sources:
            return "unknown"
        
        if sources == {InputSource.CONST_DEP}:
            return "unconditional"
        
        return "conditional"
