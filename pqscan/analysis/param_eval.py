#!/usr/bin/env python3
"""
Unified parameter evaluation utilities:
- parameter binding
- expression evaluation
- parameter inference (symbolic/AST level)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pqscan.analysis.parameter_binding import (
    ParameterBindingExtractor,
    ParamBinding,
    extract_param_bindings as _extract_param_bindings,
)
from pqscan.analysis.expression_evaluator import evaluate_expression as _evaluate_expression
from pqscan.symbolic.parameter_tracer import ParameterTracer


def bind_params(
    args_repr: List[str],
    callee_params: Optional[List[str]] = None,
    verbose: bool = False,
) -> Dict[str, ParamBinding]:
    """Bind caller arguments to callee parameters."""
    return _extract_param_bindings(args_repr, callee_params=callee_params, verbose=verbose)


def eval_expr(expr: str, variables: Optional[Dict[str, Any]] = None) -> Any:
    """Evaluate a simple expression with optional variables."""
    return _evaluate_expression(expr, variables or {})


def infer_params(
    symbol: str,
    literal_args: List[Any],
    language: str,
    *,
    variable_tracker: Optional[Any] = None,
) -> Dict[str, Any]:
    """Infer key parameters from symbol/args (optionally using a variable tracker)."""
    tracer = ParameterTracer()
    if variable_tracker is not None:
        tracer.set_variable_tracker(variable_tracker)
    return tracer.trace(symbol=symbol, literal_args=literal_args, language=language)


__all__ = [
    "ParameterBindingExtractor",
    "ParamBinding",
    "bind_params",
    "eval_expr",
    "infer_params",
]

