from collections import defaultdict, deque
from typing import Dict, Set, List, Any, Iterable, Optional


class CallGraph:
    """
    函数调用关系图
    """
    def __init__(self, edges: Optional[Dict[str, Set[str]]] = None):
        base = edges or {}
        self.edges: Dict[str, Set[str]] = {k: set(v) for k, v in base.items()}
        self._pred: Dict[str, Set[str]] = defaultdict(set)
        for u, vs in self.edges.items():
            for v in vs:
                self._pred[v].add(u)
        self.nodes: Set[str] = set(self.edges.keys()) | {v for vs in self.edges.values() for v in vs}

    def add_edge(self, caller: str, callee: str):
        if not caller or not callee:
            return
        self.edges.setdefault(caller, set()).add(callee)
        self._pred[callee].add(caller)
        self.nodes.add(caller); self.nodes.add(callee)

    def add_node(self, name: str):
        if not name:
            return
        self.edges.setdefault(name, set())
        self.nodes.add(name)

    def callees(self, fn: str) -> Set[str]:
        return self.edges.get(fn, set())

    def callers(self, fn: str) -> Set[str]:
        return self._pred.get(fn, set())

    def forward(self, u: str) -> Set[str]:
        return self.edges.get(u, set())

    def backward(self, v: str) -> Set[str]:
        return self._pred.get(v, set())

    # ---- roots: 无调用者的节点（包含 <global> 若存在） ----
    def roots(self) -> Set[str]:
        preds = {n: self.callers(n) for n in self.nodes}
        roots = {n for n, ps in preds.items() if not ps}
        if "<global>" in self.nodes:
            roots.add("<global>")
        return roots

    def reachable_from(self, src: str, max_depth: int = 8) -> Set[str]:
        seen = {src}
        q = deque([(src, 0)])
        while q:
            u, d = q.popleft()
            if d >= max_depth:
                continue
            for w in self.forward(u):
                if w not in seen:
                    seen.add(w); q.append((w, d + 1))
        seen.discard(src)
        return seen

    def reverse_reachable_to(self, targets: Iterable[str], max_depth: int = 12) -> Set[str]:
        seen: Set[str] = set()
        q = deque([(t, 0) for t in targets])
        for t in targets:
            seen.add(t)
        while q:
            v, d = q.popleft()
            if d >= max_depth:
                continue
            for p in self.backward(v):
                if p not in seen:
                    seen.add(p); q.append((p, d + 1))
        return seen

    # ---- 剪枝，仅保留 src→targets 的“可达且可回”子图 ----
    def pruned_nodes_for(self, src: str, targets: Iterable[str], max_depth_f: int = 8, max_depth_b: int = 12) -> Set[str]:
        F = self.reachable_from(src, max_depth=max_depth_f) | {src}
        B = self.reverse_reachable_to(targets, max_depth=max_depth_b) | set(targets)
        return F & B

    # ---- k 条最短简单路径（每目标），BFS + 去环 + 限制 ----
    def k_shortest_paths(
        self,
        src: str,
        targets: Set[str],
        *,
        max_depth: int = 8,
        k_per_target: int = 2,
        max_paths_total: int = 10,
        prune: bool = True
    ) -> Dict[str, List[List[str]]]:
        if not targets:
            return {}
        allowed: Optional[Set[str]] = None
        if prune:
            allowed = self.pruned_nodes_for(src, targets, max_depth_f=max_depth, max_depth_b=max_depth + 4)

        results: Dict[str, List[List[str]]] = {t: [] for t in targets}
        total = 0
        q = deque([[src]])
        seen_states = set()  # (node, tuple(last3)) 粗去重
        while q and total < max_paths_total:
            path = q.popleft()
            u = path[-1]
            if len(path) - 1 > max_depth:
                continue
            if u in targets:
                if len(results[u]) < k_per_target:
                    results[u].append(path[:]); total += 1
            for w in self.forward(u):
                if w in path:  # 简单路径去环
                    continue
                if allowed is not None and w not in allowed:
                    continue
                state = (w, tuple(path[-3:]))
                if state in seen_states:
                    continue
                seen_states.add(state)
                q.append(path + [w])
        return {t: v for t, v in results.items() if v}

    # ---- 从“根”到 via 的前缀最短路径（多条） ----
    def k_shortest_prefixes_to(
        self,
        via: str,
        *,
        max_depth: int = 8,
        k_from_roots: int = 2,
        max_total: int = 20
    ) -> List[List[str]]:
        roots = self.roots()
        # 反向 BFS 先做剪枝集合：能到达 via 的节点
        allowed = self.reverse_reachable_to([via], max_depth=max_depth) | {via}
        results: List[List[str]] = []
        total = 0
        # 多源 BFS（从每个 root 出发）
        for r in sorted(roots):
            q = deque([[r]])
            seen = {r}
            while q and total < max_total:
                path = q.popleft()
                u = path[-1]
                if len(path) - 1 > max_depth:
                    continue
                if u == via:
                    results.append(path[:]); total += 1
                    # 每个 root 最多取 k_from_roots 条
                    if sum(1 for p in results if p[0] == r) >= k_from_roots:
                        break
                for w in self.forward(u):
                    if w in seen:
                        continue
                    if w not in allowed:
                        continue
                    seen.add(w)
                    q.append(path + [w])
        return results

    # ---- 组合“根→via”前缀 与 “via→目标”后缀，得到完整链 ----
    def k_paths_via_to_targets(
        self,
        via: str,
        targets: Set[str],
        *,
        max_depth_prefix: int = 8,
        max_depth_suffix: int = 8,
        k_prefix: int = 2,
        k_suffix_per_target: int = 2,
        max_paths_total: int = 20
    ) -> Dict[str, List[List[str]]]:
        suffix_map = self.k_shortest_paths(
            src=via, targets=targets,
            max_depth=max_depth_suffix,
            k_per_target=k_suffix_per_target,
            max_paths_total=max_paths_total,
            prune=True
        )
        if not suffix_map:
            return {}
        prefixes = self.k_shortest_prefixes_to(
            via=via, max_depth=max_depth_prefix, k_from_roots=k_prefix, max_total=max_paths_total
        )
        out: Dict[str, List[List[str]]] = {}
        for t, suffixes in suffix_map.items():
            fulls: List[List[str]] = []
            for suf in suffixes:
                for pre in prefixes:
                    # pre: root..via, suf: via..target
                    fulls.append(pre + suf[1:])
                    if len(fulls) >= max_paths_total:
                        break
                if len(fulls) >= max_paths_total:
                    break
            if fulls:
                out[t] = fulls
        return out

    # ---- 构造路径前缀树（用于压缩展示） ----
    def build_path_trie(self, paths: List[List[str]]) -> Dict:
        root = {"name": "__root__", "children": {}}
        for p in paths:
            node = root
            for name in p:
                node = node["children"].setdefault(name, {"name": name, "children": {}})
        return self._collapse_trie(root)

    def _collapse_trie(self, node: Dict) -> Dict:
        while len(node["children"]) == 1 and node["name"] != "__root__":
            (k, ch), = node["children"].items()
            node["name"] = f'{node["name"]}→{k}'
            node["children"] = ch["children"]
        node["children"] = {k: self._collapse_trie(v) for k, v in node["children"].items()}
        return node


def build_callgraph_from_ast(funcs: List[Dict[str, Any]], calls: List[Dict[str, Any]]) -> CallGraph:
    """
    根据函数定义 + 调用节点构建调用关系图（基于 AST）
    """
    cg = CallGraph()
    func_names = [f["name"] for f in funcs]

    for f in func_names:
        cg.add_node(f)

    # 调用行 -> 所属函数
    scope_map = {}
    for f in funcs:
        for ln in range(f["start_line"], f["end_line"] + 1):
            scope_map[ln] = f["name"]

    for c in calls:
        line = c["line"]
        caller = scope_map.get(line)
        callee = c["symbol"]
        if not callee:
            continue
        # 内部函数 or 库原语都建边
        cg.add_edge(caller or "<global>", callee)

    return cg


def export_callgraph_dot(cg: CallGraph) -> str:
    lines = ["digraph callgraph {"]
    for caller, callees in cg.edges.items():
        for callee in callees:
            lines.append(f'  "{caller}" -> "{callee}";')
    lines.append("}")
    return "\n".join(lines)
