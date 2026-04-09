#!/usr/bin/env python3
"""
weapon_radar_query.py — weapon_radar 的 JSON 机器接口

供 ovogogogo WeaponRadar 工具调用，输出结构化 JSON，不含 rich 终端格式。

用法（单查询）:
    python3 weapon_radar_query.py -q "RCE via Apache Log4j" [-n 5] [--show-code]

用法（批量查询，模型只加载一次）:
    python3 weapon_radar_query.py --batch-json '[{"query":"...","top_k":3},...]' [--show-code]

单查询输出格式 (stdout, JSON):
    {
        "query": "...",
        "results": [...],
        "total": 3,
        "encode_ms": 120,
        "search_ms": 45
    }

批量查询输出格式 (stdout, JSON):
    {
        "batch": [
            {"query": "...", "results": [...], "total": 3, "encode_ms": 120, "search_ms": 45},
            ...
        ]
    }

错误时输出:
    { "error": "错误信息" }
    并以非零退出码退出
"""

import sys
import json
import time
import argparse
from pathlib import Path

# 确保能 import weapon_radar（同目录）
sys.path.insert(0, str(Path(__file__).parent))

try:
    from weapon_radar import load_model, create_pool, encode_query, search
except ImportError as e:
    print(json.dumps({"error": f"无法导入 weapon_radar: {e}"}))
    sys.exit(1)


def run_single_query(model, pool, query: str, top_k: int, show_code: bool) -> dict:
    """执行单次查询，返回结果 dict（不含错误处理，由调用方负责）"""
    t0 = time.time()
    query_vec = encode_query(model, query)
    encode_ms = int((time.time() - t0) * 1000)

    t1 = time.time()
    results = search(pool, query_vec, top_k)
    search_ms = int((time.time() - t1) * 1000)

    output_results = []
    for i, row in enumerate(results, start=1):
        item = {
            "rank":              i,
            "id":                row["id"],
            "module_name":       row["module_name"] or "",
            "attack_logic":      row["attack_logic"] or "",
            "opsec_risk":        row.get("opsec_risk"),
            "cve_list":          row.get("cve_list") or [],
            "required_options":  row.get("required_options") or {},
            "auto_parameters":   row.get("auto_parameters") or {},
            "score":             round(row["score"], 4),
            "score_pct":         round(row["score"] * 100, 1),
        }
        if show_code and row.get("full_poc_code"):
            item["poc_code"] = row["full_poc_code"]
        output_results.append(item)

    return {
        "query":     query,
        "results":   output_results,
        "total":     len(output_results),
        "encode_ms": encode_ms,
        "search_ms": search_ms,
    }


def main():
    parser = argparse.ArgumentParser(description="weapon_radar JSON 接口")
    parser.add_argument("-q", "--query", help="自然语言查询（攻击意图描述）")
    parser.add_argument("-n", "--top-k", type=int, default=3, help="返回结果数量（默认 3）")
    parser.add_argument("--no-code", action="store_true", help="不包含 PoC YAML 代码（默认包含）")
    parser.add_argument("--batch-json", help='批量查询 JSON 数组，格式: [{"query":"...","top_k":3},...]')
    args = parser.parse_args()

    # 验证输入
    if not args.query and not args.batch_json:
        print(json.dumps({"error": "必须提供 -q 或 --batch-json"}))
        sys.exit(1)

    if args.query and not args.query.strip():
        print(json.dumps({"error": "查询文本不能为空"}))
        sys.exit(1)

    if args.top_k < 1 or args.top_k > 50:
        print(json.dumps({"error": "--top-k 必须在 1~50 之间"}))
        sys.exit(1)

    # 默认返回 PoC 代码，除非明确 --no-code
    show_code = not args.no_code

    # 解析批量查询
    batch_queries = None
    if args.batch_json:
        try:
            batch_queries = json.loads(args.batch_json)
            if not isinstance(batch_queries, list) or len(batch_queries) == 0:
                raise ValueError("必须是非空数组")
            for item in batch_queries:
                if not isinstance(item, dict) or "query" not in item:
                    raise ValueError('每项必须包含 "query" 字段')
        except (json.JSONDecodeError, ValueError) as e:
            print(json.dumps({"error": f"--batch-json 格式错误: {e}"}))
            sys.exit(1)

    # ── 初始化（整个进程只加载一次模型）────────────────────────────────
    try:
        pool = create_pool()
    except SystemExit:
        print(json.dumps({"error": "数据库连接失败，请确认 PostgreSQL/pgvector 服务正在运行（127.0.0.1:5432）"}))
        sys.exit(1)

    try:
        import os
        import contextlib
        with open(os.devnull, 'w') as devnull:
            with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
                model = load_model()
    except SystemExit:
        print(json.dumps({"error": "模型加载失败，请确认 sentence-transformers 和 BAAI/bge-m3 已安装"}))
        sys.exit(1)

    try:
        # ── 批量模式 ────────────────────────────────────────────────────
        if batch_queries:
            batch_results = []
            for item in batch_queries:
                q = item["query"].strip()
                k = min(max(int(item.get("top_k", args.top_k)), 1), 50)
                if not q:
                    batch_results.append({"query": q, "error": "查询文本不能为空"})
                    continue
                try:
                    result = run_single_query(model, pool, q, k, show_code)
                    batch_results.append(result)
                except Exception as e:
                    batch_results.append({"query": q, "error": str(e)})
            print(json.dumps({"batch": batch_results}, ensure_ascii=False, indent=2))

        # ── 单查询模式 ──────────────────────────────────────────────────
        else:
            try:
                result = run_single_query(model, pool, args.query, args.top_k, show_code)
            except (ValueError, RuntimeError) as e:
                print(json.dumps({"error": f"查询失败: {e}"}))
                sys.exit(1)
            print(json.dumps(result, ensure_ascii=False, indent=2))

    finally:
        try:
            pool.closeall()
        except Exception:
            pass


if __name__ == "__main__":
    main()
