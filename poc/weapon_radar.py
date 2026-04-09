#!/usr/bin/env python3
"""
weapon_radar.py — 武器库语义雷达

自然语言 → BGE-M3 向量 → pgvector 余弦相似度搜索 → 返回最匹配 Nuclei PoC

依赖安装:
    pip install psycopg2-binary pgvector sentence-transformers rich \\
                torch --index-url https://download.pytorch.org/whl/cpu \\
                --break-system-packages

用法:
    python3 weapon_radar.py                  # 交互式 REPL
    python3 weapon_radar.py -n 5             # 返回 Top-5
    python3 weapon_radar.py --show-code      # 同时输出完整 PoC 代码
    python3 weapon_radar.py -q "RCE via SSTI in Jinja2"   # 单次查询后退出
"""

import sys
import time
import json
import logging
import argparse
from typing import Optional

# ─── 依赖检查 ────────────────────────────────────────────────────────────────

_MISSING: list[str] = []
try:
    import psycopg2
    import psycopg2.pool
    from pgvector.psycopg2 import register_vector
except ImportError:
    _MISSING.append("psycopg2-binary pgvector")

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    _MISSING.append("sentence-transformers torch")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False
    print("[警告] rich 未安装，使用纯文本输出。pip install rich")

if _MISSING:
    print("[错误] 缺少依赖包，请先安装:")
    print(f"  pip install {' '.join(_MISSING)} --break-system-packages")
    sys.exit(1)

# ─── 配置 ────────────────────────────────────────────────────────────────────

DB_CONFIG = {
    "host":            "127.0.0.1",
    "port":            5432,
    "dbname":          "msf",
    "user":            "msf",
    "password":        "msf",
    "connect_timeout": 10,
}

MODEL_NAME      = "BAAI/bge-m3"
MAX_SEQ_LEN     = 1024          # 防 OOM：显式截断超长输入
DEFAULT_TOP_K   = 3
MAX_RETRY       = 3             # DB 操作最大重试次数
POOL_MIN_CONN   = 1
POOL_MAX_CONN   = 4             # 保守：REPL 场景不需要太多连接

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

console = Console() if _RICH else None


# ─── 输出工具 ────────────────────────────────────────────────────────────────

def _print(msg: str, style: str = ""):
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def _print_banner():
    if console:
        console.print(Panel(
            "[bold red]武 器 库 语 义 雷 达[/bold red]\n"
            "[dim]Weapon Radar — Powered by BAAI/bge-m3 × pgvector[/dim]",
            border_style="red",
            width=60,
        ))
    else:
        print("=" * 60)
        print("  武器库语义雷达 — Weapon Radar")
        print("  Powered by BAAI/bge-m3 × pgvector")
        print("=" * 60)


def _print_result(rank: int, row: dict, show_code: bool):
    """格式化输出单条结果。"""
    score_pct = row["score"] * 100
    mod       = row["module_name"] or "(未知模块)"
    attack    = row["attack_logic"] or "(无分析)"

    if console:
        # ── Rich 富文本格式 ────────────────────────────────────
        score_color = (
            "bright_green" if score_pct >= 80 else
            "yellow"       if score_pct >= 60 else
            "red"
        )
        title = (
            f"[bold white]#{rank}[/bold white]  "
            f"[bold cyan]{mod}[/bold cyan]  "
            f"匹配度: [{score_color}]{score_pct:.1f}%[/{score_color}]"
        )
        body_lines = [f"[dim]ID:[/dim] {row['id']}"]
        body_lines.append(f"[dim]攻击逻辑:[/dim] {attack}")

        if show_code and row.get("full_poc_code"):
            code_preview = row["full_poc_code"][:800]
            if len(row["full_poc_code"]) > 800:
                code_preview += "\n... (已截断，完整代码超出显示限制)"
            body_lines.append(f"\n[dim]完整 PoC:[/dim]\n[green]{code_preview}[/green]")

        console.print(Panel(
            "\n".join(body_lines),
            title=title,
            border_style=score_color,
            width=100,
        ))
    else:
        # ── 纯文本格式 ────────────────────────────────────────
        print(f"\n{'─'*60}")
        print(f"  #{rank}  {mod}")
        print(f"  匹配度: {score_pct:.1f}%  |  ID: {row['id']}")
        print(f"  攻击逻辑: {attack}")
        if show_code and row.get("full_poc_code"):
            print(f"\n--- PoC 代码 ---\n{row['full_poc_code'][:800]}")
        print(f"{'─'*60}")


# ─── 模型加载 ────────────────────────────────────────────────────────────────

def load_model() -> SentenceTransformer:
    """
    加载 BGE-M3 模型，显式限制 max_seq_length 防止 CPU OOM。
    使用 CPU-only 推理（洛杉矶节点无 GPU）。
    """
    _print("[*] 正在加载语义模型 BAAI/bge-m3，请稍候...", "dim")
    try:
        model = SentenceTransformer(MODEL_NAME, device="cpu")
        # 关键：限制序列长度，防止超长输入撑爆内存
        model.max_seq_length = MAX_SEQ_LEN
        _print(f"[+] 模型加载完成 (max_seq_length={MAX_SEQ_LEN})", "green")
        return model
    except Exception as e:
        _print(f"[!] 模型加载失败: {e}", "bold red")
        _print("    请确认 sentence-transformers 和 torch 已正确安装，"
               "且 ~/.cache/huggingface 中已有模型权重。", "red")
        sys.exit(1)


def encode_query(model: SentenceTransformer, text: str) -> list[float]:
    """
    将自然语言查询编码为 1024 维向量。
    BGE-M3 推荐在查询前加前缀 'query: '（retrieval 场景）。
    """
    if not text.strip():
        raise ValueError("查询文本不能为空")

    try:
        # normalize_embeddings=True → 单位向量，使余弦相似度等价于点积
        embedding = model.encode(
            f"query: {text}",
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return embedding.tolist()
    except Exception as e:
        raise RuntimeError(f"向量编码失败: {e}") from e


# ─── 数据库连接池 ─────────────────────────────────────────────────────────────

def create_pool() -> psycopg2.pool.ThreadedConnectionPool:
    """创建连接池，含指数退避重试。

    register_vector 内部执行 SELECT 查询会开启隐式事务，
    之后必须 commit() 再归还连接，否则后续连接状态异常。
    """
    for attempt in range(1, MAX_RETRY + 1):
        try:
            pool = psycopg2.pool.ThreadedConnectionPool(
                POOL_MIN_CONN, POOL_MAX_CONN, **DB_CONFIG
            )
            # 对池中已建立的每条连接注册 pgvector 类型
            conn = pool.getconn()
            try:
                register_vector(conn)
                conn.commit()   # 关闭 register_vector 的隐式事务
            finally:
                pool.putconn(conn)
            return pool
        except psycopg2.OperationalError as e:
            if attempt == MAX_RETRY:
                _print(f"[!] 数据库连接失败（已重试 {MAX_RETRY} 次）: {e}", "bold red")
                _print("    请检查 Docker 是否运行、端口 5432 是否可达。", "red")
                sys.exit(1)
            wait = 2 ** attempt
            _print(f"[!] 数据库连接失败（第 {attempt} 次），{wait}s 后重试...", "yellow")
            time.sleep(wait)


# ─── 向量检索 ────────────────────────────────────────────────────────────────

SEARCH_SQL = """
SELECT
    id,
    module_name,
    full_poc_code,
    ai_analysis,
    cve_list,
    required_options,
    1 - (poc_vector <=> %s::vector) AS score
FROM nuclei_exploits
WHERE poc_vector IS NOT NULL
ORDER BY poc_vector <=> %s::vector
LIMIT %s
"""


def search(
    pool: psycopg2.pool.ThreadedConnectionPool,
    query_vec: list[float],
    top_k: int,
) -> list[dict]:
    """
    执行 pgvector 余弦相似度检索。
    使用连接池，游标通过 with 语句管理，确保释放。
    含指数退避重试（应对瞬时 DB 抖动）。
    """
    vec_param = query_vec  # pgvector 驱动接受 Python list

    for attempt in range(1, MAX_RETRY + 1):
        conn = None
        try:
            conn = pool.getconn()
            with conn.cursor() as cur:
                cur.execute(SEARCH_SQL, (vec_param, vec_param, top_k))
                rows = cur.fetchall()
                conn.commit()

            results = []
            for row in rows:
                rid, module_name, full_poc_code, ai_analysis, cve_list, required_options, score = row

                # 安全解析 JSONB → attack_logic 字段
                attack_logic = None
                opsec_risk = None
                auto_parameters = None
                if ai_analysis:
                    try:
                        if isinstance(ai_analysis, str):
                            ai_analysis = json.loads(ai_analysis)
                        attack_logic = ai_analysis.get("attack_logic")
                        opsec_risk = ai_analysis.get("opsec_risk")
                        auto_parameters = ai_analysis.get("auto_parameters")
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # 解析 CVE 列表（去重）
                cves = []
                if cve_list:
                    try:
                        if isinstance(cve_list, str):
                            cve_list = json.loads(cve_list)
                        cves = list(dict.fromkeys(cve_list))  # 去重保序
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # 解析 required_options
                req_opts = {}
                if required_options:
                    try:
                        if isinstance(required_options, str):
                            required_options = json.loads(required_options)
                        req_opts = required_options
                    except (json.JSONDecodeError, AttributeError):
                        pass

                results.append({
                    "id":                rid,
                    "module_name":       module_name,
                    "full_poc_code":     full_poc_code,
                    "attack_logic":      attack_logic,
                    "opsec_risk":        opsec_risk,
                    "auto_parameters":   auto_parameters,
                    "cve_list":          cves,
                    "required_options":  req_opts,
                    "score":             float(score),
                })
            return results

        except psycopg2.OperationalError as e:
            # 连接级别错误（断线等），需要重试
            if attempt == MAX_RETRY:
                raise RuntimeError(f"数据库查询失败（已重试 {MAX_RETRY} 次）: {e}") from e
            wait = 2 ** attempt
            _print(f"[!] 查询失败（第 {attempt} 次），{wait}s 后重试...", "yellow")
            time.sleep(wait)

        except psycopg2.DatabaseError as e:
            # SQL 错误，不重试直接抛出
            raise RuntimeError(f"SQL 执行错误: {e}") from e

        finally:
            if conn is not None:
                pool.putconn(conn)

    return []  # 理论上不会到达


# ─── 主流程 ──────────────────────────────────────────────────────────────────

def run_repl(model, pool, top_k: int, show_code: bool):
    """交互式 REPL 循环。"""
    _print_banner()
    _print(f"\n  输入攻击意图进行搜索，返回 Top-{top_k} 匹配武器", "dim")
    _print("  输入 [bold]quit[/bold] / [bold]exit[/bold] / 按 Ctrl+C 退出\n", "dim")

    while True:
        try:
            if console:
                user_input = console.input("[bold yellow]\\[?][/bold yellow] 请输入攻击意图: ").strip()
            else:
                user_input = input("[?] 请输入攻击意图: ").strip()
        except (KeyboardInterrupt, EOFError):
            _print("\n[*] 已退出。", "dim")
            break

        if not user_input:
            _print("  [提示] 请输入非空的攻击意图描述。", "dim")
            continue

        if user_input.lower() in ("quit", "exit", "q", ":q"):
            _print("[*] 已退出。", "dim")
            break

        # ── 向量编码 ──────────────────────────────────────────
        try:
            t0 = time.time()
            _print("  [*] 正在编码查询...", "dim")
            query_vec = encode_query(model, user_input)
            encode_ms = (time.time() - t0) * 1000
        except (ValueError, RuntimeError) as e:
            _print(f"  [!] 编码失败: {e}", "bold red")
            continue

        # ── 数据库检索 ─────────────────────────────────────────
        try:
            t1 = time.time()
            results = search(pool, query_vec, top_k)
            search_ms = (time.time() - t1) * 1000
        except RuntimeError as e:
            _print(f"  [!] {e}", "bold red")
            continue

        # ── 输出结果 ───────────────────────────────────────────
        if not results:
            _print("  [!] 未找到匹配结果。可能原因：向量尚未完全导入，或查询意图过于特殊。", "yellow")
            continue

        _print(
            f"\n  编码耗时 {encode_ms:.0f}ms | 检索耗时 {search_ms:.0f}ms | "
            f"返回 {len(results)} 条结果\n",
            "dim",
        )
        for i, row in enumerate(results, start=1):
            _print_result(i, row, show_code)

        print()  # 空行分隔下次输入


def run_once(model, pool, query: str, top_k: int, show_code: bool):
    """单次查询模式（-q 参数）。"""
    try:
        query_vec = encode_query(model, query)
    except (ValueError, RuntimeError) as e:
        _print(f"[!] 编码失败: {e}", "bold red")
        sys.exit(1)

    try:
        results = search(pool, query_vec, top_k)
    except RuntimeError as e:
        _print(f"[!] {e}", "bold red")
        sys.exit(1)

    if not results:
        _print("[!] 未找到匹配结果。", "yellow")
        sys.exit(0)

    _print_banner()
    _print(f'\n查询: "{query}"\n', "bold")
    for i, row in enumerate(results, start=1):
        _print_result(i, row, show_code)


# ─── CLI 入口 ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="weapon_radar — 武器库语义雷达（自然语言 → pgvector 检索）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 weapon_radar.py                         # 进入交互模式
  python3 weapon_radar.py -n 5                    # 返回 Top-5
  python3 weapon_radar.py --show-code             # 显示完整 PoC 代码
  python3 weapon_radar.py -q "exploit Apache RCE" # 单次查询
        """,
    )
    parser.add_argument(
        "-n", "--top-k",
        type=int, default=DEFAULT_TOP_K,
        help=f"返回结果数量（默认 {DEFAULT_TOP_K}）",
    )
    parser.add_argument(
        "--show-code",
        action="store_true",
        help="同时输出完整 PoC YAML 代码（默认不显示）",
    )
    parser.add_argument(
        "-q", "--query",
        type=str, default=None,
        help="单次查询模式：指定查询文本后执行一次即退出",
    )
    args = parser.parse_args()

    if args.top_k < 1 or args.top_k > 50:
        _print("[!] --top-k 必须在 1~50 之间", "red")
        sys.exit(1)

    # ── 初始化模型和连接池 ─────────────────────────────────────
    pool  = create_pool()
    model = load_model()

    # ── 执行 ───────────────────────────────────────────────────
    try:
        if args.query:
            run_once(model, pool, args.query, args.top_k, args.show_code)
        else:
            run_repl(model, pool, args.top_k, args.show_code)
    finally:
        try:
            pool.closeall()
        except Exception:
            pass


if __name__ == "__main__":
    main()
