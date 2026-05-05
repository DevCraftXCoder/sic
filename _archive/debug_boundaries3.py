"""Debug: check what happens with body_end slicing for a few tools."""
import ast
import sys

sys.stdout.reconfigure(encoding="utf-8")

with open("C:/Za/sic/hexstrike_mcp.py", encoding="utf-8") as f:
    source = f.read()

lines = source.splitlines(keepends=True)
tree = ast.parse(source)

mcp_tools = []
for node in ast.walk(tree):
    if not isinstance(node, ast.FunctionDef):
        continue
    for dec in node.decorator_list:
        if (isinstance(dec, ast.Call) and
                isinstance(dec.func, ast.Attribute) and
                dec.func.attr == "tool"):
            mcp_tools.append(node)
            break

mcp_tools.sort(key=lambda x: x.lineno)

# Find hakrawler, httpx, zap
target_names = {"hakrawler_crawl", "httpx_probe", "zap_scan", "hakrawler", "httpx", "zap"}
for fn in mcp_tools:
    name_lower = fn.name.lower()
    if any(t in name_lower for t in target_names):
        body = fn.body
        code_stmts = body
        if (body and isinstance(body[0], ast.Expr) and
                isinstance(body[0].value, ast.Constant) and
                isinstance(body[0].value.value, str)):
            code_stmts = body[1:]

        first_code_lineno = code_stmts[0].lineno if code_stmts else None
        body_end = fn.end_lineno

        print(f"Tool: {fn.name}")
        print(f"  def_line: {fn.lineno}")
        print(f"  first_code_lineno: {first_code_lineno}")
        print(f"  body_end (end_lineno): {body_end}")

        # Show last 3 lines of body and 3 lines after
        for i in range(max(first_code_lineno - 1, body_end - 3), min(body_end, len(lines))):
            content = lines[i].rstrip().encode("ascii", "replace").decode("ascii")
            print(f"    [{i+1}] {content}")

        for i in range(body_end, min(body_end + 3, len(lines))):
            content = lines[i].rstrip().encode("ascii", "replace").decode("ascii")
            print(f"  after [{i+1}] {content}")
        print()
