"""Debug: show ast end_lineno for MCP tools and what's actually on those lines."""
import ast

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

print(f"Total tools: {len(mcp_tools)}")
print()

# Print boundary info for every tool
for fn in mcp_tools:
    end = fn.end_lineno
    end_line_content = lines[end - 1].rstrip() if end <= len(lines) else "EOF"
    next_line_content = lines[end].rstrip() if end < len(lines) else "EOF"
    next_next = lines[end + 1].rstrip() if end + 1 < len(lines) else "EOF"

    # Check if end_lineno points to something suspicious (decorator or blank)
    is_suspicious = "@mcp.tool" in end_line_content or (
        end < len(lines) and "@mcp.tool" in next_line_content
    )

    if is_suspicious:
        print(f"SUSPICIOUS: {fn.name} (def line {fn.lineno}, end line {end})")
        print(f"  end_line:  {repr(end_line_content)}")
        print(f"  next_line: {repr(next_line_content)}")
        print(f"  next+1:    {repr(next_next)}")
        print()
