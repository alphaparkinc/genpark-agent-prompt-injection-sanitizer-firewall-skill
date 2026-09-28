import sys, json
from client import AgentPromptInjectionSanitizer

def handle_mcp():
    sanitizer = AgentPromptInjectionSanitizer()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(sanitizer.run_firewall_benchmark(), indent=2))
        return

    for line in sys.stdin:
        if not line.strip(): continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")
            
            if method == "initialize":
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "genpark-agent-prompt-injection-sanitizer-firewall-skill", "version": "1.0.0"},
                    "capabilities": {"tools": {}}
                }}
            elif method == "tools/list":
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [
                    {"name": "scan_prompt_safety", "description": "Scan input prompt for injection, delimiter overrides, and exfiltration.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
                    {"name": "sanitize_untrusted_input", "description": "Sanitize and neutralize adversarial payloads within untrusted data.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
                    {"name": "inspect_tool_call_safety", "description": "Verify tool call arguments against command, SQL, and path injection.", "inputSchema": {"type": "object", "properties": {"tool_name": {"type": "string"}, "tool_arguments": {"type": "object"}}}},
                    {"name": "run_firewall_benchmark", "description": "Run prompt injection firewall benchmark.", "inputSchema": {"type": "object"}}
                ]}}
            elif method == "tools/call":
                tname = req.get("params", {}).get("name")
                args = req.get("params", {}).get("arguments", {})
                if tname == "scan_prompt_safety":
                    res = sanitizer.scan_prompt_safety(args.get("text", ""))
                elif tname == "sanitize_untrusted_input":
                    res = sanitizer.sanitize_untrusted_input(args.get("text", ""))
                elif tname == "inspect_tool_call_safety":
                    res = sanitizer.inspect_tool_call_safety(args.get("tool_name", ""), args.get("tool_arguments", {}))
                else:
                    res = sanitizer.run_firewall_benchmark()
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}}
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}
            
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    handle_mcp()
