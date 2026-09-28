from client import AgentPromptInjectionSanitizer
import json

sanitizer = AgentPromptInjectionSanitizer()
print("=== AGENT PROMPT INJECTION SANITIZER BENCHMARK ===")
res = sanitizer.run_firewall_benchmark()
print(json.dumps(res, indent=2))
