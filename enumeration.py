#!/usr/bin/env python3

import json
from typing import Dict, Any, List
from mcp import ClientSession
from mcp.client.sse import sse_client
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def to_serializable(obj):
    """Convert Pydantic models and other objects into JSON-serializable types."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_serializable(v) for v in obj]
    if hasattr(obj, "model_dump"):
        return to_serializable(obj.model_dump())
    if hasattr(obj, "dict"):
        return to_serializable(obj.dict())
    return str(obj)

def print_banner():
    print("███╗   ███╗ ██████╗██████╗ ██╗      ██████╗ ██╗████████╗")
    print("████╗ ████║██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝")
    print("██╔████╔██║██║     ██████╔╝██║     ██║   ██║██║   ██║")
    print("██║╚██╔╝██║██║     ██╔═══╝ ██║     ██║   ██║██║   ██║")
    print("██║ ╚═╝ ██║╚██████╗██║     ███████╗╚██████╔╝██║   ██║")
    print("╚═╝     ╚═╝ ╚═════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝")

def print_section_header(title: str):
    """Print a formatted section header."""
    print(f"\n{Fore.YELLOW}{'='*70}")
    print(f"{Fore.YELLOW}  {title}")
    print(f"{Fore.YELLOW}{'='*70}{Style.RESET_ALL}\n")

def print_subsection(title: str, icon: str):
    """Print a formatted subsection."""
    print(f"\n{Fore.CYAN}{icon} {title}")
    print(f"{Fore.CYAN}{'-'*(len(title) + 4)}{Style.RESET_ALL}")

def print_item(index: int, data: Dict[str, Any], item_type: str):
    """Print a single item with color coding."""
    if item_type == "tool":
        color = Fore.GREEN
    elif item_type == "resource":
        color = Fore.MAGENTA
    elif item_type == "prompt":
        color = Fore.BLUE
    else:
        color = Fore.WHITE
    
    print(f"{color}[{index}] {json.dumps(data, indent=2)}{Style.RESET_ALL}")

async def perform_recon(server_url: str) -> Dict[str, Any]:
    """
    Connects to the MCP server and enumerates all available assets.
    
    Returns:
        Dict containing tools, resources, prompts, and tool names
    """
    try:
        async with ClientSession(sse_client(server_url)) as session:
            await session.initialize()

            print_section_header("🔍 RECONNAISSANCE PHASE")
            print(f"{Fore.WHITE}Target: {Fore.CYAN}{server_url}{Style.RESET_ALL}")

            # Enumerate Tools
            tools = await session.list_tools()
            serializable_tools = to_serializable(tools)
            tool_names = [t.get('name') for t in serializable_tools if isinstance(t, dict) and t.get('name')]

            print_subsection("Available Tools", "🛠️")
            if serializable_tools:
                for i, tool in enumerate(serializable_tools, 1):
                    print_item(i, tool, "tool")
            else:
                print(f"{Fore.RED}  (None found){Style.RESET_ALL}")

            # Enumerate Resources
            resources = await session.list_resources()
            serializable_resources = to_serializable(resources)

            print_subsection("Available Resources", "📦")
            if serializable_resources:
                for i, resource in enumerate(serializable_resources, 1):
                    print_item(i, resource, "resource")
            else:
                print(f"{Fore.RED}  (None found){Style.RESET_ALL}")

            # Enumerate Prompts
            prompts = await session.list_prompts()
            serializable_prompts = to_serializable(prompts)

            print_subsection("Available Prompts", "💡")
            if serializable_prompts:
                for i, prompt in enumerate(serializable_prompts, 1):
                    print_item(i, prompt, "prompt")
            else:
                print(f"{Fore.RED}  (None found){Style.RESET_ALL}")

            recon_data = {
                "server_url": server_url,
                "tools": serializable_tools,
                "resources": serializable_resources,
                "prompts": serializable_prompts,
                "tool_names": tool_names
            }

            return recon_data

    except Exception as e:
        print(f"\n{Fore.RED}[✗] Reconnaissance failed: {e}{Style.RESET_ALL}")
        raise

def detect_vulnerability(recon_data: Dict[str, Any]) -> str:
    """
    Analyzes reconnaissance data to detect vulnerability type.
    
    Returns:
        Vulnerability identifier string
    """
    tool_names = recon_data.get("tool_names", [])
    resources = recon_data.get("resources", [])
    resource_uris = [r.get('uri', '') for r in resources]
    has_notes_resource = any(uri.startswith("notes://") for uri in resource_uris)
    
    print_section_header("🎯 VULNERABILITY DETECTION")
    
    # Port 9001 - Prompt Injection (notes:// -> internal://credentials)
    if has_notes_resource or "internal://credentials" in set(resource_uris):
        vuln = "prompt_injection_9001"
        print(f"{Fore.GREEN}[✓] Detected: PROMPT INJECTION (Port 9001)")
        print(f"{Fore.YELLOW}    Vector: notes:// resource injection -> internal://credentials{Style.RESET_ALL}")
        return vuln

    # Port 9002 - Tool Poisoning
    if "get_company_data" in tool_names or "search_company_database" in tool_names:
        vuln = "tool_poisoning_9002"
        print(f"{Fore.GREEN}[✓] Detected: TOOL POISONING (Port 9002)")
        print(f"{Fore.YELLOW}    Vector: poisoned company data tools reveal confidential resources{Style.RESET_ALL}")
        return vuln

    # Port 9003 - Permission Scope
    if "read_file" in tool_names or "search_files" in tool_names:
        vuln = "permission_scope_9003"
        print(f"{Fore.GREEN}[✓] Detected: EXCESSIVE PERMISSION SCOPE (Port 9003)")
        print(f"{Fore.YELLOW}    Vector: unrestricted file read/search tools{Style.RESET_ALL}")
        return vuln

    # Port 9004 - Rug Pull
    if "get_weather" in tool_names:
        vuln = "rug_pull_9004"
        print(f"{Fore.GREEN}[✓] Detected: RUG PULL (Port 9004)")
        print(f"{Fore.YELLOW}    Vector: repeated get_weather calls unlock system://config{Style.RESET_ALL}")
        return vuln

    # Port 9005 - Tool Shadowing
    if "enhanced_calculate" in tool_names:
        vuln = "tool_shadowing_9005"
        print(f"{Fore.GREEN}[✓] Detected: TOOL SHADOWING (Port 9005)")
        print(f"{Fore.YELLOW}    Vector: enhanced_calculate shadowing to reach system://secrets{Style.RESET_ALL}")
        return vuln

    # Port 9006 - Indirect Prompt Injection
    if "process_document" in tool_names:
        vuln = "indirect_prompt_injection_9006"
        print(f"{Fore.GREEN}[✓] Detected: INDIRECT PROMPT INJECTION (Port 9006)")
        print(f"{Fore.YELLOW}    Vector: malicious documents force system://api_keys exposure{Style.RESET_ALL}")
        return vuln

    # Port 9007 - Token Theft
    if "check_email" in tool_names or "check_service_status" in tool_names or "view_system_logs" in tool_names:
        vuln = "token_theft_9007"
        print(f"{Fore.GREEN}[✓] Detected: TOKEN THEFT (Port 9007)")
        print(f"{Fore.YELLOW}    Vector: error paths leak bearer/JWT tokens{Style.RESET_ALL}")
        return vuln

    # Port 9008 - Command Injection
    if "run_system_diagnostic" in tool_names:
        vuln = "command_injection_9008"
        print(f"{Fore.GREEN}[✓] Detected: COMMAND INJECTION (Port 9008)")
        print(f"{Fore.YELLOW}    Vector: unsanitized diagnostic command execution{Style.RESET_ALL}")
        return vuln

    # Port 9010 - Multi-Vector Attack
    if "multi_stage_attack" in tool_names or bool(set(tool_names) & {"get_company_data", "enhanced_calculate"}):
        vuln = "multi_vector_9010"
        print(f"{Fore.GREEN}[✓] Detected: MULTI-VECTOR ATTACK (Port 9010)")
        print(f"{Fore.YELLOW}    Vector: chained poisoned tools + shadowed logic{Style.RESET_ALL}")
        return vuln
    
    print(f"{Fore.RED}[✗] No known vulnerability detected{Style.RESET_ALL}")
    return "unknown"

def print_recon_summary(recon_data: Dict[str, Any], vuln_name: str):
    """Print a summary of reconnaissance results."""
    print_section_header("📊 RECONNAISSANCE SUMMARY")
    
    print(f"{Fore.CYAN}Target URL:{Style.RESET_ALL} {recon_data['server_url']}")
    print(f"{Fore.CYAN}Tools Found:{Style.RESET_ALL} {len(recon_data['tool_names'])}")
    print(f"{Fore.CYAN}Resources Found:{Style.RESET_ALL} {len(recon_data['resources'])}")
    print(f"{Fore.CYAN}Prompts Found:{Style.RESET_ALL} {len(recon_data['prompts'])}")
    
    if vuln_name != "unknown":
        print(f"\n{Fore.GREEN}[✓] Vulnerability:{Style.RESET_ALL} {Fore.RED}{vuln_name.replace('_', ' ').upper()}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Status:{Style.RESET_ALL} {Fore.RED}EXPLOITABLE{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}[!] Vulnerability:{Style.RESET_ALL} Unknown or Not Detected")
        print(f"{Fore.YELLOW}[!] Status:{Style.RESET_ALL} Further analysis required")
