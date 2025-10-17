#!/usr/bin/env python3

import argparse
import asyncio
import sys
from colorama import Fore, Style, init
from enumeration import perform_recon, detect_vulnerability, print_banner, print_recon_summary
from exploitation import run_exploit, run_all_exploits

# Initialize colorama
init(autoreset=True)

# Target ports for DV-MCP
VULNERABLE_PORTS = [9001, 9002, 9003, 9005, 9007, 9008, 9010]

def print_mode_header(mode: str):
    """Print the mode header."""
    print(f"\n{Fore.MAGENTA}{'='*70}")
    print(f"{Fore.MAGENTA}  MODE: {mode.upper()}")
    print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")

async def recon_mode(target: str):
    """
    Reconnaissance mode: Enumerate target and detect vulnerabilities.
    
    Args:
        target: Target URL or IP address
    """
    print_mode_header("reconnaissance")
    
    # Parse target to construct full URL
    if not target.startswith("http"):
        # Assume localhost if just a port is provided
        if target.isdigit():
            url = f"http://localhost:{target}/sse"
        else:
            url = f"http://{target}/sse"
    else:
        url = target
    
    try:
        recon_data = await perform_recon(url)
        vuln_name = detect_vulnerability(recon_data)
        print_recon_summary(recon_data, vuln_name)
        
        if vuln_name != "unknown":
            print(f"\n{Fore.GREEN}[✓] Target is exploitable!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Use '--mode exploit --target {target}' to attempt exploitation{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No known vulnerabilities detected{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Reconnaissance failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

async def exploit_mode(target: str):
    """
    Exploitation mode: Run all available exploits against target.
    
    Args:
        target: Target URL or IP address
    """
    print_mode_header("exploitation")
    
    # Parse target to construct full URL
    if not target.startswith("http"):
        if target.isdigit():
            url = f"http://localhost:{target}/sse"
        else:
            url = f"http://{target}/sse"
    else:
        url = target
    
    try:
        # First perform recon to gather information
        print(f"{Fore.CYAN}[*] Performing initial reconnaissance...{Style.RESET_ALL}\n")
        recon_data = await perform_recon(url)
        vuln_name = detect_vulnerability(recon_data)
        
        print(f"\n{Fore.CYAN}[*] Starting exploitation phase...{Style.RESET_ALL}\n")
        
        # Run all exploits
        await run_all_exploits(url, recon_data)
        
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Exploitation failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

async def auto_mode(target: str = None):
    """
    Auto mode: Automatically scan and exploit target(s).
    
    Args:
        target: Optional specific target. If None, scans all default ports.
    """
    print_mode_header("automatic")
    
    if target:
        # Single target auto mode
        if not target.startswith("http"):
            if target.isdigit():
                url = f"http://localhost:{target}/sse"
            else:
                url = f"http://{target}/sse"
        else:
            url = target
        
        try:
            print(f"{Fore.CYAN}[*] Target: {url}{Style.RESET_ALL}\n")
            
            # Recon
            recon_data = await perform_recon(url)
            vuln_name = detect_vulnerability(recon_data)
            
            if vuln_name != "unknown":
                print(f"\n{Fore.GREEN}[✓] Target is vulnerable! Proceeding with exploitation...{Style.RESET_ALL}\n")
                await run_exploit(url, vuln_name, recon_data)
            else:
                print(f"\n{Fore.YELLOW}[!] No known vulnerabilities detected{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"\n{Fore.RED}[✗] Auto mode failed for {url}: {e}{Style.RESET_ALL}")
    
    else:
        # Multi-target auto mode - scan all vulnerable ports
        print(f"{Fore.CYAN}[*] Scanning all vulnerable ports: {VULNERABLE_PORTS}{Style.RESET_ALL}\n")
        
        successful_exploits = 0
        failed_targets = 0
        
        for port in VULNERABLE_PORTS:
            url = f"http://localhost:{port}/sse"
            
            print(f"\n{Fore.YELLOW}{'='*70}")
            print(f"{Fore.YELLOW}  🎯 SCANNING PORT {port}")
            print(f"{Fore.YELLOW}{'='*70}{Style.RESET_ALL}\n")
            
            try:
                # Recon
                recon_data = await perform_recon(url)
                vuln_name = detect_vulnerability(recon_data)
                
                if vuln_name != "unknown":
                    print(f"\n{Fore.GREEN}[✓] Vulnerability detected! Exploiting...{Style.RESET_ALL}\n")
                    success = await run_exploit(url, vuln_name, recon_data)
                    if success:
                        successful_exploits += 1
                else:
                    print(f"\n{Fore.YELLOW}[!] No vulnerability detected on port {port}{Style.RESET_ALL}")
                    
            except Exception as e:
                error_msg = str(e).lower()
                if "connection" in error_msg or "refused" in error_msg:
                    print(f"\n{Fore.RED}[✗] Port {port}: Server not running or unreachable{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}[✗] Port {port}: {e}{Style.RESET_ALL}")
                failed_targets += 1
        
        # Final summary
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}  🏁 FINAL SCAN SUMMARY")
        print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Successful Exploits: {successful_exploits}{Style.RESET_ALL}")
        print(f"{Fore.RED}Failed/Unreachable: {failed_targets}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total Ports Scanned: {len(VULNERABLE_PORTS)}{Style.RESET_ALL}\n")

def main():
    """Main entry point for DV-MCP framework."""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Damn Vulnerable MCP Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.WHITE}# Reconnaissance on port 9001{Style.RESET_ALL}
  python3 dv_mcp.py --mode recon --target 9001
  
  {Fore.WHITE}# Exploit specific target{Style.RESET_ALL}
  python3 dv_mcp.py --mode exploit --target http://localhost:9001/sse
  
  {Fore.WHITE}# Auto mode on specific port{Style.RESET_ALL}
  python3 dv_mcp.py --mode auto --target 9001
  
  {Fore.WHITE}# Auto mode on all vulnerable ports{Style.RESET_ALL}
  python3 dv_mcp.py --mode auto

        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["recon", "exploit", "auto"],
        required=True,
        help="Operation mode: recon (enumerate), exploit (attack), auto (scan+exploit)"
    )
    
    parser.add_argument(
        "--target",
        help="Target URL, IP, or port number (e.g., 9001, localhost:9001, http://localhost:9001/sse)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode in ["recon", "exploit"] and not args.target:
        print(f"{Fore.RED}[✗] Error: --target is required for {args.mode} mode{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    # Execute appropriate mode
    try:
        if args.mode == "recon":
            asyncio.run(recon_mode(args.target))
        elif args.mode == "exploit":
            asyncio.run(exploit_mode(args.target))
        elif args.mode == "auto":
            asyncio.run(auto_mode(args.target))
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
