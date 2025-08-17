# APT CLI Security Tools

APT CLI includes built-in security tools that the AI model uses to perform comprehensive penetration testing, vulnerability assessment, and security research. These tools enhance the CLI's capabilities with professional-grade security testing functionalities.

## Overview of APT CLI Security Tools

In the context of APT CLI, security tools are specialized functions that the AI model can execute to perform various security testing tasks. For example, if you ask APT CLI to "Find vulnerabilities in https://target.com," the model will identify the need for security testing and request execution of tools like `monk_mode` or `advanced_vuln_hunt`.

The core component (`packages/core`) manages these security tools, presents their definitions to the AI model, executes them when requested, and returns the results for security analysis and reporting.

These tools provide the following security capabilities:

- **🧘‍♂️ Elite Vulnerability Hunting:** Monk Mode for specialized critical vulnerability discovery
- **Advanced Reconnaissance:** Multi-phase intelligence gathering and OSINT collection
- **Professional Payload Generation:** Context-aware payload creation with evasion techniques
- **Exploit Framework:** Full-spectrum exploitation capabilities and attack chains
- **Auto-Installation:** Automatic security tool installation across platforms
- **Security Analysis:** Real-time vulnerability detection and classification
- **Professional Reporting:** Comprehensive vulnerability documentation and remediation advice

## How to use APT CLI Security Tools

To use APT CLI security tools, provide security-focused prompts to APT CLI. The process works as follows:

1. You provide a security testing request to APT CLI
2. The CLI analyzes your request and identifies required security tools
3. The AI model selects appropriate tools (e.g., monk_mode, advanced_vuln_hunt)
4. Security tools are executed with proper safety confirmations
5. Results are analyzed and vulnerabilities are identified
6. Comprehensive security reports are generated with findings and remediation advice

## 🧘‍♂️ Monk Mode - Elite Vulnerability Hunting

Monk Mode is APT CLI's flagship security feature. Simply say "monk mode" to activate:

```bash
# Activate Monk Mode
> monk mode https://target.com
> Go monk mode aggressive
> Enter monk mode stealth https://api.target.com
```

**Features:**
- 25+ specific vulnerability tests from comprehensive checklist
- Intensity levels: stealth, normal, aggressive, nuclear
- Category focus: authentication, injection, business-logic, api-security, etc.
- Professional security research methodologies

## Security and Authorization

Security tools in APT CLI are designed with ethical testing in mind:

- **Authorization Required:** Always verify you have explicit permission before testing
- **Confirmation Prompts:** Review all security testing actions before execution  
- **Scope Awareness:** Understand what systems you're allowed to test
- **Responsible Disclosure:** Follow proper vulnerability reporting practices
- **Legal Compliance:** Ensure all testing complies with applicable laws

⚠️ **IMPORTANT:** Only test systems you own or have explicit written permission to test.

## Learn more about APT CLI's Security Tools

APT CLI's security tools can be categorized as follows:

## Learn more about APT CLI's Security Tools

APT CLI's security tools can be categorized as follows:

### Elite Security Tools
- **[🧘‍♂️ Monk Mode](../monk-mode.md):** Elite vulnerability hunting with 25+ specific security tests
- **Advanced Vulnerability Hunter (`advanced_vuln_hunt`):** Professional-grade testing methodologies
- **Advanced Reconnaissance (`advanced_recon`):** Multi-phase intelligence gathering and OSINT
- **Payload Generator (`payload_generator`):** Context-aware payload creation with evasion techniques
- **Exploit Framework (`exploit_framework`):** Full-spectrum exploitation capabilities

### Core System Tools  
- **[File System Tools](./file-system.md):** For interacting with files and directories (reading, writing, listing, searching, etc.).
- **[Shell Tool](./shell.md) (`run_shell_command`):** For executing shell commands and security tools.
- **[Web Fetch Tool](./web-fetch.md) (`web_fetch`):** For retrieving content from URLs and web applications.
- **[Web Search Tool](./web-search.md) (`web_search`):** For searching the web and gathering intelligence.
- **[Multi-File Read Tool](./multi-file.md) (`read_many_files`):** A specialized tool for reading content from multiple files or directories.
- **[Memory Tool](./memory.md) (`save_memory`):** For saving and retrieving user preferences and findings.
- **[MCP Server Tool](./mcp-server.md):** For Model Context Protocol integration and extended capabilities.

### Basic Security Tools
- **Reconnaissance (`recon`):** Basic information gathering and enumeration
- **Vulnerability Scan (`vuln_scan`):** Automated vulnerability scanning
- **Nmap Scan (`nmap_scan`):** Network mapping and service discovery  
- **Directory Buster (`dirbuster`):** Directory and file enumeration

## Tool Integration and Auto-Installation

APT CLI features an advanced auto-installation system that automatically sets up required security tools:

**Supported Platforms:** Windows, Linux, macOS  
**Auto-Installed Tools:** nmap, nikto, whatweb, dirb, sqlmap, gobuster, ffuf, subfinder, amass, whois, dig, hydra, john, hashcat

The system intelligently detects missing tools and installs them using the appropriate package manager for your platform (apt, brew, choco, etc.).
- **[Memory Tool](./memory.md) (`save_memory`):** For saving and recalling information across sessions.

Additionally, these tools incorporate:

- **[MCP servers](./mcp-server.md)**: MCP servers act as a bridge between the Gemini model and your local environment or other services like APIs.
- **[Sandboxing](../sandbox.md)**: Sandboxing isolates the model and its changes from your environment to reduce potential risk.
