# APTX CLI - Advanced Penetration Testing Command Line Interface

Within APTX CLI, `packages/cli` is the security-focused frontend for users to conduct professional penetration testing with AI-powered assistance. For a general overview of APTX CLI, see the [main documentation page](../index.md).

## Security Features

APTX CLI transforms traditional penetration testing with AI-powered capabilities:

- **🧘‍♂️ Monk Mode**: Elite vulnerability hunting with 25+ specialized security tests
- **Auto Security Tool Installation**: Automatic setup of 15+ essential penetration testing tools
- **Advanced Reconnaissance**: Multi-phase intelligence gathering and OSINT capabilities
- **Payload Generation**: Context-aware payload creation with evasion techniques
- **Exploit Framework**: Full-spectrum exploitation capabilities

## Navigating this section

- **[Authentication](./authentication.md):** A guide to setting up authentication with AI providers for security testing.
- **[Commands](./commands.md):** A reference for APTX CLI commands (e.g., `/help`, `/tools`, `/theme`, `/monk`).
- **[Configuration](./configuration.md):** A guide to tailoring APTX CLI behavior using configuration files.
- **[Token Caching](./token-caching.md):** Optimize API costs during extended penetration testing sessions.
- **[Themes](./themes.md)**: A guide to customizing the CLI's appearance with security-focused themes.
- **[Tutorials](tutorials.md)**: Tutorials showing how to use APTX CLI for various penetration testing tasks.

## Non-interactive Security Testing

APTX CLI can be run in a non-interactive mode, which is useful for scripting and automated security testing. In this mode, you pipe security commands to the CLI, it executes them, and then exits.

The following example pipes a security assessment command to APTX CLI from your terminal:

```bash
echo "Scan this network for vulnerabilities: 192.168.1.0/24" | aptx-cli
```

APTX CLI executes the security assessment and prints the results to your terminal. Note that you can achieve the same behavior by using the `--prompt` or `-p` flag. For example:

```bash
aptx-cli -p "Conduct a web application security test on https://example.com"
```

## Quick Security Commands

Start security testing immediately with these common commands:

```bash
# Quick vulnerability scan
aptx-cli -p "Quick vuln scan on example.com"

# Network reconnaissance  
aptx-cli -p "Recon scan 192.168.1.0/24"

# Activate Monk Mode for elite testing
aptx-cli -p "/monk https://target.com"
```
