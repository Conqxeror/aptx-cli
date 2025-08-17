# Welcome to APT CLI documentation

This documentation provides a comprehensive guide to installing, using, and developing APT CLI. This tool is an AI-powered Advanced Penetration Testing command-line interface designed for cybersecurity professionals, bug hunters, and penetration testers.

## Overview

APT CLI brings professional-grade security testing capabilities to your terminal through an intelligent AI-powered interface. APT CLI consists of a client-side application (`packages/cli`) that communicates with a local server (`packages/core`), which manages AI models and security tools. APT CLI includes advanced security tools like Monk Mode for elite vulnerability hunting, advanced reconnaissance, payload generation, and exploit frameworks.

## 🧘‍♂️ Monk Mode - Elite Vulnerability Hunting

APT CLI's flagship feature is **Monk Mode** - a specialized vulnerability hunting mode that targets critical security flaws with laser precision. Simply say "monk mode" to activate this elite testing framework that covers 25+ specific vulnerability types.

## Key Security Features

- **Monk Mode**: Elite vulnerability hunting with intensity levels and category focus
- **Advanced Vulnerability Hunting**: Professional-grade testing methodologies
- **Comprehensive Reconnaissance**: Multi-phase intelligence gathering
- **Payload Generation**: Context-aware payload creation with evasion techniques
- **Exploit Framework**: Full-spectrum exploitation capabilities
- **Auto-Installer**: Automatic security tool installation across platforms

## Navigating the documentation

This documentation is organized into the following sections:

- **[Execution and Deployment](./deployment.md):** Information for running APT CLI.
- **[Architecture Overview](./architecture.md):** Understand the high-level design of APT CLI, including its components and how they interact.
- **CLI Usage:** Documentation for `packages/cli`.
  - **[CLI Introduction](./cli/index.md):** Overview of the command-line interface.
  - **[Commands](./cli/commands.md):** Description of available CLI commands.
  - **[Configuration](./cli/configuration.md):** Information on configuring the CLI.
  - **[Checkpointing](./checkpointing.md):** Documentation for the checkpointing feature.
  - **[Extensions](./extension.md):** How to extend the CLI with new functionality.
  - **[Telemetry](./telemetry.md):** Overview of telemetry in the CLI.
- **Core Details:** Documentation for `packages/core`.
  - **[Core Introduction](./core/index.md):** Overview of the core component.
  - **[Tools API](./core/tools-api.md):** Information on how the core manages and exposes tools.
- **Security Tools:**
  - **[Tools Overview](./tools/index.md):** Overview of the available security tools.
  - **[Monk Mode](../monkMode.md):** Elite vulnerability hunting documentation.
  - **[File System Tools](./tools/file-system.md):** Documentation for the `read_file` and `write_file` tools.
  - **[Multi-File Read Tool](./tools/multi-file.md):** Documentation for the `read_many_files` tool.
  - **[Shell Tool](./tools/shell.md):** Documentation for the `run_shell_command` tool.
  - **[Web Fetch Tool](./tools/web-fetch.md):** Documentation for the `web_fetch` tool.
  - **[Web Search Tool](./tools/web-search.md):** Documentation for the `web_search` tool.
  - **[Memory Tool](./tools/memory.md):** Documentation for the `save_memory` tool.
  - **[MCP Server Tool](./tools/mcp-server.md):** Documentation for Model Context Protocol integration.
- **[Contributing & Development Guide](../CONTRIBUTING.md):** Information for contributors and developers, including setup, building, testing, and coding conventions.
- **[NPM Workspaces and Publishing](./npm.md):** Details on how the project's packages are managed and published.
- **[Troubleshooting Guide](./troubleshooting.md):** Find solutions to common problems and FAQs.
- **[Terms of Service and Privacy Notice](./tos-privacy.md):** Information on the terms of service and privacy notices applicable to your use of APT CLI.

We hope this documentation helps you make the most of APT CLI!
