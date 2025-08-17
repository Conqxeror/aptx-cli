/**
 * @export const aptCommand: SlashCommand = {
  name: - `/about` - About APTX CLI

Happy bug hunting! 🔍🛡️`;t',
  description: 'Show APTX CLI information and available penetration testing commands',
  kind: CommandKind.BUILT_IN,
  action: async (context) => {
    const content = `# APTX CLI - Advanced Penetration Testing

APTX CLI is an AI-powered command-line tool designed for bug hunters and penetration testers.
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SlashCommand, CommandKind } from './types.js';
import { MessageType } from '../types.js';

export const aptCommand: SlashCommand = {
  name: 'apt',
  description: 'Show APT CLI information and available penetration testing commands',
  kind: CommandKind.BUILT_IN,
  action: async (context) => {
    const content = `# APT CLI - Advanced Penetration Testing

APT CLI is an AI-powered command-line tool designed for bug hunters and penetration testers.

## Available Security Commands:

### Reconnaissance
- \`recon target.com\` - Perform reconnaissance on a target
- \`recon target.com --type=dns\` - DNS enumeration only
- \`recon target.com --type=subdomain\` - Subdomain discovery
- \`recon target.com --passive\` - Passive reconnaissance only

### Vulnerability Scanning
- \`vuln_scan https://target.com\` - Comprehensive vulnerability scan
- \`vuln_scan https://target.com --type=sqli\` - SQL injection testing
- \`vuln_scan https://target.com --type=xss\` - XSS vulnerability testing

### Network Analysis
- \`nmap_scan 192.168.1.1\` - Network port scanning
- \`nmap_scan target.com --type=stealth\` - Stealth scan
- \`nmap_scan 192.168.1.0/24 --type=vuln\` - Vulnerability detection scan

### Directory Discovery
- \`dirbuster https://target.com\` - Directory and file discovery
- \`dirbuster https://target.com --wordlist=large\` - Comprehensive scan

### Web Application Testing
- \`web_fetch https://target.com "analyze for security headers"\`
- \`web_search "target.com vulnerability reports"\`

## Security Best Practices:
- Always ensure you have proper authorization before testing
- Use passive techniques when possible
- Document findings securely
- Follow responsible disclosure practices

## Getting Help:
- \`/help\` - Show all available commands
- \`/tools\` - List available security tools
- \`/about\` - About APT CLI

Happy bug hunting! 🔍🛡️`;

    const aptItem = {
      type: MessageType.INFO,
      content,
      timestamp: new Date(),
    };

    context.ui.addItem(aptItem, Date.now());
  },
};
