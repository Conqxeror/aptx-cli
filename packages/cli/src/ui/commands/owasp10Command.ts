/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SlashCommand, CommandKind } from './types.js';
import { MessageType } from '../types.js';

export const owasp10Command: SlashCommand = {
  name: 'owasp10',
  description: 'Test target against OWASP Top 10 vulnerabilities',
  kind: CommandKind.BUILT_IN,
  action: async (context) => {
    const content = `# OWASP Top 10 Testing Guide

Usage: Ask me to "test [target] for OWASP Top 10 vulnerabilities"

Example: "Test https://example.com for OWASP Top 10 vulnerabilities"

This command tests a target against the OWASP Top 10 vulnerabilities:

## OWASP Top 10 2021:

1. **A01 Broken Access Control**
   - Testing for unauthorized access
   - Privilege escalation attempts
   - IDOR (Insecure Direct Object References)

2. **A02 Cryptographic Failures**
   - Weak encryption detection
   - Sensitive data exposure
   - Certificate validation

3. **A03 Injection**
   - SQL injection testing
   - NoSQL injection
   - Command injection
   - LDAP injection

4. **A04 Insecure Design**
   - Business logic flaws
   - Missing security controls
   - Threat modeling gaps

5. **A05 Security Misconfiguration**
   - Default credentials
   - Unnecessary features enabled
   - Missing security headers

6. **A06 Vulnerable Components**
   - Outdated libraries
   - Known CVE scanning
   - Dependency analysis

7. **A07 Identification and Authentication Failures**
   - Weak password policies
   - Session management flaws
   - Multi-factor authentication bypass

8. **A08 Software and Data Integrity Failures**
   - Untrusted sources
   - Auto-update mechanisms
   - CI/CD pipeline security

9. **A09 Security Logging and Monitoring Failures**
   - Log injection
   - Insufficient logging
   - Real-time monitoring gaps

10. **A10 Server-Side Request Forgery (SSRF)**
    - Internal network access
    - Cloud metadata exposure
    - Port scanning via SSRF

**Usage Tips:**
- Provide a target URL to begin comprehensive OWASP Top 10 testing
- Ask for specific vulnerability testing: "Test for SQL injection on example.com"
- Request detailed analysis: "Perform OWASP security assessment on my application"

**Remember:** Always ensure you have proper authorization before testing!`;

    const owaspItem = {
      type: MessageType.INFO,
      content,
      timestamp: new Date(),
    };

    context.ui.addItem(owaspItem, Date.now());
  },
};
