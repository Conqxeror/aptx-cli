/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SlashCommand, CommandKind } from './types.js';
import { MessageType } from '../types.js';

export const huntCommand: SlashCommand = {
  name: 'hunt',
  description: 'Start a guided bug hunting session with AI assistance',
  kind: CommandKind.BUILT_IN,
  action: async (context) => {
    const content = `# Bug Hunting Guide

Usage: \`/hunt <target>\` (or just ask me to help hunt bugs on a specific target)

This will start a guided bug hunting session where the AI will help you:

## 1. **Reconnaissance Phase**
   - Domain and subdomain enumeration
   - Technology stack identification
   - Infrastructure analysis

## 2. **Discovery Phase** 
   - Directory and file discovery
   - Parameter fuzzing
   - Endpoint enumeration

## 3. **Vulnerability Assessment**
   - OWASP Top 10 testing
   - Business logic flaws
   - Input validation testing

## 4. **Exploitation Phase**
   - Proof-of-concept development
   - Impact assessment
   - Evidence collection

## 5. **Reporting**
   - Vulnerability documentation
   - Risk assessment
   - Remediation suggestions

**Example usage:**
- "Help me hunt for bugs on example.com"
- "Perform reconnaissance on target.com"
- "Test https://app.example.com for OWASP Top 10 vulnerabilities"

The AI will guide you through each phase and suggest appropriate tools and techniques.

**Remember:** Always ensure you have proper authorization before testing any target!`;

    const huntItem = {
      type: MessageType.INFO,
      content,
      timestamp: new Date(),
    };

    context.ui.addItem(huntItem, Date.now());
  },
};
