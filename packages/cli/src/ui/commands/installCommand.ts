/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { SlashCommand, CommandKind } from './types.js';
import { MessageType } from '../types.js';
import { SECURITY_TOOLS, autoInstallMissingTool, isToolInstalled } from '@aptx-cli/aptx-cli-core';

export const installCommand: SlashCommand = {
  name: 'install',
  description: 'Install security tools for penetration testing',
  kind: CommandKind.BUILT_IN,
  action: async (context, args) => {
    const argList = args.trim().split(/\s+/).filter(arg => arg.length > 0);
    const toolName = argList[0]?.toLowerCase();

    if (!toolName || toolName === 'help') {
      const availableTools = Object.entries(SECURITY_TOOLS)
        .map(([name, tool]) => `• **${name}**: ${tool.description}`)
        .join('\n');

      const content = `# 🔧 APTX CLI Security Tool Installer

Install essential security tools for penetration testing and vulnerability assessment.

## Available Tools:
${availableTools}

## Usage:
- \`/install [tool_name]\` - Install specific tool
- \`/install all\` - Install all available tools
- \`/install\` - Show this help

## Examples:
- \`/install nmap\` - Install Nmap network scanner
- \`/install gobuster\` - Install Gobuster directory buster
- \`/install all\` - Install all security tools

**Note**: Tools will be installed automatically when needed during scans, but you can pre-install them using this command.`;

      return {
        type: 'message' as const,
        messageType: 'info' as const,
        content: content,
      };
    }

    if (toolName === 'all') {
      const results: string[] = [];
      const allTools = Object.keys(SECURITY_TOOLS);
      
      results.push('🔧 Installing all security tools...\n');
      
      for (const tool of allTools) {
        const isInstalled = await isToolInstalled(tool);
        if (isInstalled) {
          results.push(`✅ ${SECURITY_TOOLS[tool].displayName} is already installed`);
        } else {
          results.push(`\n📦 Installing ${SECURITY_TOOLS[tool].displayName}...`);
          const installResult = await autoInstallMissingTool(tool);
          
          if (installResult.installed) {
            results.push(`✅ ${SECURITY_TOOLS[tool].displayName} installed successfully`);
          } else {
            results.push(`❌ Failed to install ${SECURITY_TOOLS[tool].displayName}: ${installResult.message}`);
          }
        }
      }

      return {
        type: 'message' as const,
        messageType: 'info' as const,
        content: results.join('\n'),
      };
    }

    // Install specific tool
    if (!SECURITY_TOOLS[toolName]) {
      const availableTools = Object.keys(SECURITY_TOOLS).join(', ');
      return {
        type: 'message' as const,
        messageType: 'error' as const,
        content: `❌ Unknown tool: "${toolName}"\n\nAvailable tools: ${availableTools}\n\nUse \`/install\` to see detailed tool descriptions.`,
      };
    }

    const tool = SECURITY_TOOLS[toolName];
    const isInstalled = await isToolInstalled(toolName);
    
    if (isInstalled) {
      return {
        type: 'message' as const,
        messageType: 'info' as const,
        content: `✅ ${tool.displayName} is already installed and ready to use.`,
      };
    }

    let output = '';
    const updateOutput = (chunk: string) => {
      output += chunk;
    };

    const installResult = await autoInstallMissingTool(toolName, updateOutput);
    
    if (installResult.installed) {
      return {
        type: 'message' as const,
        messageType: 'info' as const,
        content: `✅ ${tool.displayName} installed successfully!\n\n${output}`,
      };
    } else {
      return {
        type: 'message' as const,
        messageType: 'error' as const,
        content: `❌ Failed to install ${tool.displayName}: ${installResult.message}\n\n${output}`,
      };
    }
  },
};
