/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, Icon, ToolResult, ToolCallConfirmationDetails, ToolConfirmationOutcome } from './tools.js';
import { Type } from '@google/genai';
import { SchemaValidator } from '../utils/schemaValidator.js';
import { Config } from '../config/config.js';
import { spawn } from 'node:child_process';
import { getErrorMessage } from '../utils/errors.js';
import { autoInstallMissingTool, isToolInstalled } from './security-installer.js';

/**
 * Parameters for the NmapScanTool.
 */
export interface NmapScanToolParams {
  /**
   * Target IP address, hostname, or network range
   */
  target: string;
  /**
   * Scan type (quick, stealth, service, vuln, full)
   */
  scanType?: 'quick' | 'stealth' | 'service' | 'vuln' | 'full';
  /**
   * Additional nmap options
   */
  options?: string;
}

/**
 * A tool to perform network reconnaissance using Nmap.
 */
export class NmapScanTool extends BaseTool<NmapScanToolParams, ToolResult> {
  static readonly Name: string = 'nmap_scan';

  constructor(private readonly config: Config) {
    super(
      NmapScanTool.Name,
      'Nmap Network Scanner',
      'Performs network reconnaissance and port scanning using Nmap to discover hosts, services, and potential vulnerabilities.',
      Icon.Terminal,
      {
        type: Type.OBJECT,
        properties: {
          target: {
            type: Type.STRING,
            description: 'Target IP address, hostname, or network range (e.g., 192.168.1.1, example.com, 192.168.1.0/24)',
          },
          scanType: {
            type: Type.STRING,
            enum: ['quick', 'stealth', 'service', 'vuln', 'full'],
            description: 'Type of scan to perform (quick: fast port scan, stealth: SYN stealth scan, service: service detection, vuln: vulnerability detection, full: comprehensive scan)',
          },
          options: {
            type: Type.STRING,
            description: 'Additional nmap options (e.g., "-p 80,443,8080" for specific ports)',
          },
        },
        required: ['target'],
      },
      true,
      true,
    );
  }

  validateToolParams(params: NmapScanToolParams): string | null {
    const errors = SchemaValidator.validate(this.schema.parameters, params);
    if (errors) {
      return errors;
    }

    if (!params.target || params.target.trim() === '') {
      return "The 'target' parameter cannot be empty.";
    }

    // Basic validation for target format
    const target = params.target.trim();
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const hostnameRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (!ipRegex.test(target) && !hostnameRegex.test(target) && target !== 'localhost') {
      return 'Target must be a valid IP address, hostname, or network range.';
    }

    return null;
  }

  getDescription(params: NmapScanToolParams): string {
    const scanType = params.scanType || 'quick';
    return `Performing ${scanType} Nmap scan on target: ${params.target}`;
  }

  async shouldConfirmExecute(
    params: NmapScanToolParams,
  ): Promise<ToolCallConfirmationDetails | false> {
    return {
      type: 'info',
      title: 'Confirm Network Scan',
      prompt: `This will perform a network scan on ${params.target}. Ensure you have proper authorization to scan this target.`,
      urls: [],
      onConfirm: async (outcome: ToolConfirmationOutcome) => {
        // Handle confirmation outcome if needed
      },
    };
  }

  private getNmapCommand(params: NmapScanToolParams): string[] {
    const args = ['nmap'];
    const scanType = params.scanType || 'quick';

    switch (scanType) {
      case 'quick':
        args.push('-T4', '-F'); // Fast scan, common ports only
        break;
      case 'stealth':
        args.push('-sS', '-T2'); // SYN stealth scan, slower timing
        break;
      case 'service':
        args.push('-sV', '-sC', '-T4'); // Service detection with default scripts
        break;
      case 'vuln':
        args.push('-sV', '--script=vuln', '-T4'); // Vulnerability detection scripts
        break;
      case 'full':
        args.push('-sS', '-sV', '-sC', '-O', '-T4', '-p-'); // Comprehensive scan
        break;
    }

    if (params.options) {
      const additionalOptions = params.options.split(' ').filter(opt => opt.trim());
      args.push(...additionalOptions);
    }

    args.push(params.target);
    return args;
  }

  async execute(
    params: NmapScanToolParams,
    signal: AbortSignal,
    updateOutput?: (output: string) => void,
  ): Promise<ToolResult> {
    const validationError = this.validateToolParams(params);
    if (validationError) {
      return {
        llmContent: `Error: Invalid parameters. ${validationError}`,
        returnDisplay: validationError,
      };
    }

    // Check if nmap is installed, auto-install if needed
    const isInstalled = await isToolInstalled('nmap');
    if (!isInstalled) {
      updateOutput?.('🔧 Nmap not found. Attempting to install automatically...\n\n');
      const installResult = await autoInstallMissingTool('nmap', updateOutput);
      
      if (!installResult.installed) {
        return {
          llmContent: `Nmap installation failed: ${installResult.message}. Please install nmap manually and try again.`,
          returnDisplay: `❌ Nmap installation failed: ${installResult.message}`,
        };
      }
    }

    try {
      const command = this.getNmapCommand(params);
      updateOutput?.(`Running: ${command.join(' ')}\n\n`);

      return new Promise((resolve) => {
        const process = spawn(command[0], command.slice(1), {
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        let output = '';
        let errorOutput = '';

        process.stdout?.on('data', (data: any) => {
          const chunk = data.toString();
          output += chunk;
          updateOutput?.(chunk);
        });

        process.stderr?.on('data', (data: any) => {
          const chunk = data.toString();
          errorOutput += chunk;
          updateOutput?.(chunk);
        });

        signal.addEventListener('abort', () => {
          process.kill('SIGTERM');
        });

        process.on('close', (code: any) => {
          if (code === 0 || output.length > 0) {
            resolve({
              llmContent: `Nmap scan completed for ${params.target}:\n\n${output}`,
              returnDisplay: output || 'Scan completed successfully.',
            });
          } else {
            resolve({
              llmContent: `Nmap scan failed: ${errorOutput || 'Unknown error'}`,
              returnDisplay: errorOutput || 'Scan failed with unknown error.',
            });
          }
        });

        process.on('error', (error: any) => {
          resolve({
            llmContent: `Failed to execute nmap: ${getErrorMessage(error)}`,
            returnDisplay: `Error: ${getErrorMessage(error)}`,
          });
        });
      });
    } catch (error) {
      return {
        llmContent: `Failed to start nmap scan: ${getErrorMessage(error)}`,
        returnDisplay: `Error: ${getErrorMessage(error)}`,
      };
    }
  }
}
