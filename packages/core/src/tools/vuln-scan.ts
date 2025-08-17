/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, Icon, ToolResult, ToolCallConfirmationDetails, ToolConfirmationOutcome } from './tools.js';
import { Type } from '@google/genai';
import { SchemaValidator } from '../utils/schemaValidator.js';
import { Config } from '../config/config.js';
import { spawn } from 'child_process';
import { getErrorMessage } from '../utils/errors.js';
import { autoInstallMissingTool, isToolInstalled } from './security-installer.js';

/**
 * Parameters for the VulnScanTool.
 */
export interface VulnScanToolParams {
  /**
   * Target URL to scan for vulnerabilities
   */
  url: string;
  /**
   * Type of vulnerability scan to perform
   */
  scanType?: 'xss' | 'sqli' | 'lfi' | 'rfi' | 'xxe' | 'ssrf' | 'owasp' | 'all';
  /**
   * Scan intensity level
   */
  intensity?: 'low' | 'medium' | 'high';
  /**
   * Authentication data (cookies, tokens, etc.)
   */
  auth?: string;
  /**
   * Additional scan options
   */
  options?: string;
}

/**
 * A tool to perform automated vulnerability scanning on web applications.
 */
export class VulnScanTool extends BaseTool<VulnScanToolParams, ToolResult> {
  static readonly Name: string = 'vuln_scan';

  constructor(private readonly config: Config) {
    super(
      VulnScanTool.Name,
      'Vulnerability Scanner',
      'Performs automated vulnerability scanning on web applications to detect common security flaws like XSS, SQL injection, and OWASP Top 10 vulnerabilities.',
      Icon.Terminal,
      {
        type: Type.OBJECT,
        properties: {
          url: {
            type: Type.STRING,
            description: 'Target URL to scan for vulnerabilities (e.g., https://example.com)',
          },
          scanType: {
            type: Type.STRING,
            enum: ['xss', 'sqli', 'lfi', 'rfi', 'xxe', 'ssrf', 'owasp', 'all'],
            description: 'Type of vulnerability scan (xss: Cross-Site Scripting, sqli: SQL Injection, lfi: Local File Inclusion, rfi: Remote File Inclusion, xxe: XML External Entity, ssrf: Server-Side Request Forgery, owasp: OWASP Top 10, all: comprehensive scan)',
          },
          intensity: {
            type: Type.STRING,
            enum: ['low', 'medium', 'high'],
            description: 'Scan intensity level (low: basic checks, medium: moderate testing, high: comprehensive testing)',
          },
          auth: {
            type: Type.STRING,
            description: 'Authentication data such as session cookies or API tokens',
          },
          options: {
            type: Type.STRING,
            description: 'Additional scanner options',
          },
        },
        required: ['url'],
      },
      true,
      true,
    );
  }

  validateToolParams(params: VulnScanToolParams): string | null {
    const errors = SchemaValidator.validate(this.schema.parameters, params);
    if (errors) {
      return errors;
    }

    if (!params.url || params.url.trim() === '') {
      return "The 'url' parameter cannot be empty.";
    }

    try {
      new URL(params.url);
    } catch {
      return 'URL must be a valid HTTP/HTTPS URL.';
    }

    return null;
  }

  getDescription(params: VulnScanToolParams): string {
    const scanType = params.scanType || 'owasp';
    const intensity = params.intensity || 'medium';
    return `Performing ${intensity} intensity ${scanType} vulnerability scan on ${params.url}`;
  }

  async shouldConfirmExecute(
    params: VulnScanToolParams,
  ): Promise<ToolCallConfirmationDetails | false> {
    return {
      type: 'info',
      title: 'Confirm Vulnerability Scan',
      prompt: `This will perform a vulnerability scan on ${params.url}. Ensure you have proper authorization to test this target and that it's not a production system.`,
      urls: [params.url],
      onConfirm: async (outcome: ToolConfirmationOutcome) => {
        // Handle confirmation outcome if needed
      },
    };
  }

  private getNiktoCommand(params: VulnScanToolParams): string[] {
    const args = ['nikto'];
    
    args.push('-h', params.url);
    
    const intensity = params.intensity || 'medium';
    switch (intensity) {
      case 'low':
        args.push('-Tuning', '1,2,3'); // Basic tests only
        break;
      case 'medium':
        args.push('-Tuning', '1,2,3,4,5,6'); // Standard tests
        break;
      case 'high':
        args.push('-Tuning', 'x'); // All tests
        break;
    }
    
    if (params.auth) {
      args.push('-id', params.auth);
    }
    
    args.push('-Format', 'txt');
    args.push('-Display', '1,2,3,V');
    
    if (params.options) {
      const additionalOptions = params.options.split(' ').filter(opt => opt.trim());
      args.push(...additionalOptions);
    }

    return args;
  }

  private getZapBaselineCommand(params: VulnScanToolParams): string[] {
    const args = ['zap-baseline.py'];
    
    args.push('-t', params.url);
    args.push('-J', 'zap-report.json');
    args.push('-r', 'zap-report.html');
    
    const intensity = params.intensity || 'medium';
    switch (intensity) {
      case 'low':
        args.push('-l', 'PASS'); // Passive scan only
        break;
      case 'medium':
        args.push('-m', '5'); // 5 minute timeout
        break;
      case 'high':
        args.push('-m', '10'); // 10 minute timeout
        args.push('-d'); // Debug mode
        break;
    }
    
    if (params.auth) {
      args.push('-z', `-config auth.loginurl=${params.url}/login`);
    }
    
    if (params.options) {
      const additionalOptions = params.options.split(' ').filter(opt => opt.trim());
      args.push(...additionalOptions);
    }

    return args;
  }

  private getSqlMapCommand(params: VulnScanToolParams): string[] {
    const args = ['sqlmap'];
    
    args.push('-u', params.url);
    args.push('--batch'); // Non-interactive mode
    args.push('--smart'); // Smart payload selection
    
    const intensity = params.intensity || 'medium';
    switch (intensity) {
      case 'low':
        args.push('--level=1', '--risk=1');
        break;
      case 'medium':
        args.push('--level=3', '--risk=2');
        break;
      case 'high':
        args.push('--level=5', '--risk=3');
        break;
    }
    
    if (params.auth) {
      args.push('--cookie', params.auth);
    }
    
    // Common detection techniques
    args.push('--technique=BEUSTQ');
    args.push('--threads=5');
    
    if (params.options) {
      const additionalOptions = params.options.split(' ').filter(opt => opt.trim());
      args.push(...additionalOptions);
    }

    return args;
  }

  private async runScanner(
    command: string[],
    scannerName: string,
    signal: AbortSignal,
    updateOutput?: (output: string) => void,
  ): Promise<string> {
    return new Promise((resolve, reject) => {
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

      process.on('close', (code: number | null) => {
        if (code === 0 || output.length > 0) {
          resolve(output);
        } else {
          reject(new Error(errorOutput || `${scannerName} failed with exit code ${code}`));
        }
      });

      process.on('error', (error: Error) => {
        reject(error);
      });
    });
  }

  async execute(
    params: VulnScanToolParams,
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

    const scanType = params.scanType || 'owasp';
    
    // Check and install required tools based on scan type
    const requiredTools: string[] = [];
    switch (scanType) {
      case 'sqli':
        requiredTools.push('sqlmap');
        break;
      case 'owasp':
      case 'all':
        requiredTools.push('zap-baseline', 'nikto');
        break;
      case 'xss':
        requiredTools.push('nikto');
        break;
    }

    // Auto-install missing tools
    for (const tool of requiredTools) {
      const isInstalled = await isToolInstalled(tool);
      if (!isInstalled) {
        updateOutput?.(`🔧 ${tool} not found. Attempting to install automatically...\n\n`);
        const installResult = await autoInstallMissingTool(tool, updateOutput);
        if (!installResult.installed) {
          updateOutput?.(`⚠️ Warning: ${tool} could not be installed automatically. Some scans may fail.\n\n`);
        }
      }
    }

    let results = '';

    try {
      updateOutput?.(`Starting ${scanType} vulnerability scan on ${params.url}\n\n`);

      switch (scanType) {
        case 'sqli':
          updateOutput?.('Running SQL injection tests with sqlmap...\n');
          try {
            const sqlmapResult = await this.runScanner(
              this.getSqlMapCommand(params),
              'sqlmap',
              signal,
              updateOutput,
            );
            results += `SQL Injection Scan Results:\n${sqlmapResult}\n\n`;
          } catch (error) {
            results += `SQL Injection scan failed: ${getErrorMessage(error)}\n\n`;
          }
          break;

        case 'owasp':
        case 'all':
          updateOutput?.('Running OWASP ZAP baseline scan...\n');
          try {
            const zapResult = await this.runScanner(
              this.getZapBaselineCommand(params),
              'ZAP',
              signal,
              updateOutput,
            );
            results += `OWASP ZAP Scan Results:\n${zapResult}\n\n`;
          } catch (error) {
            updateOutput?.('ZAP not available, trying Nikto...\n');
            try {
              const niktoResult = await this.runScanner(
                this.getNiktoCommand(params),
                'Nikto',
                signal,
                updateOutput,
              );
              results += `Nikto Scan Results:\n${niktoResult}\n\n`;
            } catch (niktoError) {
              results += `Vulnerability scan failed: ${getErrorMessage(niktoError)}\n\n`;
            }
          }
          break;

        default:
          updateOutput?.('Running general vulnerability scan with Nikto...\n');
          try {
            const niktoResult = await this.runScanner(
              this.getNiktoCommand(params),
              'Nikto',
              signal,
              updateOutput,
            );
            results += `Vulnerability Scan Results:\n${niktoResult}\n\n`;
          } catch (error) {
            results += `Vulnerability scan failed: ${getErrorMessage(error)}\n\n`;
          }
          break;
      }

      if (results.trim()) {
        return {
          llmContent: `Vulnerability scan completed for ${params.url}:\n\n${results}`,
          returnDisplay: results,
        };
      } else {
        return {
          llmContent: `Vulnerability scan completed but no results were generated. This might indicate that the required tools are not installed.`,
          returnDisplay: 'Scan completed but no results available. Please ensure vulnerability scanning tools are installed.',
        };
      }
    } catch (error) {
      return {
        llmContent: `Failed to complete vulnerability scan: ${getErrorMessage(error)}`,
        returnDisplay: `Error: ${getErrorMessage(error)}`,
      };
    }
  }
}
