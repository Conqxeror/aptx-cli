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
 * Parameters for the DirBusterTool.
 */
export interface DirBusterToolParams {
  /**
   * Target URL to scan for directories and files
   */
  url: string;
  /**
   * Wordlist type to use for directory discovery
   */
  wordlist?: 'common' | 'medium' | 'large' | 'api' | 'admin';
  /**
   * File extensions to search for
   */
  extensions?: string;
  /**
   * Number of threads to use
   */
  threads?: number;
}

/**
 * A tool to discover hidden directories and files on web servers using gobuster or ffuf.
 */
export class DirBusterTool extends BaseTool<DirBusterToolParams, ToolResult> {
  static readonly Name: string = 'dirbuster';

  constructor(private readonly config: Config) {
    super(
      DirBusterTool.Name,
      'Directory Buster',
      'Discovers hidden directories and files on web servers using directory fuzzing techniques with gobuster or ffuf.',
      Icon.Terminal,
      {
        type: Type.OBJECT,
        properties: {
          url: {
            type: Type.STRING,
            description: 'Target URL to scan (e.g., https://example.com)',
          },
          wordlist: {
            type: Type.STRING,
            enum: ['common', 'medium', 'large', 'api', 'admin'],
            description: 'Wordlist size to use (common: ~1k, medium: ~10k, large: ~100k+, api: API endpoints, admin: admin panels)',
          },
          extensions: {
            type: Type.STRING,
            description: 'File extensions to search for (e.g., "php,html,txt,js")',
          },
          threads: {
            type: Type.NUMBER,
            description: 'Number of concurrent threads (default: 10)',
          },
        },
        required: ['url'],
      },
      true,
      true,
    );
  }

  validateToolParams(params: DirBusterToolParams): string | null {
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

    if (params.threads && (params.threads < 1 || params.threads > 100)) {
      return 'Threads must be between 1 and 100.';
    }

    return null;
  }

  getDescription(params: DirBusterToolParams): string {
    const wordlist = params.wordlist || 'common';
    return `Performing directory discovery on ${params.url} using ${wordlist} wordlist`;
  }

  async shouldConfirmExecute(
    params: DirBusterToolParams,
  ): Promise<ToolCallConfirmationDetails | false> {
    return {
      type: 'info',
      title: 'Confirm Directory Discovery',
      prompt: `This will scan ${params.url} for hidden directories and files. This is an active reconnaissance technique that sends many requests to the target server.`,
      urls: [],
      onConfirm: async (outcome: ToolConfirmationOutcome) => {
        // Handle confirmation outcome if needed
      },
    };
  }

  private getGobusterCommand(params: DirBusterToolParams): string[] {
    const args = ['gobuster', 'dir', '-u', params.url];
    
    // Select wordlist
    const wordlist = params.wordlist || 'common';
    const wordlists = {
      common: '/usr/share/wordlists/dirb/common.txt',
      medium: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
      large: '/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt',
      api: '/usr/share/wordlists/dirb/vulns/api.txt',
      admin: '/usr/share/wordlists/dirb/vulns/admin.txt',
    };
    
    args.push('-w', wordlists[wordlist]);
    
    if (params.extensions) {
      args.push('-x', params.extensions);
    }
    
    if (params.threads) {
      args.push('-t', params.threads.toString());
    } else {
      args.push('-t', '10');
    }
    
    // Add common options
    args.push('-k', '--no-error', '--wildcard');
    
    return args;
  }

  private getFfufCommand(params: DirBusterToolParams): string[] {
    const args = ['ffuf', '-u', `${params.url}/FUZZ`];
    
    // Select wordlist
    const wordlist = params.wordlist || 'common';
    const wordlists = {
      common: '/usr/share/wordlists/dirb/common.txt',
      medium: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
      large: '/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt',
      api: '/usr/share/wordlists/dirb/vulns/api.txt',
      admin: '/usr/share/wordlists/dirb/vulns/admin.txt',
    };
    
    args.push('-w', wordlists[wordlist]);
    
    if (params.extensions) {
      const exts = params.extensions.split(',').map(ext => ext.trim());
      args.push('-e', exts.join(','));
    }
    
    if (params.threads) {
      args.push('-t', params.threads.toString());
    } else {
      args.push('-t', '10');
    }
    
    // Add common options
    args.push('-c', '-v');
    
    return args;
  }

  async execute(
    params: DirBusterToolParams,
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

    // Check if gobuster is installed, try to auto-install if needed
    let useGobuster = await isToolInstalled('gobuster');
    if (!useGobuster) {
      updateOutput?.('🔧 Gobuster not found. Attempting to install automatically...\n\n');
      const gobusterInstall = await autoInstallMissingTool('gobuster', updateOutput);
      useGobuster = gobusterInstall.installed;
    }

    // If gobuster failed, try ffuf
    let useFfuf = false;
    if (!useGobuster) {
      useFfuf = await isToolInstalled('ffuf');
      if (!useFfuf) {
        updateOutput?.('🔧 Ffuf not found. Attempting to install automatically...\n\n');
        const ffufInstall = await autoInstallMissingTool('ffuf', updateOutput);
        useFfuf = ffufInstall.installed;
      }
    }

    // If neither tool is available, return error
    if (!useGobuster && !useFfuf) {
      return {
        llmContent: 'Neither gobuster nor ffuf could be installed. Please install one of these tools manually.',
        returnDisplay: '❌ Directory busting tools not available. Please install gobuster or ffuf manually.',
      };
    }

    try {
      // Use the available tool
      let command: string[];
      let toolName: string;
      
      if (useGobuster) {
        command = this.getGobusterCommand(params);
        toolName = 'gobuster';
      } else {
        command = this.getFfufCommand(params);
        toolName = 'ffuf';
      }
      
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
              llmContent: `Directory discovery completed for ${params.url} using ${toolName}:\n\n${output}`,
              returnDisplay: output || 'Directory discovery completed successfully.',
            });
          } else {
            resolve({
              llmContent: `Directory discovery failed: ${errorOutput || 'Unknown error'}`,
              returnDisplay: errorOutput || 'Directory discovery failed with unknown error.',
            });
          }
        });

        process.on('error', (error: any) => {
          resolve({
            llmContent: `Failed to execute ${toolName}: ${getErrorMessage(error)}`,
            returnDisplay: `Error: ${getErrorMessage(error)}`,
          });
        });
      });
    } catch (error) {
      return {
        llmContent: `Failed to start directory discovery: ${getErrorMessage(error)}`,
        returnDisplay: `Error: ${getErrorMessage(error)}`,
      };
    }
  }
}
