/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { spawn } from 'child_process';
import { platform } from 'os';
import { getErrorMessage } from '../utils/errors.js';

export interface SecurityTool {
  name: string;
  displayName: string;
  description: string;
  installCommands: {
    linux: string[];
    darwin: string[]; // macOS
    win32: string[];
  };
  verifyCommand: string;
  homepage?: string;
}

export const SECURITY_TOOLS: Record<string, SecurityTool> = {
  nmap: {
    name: 'nmap',
    displayName: 'Nmap',
    description: 'Network discovery and security auditing tool',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'nmap'],
      darwin: ['brew', 'install', 'nmap'],
      win32: ['choco', 'install', 'nmap', '-y'],
    },
    verifyCommand: 'nmap --version',
    homepage: 'https://nmap.org/',
  },
  gobuster: {
    name: 'gobuster',
    displayName: 'Gobuster',
    description: 'Directory/file & DNS busting tool',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'gobuster'],
      darwin: ['brew', 'install', 'gobuster'],
      win32: ['go', 'install', 'github.com/OJ/gobuster/v3@latest'],
    },
    verifyCommand: 'gobuster version',
    homepage: 'https://github.com/OJ/gobuster',
  },
  ffuf: {
    name: 'ffuf',
    displayName: 'Ffuf',
    description: 'Fast web fuzzer',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'ffuf'],
      darwin: ['brew', 'install', 'ffuf'],
      win32: ['go', 'install', 'github.com/ffuf/ffuf@latest'],
    },
    verifyCommand: 'ffuf -V',
    homepage: 'https://github.com/ffuf/ffuf',
  },
  nikto: {
    name: 'nikto',
    displayName: 'Nikto',
    description: 'Web server scanner',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'nikto'],
      darwin: ['brew', 'install', 'nikto'],
      win32: ['git', 'clone', 'https://github.com/sullo/nikto.git', '&&', 'cd', 'nikto/program'],
    },
    verifyCommand: 'nikto -Version',
    homepage: 'https://cirt.net/Nikto2',
  },
  sqlmap: {
    name: 'sqlmap',
    displayName: 'SQLMap',
    description: 'Automatic SQL injection and database takeover tool',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'sqlmap'],
      darwin: ['brew', 'install', 'sqlmap'],
      win32: ['pip', 'install', 'sqlmap'],
    },
    verifyCommand: 'sqlmap --version',
    homepage: 'https://sqlmap.org/',
  },
  'zap-baseline': {
    name: 'zap-baseline',
    displayName: 'OWASP ZAP',
    description: 'Web application security scanner',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'zaproxy'],
      darwin: ['brew', 'install', '--cask', 'owasp-zap'],
      win32: ['choco', 'install', 'zap', '-y'],
    },
    verifyCommand: 'zap-baseline.py --version',
    homepage: 'https://owasp.org/www-project-zap/',
  },
  subfinder: {
    name: 'subfinder',
    displayName: 'Subfinder',
    description: 'Subdomain discovery tool',
    installCommands: {
      linux: ['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
      darwin: ['brew', 'install', 'subfinder'],
      win32: ['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
    },
    verifyCommand: 'subfinder -version',
    homepage: 'https://github.com/projectdiscovery/subfinder',
  },
  amass: {
    name: 'amass',
    displayName: 'Amass',
    description: 'Network mapping and attack surface discovery',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'amass'],
      darwin: ['brew', 'install', 'amass'],
      win32: ['go', 'install', '-v', 'github.com/OWASP/Amass/v3/...@master'],
    },
    verifyCommand: 'amass -version',
    homepage: 'https://github.com/OWASP/Amass',
  },
  whatweb: {
    name: 'whatweb',
    displayName: 'WhatWeb',
    description: 'Web technology detector',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'whatweb'],
      darwin: ['brew', 'install', 'whatweb'],
      win32: ['gem', 'install', 'whatweb'],
    },
    verifyCommand: 'whatweb --version',
    homepage: 'https://github.com/urbanadventurer/WhatWeb',
  },
  dirb: {
    name: 'dirb',
    displayName: 'DIRB',
    description: 'Web content scanner',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'dirb'],
      darwin: ['brew', 'install', 'dirb'],
      win32: ['choco', 'install', 'dirb', '-y'],
    },
    verifyCommand: 'dirb',
    homepage: 'http://dirb.sourceforge.net/',
  },
  whois: {
    name: 'whois',
    displayName: 'WHOIS',
    description: 'Domain registration information lookup',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'whois'],
      darwin: ['brew', 'install', 'whois'],
      win32: ['choco', 'install', 'whois', '-y'],
    },
    verifyCommand: 'whois --version',
    homepage: 'https://www.gnu.org/software/inetutils/',
  },
  dig: {
    name: 'dig',
    displayName: 'DNS Lookup (dig)',
    description: 'DNS lookup tool',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'dnsutils'],
      darwin: ['brew', 'install', 'bind'],
      win32: ['choco', 'install', 'bind-toolsonly', '-y'],
    },
    verifyCommand: 'dig -v',
    homepage: 'https://www.isc.org/bind/',
  },
  hydra: {
    name: 'hydra',
    displayName: 'THC Hydra',
    description: 'Login cracker supporting many protocols',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'hydra'],
      darwin: ['brew', 'install', 'hydra'],
      win32: ['choco', 'install', 'thc-hydra', '-y'],
    },
    verifyCommand: 'hydra -h',
    homepage: 'https://github.com/vanhauser-thc/thc-hydra',
  },
  john: {
    name: 'john',
    displayName: 'John the Ripper',
    description: 'Password cracker',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'john'],
      darwin: ['brew', 'install', 'john'],
      win32: ['choco', 'install', 'john', '-y'],
    },
    verifyCommand: 'john --version',
    homepage: 'https://www.openwall.com/john/',
  },
  hashcat: {
    name: 'hashcat',
    displayName: 'Hashcat',
    description: 'Advanced password recovery',
    installCommands: {
      linux: ['sudo', 'apt-get', 'update', '&&', 'sudo', 'apt-get', 'install', '-y', 'hashcat'],
      darwin: ['brew', 'install', 'hashcat'],
      win32: ['choco', 'install', 'hashcat', '-y'],
    },
    verifyCommand: 'hashcat --version',
    homepage: 'https://hashcat.net/hashcat/',
  },
};

/**
 * Check if a security tool is installed on the system
 */
export async function isToolInstalled(toolName: string): Promise<boolean> {
  const tool = SECURITY_TOOLS[toolName];
  if (!tool) {
    return false;
  }

  return new Promise((resolve) => {
    const [command, ...args] = tool.verifyCommand.split(' ');
    const process = spawn(command, args, { stdio: 'pipe' });

    process.on('close', (code) => {
      resolve(code === 0);
    });

    process.on('error', () => {
      resolve(false);
    });

    // Kill process after 5 seconds to avoid hanging
    setTimeout(() => {
      process.kill();
      resolve(false);
    }, 5000);
  });
}

/**
 * Install a security tool with user permission
 */
export async function installSecurityTool(
  toolName: string,
  updateOutput?: (output: string) => void,
): Promise<{ success: boolean; message: string }> {
  const tool = SECURITY_TOOLS[toolName];
  if (!tool) {
    return { success: false, message: `Unknown tool: ${toolName}` };
  }

  const currentPlatform = platform() as keyof typeof tool.installCommands;
  const installCommands = tool.installCommands[currentPlatform];

  if (!installCommands) {
    return {
      success: false,
      message: `Installation not supported on ${currentPlatform}`,
    };
  }

  updateOutput?.(`Installing ${tool.displayName} (${tool.description})...\n\n`);

  // For compound commands with &&, we need to handle them specially
  const commandString = installCommands.join(' ');
  const isCompoundCommand = commandString.includes('&&');

  if (isCompoundCommand) {
    // Use shell to execute compound commands
    return executeShellCommand(commandString, updateOutput);
  } else {
    // Execute simple command
    const [command, ...args] = installCommands;
    return executeCommand(command, args, updateOutput);
  }
}

/**
 * Execute a shell command (for compound commands with &&)
 */
async function executeShellCommand(
  commandString: string,
  updateOutput?: (output: string) => void,
): Promise<{ success: boolean; message: string }> {
  return new Promise((resolve) => {
    const isWindows = platform() === 'win32';
    const shell = isWindows ? 'cmd' : 'bash';
    const shellFlag = isWindows ? '/c' : '-c';

    const process = spawn(shell, [shellFlag, commandString], {
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

    process.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, message: 'Installation completed successfully' });
      } else {
        resolve({
          success: false,
          message: `Installation failed with exit code ${code}: ${errorOutput}`,
        });
      }
    });

    process.on('error', (error) => {
      resolve({
        success: false,
        message: `Installation failed: ${getErrorMessage(error)}`,
      });
    });
  });
}

/**
 * Execute a simple command
 */
async function executeCommand(
  command: string,
  args: string[],
  updateOutput?: (output: string) => void,
): Promise<{ success: boolean; message: string }> {
  return new Promise((resolve) => {
    const process = spawn(command, args, {
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

    process.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, message: 'Installation completed successfully' });
      } else {
        resolve({
          success: false,
          message: `Installation failed with exit code ${code}: ${errorOutput}`,
        });
      }
    });

    process.on('error', (error) => {
      resolve({
        success: false,
        message: `Installation failed: ${getErrorMessage(error)}`,
      });
    });
  });
}

/**
 * Get installation suggestions for missing tools
 */
export function getInstallationSuggestions(toolName: string): string {
  const tool = SECURITY_TOOLS[toolName];
  if (!tool) {
    return `Unknown tool: ${toolName}`;
  }

  const currentPlatform = platform();
  const commands = tool.installCommands[currentPlatform as keyof typeof tool.installCommands];

  if (!commands) {
    return `Installation instructions not available for ${currentPlatform}. Please visit ${tool.homepage || 'the official website'} for manual installation instructions.`;
  }

  const installCommand = commands.join(' ');
  
  return `To install ${tool.displayName}:

**${tool.description}**

Installation command for ${currentPlatform}:
\`\`\`
${installCommand}
\`\`\`

Or ask me to install it for you by saying "Install ${toolName}" or "Set up ${tool.displayName}".

More information: ${tool.homepage || 'Official documentation'}`;
}

/**
 * Auto-install missing tools with user confirmation
 */
export async function autoInstallMissingTool(
  toolName: string,
  updateOutput?: (output: string) => void,
): Promise<{ installed: boolean; message: string }> {
  const tool = SECURITY_TOOLS[toolName];
  if (!tool) {
    return { installed: false, message: `Unknown tool: ${toolName}` };
  }

  // Check if already installed
  const isInstalled = await isToolInstalled(toolName);
  if (isInstalled) {
    return { installed: true, message: `${tool.displayName} is already installed` };
  }

  updateOutput?.(`${tool.displayName} is not installed. Installing automatically...\n`);
  
  const result = await installSecurityTool(toolName, updateOutput);
  
  if (result.success) {
    // Verify installation
    const verified = await isToolInstalled(toolName);
    if (verified) {
      updateOutput?.(`\n✅ ${tool.displayName} installed successfully!\n\n`);
      return { installed: true, message: `${tool.displayName} installed successfully` };
    } else {
      updateOutput?.(`\n❌ Installation completed but verification failed\n\n`);
      return { installed: false, message: 'Installation completed but verification failed' };
    }
  } else {
    updateOutput?.(`\n❌ Installation failed: ${result.message}\n\n`);
    updateOutput?.(getInstallationSuggestions(toolName) + '\n\n');
    return { installed: false, message: result.message };
  }
}
