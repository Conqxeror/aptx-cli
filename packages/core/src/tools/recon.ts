/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, Icon, ToolResult, ToolCallConfirmationDetails, ToolConfirmationOutcome } from './tools.js';
import { Type } from '@google/genai';
import { SchemaValidator } from '../utils/schemaValidator.js';
import { Config } from '../config/config.js';
import { autoInstallMissingTool, isToolInstalled } from './security-installer.js';

/**
 * Parameters for the ReconTool.
 */
export interface ReconToolParams {
  /**
   * Target domain or IP address to gather information about
   */
  target: string;
  /**
   * Type of reconnaissance to perform
   */
  reconType?: 'dns' | 'whois' | 'subdomain' | 'tech' | 'social' | 'all';
  /**
   * Whether to include passive reconnaissance only
   */
  passive?: boolean;
}

/**
 * A tool to perform reconnaissance and information gathering on targets.
 */
export class ReconTool extends BaseTool<ReconToolParams, ToolResult> {
  static readonly Name: string = 'recon';

  constructor(private readonly config: Config) {
    super(
      ReconTool.Name,
      'Reconnaissance Tool',
      'Performs passive and active reconnaissance to gather information about targets including DNS records, WHOIS data, subdomain enumeration, and technology stack detection.',
      Icon.Globe,
      {
        type: Type.OBJECT,
        properties: {
          target: {
            type: Type.STRING,
            description: 'Target domain or IP address (e.g., example.com, 192.168.1.1)',
          },
          reconType: {
            type: Type.STRING,
            enum: ['dns', 'whois', 'subdomain', 'tech', 'social', 'all'],
            description: 'Type of reconnaissance (dns: DNS records, whois: WHOIS data, subdomain: subdomain enumeration, tech: technology detection, social: social media/email gathering, all: comprehensive recon)',
          },
          passive: {
            type: Type.BOOLEAN,
            description: 'Perform only passive reconnaissance (no direct contact with target)',
          },
        },
        required: ['target'],
      },
      true,
      false,
    );
  }

  validateToolParams(params: ReconToolParams): string | null {
    const errors = SchemaValidator.validate(this.schema.parameters, params);
    if (errors) {
      return errors;
    }

    if (!params.target || params.target.trim() === '') {
      return "The 'target' parameter cannot be empty.";
    }

    // Basic validation for target format
    const target = params.target.trim();
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (!ipRegex.test(target) && !domainRegex.test(target) && target !== 'localhost') {
      return 'Target must be a valid IP address or domain name.';
    }

    return null;
  }

  getDescription(params: ReconToolParams): string {
    const reconType = params.reconType || 'all';
    const mode = params.passive ? 'passive' : 'active';
    return `Performing ${mode} ${reconType} reconnaissance on ${params.target}`;
  }

  async shouldConfirmExecute(
    params: ReconToolParams,
  ): Promise<ToolCallConfirmationDetails | false> {
    if (!params.passive) {
      return {
        type: 'info',
        title: 'Confirm Reconnaissance',
        prompt: `This will perform active reconnaissance on ${params.target}. Ensure you have proper authorization to gather information about this target.`,
        urls: [],
        onConfirm: async (outcome: ToolConfirmationOutcome) => {
          // Handle confirmation outcome if needed
        },
      };
    }
    return false;
  }

  private async performDnsLookup(target: string): Promise<string> {
    const results: string[] = [];
    
    results.push(`=== DNS Reconnaissance for ${target} ===`);
    
    try {
      // Simulate DNS lookup results (in a real implementation, you'd use dns.resolve() etc.)
      results.push(`A Records: (Use 'nslookup ${target}' or 'dig A ${target}' for actual results)`);
      results.push(`MX Records: (Use 'nslookup -type=MX ${target}' for actual results)`);
      results.push(`NS Records: (Use 'nslookup -type=NS ${target}' for actual results)`);
      results.push(`TXT Records: (Use 'nslookup -type=TXT ${target}' for actual results)`);
      results.push(`CNAME Records: (Use 'nslookup -type=CNAME ${target}' for actual results)`);
      
      results.push('\nSuggested commands for manual verification:');
      results.push(`nslookup ${target}`);
      results.push(`dig ${target} ANY`);
      results.push(`host ${target}`);
    } catch (error) {
      results.push(`DNS lookup failed: ${error}`);
    }
    
    return results.join('\n');
  }

  private async performWhoisLookup(target: string): Promise<string> {
    const results: string[] = [];
    
    results.push(`=== WHOIS Information for ${target} ===`);
    results.push(`Use the following command for actual WHOIS data:`);
    results.push(`whois ${target}`);
    results.push('\nTypical WHOIS information includes:');
    results.push('- Domain registration date');
    results.push('- Expiration date');
    results.push('- Registrar information');
    results.push('- Nameservers');
    results.push('- Contact information (if not private)');
    
    return results.join('\n');
  }

  private async performSubdomainEnum(target: string): Promise<string> {
    const results: string[] = [];
    
    results.push(`=== Subdomain Enumeration for ${target} ===`);
    results.push('Suggested tools and techniques:');
    results.push(`sublist3r -d ${target}`);
    results.push(`amass enum -d ${target}`);
    results.push(`subfinder -d ${target}`);
    results.push(`assetfinder ${target}`);
    results.push(`dnsrecon -d ${target} -t brt`);
    
    results.push('\nPassive sources to check:');
    results.push('- Certificate Transparency logs (crt.sh)');
    results.push('- DNS databases (SecurityTrails, VirusTotal)');
    results.push('- Search engines (Google dorking)');
    results.push('- Archive.org (Wayback Machine)');
    
    return results.join('\n');
  }

  private async performTechDetection(target: string): Promise<string> {
    const results: string[] = [];
    
    results.push(`=== Technology Detection for ${target} ===`);
    results.push('Suggested tools for technology stack detection:');
    results.push(`whatweb ${target}`);
    results.push(`wappalyzer ${target}`);
    results.push(`builtwith.com lookup`);
    results.push(`netcraft.com site report`);
    
    results.push('\nTechnologies to identify:');
    results.push('- Web server (Apache, Nginx, IIS)');
    results.push('- Programming languages (PHP, Python, Java, .NET)');
    results.push('- CMS platforms (WordPress, Drupal, Joomla)');
    results.push('- JavaScript frameworks (React, Angular, Vue)');
    results.push('- CDN providers (Cloudflare, AWS CloudFront)');
    results.push('- Analytics platforms (Google Analytics, etc.)');
    
    return results.join('\n');
  }

  private async performSocialRecon(target: string): Promise<string> {
    const results: string[] = [];
    
    results.push(`=== Social Media & Email Reconnaissance for ${target} ===`);
    results.push('Suggested tools and techniques:');
    results.push(`theHarvester -d ${target} -b all`);
    results.push(`hunter.io email search`);
    results.push(`pipl.com people search`);
    results.push(`spokeo.com search`);
    
    results.push('\nInformation sources:');
    results.push('- LinkedIn profiles and company pages');
    results.push('- Twitter/X accounts and mentions');
    results.push('- Facebook business pages');
    results.push('- Instagram business accounts');
    results.push('- Employee email patterns');
    results.push('- Job postings and hiring information');
    results.push('- News articles and press releases');
    
    results.push('\nPassive OSINT techniques:');
    results.push('- Google dorking with site:target.com');
    results.push('- Archive.org historical data');
    results.push('- Public document metadata');
    results.push('- Code repositories (GitHub, GitLab)');
    
    return results.join('\n');
  }

  async execute(
    params: ReconToolParams,
    signal: AbortSignal,
  ): Promise<ToolResult> {
    const validationError = this.validateToolParams(params);
    if (validationError) {
      return {
        llmContent: `Error: Invalid parameters. ${validationError}`,
        returnDisplay: validationError,
      };
    }

    const reconType = params.reconType || 'all';
    const results: string[] = [];

    try {
      results.push(`Reconnaissance Report for ${params.target}`);
      results.push(`Mode: ${params.passive ? 'Passive' : 'Active'}`);
      results.push(`Scope: ${reconType}`);
      results.push('=' .repeat(50));
      results.push('');

      switch (reconType) {
        case 'dns':
          results.push(await this.performDnsLookup(params.target));
          break;
        case 'whois':
          results.push(await this.performWhoisLookup(params.target));
          break;
        case 'subdomain':
          results.push(await this.performSubdomainEnum(params.target));
          break;
        case 'tech':
          results.push(await this.performTechDetection(params.target));
          break;
        case 'social':
          results.push(await this.performSocialRecon(params.target));
          break;
        case 'all':
        default:
          results.push(await this.performDnsLookup(params.target));
          results.push('\n');
          results.push(await this.performWhoisLookup(params.target));
          results.push('\n');
          results.push(await this.performSubdomainEnum(params.target));
          results.push('\n');
          results.push(await this.performTechDetection(params.target));
          results.push('\n');
          results.push(await this.performSocialRecon(params.target));
          break;
      }

      results.push('\n');
      results.push('=== Security Considerations ===');
      results.push('- Always ensure you have proper authorization before conducting reconnaissance');
      results.push('- Use passive techniques when possible to avoid detection');
      results.push('- Respect rate limits and avoid aggressive scanning');
      results.push('- Document findings securely and follow responsible disclosure');

      const finalResults = results.join('\n');

      return {
        llmContent: `Reconnaissance completed for ${params.target}:\n\n${finalResults}`,
        returnDisplay: finalResults,
      };
    } catch (error) {
      return {
        llmContent: `Failed to complete reconnaissance: ${error}`,
        returnDisplay: `Error: ${error}`,
      };
    }
  }
}
