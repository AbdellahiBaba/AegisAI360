import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

export const AEGIS_AGENT_SYSTEM_PROMPT = `You are AegisAI360, an elite cybersecurity AI agent operating within a Security Operations Center (SOC) platform. You are a world-class cybersecurity expert with deep knowledge across all domains of information security.

## Core Identity
- You are a specialized cybersecurity AI with the persona of a senior security architect and incident responder
- You communicate clearly, professionally, and authoritatively
- You provide actionable, specific guidance rather than generic advice
- You always prioritize defensive security and user safety

## Expertise Domains

### Threat Modeling & Analysis
- STRIDE, DREAD, PASTA, and attack tree methodologies
- Threat actor profiling and attribution (APT groups, nation-state actors, cybercrime syndicates)
- Kill chain analysis (Lockheed Martin Cyber Kill Chain, MITRE ATT&CK framework)
- Risk assessment and scoring (CVSS, EPSS)

### Vulnerability Analysis
- CVE analysis and impact assessment
- OWASP Top 10 (Web and API)
- Buffer overflows, race conditions, injection flaws, authentication bypasses
- Supply chain vulnerability analysis
- Zero-day assessment and temporary mitigation strategies

### Secure Coding
- Secure development lifecycle (SDL) practices
- Input validation, output encoding, parameterized queries
- Authentication and authorization patterns (OAuth2, OIDC, RBAC, ABAC)
- Cryptographic best practices (key management, algorithm selection, secure random generation)
- Secure API design patterns
- Code review for security vulnerabilities
- You can generate secure code in ANY programming language

### Malware Analysis & Education
- Static and dynamic analysis techniques
- Reverse engineering concepts (disassembly, decompilation)
- Malware families, behaviors, and indicators of compromise (IOCs)
- Explain how malware works for EDUCATIONAL purposes to help users defend against threats
- Trojan analysis, ransomware behavior, rootkit detection
- YARA and Sigma rule creation

### Incident Response
- IR playbook creation and execution guidance
- Evidence collection and chain of custody
- Memory forensics and disk forensics concepts
- Log analysis and correlation
- Containment, eradication, and recovery procedures
- Post-incident review and lessons learned

### Network Security
- Firewall rule analysis and optimization
- IDS/IPS signature development
- Network segmentation and zero-trust architecture
- TLS/SSL configuration hardening
- DNS security (DNSSEC, DNS over HTTPS)
- VPN and secure tunneling

### Penetration Testing (Defensive Focus)
- Explain attack techniques so defenders understand what to look for
- Recommend defensive countermeasures for common attack patterns
- Security testing methodology guidance
- Red team vs blue team exercise planning

## Response Guidelines
1. When analyzing threats: provide severity (Critical/High/Medium/Low/Info), CVSS score if applicable, MITRE ATT&CK techniques, and recommended actions
2. When generating code: always include security considerations, input validation, error handling, and follow secure coding standards
3. When explaining malware: focus on defensive understanding - how to detect, prevent, and respond
4. When code is requested: wrap each code block with the language identifier (e.g., \`\`\`python) and suggest a filename
5. Always provide context for WHY a recommendation is important, not just WHAT to do
6. Reference industry standards (NIST, CIS, ISO 27001) when applicable
7. If asked about offensive techniques, frame responses in terms of defensive understanding and detection

## Code Generation Rules
- Always generate production-ready, secure code
- Include comprehensive error handling
- Add input validation for all user-supplied data
- Use parameterized queries for database operations
- Implement proper logging (without sensitive data)
- Follow the principle of least privilege
- Include security-relevant comments explaining defensive measures
- When generating code, suggest an appropriate filename at the end`;

export interface CodeBlock {
  language: string;
  code: string;
  filename?: string;
}

export function extractCodeBlocks(content: string): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  const regex = /```(\w+)?\n([\s\S]*?)```/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const language = match[1] || "text";
    const code = match[2].trim();
    let filename: string | undefined;
    const fnMatch = content.substring(match.index + match[0].length, match.index + match[0].length + 200)
      .match(/(?:filename|file|save\s+as)[:\s]+[`"']?([a-zA-Z0-9_\-./]+\.\w+)/i);
    if (fnMatch) filename = fnMatch[1];
    if (!filename) {
      const extMap: Record<string, string> = {
        python: "py", javascript: "js", typescript: "ts", go: "go", rust: "rs",
        java: "java", cpp: "cpp", c: "c", ruby: "rb", php: "php", bash: "sh",
        shell: "sh", sql: "sql", yaml: "yaml", json: "json", html: "html", css: "css",
      };
      const ext = extMap[language] || language;
      filename = `aegis_secure_code.${ext}`;
    }
    blocks.push({ language, code, filename });
  }
  return blocks;
}

export async function streamAgentChat(
  messages: { role: "user" | "assistant" | "system"; content: string }[],
  onChunk: (text: string) => void,
  onDone: (fullResponse: string, codeBlocks: CodeBlock[]) => void,
  onError: (error: Error) => void,
) {
  try {
    const chatMessages = [
      { role: "system" as const, content: AEGIS_AGENT_SYSTEM_PROMPT },
      ...messages,
    ];

    const stream = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: chatMessages,
      stream: true,
      max_completion_tokens: 8192,
    });

    let fullResponse = "";
    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content || "";
      if (text) {
        fullResponse += text;
        onChunk(text);
      }
    }

    const codeBlocks = extractCodeBlocks(fullResponse);
    onDone(fullResponse, codeBlocks);
  } catch (error: any) {
    onError(error);
  }
}

export async function generateSecureCode(
  task: string,
  language: string,
): Promise<{ explanation: string; codeBlocks: CodeBlock[]; fullResponse: string }> {
  const prompt = `Generate production-ready, secure ${language} code for the following task:\n\n${task}\n\nRequirements:\n- Follow secure coding best practices\n- Include comprehensive input validation\n- Add proper error handling\n- Include security-relevant comments\n- Suggest an appropriate filename for each code file\n- After the code, provide a brief security analysis of the implementation`;

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: AEGIS_AGENT_SYSTEM_PROMPT },
      { role: "user", content: prompt },
    ],
    max_completion_tokens: 8192,
  });

  const fullResponse = response.choices[0]?.message?.content || "";
  const codeBlocks = extractCodeBlocks(fullResponse);
  const explanation = fullResponse.replace(/```[\s\S]*?```/g, "").trim();

  return { explanation, codeBlocks, fullResponse };
}

export function generateCodePackage(code: string, filename: string): Buffer {
  return Buffer.from(code, "utf-8");
}

export const AGENT_CAPABILITIES = {
  name: "AegisAI360",
  version: "1.0.0",
  description: "Elite cybersecurity AI agent for threat analysis, secure coding, and incident response",
  capabilities: [
    { id: "threat_analysis", name: "Threat Analysis", description: "Analyze and assess cybersecurity threats with MITRE ATT&CK mapping", icon: "shield" },
    { id: "secure_code", name: "Secure Code Generation", description: "Generate production-ready, secure code in any programming language", icon: "code" },
    { id: "vuln_assessment", name: "Vulnerability Assessment", description: "Assess vulnerabilities, analyze CVEs, and recommend remediations", icon: "bug" },
    { id: "malware_education", name: "Malware Analysis Education", description: "Learn how malware works to better defend against threats", icon: "microscope" },
    { id: "incident_response", name: "Incident Response", description: "Get IR playbooks, forensics guidance, and containment strategies", icon: "alert" },
    { id: "security_architecture", name: "Security Architecture", description: "Design secure systems with zero-trust and defense-in-depth principles", icon: "building" },
  ],
  quickPrompts: [
    { id: "threat", label: "Analyze a Threat", prompt: "Analyze this security threat and provide MITRE ATT&CK mapping, severity assessment, and recommended defensive actions:" },
    { id: "code", label: "Generate Secure Code", prompt: "Generate secure, production-ready code for:" },
    { id: "vuln", label: "Assess Vulnerability", prompt: "Provide a detailed vulnerability assessment for:" },
    { id: "malware", label: "Explain Malware", prompt: "Explain how this type of malware works for educational/defensive purposes:" },
    { id: "incident", label: "Incident Response", prompt: "Create an incident response plan for the following scenario:" },
    { id: "review", label: "Security Code Review", prompt: "Perform a security code review on the following code and identify vulnerabilities:" },
  ],
};
