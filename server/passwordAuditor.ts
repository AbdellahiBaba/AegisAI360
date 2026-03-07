import { createHash } from "crypto";

const COMMON_PASSWORDS = [
  "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
  "qwerty", "abc123", "111111", "password1", "iloveyou", "1q2w3e4r", "000000",
  "qwerty123", "zaq12wsx", "dragon", "sunshine", "princess", "letmein", "654321",
  "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman", "asdfghjkl",
  "football", "master", "welcome", "shadow", "ashley", "michael", "ninja",
  "mustang", "jessica", "charlie", "andrew", "joshua", "batman", "daniel",
  "trustno1", "whatever", "access", "starwars", "passw0rd", "hello", "admin",
  "121212", "flower", "hottie", "lovely", "7777777", "888888", "666666",
  "computer", "killer", "pepper", "soccer", "hockey", "hunter", "harley",
  "ranger", "buster", "thomas", "robert", "baseball", "solo", "ashley1",
  "password123", "qwerty1", "letmein1", "welcome1", "admin123", "login",
  "changeme", "default", "guest", "root", "toor", "pass", "test", "user",
  "demo", "p@ssw0rd", "p@ssword", "pa$$word", "passw0rd!", "Password1",
  "Password1!", "P@ssw0rd", "P@ssword1", "Qwerty123", "Abc123!", "Admin123!",
];

const KEYBOARD_WALKS = [
  "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
  "qweasd", "qweasdzxc", "1qaz2wsx", "1qaz2wsx3edc", "zaq12wsx",
  "!qaz@wsx", "qazwsx", "qazwsxedc", "rfvtgb", "tgbyhn", "yhnujm",
  "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "0987654321",
];

const LEET_MAP: Record<string, string> = {
  "4": "a", "@": "a", "8": "b", "(": "c", "3": "e",
  "6": "g", "#": "h", "1": "i", "!": "i", "|": "l",
  "0": "o", "$": "s", "5": "s", "7": "t", "+": "t",
  "2": "z",
};

function decodeLeet(password: string): string {
  return password.toLowerCase().split("").map(c => LEET_MAP[c] || c).join("");
}

function calculateEntropy(password: string): number {
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) charsetSize += 33;
  if (charsetSize === 0) return 0;
  return password.length * Math.log2(charsetSize);
}

function detectPatterns(password: string): string[] {
  const patterns: string[] = [];
  const lower = password.toLowerCase();

  if (/(.)\1{2,}/.test(password)) {
    patterns.push("Contains repeated characters (e.g., 'aaa')");
  }

  if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
    patterns.push("Contains alphabetical sequence");
  }

  if (/(?:012|123|234|345|456|567|678|789|890)/.test(password)) {
    patterns.push("Contains numeric sequence");
  }

  for (const walk of KEYBOARD_WALKS) {
    if (lower.includes(walk)) {
      patterns.push(`Contains keyboard walk pattern ('${walk}')`);
      break;
    }
  }

  const decoded = decodeLeet(password);
  if (decoded !== lower && COMMON_PASSWORDS.includes(decoded)) {
    patterns.push("Uses leet speak substitution of a common password");
  }

  if (/^(19|20)\d{2}$/.test(password) || /(19|20)\d{2}/.test(password)) {
    patterns.push("Contains a year pattern (potential date)");
  }

  if (/^\d{2}[\/\-]\d{2}[\/\-]\d{2,4}$/.test(password)) {
    patterns.push("Password appears to be a date");
  }

  if (/^[A-Z][a-z]+\d+[!@#$%^&*]?$/.test(password)) {
    patterns.push("Follows predictable pattern: Capital + lowercase + digits + symbol");
  }

  if (/^(.+)\1+$/.test(password)) {
    patterns.push("Password is a repeated pattern");
  }

  return patterns;
}

function estimateCrackTime(entropy: number): {
  onlineThrottled: string;
  onlineUnthrottled: string;
  offlineSlow: string;
  offlineFast: string;
  gpuCluster: string;
} {
  const combinations = Math.pow(2, entropy);

  function formatTime(seconds: number): string {
    if (seconds < 0.001) return "instant";
    if (seconds < 1) return "less than a second";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
    const years = seconds / 31536000;
    if (years < 1000) return `${Math.round(years)} years`;
    if (years < 1e6) return `${Math.round(years / 1000)}K years`;
    if (years < 1e9) return `${Math.round(years / 1e6)}M years`;
    if (years < 1e12) return `${Math.round(years / 1e9)}B years`;
    return "centuries+";
  }

  return {
    onlineThrottled: formatTime(combinations / 10),
    onlineUnthrottled: formatTime(combinations / 100),
    offlineSlow: formatTime(combinations / 10000),
    offlineFast: formatTime(combinations / 1e10),
    gpuCluster: formatTime(combinations / 1e12),
  };
}

function getStrengthLabel(score: number): string {
  if (score >= 90) return "Very Strong";
  if (score >= 70) return "Strong";
  if (score >= 50) return "Moderate";
  if (score >= 30) return "Weak";
  return "Very Weak";
}

function getStrengthColor(score: number): string {
  if (score >= 90) return "emerald";
  if (score >= 70) return "green";
  if (score >= 50) return "yellow";
  if (score >= 30) return "orange";
  return "red";
}

export function analyzePassword(password: string) {
  const composition = {
    length: password.length,
    uppercase: (password.match(/[A-Z]/g) || []).length,
    lowercase: (password.match(/[a-z]/g) || []).length,
    digits: (password.match(/[0-9]/g) || []).length,
    special: (password.match(/[^A-Za-z0-9\s]/g) || []).length,
    spaces: (password.match(/\s/g) || []).length,
    uniqueChars: new Set(password).size,
  };

  const entropy = calculateEntropy(password);
  const patterns = detectPatterns(password);
  const isCommon = COMMON_PASSWORDS.includes(password.toLowerCase());
  const crackTime = estimateCrackTime(entropy);

  const weaknesses: string[] = [];
  const suggestions: string[] = [];

  if (password.length < 8) {
    weaknesses.push("Password is too short (minimum 8 characters recommended)");
    suggestions.push("Use at least 12 characters for better security");
  } else if (password.length < 12) {
    weaknesses.push("Password length is acceptable but could be longer");
    suggestions.push("Consider using 16+ characters for optimal security");
  }

  if (composition.uppercase === 0) {
    weaknesses.push("No uppercase letters");
    suggestions.push("Add uppercase letters to increase complexity");
  }
  if (composition.lowercase === 0) {
    weaknesses.push("No lowercase letters");
    suggestions.push("Add lowercase letters to increase complexity");
  }
  if (composition.digits === 0) {
    weaknesses.push("No numeric digits");
    suggestions.push("Add numbers to increase complexity");
  }
  if (composition.special === 0) {
    weaknesses.push("No special characters");
    suggestions.push("Add special characters (!@#$%^&*) to increase complexity");
  }

  if (isCommon) {
    weaknesses.push("Password is in the common passwords list");
    suggestions.push("Choose a unique password not found in common lists");
  }

  if (composition.uniqueChars < password.length * 0.5) {
    weaknesses.push("Low character diversity - too many repeated characters");
    suggestions.push("Use more varied characters throughout the password");
  }

  weaknesses.push(...patterns);

  let score = 0;
  score += Math.min(25, password.length * 2);
  score += Math.min(15, entropy / 5);
  score += composition.uppercase > 0 ? 5 : 0;
  score += composition.lowercase > 0 ? 5 : 0;
  score += composition.digits > 0 ? 5 : 0;
  score += composition.special > 0 ? 10 : 0;
  score += Math.min(10, (composition.uniqueChars / password.length) * 10);
  score -= isCommon ? 40 : 0;
  score -= patterns.length * 5;
  score = Math.max(0, Math.min(100, Math.round(score)));

  const nistCompliance = checkNISTCompliance(password);

  return {
    score,
    strength: getStrengthLabel(score),
    strengthColor: getStrengthColor(score),
    entropy: Math.round(entropy * 10) / 10,
    composition,
    crackTime,
    weaknesses,
    suggestions,
    patterns,
    isCommon,
    nistCompliance,
  };
}

function checkNISTCompliance(password: string): {
  compliant: boolean;
  checks: Array<{ rule: string; passed: boolean; description: string }>;
} {
  const checks = [
    {
      rule: "Minimum Length (8 characters)",
      passed: password.length >= 8,
      description: "NIST SP 800-63B requires a minimum of 8 characters for memorized secrets",
    },
    {
      rule: "Recommended Length (15+ characters)",
      passed: password.length >= 15,
      description: "NIST recommends supporting passwords up to 64 characters and encouraging longer passphrases",
    },
    {
      rule: "Not a Common Password",
      passed: !COMMON_PASSWORDS.includes(password.toLowerCase()),
      description: "Password must not appear in commonly-used or compromised password lists",
    },
    {
      rule: "No Repetitive Patterns",
      passed: !/(.)\1{2,}/.test(password),
      description: "Should not contain repetitive or sequential characters",
    },
    {
      rule: "No Sequential Characters",
      passed: !(/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password) || /(?:012|123|234|345|456|567|678|789|890)/.test(password)),
      description: "Should not contain sequential characters like 'abc' or '123'",
    },
    {
      rule: "Not Context-Specific",
      passed: !/^(password|admin|user|login|welcome|guest|root)/i.test(password),
      description: "Should not be a context-specific word such as the service name or username",
    },
  ];

  return {
    compliant: checks.filter(c => c.rule.includes("Minimum") || c.rule.includes("Common")).every(c => c.passed),
    checks,
  };
}

export async function checkBreachStatus(password: string): Promise<{
  breached: boolean;
  occurrences: number;
  message: string;
}> {
  try {
    const sha1Hash = createHash("sha1").update(password).digest("hex").toUpperCase();
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "User-Agent": "AegisAI360-PasswordAuditor" },
    });

    if (!response.ok) {
      throw new Error(`HIBP API returned ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split("\n");

    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(":");
      if (hashSuffix === suffix) {
        const occurrences = parseInt(count, 10);
        return {
          breached: true,
          occurrences,
          message: `This password has been found in ${occurrences.toLocaleString()} data breaches. It should NOT be used.`,
        };
      }
    }

    return {
      breached: false,
      occurrences: 0,
      message: "This password has not been found in any known data breaches.",
    };
  } catch (error: any) {
    return {
      breached: false,
      occurrences: -1,
      message: `Unable to check breach status: ${error.message}`,
    };
  }
}

export function auditPolicy(policy: {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireDigits?: boolean;
  requireSpecial?: boolean;
  preventCommon?: boolean;
  maxAge?: number;
  historyCount?: number;
  lockoutThreshold?: number;
  lockoutDuration?: number;
  mfaRequired?: boolean;
}) {
  const findings: Array<{
    category: string;
    rule: string;
    status: "pass" | "fail" | "warning";
    recommendation: string;
    nistReference: string;
  }> = [];

  const minLen = policy.minLength || 0;
  findings.push({
    category: "Length Requirements",
    rule: `Minimum length: ${minLen} characters`,
    status: minLen >= 8 ? (minLen >= 12 ? "pass" : "warning") : "fail",
    recommendation: minLen < 8
      ? "Increase minimum length to at least 8 characters (12+ recommended)"
      : minLen < 12
        ? "Consider increasing minimum length to 12+ characters for stronger security"
        : "Minimum length meets best practice guidelines",
    nistReference: "NIST SP 800-63B Section 5.1.1.1",
  });

  const maxLen = policy.maxLength || 64;
  findings.push({
    category: "Length Requirements",
    rule: `Maximum length: ${maxLen} characters`,
    status: maxLen >= 64 ? "pass" : (maxLen >= 32 ? "warning" : "fail"),
    recommendation: maxLen < 64
      ? "Allow passwords up to at least 64 characters to support passphrases"
      : "Maximum length supports passphrases as recommended",
    nistReference: "NIST SP 800-63B Section 5.1.1.1",
  });

  findings.push({
    category: "Complexity",
    rule: `Require uppercase: ${policy.requireUppercase ? "Yes" : "No"}`,
    status: "warning",
    recommendation: "NIST no longer recommends mandatory complexity rules. Focus on length and breach checking instead.",
    nistReference: "NIST SP 800-63B Section 5.1.1.1",
  });

  findings.push({
    category: "Breach Protection",
    rule: `Check against common passwords: ${policy.preventCommon ? "Yes" : "No"}`,
    status: policy.preventCommon ? "pass" : "fail",
    recommendation: policy.preventCommon
      ? "Good - checking against known breached/common passwords"
      : "Enable checking passwords against known breached/common password lists",
    nistReference: "NIST SP 800-63B Section 5.1.1.2",
  });

  const maxAge = policy.maxAge || 0;
  findings.push({
    category: "Rotation Policy",
    rule: maxAge > 0 ? `Password expires every ${maxAge} days` : "No password expiration",
    status: maxAge === 0 ? "pass" : (maxAge >= 90 ? "warning" : "fail"),
    recommendation: maxAge > 0
      ? "NIST recommends NOT requiring periodic password changes unless there is evidence of compromise"
      : "Good - no forced periodic password rotation",
    nistReference: "NIST SP 800-63B Section 5.1.1.2",
  });

  findings.push({
    category: "Multi-Factor Authentication",
    rule: `MFA required: ${policy.mfaRequired ? "Yes" : "No"}`,
    status: policy.mfaRequired ? "pass" : "fail",
    recommendation: policy.mfaRequired
      ? "Good - multi-factor authentication is enabled"
      : "Enable multi-factor authentication for all accounts",
    nistReference: "NIST SP 800-63B Section 5.1.2",
  });

  const lockout = policy.lockoutThreshold || 0;
  findings.push({
    category: "Account Lockout",
    rule: lockout > 0 ? `Lock after ${lockout} failed attempts` : "No account lockout",
    status: lockout > 0 ? (lockout <= 10 ? "pass" : "warning") : "fail",
    recommendation: lockout === 0
      ? "Implement account lockout or rate limiting after failed login attempts"
      : lockout > 10
        ? "Consider reducing lockout threshold to 5-10 attempts"
        : "Account lockout threshold is properly configured",
    nistReference: "NIST SP 800-63B Section 5.2.2",
  });

  const passCount = findings.filter(f => f.status === "pass").length;
  const totalCount = findings.length;
  const overallScore = Math.round((passCount / totalCount) * 100);

  return {
    overallScore,
    grade: overallScore >= 90 ? "A" : overallScore >= 75 ? "B" : overallScore >= 60 ? "C" : overallScore >= 40 ? "D" : "F",
    findings,
    summary: {
      total: totalCount,
      pass: passCount,
      warning: findings.filter(f => f.status === "warning").length,
      fail: findings.filter(f => f.status === "fail").length,
    },
  };
}

export function generatePassword(options: {
  length?: number;
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeDigits?: boolean;
  includeSpecial?: boolean;
  excludeAmbiguous?: boolean;
  count?: number;
}): string[] {
  const length = Math.max(8, Math.min(128, options.length || 16));
  const count = Math.max(1, Math.min(10, options.count || 5));

  let chars = "";
  const required: string[] = [];

  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

  const ambiguous = "Il1O0oS5Z2";

  const filterAmbiguous = (s: string) =>
    options.excludeAmbiguous ? s.split("").filter(c => !ambiguous.includes(c)).join("") : s;

  if (options.includeUppercase !== false) {
    const filtered = filterAmbiguous(upper);
    chars += filtered;
    required.push(filtered[Math.floor(Math.random() * filtered.length)]);
  }
  if (options.includeLowercase !== false) {
    const filtered = filterAmbiguous(lower);
    chars += filtered;
    required.push(filtered[Math.floor(Math.random() * filtered.length)]);
  }
  if (options.includeDigits !== false) {
    const filtered = filterAmbiguous(digits);
    chars += filtered;
    required.push(filtered[Math.floor(Math.random() * filtered.length)]);
  }
  if (options.includeSpecial !== false) {
    const filtered = filterAmbiguous(special);
    chars += filtered;
    required.push(filtered[Math.floor(Math.random() * filtered.length)]);
  }

  if (chars.length === 0) {
    chars = filterAmbiguous(lower + digits);
  }

  const passwords: string[] = [];
  for (let i = 0; i < count; i++) {
    let pw = "";
    for (let j = 0; j < length - required.length; j++) {
      pw += chars[Math.floor(Math.random() * chars.length)];
    }
    const allChars = pw.split("").concat(required);
    for (let j = allChars.length - 1; j > 0; j--) {
      const k = Math.floor(Math.random() * (j + 1));
      [allChars[j], allChars[k]] = [allChars[k], allChars[j]];
    }
    passwords.push(allChars.join(""));
  }

  return passwords;
}
