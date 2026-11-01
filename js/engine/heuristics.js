/**
 * Heuristics and Detection Engine
 * Analyzes string entropy, structure, format signatures, and language/code likelihood.
 */

const Heuristics = {
  // Common programming and natural language words to evaluate readability
  COMMON_WORDS: new Set([
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
    'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there',
    'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no',
    'just', 'him', 'know', 'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then',
    'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well',
    'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most', 'us',
    // Code keywords
    'function', 'var', 'let', 'const', 'return', 'import', 'export', 'class', 'extends', 'default', 'null', 'undefined', 'true', 'false',
    'if', 'else', 'while', 'for', 'switch', 'case', 'break', 'try', 'catch', 'finally', 'throw', 'new', 'this', 'typeof', 'instanceof',
    'document', 'window', 'console', 'log', 'string', 'number', 'boolean', 'array', 'object', 'eval', 'exec',
    // PowerShell & Bash keywords
    'powershell', 'iex', 'invoke-expression', 'invoke-webrequest', 'downloadstring', 'webclient', 'new-object', 'system', 'net',
    'param', 'process', 'scriptblock', 'pipeline', 'set-executionpolicy', 'bypass', 'hidden', 'windowstyle',
    'select-object', 'where-object', 'foreach-object', 'get-content', 'out-file', 'cmd', 'echo', 'sh', 'bash', 'curl', 'wget', 'sudo',
    'chmod', 'grep', 'awk', 'sed', 'python', 'import', 'def', 'print', 'sys', 'os', 'subprocess', 'requests', 'socket',
    // Web / Network keywords
    'http', 'https', 'url', 'uri', 'api', 'json', 'xml', 'html', 'body', 'head', 'script', 'style', 'href', 'src', 'post', 'get',
    'header', 'cookie', 'token', 'bearer', 'authorization', 'user-agent', 'content-type', 'localhost'
  ]),

  /**
   * Calculates Shannon Entropy of a string (0.0 to 8.0)
   * Lower entropy = highly structured / repetitive
   * High entropy (~7.5 - 8.0) = encrypted or compressed data
   * Medium entropy (~4.0 - 5.5) = typical English / source code
   * Base64/Hex encoding usually has characteristic entropy (~5.9 for b64, ~3.8-4.0 for pure hex)
   */
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  },

  /**
   * Computes a readability / meaningfulness score between 0 and 100
   * Looks at printable ratio, word recognitions, syntax punctuation, and whitespace flow
   */
  scoreReadability(text) {
    if (!text || typeof text !== 'string') return 0;
    if (text.length === 0) return 0;

    let printableCount = 0;
    let nullBytes = 0;
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code === 0) nullBytes++;
      if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13 || (code >= 160 && code <= 255)) {
        printableCount++;
      }
    }

    const printableRatio = printableCount / text.length;
    if (printableRatio < 0.65 || (nullBytes / text.length) > 0.1) {
      // Mostly binary or null-padded binary
      return Math.round(printableRatio * 20);
    }

    // Split into tokens
    const tokens = text.toLowerCase().match(/[a-z_-]{2,}/g) || [];
    if (tokens.length === 0) return Math.round(printableRatio * 30);

    let matchCount = 0;
    for (const token of tokens) {
      if (this.COMMON_WORDS.has(token)) {
        matchCount++;
      }
    }

    const wordMatchRatio = matchCount / Math.min(tokens.length, 100);
    const spaceRatio = (text.match(/\s/g) || []).length / text.length;

    // Source code syntax punctuation density
    const codePunctuation = (text.match(/[(){}\[\];,=<>+*\/\.:]/g) || []).length / text.length;

    let score = (printableRatio * 30) + (wordMatchRatio * 45) + (Math.min(spaceRatio, 0.25) * 60) + (Math.min(codePunctuation, 0.15) * 100);
    return Math.min(100, Math.max(0, Math.round(score)));
  },

  /**
   * Identifies if a string looks like Base64
   */
  isBase64(str) {
    const trimmed = str.trim();
    if (trimmed.length < 8) return false;
    // Strip trailing padding for test
    const clean = trimmed.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/_-]+={0,3}$/.test(clean)) return false;
    // Check if valid base64 character distribution
    const unpadded = clean.replace(/=+$/, '');
    if (unpadded.length % 4 === 1) return false;
    // If it's pure decimal or purely one letter, reject
    if (/^\d+$/.test(unpadded)) return false;
    return true;
  },

  /**
   * Identifies PowerShell style UTF-16LE Base64
   */
  isBase64UTF16(str) {
    if (!this.isBase64(str)) return false;
    try {
      const clean = str.trim().replace(/\s+/g, '');
      const binary = atob(clean.replace(/-/g, '+').replace(/_/g, '/'));
      if (binary.length < 6) return false;
      let nullCount = 0;
      for (let i = 1; i < binary.length; i += 2) {
        if (binary.charCodeAt(i) === 0) nullCount++;
      }
      return (nullCount / Math.floor(binary.length / 2)) > 0.7;
    } catch {
      return false;
    }
  },

  /**
   * Identifies Hex / Hex dump formats
   */
  isHex(str) {
    const trimmed = str.trim();
    if (trimmed.length < 4) return false;

    // Format \x41\x42 or 0x41,0x42
    if (/^(\\x[0-9a-fA-F]{2})+$/.test(trimmed)) return true;
    if (/^(0x[0-9a-fA-F]{2}[\s,]*)+$/.test(trimmed)) return true;

    // Continuous hex: 48656c6c6f...
    const clean = trimmed.replace(/[\s:-]+/g, '');
    if (clean.length % 2 === 0 && clean.length >= 6 && /^[0-9a-fA-F]+$/.test(clean)) {
      // Must not be a simple single word like "deadbeef" in a sentence, check length and context
      return true;
    }
    return false;
  },

  /**
   * Identifies URL Encoding
   */
  isUrlEncoded(str) {
    const matches = str.match(/%[0-9a-fA-F]{2}/g);
    if (!matches || matches.length < 2) return false;
    // At least 2% of the string or 2+ instances
    return matches.length >= 2 && (matches.length * 3 / str.length) > 0.05;
  },

  /**
   * Identifies HTML Entities (&amp;, &#65;, &#x41;)
   */
  isHtmlEntities(str) {
    const matches = str.match(/(&[a-zA-Z]+;|&#\d{2,4};|&#x[0-9a-fA-F]{2,4};)/g);
    return matches && matches.length >= 2;
  },

  /**
   * Identifies Unicode escapes (\u0041, \u{41})
   */
  isUnicodeEscapes(str) {
    const matches = str.match(/(\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\})/g);
    return matches && matches.length >= 2;
  },

  /**
   * Identifies Binary bit strings (e.g. 01001000 01100101)
   */
  isBinaryBits(str) {
    const clean = str.trim().replace(/\s+/g, '');
    if (clean.length < 8 || clean.length % 8 !== 0) return false;
    return /^[01]+$/.test(clean);
  },

  /**
   * Identifies Decimal Byte arrays / CharCode lists
   * e.g. [104, 101, 108, 108, 111] or String.fromCharCode(104,101,...)
   */
  isDecimalBytes(str) {
    const trimmed = str.trim();
    if (/^(?:String\.fromCharCode\s*\(\s*)?(\d{1,3}\s*,\s*)+\d{1,3}\s*\)?$/.test(trimmed)) {
      return true;
    }
    if (/^\[?\s*(\d{1,3}\s*,\s*)+\d{1,3}\s*\]?$/.test(trimmed)) {
      const numbers = trimmed.replace(/[\[\]]/g, '').split(',').map(s => parseInt(s.trim(), 10));
      return numbers.length >= 3 && numbers.every(n => n >= 0 && n <= 255);
    }
    return false;
  },

  /**
   * Identifies Gzip/Zlib binary header
   */
  isGzipOrZlib(uint8Array) {
    if (!uint8Array || uint8Array.length < 3) return false;
    // Gzip magic 1F 8B
    if (uint8Array[0] === 0x1f && uint8Array[1] === 0x8b) return 'gzip';
    // Zlib magic 78 01, 78 9C, 78 DA
    if (uint8Array[0] === 0x78 && (uint8Array[1] === 0x01 || uint8Array[1] === 0x9c || uint8Array[1] === 0xda || uint8Array[1] === 0x5e)) {
      return 'zlib';
    }
    return false;
  },

  /**
   * Identifies JWT (JSON Web Token)
   */
  isJWT(str) {
    const parts = str.trim().split('.');
    if (parts.length !== 3) return false;
    return /^[A-Za-z0-9_-]+$/.test(parts[0]) && /^[A-Za-z0-9_-]+$/.test(parts[1]) && /^[A-Za-z0-9_-]+$/.test(parts[2]);
  },

  /**
   * Checks if string contains nested obfuscated payloads inside scripts
   * e.g. eval(atob("...")), powershell -enc "...", String.fromCharCode(...), etc.
   */
  detectEmbeddedPayloads(str) {
    const payloads = [];

    // PowerShell -enc or -EncodedCommand
    const psEncRegex = /(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{16,})/gi;
    let match;
    while ((match = psEncRegex.exec(str)) !== null) {
      payloads.push({
        type: 'powershell-enc',
        raw: match[1],
        fullMatch: match[0],
        index: match.index
      });
    }

    // atob("...") or window.atob("...")
    const atobRegex = /(?:atob|window\[['"]atob['"]\])\s*\(\s*['"`]([A-Za-z0-9+/=]{8,})['"`]\s*\)/gi;
    while ((match = atobRegex.exec(str)) !== null) {
      payloads.push({
        type: 'atob',
        raw: match[1],
        fullMatch: match[0],
        index: match.index
      });
    }

    // FromBase64String("...")
    const b64MethodRegex = /(?:FromBase64String|from_base64|b64decode)\s*\(\s*['"`]([A-Za-z0-9+/=]{8,})['"`]\s*\)/gi;
    while ((match = b64MethodRegex.exec(str)) !== null) {
      payloads.push({
        type: 'base64-blob',
        raw: match[1],
        fullMatch: match[0],
        index: match.index
      });
    }

    // eval(unescape("..."))
    const unescapeRegex = /unescape\s*\(\s*['"`](%[0-9a-fA-F]{2}[^'"`]+)['"`]\s*\)/gi;
    while ((match = unescapeRegex.exec(str)) !== null) {
      payloads.push({
        type: 'unescape',
        raw: match[1],
        fullMatch: match[0],
        index: match.index
      });
    }

    // String.fromCharCode(101, 118, ...)
    const charCodeRegex = /String\.fromCharCode\s*\(\s*([0-9\s,]+)\s*\)/gi;
    while ((match = charCodeRegex.exec(str)) !== null) {
      payloads.push({
        type: 'charcodes',
        raw: match[1],
        fullMatch: match[0],
        index: match.index
      });
    }

    return payloads;
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Heuristics;
}
