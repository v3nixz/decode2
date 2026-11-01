/**
 * Decoders and Deobfuscation Transforms
 * Contains standalone and chained transformation functions.
 */

const Decoders = {
  // UTF-8 / Text utilities
  textDecoder: new TextDecoder('utf-8', { fatal: false }),
  textEncoder: new TextEncoder(),

  /**
   * Safe Base64 decode supporting UTF-8 and URL-safe characters
   */
  fromBase64(input, isUrlSafe = false) {
    if (!input || typeof input !== 'string') throw new Error('Invalid input');
    let clean = input.trim().replace(/\s+/g, '');
    if (isUrlSafe || clean.includes('-') || clean.includes('_')) {
      clean = clean.replace(/-/g, '+').replace(/_/g, '/');
    }
    // Pad with =
    while (clean.length % 4 !== 0) {
      clean += '=';
    }
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return this.textDecoder.decode(bytes);
  },

  /**
   * PowerShell UTF-16LE Base64 decoder
   * Used heavily in malicious PowerShell commands (e.g. powershell -enc ...)
   */
  fromBase64UTF16(input) {
    if (!input || typeof input !== 'string') throw new Error('Invalid input');
    let clean = input.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (clean.length % 4 !== 0) clean += '=';
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const utf16decoder = new TextDecoder('utf-16le', { fatal: false });
    return utf16decoder.decode(bytes);
  },

  /**
   * Base32 Decode
   */
  fromBase32(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let clean = input.trim().toUpperCase().replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    const output = [];

    for (let i = 0; i < clean.length; i++) {
      const idx = alphabet.indexOf(clean[i]);
      if (idx === -1) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return this.textDecoder.decode(new Uint8Array(output));
  },

  /**
   * Hex to String (handles \x41, 0x41, %41, space/comma separated, continuous hex)
   */
  fromHex(input) {
    if (!input || typeof input !== 'string') throw new Error('Invalid input');
    let clean = input.trim();

    // Strip common hex prefixes
    clean = clean.replace(/\\x/gi, ' ')
                 .replace(/0x/gi, ' ')
                 .replace(/%/gi, ' ')
                 .replace(/[,;:-]/g, ' ')
                 .replace(/\s+/g, ' ')
                 .trim();

    let hexTokens;
    if (clean.includes(' ')) {
      hexTokens = clean.split(' ').filter(t => t.length > 0);
    } else {
      // Continuous string
      if (clean.length % 2 !== 0) clean = '0' + clean;
      hexTokens = clean.match(/.{1,2}/g) || [];
    }

    const bytes = new Uint8Array(hexTokens.map(h => parseInt(h, 16)));
    return this.textDecoder.decode(bytes);
  },

  /**
   * URL Decode (Percent decoding)
   */
  fromUrl(input) {
    if (!input || typeof input !== 'string') throw new Error('Invalid input');
    try {
      return decodeURIComponent(input);
    } catch {
      // Fallback for malformed percent sequences
      return unescape(input);
    }
  },

  /**
   * HTML Entities Decode
   */
  fromHtmlEntities(input) {
    if (!input || typeof input !== 'string') return '';
    const temp = document.createElement('textarea');
    temp.innerHTML = input;
    return temp.value;
  },

  /**
   * Unicode Escapes Decode (\u0041, \u{41}, \U00000041)
   */
  fromUnicodeEscapes(input) {
    return input.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
                .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
                .replace(/\\U([0-9a-fA-F]{8})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)));
  },

  /**
   * Binary bit stream to String (e.g. 01001000 01100101)
   */
  fromBinary(input) {
    const clean = input.replace(/\s+/g, '');
    const bytes = [];
    for (let i = 0; i < clean.length; i += 8) {
      const byteStr = clean.substr(i, 8);
      if (byteStr.length === 8) {
        bytes.push(parseInt(byteStr, 2));
      }
    }
    return this.textDecoder.decode(new Uint8Array(bytes));
  },

  /**
   * Octal to String (\101\102 or space separated)
   */
  fromOctal(input) {
    const tokens = input.match(/\\[0-7]{1,3}|[0-7]{3}/g);
    if (!tokens) throw new Error('No valid octal tokens found');
    const bytes = tokens.map(t => parseInt(t.replace('\\', ''), 8));
    return this.textDecoder.decode(new Uint8Array(bytes));
  },

  /**
   * Decimal CharCode / Byte Array to String ([72, 101, 108, 108, 111])
   */
  fromDecimalBytes(input) {
    const clean = input.replace(/String\.fromCharCode\s*\(/gi, '')
                       .replace(/[\[\]\(\);]/g, '');
    const tokens = clean.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (tokens.length === 0) throw new Error('No valid numbers');
    return String.fromCharCode(...tokens);
  },

  /**
   * ROT13 & ROT47
   */
  fromRot13(input) {
    return input.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
  },

  fromRot47(input) {
    return input.replace(/[\x21-\x7e]/g, c => {
      return String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94));
    });
  },

  /**
   * Caesar Cipher Auto-Crack (tests shifts 1..25 and picks highest readability score)
   */
  autoCaesar(input) {
    let bestShift = 0;
    let bestScore = -1;
    let bestDecoded = input;

    for (let shift = 1; shift < 26; shift++) {
      const decoded = input.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - base - shift + 26) % 26 + base);
      });
      const score = Heuristics.scoreReadability(decoded);
      if (score > bestScore) {
        bestScore = score;
        bestShift = shift;
        bestDecoded = decoded;
      }
    }
    return { decoded: bestDecoded, shift: bestShift, score: bestScore };
  },

  /**
   * Reverse string
   */
  fromReverse(input) {
    return input.split('').reverse().join('');
  },

  /**
   * Single-byte XOR Auto-Crack
   * Scans keys 1..255 and finds key with best score
   */
  autoXor(input) {
    let bytes;
    // If input is hex or raw string
    if (Heuristics.isHex(input)) {
      try {
        const hexStr = input.replace(/[\s\\x,:-]/g, '');
        const matched = hexStr.match(/.{1,2}/g) || [];
        bytes = new Uint8Array(matched.map(h => parseInt(h, 16)));
      } catch {
        bytes = this.textEncoder.encode(input);
      }
    } else {
      bytes = this.textEncoder.encode(input);
    }

    let bestKey = -1;
    let bestScore = -1;
    let bestDecoded = '';

    for (let key = 1; key < 256; key++) {
      const xored = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        xored[i] = bytes[i] ^ key;
      }
      const candidate = this.textDecoder.decode(xored);
      const score = Heuristics.scoreReadability(candidate);
      if (score > bestScore) {
        bestScore = score;
        bestKey = key;
        bestDecoded = candidate;
      }
    }

    return { decoded: bestDecoded, key: bestKey, score: bestScore };
  },

  /**
   * Native Gzip Decompress using browser DecompressionStream
   */
  async fromGzip(input) {
    let uint8Array;
    if (typeof input === 'string') {
      // If it's base64 or raw string
      if (Heuristics.isBase64(input)) {
        const binary = atob(input.trim().replace(/\s+/g, ''));
        uint8Array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) uint8Array[i] = binary.charCodeAt(i);
      } else {
        uint8Array = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i++) uint8Array[i] = input.charCodeAt(i) & 0xff;
      }
    } else {
      uint8Array = input;
    }

    if (typeof DecompressionStream === 'undefined') {
      throw new Error('DecompressionStream not supported in this environment');
    }

    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    writer.write(uint8Array);
    writer.close();

    const response = new Response(ds.readable);
    const arrayBuffer = await response.arrayBuffer();
    return this.textDecoder.decode(arrayBuffer);
  },

  /**
   * Native Deflate / Zlib Decompress
   */
  async fromDeflate(input) {
    let uint8Array;
    if (typeof input === 'string') {
      if (Heuristics.isBase64(input)) {
        const binary = atob(input.trim().replace(/\s+/g, ''));
        uint8Array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) uint8Array[i] = binary.charCodeAt(i);
      } else {
        uint8Array = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i++) uint8Array[i] = input.charCodeAt(i) & 0xff;
      }
    } else {
      uint8Array = input;
    }

    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    writer.write(uint8Array);
    writer.close();

    const response = new Response(ds.readable);
    const arrayBuffer = await response.arrayBuffer();
    return this.textDecoder.decode(arrayBuffer);
  },

  /**
   * JWT Decode
   */
  fromJwt(input) {
    const parts = input.trim().split('.');
    if (parts.length < 2) throw new Error('Not a valid JWT');
    const header = JSON.parse(this.fromBase64(parts[0], true));
    const payload = JSON.parse(this.fromBase64(parts[1], true));
    return JSON.stringify({ Header: header, Payload: payload, Signature: parts[2] || '' }, null, 2);
  },

  /**
   * PowerShell Specific Deobfuscation
   * Cleans backticks, resolves format strings, concatenations, and [char] casts
   */
  fromPowerShellObfuscation(code) {
    let result = code;

    // 1. Remove backtick obfuscation: "d`o`w`n`l`o`a`d" -> "download"
    result = result.replace(/`([a-zA-Z0-9$])/g, '$1');

    // 2. PowerShell format operator: ("{1}{0}" -f 'b','a') -> ('ab')
    const formatRegex = /\(\s*(["'])(.+?)\1\s+-f\s+((?:["'].*?["']\s*,\s*)*["'].*?["'])\s*\)/gi;
    result = result.replace(formatRegex, (_, quote, formatTemplate, argsStr) => {
      const args = argsStr.split(/,\s*/).map(a => a.trim().replace(/^['"]|['"]$/g, ''));
      let formatted = formatTemplate.replace(/\{(\d+)\}/g, (m, idx) => {
        const i = parseInt(idx, 10);
        return args[i] !== undefined ? args[i] : m;
      });
      return `"${formatted}"`;
    });

    // 3. String concatenation: ('a' + 'b' + 'c') -> ('abc')
    const concatRegex = /(['"])(.*?)\1\s*\+\s*(['"])(.*?)\3/g;
    let prev;
    do {
      prev = result;
      result = result.replace(concatRegex, '$1$2$4$1');
    } while (result !== prev);

    // 4. [char]0x41 or [char]65
    result = result.replace(/\[char\](0x[0-9a-fA-F]+|\d+)/gi, (_, num) => {
      const val = num.startsWith('0x') || num.startsWith('0X') ? parseInt(num, 16) : parseInt(num, 10);
      return `'${String.fromCharCode(val)}'`;
    });

    // 5. [char[]](65, 66, 67) -join ''
    const charArrayRegex = /\[char\[\]\]\s*\(\s*([\d\s,]+)\s*\)\s*-join\s*['"]{2}/gi;
    result = result.replace(charArrayRegex, (_, nums) => {
      const chars = nums.split(',').map(n => String.fromCharCode(parseInt(n.trim(), 10))).join('');
      return `"${chars}"`;
    });

    return result;
  },

  /**
   * JavaScript Specific Deobfuscation
   * Unescapes hex literals, concatenations, unpacks Dean Edwards packer
   */
  fromJsObfuscation(code) {
    let result = code;

    // 1. Dean Edwards Packer Unpacker: eval(function(p,a,c,k,e,d)...)
    const packerRegex = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)[\s\S]+?\}\s*\(\s*(['"].*?['"]|.*?)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*['"](.*?)['"]\.split\(['"]\|['"]\)/;
    const match = result.match(packerRegex);
    if (match) {
      try {
        let p = match[1];
        if (p.startsWith("'") || p.startsWith('"')) p = p.slice(1, -1);
        const a = parseInt(match[2], 10);
        const c = parseInt(match[3], 10);
        const k = match[4].split('|');
        const e = (c) => (c < a ? '' : e(parseInt(c / a))) + ((c = c % a) > 35 ? String.fromCharCode(c + 29) : c.toString(36));
        let unpacked = p;
        for (let i = c - 1; i >= 0; i--) {
          if (k[i]) {
            const regex = new RegExp('\\b' + e(i) + '\\b', 'g');
            unpacked = unpacked.replace(regex, k[i]);
          }
        }
        result = result.replace(match[0], unpacked);
      } catch (err) {
        console.warn('Packer unpack failed:', err);
      }
    }

    // 2. Unescape \xNN hex strings inside JS code
    result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
      const char = String.fromCharCode(parseInt(hex, 16));
      // Only unescape safe printable chars to prevent breaking JS syntax quotes
      if (char >= ' ' && char <= '~' && char !== '"' && char !== "'" && char !== '\\') {
        return char;
      }
      return `\\x${hex}`;
    });

    // 3. String concatenation joins: "hel" + "lo"
    const jsConcatRegex = /(['"])(.*?)\1\s*\+\s*(['"])(.*?)\3/g;
    let prev;
    do {
      prev = result;
      result = result.replace(jsConcatRegex, '$1$2$4$1');
    } while (result !== prev);

    // 4. String.fromCharCode(104, 101, 108, 108, 111)
    result = result.replace(/String\.fromCharCode\s*\(\s*([0-9\s,]+)\s*\)/g, (_, nums) => {
      const str = nums.split(',').map(n => String.fromCharCode(parseInt(n.trim(), 10))).join('');
      return JSON.stringify(str);
    });

    return result;
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Decoders;
}
