/**
 * Recursive Auto-Deobfuscation Engine
 * Automatically unravels multi-layered obfuscation nested within one another.
 */

class AutoDeobfuscator {
  constructor(options = {}) {
    this.maxDepth = options.maxDepth || 20;
    this.minScoreImprovement = options.minScoreImprovement || 0;
  }

  /**
   * Main entry point: recursively deobfuscates nested layers
   * @param {string} input - The raw or obfuscated code/string
   * @param {function} progressCallback - Optional callback for live step updates
   * @returns {Promise<object>} Detailed analysis report and unraveled layers
   */
  async deobfuscate(input, progressCallback = null) {
    if (!input || typeof input !== 'string') {
      return {
        initialInput: '',
        finalOutput: '',
        totalLayers: 0,
        steps: [],
        summary: 'Nenhum input fornecido.'
      };
    }

    const steps = [];
    const seenHashes = new Set();
    let current = input.trim();
    let layer = 0;
    let keepGoing = true;

    seenHashes.add(this.hashString(current));

    while (keepGoing && layer < this.maxDepth) {
      layer++;
      const currentEntropy = Heuristics.calculateEntropy(current);
      const currentScore = Heuristics.scoreReadability(current);

      if (progressCallback) {
        progressCallback({ layer, status: 'analyzing', currentLength: current.length });
      }

      const bestCandidate = await this.findBestTransformation(current);

      if (!bestCandidate || bestCandidate.result === current) {
        // No further viable transformation found
        keepGoing = false;
        break;
      }

      const newHash = this.hashString(bestCandidate.result);
      if (seenHashes.has(newHash)) {
        // Detected a cycle (e.g. reverse back and forth or rot13 cycle)
        keepGoing = false;
        break;
      }
      seenHashes.add(newHash);

      const nextEntropy = Heuristics.calculateEntropy(bestCandidate.result);
      const nextScore = Heuristics.scoreReadability(bestCandidate.result);

      const stepRecord = {
        layer,
        operationId: bestCandidate.opId,
        operationName: bestCandidate.opName,
        category: bestCandidate.category,
        description: bestCandidate.description,
        inputBefore: current,
        outputAfter: bestCandidate.result,
        entropyBefore: currentEntropy,
        entropyAfter: nextEntropy,
        readabilityBefore: currentScore,
        readabilityAfter: nextScore,
        confidence: bestCandidate.confidence
      };

      steps.push(stepRecord);
      current = bestCandidate.result;

      if (progressCallback) {
        progressCallback({ layer, status: 'applied', step: stepRecord });
      }

      // Check if we reached clear readable plain text with no remaining signs of obfuscation
      if (nextScore > 80 && !this.hasRemainingObfuscation(current)) {
        // We reached high confidence readable plain source code / text
        // Do one last check for PowerShell/JS syntax beautification if applicable
        const codeClean = this.applySyntaxClean(current);
        if (codeClean && codeClean !== current) {
          layer++;
          steps.push({
            layer,
            operationId: 'code-clean',
            operationName: 'Limpeza e Formatação de Código',
            category: 'script',
            description: 'Simplificou concatenações e normalizou strings',
            inputBefore: current,
            outputAfter: codeClean,
            entropyBefore: nextEntropy,
            entropyAfter: Heuristics.calculateEntropy(codeClean),
            readabilityBefore: nextScore,
            readabilityAfter: Heuristics.scoreReadability(codeClean),
            confidence: 95
          });
          current = codeClean;
        }
        break;
      }
    }

    return {
      initialInput: input,
      finalOutput: current,
      totalLayers: steps.length,
      steps,
      summary: this.generateSummary(steps)
    };
  }

  /**
   * Tests all potential transformations on the current string and returns the highest quality candidate
   */
  async findBestTransformation(str) {
    const candidates = [];

    // 1. Embedded wrapper extraction (e.g. powershell -enc [blob], eval(atob([blob])), etc.)
    const embedded = Heuristics.detectEmbeddedPayloads(str);
    if (embedded && embedded.length > 0) {
      for (const item of embedded) {
        if (item.type === 'powershell-enc') {
          try {
            const decoded = Decoders.fromBase64UTF16(item.raw);
            if (decoded && decoded.length > 5) {
              const replaced = str.replace(item.fullMatch, `[PowerShell Deobfuscated: \n${decoded}\n]`);
              candidates.push({
                opId: 'powershell-enc-extract',
                opName: 'PowerShell -EncodedCommand Extraído',
                category: 'script',
                description: 'Extraiu e decodificou comando UTF-16LE Base64 embutido',
                result: decoded.length > (str.length * 0.6) ? decoded : replaced,
                score: Heuristics.scoreReadability(decoded),
                confidence: 98
              });
            }
          } catch (_) {}
        } else if (item.type === 'atob' || item.type === 'base64-blob') {
          try {
            const decoded = Decoders.fromBase64(item.raw);
            if (decoded && decoded.length > 5) {
              const replaced = str.replace(item.fullMatch, decoded);
              candidates.push({
                opId: 'atob-extract',
                opName: 'Base64 Embutido (atob) Extraído',
                category: 'script',
                description: 'Desempacotou string Base64 chamada via atob() ou FromBase64String()',
                result: decoded.length > (str.length * 0.6) ? decoded : replaced,
                score: Heuristics.scoreReadability(decoded),
                confidence: 95
              });
            }
          } catch (_) {}
        } else if (item.type === 'unescape') {
          try {
            const decoded = Decoders.fromUrl(item.raw);
            if (decoded && decoded.length > 5) {
              const replaced = str.replace(item.fullMatch, decoded);
              candidates.push({
                opId: 'unescape-extract',
                opName: 'unescape() / URL Embutido Extraído',
                category: 'script',
                description: 'Decodificou payload percent-encoded embutido em unescape()',
                result: decoded.length > (str.length * 0.6) ? decoded : replaced,
                score: Heuristics.scoreReadability(decoded),
                confidence: 90
              });
            }
          } catch (_) {}
        }
      }
    }

    // 2. PowerShell Specific Obfuscation (Backticks, format operator -f, concatenations)
    if (str.includes('`') || str.includes('-f') || /(['"])\s*\+\s*(['"])/.test(str) || /\[char\]/i.test(str)) {
      try {
        const psCleaned = Decoders.fromPowerShellObfuscation(str);
        if (psCleaned !== str && psCleaned.length > 0) {
          const score = Heuristics.scoreReadability(psCleaned);
          candidates.push({
            opId: 'powershell-clean',
            opName: 'PowerShell Deobfuscator',
            category: 'script',
            description: 'Removeu backticks, resolveu operadores de formato (-f) e concatenações',
            result: psCleaned,
            score: score + 10,
            confidence: 90
          });
        }
      } catch (_) {}
    }

    // 3. JavaScript Dean Edwards Packer / Obfuscation
    if (/eval\s*\(\s*function\s*\(\s*p\s*,/i.test(str) || /\\x[0-9a-fA-F]{2}/.test(str)) {
      try {
        const jsCleaned = Decoders.fromJsObfuscation(str);
        if (jsCleaned !== str && jsCleaned.length > 0) {
          candidates.push({
            opId: 'js-clean',
            opName: 'JavaScript Packer & Hex Unpacker',
            category: 'script',
            description: 'Descompactou Packer eval(p,a,c,k) e converteu escapes hex',
            result: jsCleaned,
            score: Heuristics.scoreReadability(jsCleaned) + 15,
            confidence: 95
          });
        }
      } catch (_) {}
    }

    // 4. URL Percent Encoding
    if (Heuristics.isUrlEncoded(str)) {
      try {
        const decoded = Decoders.fromUrl(str);
        if (decoded !== str) {
          candidates.push({
            opId: 'url-decode',
            opName: 'URL Decode (Percent)',
            category: 'encoding',
            description: 'Decodificou caracteres codificados por URL (%XX)',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 92
          });
        }
      } catch (_) {}
    }

    // 5. HTML Entities
    if (Heuristics.isHtmlEntities(str)) {
      try {
        const decoded = Decoders.fromHtmlEntities(str);
        if (decoded !== str) {
          candidates.push({
            opId: 'html-entities',
            opName: 'HTML Entities Decode',
            category: 'encoding',
            description: 'Converteu entidades HTML (&amp;, &#xx;, &quot;)',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 88
          });
        }
      } catch (_) {}
    }

    // 6. Unicode Escapes
    if (Heuristics.isUnicodeEscapes(str)) {
      try {
        const decoded = Decoders.fromUnicodeEscapes(str);
        if (decoded !== str) {
          candidates.push({
            opId: 'unicode-escapes',
            opName: 'Unicode Escapes Decode',
            category: 'encoding',
            description: 'Converteu sequências Unicode (\\u0041 / \\u{41})',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 90
          });
        }
      } catch (_) {}
    }

    // 7. Base64 UTF-16LE (PowerShell command format)
    if (Heuristics.isBase64UTF16(str)) {
      try {
        const decoded = Decoders.fromBase64UTF16(str);
        if (decoded && decoded.length > 0) {
          candidates.push({
            opId: 'base64-utf16',
            opName: 'From Base64 (UTF-16LE / PowerShell)',
            category: 'encoding',
            description: 'Decodificou Base64 codificado em 2 bytes UTF-16LE (formato padrão PowerShell)',
            result: decoded,
            score: Heuristics.scoreReadability(decoded) + 10,
            confidence: 95
          });
        }
      } catch (_) {}
    }

    // 8. Base64 (Standard UTF-8 / ASCII)
    if (Heuristics.isBase64(str)) {
      try {
        const decoded = Decoders.fromBase64(str);
        if (decoded && decoded.length > 0) {
          // Check if the decoded payload is actually Gzip or Zlib compressed!
          const uint8 = new Uint8Array(decoded.length);
          for (let i = 0; i < decoded.length; i++) uint8[i] = decoded.charCodeAt(i) & 0xff;
          const compressionType = Heuristics.isGzipOrZlib(uint8);

          if (compressionType === 'gzip') {
            try {
              const decompressed = await Decoders.fromGzip(uint8);
              candidates.push({
                opId: 'base64-gzip',
                opName: 'Base64 + Gunzip Decompress',
                category: 'compression',
                description: 'Decodificou Base64 e descompactou stream Gzip',
                result: decompressed,
                score: Heuristics.scoreReadability(decompressed) + 20,
                confidence: 98
              });
            } catch (_) {}
          } else if (compressionType === 'zlib') {
            try {
              const decompressed = await Decoders.fromDeflate(uint8);
              candidates.push({
                opId: 'base64-zlib',
                opName: 'Base64 + Deflate / Zlib Decompress',
                category: 'compression',
                description: 'Decodificou Base64 e descompactou stream Zlib/Deflate',
                result: decompressed,
                score: Heuristics.scoreReadability(decompressed) + 20,
                confidence: 98
              });
            } catch (_) {}
          }

          // Also candidate pure base64
          candidates.push({
            opId: 'base64',
            opName: 'From Base64',
            category: 'encoding',
            description: 'Decodificou representação Base64 RFC 4648',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 85
          });
        }
      } catch (_) {}
    }

    // 9. Hex / Hex Dump
    if (Heuristics.isHex(str)) {
      try {
        const decoded = Decoders.fromHex(str);
        if (decoded && decoded.length > 0) {
          candidates.push({
            opId: 'hex',
            opName: 'From Hex',
            category: 'encoding',
            description: 'Converteu bytes hexadecimais para texto',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 87
          });
        }
      } catch (_) {}
    }

    // 10. Decimal Byte Array / CharCode string
    if (Heuristics.isDecimalBytes(str)) {
      try {
        const decoded = Decoders.fromDecimalBytes(str);
        if (decoded && decoded.length > 0) {
          candidates.push({
            opId: 'decimal-bytes',
            opName: 'Decimal Bytes / String.fromCharCode',
            category: 'encoding',
            description: 'Converteu array de inteiros (char codes) para string',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 92
          });
        }
      } catch (_) {}
    }

    // 11. Binary Bit Stream
    if (Heuristics.isBinaryBits(str)) {
      try {
        const decoded = Decoders.fromBinary(str);
        if (decoded && decoded.length > 0) {
          candidates.push({
            opId: 'binary',
            opName: 'From Binary (8-bit)',
            category: 'encoding',
            description: 'Converteu sequência de bits 0/1 para caracteres',
            result: decoded,
            score: Heuristics.scoreReadability(decoded),
            confidence: 85
          });
        }
      } catch (_) {}
    }

    // 12. JWT (JSON Web Token)
    if (Heuristics.isJWT(str)) {
      try {
        const decoded = Decoders.fromJwt(str);
        candidates.push({
          opId: 'jwt',
          opName: 'JSON Web Token (JWT) Decode',
          category: 'formats',
          description: 'Decodificou cabeçalho e payload JSON do token',
          result: decoded,
          score: 95,
          confidence: 99
        });
      } catch (_) {}
    }

    // 13. ROT13 & Caesar Cipher test (only if candidate score shows noticeable jump)
    const baseScore = Heuristics.scoreReadability(str);
    if (baseScore < 45 && str.length > 15) {
      const rot13 = Decoders.fromRot13(str);
      const rotScore = Heuristics.scoreReadability(rot13);
      if (rotScore > baseScore + 20) {
        candidates.push({
          opId: 'rot13',
          opName: 'ROT13',
          category: 'ciphers',
          description: 'Rotacionou caracteres alfabéticos por 13 posições',
          result: rot13,
          score: rotScore,
          confidence: 80
        });
      } else {
        const caesar = Decoders.autoCaesar(str);
        if (caesar.score > baseScore + 25) {
          candidates.push({
            opId: 'caesar',
            opName: `Cifra de César (Shift +${caesar.shift})`,
            category: 'ciphers',
            description: `Auto-detectou deslocamento de César de ${caesar.shift} posições`,
            result: caesar.decoded,
            score: caesar.score,
            confidence: 78
          });
        }
      }
    }

    // 14. Single-byte XOR crack (if input looks like hex or printable encrypted text)
    if (baseScore < 35 && (Heuristics.isHex(str) || str.length > 20)) {
      const xorResult = Decoders.autoXor(str);
      if (xorResult.score > baseScore + 30 && xorResult.score > 40) {
        candidates.push({
          opId: 'auto-xor',
          opName: `XOR Auto-Crack (Key 0x${xorResult.key.toString(16).toUpperCase()})`,
          category: 'ciphers',
          description: `Identificou chave XOR de byte único 0x${xorResult.key.toString(16).toUpperCase()}`,
          result: xorResult.decoded,
          score: xorResult.score,
          confidence: 85
        });
      }
    }

    // 15. Reverse String test
    // E.g. '=gM0ADM1YDO...': ends with = or starts with reversed b64
    if (str.startsWith('=') || (baseScore < 30 && str.length > 12)) {
      const reversed = Decoders.fromReverse(str);
      if (Heuristics.isBase64(reversed) || Heuristics.scoreReadability(reversed) > baseScore + 20) {
        candidates.push({
          opId: 'reverse',
          opName: 'Reverse Text',
          category: 'transforms',
          description: 'Inverteu a ordem dos caracteres',
          result: reversed,
          score: Heuristics.scoreReadability(reversed) + 10,
          confidence: 75
        });
      }
    }

    if (candidates.length === 0) return null;

    // Sort by confidence and readability score
    candidates.sort((a, b) => (b.confidence * 0.4 + b.score * 0.6) - (a.confidence * 0.4 + a.score * 0.6));
    return candidates[0];
  }

  applySyntaxClean(code) {
    let clean = code;
    try {
      clean = Decoders.fromPowerShellObfuscation(clean);
      clean = Decoders.fromJsObfuscation(clean);
    } catch (_) {}
    return clean;
  }

  hasRemainingObfuscation(str) {
    if (Heuristics.isBase64(str)) return true;
    if (Heuristics.isHex(str)) return true;
    if (Heuristics.isUrlEncoded(str)) return true;
    if (Heuristics.isUnicodeEscapes(str)) return true;
    if (Heuristics.isHtmlEntities(str)) return true;
    if (Heuristics.detectEmbeddedPayloads(str).length > 0) return true;
    return false;
  }

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < Math.min(str.length, 500); i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return `${hash}_${str.length}`;
  }

  generateSummary(steps) {
    if (!steps || steps.length === 0) {
      return 'Nenhuma camada de ofuscação conhecida foi detectada no texto fornecido.';
    }
    const chain = steps.map(s => s.operationName).join(' ➔ ');
    return `Desofuscado com sucesso através de ${steps.length} camada(s) aninhada(s):\n${chain}`;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AutoDeobfuscator;
}
