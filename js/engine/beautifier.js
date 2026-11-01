/**
 * Lightweight Code Beautifier and Formatter
 * Formats JSON, JavaScript, HTML, and generic scripts.
 */

const Beautifier = {
  /**
   * Auto-detects and beautifies code or structured text
   */
  beautify(text) {
    if (!text || typeof text !== 'string') return '';
    const trimmed = text.trim();

    // 1. JSON
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        const parsed = JSON.parse(trimmed);
        return JSON.stringify(parsed, null, 2);
      } catch (_) {}
    }

    // 2. JavaScript / C-style / PowerShell
    if (trimmed.includes('{') || trimmed.includes(';') || trimmed.includes('function') || trimmed.includes('$')) {
      return this.beautifyCStyle(trimmed);
    }

    // 3. XML / HTML
    if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
      return this.beautifyXml(trimmed);
    }

    return text;
  },

  beautifyCStyle(code) {
    let indent = 0;
    const tab = '  ';
    let output = '';
    let inString = false;
    let stringChar = '';
    let isEscaped = false;

    // Normalizing semicolons and brackets with newlines
    let normalized = code.replace(/;\s*/g, ';\n')
                         .replace(/\{\s*/g, '{\n')
                         .replace(/\}\s*/g, '\n}\n');

    const lines = normalized.split('\n');
    const formattedLines = [];

    for (let rawLine of lines) {
      let line = rawLine.trim();
      if (!line) continue;

      if (line.startsWith('}')) {
        indent = Math.max(0, indent - 1);
      }

      formattedLines.push(tab.repeat(indent) + line);

      if (line.endsWith('{')) {
        indent++;
      }
    }

    return formattedLines.join('\n');
  },

  beautifyXml(xml) {
    let formatted = '';
    let indent = 0;
    const tab = '  ';
    const reg = /(>)(<)(\/*)/g;
    xml = xml.replace(reg, '$1\r\n$2$3');

    xml.split('\r\n').forEach(node => {
      let change = 0;
      if (node.match(/.+<\/\w[^>]*>$/)) {
        change = 0;
      } else if (node.match(/^<\/\w/)) {
        if (indent !== 0) indent -= 1;
      } else if (node.match(/^<\w[^>]*[^\/]>.*$/)) {
        change = 1;
      }
      formatted += tab.repeat(indent) + node + '\r\n';
      indent += change;
    });

    return formatted.trim();
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Beautifier;
}
