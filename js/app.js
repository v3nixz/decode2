/**
 * CyberDecode Auto - Application Controller & UI Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const inputCode = document.getElementById('inputCode');
  const outputCode = document.getElementById('outputCode');
  const btnAutoDeobfuscate = document.getElementById('btnAutoDeobfuscate');
  const btnReset = document.getElementById('btnReset');
  const btnCopy = document.getElementById('btnCopy');
  const btnDownload = document.getElementById('btnDownload');
  const btnBake = document.getElementById('btnBake');
  const btnBeautify = document.getElementById('btnBeautify');
  const btnPaste = document.getElementById('btnPaste');
  const btnUpload = document.getElementById('btnUpload');
  const fileUpload = document.getElementById('fileUpload');
  const sampleSelect = document.getElementById('sampleSelect');
  const opsList = document.getElementById('opsList');
  const searchOps = document.getElementById('searchOps');
  const pipelineSteps = document.getElementById('pipelineSteps');
  const layerCountBadge = document.getElementById('layerCountBadge');
  const inputEntropy = document.getElementById('inputEntropy');
  const inputSize = document.getElementById('inputSize');
  const outputEntropy = document.getElementById('outputEntropy');
  const outputScore = document.getElementById('outputScore');
  const outputSize = document.getElementById('outputSize');
  const statusIndicator = document.getElementById('statusIndicator');
  const statusDetails = document.getElementById('statusDetails');
  const outputTitleText = document.getElementById('outputTitleText');
  const infoModal = document.getElementById('infoModal');
  const btnInfo = document.getElementById('btnInfo');
  const btnCloseModal = document.getElementById('btnCloseModal');

  // State
  const autoEngine = new AutoDeobfuscator();
  let currentAnalysis = null;
  let activeStepIndex = -1;

  // Manual Operations Catalog
  const OPERATIONS_CATALOG = [
    {
      category: '🔤 Bases & Codificações',
      items: [
        { id: 'from-base64', name: 'From Base64 (UTF-8)', badge: 'B64', fn: (s) => Decoders.fromBase64(s) },
        { id: 'from-base64-utf16', name: 'From Base64 (UTF-16LE / PowerShell)', badge: 'PS-B64', fn: (s) => Decoders.fromBase64UTF16(s) },
        { id: 'from-hex', name: 'From Hex', badge: '0x / \\x', fn: (s) => Decoders.fromHex(s) },
        { id: 'from-url', name: 'URL Decode', badge: '%XX', fn: (s) => Decoders.fromUrl(s) },
        { id: 'from-html', name: 'HTML Entities Decode', badge: '&amp;', fn: (s) => Decoders.fromHtmlEntities(s) },
        { id: 'from-unicode', name: 'Unicode Escapes Decode', badge: '\\u0041', fn: (s) => Decoders.fromUnicodeEscapes(s) },
        { id: 'from-decimal', name: 'Decimal Bytes / CharCodes', badge: '[72,101]', fn: (s) => Decoders.fromDecimalBytes(s) },
        { id: 'from-binary', name: 'From Binary (8-bit)', badge: '0101', fn: (s) => Decoders.fromBinary(s) },
        { id: 'from-base32', name: 'From Base32', badge: 'B32', fn: (s) => Decoders.fromBase32(s) }
      ]
    },
    {
      category: '💻 Scripts & Malware',
      items: [
        { id: 'ps-clean', name: 'PowerShell Deobfuscator', badge: 'PS', fn: (s) => Decoders.fromPowerShellObfuscation(s) },
        { id: 'js-packer', name: 'JS Packer & Hex Unpacker', badge: 'JS', fn: (s) => Decoders.fromJsObfuscation(s) },
        { id: 'jwt-decode', name: 'JWT Token Decode', badge: 'JWT', fn: (s) => Decoders.fromJwt(s) }
      ]
    },
    {
      category: '🔐 Cifras & Cripto',
      items: [
        { id: 'rot13', name: 'ROT13', badge: 'ROT13', fn: (s) => Decoders.fromRot13(s) },
        { id: 'rot47', name: 'ROT47', badge: 'ROT47', fn: (s) => Decoders.fromRot47(s) },
        { id: 'caesar-auto', name: 'Cifra de César Auto-Crack', badge: 'Caesar', fn: (s) => Decoders.autoCaesar(s).decoded },
        { id: 'xor-auto', name: 'XOR Auto-Crack (Byte único)', badge: 'XOR', fn: (s) => Decoders.autoXor(s).decoded },
        { id: 'reverse', name: 'Inverter Texto', badge: 'Rev', fn: (s) => Decoders.fromReverse(s) }
      ]
    },
    {
      category: '🗜️ Compressão',
      items: [
        { id: 'from-gzip', name: 'Gunzip Decompress', badge: 'Gzip', fn: async (s) => await Decoders.fromGzip(s) },
        { id: 'from-deflate', name: 'Deflate / Zlib Decompress', badge: 'Zlib', fn: async (s) => await Decoders.fromDeflate(s) }
      ]
    }
  ];

  // Initialize UI
  initCatalog();
  initSamples();
  setupEventListeners();

  // Populate Operations Catalog
  function initCatalog() {
    opsList.innerHTML = '';
    OPERATIONS_CATALOG.forEach(cat => {
      const catDiv = document.createElement('div');
      catDiv.className = 'ops-category';
      catDiv.innerHTML = `<div class="ops-category-title">${cat.category}</div>`;

      cat.items.forEach(op => {
        const item = document.createElement('div');
        item.className = 'ops-item';
        item.dataset.opId = op.id;
        item.dataset.opName = op.name.toLowerCase();
        item.innerHTML = `
          <div class="op-name">
            <span>🔹</span>
            <span>${op.name}</span>
          </div>
          <span class="op-badge">${op.badge}</span>
        `;
        item.addEventListener('click', () => applyManualOperation(op));
        catDiv.appendChild(item);
      });

      opsList.appendChild(catDiv);
    });
  }

  // Search Filter
  searchOps.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    document.querySelectorAll('.ops-item').forEach(item => {
      const name = item.dataset.opName;
      if (!q || name.includes(q)) {
        item.style.display = 'flex';
      } else {
        item.style.display = 'none';
      }
    });
  });

  // Populate Samples
  function initSamples() {
    if (typeof SAMPLE_PAYLOADS !== 'undefined') {
      SAMPLE_PAYLOADS.forEach((sample, idx) => {
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = `${sample.name} [${sample.badge}]`;
        sampleSelect.appendChild(opt);
      });
    }
  }

  sampleSelect.addEventListener('change', (e) => {
    const idx = parseInt(e.target.value, 10);
    if (!isNaN(idx) && SAMPLE_PAYLOADS[idx]) {
      const sample = SAMPLE_PAYLOADS[idx];
      inputCode.value = sample.data;
      updateInputMetrics();
      statusDetails.textContent = `Carregado: ${sample.description}`;
      // Trigger auto deobfuscate immediately for smooth UX
      runAutoDeobfuscate();
    }
  });

  // Event Listeners
  function setupEventListeners() {
    inputCode.addEventListener('input', updateInputMetrics);

    btnAutoDeobfuscate.addEventListener('click', runAutoDeobfuscate);

    btnReset.addEventListener('click', () => {
      inputCode.value = '';
      outputCode.value = '';
      currentAnalysis = null;
      activeStepIndex = -1;
      updateInputMetrics();
      clearOutputMetrics();
      renderEmptyPipeline();
      sampleSelect.selectedIndex = 0;
      statusIndicator.textContent = '🟢 Pronto';
      statusDetails.textContent = 'Aguardando entrada de dados';
    });

    btnCopy.addEventListener('click', () => {
      if (!outputCode.value) return;
      navigator.clipboard.writeText(outputCode.value).then(() => {
        const originalText = btnCopy.textContent;
        btnCopy.textContent = '✅ Copiado!';
        setTimeout(() => { btnCopy.textContent = originalText; }, 1500);
      });
    });

    btnDownload.addEventListener('click', () => {
      if (!outputCode.value) return;
      const blob = new Blob([outputCode.value], { type: 'text/plain;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'decoded_payload.txt';
      a.click();
    });

    btnBake.addEventListener('click', () => {
      if (!outputCode.value) return;
      inputCode.value = outputCode.value;
      updateInputMetrics();
      runAutoDeobfuscate();
    });

    btnBeautify.addEventListener('click', () => {
      if (!outputCode.value) return;
      outputCode.value = Beautifier.beautify(outputCode.value);
    });

    btnPaste.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        inputCode.value = text;
        updateInputMetrics();
      } catch {
        inputCode.focus();
      }
    });

    btnUpload.addEventListener('click', () => fileUpload.click());
    fileUpload.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        inputCode.value = evt.target.result;
        updateInputMetrics();
        runAutoDeobfuscate();
      };
      reader.readAsText(file);
    });

    // Modal
    btnInfo.addEventListener('click', () => infoModal.classList.add('open'));
    btnCloseModal.addEventListener('click', () => infoModal.classList.remove('open'));
    infoModal.addEventListener('click', (e) => {
      if (e.target === infoModal) infoModal.classList.remove('open');
    });
  }

  // Metrics update
  function updateInputMetrics() {
    const text = inputCode.value;
    inputSize.textContent = `${text.length.toLocaleString()} chars`;
    const entropy = Heuristics.calculateEntropy(text);
    inputEntropy.textContent = `Entropia: ${entropy.toFixed(2)}`;
    setEntropyPillClass(inputEntropy, entropy);
  }

  function updateOutputMetrics(text) {
    outputSize.textContent = `${text.length.toLocaleString()} chars`;
    const entropy = Heuristics.calculateEntropy(text);
    outputEntropy.textContent = `Entropia: ${entropy.toFixed(2)}`;
    setEntropyPillClass(outputEntropy, entropy);

    const score = Heuristics.scoreReadability(text);
    outputScore.textContent = `Score: ${score}/100`;
  }

  function clearOutputMetrics() {
    outputSize.textContent = '0 chars';
    outputEntropy.textContent = 'Entropia: --';
    outputScore.textContent = 'Score: --';
    outputEntropy.className = 'meta-pill';
  }

  function setEntropyPillClass(el, entropy) {
    el.className = 'meta-pill';
    if (entropy >= 5.8) el.classList.add('entropy-high');
    else if (entropy >= 4.0) el.classList.add('entropy-med');
    else el.classList.add('entropy-low');
  }

  // --- O GRANDE DIFERENCIAL: EXECUÇÃO RECURSIVA AUTOMÁTICA ---
  async function runAutoDeobfuscate() {
    const raw = inputCode.value;
    if (!raw.trim()) {
      alert('Por favor, cole ou digite um código/payload no campo de entrada.');
      return;
    }

    statusIndicator.textContent = '⚡ Analisando...';
    statusDetails.textContent = 'Escaneando padrões heurísticos e desenrolando camadas aninhadas...';
    btnAutoDeobfuscate.disabled = true;

    try {
      const result = await autoEngine.deobfuscate(raw, (progress) => {
        statusDetails.textContent = `Camada ${progress.layer}: ${progress.status === 'applied' ? progress.step.operationName : 'Examinando...'}`;
      });

      currentAnalysis = result;
      btnAutoDeobfuscate.disabled = false;

      if (result.totalLayers === 0) {
        outputCode.value = raw;
        updateOutputMetrics(raw);
        statusIndicator.textContent = '🟡 Nenhuma camada detectada';
        statusDetails.textContent = 'O texto parece já estar limpo ou utiliza cifragem não reconhecida.';
        renderSingleNodePipeline('Entrada Direta (Sem alterações)', raw);
        return;
      }

      // Display final clean output
      outputCode.value = result.finalOutput;
      outputTitleText.textContent = `Resultado Final (${result.totalLayers} camada${result.totalLayers > 1 ? 's' : ''} desofuscada${result.totalLayers > 1 ? 's' : ''})`;
      updateOutputMetrics(result.finalOutput);

      statusIndicator.textContent = `✅ Sucesso (${result.totalLayers} Camadas)`;
      statusDetails.textContent = result.steps.map(s => s.operationName).join(' ➔ ');
      layerCountBadge.textContent = `${result.totalLayers} camada(s) detectada(s)`;

      renderPipelineSteps(result.steps, raw);

    } catch (err) {
      console.error(err);
      btnAutoDeobfuscate.disabled = false;
      statusIndicator.textContent = '❌ Erro';
      statusDetails.textContent = `Erro ao processar: ${err.message}`;
    }
  }

  // Render the interactive pipeline stepper cards
  function renderPipelineSteps(steps, initialRaw) {
    pipelineSteps.innerHTML = '';

    // Node 0: Raw Input
    const rawEntropy = Heuristics.calculateEntropy(initialRaw);
    const rawNode = createStepNode({
      index: 0,
      badge: 'Camada 0',
      title: 'Payload Original (Bruto)',
      desc: 'Entrada original recebida antes de qualquer transformação',
      metaLeft: `Tamanho: ${initialRaw.length} chars`,
      metaRight: `Entropia: ${rawEntropy.toFixed(2)}`,
      data: initialRaw,
      isFinal: false
    });
    pipelineSteps.appendChild(rawNode);

    // Connected steps
    steps.forEach((step, idx) => {
      // Arrow separator
      const arrow = document.createElement('div');
      arrow.className = 'step-arrow';
      arrow.textContent = '➔';
      pipelineSteps.appendChild(arrow);

      const isFinal = idx === steps.length - 1;
      const node = createStepNode({
        index: idx + 1,
        badge: `Camada ${step.layer}`,
        title: step.operationName,
        desc: step.description,
        metaLeft: `Δ Entropia: ${step.entropyBefore} → ${step.entropyAfter}`,
        metaRight: `Confiança: ${step.confidence}%`,
        data: step.outputAfter,
        isFinal
      });
      pipelineSteps.appendChild(node);
    });

    // Select the final node by default
    selectStep(steps.length, steps[steps.length - 1].outputAfter, `Camada Final: ${steps[steps.length - 1].operationName}`);
  }

  function createStepNode({ index, badge, title, desc, metaLeft, metaRight, data, isFinal }) {
    const card = document.createElement('div');
    card.className = `step-node ${isFinal ? 'active' : ''}`;
    card.dataset.index = index;

    card.innerHTML = `
      <div class="step-node-header">
        <span class="step-badge">${badge}</span>
        ${isFinal ? '<span style="font-size:10px; color:var(--green); font-weight:700;">★ FINAL</span>' : ''}
      </div>
      <div class="step-title" title="${title}">${title}</div>
      <div class="step-desc">${desc}</div>
      <div class="step-meta">
        <span>${metaLeft}</span>
        <span>${metaRight}</span>
      </div>
    `;

    card.addEventListener('click', () => {
      selectStep(index, data, `${badge}: ${title}`);
    });

    return card;
  }

  function selectStep(index, content, title) {
    activeStepIndex = index;
    document.querySelectorAll('.step-node').forEach(n => {
      if (parseInt(n.dataset.index, 10) === index) {
        n.classList.add('active');
        n.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
      } else {
        n.classList.remove('active');
      }
    });

    outputCode.value = content;
    outputTitleText.textContent = title;
    updateOutputMetrics(content);
  }

  function renderSingleNodePipeline(title, text) {
    pipelineSteps.innerHTML = '';
    const node = createStepNode({
      index: 0,
      badge: 'Direto',
      title: title,
      desc: 'Nenhuma alteração de ofuscação foi necessária',
      metaLeft: `Tamanho: ${text.length} chars`,
      metaRight: `Entropia: ${Heuristics.calculateEntropy(text).toFixed(2)}`,
      data: text,
      isFinal: true
    });
    pipelineSteps.appendChild(node);
    layerCountBadge.textContent = '0 camadas';
  }

  function renderEmptyPipeline() {
    layerCountBadge.textContent = '0 camadas detectadas';
    pipelineSteps.innerHTML = `
      <div class="empty-pipeline">
        <span>⚡ Nenhuma análise executada ainda. Cole seu código e clique em <b>"Desofuscar Tudo Automaticamente"</b> acima.</span>
      </div>
    `;
  }

  // Apply single manual operation from catalog (like CyberChef)
  async function applyManualOperation(op) {
    const current = outputCode.value || inputCode.value;
    if (!current) {
      alert('Cole um texto no Input para aplicar esta operação.');
      return;
    }
    try {
      statusIndicator.textContent = '⚙️ Aplicando...';
      statusDetails.textContent = `Executando: ${op.name}`;
      const res = await op.fn(current);
      outputCode.value = res;
      outputTitleText.textContent = `Manual: ${op.name}`;
      updateOutputMetrics(res);
      statusIndicator.textContent = '✅ Aplicado';
      statusDetails.textContent = `Operação manual '${op.name}' executada com sucesso.`;
    } catch (err) {
      alert(`Falha ao aplicar ${op.name}: ${err.message}`);
      statusIndicator.textContent = '❌ Erro';
      statusDetails.textContent = err.message;
    }
  }

});
