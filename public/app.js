/**
 * IP Intelligence — Modern Web Interface JS
 * Includes numeric counter animations, staggered entrances, and fluid SSE processing.
 */

// ── State ────────────────────────────────────────────────────────────────────
const state = {
    reports: [],
    analyzing: false,
};

// ── DOM Elements ─────────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const els = {
    btnSettings: $('#btn-settings'),
    settingsModal: $('#settings-modal'),
    btnCloseSettings: $('#btn-close-settings'),
    btnSaveSettings: $('#btn-save-settings'),
    ipInput: $('#ip-input'),
    ipCount: $('#ip-count'),
    btnAnalyze: $('#btn-analyze'),
    btnUpload: $('#btn-upload'),
    fileUpload: $('#file-upload'),
    progressContainer: $('#progress-container'),
    progressFill: $('#progress-fill'),
    progressText: $('#progress-text'),
    summaryBar: $('#summary-bar'),
    controlsHeader: $('#controls-header'),
    resultsContainer: $('#results-container'),
    emptyState: $('#empty-state'),
    keyVt: $('#key-vt'),
    keyAbuse: $('#key-abuse'),
    keyShodan: $('#key-shodan'),
    keyGreynoise: $('#key-greynoise'),
    keyAlienvault: $('#key-alienvault'),
};

// ── Number Counter Animation ─────────────────────────────────────────────────
function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        // easeOutQuart
        const ease = 1 - Math.pow(1 - progress, 4);
        obj.innerHTML = Math.floor(ease * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            obj.innerHTML = end;
        }
    };
    window.requestAnimationFrame(step);
}

function updateCounterEl(id, newValue) {
    const el = $(id);
    const currentValue = parseInt(el.dataset.val || "0", 10);
    if (currentValue !== newValue) {
        el.dataset.val = newValue;
        animateValue(el, currentValue, newValue, 800);
    }
}

// ── API Keys ─────────────────────────────────────────────────────────────────
function loadKeys() {
    els.keyVt.value = localStorage.getItem('ip_intel_vt_key') || '';
    els.keyAbuse.value = localStorage.getItem('ip_intel_abuse_key') || '';
    els.keyShodan.value = localStorage.getItem('ip_intel_shodan_key') || '';
    els.keyGreynoise.value = localStorage.getItem('ip_intel_greynoise_key') || '';
    els.keyAlienvault.value = localStorage.getItem('ip_intel_alienvault_key') || '';
    updateKeyStatus();
}

function saveKeys() {
    localStorage.setItem('ip_intel_vt_key', els.keyVt.value.trim());
    localStorage.setItem('ip_intel_abuse_key', els.keyAbuse.value.trim());
    localStorage.setItem('ip_intel_shodan_key', els.keyShodan.value.trim());
    localStorage.setItem('ip_intel_greynoise_key', els.keyGreynoise.value.trim());
    localStorage.setItem('ip_intel_alienvault_key', els.keyAlienvault.value.trim());
    updateKeyStatus();
}

function getKeys() {
    return {
        virustotal: els.keyVt.value.trim(),
        abuseipdb: els.keyAbuse.value.trim(),
        shodan: els.keyShodan.value.trim(),
        greynoise: els.keyGreynoise.value.trim(),
        alienvault: els.keyAlienvault.value.trim(),
    };
}

function updateKeyStatus() {
    const vt = els.keyVt.value.trim();
    const abuse = els.keyAbuse.value.trim();
    const shodan = els.keyShodan.value.trim();
    const gn = els.keyGreynoise.value.trim();
    const otx = els.keyAlienvault.value.trim();

    $('#status-vt').textContent = vt ? '✅ Active' : 'Inactive';
    $('#status-vt').style.color = vt ? 'var(--green)' : 'var(--text-muted)';
    $('#status-abuse').textContent = abuse ? '✅ Active' : 'Inactive';
    $('#status-abuse').style.color = abuse ? 'var(--green)' : 'var(--text-muted)';
    $('#status-shodan').textContent = shodan ? '✅ Shodan API Active' : '🌐 Using Free InternetDB';
    $('#status-shodan').style.color = shodan ? 'var(--green)' : 'var(--accent)';
    $('#status-greynoise').textContent = gn ? '✅ Full API Active' : '🌐 Using Free Community API';
    $('#status-greynoise').style.color = gn ? 'var(--green)' : 'var(--accent)';
    $('#status-alienvault').textContent = otx ? '✅ OTX API Active' : '🌐 Using Free OTX API';
    $('#status-alienvault').style.color = otx ? 'var(--green)' : 'var(--accent)';
}

// ── IP Parsing ───────────────────────────────────────────────────────────────
function parseIPs(text) {
    let raw = text.split(/[\n,\s]+/).map(s => s.trim()).filter(s => s.length > 0);
    let expanded = [];
    for (const token of raw) {
        if (token.includes('/')) {
            expanded.push(...expandCIDR(token));
        } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(token) || token.includes(':')) {
            expanded.push(token);
        }
    }
    return [...new Set(expanded)];
}

function handleIPInputChange() {
    const ips = parseIPs(els.ipInput.value);
    const count = ips.length;
    els.ipCount.textContent = `${count} IP(s) ready`;
    els.btnAnalyze.disabled = count === 0 || state.analyzing;

    if (count > 100) {
        els.ipCount.style.color = 'var(--red)';
        els.ipCount.textContent = `${count} IPs (max 100 on web)`;
    } else {
        els.ipCount.style.color = 'var(--text-muted)';
    }
}

// ── Card Rendering ───────────────────────────────────────────────────────────
function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function helpTip(text) {
    return `<span class="help-tip" tabindex="0" aria-label="${escHtml(text)}">?<span class="help-tip-content">${escHtml(text)}</span></span>`;
}

function classLabel(cls) {
    const map = { 'Benign': 'benign', 'Suspicious': 'suspicious', 'Likely Malicious': 'likely-mal', 'Malicious': 'malicious' };
    return map[cls] || 'benign';
}

function renderCard(report, index) {
    const r = report;
    const cls = classLabel(r.risk.classification);
    const score = r.risk.score;
    const own = r.ownership || {};
    const vt = r.virustotal || {};
    const abuse = r.abuseipdb || {};
    const shodan = r.shodan || {};
    const dns = r.dns || {};
    const gn = r.greynoise || {};
    const otx = r.alienvault || {};

    let servicesHtml = '';
    if (shodan.services && shodan.services.length > 0) {
        servicesHtml = `<div style="margin-top:1rem;border-top:1px dashed rgba(255,255,255,0.1);padding-top:1rem;">
            <span style="font-size:0.75rem;font-family:var(--font-head);text-transform:uppercase;color:var(--text-bright);">Detected Services</span>
            ${shodan.services.map(svc => `
                <div class="service-item">
                    <div class="service-header">
                        <span class="service-port">Port ${svc.port}/${svc.protocol || 'tcp'}</span>
                        <span class="service-name">${escHtml(svc.service || 'Unknown')} ${escHtml(svc.version || '')}</span>
                    </div>
                    ${svc.banner ? `<div class="service-banner">${escHtml(svc.banner)}</div>` : ''}
                </div>
            `).join('')}
        </div>`;
    }

    let signalsHtml = '';
    if (r.risk.signals && r.risk.signals.length > 0) {
        signalsHtml = `
        <div class="signals-section">
            <table class="signals-table">
                <thead><tr><th>Weight</th><th>Signal Activity</th><th>Reasoning Context</th></tr></thead>
                <tbody>
                    ${r.risk.signals.map(s => `
                        <tr>
                            <td class="weight ${s.weight >= 0 ? 'weight-positive' : 'weight-negative'}">${s.weight >= 0 ? '+' : ''}${s.weight}</td>
                            <td style="font-weight:600;">${escHtml(s.name)}</td>
                            <td style="color:var(--text-muted)">${escHtml(s.reason)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>`;
    }

    const card = document.createElement('div');
    card.className = 'glass-panel ip-card';
    // Stagger animation based on index
    card.style.animationDelay = `${(index % 10) * 0.1}s`;
    
    const domainsList = (vt.historic_domains || []).map(d => escHtml(d)).join(', ');
    const vulnsList = (shodan.vulns || []).map(v => escHtml(v)).join(', ');
    const hostnamesList = (shodan.hostnames || []).map(h => escHtml(h)).join(', ');

    card.innerHTML = `
        <div class="ip-card-header" onclick="toggleCard(this)">
            <div class="ip-card-left">
                <span class="ip-card-ip">${escHtml(r.ip)}</span>
                <div class="ip-card-tags">
                    ${own.country ? `<span class="tag tag-country">${escHtml(own.country)}</span>` : ''}
                    ${own.asn ? `<span class="tag tag-asn">AS${escHtml(own.asn)}</span>` : ''}
                    ${own.org ? `<span class="tag tag-org">${escHtml(own.org)}</span>` : ''}
                </div>
            </div>
            <div class="ip-card-right">
                <div class="score-badge">
                    <span class="classification-label ${cls}">${r.risk.classification}</span>
                    <span class="score-circle ${cls}">${score}</span>
                </div>
                <span class="expand-chevron">▼</span>
            </div>
        </div>
        <div class="ip-card-details">
            <div class="details-grid">
                <div class="detail-section">
                    <h4>🌐 Network Identity ${helpTip('Basic ownership info from WHOIS/RDAP — shows the ASN, organization, CIDR block, and country that owns this IP address.')}</h4>
                    <div class="detail-row"><span class="key">ASN</span><span class="val">${escHtml(own.asn || '—')}</span></div>
                    <div class="detail-row"><span class="key">Organization</span><span class="val">${escHtml(own.org || '—')}</span></div>
                    <div class="detail-row"><span class="key">CIDR Range</span><span class="val">${escHtml(own.cidr || '—')}</span></div>
                    <div class="detail-row"><span class="key">Country</span><span class="val">${escHtml(own.country || '—')}</span></div>
                    <div class="detail-row"><span class="key">Registry</span><span class="val">${escHtml(own.rir || '—')}</span></div>
                    <div class="detail-row"><span class="key">PTR Record</span><span class="val">${escHtml(dns.ptr || '—')}</span></div>
                </div>

                <div class="detail-section">
                    <h4>⚠️ VirusTotal Telemetry ${helpTip('Aggregated scan results from 70+ antivirus engines. "Malicious Flags" means how many vendors flagged this IP as dangerous. Higher = worse.')}</h4>
                    ${vt.available ? `
                        <div class="detail-row"><span class="key">Malicious Flags</span><span class="val" style="color:${vt.malicious > 0 ? '#f87171' : 'var(--text-bright)'}">${vt.malicious}</span></div>
                        <div class="detail-row"><span class="key">Suspicious Flags</span><span class="val" style="color:${vt.suspicious > 0 ? '#fbbf24' : 'var(--text-bright)'}">${vt.suspicious}</span></div>
                        <div class="detail-row"><span class="key">Harmless Flags</span><span class="val">${vt.harmless}</span></div>
                        <div class="detail-row"><span class="key">Reputation Score</span><span class="val">${vt.reputation}</span></div>
                        <div class="detail-row"><span class="key">AS Owner</span><span class="val">${escHtml(vt.as_owner || '—')}</span></div>
                        ${domainsList ? `<div style="margin-top:0.8rem;"><div class="key" style="margin-bottom:0.2rem;">Historic Resolutions</div><div class="domain-list">${domainsList}</div></div>` : ''}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">Telemetry unavailable (No API Key)</div>`}
                </div>

                <div class="detail-section">
                    <h4>🚨 AbuseIPDB Reports ${helpTip('Community-sourced abuse reports. "Confidence Score" (0-100%) reflects how likely this IP is involved in attacks. Reports come from sysadmins worldwide.')}</h4>
                    ${abuse.available ? `
                        <div class="detail-row"><span class="key">Confidence Score</span><span class="val" style="color:${abuse.abuse_confidence_score > 70 ? '#f87171' : abuse.abuse_confidence_score > 40 ? '#fbbf24' : '#34d399'}">${abuse.abuse_confidence_score}%</span></div>
                        <div class="detail-row"><span class="key">Total Reports</span><span class="val">${abuse.total_reports}</span></div>
                        <div class="detail-row"><span class="key">Whitelisted</span><span class="val">${abuse.is_whitelisted ? '✅ Yes' : 'No'}</span></div>
                        <div class="detail-row"><span class="key">ISP / Hosting</span><span class="val">${escHtml(abuse.isp || '—')}</span></div>
                        <div class="detail-row"><span class="key">Usage Type</span><span class="val">${escHtml(abuse.usage_type || '—')}</span></div>
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">Telemetry unavailable (No API Key)</div>`}
                </div>

                <div class="detail-section">
                    <h4>🔍 Shodan Surface ${helpTip('Attack surface analysis showing open ports, running services, and known CVE vulnerabilities. Exposed ports and unpatched CVEs significantly increase risk.')}</h4>
                    ${shodan.available ? `
                        <div class="detail-row"><span class="key">Open Ports</span><span class="val">${shodan.open_ports && shodan.open_ports.length ? shodan.open_ports.join(', ') : '<span style="color:var(--text-muted)">Clean</span>'}</span></div>
                        ${hostnamesList ? `<div class="detail-row"><span class="key">Hostnames</span><span class="val">${hostnamesList}</span></div>` : ''}
                        ${vulnsList ? `<div style="margin-top:0.8rem;"><div class="key" style="color:#f87171;margin-bottom:0.2rem;">CVE Vulnerabilities</div><div class="vuln-list">${vulnsList}</div></div>` : ''}
                        ${servicesHtml}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">Scanner unreachable</div>`}
                </div>

                <div class="detail-section">
                    <h4>🤫 GreyNoise Context ${helpTip('Identifies mass internet scanners and known-good services. "RIOT" means the IP belongs to a trusted service (e.g. Google, Cloudflare). "Internet Noise" means it\'s scanning the entire internet.')}</h4>
                    ${gn.available ? `
                        <div class="detail-row"><span class="key">Classification</span><span class="val" style="color:${gn.classification==='malicious'?'#f87171':gn.classification==='benign'?'#34d399':'var(--text-bright)'}">${escHtml(gn.classification || 'unknown')}</span></div>
                        <div class="detail-row"><span class="key">Internet Noise</span><span class="val">${gn.seen ? '⚠️ Yes — Mass Scanner' : '✅ No'}</span></div>
                        <div class="detail-row"><span class="key">RIOT (Known Good)</span><span class="val" style="color:${gn.riot?'#34d399':'var(--text-bright)'}">${gn.riot ? '✅ Yes' : 'No'}</span></div>
                        ${gn.name ? `<div class="detail-row"><span class="key">Actor / Name</span><span class="val">${escHtml(gn.name)}</span></div>` : ''}
                        ${gn.tags && gn.tags.length ? `<div class="detail-row"><span class="key">Tags</span><span class="val">${gn.tags.map(t=>escHtml(t)).join(', ')}</span></div>` : ''}
                        ${gn.cve && gn.cve.length ? `<div class="detail-row"><span class="key">CVEs Exploited</span><span class="val" style="color:#f87171">${gn.cve.join(', ')}</span></div>` : ''}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">GreyNoise data unavailable</div>`}
                </div>

                <div class="detail-section">
                    <h4>👽 AlienVault OTX ${helpTip('Open Threat Exchange pulse data. "Threat Pulses" are community-reported threat campaigns. Associated adversary groups and malware samples indicate active threat actor involvement.')}</h4>
                    ${otx.available ? `
                        <div class="detail-row"><span class="key">Threat Pulses</span><span class="val" style="color:${otx.pulse_count>3?'#f87171':otx.pulse_count>0?'#fbbf24':'#34d399'}">${otx.pulse_count}</span></div>
                        <div class="detail-row"><span class="key">Malware Samples</span><span class="val" style="color:${otx.malware_count>0?'#f87171':'var(--text-bright)'}">${otx.malware_count}</span></div>
                        ${otx.adversary ? `<div class="detail-row"><span class="key">Threat Group</span><span class="val" style="color:#f87171;font-weight:700">${escHtml(otx.adversary)}</span></div>` : ''}
                        ${otx.pulse_names && otx.pulse_names.length ? `<div style="margin-top:0.8rem;"><div class="key" style="margin-bottom:0.2rem;">Threat Campaigns</div><div class="domain-list">${otx.pulse_names.map(p=>escHtml(p)).join(', ')}</div></div>` : ''}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">OTX data unavailable</div>`}
                </div>
            </div>
            ${signalsHtml}
        </div>
    `;
    return card;
}

window.toggleCard = function(headerEl) {
    const card = headerEl.closest('.ip-card');
    card.classList.toggle('expanded');
};

// ── Summary Update ───────────────────────────────────────────────────────────
function updateSummary() {
    const reports = state.reports;
    const total = reports.length;
    
    updateCounterEl('#stat-total', total);
    updateCounterEl('#stat-benign', reports.filter(r => r.risk.classification === 'Benign').length);
    updateCounterEl('#stat-suspicious', reports.filter(r => r.risk.classification === 'Suspicious').length);
    updateCounterEl('#stat-likely-mal', reports.filter(r => r.risk.classification === 'Likely Malicious').length);
    updateCounterEl('#stat-malicious', reports.filter(r => r.risk.classification === 'Malicious').length);

    if (total > 0) {
        els.summaryBar.classList.add('visible');
        els.controlsHeader.classList.add('visible');
    }
}

// ── Analyze SSE ──────────────────────────────────────────────────────────────
async function analyze() {
    const ips = parseIPs(els.ipInput.value);
    if (ips.length === 0 || state.analyzing) return;
    if (ips.length > 100) { alert(`Max 100 IPs allowed on web. Sent ${ips.length}.`); return; }

    state.reports = [];
    state.analyzing = true;
    
    els.btnAnalyze.classList.add('loading');
    els.btnAnalyze.disabled = true;
    els.emptyState.style.display = 'none';
    els.resultsContainer.innerHTML = '';
    clearMap();
    
    els.summaryBar.classList.remove('visible');
    els.controlsHeader.classList.remove('visible');
    
    els.progressContainer.classList.add('active');
    els.progressFill.style.width = '0%';
    els.progressText.textContent = `Establishing connection...`;

    // Reset counters to 0
    ['#stat-total', '#stat-benign', '#stat-suspicious', '#stat-likely-mal', '#stat-malicious'].forEach(id => {
        $(id).dataset.val = "0"; $(id).textContent = "0";
    });

    const keys = getKeys();
    let indexCount = 0;

    try {
        const resp = await fetch('/api/analyze/stream', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips, keys }),
        });

        if (!resp.ok) {
            let errMsg = `HTTP ${resp.status}`;
            try {
                const err = await resp.json();
                errMsg = err.error || errMsg;
            } catch (e) {
                errMsg = `Server Error (${resp.status}). The backend failed to start or crashed.`;
            }
            throw new Error(errMsg);
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            let eventType = '';
            let eventData = '';

            for (const line of lines) {
                if (line.startsWith('event: ')) eventType = line.slice(7).trim();
                else if (line.startsWith('data: ')) {
                    eventData = line.slice(6);
                    if (eventType === 'result') {
                        try {
                            const payload = JSON.parse(eventData);
                            state.reports.push(payload.report);
                            els.resultsContainer.appendChild(renderCard(payload.report, indexCount++));
                            plotIPOnMap(payload.report);
                            const pct = (payload.progress / payload.total * 100).toFixed(0);
                            els.progressFill.style.width = pct + '%';
                            els.progressText.textContent = `Streaming data: ${payload.progress} / ${payload.total} complete`;
                            updateSummary();
                        } catch (e) { console.error('Parse err:', e); }
                    } else if (eventType === 'error') {
                        try {
                            const payload = JSON.parse(eventData);
                            const pct = (payload.progress / payload.total * 100).toFixed(0);
                            els.progressFill.style.width = pct + '%';
                            els.progressText.textContent = `Error on IP: ${payload.error}`;
                        } catch (e) {}
                    } else if (eventType === 'done') {
                        els.progressText.textContent = `Analysis sequence complete.`;
                        els.progressFill.style.width = '100%';
                    }
                    eventType = ''; eventData = '';
                }
            }
        }
    } catch (err) {
        console.error('Analysis error:', err);
        els.progressText.textContent = `Fatal Error: ${err.message}`;
    } finally {
        state.analyzing = false;
        els.btnAnalyze.classList.remove('loading');
        els.btnAnalyze.disabled = false;
        setTimeout(() => els.progressContainer.classList.remove('active'), 2500);

        // Final Sort & Render Stagger
        state.reports.sort((a, b) => b.risk.score - a.risk.score);
        els.resultsContainer.innerHTML = '';
        state.reports.forEach((r, i) => els.resultsContainer.appendChild(renderCard(r, i)));
        updateSummary();

        if (state.reports.length === 0) {
            els.emptyState.style.display = 'flex';
            els.resultsContainer.appendChild(els.emptyState);
        }
    }
}

// ── Exports ──────────────────────────────────────────────────────────────────
function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportJSON() { downloadFile(JSON.stringify(state.reports, null, 2), 'ip_intel_report.json', 'application/json'); }
function exportHTML() { downloadFile(document.documentElement.outerHTML, 'ip_intel_report.html', 'text/html'); }
function exportCSV() {
    const h = ['IP', 'Score', 'Class', 'ASN', 'Org', 'Country', 'VT_Mal', 'Abuse_Score', 'Ports', 'GreyNoise', 'OTX_Pulses'];
    const r = state.reports.map(r => [
        r.ip, r.risk.score, r.risk.classification, r.ownership?.asn||'', r.ownership?.org||'', r.ownership?.country||'',
        r.virustotal?.malicious||0, r.abuseipdb?.abuse_confidence_score||0, (r.shodan?.open_ports||[]).join(';'),
        r.greynoise?.classification||'', r.alienvault?.pulse_count||0
    ]);
    const csv = [h.join(','), ...r.map(row => row.map(c => `"${c}"`).join(','))].join('\n');
    downloadFile(csv, 'ip_intel_report.csv', 'text/csv');
}

function exportPDF() {
    if (!state.reports.length) return;
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(18);
    doc.setTextColor(30, 30, 30);
    doc.text('IP Intelligence Report', 14, 22);
    doc.setFontSize(9);
    doc.setTextColor(120);
    doc.text(`Generated: ${new Date().toISOString()}  |  Total: ${state.reports.length} IP(s)`, 14, 30);
    let y = 40;
    state.reports.forEach((r, i) => {
        if (y > 260) { doc.addPage(); y = 20; }
        doc.setFontSize(11); doc.setTextColor(0);
        doc.text(`${i+1}. ${r.ip}  —  Score: ${r.risk.score} (${r.risk.classification})`, 14, y); y += 6;
        doc.setFontSize(8); doc.setTextColor(80);
        doc.text(`ASN: ${r.ownership?.asn||'-'}  |  Org: ${r.ownership?.org||'-'}  |  Country: ${r.ownership?.country||'-'}`, 18, y); y += 5;
        doc.text(`VT Malicious: ${r.virustotal?.malicious||0}  |  Abuse Score: ${r.abuseipdb?.abuse_confidence_score||0}%  |  Ports: ${(r.shodan?.open_ports||[]).join(',')||'none'}`, 18, y); y += 5;
        doc.text(`GreyNoise: ${r.greynoise?.classification||'-'}  |  OTX Pulses: ${r.alienvault?.pulse_count||0}`, 18, y); y += 4;
        if (r.risk.signals && r.risk.signals.length) {
            r.risk.signals.forEach(s => {
                if (y > 270) { doc.addPage(); y = 20; }
                doc.text(`  [${s.weight>=0?'+':''}${s.weight}] ${s.name}: ${s.reason}`, 20, y); y += 4;
            });
        }
        y += 4;
    });
    doc.save('ip_intel_report.pdf');
}

// ── Threat Map (Leaflet.js) ─────────────────────────────────────────────
let threatMap = null;
let mapMarkers = [];

function initMap() {
    if (threatMap) return;
    threatMap = L.map('threat-map', { zoomControl: true, attributionControl: false }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18,
    }).addTo(threatMap);
}

function plotIPOnMap(report) {
    if (!threatMap) initMap();
    // Use a free IP geolocation API to get lat/lng
    const ip = report.ip;
    fetch(`https://ipapi.co/${ip}/json/`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (!data || !data.latitude) return;
            const cls = report.risk.classification;
            const color = cls === 'Malicious' ? '#ef4444' : cls === 'Likely Malicious' ? '#f97316' : cls === 'Suspicious' ? '#eab308' : '#22c55e';
            const marker = L.circleMarker([data.latitude, data.longitude], {
                radius: 8, fillColor: color, color: '#fff', weight: 1, opacity: 0.9, fillOpacity: 0.8,
            }).addTo(threatMap);
            marker.bindPopup(`<b>${ip}</b><br>Score: ${report.risk.score}<br>${cls}<br>${data.city || ''}, ${data.country_name || ''}`);
            mapMarkers.push(marker);
            $('#map-section').classList.add('visible');
        }).catch(() => {});
}

function clearMap() {
    if (!threatMap) return;
    mapMarkers.forEach(m => threatMap.removeLayer(m));
    mapMarkers = [];
    $('#map-section').classList.remove('visible');
}

// ── CIDR Expansion ───────────────────────────────────────────────────
function expandCIDR(cidr) {
    const [base, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    if (isNaN(mask) || mask < 24 || mask > 32) return []; // Only allow /24-/32
    const parts = base.split('.').map(Number);
    const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    const hostBits = 32 - mask;
    const count = Math.pow(2, hostBits);
    const network = ipNum & (~0 << hostBits);
    const ips = [];
    for (let i = 1; i < count - 1 && ips.length < 100; i++) {
        const ip = network + i;
        ips.push(`${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`);
    }
    return ips;
}

// ── Listeners ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadKeys();
    initMap();

    els.btnSettings.addEventListener('click', () => els.settingsModal.classList.add('open'));
    els.btnCloseSettings.addEventListener('click', () => els.settingsModal.classList.remove('open'));
    els.btnSaveSettings.addEventListener('click', () => { els.settingsModal.classList.remove('open'); saveKeys(); });
    els.settingsModal.addEventListener('click', (e) => { if (e.target === els.settingsModal) els.settingsModal.classList.remove('open'); });

    $$('.key-toggle-vis').forEach(btn => {
        btn.addEventListener('click', () => {
            const i = $(`#${btn.dataset.target}`);
            i.type = i.type === 'password' ? 'text' : 'password';
            btn.textContent = i.type === 'password' ? '👁' : '🙈';
        });
    });

    [els.keyVt, els.keyAbuse, els.keyShodan, els.keyGreynoise, els.keyAlienvault].forEach(i => i.addEventListener('input', saveKeys));
    els.ipInput.addEventListener('input', handleIPInputChange);

    els.btnUpload.addEventListener('click', () => els.fileUpload.click());
    els.fileUpload.addEventListener('change', (e) => {
        const file = e.target.files[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
            els.ipInput.value = els.ipInput.value.trim() === '' ? event.target.result : els.ipInput.value + '\n' + event.target.result;
            handleIPInputChange();
        };
        reader.readAsText(file);
        els.fileUpload.value = '';
    });

    els.btnAnalyze.addEventListener('click', analyze);
    els.ipInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); if (!els.btnAnalyze.disabled) analyze(); }
    });

    $('#btn-export-json').addEventListener('click', exportJSON);
    $('#btn-export-csv').addEventListener('click', exportCSV);
    $('#btn-export-html').addEventListener('click', exportHTML);
    $('#btn-export-pdf').addEventListener('click', exportPDF);
});
