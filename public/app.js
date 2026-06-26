/**
 * IP Intelligence — Modern Web Interface JS
 * Includes numeric counter animations, staggered entrances, and fluid SSE processing.
 */

// ── State ────────────────────────────────────────────────────────────────────
const state = {
    reports: [],
    analyzing: false,
    activeTagFilter: null,
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
    // Phase 3 additions
    historyDrawer: $('#history-drawer'),
    drawerOverlay: $('#drawer-overlay'),
    btnHistory: $('#btn-history'),
    btnCloseHistory: $('#btn-close-history'),
    historySearch: $('#history-search'),
    historyList: $('#history-list'),
    campaignBar: $('#campaign-bar'),
    campaignTagsList: $('#campaign-tags-list'),
    reportSearch: $('#report-search'),
    filterClassification: $('#filter-classification'),
    filterStatusChip: $('#filter-status-chip'),
    filterChipText: $('#filter-chip-text'),
    btnClearFilter: $('#btn-clear-filter'),
    rateLimitToasts: $('#rate-limit-toasts'),
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

    $('#status-vt').textContent = vt ? 'Active' : 'Inactive';
    $('#status-vt').style.color = vt ? 'var(--green)' : 'var(--text-muted)';
    $('#status-abuse').textContent = abuse ? 'Active' : 'Inactive';
    $('#status-abuse').style.color = abuse ? 'var(--green)' : 'var(--text-muted)';
    $('#status-shodan').textContent = shodan ? 'Shodan API Active' : 'Using Free InternetDB';
    $('#status-shodan').style.color = shodan ? 'var(--green)' : 'var(--accent)';
    $('#status-greynoise').textContent = gn ? 'Full API Active' : 'Using Free Community API';
    $('#status-greynoise').style.color = gn ? 'var(--green)' : 'var(--accent)';
    $('#status-alienvault').textContent = otx ? 'OTX API Active' : 'Using Free OTX API';
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
    const map = { 'Benign': 'benign', 'Suspicious': 'suspicious', 'Likely Malicious': 'likely-mal', 'Malicious': 'malicious', 'Insufficient Data': 'insufficient' };
    return map[cls] || 'benign';
}

function infraLabel(type) {
    const map = { 'shared_cloud': '☁ Cloud', 'cdn': '🌐 CDN', 'residential': '🏠 Residential', 'vps': '🖥 VPS', 'enterprise': '🏢 Enterprise', 'unknown': '❓ Unknown' };
    return map[type] || type;
}

function generateSummary(r) {
    const cls = r.risk.classification;
    const score = r.risk.score;
    const own = r.ownership || {};
    const vt = r.virustotal || {};
    const abuse = r.abuseipdb || {};
    const shodan = r.shodan || {};
    const gn = r.greynoise || {};
    const otx = r.alienvault || {};

    const parts = [];

    // Opening line
    const orgStr = own.org ? ` owned by ${own.org}` : '';
    const countryStr = own.country ? ` (${own.country})` : '';
    parts.push(`This IP${orgStr}${countryStr} has a risk score of <strong>${score}</strong> and is classified as <strong style="color:${cls==='Malicious'?'#f87171':cls==='Likely Malicious'?'#fb923c':cls==='Suspicious'?'#fbbf24':'#34d399'}">${cls}</strong>.`);

    // VirusTotal
    if (vt.available) {
        if (vt.malicious > 0) parts.push(`<strong>${vt.malicious}</strong> security vendor(s) on VirusTotal flag this IP as malicious.`);
        else parts.push('No malicious telemetry reported on VirusTotal.');
    }

    // AbuseIPDB
    if (abuse.available) {
        if (abuse.total_reports > 0) parts.push(`AbuseIPDB shows <strong>${abuse.total_reports}</strong> abuse report(s) with a <strong>${abuse.abuse_confidence_score}%</strong> confidence score.`);
        else parts.push('No abuse reports found on AbuseIPDB.');
    }

    // Shodan
    if (shodan.available) {
        const ports = shodan.open_ports || [];
        const vulns = shodan.vulns || [];
        if (ports.length > 0) {
            parts.push(`Shodan detected <strong>${ports.length}</strong> open port(s): ${ports.slice(0,5).join(', ')}${ports.length > 5 ? '...' : ''}.`);
        }
        if (vulns.length > 0) {
            parts.push(`<strong>${vulns.length}</strong> known CVE(s) detected: ${vulns.slice(0,3).join(', ')}${vulns.length > 3 ? '...' : ''}.`);
        }
    }

    // GreyNoise
    if (gn.available) {
        if (gn.riot) parts.push(`GreyNoise identifies this IP as a highly trusted <strong style="color:#34d399">known-good service</strong> (RIOT)${gn.name ? ` — ${gn.name}` : ''}.`);
        else if (gn.seen && gn.classification === 'malicious') parts.push(`GreyNoise reports active <strong style="color:#f87171">malicious scanning</strong> from this IP.`);
        else if (gn.seen) parts.push(`GreyNoise has observed this IP generating background noise (${gn.classification || 'unknown'}).`);
    }

    // AlienVault OTX
    if (otx.available) {
        const curated = (otx.pulses || []).filter(p => !p.is_auto_generated).length;
        if (curated > 0) {
            parts.push(`Referenced in <strong style="color:#fbbf24">${curated}</strong> curated community threat campaign(s)${otx.adversary ? ` discussing <strong style="color:#f87171">${escHtml(otx.adversary)}</strong>` : ''}.`);
        } else if (otx.pulse_count > 0) {
            parts.push(`Referenced in automated/bulk OTX pulse feeds.`);
        }
    }

    return parts.join(' ');
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
    const sanctions = r.sanctions || {};
    const sslInfo = r.ssl || {};
    const cveDetails = r.cve_details || [];
    const countryRisk = r.country_risk || {};

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
        const catOrder = ['direct_malicious', 'contextual', 'reputation', 'infrastructure'];
        const catLabels = { direct_malicious: '🚨 Direct Malicious Evidence', contextual: '🔍 Contextual Intelligence', reputation: '⭐ Reputation Signals', infrastructure: '🏢 Infrastructure' };
        const grouped = {};
        r.risk.signals.forEach(s => {
            const cat = s.category || 'contextual';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(s);
        });
        const rows = catOrder.filter(c => grouped[c]).map(cat => {
            const label = catLabels[cat] || cat;
            return `<tr class="signal-category-header"><td colspan="3" style="font-size:0.75rem;text-transform:uppercase;color:var(--accent);padding:0.75rem 0.5rem 0.25rem;border:none;font-weight:700;">${label}</td></tr>` +
                grouped[cat].map(s => `
                    <tr>
                        <td class="weight ${s.weight >= 0 ? 'weight-positive' : 'weight-negative'}">${s.weight >= 0 ? '+' : ''}${s.weight}</td>
                        <td style="font-weight:600;">${escHtml(s.name)}</td>
                        <td style="color:var(--text-muted)">${escHtml(s.reason)}</td>
                    </tr>
                `).join('');
        }).join('');
        signalsHtml = `
        <div class="signals-section">
            <h4 style="font-size:0.85rem;text-transform:uppercase;color:var(--text-bright);margin-bottom:0.75rem;padding-bottom:0.5rem;">Evidence Breakdown</h4>
            <table class="signals-table">
                <thead><tr><th>Weight</th><th>Signal</th><th>Context</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
    }

    let conflictsHtml = '';
    if (r.risk.conflicts && r.risk.conflicts.length > 0) {
        conflictsHtml = `
        <div class="conflicts-section" style="margin:1rem 1.5rem;background:rgba(251, 191, 36, 0.1);border-left:4px solid #fbbf24;padding:1rem;border-radius:var(--radius-sm);">
            <div style="color:#fbbf24;font-weight:700;margin-bottom:0.5rem;display:flex;align-items:center;gap:0.5rem;">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                Contradictory Intelligence Detected
            </div>
            ${r.risk.conflicts.map(c => `<div style="font-size:0.85rem;color:var(--text-bright); margin-bottom: 0.25rem;"><strong>${c.severity.toUpperCase()}:</strong> ${escHtml(c.explanation)}</div>`).join('')}
        </div>`;
    }

    let reasoningHtml = '';
    if (r.risk.reasoning_chain && r.risk.reasoning_chain.length > 0) {
        reasoningHtml = `
        <div class="reasoning-section" style="margin:1.5rem;padding:1rem;background:rgba(0,0,0,0.2);border-radius:var(--radius-sm);border:1px solid rgba(255,255,255,0.05);">
            <h4 style="font-size:0.85rem;text-transform:uppercase;color:var(--text-bright);margin-bottom:0.75rem;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:0.5rem;">Why? (Analyst Reasoning)</h4>
            <ul style="list-style-type:none;padding:0;margin:0;display:flex;flex-direction:column;gap:0.6rem;">
                ${r.risk.reasoning_chain.map(reason => `
                    <li style="display:flex;gap:0.5rem;align-items:flex-start;font-size:0.85rem;color:var(--text-bright);line-height:1.4;">
                        <svg style="flex-shrink:0;color:var(--accent);margin-top:0.15rem;" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                        <span>${escHtml(reason)}</span>
                    </li>
                `).join('')}
            </ul>
        </div>`;
    }

    const card = document.createElement('div');
    card.className = 'glass-panel ip-card';
    // Stagger animation based on index
    card.style.animationDelay = `${(index % 10) * 0.1}s`;
    
    const domainsList = (vt.historic_domains || []).map(d => escHtml(d)).join(', ');
    const vulnsList = (shodan.vulns || []).map(v => escHtml(v)).join(', ');
    const hostnamesList = (shodan.hostnames || []).map(h => escHtml(h)).join(', ');

    const attribConf = r.risk.attribution_confidence != null ? r.risk.attribution_confidence : 100;
    const infraType = r.risk.infrastructure_type || 'unknown';
    const dataComp = r.risk.data_completeness != null ? r.risk.data_completeness : 100;
    const threatScore = r.risk.threat_activity_score != null ? r.risk.threat_activity_score : score;

    card.innerHTML = `
        <div class="ip-card-header" onclick="toggleCard(this)">
            <div class="ip-card-left">
                <span class="ip-card-ip">${escHtml(r.ip)}</span>
                <div class="ip-card-tags">
                    ${own.country && own.country.toLowerCase() !== 'unknown' ? `<span class="tag tag-country">${escHtml(own.country)}</span>` : ''}
                    ${countryRisk.risk_tier && countryRisk.risk_tier !== 'minimal' && countryRisk.risk_tier !== 'unknown' ? `<span class="tag tag-risk-${countryRisk.risk_tier}">${countryRisk.risk_tier === 'critical' ? '🔴' : countryRisk.risk_tier === 'high' ? '🟠' : '🟡'} ${escHtml(countryRisk.risk_tier).toUpperCase()} RISK</span>` : ''}
                    ${own.asn ? `<span class="tag tag-asn">AS${escHtml(own.asn)}</span>` : ''}
                    ${own.org && own.org.toLowerCase() !== 'unknown' ? `<span class="tag tag-org">${escHtml(own.org)}</span>` : ''}
                    ${infraType && infraType !== 'unknown' ? `<span class="tag tag-infra">${infraLabel(infraType)}</span>` : ''}
                    ${sanctions.is_sanctioned ? `<span class="tag tag-sanctioned">⚠️ SANCTIONED</span>` : ''}
                </div>
                ${r.campaign_tags && r.campaign_tags.length > 0 ? `
                    <div class="ip-header-tags">
                        ${r.campaign_tags.slice(0, 8).map(tag => `<span class="tag-badge" onclick="event.stopPropagation(); filterByTag('${escHtml(tag)}')" title="Filter by ${escHtml(tag)}">${escHtml(tag)}</span>`).join('')}
                    </div>
                ` : ''}
            </div>
            <div class="ip-card-right">
                <div class="score-badge">
                    <span class="classification-label ${cls}">${r.risk.classification}</span>
                    <span class="score-circle ${cls}">${score}</span>
                </div>
                <div style="display:flex;flex-direction:column;align-items:center;gap:0.15rem;margin-left:0.75rem;">
                    <span style="font-size:0.6rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;">Attrib</span>
                    <span style="font-size:0.85rem;font-weight:700;font-family:var(--mono);color:${attribConf >= 90 ? '#34d399' : attribConf >= 70 ? '#fbbf24' : '#f87171'};">${attribConf}%</span>
                </div>
                <span class="expand-chevron">▼</span>
            </div>
        </div>
        <div class="ip-card-details">
            ${sanctions.is_sanctioned ? `
            <div class="sanctions-alert">
                <div class="sanctions-alert-icon">⚠️</div>
                <div class="sanctions-alert-body">
                    <div class="sanctions-alert-title">OFAC SDN — Sanctioned Entity Match</div>
                    <div class="sanctions-alert-detail">Matched: <strong>${escHtml(sanctions.matched_entity)}</strong> (${(sanctions.match_score * 100).toFixed(0)}% confidence) — ${escHtml(sanctions.sanctions_program)}</div>
                </div>
            </div>` : ''}
            <div class="ip-summary-banner">
                <div class="summary-icon">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                </div>
                <div class="summary-text">${generateSummary(r)}</div>
            </div>
            <div class="details-grid">
                <div class="detail-section">
                    <h4>Network Identity ${helpTip('Basic ownership info from WHOIS/RDAP — shows the ASN, organization, CIDR block, and country that owns this IP address.')}</h4>
                    <div class="detail-row"><span class="key">ASN</span><span class="val">${escHtml(own.asn || '—')}</span></div>
                    <div class="detail-row"><span class="key">Organization</span><span class="val">${escHtml(own.org || '—')}</span></div>
                    <div class="detail-row"><span class="key">CIDR Range</span><span class="val">${escHtml(own.cidr || '—')}</span></div>
                    <div class="detail-row"><span class="key">Country</span><span class="val">${escHtml(own.country || '—')}</span></div>
                    <div class="detail-row"><span class="key">Registry</span><span class="val">${escHtml(own.rir || '—')}</span></div>
                    <div class="detail-row"><span class="key">PTR Record</span><span class="val">${escHtml(dns.ptr || '—')}</span></div>
                    ${dns.fcrdns_valid != null ? `<div class="detail-row"><span class="key">FCrDNS</span><span class="val" style="color:${dns.fcrdns_valid ? '#34d399' : '#f87171'}">${dns.fcrdns_valid ? '✅ PASS' : '❌ FAIL'}</span></div>` : ''}
                    ${countryRisk.risk_tier && countryRisk.risk_tier !== 'unknown' ? `<div class="detail-row"><span class="key">Country Risk</span><span class="val tag-risk-inline tag-risk-${countryRisk.risk_tier}">${escHtml(countryRisk.risk_label || countryRisk.risk_tier)}</span></div>` : ''}
                    <div class="geo-inject" style="border-top:1px dashed rgba(255,255,255,0.06);margin-top:0.6rem;padding-top:0.6rem;">
                        <div class="detail-row" style="opacity:0.4;"><span class="key">Coordinates</span><span class="val" style="font-style:italic;">Loading…</span></div>
                    </div>
                </div>

                <div class="detail-section">
                    <h4>VirusTotal Telemetry ${helpTip('Aggregated scan results from 70+ antivirus engines. "Malicious Flags" means how many vendors flagged this IP as dangerous. Higher = worse.')}</h4>
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
                    <h4>Passive DNS Timeline ${helpTip('Chronological history of domain resolutions to this IP address (from VirusTotal). Helps identify C2 domains or domain reuse.')}</h4>
                    ${vt.available && vt.passive_dns && vt.passive_dns.length > 0 ? `
                        <div class="pdns-timeline">
                            ${vt.passive_dns.slice(0, 15).map((entry, idx) => `
                                <div class="pdns-entry ${idx < 3 ? 'recent' : ''}">
                                    <span class="pdns-date">${escHtml(entry.resolved_date || 'Unknown Date')}</span>
                                    <span class="pdns-domain">${escHtml(entry.hostname)}</span>
                                </div>
                            `).join('')}
                        </div>
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">No passive DNS timeline data available</div>`}
                </div>

                <div class="detail-section">
                    <h4>AbuseIPDB Reports ${helpTip('Community-sourced abuse reports. "Confidence Score" (0-100%) reflects how likely this IP is involved in attacks. Reports come from sysadmins worldwide.')}</h4>
                    ${abuse.available ? `
                        <div class="detail-row"><span class="key">Confidence Score</span><span class="val" style="color:${abuse.abuse_confidence_score > 70 ? '#f87171' : abuse.abuse_confidence_score > 40 ? '#fbbf24' : '#34d399'}">${abuse.abuse_confidence_score}%</span></div>
                        <div class="detail-row"><span class="key">Total Reports</span><span class="val">${abuse.total_reports}</span></div>
                        <div class="detail-row"><span class="key">Whitelisted</span><span class="val">${abuse.is_whitelisted ? '✅ Yes' : 'No'}</span></div>
                        <div class="detail-row"><span class="key">ISP / Hosting</span><span class="val">${escHtml(abuse.isp || '—')}</span></div>
                        <div class="detail-row"><span class="key">Usage Type</span><span class="val">${escHtml(abuse.usage_type || '—')}</span></div>
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">Telemetry unavailable (No API Key)</div>`}
                </div>

                <div class="detail-section">
                    <h4>Shodan Surface ${helpTip('Attack surface analysis showing open ports, running services, and known CVE vulnerabilities. Exposed ports and unpatched CVEs significantly increase risk.')}</h4>
                    ${shodan.available ? `
                        <div class="detail-row"><span class="key">Open Ports</span><span class="val">${shodan.open_ports && shodan.open_ports.length ? shodan.open_ports.join(', ') : '<span style="color:var(--text-muted)">Clean</span>'}</span></div>
                        ${hostnamesList ? `<div class="detail-row"><span class="key">Hostnames</span><span class="val">${hostnamesList}</span></div>` : ''}
                        ${vulnsList ? `<div style="margin-top:0.8rem;"><div class="key" style="color:#f87171;margin-bottom:0.2rem;">CVE Vulnerabilities</div><div class="vuln-list">${vulnsList}</div></div>` : ''}
                        ${servicesHtml}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">Scanner unreachable</div>`}
                </div>

                <div class="detail-section">
                    <h4>GreyNoise Context ${helpTip('Identifies mass internet scanners and known-good services. "RIOT" means the IP belongs to a trusted service (e.g. Google, Cloudflare). "Internet Noise" means it\'s scanning the entire internet.')}</h4>
                    ${gn.available ? `
                        <div class="detail-row"><span class="key">Classification</span><span class="val" style="color:${gn.classification==='malicious'?'#f87171':gn.classification==='benign'?'#34d399':'var(--text-bright)'}">${escHtml(gn.classification || 'unknown')}</span></div>
                        <div class="detail-row"><span class="key">Internet Noise</span><span class="val">${gn.seen ? 'Yes — Mass Scanner' : 'No'}</span></div>
                        <div class="detail-row"><span class="key">RIOT (Known Good)</span><span class="val" style="color:${gn.riot?'#34d399':'var(--text-bright)'}">${gn.riot ? '✅ Yes' : 'No'}</span></div>
                        ${gn.name ? `<div class="detail-row"><span class="key">Actor / Name</span><span class="val">${escHtml(gn.name)}</span></div>` : ''}
                        ${gn.tags && gn.tags.length ? `<div class="detail-row"><span class="key">Tags</span><span class="val">${gn.tags.map(t=>escHtml(t)).join(', ')}</span></div>` : ''}
                        ${gn.cve && gn.cve.length ? `<div class="detail-row"><span class="key">CVEs Exploited</span><span class="val" style="color:#f87171">${gn.cve.join(', ')}</span></div>` : ''}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">GreyNoise data unavailable</div>`}
                </div>

                <div class="detail-section">
                    <h4>AlienVault OTX ${helpTip('Open Threat Exchange pulse data. "Threat Pulses" are community-reported threat campaigns. Associated adversary groups and malware samples indicate active threat actor involvement.')}</h4>
                    ${otx.available ? `
                        <div class="detail-row"><span class="key">Threat Pulses</span><span class="val" style="color:${otx.pulse_count>3?'#f87171':otx.pulse_count>0?'#fbbf24':'#34d399'}">${otx.pulse_count}</span></div>
                        <div class="detail-row"><span class="key">Malware Samples</span><span class="val" style="color:${otx.malware_count>0?'#f87171':'var(--text-bright)'}">${otx.malware_count}</span></div>
                        ${otx.adversary ? `<div class="detail-row"><span class="key">Threat Group</span><span class="val" style="color:#f87171;font-weight:700">${escHtml(otx.adversary)}</span></div>` : ''}
                        ${otx.pulse_names && otx.pulse_names.length ? `<div style="margin-top:0.8rem;"><div class="key" style="margin-bottom:0.2rem;">Threat Campaigns</div><div class="domain-list">${otx.pulse_names.map(p=>escHtml(p)).join(', ')}</div></div>` : ''}
                    ` : `<div style="color:var(--text-muted);font-size:0.85rem;font-style:italic;">OTX data unavailable</div>`}
                </div>

                ${sslInfo.has_ssl ? `
                <div class="detail-section">
                    <h4>🔒 SSL/TLS Certificate ${helpTip('TLS certificate details from port 443. Expired or self-signed certificates are strong indicators of malicious infrastructure.')}</h4>
                    <div class="detail-row"><span class="key">Issuer</span><span class="val">${escHtml(sslInfo.issuer || '—')}</span></div>
                    <div class="detail-row"><span class="key">Subject</span><span class="val">${escHtml(sslInfo.subject || '—')}</span></div>
                    <div class="detail-row"><span class="key">Valid From</span><span class="val">${escHtml(sslInfo.not_before || '—')}</span></div>
                    <div class="detail-row"><span class="key">Valid Until</span><span class="val" style="color:${sslInfo.is_expired ? '#f87171' : 'var(--text-bright)'}">${escHtml(sslInfo.not_after || '—')} ${sslInfo.is_expired ? '⚠️ EXPIRED' : ''}</span></div>
                    ${sslInfo.is_self_signed ? `<div class="detail-row"><span class="key">Self-Signed</span><span class="val" style="color:#f87171">⚠️ Yes — No trusted CA</span></div>` : ''}
                    <div class="detail-row"><span class="key">Key Size</span><span class="val">${sslInfo.key_size || '—'} bits</span></div>
                    <div class="detail-row"><span class="key">Algorithm</span><span class="val">${escHtml(sslInfo.signature_algorithm || '—')}</span></div>
                    ${sslInfo.sans && sslInfo.sans.length ? `<div style="margin-top:0.8rem;"><div class="key" style="margin-bottom:0.2rem;">Subject Alt Names (${sslInfo.sans.length})</div><div class="domain-list">${sslInfo.sans.map(s => escHtml(s)).join(', ')}</div></div>` : ''}
                </div>` : ''}

                ${cveDetails.length ? `
                <div class="detail-section">
                    <h4>🛡️ CVE Intelligence (${cveDetails.length}) ${helpTip('Enriched vulnerability details from the National Vulnerability Database (NVD). Shows CVSS scores, severity, and descriptions for CVEs found on this host.')}</h4>
                    ${cveDetails.map(cve => `
                        <div class="cve-card cve-${cve.severity.toLowerCase()}">
                            <div class="cve-header">
                                <span class="cve-id">${escHtml(cve.cve_id)}</span>
                                <span class="cve-badge cve-badge-${cve.severity.toLowerCase()}">${cve.cvss_score.toFixed(1)} ${escHtml(cve.severity)}</span>
                            </div>
                            ${cve.description ? `<div class="cve-desc">${escHtml(cve.description)}</div>` : ''}
                            ${cve.affected_products && cve.affected_products.length ? `<div class="cve-products">${cve.affected_products.map(p => `<span class="cve-product-tag">${escHtml(p)}</span>`).join('')}</div>` : ''}
                        </div>
                    `).join('')}
                </div>` : ''}

                ${dns.a_records && dns.a_records.length || dns.mx_records && dns.mx_records.length || dns.txt_records && dns.txt_records.length ? `
                <div class="detail-section">
                    <h4>📡 Full DNS Records ${helpTip('Complete DNS record enumeration for the PTR hostname. Includes A, AAAA, MX, NS, and TXT records. FCrDNS (Forward-Confirmed Reverse DNS) validates IP ownership.')}</h4>
                    ${dns.a_records && dns.a_records.length ? `<div class="detail-row"><span class="key">A Records</span><span class="val">${dns.a_records.map(r => escHtml(r)).join(', ')}</span></div>` : ''}
                    ${dns.aaaa_records && dns.aaaa_records.length ? `<div class="detail-row"><span class="key">AAAA Records</span><span class="val">${dns.aaaa_records.map(r => escHtml(r)).join(', ')}</span></div>` : ''}
                    ${dns.mx_records && dns.mx_records.length ? `<div class="detail-row"><span class="key">MX Records</span><span class="val">${dns.mx_records.map(r => escHtml(r)).join(', ')}</span></div>` : ''}
                    ${dns.ns_records && dns.ns_records.length ? `<div class="detail-row"><span class="key">NS Records</span><span class="val">${dns.ns_records.map(r => escHtml(r)).join(', ')}</span></div>` : ''}
                    ${dns.txt_records && dns.txt_records.length ? `<div style="margin-top:0.8rem;"><div class="key" style="margin-bottom:0.2rem;">TXT Records</div><div class="domain-list" style="font-size:0.75rem;">${dns.txt_records.map(r => escHtml(r)).join('<br>')}</div></div>` : ''}
                </div>` : ''}

                <div class="detail-section" style="grid-column: 1 / -1;">
                    <h4>Feed Intelligence Confidence ${helpTip('Visual representation of the reliability weight assigned to each intelligence source. Higher confidence sources have more impact on the final score.')}</h4>
                    <div class="confidence-bars" style="display:flex; flex-direction:column; gap:0.6rem; margin-top:0.5rem; background:rgba(0,0,0,0.2); padding:1rem; border-radius:var(--radius-sm); border:1px solid rgba(255,255,255,0.05);">
                        ${[
                            {name: "GreyNoise", conf: 95, color: "#34d399", val: gn.available},
                            {name: "VirusTotal", conf: 85, color: "#60a5fa", val: vt.available},
                            {name: "AbuseIPDB", conf: 75, color: "#fbbf24", val: abuse.available},
                            {name: "Shodan", conf: 60, color: "#a78bfa", val: shodan.available},
                            {name: "OTX (Curated)", conf: 55, color: "#f87171", val: otx.available},
                            {name: "OTX (Automated)", conf: 15, color: "#9ca3af", val: otx.available}
                        ].map(f => `
                            <div style="display:flex; align-items:center; gap:1rem; font-size:0.8rem; font-family:var(--mono);">
                                <div style="width:130px; color:${f.val ? 'var(--text-bright)' : 'var(--text-muted)'}">${f.name}</div>
                                <div style="flex:1; background:rgba(255,255,255,0.05); height:8px; border-radius:4px; overflow:hidden; position:relative;">
                                    <div style="position:absolute; left:0; top:0; height:100%; width:${f.conf}%; background:${f.val ? f.color : 'rgba(255,255,255,0.1)'}; opacity:${f.val ? '1' : '0.3'};"></div>
                                </div>
                                <div style="width:40px; text-align:right; color:${f.val ? 'var(--text-bright)' : 'var(--text-muted)'}">${f.conf}%</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
            ${conflictsHtml}
            ${reasoningHtml}
            ${signalsHtml}
        </div>
    `;
    return card;
}

window.toggleCard = function(headerEl) {
    const card = headerEl.closest('.ip-card');
    card.classList.toggle('expanded');
};

// ── Filtering, Campaigns, and History (Phase 3) ──────────────────────────────

// Global helper to filter the current reports set
function getFilteredReports() {
    let list = state.reports;

    // 1. Filter by campaign tag pill
    if (state.activeTagFilter) {
        const tagLower = state.activeTagFilter.toLowerCase();
        list = list.filter(r => (r.campaign_tags || []).some(t => t.toLowerCase() === tagLower));
    }

    // 2. Filter by classification dropdown
    const classVal = els.filterClassification.value;
    if (classVal !== 'all') {
        list = list.filter(r => r.risk.classification.toLowerCase() === classVal.toLowerCase());
    }

    // 3. Filter by search query
    const searchVal = els.reportSearch.value.trim().toLowerCase();
    if (searchVal) {
        list = list.filter(r => {
            const ip = r.ip.toLowerCase();
            const org = (r.ownership?.org || '').toLowerCase();
            const asn = String(r.ownership?.asn || '').toLowerCase();
            const country = (r.ownership?.country || '').toLowerCase();
            const registry = (r.ownership?.rir || '').toLowerCase();
            return ip.includes(searchVal) || org.includes(searchVal) || asn.includes(searchVal) || country.includes(searchVal) || registry.includes(searchVal);
        });
    }

    return list;
}

// Re-render only matching report cards and update stats count
function applyFilters() {
    const filtered = getFilteredReports();
    els.resultsContainer.innerHTML = '';

    if (filtered.length === 0) {
        els.resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                </div>
                <h3>No Matching Reports</h3>
                <p>Try refining your search text or removing the selected filters.</p>
            </div>
        `;
    } else {
        filtered.forEach((r, i) => {
            els.resultsContainer.appendChild(renderCard(r, i));
        });
    }

    // Update stats cards to match filtered subset
    updateCounterEl('#stat-total', filtered.length);
    updateCounterEl('#stat-benign', filtered.filter(r => r.risk.classification === 'Benign').length);
    updateCounterEl('#stat-suspicious', filtered.filter(r => r.risk.classification === 'Suspicious').length);
    updateCounterEl('#stat-likely-mal', filtered.filter(r => r.risk.classification === 'Likely Malicious').length);
    updateCounterEl('#stat-malicious', filtered.filter(r => r.risk.classification === 'Malicious').length);
}

// Aggregate and display campaign tags from reports
function updateCampaignBar() {
    const counts = {};
    state.reports.forEach(r => {
        (r.campaign_tags || []).forEach(t => {
            counts[t] = (counts[t] || 0) + 1;
        });
    });

    const tags = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);

    if (tags.length === 0) {
        els.campaignBar.style.display = 'none';
        return;
    }

    els.campaignBar.style.display = 'flex';
    els.campaignTagsList.innerHTML = tags.map(tag => {
        const activeClass = state.activeTagFilter === tag ? 'active' : '';
        return `<span class="campaign-tag ${activeClass}" onclick="filterByTag('${escHtml(tag)}')">${escHtml(tag)} <span style="opacity:0.6;font-size:0.7rem;">(${counts[tag]})</span></span>`;
    }).join('');
}

// Set active tag filter
window.filterByTag = function(tag) {
    if (state.activeTagFilter === tag) {
        // Toggle off if clicked again
        clearActiveFilter();
        return;
    }
    state.activeTagFilter = tag;
    els.filterChipText.textContent = `Tag: ${tag}`;
    els.filterStatusChip.style.display = 'flex';
    updateCampaignBar();
    applyFilters();
};

// Clear active tag filter
window.clearActiveFilter = function() {
    state.activeTagFilter = null;
    els.filterStatusChip.style.display = 'none';
    updateCampaignBar();
    applyFilters();
};

// Rate Limit countdown toast manager
const activeToasts = {};

function showRateLimitToast(provider, waitSeconds) {
    const key = provider.toLowerCase().replace(/\s+/g, '');
    let toast = activeToasts[key];

    if (toast) {
        toast.waitSeconds = Math.max(toast.waitSeconds, waitSeconds);
        const countdownEl = toast.el.querySelector('.rate-toast-countdown');
        if (countdownEl) countdownEl.textContent = `${Math.ceil(toast.waitSeconds)}s`;
        return;
    }

    // Create new toast element
    const toastEl = document.createElement('div');
    toastEl.className = 'rate-limit-toast';
    toastEl.innerHTML = `
        <span class="rate-toast-icon">⏳</span>
        <div class="rate-toast-content">
            <div class="rate-toast-title">Rate Limit Active</div>
            <div class="rate-toast-msg">Queued request for ${escHtml(provider)}</div>
        </div>
        <div class="rate-toast-countdown">${Math.ceil(waitSeconds)}s</div>
    `;

    els.rateLimitToasts.appendChild(toastEl);

    toast = {
        el: toastEl,
        waitSeconds: waitSeconds,
        interval: setInterval(() => {
            toast.waitSeconds -= 1;
            if (toast.waitSeconds <= 0) {
                clearInterval(toast.interval);
                toastEl.classList.add('fade-out');
                setTimeout(() => {
                    toastEl.remove();
                    delete activeToasts[key];
                }, 400);
            } else {
                const countEl = toastEl.querySelector('.rate-toast-countdown');
                if (countEl) countEl.textContent = `${Math.ceil(toast.waitSeconds)}s`;
            }
        }, 1000)
    };

    activeToasts[key] = toast;
}

// ── Scan History Log ─────────────────────────────────────────────────────────

function getHistory() {
    try {
        return JSON.parse(localStorage.getItem('ip_intel_history') || '[]');
    } catch (e) {
        return [];
    }
}

function saveToHistory(newReports) {
    if (!newReports || newReports.length === 0) return;
    let history = getHistory();

    newReports.forEach(r => {
        // Remove existing cached scan for the same IP
        history = history.filter(item => item.ip !== r.ip);
        // Prepend new scan record
        history.unshift({
            ip: r.ip,
            classification: r.risk.classification,
            score: r.risk.score,
            asn: r.ownership?.asn || '',
            org: r.ownership?.org || '',
            country: r.ownership?.country || '',
            timestamp: new Date().toISOString(),
            report: r
        });
    });

    // Cap at 100 records
    if (history.length > 100) {
        history = history.slice(0, 100);
    }

    localStorage.setItem('ip_intel_history', JSON.stringify(history));
    renderHistoryList();
}

function renderHistoryList() {
    const history = getHistory();
    const searchVal = els.historySearch.value.trim().toLowerCase();

    const filtered = history.filter(item => {
        return item.ip.toLowerCase().includes(searchVal) ||
               (item.org || '').toLowerCase().includes(searchVal) ||
               (item.country || '').toLowerCase().includes(searchVal);
    });

    if (filtered.length === 0) {
        els.historyList.innerHTML = `<div class="empty-history">No matching scans found.</div>`;
        return;
    }

    els.historyList.innerHTML = filtered.map(item => {
        const cls = classLabel(item.classification);
        const date = new Date(item.timestamp).toLocaleDateString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
        return `
            <div class="history-item" onclick="loadHistoryItem('${escHtml(item.ip)}')">
                <div class="history-item-header">
                    <span class="history-item-ip">${escHtml(item.ip)}</span>
                    <span class="history-item-score ${cls}">${item.score}</span>
                </div>
                <div class="history-item-meta">
                    <span>${escHtml(item.org || 'Unknown Org')} (${escHtml(item.country || '??')})</span>
                    <span>${date}</span>
                </div>
            </div>
        `;
    }).join('');
}

window.loadHistoryItem = function(ip) {
    const history = getHistory();
    const match = history.find(item => item.ip === ip);
    if (!match) return;

    // Load matching report into current active state
    state.reports = [match.report];
    state.activeTagFilter = null;
    els.filterStatusChip.style.display = 'none';

    // Populate IP input box and update layout
    els.ipInput.value = ip;
    handleIPInputChange();

    // Hide drawer
    els.historyDrawer.classList.remove('open');
    els.drawerOverlay.classList.remove('open');

    // Render & display
    els.emptyState.style.display = 'none';
    applyFilters();
    updateCampaignBar();
    clearMap();
    plotIPOnMap(match.report);

    els.summaryBar.classList.add('visible');
    els.controlsHeader.classList.add('visible');
};

// ── Summary Update ───────────────────────────────────────────────────────────
function updateSummary() {
    // Basic wrapper to call the filter-aware counters
    applyFilters();

    if (state.reports.length > 0) {
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
    state.activeTagFilter = null;
    els.filterStatusChip.style.display = 'none';
    state.analyzing = true;
    
    els.btnAnalyze.classList.add('loading');
    els.btnAnalyze.disabled = true;
    els.emptyState.style.display = 'none';
    els.resultsContainer.innerHTML = '';
    clearMap();
    
    els.summaryBar.classList.remove('visible');
    els.controlsHeader.classList.remove('visible');
    els.campaignBar.style.display = 'none';
    
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
                            
                            // Re-calculate campaigns and summary dynamically
                            updateCampaignBar();
                            updateSummary();
                        } catch (e) { console.error('Parse err:', e); }
                    } else if (eventType === 'rate_limit') {
                        try {
                            const payload = JSON.parse(eventData);
                            showRateLimitToast(payload.provider, payload.wait_seconds);
                        } catch (e) { console.error('Rate limit parse err:', e); }
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

        // Save active scans to local history cache
        saveToHistory(state.reports);

        // Final Sort & Render Stagger
        state.reports.sort((a, b) => b.risk.score - a.risk.score);
        
        // Re-render everything in sorted order
        els.resultsContainer.innerHTML = '';
        clearMap();
        state.reports.forEach((r, i) => {
            els.resultsContainer.appendChild(renderCard(r, i));
            plotIPOnMap(r);
        });

        updateCampaignBar();
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

function exportJSON() {
    if (!state.reports.length) return;
    const clean = state.reports.map(r => ({
        ip: r.ip,
        risk: { score: r.risk.score, classification: r.risk.classification, signals: r.risk.signals },
        ownership: r.ownership || {},
        virustotal: r.virustotal || {},
        abuseipdb: r.abuseipdb || {},
        shodan: r.shodan || {},
        greynoise: r.greynoise || {},
        alienvault: r.alienvault || {},
        dns: r.dns || {},
    }));
    downloadFile(JSON.stringify(clean, null, 2), `ip_intel_report_${new Date().toISOString().slice(0,10)}.json`, 'application/json');
}

function exportCSV() {
    if (!state.reports.length) return;
    const headers = ['IP','Risk Score','Classification','ASN','Organization','Country','VT Malicious','VT Suspicious','Abuse Confidence','Abuse Reports','Open Ports','Vulnerabilities','GreyNoise Class','GreyNoise Noise','OTX Pulses','OTX Malware','Signals'];
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = state.reports.map(r => [
        r.ip,
        r.risk.score,
        r.risk.classification,
        r.ownership?.asn || '',
        r.ownership?.org || '',
        r.ownership?.country || '',
        r.virustotal?.malicious ?? '',
        r.virustotal?.suspicious ?? '',
        r.abuseipdb?.abuse_confidence_score ?? '',
        r.abuseipdb?.total_reports ?? '',
        (r.shodan?.open_ports || []).join('; '),
        (r.shodan?.vulns || []).join('; '),
        r.greynoise?.classification || '',
        r.greynoise?.seen ? 'Yes' : 'No',
        r.alienvault?.pulse_count ?? '',
        r.alienvault?.malware_count ?? '',
        (r.risk.signals || []).map(s => `[${s.weight>=0?'+':''}${s.weight}] ${s.name}`).join(' | ')
    ].map(esc).join(','));
    downloadFile([headers.map(esc).join(','), ...rows].join('\n'), `ip_intel_report_${new Date().toISOString().slice(0,10)}.csv`, 'text/csv;charset=utf-8');
}

function exportHTML() {
    if (!state.reports.length) return;
    const ts = new Date().toLocaleString();
    let cards = '';
    state.reports.forEach(r => {
        const cls = r.risk.classification;
        const clsColor = cls === 'Malicious' ? '#ef4444' : cls === 'Likely Malicious' ? '#f97316' : cls === 'Suspicious' ? '#eab308' : '#22c55e';
        const signals = (r.risk.signals || []).map(s =>
            `<tr><td style="padding:4px 8px;color:${s.weight>=0?'#ef4444':'#22c55e'};font-weight:700;">${s.weight>=0?'+':''}${s.weight}</td><td style="padding:4px 8px;">${s.name}</td><td style="padding:4px 8px;color:#94a3b8;">${s.reason}</td></tr>`
        ).join('');
        cards += `
        <div style="background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <span style="font-family:monospace;font-size:1.15rem;font-weight:700;">${r.ip}</span>
                <span style="background:${clsColor}22;color:${clsColor};padding:4px 12px;border-radius:20px;font-weight:700;font-size:0.85rem;">${r.risk.score} — ${cls}</span>
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:0.85rem;margin-bottom:8px;">
                <tr><td style="color:#6b7280;padding:3px 0;">ASN</td><td>${r.ownership?.asn||'—'}</td><td style="color:#6b7280;">Org</td><td>${r.ownership?.org||'—'}</td><td style="color:#6b7280;">Country</td><td>${r.ownership?.country||'—'}</td></tr>
                <tr><td style="color:#6b7280;padding:3px 0;">VT Malicious</td><td style="color:${(r.virustotal?.malicious||0)>0?'#ef4444':'inherit'}">${r.virustotal?.malicious??'—'}</td><td style="color:#6b7280;">Abuse Score</td><td style="color:${(r.abuseipdb?.abuse_confidence_score||0)>50?'#ef4444':'inherit'}">${r.abuseipdb?.abuse_confidence_score??'—'}%</td><td style="color:#6b7280;">Ports</td><td>${(r.shodan?.open_ports||[]).join(', ')||'none'}</td></tr>
                <tr><td style="color:#6b7280;padding:3px 0;">GreyNoise</td><td>${r.greynoise?.classification||'—'}</td><td style="color:#6b7280;">RIOT</td><td>${r.greynoise?.riot?'✅ Yes':'No'}</td><td style="color:#6b7280;">OTX Pulses</td><td style="color:${(r.alienvault?.pulse_count||0)>0?'#eab308':'inherit'}">${r.alienvault?.pulse_count??'—'}</td></tr>
            </table>
            ${signals ? `<details style="margin-top:8px;"><summary style="cursor:pointer;color:#60a5fa;font-size:0.8rem;">Risk Signals (${r.risk.signals.length})</summary><table style="width:100%;font-size:0.8rem;margin-top:6px;">${signals}</table></details>` : ''}
        </div>`;
    });
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>IP Intelligence Report</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#050505;color:#f8fafc;padding:40px;max-width:1000px;margin:0 auto;line-height:1.6;}h1{font-size:1.75rem;margin-bottom:4px;}p.meta{color:#6b7280;font-size:0.85rem;margin-bottom:24px;}table td{vertical-align:top;}</style>
</head><body>
<h1>IP Intelligence Report</h1>
<p class="meta">Generated: ${ts} • ${state.reports.length} IP(s) analyzed</p>
${cards}
<p style="text-align:center;color:#4b5563;font-size:0.75rem;margin-top:32px;">Powered by IP Intel Engine</p>
</body></html>`;
    downloadFile(html, `ip_intel_report_${new Date().toISOString().slice(0,10)}.html`, 'text/html;charset=utf-8');
}

function exportPDF() {
    if (!state.reports.length) return;
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const pw = doc.internal.pageSize.getWidth();

    // Title
    doc.setFontSize(20); doc.setTextColor(30, 30, 30);
    doc.text('IP Intelligence Report', 14, 22);
    doc.setFontSize(9); doc.setTextColor(120);
    doc.text(`Generated: ${new Date().toLocaleString()}  |  Total: ${state.reports.length} IP(s)`, 14, 30);
    doc.setDrawColor(200); doc.line(14, 33, pw - 14, 33);

    let y = 40;
    state.reports.forEach((r, i) => {
        // Check page break
        if (y > 250) { doc.addPage(); y = 20; }

        // IP header with colored score
        doc.setFontSize(12); doc.setTextColor(0);
        doc.text(`${r.ip}`, 14, y);
        const cls = r.risk.classification;
        if (cls === 'Malicious') doc.setTextColor(220, 38, 38);
        else if (cls === 'Likely Malicious') doc.setTextColor(234, 88, 12);
        else if (cls === 'Suspicious') doc.setTextColor(202, 138, 4);
        else doc.setTextColor(22, 163, 74);
        doc.text(`Score: ${r.risk.score}  (${cls})`, pw - 14, y, { align: 'right' });
        y += 2;
        doc.setDrawColor(230); doc.line(14, y, pw - 14, y); y += 5;

        // Details grid
        doc.setFontSize(8); doc.setTextColor(100);
        const details = [
            [`ASN: ${r.ownership?.asn||'-'}`, `Org: ${r.ownership?.org||'-'}`, `Country: ${r.ownership?.country||'-'}`],
            [`VT Malicious: ${r.virustotal?.malicious??'-'}`, `Abuse Score: ${r.abuseipdb?.abuse_confidence_score??'-'}%`, `Ports: ${(r.shodan?.open_ports||[]).join(',')||'none'}`],
            [`GreyNoise: ${r.greynoise?.classification||'-'}`, `RIOT: ${r.greynoise?.riot?'Yes':'No'}`, `OTX Pulses: ${r.alienvault?.pulse_count??'-'}`],
        ];
        details.forEach(row => {
            if (y > 275) { doc.addPage(); y = 20; }
            doc.text(row.join('   |   '), 18, y); y += 4;
        });

        // Signals
        if (r.risk.signals && r.risk.signals.length) {
            y += 1;
            doc.setFontSize(7); doc.setTextColor(130);
            doc.text('Risk Signals:', 18, y); y += 3.5;
            r.risk.signals.forEach(s => {
                if (y > 275) { doc.addPage(); y = 20; }
                const prefix = s.weight >= 0 ? '+' : '';
                doc.setTextColor(s.weight >= 0 ? 200 : 34, s.weight >= 0 ? 60 : 150, s.weight >= 0 ? 60 : 100);
                doc.text(`[${prefix}${s.weight}]`, 20, y);
                doc.setTextColor(80);
                doc.text(`${s.name}: ${s.reason}`, 34, y);
                y += 3.5;
            });
        }
        y += 6;
    });

    doc.save(`ip_intel_report_${new Date().toISOString().slice(0,10)}.pdf`);
}

// ── Threat Map (MapLibre GL) — Enhanced ────────────────────────────────────
let threatMap = null;
let geojsonSource = {
    type: 'FeatureCollection',
    features: []
};
let mapCountries = new Set();
let activePopup = null;

function initMap() {
    if (threatMap) return;
    
    threatMap = new maplibregl.Map({
        container: 'threat-map',
        style: 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',
        center: [0, 20],
        zoom: 2,
        attributionControl: false
    });

    threatMap.addControl(new maplibregl.NavigationControl(), 'top-left');

    threatMap.on('load', () => {
        // Add a clustered GeoJSON source
        threatMap.addSource('threat-ips', {
            type: 'geojson',
            data: geojsonSource,
            cluster: true,
            clusterMaxZoom: 14,
            clusterRadius: 50 // Radius of each cluster
        });

        // Layer 1: Cluster circles
        threatMap.addLayer({
            id: 'clusters',
            type: 'circle',
            source: 'threat-ips',
            filter: ['has', 'point_count'],
            paint: {
                'circle-color': [
                    'step',
                    ['get', 'point_count'],
                    '#3b82f6', // blue for < 5
                    5,
                    '#8b5cf6', // purple for < 15
                    15,
                    '#ef4444'  // red for >= 15
                ],
                'circle-radius': [
                    'step',
                    ['get', 'point_count'],
                    15, // size for < 5
                    5,
                    20, // size for < 15
                    15,
                    25  // size for >= 15
                ],
                'circle-opacity': 0.8,
                'circle-stroke-width': 2,
                'circle-stroke-color': '#ffffff'
            }
        });

        // Layer 2: Cluster counts
        threatMap.addLayer({
            id: 'cluster-count',
            type: 'symbol',
            source: 'threat-ips',
            filter: ['has', 'point_count'],
            layout: {
                'text-field': '{point_count_abbreviated}',
                'text-font': ['Open Sans Bold', 'Arial Unicode MS Bold'],
                'text-size': 12
            },
            paint: {
                'text-color': '#ffffff'
            }
        });

        // Layer 3: Unclustered points
        threatMap.addLayer({
            id: 'unclustered-point',
            type: 'circle',
            source: 'threat-ips',
            filter: ['!', ['has', 'point_count']],
            paint: {
                'circle-color': [
                    'match',
                    ['get', 'risk_level'],
                    'Malicious', '#ef4444',
                    'Likely Malicious', '#f97316',
                    'Suspicious', '#eab308',
                    /* other */ '#22c55e'
                ],
                'circle-radius': [
                    'match',
                    ['get', 'risk_level'],
                    'Malicious', 8,
                    'Likely Malicious', 7,
                    /* other */ 6
                ],
                'circle-stroke-width': 1.5,
                'circle-stroke-color': '#ffffff'
            }
        });

        // Interaction: Click cluster to zoom in
        threatMap.on('click', 'clusters', (e) => {
            const features = threatMap.queryRenderedFeatures(e.point, { layers: ['clusters'] });
            const clusterId = features[0].properties.cluster_id;
            threatMap.getSource('threat-ips').getClusterExpansionZoom(clusterId, (err, zoom) => {
                if (err) return;
                threatMap.flyTo({
                    center: features[0].geometry.coordinates,
                    zoom: zoom
                });
            });
        });

        // Interaction: Click unclustered point to show popup
        threatMap.on('click', 'unclustered-point', (e) => {
            const coordinates = e.features[0].geometry.coordinates.slice();
            const props = e.features[0].properties;

            // Ensure coordinates wrap correctly around the anti-meridian
            while (Math.abs(e.lngLat.lng - coordinates[0]) > 180) {
                coordinates[0] += e.lngLat.lng > coordinates[0] ? 360 : -360;
            }

            if (activePopup) activePopup.remove();

            activePopup = new maplibregl.Popup({ closeOnClick: true, maxWidth: '340px' })
                .setLngLat(coordinates)
                .setHTML(props.popupHtml)
                .addTo(threatMap);
        });

        // Cursor change on hover
        threatMap.on('mouseenter', 'clusters', () => { threatMap.getCanvas().style.cursor = 'pointer'; });
        threatMap.on('mouseleave', 'clusters', () => { threatMap.getCanvas().style.cursor = ''; });
        threatMap.on('mouseenter', 'unclustered-point', () => { threatMap.getCanvas().style.cursor = 'pointer'; });
        threatMap.on('mouseleave', 'unclustered-point', () => { threatMap.getCanvas().style.cursor = ''; });
    });
}

function getScoreBg(cls) {
    if (cls === 'Malicious') return 'background:rgba(239,68,68,0.2); color:#f87171;';
    if (cls === 'Likely Malicious') return 'background:rgba(249,115,22,0.2); color:#fb923c;';
    if (cls === 'Suspicious') return 'background:rgba(234,179,8,0.2); color:#fbbf24;';
    return 'background:rgba(34,197,94,0.2); color:#34d399;';
}

function buildPopupContent(report, geoData) {
    const cls = report.risk.classification;
    const score = report.risk.score;
    const own = report.ownership || {};
    const shodan = report.shodan || {};
    const ports = (shodan.open_ports || []).slice(0, 6);
    const vulns = (shodan.vulns || []).slice(0, 4);
    const tags = (report.campaign_tags || []).slice(0, 5);

    let tagsHtml = '';
    if (ports.length || vulns.length || tags.length) {
        const portPills = ports.map(p => `<span class="map-popup-tag port">${p}</span>`).join('');
        const vulnPills = vulns.map(v => `<span class="map-popup-tag vuln">${escHtml(v)}</span>`).join('');
        const tagPills = tags.map(t => `<span class="map-popup-tag campaign">${escHtml(t)}</span>`).join('');
        tagsHtml = `<div class="map-popup-tags">${portPills}${vulnPills}${tagPills}</div>`;
    }

    return `
        <div class="map-popup">
            <div class="map-popup-header">
                <span class="map-popup-ip">${escHtml(report.ip)}</span>
            </div>
            <div class="map-popup-body">
                <div class="map-popup-row">
                    <span class="map-popup-key">Location</span>
                    <span class="map-popup-val">${escHtml(geoData.city || '—')}, ${escHtml(geoData.region || '')} ${escHtml(geoData.country_name || '')}</span>
                </div>
                <div class="map-popup-row">
                    <span class="map-popup-key">Coordinates</span>
                    <span class="map-popup-val">${geoData.latitude.toFixed(4)}, ${geoData.longitude.toFixed(4)}</span>
                </div>
                <div class="map-popup-row">
                    <span class="map-popup-key">ASN / Org</span>
                    <span class="map-popup-val">${escHtml(own.asn ? `AS${own.asn}` : '—')} — ${escHtml(own.org || '—')}</span>
                </div>
                <div class="map-popup-row">
                    <span class="map-popup-key">Network</span>
                    <span class="map-popup-val">${escHtml(own.cidr || geoData.network || '—')}</span>
                </div>
                <div class="map-popup-row">
                    <span class="map-popup-key">ISP</span>
                    <span class="map-popup-val">${escHtml(geoData.org || '—')}</span>
                </div>
                <div class="map-popup-row">
                    <span class="map-popup-key">Open Ports</span>
                    <span class="map-popup-val">${ports.length ? ports.join(', ') : 'None detected'}</span>
                </div>
            </div>
            ${tagsHtml}
        </div>
    `;
}

function updateMapStats() {
    const plotted = geojsonSource.features.length;
    const malCount = geojsonSource.features.filter(f => f.properties.is_malicious).length;
    const countries = mapCountries.size;

    const pEl = $('#map-stat-plotted');
    const mEl = $('#map-stat-malicious');
    const cEl = $('#map-stat-countries');
    if (pEl) pEl.textContent = plotted;
    if (mEl) mEl.textContent = malCount;
    if (cEl) cEl.textContent = countries;
}

function plotIPOnMap(report) {
    if (!threatMap) initMap();
    const ip = report.ip;
    const cls = report.risk.classification;
    const isMalicious = cls === 'Malicious' || cls === 'Likely Malicious';

    fetch(`https://ipapi.co/${ip}/json/`)
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (!data || !data.latitude) return;

            if (data.country_name) mapCountries.add(data.country_name);

            const popupContent = buildPopupContent(report, data);

            // Add point to GeoJSON source
            const feature = {
                type: 'Feature',
                geometry: {
                    type: 'Point',
                    coordinates: [data.longitude, data.latitude] // Note: GeoJSON is [lng, lat]
                },
                properties: {
                    ip: ip,
                    risk_level: cls,
                    is_malicious: isMalicious,
                    popupHtml: popupContent
                }
            };
            
            geojsonSource.features.push(feature);

            // Update map source if it's loaded
            if (threatMap && threatMap.getSource('threat-ips')) {
                threatMap.getSource('threat-ips').setData(geojsonSource);
                
                // Fly to the newly plotted coordinate
                threatMap.flyTo({
                    center: [data.longitude, data.latitude],
                    zoom: threatMap.getZoom() < 4 ? 4 : threatMap.getZoom(),
                    essential: true,
                    speed: 1.5
                });
            }

            updateMapStats();
            $('#map-section').classList.add('visible');

            // Inject geolocation data into the matching report card
            const cards = document.querySelectorAll('.ip-card');
            for (const card of cards) {
                const ipEl = card.querySelector('.ip-card-ip');
                if (ipEl && ipEl.textContent.trim() === ip) {
                    const geoSlot = card.querySelector('.geo-inject');
                    if (geoSlot) {
                        geoSlot.innerHTML = `
                            <div class="detail-row"><span class="key">City</span><span class="val">${escHtml(data.city || '—')}, ${escHtml(data.region || '')}</span></div>
                            <div class="detail-row"><span class="key">Coordinates</span><span class="val" style="font-family:var(--mono);font-size:0.8rem;">${data.latitude.toFixed(4)}, ${data.longitude.toFixed(4)}</span></div>
                            <div class="detail-row"><span class="key">ISP</span><span class="val">${escHtml(data.org || '—')}</span></div>
                            <div class="detail-row"><span class="key">Timezone</span><span class="val">${escHtml(data.timezone || '—')}</span></div>
                        `;
                    }
                    break;
                }
            }
        }).catch(() => {});
}

function clearMap() {
    geojsonSource.features = [];
    if (threatMap && threatMap.getSource('threat-ips')) {
        threatMap.getSource('threat-ips').setData(geojsonSource);
    }
    if (activePopup) activePopup.remove();
    mapCountries.clear();
    updateMapStats();
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
    renderHistoryList();

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

    // Phase 3 additions event bindings
    if (els.btnHistory) {
        els.btnHistory.addEventListener('click', () => {
            renderHistoryList();
            els.historyDrawer.classList.add('open');
            els.drawerOverlay.classList.add('open');
        });
    }

    if (els.btnCloseHistory) {
        els.btnCloseHistory.addEventListener('click', () => {
            els.historyDrawer.classList.remove('open');
            els.drawerOverlay.classList.remove('open');
        });
    }

    if (els.drawerOverlay) {
        els.drawerOverlay.addEventListener('click', () => {
            els.historyDrawer.classList.remove('open');
            els.drawerOverlay.classList.remove('open');
        });
    }

    if (els.historySearch) {
        els.historySearch.addEventListener('input', renderHistoryList);
    }

    if (els.reportSearch) {
        els.reportSearch.addEventListener('input', applyFilters);
    }

    if (els.filterClassification) {
        els.filterClassification.addEventListener('change', applyFilters);
    }

    if (els.btnClearFilter) {
        els.btnClearFilter.addEventListener('click', clearActiveFilter);
    }

    // ── Keyboard Shortcuts ───────────────────────────────────────────────
    document.addEventListener('keydown', (e) => {
        // Don't intercept when typing in inputs/textareas
        const tag = document.activeElement?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
            if (e.key === 'Escape') {
                document.activeElement.blur();
            }
            return;
        }

        switch (e.key) {
            case '/':
                e.preventDefault();
                const searchEl = els.reportSearch || $('#ip-input');
                if (searchEl) searchEl.focus();
                break;
            case 'Escape':
                // Close any open modals/drawers
                els.settingsModal?.classList.remove('open');
                els.historyDrawer?.classList.remove('open');
                els.drawerOverlay?.classList.remove('open');
                const helpOverlay = $('#shortcut-help-overlay');
                if (helpOverlay) helpOverlay.style.display = 'none';
                // Collapse expanded cards
                document.querySelectorAll('.ip-card.expanded').forEach(c => c.classList.remove('expanded'));
                break;
            case 'm':
            case 'M':
                e.preventDefault();
                const mapSection = $('#map-section');
                if (mapSection) mapSection.scrollIntoView({ behavior: 'smooth' });
                break;
            case '?':
                e.preventDefault();
                toggleShortcutHelp();
                break;
        }
    });
});

// ── Keyboard Shortcut Help ───────────────────────────────────────────────
function toggleShortcutHelp() {
    let overlay = $('#shortcut-help-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'shortcut-help-overlay';
        overlay.className = 'shortcut-help-overlay';
        overlay.innerHTML = `
            <div class="shortcut-help-panel glass-panel">
                <div class="shortcut-help-header">
                    <h3>⌨️ Keyboard Shortcuts</h3>
                    <button class="modal-close" onclick="document.getElementById('shortcut-help-overlay').style.display='none'">&times;</button>
                </div>
                <div class="shortcut-help-body">
                    <div class="shortcut-row"><kbd>/</kbd><span>Focus search box</span></div>
                    <div class="shortcut-row"><kbd>Esc</kbd><span>Close modals / collapse cards</span></div>
                    <div class="shortcut-row"><kbd>M</kbd><span>Scroll to threat map</span></div>
                    <div class="shortcut-row"><kbd>?</kbd><span>Toggle this help</span></div>
                    <div class="shortcut-row"><kbd>Ctrl+Enter</kbd><span>Run analysis (when in IP input)</span></div>
                </div>
            </div>
        `;
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.style.display = 'none';
        });
        document.body.appendChild(overlay);
    }
    overlay.style.display = overlay.style.display === 'flex' ? 'none' : 'flex';
}
