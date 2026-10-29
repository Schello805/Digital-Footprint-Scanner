// Global State
let currentTab = 'fullscan';
let fullScanProfiles = [];
let usernameEventSource = null;
let currentResults = [];
let leafletMap = null;
let leafletMarker = null;
let currentSelectedFile = null;

// --- Tab Navigation ---
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
  const targetPane = document.getElementById(`tab-content-${tabId}`);
  if (targetPane) targetPane.classList.remove('hidden');

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('bg-indigo-600', 'text-white', 'shadow-md');
    btn.classList.add('text-slate-400', 'hover:text-slate-200');
  });

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.remove('text-slate-400', 'hover:text-slate-200');
    activeBtn.classList.add('bg-indigo-600', 'text-white', 'shadow-md');
  }

  if (tabId === 'exif' && leafletMap) {
    setTimeout(() => leafletMap.invalidateSize(), 200);
  }
}

// ==================== 0. AUTOMATISIERTER 1-KLICK VOLLSCAN ====================
async function runFullScan(e) {
  e.preventDefault();

  const payload = {
    name: document.getElementById('fsName').value.trim(),
    username: document.getElementById('fsUsername').value.trim(),
    email: document.getElementById('fsEmail').value.trim(),
    password: document.getElementById('fsPassword').value,
    city: document.getElementById('fsCity').value.trim(),
    employer: document.getElementById('fsEmployer').value.trim(),
    phone: document.getElementById('fsPhone').value.trim(),
    domain: document.getElementById('fsDomain').value.trim()
  };

  if (!payload.name && !payload.username && !payload.email && !payload.phone && !payload.domain) {
    alert('Bitte gib mindestens einen Namen, Benutzernamen, eine E-Mail oder Domain an.');
    return;
  }

  const btn = document.getElementById('fsSubmitBtn');
  const btnText = document.getElementById('fsBtnText');
  const spinner = document.getElementById('fsSpinner');
  const progressBox = document.getElementById('fsProgressContainer');
  const progressBar = document.getElementById('fsProgressBar');
  const progressStep = document.getElementById('fsProgressStep');
  const reportBox = document.getElementById('fullReportContainer');

  btn.disabled = true;
  spinner.classList.remove('hidden');
  btnText.textContent = 'Scanne gesamte Präsenz...';
  progressBox.classList.remove('hidden');
  reportBox.classList.add('hidden');

  progressBar.style.width = '30%';
  progressStep.textContent = '1/3: Prüfe k-Anonymity Hashes & Identitätsvektoren...';

  const t1 = setTimeout(() => {
    progressBar.style.width = '65%';
    progressStep.textContent = '2/3: Durchsuche 40+ Social-Media & Tech-Plattformen...';
  }, 900);

  const t2 = setTimeout(() => {
    progressBar.style.width = '88%';
    progressStep.textContent = '3/3: Analysiere Domain-Security & erstelle DIN A4 Dossier...';
  }, 1900);

  try {
    const res = await fetch('/api/scan/full', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const json = await res.json();

    clearTimeout(t1);
    clearTimeout(t2);

    if (json.success) {
      progressBar.style.width = '100%';
      progressStep.textContent = '✓ Vollscan abgeschlossen! DIN A4 Steckbrief erstellt.';
      setTimeout(() => progressBox.classList.add('hidden'), 800);
      renderFullReport(json, payload);
    } else {
      alert('Fehler: ' + (json.error || 'Vollscan fehlgeschlagen'));
    }
  } catch (err) {
    clearTimeout(t1);
    clearTimeout(t2);
    alert('Fehler beim Vollscan: ' + err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add('hidden');
    btnText.textContent = '🚀 Vollscan starten (Alles prüfen)';
  }
}

function renderFullReport(res, payload) {
  const data = res;
  const s = data.summary;
  fullScanProfiles = data.found_profiles || [];

  const reportContainer = document.getElementById('fullReportContainer');
  reportContainer.classList.remove('hidden');

  // Set Timestamp & Dossier Az
  const now = new Date();
  document.getElementById('dossierTimestamp').textContent = `Erstellt am: ${now.toLocaleDateString('de-DE')} um ${now.toLocaleTimeString('de-DE')} Uhr`;
  const randNum = Math.floor(1000 + Math.random() * 9000);
  document.getElementById('dossierAktenzeichen').textContent = `AKTENZEICHEN: AZ-OSINT-2026-${randNum}`;

  // 1. Steckbrief-Kopf
  const targetName = payload.name || payload.username || 'UNBEKANNTE ZIELPERSON';
  document.getElementById('sbTargetNameTop').textContent = targetName;
  document.getElementById('sbTargetAliasTop').textContent = payload.username ? `@${payload.username}` : (payload.name ? `Namensabfrage: ${payload.name}` : '-');

  // Stammdaten-Tabelle
  document.getElementById('sbName').textContent = payload.name || '-';
  document.getElementById('sbCity').textContent = payload.city || '-';
  document.getElementById('sbEmployer').textContent = payload.employer || '-';
  document.getElementById('sbEmail').textContent = payload.email || '-';
  
  if (data.phone_result) {
    document.getElementById('sbPhone').textContent = `${data.phone_result.raw} (${data.phone_result.type} - ${data.phone_result.region_or_carrier})`;
  } else {
    document.getElementById('sbPhone').textContent = payload.phone || '-';
  }
  document.getElementById('sbDomain').textContent = payload.domain || '-';

  // Exposure Stamp
  document.getElementById('sbExposureVal').textContent = `${s.exposure_score}%`;
  document.getElementById('sbExposureLevel').textContent = `RISIKO: ${s.exposure_level}`;
  
  const stamp = document.getElementById('sbDossierStamp');
  if (s.exposure_score >= 70) {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-rose-500 text-rose-500';
  } else if (s.exposure_score >= 35) {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-amber-500 text-amber-500';
  } else {
    stamp.className = 'dossier-stamp p-3 rounded-lg text-center border-emerald-500 text-emerald-500';
  }

  // 2. Sicherheitsstatus (Section 1)
  const pwdStatus = document.getElementById('sbPwdStatus');
  const pwdDetail = document.getElementById('sbPwdDetail');
  if (s.password_pwned === true) {
    pwdStatus.innerHTML = `<span class="text-rose-400">⚠️ ${s.password_breach_count.toLocaleString()}x GELEAKT!</span>`;
    pwdDetail.textContent = 'Passwort ist öffentlich kompromittiert!';
  } else if (s.password_pwned === false) {
    pwdStatus.innerHTML = `<span class="text-emerald-400">✓ Sicher (Kein Leak)</span>`;
    pwdDetail.textContent = 'In 800M+ Datensätzen sauber';
  } else {
    pwdStatus.textContent = 'Nicht getestet';
    pwdDetail.textContent = 'Kein Passwort übermittelt';
  }

  const emailStatus = document.getElementById('sbEmailStatus');
  const emailDetail = document.getElementById('sbEmailDetail');
  if (data.email_result) {
    if (data.email_result.breached) {
      emailStatus.innerHTML = `<span class="text-rose-400">⚠️ In ${data.email_result.breach_count} Datenlecks</span>`;
      const names = (data.email_result.breach_names || []).slice(0, 3).join(', ');
      emailDetail.textContent = names ? `${names}... (${data.email_result.source.split(' ')[0]})` : 'Betroffen von Sicherheitsvorfällen';
    } else {
      emailStatus.innerHTML = `<span class="text-emerald-400">✓ Keine direkten Leaks</span>`;
      emailDetail.textContent = `Geprüft via ${data.email_result.source.split(' ')[0]}`;
    }
  } else {
    emailStatus.textContent = payload.email ? 'Geprüft' : 'Keine E-Mail angegeben';
    emailDetail.textContent = payload.email ? 'k-Anonymity / OSINT' : '-';
  }

  const domStatus = document.getElementById('sbDomainStatus');
  const domDetail = document.getElementById('sbDomainDetail');
  if (data.domain_result) {
    const spf = data.domain_result.email_security.spf.status;
    const dmarc = data.domain_result.email_security.dmarc.status;
    if (spf === 'secure' && dmarc === 'secure') {
      domStatus.innerHTML = `<span class="text-emerald-400">✓ Gesichert</span>`;
      domDetail.textContent = 'Strikter SPF- und DMARC-Schutz';
    } else {
      domStatus.innerHTML = `<span class="text-amber-400">⚠️ Schwachstelle (${spf})</span>`;
      domDetail.textContent = data.domain_result.email_security.dmarc.assessment;
    }
  } else {
    domStatus.textContent = 'Keine Domain';
    domDetail.textContent = 'Nicht analysiert';
  }

  // 3. Entdeckte Profile Tabelle (Section 2)
  document.getElementById('sbProfilesCountText').textContent = `${fullScanProfiles.length} gefundene Accounts (${s.high_confidence_matches} verifiziert)`;
  const tbody = document.getElementById('sbProfilesTableBody');
  tbody.innerHTML = '';

  if (fullScanProfiles.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500">Keine Accounts unter diesem Benutzernamen identifiziert (oder kein Benutzername angegeben).</td></tr>`;
  } else {
    fullScanProfiles.forEach(p => {
      const isHigh = p.match && (p.match.confidence === 'high' || p.match.confidence === 'medium');
      let matchBadge = '<span class="text-slate-500">⚪ Namensvetter</span>';
      if (p.match && p.match.confidence === 'high') {
        matchBadge = `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-800">🟢 ${p.match.score}% MATCH</span>`;
      } else if (p.match && p.match.confidence === 'medium') {
        matchBadge = `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-yellow-950 text-yellow-400 border border-yellow-800">🟡 ${p.match.score}% Treffer</span>`;
      }

      const noteText = p.snippet ? `"${p.snippet}"` : (p.match && p.match.matches ? p.match.matches.join(', ') : '-');

      const tr = document.createElement('tr');
      tr.className = isHigh ? 'bg-indigo-950/20' : '';
      tr.innerHTML = `
        <td class="py-2 px-3 font-bold text-white">${p.platform}</td>
        <td class="py-2 px-3 text-slate-400">${p.category}</td>
        <td class="py-2 px-3">${matchBadge}</td>
        <td class="py-2 px-3 text-slate-300 italic max-w-xs truncate">${noteText}</td>
        <td class="py-2 px-3 text-right">
          <a href="${p.url}" target="_blank" class="text-cyan-400 hover:underline">Profil ↗</a>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 4. Bedrohungsvektoren (Section 3)
  const threatsBox = document.getElementById('sbThreatsContainer');
  threatsBox.innerHTML = '';
  const threats = data.identity_audit.threat_vectors || [];
  if (threats.length === 0) {
    threatsBox.innerHTML = '<p class="text-slate-400">Keine direkten Identitätskonflikte oder kritischen Risikoverknüpfungen festgestellt.</p>';
  } else {
    threats.forEach(tv => {
      const div = document.createElement('div');
      div.className = 'p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-3';
      div.innerHTML = `
        <div>
          <span class="font-bold text-white block text-xs">${tv.title}</span>
          <span class="text-slate-400 text-[11px] leading-relaxed block mt-0.5">${tv.desc}</span>
        </div>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-400 border border-rose-800 shrink-0">${tv.severity}</span>
      `;
      threatsBox.appendChild(div);
    });
  }

  // 5. Phone & Permutations (Section 4)
  const phoneBox = document.getElementById('sbPhoneReconBox');
  if (data.phone_result) {
    const pr = data.phone_result;
    phoneBox.innerHTML = `
      <div class="mb-1 text-white font-mono font-bold">${pr.raw} &rarr; ${pr.type} (${pr.region_or_carrier})</div>
      <div class="flex flex-wrap gap-1.5 pt-1">
        ${pr.lookup_links.map(l => `<a href="${l.url}" target="_blank" class="text-[10px] text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 hover:underline">${l.name} ↗</a>`).join('')}
      </div>
    `;
  } else {
    phoneBox.textContent = 'Keine Rufnummer zur Analyse angegeben.';
  }

  // Mailing List Recon Box
  const mlBox = document.getElementById('sbMailingListBox');
  if (data.mailing_list_result) {
    const ml = data.mailing_list_result;
    if (ml.found_in_marc) {
      mlBox.innerHTML = `
        <div class="text-rose-400 font-bold">⚠️ ${ml.marc_hit_count} Treffer auf MARC.info</div>
        <div class="text-[10px] text-slate-300">Listen: ${ml.detected_lists.slice(0, 3).join(', ')}</div>
        <div class="pt-1 flex flex-wrap gap-1">
          <a href="${ml.marc_url}" target="_blank" class="text-[10px] text-cyan-400 hover:underline">MARC Archiv ↗</a>
          <a href="${ml.specialized_searches[0].url}" target="_blank" class="text-[10px] text-indigo-400 hover:underline">The Mail Archive ↗</a>
        </div>
      `;
    } else {
      mlBox.innerHTML = `
        <div class="text-emerald-400 font-medium">Keine MARC-Treffer</div>
        <div class="flex flex-wrap gap-1 pt-0.5">
          <a href="${ml.specialized_searches[0].url}" target="_blank" class="text-[10px] text-indigo-400 hover:underline">Mail Archive ↗</a>
          <a href="${ml.specialized_searches[1].url}" target="_blank" class="text-[10px] text-indigo-400 hover:underline">Pipermail ↗</a>
        </div>
      `;
    }
  } else {
    mlBox.textContent = 'Keine E-Mail angegeben.';
  }

  const permBox = document.getElementById('sbPermutationsBox');
  const perms = data.identity_audit.email_permutations || [];
  if (perms.length > 0) {
    permBox.innerHTML = perms.slice(0, 8).map(em => `<span class="inline-block bg-slate-900 px-2 py-0.5 rounded border border-slate-800 mr-1 mb-1 text-[11px] text-slate-300">${em}</span>`).join('');
  } else {
    permBox.textContent = 'Keine Permutationen berechnet.';
  }

  // 6. Register & Dorks (Section 5)
  const dorksBox = document.getElementById('sbDorksLinksList');
  dorksBox.innerHTML = '';
  (data.dorks || []).forEach(cat => {
    cat.items.forEach(item => {
      const a = document.createElement('a');
      a.href = item.google_url;
      a.target = '_blank';
      a.className = 'px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-indigo-400 hover:text-indigo-300 hover:border-indigo-500 transition text-[11px] flex items-center space-x-1';
      a.innerHTML = `<span>🔍 ${item.title}</span> <span>↗</span>`;
      dorksBox.appendChild(a);
    });
  });

  // 7. GDPR Letter
  document.getElementById('repGdprText').value = data.identity_audit.gdpr_template || '';

  // Scroll smoothly down to the dossier
  reportContainer.scrollIntoView({ behavior: 'smooth' });
}

function toggleDossierView() {
  const dossier = document.getElementById('dossierSheet');
  const btn = document.getElementById('toggleViewBtn');
  if (dossier.classList.contains('border-indigo-500')) {
    dossier.classList.remove('border-indigo-500');
    btn.textContent = 'Kompakt-Modus';
  } else {
    dossier.classList.add('border-indigo-500');
    btn.textContent = 'Dossier-Modus';
  }
}

// Copy GDPR helper
function copyGdprTemplate(btn) {
  const text = document.getElementById('repGdprText') ? document.getElementById('repGdprText').value : '';
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Kopiert!';
    setTimeout(() => btn.textContent = orig, 1800);
  });
}

// ==================== 1. USERNAME SCANNER (INDIVIDUAL TAB) ====================
function startUsernameScan(e) {
  e.preventDefault();
  const username = document.getElementById('usernameInput').value.trim();
  if (!username) return;

  if (usernameEventSource) usernameEventSource.close();

  currentResults = [];
  document.getElementById('usernameResultsGrid').innerHTML = '';
  document.getElementById('usernameProgressSection').classList.remove('hidden');

  const btn = document.getElementById('usernameScanBtn');
  btn.disabled = true;
  btn.textContent = 'Scanne...';

  const url = `/api/scan/username/stream?username=${encodeURIComponent(username)}`;
  usernameEventSource = new EventSource(url);

  usernameEventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.event === 'done') {
      btn.disabled = false;
      btn.textContent = 'Scan starten';
      usernameEventSource.close();
      return;
    }
    currentResults.push(data);
    if (data.progress) {
      document.getElementById('scanProgressBar').style.width = `${data.progress.percent}%`;
      document.getElementById('scanCount').textContent = `${data.progress.checked}/${data.progress.total}`;
      document.getElementById('scanFoundCount').textContent = data.progress.found;
    }
    if (data.exists) {
      const card = document.createElement('div');
      card.className = 'p-3 bg-slate-900 rounded-xl border border-emerald-500/50 flex justify-between items-center';
      card.innerHTML = `
        <div>
          <span class="font-bold text-white text-xs block">${data.platform}</span>
          <span class="text-[10px] text-slate-400">${data.category}</span>
        </div>
        <a href="${data.url}" target="_blank" class="text-xs text-cyan-400 hover:underline">Öffnen ↗</a>
      `;
      document.getElementById('usernameResultsGrid').appendChild(card);
    }
  };

  usernameEventSource.onerror = function() {
    btn.disabled = false;
    btn.textContent = 'Scan starten';
    if (usernameEventSource) usernameEventSource.close();
  };
}

// ==================== 2. EXIF INSPECTOR ====================
const dropZone = document.getElementById('dropZone');
if (dropZone) {
  dropZone.addEventListener('click', () => document.getElementById('exifFileInput').click());
  ['dragenter', 'dragover'].forEach(ev => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('border-cyan-400'); }));
  ['dragleave', 'drop'].forEach(ev => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('border-cyan-400'); }));
  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFileSelect(files[0]);
  });
}

async function handleFileSelect(file) {
  if (!file) return;
  currentSelectedFile = file;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/exif/inspect', { method: 'POST', body: formData });
    const json = await res.json();
    if (json.success) renderExifResults(json.data);
  } catch (err) {
    alert('Fehler: ' + err.message);
  }
}

function renderExifResults(data) {
  document.getElementById('exifActions').classList.remove('hidden');
  document.getElementById('exifRiskCard').classList.remove('hidden');
  document.getElementById('exifTableContainer').classList.remove('hidden');

  const badge = document.getElementById('exifRiskBadge');
  badge.textContent = `Risiko: ${data.risk_level}`;
  badge.className = 'text-xs px-2.5 py-1 rounded font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800';

  const reasons = document.getElementById('exifRiskReasons');
  reasons.innerHTML = data.risk_reasons.map(r => `<li>• ${r}</li>`).join('');

  const tbody = document.getElementById('exifTableBody');
  tbody.innerHTML = Object.entries(data.metadata).map(([k, v]) => `<tr><td class="py-2 px-3 font-semibold text-slate-400">${k}</td><td class="py-2 px-3 text-slate-200 break-all">${v}</td></tr>`).join('');

  const mapContainer = document.getElementById('exifMapContainer');
  if (data.gps) {
    mapContainer.classList.remove('hidden');
    document.getElementById('exifMapCoords').textContent = `${data.gps.latitude}, ${data.gps.longitude}`;
    if (!leafletMap) {
      leafletMap = L.map('exifMap').setView([data.gps.latitude, data.gps.longitude], 15);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(leafletMap);
      leafletMarker = L.marker([data.gps.latitude, data.gps.longitude]).addTo(leafletMap);
    } else {
      leafletMap.setView([data.gps.latitude, data.gps.longitude], 15);
      leafletMarker.setLatLng([data.gps.latitude, data.gps.longitude]);
    }
  }
}

async function downloadSanitizedImage() {
  if (!currentSelectedFile) return;
  const formData = new FormData();
  formData.append('file', currentSelectedFile);
  const res = await fetch('/api/exif/strip', { method: 'POST', body: formData });
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = window.URL.createObjectURL(blob);
  a.download = `sanitized_${currentSelectedFile.name}`;
  a.click();
}

// ==================== 3. DOMAIN RECON ====================
async function startDomainRecon(e) {
  e.preventDefault();
  const domain = document.getElementById('domainInput').value.trim();
  const res = await fetch(`/api/recon/domain?domain=${encodeURIComponent(domain)}`);
  const json = await res.json();
  if (json.success) {
    document.getElementById('domainResults').classList.remove('hidden');
    const spf = json.data.email_security.spf;
    const dmarc = json.data.email_security.dmarc;
    document.getElementById('spfBadge').textContent = spf.status;
    document.getElementById('spfAssessment').textContent = spf.assessment;
    document.getElementById('dmarcBadge').textContent = dmarc.status;
    document.getElementById('dmarcAssessment').textContent = dmarc.assessment;
  }
}

// ==================== 4. BREACH CHECK ====================
async function checkPassword(e) {
  e.preventDefault();
  const pwd = document.getElementById('passwordInput').value;
  const res = await fetch('/api/breach/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pwd })
  });
  const json = await res.json();
  const r = document.getElementById('pwdResult');
  r.classList.remove('hidden');
  if (json.data.pwned) {
    r.className = 'mt-4 p-4 rounded-xl border bg-rose-950 text-rose-300';
    r.innerHTML = `⚠️ Gefunden in ${json.data.count.toLocaleString()} Leaks!`;
  } else {
    r.className = 'mt-4 p-4 rounded-xl border bg-emerald-950 text-emerald-300';
    r.innerHTML = `✓ Kein Leak gefunden.`;
  }
}

async function checkEmail(e) {
  e.preventDefault();
  const email = document.getElementById('emailInput').value.trim();
  const res = await fetch(`/api/breach/email?email=${encodeURIComponent(email)}`);
  const json = await res.json();
  const r = document.getElementById('emailResult');
  r.classList.remove('hidden');
  r.innerHTML = `<div class="p-3 bg-slate-950 rounded border border-slate-800 text-xs">${json.data.message || 'Geprüft'}</div>`;
}

// ==================== 5. DORKS ====================
async function generateDorkQueries(e) {
  e.preventDefault();
  const res = await fetch('/api/dorks/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('dorkName').value,
      city: document.getElementById('dorkCity').value
    })
  });
  const json = await res.json();
  const c = document.getElementById('dorksContainer');
  c.innerHTML = json.data.map(cat => `
    <div class="p-4 bg-slate-900 rounded-xl border border-slate-800">
      <h3 class="font-bold text-sm text-white mb-2">${cat.category}</h3>
      ${cat.items.map(i => `<div class="text-xs py-1"><a href="${i.google_url}" target="_blank" class="text-indigo-400 hover:underline">${i.title} ↗</a></div>`).join('')}
    </div>
  `).join('');
}

// ==================== 6. SETTINGS ====================
async function saveSettings(e) {
  e.preventDefault();
  await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hibp_api_key: document.getElementById('hibpApiKeyInput').value })
  });
  alert('Einstellungen gespeichert!');
}
