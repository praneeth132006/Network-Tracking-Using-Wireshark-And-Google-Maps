/* NetMap dashboard. Renders analyzer snapshots pushed over Socket.IO, or a baked-in
   snapshot (window.STATIC_SNAPSHOT) when opened as an exported offline report. */
(() => {
    'use strict';

    const STATIC = window.STATIC_SNAPSHOT || null;
    const $ = (id) => document.getElementById(id);
    const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const STATUS_RANK = { encrypted: 0, other: 1, plaintext: 2, alert: 3 };
    const STATUS_LABEL = { encrypted: 'Encrypted', other: 'Other', plaintext: 'Unencrypted', alert: 'Alert' };
    const icon = (name) => `<svg><use href="#i-${name}"/></svg>`;

    let snap = null;
    let status = null;
    let view = 'overview';
    let hostIp = null;              // host shown in the detail view
    let statusFilter = '';
    let lastFitSource;
    let lastError = null;
    let samples = [];

    // ------------------------------------------------------------------ formatting
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const fmtNum = (n) => (n || 0).toLocaleString();
    function fmtBytes(n) {
        n = n || 0;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 1 : 0)) + ' ' + units[i];
    }
    const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : '';
    const fmtDateTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '';
    function fmtDur(s) {
        s = Math.max(0, Math.round(s || 0));
        const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
        return h ? `${h}h ${m}m` : m ? `${m}m ${sec}s` : `${sec}s`;
    }
    const flag = (cc) => (cc && cc.length === 2)
        ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1F1A5 + c.charCodeAt(0))) : '';
    const place = (r) => [r.city, r.country].filter(Boolean).join(', ');
    const hostName = (r) => r.hostname || r.ip;
    const endpoint = (ip) => snap && snap.endpoints.find((e) => e.ip === ip);

    // ------------------------------------------------------------------ toasts
    function toast(html, kind = 'info', ms = 6000) {
        const el = document.createElement('div');
        el.className = `toast ${kind}`;
        el.innerHTML = `<div>${html}</div><button class="icon-btn" aria-label="Dismiss">${icon('x')}</button>`;
        el.querySelector('button').onclick = () => el.remove();
        $('toasts').appendChild(el);
        if (ms) setTimeout(() => el.remove(), ms);
    }

    // ------------------------------------------------------------------ map
    const map = L.map('map', { worldCopyJump: true, minZoom: 2, zoomSnap: 0.5, zoomControl: true }).setView([25, 15], 2.5);
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
        maxZoom: 16, attribution: 'Tiles &copy; Esri &mdash; Esri, HERE, Garmin, &copy; OpenStreetMap contributors',
    }).addTo(map);
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
        maxZoom: 16, opacity: 0.55,
    }).addTo(map);
    const lineLayer = L.layerGroup().addTo(map);
    const markerLayer = L.layerGroup().addTo(map);
    const locations = new Map();      // "lat,lon" -> {marker, line, lastSeen, status}
    let homeMarker = null;
    let homeKey = null;
    setTimeout(() => map.invalidateSize(), 300);

    const statusColor = (s) => cssVar(`--${s}`);

    function arcPoints(a, b) {
        const [lat1, lon1] = a, [lat2, lon2] = b;
        const dx = lon2 - lon1, dy = lat2 - lat1;
        const cx = (lon1 + lon2) / 2 - dy * 0.2, cy = (lat1 + lat2) / 2 + dx * 0.2;
        const pts = [];
        for (let i = 0; i <= 40; i++) {
            const t = i / 40, u = 1 - t;
            pts.push([u * u * lat1 + 2 * u * t * cy + t * t * lat2, u * u * lon1 + 2 * u * t * cx + t * t * lon2]);
        }
        return pts;
    }

    function popupHtml(g) {
        const hosts = [...g.hosts].sort((a, b) => b.bytes - a.bytes);
        const rows = hosts.slice(0, 7).map((h) => `
            <button class="pop-host" data-ip="${esc(h.ip)}"><i class="sdot s-${h.status}"></i>
              <span class="name">${esc(hostName(h))}</span><span class="val">${fmtBytes(h.bytes)}</span></button>`).join('');
        const more = hosts.length > 7 ? `<div class="muted" style="margin-top:4px">+${hosts.length - 7} more</div>` : '';
        return `<div class="pop-title">${flag(g.cc)} ${esc(place(g) || 'Unknown location')}</div>
            <div class="pop-sub">${hosts.length} host${hosts.length > 1 ? 's' : ''} · ${fmtBytes(g.bytes)} · ${fmtNum(g.packets)} packets</div>${rows}${more}`;
    }

    function setPathStatus(layer, base, statusName) {
        const el = layer && layer._path;
        if (!el) return;
        el.setAttribute('class', `${base} s-${statusName} leaflet-interactive`);
    }

    function updateMap() {
        const home = snap.home || {};
        const hasHome = home.lat != null && home.lon != null;
        const showLines = $('toggle-lines').checked;

        const newHomeKey = hasHome ? `${home.lat},${home.lon}` : null;
        if (newHomeKey !== homeKey) {
            if (homeMarker) { homeMarker.remove(); homeMarker = null; }
            homeKey = newHomeKey;
            if (hasHome) {
                homeMarker = L.marker([home.lat, home.lon], {
                    icon: L.divIcon({ className: 'home', html: '<i></i>', iconSize: [14, 14], iconAnchor: [7, 7] }),
                    zIndexOffset: 1000,
                }).bindPopup(`<div class="pop-title">You</div><div class="pop-sub">${esc(home.label || '')}${home.ip ? ' · ' + esc(home.ip) : ''}</div>`).addTo(map);
            }
            locations.forEach((loc) => { loc.marker.remove(); if (loc.line) loc.line.remove(); });
            locations.clear();
        }

        // Group hosts that share coordinates (GeoIP often returns one point per city/country)
        const groups = new Map();
        for (const ep of snap.endpoints) {
            if (ep.lat == null) continue;
            const key = `${ep.lat},${ep.lon}`;
            let g = groups.get(key);
            if (!g) {
                g = { key, lat: ep.lat, lon: ep.lon, city: ep.city, country: ep.country, cc: ep.cc, hosts: [], bytes: 0, packets: 0, lastSeen: 0, status: 'encrypted' };
                groups.set(key, g);
            }
            g.hosts.push(ep);
            g.bytes += ep.bytes;
            g.packets += ep.packets;
            g.lastSeen = Math.max(g.lastSeen, ep.last_seen);
            if (STATUS_RANK[ep.status] > STATUS_RANK[g.status]) g.status = ep.status;
            if (!ep.city) g.city = null;
        }
        const maxBytes = Math.max(1, ...[...groups.values()].map((g) => g.bytes));

        for (const [key, loc] of locations) {
            if (!groups.has(key)) { loc.marker.remove(); if (loc.line) loc.line.remove(); locations.delete(key); }
        }
        for (const g of groups.values()) {
            const color = statusColor(g.status);
            const radius = 4 + Math.sqrt(g.bytes / maxBytes) * 16;
            let loc = locations.get(g.key);
            if (!loc) {
                const marker = L.circleMarker([g.lat, g.lon], { radius, color, weight: 1.5, fillColor: color, fillOpacity: 0.35, className: `node s-${g.status}` })
                    .bindPopup('', { maxWidth: 300, minWidth: 240 }).addTo(markerLayer);
                const line = hasHome ? L.polyline(arcPoints([home.lat, home.lon], [g.lat, g.lon]), { color, weight: 1.4, opacity: 0.5, interactive: false, className: `arc s-${g.status}` }) : null;
                if (line && showLines) line.addTo(lineLayer);
                loc = { marker, line, lastSeen: g.lastSeen, status: g.status };
                locations.set(g.key, loc);
            } else {
                loc.marker.setStyle({ color, fillColor: color });
                loc.marker.setRadius(radius);
                if (loc.line) loc.line.setStyle({ color });
                if (loc.status !== g.status) {
                    setPathStatus(loc.marker, 'node', g.status);
                    setPathStatus(loc.line, 'arc', g.status);
                    loc.status = g.status;
                }
                if (snap.live && g.lastSeen > loc.lastSeen) pulse(loc.marker);
                loc.lastSeen = g.lastSeen;
            }
            loc.marker.setPopupContent(popupHtml(g));
        }

        if (snap.source !== lastFitSource && groups.size) {
            lastFitSource = snap.source;
            fitAll();
        }
    }

    function pulse(marker) {
        const path = marker._path;
        if (!path) return;
        path.classList.remove('pulse');
        void path.getBoundingClientRect();
        path.classList.add('pulse');
    }

    function fitAll() {
        const pts = [...locations.values()].map((l) => l.marker.getLatLng());
        if (homeMarker) pts.push(homeMarker.getLatLng());
        if (pts.length === 1) map.setView(pts[0], 4);
        else if (pts.length) map.fitBounds(L.latLngBounds(pts), { padding: [60, 60], maxZoom: 5 });
    }

    function flyToHost(ep) {
        if (!ep || ep.lat == null) return;
        const loc = locations.get(`${ep.lat},${ep.lon}`);
        if (!loc) return;
        map.flyTo(loc.marker.getLatLng(), Math.max(map.getZoom(), 4), { duration: 0.8 });
        setTimeout(() => loc.marker.openPopup(), 850);
    }

    $('toggle-lines').addEventListener('change', (e) => {
        locations.forEach((loc) => { if (loc.line) (e.target.checked ? loc.line.addTo(lineLayer) : loc.line.remove()); });
    });
    $('btn-fit').addEventListener('click', fitAll);
    document.addEventListener('click', (e) => {
        const b = e.target.closest('.pop-host');
        if (b) { map.closePopup(); openHost(b.dataset.ip, false); }
    });

    // ------------------------------------------------------------------ throughput chart
    Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.color = cssVar('--text-3');
    const bwCanvas = $('chart-bw');
    const gradient = bwCanvas.getContext('2d').createLinearGradient(0, 0, 0, 120);
    gradient.addColorStop(0, 'rgba(139, 147, 255, .35)');
    gradient.addColorStop(1, 'rgba(139, 147, 255, 0)');
    const bwChart = new Chart(bwCanvas, {
        type: 'line',
        data: { labels: [], datasets: [{ data: [], borderColor: cssVar('--accent'), backgroundColor: gradient, fill: true, tension: 0.35, pointRadius: 0, borderWidth: 1.8 }] },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            interaction: { mode: 'index', intersect: false },
            plugins: { legend: { display: false }, tooltip: { displayColors: false, callbacks: { label: (c) => fmtBytes(c.raw) + '/s' } } },
            scales: {
                x: { ticks: { maxTicksLimit: 4, maxRotation: 0, autoSkipPadding: 20 }, grid: { display: false }, border: { display: false } },
                y: { beginAtZero: true, ticks: { maxTicksLimit: 3, callback: (v) => fmtBytes(v) + '/s' }, grid: { color: 'rgba(148,163,196,.08)' }, border: { display: false } },
            },
        },
    });

    // ------------------------------------------------------------------ views
    function showView(name) {
        view = name;
        const tabName = name === 'host' ? 'hosts' : name;
        document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.view === tabName));
        document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
        $('panel-body').scrollTop = 0;
        renderView();
    }
    $('tabs').addEventListener('click', (e) => {
        const b = e.target.closest('button');
        if (b) { hostIp = null; showView(b.dataset.view); }
    });
    document.addEventListener('click', (e) => {
        const g = e.target.closest('[data-goto]');
        if (g) showView(g.dataset.goto);
    });

    function openHost(ip, fly = true) {
        const ep = endpoint(ip);
        if (!ep) return;
        hostIp = ip;
        showView('host');
        if (fly) flyToHost(ep);
    }

    function renderView() {
        if (!snap) return;
        ({ overview: renderOverview, hosts: renderHosts, host: renderHost, alerts: renderAlerts, dns: renderDns, activity: renderActivity })[view]();
    }

    function hostRow(r, max) {
        const sub = [flag(r.cc) + ' ' + (place(r) || (r.ip.includes(':') ? 'IPv6 · location unknown' : 'Location unknown')), r.org, r.services[0]].filter(Boolean).join(' · ');
        return `<button class="row" data-host="${esc(r.ip)}">
            <i class="sdot s-${r.status}" title="${STATUS_LABEL[r.status]}"></i>
            <span class="row-main"><span class="row-title">${esc(hostName(r))}</span><span class="row-sub">${esc(sub)}</span></span>
            <span class="row-side">${fmtBytes(r.bytes)}<span class="minibar"><i style="width:${Math.max(3, r.bytes / max * 100)}%"></i></span></span>
        </button>`;
    }
    document.addEventListener('click', (e) => {
        const r = e.target.closest('[data-host]');
        if (r) openHost(r.dataset.host);
    });

    function bars(rows, label, value, fmt, clickAttr) {
        const max = Math.max(1, ...rows.map(value));
        return rows.map((r) => {
            const tag = clickAttr ? 'button' : 'div';
            return `<${tag} class="bar-row" ${clickAttr ? clickAttr(r) : ''}><span>${label(r)}</span><span class="v">${fmt(value(r))}</span>
                <span class="bar-track"><i style="width:${Math.max(2, value(r) / max * 100)}%"></i></span></${tag}>`;
        }).join('');
    }

    function renderOverview() {
        const s = snap.summary;
        const sev = s.alerts_by_severity || {};
        $('k-bytes').textContent = fmtBytes(s.bytes);
        $('k-bytes-sub').textContent = s.bytes ? `${fmtBytes(s.internet_bytes)} internet` : ' ';
        $('k-hosts').textContent = fmtNum(s.remote_hosts);
        $('k-hosts-sub').textContent = s.remote_hosts ? `${s.mapped_hosts} on the map` : ' ';
        $('k-countries').textContent = fmtNum(s.countries);
        $('k-countries-sub').textContent = snap.countries[0] ? `Most: ${snap.countries[0].country}` : ' ';
        $('k-packets').textContent = fmtNum(s.packets);
        $('k-packets-sub').textContent = s.packets ? `over ${fmtDur(s.duration)}` : ' ';
        $('k-local').textContent = fmtNum(s.local_hosts);
        $('k-local-sub').textContent = s.local_hosts ? 'on your network' : ' ';
        $('k-alerts').textContent = fmtNum(s.alerts);
        $('k-alerts-sub').textContent = s.alerts ? ['high', 'medium', 'low'].filter((k) => sev[k]).map((k) => `${sev[k]} ${k}`).join(' · ') : (s.packets ? 'all clear' : ' ');
        $('kpi-alerts').classList.toggle('hot', !!sev.high);
        $('kpi-alerts').classList.toggle('warm', !sev.high && !!sev.medium);

        const tl = snap.timeline;
        bwChart.data.labels = tl.bytes.map((_, i) => fmtTime(tl.start + i * tl.bucket));
        bwChart.data.datasets[0].data = tl.bytes.map((b) => b / tl.bucket);
        bwChart.update('none');
        $('bw-title').textContent = snap.live ? 'Throughput · last 2 minutes' : 'Throughput over the capture';
        const peak = Math.max(0, ...tl.bytes) / (tl.bucket || 1);
        $('bw-peak').textContent = peak ? `peak ${fmtBytes(peak)}/s` : '';

        const top = snap.endpoints.slice(0, 6);
        const max = Math.max(1, ...top.map((r) => r.bytes));
        $('top-hosts').innerHTML = top.length ? top.map((r) => hostRow(r, max)).join('') : emptyState('No remote hosts yet');

        $('services-bars').innerHTML = snap.services.length
            ? bars(snap.services.slice(0, 6), (r) => esc(r.name), (r) => r.bytes, fmtBytes, (r) => `data-filter="${esc(r.name)}"`)
            : emptyState('Nothing yet');
        $('country-bars').innerHTML = snap.countries.length
            ? bars(snap.countries.slice(0, 6), (r) => `${flag(r.cc)} ${esc(r.country)} <span class="muted">${r.hosts} host${r.hosts > 1 ? 's' : ''}</span>`, (r) => r.bytes, fmtBytes, (r) => `data-filter="${esc(r.country)}"`)
            : emptyState('Nothing yet');
        const lmax = Math.max(1, ...snap.local_hosts.map((r) => r.bytes));
        $('local-list').innerHTML = snap.local_hosts.length ? snap.local_hosts.slice(0, 8).map((r) => `
            <div class="row"><i class="sdot" style="background:var(--accent)"></i>
            <span class="row-main"><span class="row-title mono">${esc(r.ip)}</span><span class="row-sub">${fmtNum(r.packets)} packets</span></span>
            <span class="row-side">${fmtBytes(r.bytes)}<span class="minibar"><i style="width:${Math.max(3, r.bytes / lmax * 100)}%"></i></span></span></div>`).join('')
            : emptyState('No devices seen yet');
    }
    document.addEventListener('click', (e) => {
        const f = e.target.closest('[data-filter]');
        if (!f) return;
        $('host-search').value = f.dataset.filter;
        statusFilter = '';
        document.querySelectorAll('#status-chips button').forEach((x) => x.classList.toggle('active', x.dataset.status === ''));
        showView('hosts');
    });

    const emptyState = (text, ok) => `<div class="empty-state">${ok ? icon('check') : ''}${esc(text)}</div>`;

    function renderHosts() {
        const q = $('host-search').value.trim().toLowerCase();
        const sort = $('host-sort').value;
        let rows = snap.endpoints.filter((r) => !statusFilter || r.status === statusFilter);
        if (q) rows = rows.filter((r) => [r.ip, r.hostname, r.org, r.city, r.country, ...r.services, ...r.ports].join(' ').toLowerCase().includes(q));
        const sorters = {
            bytes: (a, b) => b.bytes - a.bytes, packets: (a, b) => b.packets - a.packets,
            recent: (a, b) => b.last_seen - a.last_seen, name: (a, b) => hostName(a).localeCompare(hostName(b)),
        };
        rows = [...rows].sort(sorters[sort]);
        const max = Math.max(1, ...rows.map((r) => r.bytes));
        const shown = rows.slice(0, 300);
        $('host-list').innerHTML = shown.length
            ? shown.map((r) => hostRow(r, max)).join('') + (rows.length > shown.length ? `<div class="more-note">Showing ${shown.length} of ${rows.length} – search to narrow down</div>` : '')
            : emptyState(q || statusFilter ? 'No hosts match' : 'No remote hosts yet');
    }
    let searchTimer;
    $('host-search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(renderHosts, 120); });
    $('host-sort').addEventListener('change', renderHosts);
    $('status-chips').addEventListener('click', (e) => {
        const b = e.target.closest('button');
        if (!b) return;
        statusFilter = b.dataset.status;
        document.querySelectorAll('#status-chips button').forEach((x) => x.classList.toggle('active', x === b));
        renderHosts();
    });

    const EXPLAIN = {
        encrypted: 'Traffic with this server is <b>encrypted</b>. Others on your network can see that you connect to it, but not what is sent.',
        plaintext: 'Some traffic with this server is <b>not encrypted</b>. Anyone on the same network (e.g. public Wi-Fi) could read it.',
        alert: 'NetMap <b>flagged</b> this host. See the alerts below for why.',
        other: 'This host uses protocols NetMap can’t classify as encrypted or unencrypted.',
    };

    function renderHost() {
        const r = endpoint(hostIp);
        const el = $('view-host');
        if (!r) { el.innerHTML = `<button class="back" data-goto="hosts">${icon('back')}All hosts</button>${emptyState('This host is no longer in the data')}`; return; }
        const alerts = snap.alerts.filter((a) => a.ip === r.ip);
        const fact = (label, value, wide) => `<div class="fact${wide ? ' wide' : ''}"><span>${label}</span><b>${value}</b></div>`;
        el.innerHTML = `
            <button class="back" data-goto="hosts">${icon('back')}All hosts</button>
            <div class="detail-title">${esc(hostName(r))}</div>
            <div class="detail-ip mono">${esc(r.ip)}<button class="icon-btn" data-copy="${esc(r.ip)}" title="Copy IP">${icon('copy')}</button></div>
            <div class="badges">
                <span class="badge b-${r.status}"><i class="sdot s-${r.status}"></i>${STATUS_LABEL[r.status]}</span>
                ${r.org ? `<span class="badge">${esc(r.org)}</span>` : ''}
                ${r.services.map((s) => `<span class="badge">${esc(s)}</span>`).join('')}
            </div>
            <div class="explain">${EXPLAIN[r.status]}</div>
            <div class="facts">
                ${fact('Location', r.country ? `${flag(r.cc)} ${esc(place(r))}` : (r.ip.includes(':') ? 'Unknown (IPv6)' : 'Unknown'), true)}
                ${fact('Sent to it', fmtBytes(r.bytes_out))}
                ${fact('Received', fmtBytes(r.bytes_in))}
                ${fact('Packets', fmtNum(r.packets))}
                ${fact('Ports', esc(r.ports.join(', ') || '–'))}
                ${fact('First seen', esc(fmtDateTime(r.first_seen)))}
                ${fact('Last seen', esc(fmtDateTime(r.last_seen)))}
                ${fact('Your devices talking to it', `<span class="mono">${esc(r.locals.join(', ') || '–')}</span>`, true)}
            </div>
            <div class="detail-actions">
                ${r.lat != null ? `<button class="btn" id="d-fly">${icon('pin')}Show on map</button>` : ''}
                <a class="btn" href="https://ipinfo.io/${encodeURIComponent(r.ip)}" target="_blank" rel="noopener">${icon('external')}Who owns this IP?</a>
            </div>
            ${alerts.length ? `<div class="section-h">Alerts</div>${alerts.map(alertCard).join('')}` : ''}
            <p class="footnote">Locations come from a GeoIP database and show where an IP is registered or hosted, often a nearby CDN server rather than the company’s headquarters.</p>`;
        const fly = $('d-fly');
        if (fly) fly.onclick = () => flyToHost(r);
    }
    document.addEventListener('click', (e) => {
        const c = e.target.closest('[data-copy]');
        if (!c) return;
        navigator.clipboard && navigator.clipboard.writeText(c.dataset.copy).then(() => toast('Copied to clipboard', 'info', 1800));
    });

    function alertCard(a) {
        return `<button class="alert-card sev-${a.severity}" data-alert-ip="${esc(a.ip)}"><span class="sev">${a.severity}</span>
            <span><div class="msg">${esc(a.message)}</div><div class="meta">${fmtDateTime(a.ts)}</div></span></button>`;
    }
    document.addEventListener('click', (e) => {
        const a = e.target.closest('[data-alert-ip]');
        if (a && endpoint(a.dataset.alertIp)) openHost(a.dataset.alertIp);
    });

    function renderAlerts() {
        $('alert-list').innerHTML = snap.alerts.length
            ? `<p class="view-intro">Things worth a closer look, most serious first. These are heuristics, not proof of an attack.</p>` + snap.alerts.slice(0, 200).map(alertCard).join('')
            : emptyState(snap.summary.packets ? 'No suspicious activity detected' : 'Alerts will appear here', !!snap.summary.packets);
    }

    function renderDns() {
        const q = $('dns-search').value.trim().toLowerCase();
        const byHost = new Map();
        for (const e of snap.endpoints) if (e.hostname) {
            const cur = byHost.get(e.hostname);
            if (!cur || e.bytes > cur.bytes) byHost.set(e.hostname, e);
        }
        const rows = snap.domains.filter((d) => !q || d.name.includes(q));
        $('dns-list').innerHTML = rows.length ? rows.map((d) => {
            const ep = byHost.get(d.name);
            const sub = ep ? `${flag(ep.cc)} ${place(ep) || 'unknown location'} · ${fmtBytes(ep.bytes)}` : 'looked up, no traffic seen';
            return `<${ep ? `button data-host="${esc(ep.ip)}"` : 'div'} class="row"><i class="sdot s-${ep ? ep.status : 'other'}"></i>
                <span class="row-main"><span class="row-title">${esc(d.name)}</span><span class="row-sub">${esc(sub)}</span></span>
                <span class="row-side">${fmtNum(d.count)}<small>lookup${d.count > 1 ? 's' : ''}</small></span></${ep ? 'button' : 'div'}>`;
        }).join('') : emptyState(q ? 'No domains match' : 'No DNS lookups seen yet');
    }
    $('dns-search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(renderDns, 120); });

    function renderActivity() {
        const statusOf = new Map(snap.endpoints.map((e) => [e.ip, e.status]));
        $('activity-list').innerHTML = snap.feed.length ? snap.feed.map((f) => `
            <button class="row" data-host="${esc(f.remote)}"><i class="sdot s-${statusOf.get(f.remote) || 'other'}"></i>
                <span class="row-main"><span class="row-title">${esc(f.hostname || f.remote)}</span>
                <span class="row-sub">${f.outbound ? '↗ out' : '↙ in'} · ${esc(f.service)} · <span class="mono">${esc(f.local)}</span></span></span>
                <span class="row-side mono">${fmtTime(f.ts)}</span></button>`).join('')
            : emptyState('New connections will appear here');
    }

    // ------------------------------------------------------------------ render
    function render(newSnap) {
        snap = newSnap;
        const s = snap.summary;
        $('n-hosts').textContent = s.remote_hosts || '';
        const nA = $('n-alerts');
        nA.textContent = s.alerts || '';
        nA.classList.toggle('hot', !!(s.alerts_by_severity || {}).high);
        $('n-dns').textContent = snap.domains.length || '';
        updateMap();
        renderView();
        updateChrome();
    }

    // Everything that depends on both the status and the data
    function updateChrome() {
        const st = status || {};
        const s = snap ? snap.summary : { packets: 0 };
        const source = $('source');
        let cls = '', text = 'No data yet', meta = '';
        if (STATIC) {
            cls = 'is-file'; text = `Report · ${snap.source || 'capture'}`; meta = fmtDateTime(snap.generated_at);
        } else if (st.loading) {
            cls = 'is-busy'; text = `Analyzing ${st.source || ''}`; meta = `${Math.round((st.progress || 0) * 100)}%`;
        } else if (st.starting) {
            cls = 'is-busy'; text = 'Waiting for your password…';
        } else if (st.capturing) {
            cls = 'is-live'; text = st.source || 'Live'; meta = s.start ? fmtDur(Date.now() / 1000 - s.start) : 'listening…';
        } else if (st.mode === 'live') {
            text = `Paused · ${(st.source || '').replace('Live · ', '')}`; meta = s.packets ? `${fmtNum(s.packets)} packets` : '';
        } else if (st.mode === 'pcap') {
            cls = 'is-file'; text = st.source || 'Capture file'; meta = s.packets ? `${fmtDur(s.duration)} of traffic` : '';
        }
        source.className = `source ${cls}`;
        $('source-text').textContent = text;
        $('source-meta').textContent = meta;
        document.body.classList.toggle('is-live', !!st.capturing);

        const showWelcome = !STATIC && status && st.mode === 'idle' && !st.loading && !st.starting && !(s.packets > 0);
        $('welcome').classList.toggle('hidden', !showWelcome);

        const loading = $('loading');
        if (!STATIC && st.loading) {
            loading.classList.remove('hidden');
            $('loading-title').textContent = `Analyzing ${st.source || 'capture'}…`;
            $('loading-sub').textContent = `${Math.round((st.progress || 0) * 100)}%`;
        } else if (!STATIC && st.starting) {
            loading.classList.remove('hidden');
            $('loading-title').textContent = 'Waiting for your password…';
            $('loading-sub').textContent = 'Approve the system prompt to start watching live traffic.';
        } else loading.classList.add('hidden');

        const rate = $('live-rate');
        if (st.capturing && snap) {
            const b = snap.timeline.bytes;
            const perSec = b.length > 1 ? b[b.length - 2] : 0;
            rate.classList.remove('hidden');
            $('live-rate-text').textContent = `${fmtBytes(perSec)}/s`;
        } else rate.classList.add('hidden');
    }

    function renderStatus(st) {
        status = st;
        const btn = $('btn-live');
        if (st.capturing) { btn.className = 'btn btn-primary is-stop'; btn.innerHTML = `${icon('stop')}<span>Stop</span>`; }
        else if (st.starting) { btn.className = 'btn btn-primary is-wait'; btn.innerHTML = `<span>Cancel</span>`; }
        else { btn.className = 'btn btn-primary'; btn.innerHTML = `${icon('play')}<span>${st.mode === 'live' ? 'Resume live' : 'Start live'}</span>`; }
        btn.disabled = st.loading;
        $('btn-open').disabled = st.loading;
        $('iface-select').disabled = $('bpf-input').disabled = st.capturing || st.starting;

        const hint = {
            ready: 'Capture starts right away.',
            password: 'You’ll be asked for your computer password once. Packets are analyzed on this computer only.',
            unavailable: 'Live capture needs admin rights here: start NetMap with <code>sudo ./run_dashboard.sh</code>.',
        }[st.capture_access] || '';
        $('live-hint').innerHTML = hint + ' Filter examples: <code>not port 22</code>, <code>host 8.8.8.8</code>, <code>tcp</code>.';
        $('w-live-hint').textContent = { ready: 'Starts immediately', password: 'Asks for your password once', unavailable: 'Needs NetMap started with sudo' }[st.capture_access] || '';

        $('progress').style.visibility = st.loading ? 'visible' : 'hidden';
        $('progress-bar').style.width = `${Math.round((st.progress || 0) * 100)}%`;

        if (st.error && st.error !== lastError) toast(esc(st.error).replace(/&quot;(sudo [^&]+)&quot;/, '<code>$1</code>'), 'error', 12000);
        lastError = st.error;
        if (!st.geoip.ok && !renderStatus.warnedGeo) {
            renderStatus.warnedGeo = true;
            toast(`GeoIP database not loaded, so hosts can’t be placed on the map. ${esc(st.geoip.error || '')}`, 'error', 0);
        }
        $('footnote').textContent = `Locations: ${st.geoip.db}${st.geoip.ipv6 ? ' (IPv4 + IPv6)' : ' (IPv4 only – add a .mmdb database for IPv6)'}. Hostnames come from DNS answers, TLS SNI, HTTP Host headers and reverse DNS.`;
        updateChrome();
    }

    // ------------------------------------------------------------------ static report mode
    if (STATIC) {
        render(STATIC);
        $('footnote').textContent = `Generated by NetMap on ${fmtDateTime(STATIC.generated_at)}.`;
        return;
    }

    // ------------------------------------------------------------------ live controls
    const socket = io();
    socket.on('status', renderStatus);
    socket.on('snapshot', render);
    let wasConnected = false;
    socket.on('connect', () => { wasConnected = true; });
    socket.on('disconnect', () => { if (wasConnected) toast('Lost connection to NetMap. Is it still running?', 'error', 8000); });

    const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
        .then((r) => r.json()).then(renderStatus).catch((e) => toast(esc(e.message), 'error'));

    fetch('/api/interfaces').then((r) => r.json()).then((d) => {
        const sel = $('iface-select');
        if (!d.interfaces.length) return;
        sel.innerHTML = '';
        for (const i of d.interfaces) {
            const opt = document.createElement('option');
            opt.value = i.name;
            opt.textContent = i.ips.length ? `${i.name} · ${i.ips[0]}` : i.name;
            if (i.default) opt.selected = true;
            sel.appendChild(opt);
        }
    }).catch(() => {});

    fetch('/api/pcap/samples').then((r) => r.json()).then((d) => {
        samples = d.files;
        const list = $('samples-list');
        list.innerHTML = samples.length ? '' : '<div class="empty">No capture files in the NetMap folder</div>';
        for (const f of samples) {
            const b = document.createElement('button');
            b.innerHTML = `<b>${esc(f)}</b><span>Open this capture</span>`;
            b.onclick = () => openSample(f);
            list.appendChild(b);
        }
        const preferred = samples.includes('traffic2.pcap') ? 'traffic2.pcap' : samples[0];
        $('w-sample').disabled = !preferred;
        $('w-sample-name').textContent = preferred || 'No sample available';
        $('w-sample').onclick = () => preferred && openSample(preferred);
    }).catch(() => {});

    function openSample(name) { lastFitSource = undefined; closeMenus(); post('/api/pcap/open', { name }); }

    function startOrStopLive() {
        closeMenus();
        if (status && (status.capturing || status.starting)) post('/api/capture/stop');
        else { lastFitSource = undefined; post('/api/capture/start', { iface: $('iface-select').value, filter: $('bpf-input').value }); }
    }
    $('btn-live').addEventListener('click', startOrStopLive);
    $('w-live').addEventListener('click', startOrStopLive);
    $('btn-live-opts').addEventListener('click', (e) => { e.stopPropagation(); $('live-popover').classList.toggle('open'); });
    $('btn-reset').addEventListener('click', () => {
        closeMenus();
        if (confirm('Clear all data and start over?')) { lastFitSource = undefined; hostIp = null; showView('overview'); post('/api/reset'); }
    });

    // Menus
    function closeMenus() {
        document.querySelectorAll('.dropdown.open').forEach((d) => d.classList.remove('open'));
        $('live-popover').classList.remove('open');
    }
    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('[data-menu]');
        if (trigger) {
            const dd = trigger.closest('.dropdown');
            const open = !dd.classList.contains('open');
            closeMenus();
            dd.classList.toggle('open', open);
            return;
        }
        if (e.target.closest('.menu a')) { closeMenus(); toast('Preparing your download…', 'info', 2500); return; }
        if (!e.target.closest('.popover') && !e.target.closest('.menu')) closeMenus();
    });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeMenus(); map.closePopup(); } });

    // File upload (button, welcome card, or drag & drop anywhere)
    $('btn-open').addEventListener('click', () => $('file-input').click());
    $('w-open').addEventListener('click', () => $('file-input').click());
    $('file-input').addEventListener('change', (e) => { if (e.target.files[0]) upload(e.target.files[0]); e.target.value = ''; });

    function upload(file) {
        if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
            toast('That isn’t a capture file. Choose a .pcap, .pcapng or .cap file (in Wireshark: File → Save As).', 'error');
            return;
        }
        lastFitSource = undefined;
        const xhr = new XMLHttpRequest();
        const fd = new FormData();
        fd.append('file', file);
        $('progress').style.visibility = 'visible';
        $('source').className = 'source is-busy';
        $('source-text').textContent = `Uploading ${file.name}`;
        xhr.upload.onprogress = (e) => { if (e.lengthComputable) $('progress-bar').style.width = `${e.loaded / e.total * 100}%`; };
        xhr.onload = () => {
            let data = {};
            try { data = JSON.parse(xhr.responseText); } catch (_) { /* non-JSON error page */ }
            if (xhr.status >= 400) {
                $('progress').style.visibility = 'hidden';
                toast(esc(data.error || `Upload failed (${xhr.status})`), 'error');
                updateChrome();
            } else renderStatus(data);
        };
        xhr.onerror = () => { $('progress').style.visibility = 'hidden'; toast('Upload failed. Is NetMap still running?', 'error'); };
        xhr.open('POST', '/api/pcap/upload');
        xhr.send(fd);
    }

    let dragDepth = 0;
    window.addEventListener('dragenter', (e) => { if ([...e.dataTransfer.types].includes('Files')) { dragDepth++; document.body.classList.add('dragging'); } });
    window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => {
        e.preventDefault();
        dragDepth = 0;
        document.body.classList.remove('dragging');
        if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]);
    });

    // Keep the live duration ticking between snapshots
    setInterval(() => { if (status && status.capturing) updateChrome(); }, 1000);
})();
