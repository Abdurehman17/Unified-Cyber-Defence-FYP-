// === 1. CHART CONFIGURATION ===
Chart.defaults.color = '#6c757d'; 
Chart.defaults.font.family = "'Roboto', sans-serif";
Chart.defaults.borderColor = '#dfe3e8'; 

const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const gradient = ctxTraffic.createLinearGradient(0, 0, 0, 300);
gradient.addColorStop(0, 'rgba(0, 86, 179, 0.3)');
gradient.addColorStop(1, 'rgba(0, 86, 179, 0.0)');

const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packets/sec',
            data: [],
            borderColor: '#0056b3',
            backgroundColor: gradient,
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            pointHoverRadius: 5
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { grid: { display: false } }, y: { beginAtZero: true } },
        animation: false
    }
});

const ctxProto = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP/Other'],
        datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#0056b3', '#003366', '#adb5bd'],
            borderWidth: 2,
            borderColor: '#ffffff'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } }
    }
});

// === 2. MAP INITIALIZATION ===
var map = L.map('threatMap').setView([30, 69], 3);
L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap', subdomains: 'abcd', maxZoom: 19
}).addTo(map);

var redIcon = new L.Icon({
    iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
    shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/images/marker-shadow.png',
    iconSize: [25, 41], iconAnchor: [12, 41], popupAnchor: [1, -34], shadowSize: [41, 41]
});
var mappedIPs = new Set();

// === 3. STATE ===
let uptimeSeconds = 0;
let uptimeInterval = null; 
let isMonitoring = false;

// === 4. CONTROL FUNCTIONS ===
function startSniffing() {
    isMonitoring = true; 
    uptimeSeconds = 0;
    
    document.getElementById('total-packets').innerText = "0";
    document.getElementById('threat-count').innerText = "0";
    document.getElementById('log-table-body').innerHTML = "";
    document.getElementById('threat-card-container').classList.remove('threat-card-active');
    document.getElementById('threat-count').classList.remove('threat-text-active');
    mappedIPs.clear(); 

    trafficChart.data.labels = [];
    trafficChart.data.datasets[0].data = [];
    trafficChart.update();
    protocolChart.data.datasets[0].data = [0, 0, 0];
    protocolChart.update();

    updateStatus("Monitoring Active", "active");
    const protEl = document.getElementById('protection-status-text');
    protEl.innerText = "Engaged";
    protEl.style.color = "#0056b3";

    if (uptimeInterval) clearInterval(uptimeInterval);
    uptimeInterval = setInterval(() => {
        uptimeSeconds++;
        const date = new Date(0);
        date.setSeconds(uptimeSeconds); 
        document.getElementById('uptime-counter').innerText = date.toISOString().substring(11, 19);
    }, 1000);

    fetch('/api/start', { method: 'POST' })
    .catch(err => { if(err.status === 401) window.location.reload(); });
}

function stopSniffing() {
    isMonitoring = false; 
    if (uptimeInterval) clearInterval(uptimeInterval);

    fetch('/api/stop', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            updateStatus("Monitoring Suspended", "alert");
            const protEl = document.getElementById('protection-status-text');
            protEl.innerText = "Inactive";
            protEl.style.color = "#6c757d";
        })
        .catch(err => window.location.reload());
}

function downloadReport() { window.location.href = "/api/download_report"; }

function updateStatus(text, type) {
    const el = document.getElementById('system-status');
    el.innerHTML = `<div class="status-dot"></div> <span>${text}</span>`;
    el.classList.remove('status-active', 'status-alert');
    if(type === 'active') el.classList.add('status-active');
    if(type === 'alert') el.classList.add('status-alert');
}

// === 5. SETTINGS ===
function openSettings() { document.getElementById('settingsModal').style.display = 'flex'; }
function closeSettings() { 
    document.getElementById('settingsModal').style.display = 'none'; 
    document.getElementById('oldPass').value = '';
    document.getElementById('newPass').value = '';
}
function savePassword() {
    const oldP = document.getElementById('oldPass').value;
    const newP = document.getElementById('newPass').value;
    if(!oldP || !newP) { alert("Both fields required."); return; }
    
    const formData = new FormData();
    formData.append('old_password', oldP);
    formData.append('new_password', newP);

    fetch('/change_password', { method: 'POST', body: formData })
    .then(res => res.json())
    .then(data => {
        if(data.status === 'success') {
            alert("Success! Please login again.");
            window.location.href = "/logout";
        } else { alert("Error: " + data.message); }
    });
}

// === 6. SMART TIMER ===
let inactivityTime = function () {
    let time;
    window.onload = resetTimer;
    document.onmousemove = resetTimer;
    document.onkeypress = resetTimer;
    document.ontouchstart = resetTimer;
    document.onclick = resetTimer;

    function logout() {
        if (isMonitoring) { resetTimer(); return; }
        window.location.href = '/logout';
    }
    function resetTimer() {
        clearTimeout(time);
        time = setTimeout(logout, 30000);
    }
};
inactivityTime();

// === 7. DATA LOOP ===
setInterval(() => {
    if (!isMonitoring) return; 

    fetch('/api/system_health').then(res => { if(res.status === 401) window.location.href = "/logout"; return res.json(); })
    .then(data => {
        if(document.getElementById('cpu-text')) {
            document.getElementById('cpu-text').innerText = data.cpu + "%";
            document.getElementById('cpu-bar').style.width = data.cpu + "%";
            document.getElementById('ram-text').innerText = data.ram + "%";
            document.getElementById('ram-bar').style.width = data.ram + "%";
        }
    });

    fetch('/api/data').then(res => res.json()).then(response => {
        const logs = response.logs;
        document.getElementById('total-packets').innerText = response.total_count.toLocaleString();
        const tableBody = document.getElementById('log-table-body');
        tableBody.innerHTML = ""; 

        logs.slice().reverse().slice(0, 50).forEach(log => {
            let row = `<tr><td>${log.timestamp}</td><td>${log.src}</td><td>${log.dst}</td><td>${log.protocol}</td><td>${log.payload}</td></tr>`;
            tableBody.innerHTML += row;
        });

        const protos = response.proto_counts;
        protocolChart.data.datasets[0].data = [protos.TCP, protos.UDP, protos.Other];
        protocolChart.update();

        const timeStr = new Date().toLocaleTimeString([], { hour12: false });
        if (trafficChart.data.labels.length > 30) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();
        }
        trafficChart.data.labels.push(timeStr);
        trafficChart.data.datasets[0].data.push(logs.length); 
        trafficChart.update();
    });

   fetch('/api/threats')
        .then(res => res.json())
        .then(data => {
            // === FIX: Use 'total' from backend, not array length ===
            const count = data.total;       // Takes the real DB count (e.g., 105)
            const threats = data.recent;    // Takes the list of 50 for the map
            
            const threatEl = document.getElementById('threat-count');
            const threatCard = document.getElementById('threat-card-container');
            
            threatEl.innerText = count;
            
            if (count > 0) {
                threatCard.classList.add('threat-card-active');
                threatEl.classList.add('threat-text-active');
                
                threats.forEach(threat => {
                    if (threat.geo && threat.geo.lat && threat.geo.lon && !mappedIPs.has(threat.ip)) {
                        L.marker([threat.geo.lat, threat.geo.lon], {icon: redIcon})
                            .addTo(map)
                            .bindPopup(`
                                <div style="color:#333; font-family: Roboto, sans-serif; text-align: center;">
                                    <h6 style="margin:0; font-weight:700; color: #d9534f;">THREAT BLOCKED</h6>
                                    <hr style="margin: 5px 0;">
                                    <b>IP:</b> ${threat.ip}<br>
                                    <b>Location:</b> ${threat.geo.city || 'Unknown'}, ${threat.geo.country || 'Unknown'}<br>
                                    <span style="font-size: 0.8rem;">${threat.attack_type}</span>
                                </div>
                            `);
                        mappedIPs.add(threat.ip); 
                    }
                });
            }
        });
}, 1000);