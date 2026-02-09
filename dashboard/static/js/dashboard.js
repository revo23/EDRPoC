// EDR Dashboard JavaScript
(function() {
    'use strict';

    // State
    let socket = null;
    let alertTimelineChart = null;
    let severityChart = null;
    let weightsChart = null;
    let refreshInterval = null;
    let startTime = Date.now();

    // Initialize
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        initSocket();
        initTabs();
        initCharts();
        refreshAll();
        refreshInterval = setInterval(refreshAll, 5000);
        setInterval(updateUptime, 1000);
        drawHealthGauge(100);
    }

    // WebSocket
    function initSocket() {
        socket = io();

        socket.on('connect', function() {
            document.getElementById('sensorStatus').classList.add('green');
        });

        socket.on('disconnect', function() {
            document.getElementById('sensorStatus').classList.remove('green');
        });

        socket.on('new_alert', function(alert) {
            prependAlert(alert, true);
            refreshAlertStats();
        });

        socket.on('process_update', function(data) {
            // Refresh process table if on that tab
            if (document.getElementById('tab-processes').classList.contains('active')) {
                refreshProcesses();
            }
        });

        socket.on('ml_score_update', function(data) {
            if (data && data.threat_score !== undefined) {
                updateHealthScore(data.threat_score);
            }
        });
    }

    // Tabs
    function initTabs() {
        document.querySelectorAll('.tab-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var tab = this.dataset.tab;
                document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
                document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
                this.classList.add('active');
                document.getElementById('tab-' + tab).classList.add('active');

                if (tab === 'processes') refreshProcesses();
                else if (tab === 'ml') refreshMLMetrics();
                else if (tab === 'mitre') refreshMitre();
                else if (tab === 'response') refreshResponseLog();
            });
        });

        // Alert filters
        document.getElementById('alertSeverityFilter').addEventListener('change', refreshAlerts);
        document.getElementById('alertStatusFilter').addEventListener('change', refreshAlerts);
    }

    // Charts
    function initCharts() {
        var timelineCtx = document.getElementById('alertTimeline');
        if (timelineCtx) {
            alertTimelineChart = new Chart(timelineCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Events',
                        data: [],
                        backgroundColor: 'rgba(59,130,246,0.5)',
                        borderColor: 'rgba(59,130,246,1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            ticks: { color: '#6b7280', font: { size: 10 }, maxTicksLimit: 12 },
                            grid: { color: 'rgba(45,58,77,0.5)' }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#6b7280', font: { size: 10 } },
                            grid: { color: 'rgba(45,58,77,0.5)' }
                        }
                    }
                }
            });
        }

        var sevCtx = document.getElementById('severityChart');
        if (sevCtx) {
            severityChart = new Chart(sevCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#9ca3af', font: { size: 11 } }
                        }
                    }
                }
            });
        }

        var wCtx = document.getElementById('weightsChart');
        if (wCtx) {
            weightsChart = new Chart(wCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Isolation Forest', 'Autoencoder', 'Behavioral'],
                    datasets: [{
                        data: [40, 40, 20],
                        backgroundColor: ['#3b82f6', '#8b5cf6', '#f97316'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#9ca3af', font: { size: 11 } }
                        }
                    }
                }
            });
        }
    }

    // Refresh functions
    function refreshAll() {
        refreshAlertStats();
        refreshAlerts();
        refreshTimeline();
    }

    function refreshAlertStats() {
        fetch('/api/alerts/stats')
            .then(function(r) { return r.json(); })
            .then(function(stats) {
                document.getElementById('statCritical').textContent = stats.critical || 0;
                document.getElementById('statHigh').textContent = stats.high || 0;
                document.getElementById('statMedium').textContent = stats.medium || 0;
                document.getElementById('statLow').textContent = stats.low || 0;
                document.getElementById('statTotal').textContent = stats.total || 0;

                var total = (stats.critical || 0) + (stats.high || 0) + (stats.medium || 0);
                var health = Math.max(0, 100 - total * 5);
                drawHealthGauge(health);
            })
            .catch(function() {});
    }

    function refreshAlerts() {
        var severity = document.getElementById('alertSeverityFilter').value;
        var status = document.getElementById('alertStatusFilter').value;
        var url = '/api/alerts?limit=50';
        if (severity) url += '&severity=' + severity;
        if (status) url += '&status=' + status;

        fetch(url)
            .then(function(r) { return r.json(); })
            .then(function(alerts) {
                var list = document.getElementById('alertList');
                if (!alerts.length) {
                    list.innerHTML = '<div class="empty-state">Monitoring... No alerts yet.</div>';
                    return;
                }
                list.innerHTML = '';
                alerts.forEach(function(alert) { prependAlert(alert, false); });
            })
            .catch(function() {});
    }

    function prependAlert(alert, isNew) {
        var list = document.getElementById('alertList');
        var empty = list.querySelector('.empty-state');
        if (empty) empty.remove();

        var div = document.createElement('div');
        div.className = 'alert-item' + (isNew ? ' new' : '');
        var severity = alert.severity || 'info';
        var ts = alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleTimeString() : '';
        var score = (alert.threat_score || 0).toFixed(1);
        var mitre = alert.mitre_technique || '';

        div.innerHTML =
            '<div class="alert-severity ' + severity + '"></div>' +
            '<div class="alert-body">' +
                '<div class="alert-header-row">' +
                    '<span class="alert-rule">' + escHtml(alert.rule_id || 'ALERT') + '</span>' +
                    '<span class="alert-time">' + ts + '</span>' +
                '</div>' +
                '<div class="alert-desc">' + escHtml(alert.description || '') + '</div>' +
                '<div class="alert-meta">' +
                    '<span class="alert-tag ' + severity + '">' + severity.toUpperCase() + '</span>' +
                    '<span>Score: ' + score + '</span>' +
                    (alert.process_name ? '<span>Process: ' + escHtml(alert.process_name) + ' (PID ' + (alert.process_pid || '') + ')</span>' : '') +
                    (mitre ? '<span>MITRE: ' + escHtml(mitre) + '</span>' : '') +
                '</div>' +
            '</div>' +
            '<div class="alert-actions">' +
                '<button class="btn-sm" onclick="acknowledgeAlert(' + (alert.id || 0) + ')">ACK</button>' +
                '<button class="btn-sm" onclick="resolveAlert(' + (alert.id || 0) + ')">Resolve</button>' +
                (alert.process_pid ? '<button class="btn-sm danger" onclick="killProcess(' + alert.process_pid + ')">Kill</button>' : '') +
            '</div>';

        if (isNew) {
            list.insertBefore(div, list.firstChild);
        } else {
            list.appendChild(div);
        }
    }

    function refreshTimeline() {
        fetch('/api/events/timeline?hours=1')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!alertTimelineChart || !data.length) return;
                var buckets = {};
                data.forEach(function(d) {
                    var label = new Date(d.bucket * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
                    buckets[label] = (buckets[label] || 0) + d.count;
                });
                alertTimelineChart.data.labels = Object.keys(buckets);
                alertTimelineChart.data.datasets[0].data = Object.values(buckets);
                alertTimelineChart.update('none');
            })
            .catch(function() {});
    }

    function refreshProcesses() {
        fetch('/api/processes')
            .then(function(r) { return r.json(); })
            .then(function(procs) {
                var tbody = document.getElementById('processTableBody');
                tbody.innerHTML = '';
                procs.forEach(function(p) {
                    var tr = document.createElement('tr');
                    var score = p.threat_score || 0;
                    var badgeClass = score >= 80 ? 'critical' : score >= 60 ? 'malicious' : score >= 30 ? 'suspicious' : 'normal';
                    tr.innerHTML =
                        '<td><span class="tree-pid">' + p.pid + '</span></td>' +
                        '<td>' + (p.ppid || '-') + '</td>' +
                        '<td>' + escHtml(p.name || '') + '</td>' +
                        '<td>' + escHtml(p.username || '') + '</td>' +
                        '<td><span class="threat-badge ' + badgeClass + '">' + score.toFixed(1) + '</span></td>' +
                        '<td>' +
                            '<button class="btn-sm" onclick="viewProcessTree(' + p.pid + ')">Tree</button> ' +
                            '<button class="btn-sm danger" onclick="killProcess(' + p.pid + ')">Kill</button>' +
                        '</td>';
                    tbody.appendChild(tr);
                });
            })
            .catch(function() {});
    }

    function refreshMLMetrics() {
        fetch('/api/ml/metrics')
            .then(function(r) { return r.json(); })
            .then(function(m) {
                var ifParams = m.isolation_forest || {};
                var aeParams = m.autoencoder || {};
                document.getElementById('ifStatus').textContent = ifParams.is_fitted ? 'Trained (' + (ifParams.samples_since_train || 0) + ' since)' : 'Not Trained';
                document.getElementById('aeStatus').textContent = aeParams.is_fitted ? 'Trained (' + (aeParams.samples_since_train || 0) + ' since)' : 'Not Trained';
                document.getElementById('samplesScored').textContent = m.samples_scored || 0;
                document.getElementById('avgThreatScore').textContent = (m.avg_threat_score || 0).toFixed(1);

                document.getElementById('ifStatus').style.color = ifParams.is_fitted ? '#22c55e' : '#ef4444';
                document.getElementById('aeStatus').style.color = aeParams.is_fitted ? '#22c55e' : '#ef4444';
                document.getElementById('mlStatus').classList.toggle('green', ifParams.is_fitted || aeParams.is_fitted);
                document.getElementById('mlStatus').classList.toggle('yellow', !ifParams.is_fitted && !aeParams.is_fitted);

                // Severity distribution
                if (severityChart && m.severity_distribution) {
                    var dist = m.severity_distribution;
                    severityChart.data.datasets[0].data = [
                        dist.critical || 0, dist.high || 0, dist.medium || 0,
                        dist.low || 0, dist.info || 0
                    ];
                    severityChart.update('none');
                }

                // Weights
                if (weightsChart && m.weights) {
                    weightsChart.data.datasets[0].data = [
                        (m.weights.isolation_forest || 0) * 100,
                        (m.weights.autoencoder || 0) * 100,
                        (m.weights.behavioral || 0) * 100
                    ];
                    weightsChart.update('none');
                }

                // Threat intel
                var ti = m.threat_intel || {};
                document.getElementById('tiHashes').textContent = ti.hashes || 0;
                document.getElementById('tiIPs').textContent = ti.ips || 0;
                document.getElementById('tiDomains').textContent = ti.domains || 0;
                document.getElementById('tiTotal').textContent = ti.total || 0;
            })
            .catch(function() {});
    }

    function refreshMitre() {
        fetch('/api/mitre/matrix')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var container = document.getElementById('mitreMatrix');
                container.innerHTML = '';
                var matrix = data.matrix || {};
                var coverage = data.coverage || {};

                var tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                    'Collection', 'Exfiltration', 'Command and Control', 'Impact'];

                tactics.forEach(function(tactic) {
                    var techniques = matrix[tactic] || [];
                    if (!techniques.length) return;

                    var tacticDiv = document.createElement('div');
                    tacticDiv.className = 'mitre-tactic';
                    var headerDiv = document.createElement('div');
                    headerDiv.className = 'mitre-tactic-header';
                    headerDiv.textContent = tactic;
                    tacticDiv.appendChild(headerDiv);

                    var techDiv = document.createElement('div');
                    techDiv.className = 'mitre-techniques';

                    techniques.forEach(function(t) {
                        var el = document.createElement('div');
                        el.className = 'mitre-technique';
                        var count = coverage[t.id] || 0;
                        if (count > 0) el.classList.add('detected');
                        el.innerHTML = '<span class="technique-id">' + t.id + '</span>' +
                            escHtml(t.name) +
                            (count > 0 ? '<span class="hit-count">(' + count + ')</span>' : '');
                        el.title = t.description;
                        techDiv.appendChild(el);
                    });

                    tacticDiv.appendChild(techDiv);
                    container.appendChild(tacticDiv);
                });
            })
            .catch(function() {});
    }

    function refreshResponseLog() {
        fetch('/api/response/log')
            .then(function(r) { return r.json(); })
            .then(function(log) {
                var container = document.getElementById('responseLog');
                if (!log.length) {
                    container.innerHTML = '<div class="empty-state">No response actions taken yet.</div>';
                    return;
                }
                container.innerHTML = '';
                log.forEach(function(entry) {
                    var icons = {kill_process: '&#9760;', quarantine_file: '&#128274;', suspend_process: '&#9208;', network_isolate: '&#128274;'};
                    var div = document.createElement('div');
                    div.className = 'response-item';
                    var ts = entry.timestamp ? new Date(entry.timestamp * 1000).toLocaleTimeString() : '';
                    div.innerHTML =
                        '<div class="response-icon">' + (icons[entry.action] || '&#8226;') + '</div>' +
                        '<div class="response-body">' +
                            '<div class="response-action">' + escHtml(entry.action || '') +
                                (entry.pid ? ' (PID ' + entry.pid + ')' : '') +
                                (entry.path ? ': ' + escHtml(entry.path) : '') +
                            '</div>' +
                            '<div class="response-detail">' + escHtml(entry.reason || '') + '</div>' +
                        '</div>' +
                        '<span class="response-status ' + (entry.success ? 'success' : 'failed') + '">' +
                            (entry.success ? 'Success' : (entry.error || 'Failed')) +
                        '</span>' +
                        '<span class="response-time">' + ts + '</span>';
                    container.appendChild(div);
                });
            })
            .catch(function() {});
    }

    // Health Gauge
    function drawHealthGauge(score) {
        var canvas = document.getElementById('healthGauge');
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        var cx = 40, cy = 40, r = 32;
        ctx.clearRect(0, 0, 80, 80);

        // Background arc
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI * 0.75, Math.PI * 2.25);
        ctx.strokeStyle = '#2d3a4d';
        ctx.lineWidth = 6;
        ctx.lineCap = 'round';
        ctx.stroke();

        // Score arc
        var pct = score / 100;
        var endAngle = Math.PI * 0.75 + pct * Math.PI * 1.5;
        var color = score >= 70 ? '#22c55e' : score >= 40 ? '#eab308' : '#ef4444';
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI * 0.75, endAngle);
        ctx.strokeStyle = color;
        ctx.lineWidth = 6;
        ctx.lineCap = 'round';
        ctx.stroke();

        var el = document.getElementById('healthScore');
        el.textContent = Math.round(score);
        el.style.color = color;
    }

    function updateHealthScore(threatScore) {
        var health = Math.max(0, 100 - threatScore);
        drawHealthGauge(health);
    }

    function updateUptime() {
        var seconds = Math.floor((Date.now() - startTime) / 1000);
        var h = Math.floor(seconds / 3600);
        var m = Math.floor((seconds % 3600) / 60);
        var s = seconds % 60;
        document.getElementById('uptime').textContent = 'Uptime: ' +
            String(h).padStart(2, '0') + ':' +
            String(m).padStart(2, '0') + ':' +
            String(s).padStart(2, '0');
    }

    // Global action functions
    window.killProcess = function(pid) {
        if (!confirm('Kill process ' + pid + '?')) return;
        fetch('/api/response/kill/' + pid, { method: 'POST' })
            .then(function(r) { return r.json(); })
            .then(function(result) {
                if (result.success) {
                    refreshProcesses();
                    refreshResponseLog();
                }
            });
    };

    window.viewProcessTree = function(pid) {
        fetch('/api/process/' + pid + '/tree')
            .then(function(r) { return r.json(); })
            .then(function(tree) {
                var container = document.getElementById('processTree');
                container.innerHTML = '';
                renderTreeNode(container, tree, 0);
            })
            .catch(function() {
                document.getElementById('processTree').innerHTML =
                    '<div class="empty-state">Could not load process tree.</div>';
            });
    };

    window.acknowledgeAlert = function(id) {
        fetch('/api/alerts/' + id + '/acknowledge', { method: 'POST' })
            .then(function() { refreshAlerts(); refreshAlertStats(); });
    };

    window.resolveAlert = function(id) {
        fetch('/api/alerts/' + id + '/resolve', { method: 'POST' })
            .then(function() { refreshAlerts(); refreshAlertStats(); });
    };

    function renderTreeNode(parent, node, depth) {
        if (!node) return;
        var div = document.createElement('div');
        div.className = 'tree-node';
        div.style.marginLeft = (depth * 20) + 'px';

        var score = node.threat_score || 0;
        var badgeClass = score >= 80 ? 'critical' : score >= 60 ? 'malicious' : score >= 30 ? 'suspicious' : 'normal';

        div.innerHTML =
            '<div class="tree-node-content">' +
                '<span class="tree-toggle">' + (node.children && node.children.length ? '&#9660;' : '&#8226;') + '</span>' +
                '<span class="tree-pid">' + node.pid + '</span>' +
                '<span class="tree-name">' + escHtml(node.name || '') + '</span>' +
                '<span class="threat-badge ' + badgeClass + '">' + score.toFixed(1) + '</span>' +
            '</div>';

        parent.appendChild(div);

        if (node.children) {
            node.children.forEach(function(child) {
                renderTreeNode(parent, child, depth + 1);
            });
        }
    }

    function escHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
})();
