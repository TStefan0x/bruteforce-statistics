import re
import subprocess
from collections import Counter
from datetime import datetime

from flask import Flask, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit

LOG_FILE = '/var/log/auth.log'
PATTERNS = [
    re.compile(r"Failed password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port \d+)?"),
    re.compile(r"Invalid user (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
]

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

limiter = Limiter(key_func=get_remote_address, default_limits=["100 per minute"])
limiter.init_app(app)

socketio = SocketIO(app, cors_allowed_origins='*')

# Parse entire log, group by user, ip, and by hour

def get_known_ips():
    try:
        output = subprocess.check_output(['last', '-i'], stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return set()
    ips = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[2]):
            ips.add(parts[2])
    return ips


def compute_stats():
    known_ips = get_known_ips()
    user_counts = Counter()
    ip_counts = Counter()
    hourly_counts = Counter()

    try:
        with open(LOG_FILE, 'r', errors='ignore') as f:
            for line in f:
                # extract timestamp hour from line
                parts = line.split()
                if len(parts) < 3:
                    continue
                # example: 'Jun 22 08:15:20'
                timestamp_str = ' '.join(parts[:3])
                try:
                    dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                    hour_label = dt.strftime('%Y-%m-%d %H:00')
                except ValueError:
                    continue
                for pat in PATTERNS:
                    m = pat.search(line)
                    if m:
                        ip = m.group('ip')
                        user = m.group('user')
                        if ip not in known_ips:
                            user_counts[user] += 1
                            ip_counts[ip] += 1
                            hourly_counts[hour_label] += 1
    except Exception:
        pass

    return {
        'top_users': [{'user': u, 'count': c} for u, c in user_counts.most_common(10)],
        'top_ips': [{'ip': ip, 'count': c} for ip, c in ip_counts.most_common(10)],
        'hourly': [{'time': t, 'count': c} for t, c in sorted(hourly_counts.items())]
    }

@app.route('/data')
@limiter.limit("10 per second")
def data():
    stats = compute_stats()
    return jsonify(stats)

@socketio.on('connect')
def handle_connect():
    emit('update', compute_stats())


def background_updates():
    while True:
        socketio.sleep(3)
        socketio.emit('update', compute_stats())

TEMPLATE = '''<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>SSH Attack Visualizer</title>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">SSH Visualizer</a>
      <button class="btn btn-outline-secondary" id="toggle-theme">Toggle Theme</button>
    </div>
  </nav>
  <div class="container py-4">
    <div class="row mb-4" id="summary-cards"></div>
    <div class="row">
      <div class="col-md-6 mb-4">
        <div class="card"><div class="card-header">Top Users</div><div class="card-body"><canvas id="userChart"></canvas></div></div>
      </div>
      <div class="col-md-6 mb-4">
        <div class="card"><div class="card-header">Top IPs</div><div class="card-body"><canvas id="ipChart"></canvas></div></div>
      </div>
      <div class="col-12">
        <div class="card"><div class="card-header">Hourly Attempts</div><div class="card-body"><canvas id="timeChart"></canvas></div></div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.socket.io/4.4.1/socket.io.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const socket = io();
    let userChart, ipChart, timeChart;
    document.getElementById('toggle-theme').onclick = () => {
      const doc = document.documentElement;
      doc.setAttribute('data-bs-theme', doc.getAttribute('data-bs-theme') === 'light' ? 'dark' : 'light');
    };
    function renderSummary(data) {
      const totalFails = data.top_users.reduce((sum, u) => sum + u.count, 0);
      const uniqueIPs = data.top_ips.length;
      const hours = data.hourly.length;
      document.getElementById('summary-cards').innerHTML = `
        <div class="col-md-4"><div class="card text-center p-3">Total Fails<br><h2>${totalFails}</h2></div></div>
        <div class="col-md-4"><div class="card text-center p-3">Unique IPs<br><h2>${uniqueIPs}</h2></div></div>
        <div class="col-md-4"><div class="card text-center p-3">Hours<br><h2>${hours}</h2></div></div>
      `;
    }
    function updateCharts(data) {
      const users = data.top_users.map(x => x.user);
      const ucounts = data.top_users.map(x => x.count);
      const ips = data.top_ips.map(x => x.ip);
      const icounts = data.top_ips.map(x => x.count);
      const times = data.hourly.map(x => x.time);
      const tcounts = data.hourly.map(x => x.count);
      if (!userChart) userChart = new Chart(document.getElementById('userChart'), {type:'bar', data:{labels:users, datasets:[{label:'Users', data:ucounts}]}, options:{responsive:true}});
      else { userChart.data.labels = users; userChart.data.datasets[0].data = ucounts; userChart.update(); }
      if (!ipChart) ipChart = new Chart(document.getElementById('ipChart'), {type:'bar', data:{labels:ips, datasets:[{label:'IPs', data:icounts}]}, options:{responsive:true}});
      else { ipChart.data.labels = ips; ipChart.data.datasets[0].data = icounts; ipChart.update(); }
      if (!timeChart) timeChart = new Chart(document.getElementById('timeChart'), {type:'line', data:{labels:times, datasets:[{label:'Hourly', data:tcounts, fill:false}]}, options:{responsive:true}});
      else { timeChart.data.labels = times; timeChart.data.datasets[0].data = tcounts; timeChart.update(); }
    }
    socket.on('update', data => { renderSummary(data); updateCharts(data); });
  </script>
</body>
</html>'''

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

if __name__ == '__main__':
    socketio.start_background_task(background_updates)
    socketio.run(app, host='0.0.0.0', port=5000)
