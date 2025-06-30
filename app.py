# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import datetime
from scanner import scan
import psutil
import time
import sqlite3
import subprocess
import threading
import os

app = Flask(__name__)
app.secret_key = "icsguard-secret"

scan_results = []
last_scan_time = None
active_detection = None  

@app.route('/modify_rule', methods=['POST'])
def modify_rule():
    ip = request.form['target_ip']
    router_ip = request.form['router_ip']
    action = request.form['action']

    # You could check active spoofed IPs here
    if action == 'block':
        block_ip(ip)
        flash(f"Blocked internet for {ip}", "warning")
    elif action == 'isolate':
        isolate_node(ip, router_ip)
        flash(f"Isolated {ip} from LAN", "info")
    elif action == 'unblock':
        unblock_ip(ip)
        flash(f"Unblocked {ip}", "success")

    return redirect(url_for('dashboard'))


@app.route('/alerts/live')
def live_alerts():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp || ' - ' || event FROM alerts ORDER BY id DESC LIMIT 5")
    alerts = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)


def init_db():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event TEXT,
            severity TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_alerts_from_db():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp || ' - ' || event FROM alerts ORDER BY id DESC LIMIT 5")
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def get_all_alerts():
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, event, severity FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"time": row[0], "event": row[1], "severity": row[2]} for row in rows]

@app.route('/start_detection', methods=['POST'])
def start_detection():
    global active_detection

    victim_ip = request.form['victim_ip']
    router_ip = request.form['router_ip']

    try:
        subprocess.Popen(["python3", "arp_spoofer.py", victim_ip, router_ip])
        subprocess.Popen(["python3", "dns_sniffer.py", victim_ip])

        active_detection = victim_ip
        flash(f"Phishing detection started for {victim_ip}.", "success")
    except Exception as e:
        flash(f"Failed to start detection: {e}", "danger")

    return redirect(url_for('dashboard'))

@app.route('/stop_detection', methods=['POST'])
def stop_detection():
    global active_detection

    try:
        # Gracefully stop processes
        with open("/tmp/stop_spoofing", "w") as f:
            f.write("stop")

        subprocess.call(["pkill", "-f", "dns_sniffer.py"])

        flash("Phishing detection stopped and ARP tables restored.", "info")
        active_detection = None
    except Exception as e:
        flash(f"Failed to stop detection: {e}", "danger")

    return redirect(url_for('dashboard'))


@app.route('/', methods=['GET', 'POST'])
def dashboard():
    init_db()
    global scan_results, last_scan_time

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'scan':
            subnet = request.form.get('subnet', '192.168.1.1/24')
            print(f"[ACTION] Scanning network: {subnet}")
            scan_results = scan(subnet)
            print(scan_results)
            last_scan_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            flash(f"Scan complete. Found {len(scan_results)} device(s).", "success")

        elif action == 'block_ip':
            ip_to_block = request.form.get('block_ip')
            if ip_to_block:
                subprocess.call(["iptables", "-A", "INPUT", "-s", ip_to_block, "-j", "DROP"])
                flash(f"Blocked IP: {ip_to_block}", "warning")

        elif action == 'unblock_ip':
            ip_to_unblock = request.form.get('block_ip')
            if ip_to_unblock:
                subprocess.call(["iptables", "-D", "INPUT", "-s", ip_to_unblock, "-j", "DROP"])
                flash(f"Unblocked IP: {ip_to_unblock}", "info")

        elif action == 'isolate':
            ip_to_isolate = request.form.get('block_ip')
            if ip_to_isolate:
                subprocess.call(["iptables", "-A", "INPUT", "-s", ip_to_isolate, "-j", "DROP"])
                subprocess.call(["iptables", "-A", "OUTPUT", "-d", ip_to_isolate, "-j", "DROP"])
                flash(f"Isolated node: {ip_to_isolate}", "danger")

        elif action == 'unisolate':
            ip_to_unisolate = request.form.get('block_ip')
            if ip_to_unisolate:
                subprocess.call(["iptables", "-D", "INPUT", "-s", ip_to_unisolate, "-j", "DROP"])
                subprocess.call(["iptables", "-D", "OUTPUT", "-d", ip_to_unisolate, "-j", "DROP"])
                flash(f"Removed isolation for: {ip_to_unisolate}", "info")

        elif action == 'start_detection':
            victim_ip = request.form.get('victim_ip')
            router_ip = request.form.get('router_ip', '192.168.1.1')  # Default if not provided
            if victim_ip and router_ip:
                try:
                    subprocess.Popen(["python3", "arp_spoofer.py", victim_ip, router_ip])
                    flash(f"Started ARP spoofing for {victim_ip}.", "success")
                except Exception as e:
                    flash(f"Error starting spoofing: {e}", "danger")
            else:
                flash("Both victim and router IP are required.", "danger")




        elif action == 'start_arp_sniff':
            target = request.form.get('target_ip')
            gateway = request.form.get('gateway_ip')
            if target and gateway:
                threading.Thread(target=start_arp_sniffer, args=(target, gateway)).start()
                flash("Started ARP poisoning and DNS monitoring.", "info")

        return redirect(url_for('dashboard'))

    data = {
        "alerts": get_alerts_from_db(),
        "logs": get_all_alerts(),
        "scan_results": scan_results,
        "last_scan_time": last_scan_time,
        "active_detection": active_detection
    }
    return render_template("dashboard.html", data=data)

@app.route('/logs')
def logs():
    init_db()
    conn = sqlite3.connect("phishguard.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, event, severity FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template("logs.html", logs=rows)

def block_ip(ip):
    subprocess.call(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"])

def isolate_node(ip, router_ip):
    # Allow only router traffic
    subprocess.call(["iptables", "-A", "FORWARD", "-s", ip, "-d", router_ip, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-s", ip, "-d", "192.168.1.0/24", "!", "-d", router_ip, "-j", "DROP"])

def unblock_ip(ip):
    subprocess.call(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.call(["iptables", "-F"])  # (optional: flush all FORWARD rules if needed)


def start_arp_sniffer(target_ip, gateway_ip):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    from scapy.all import sniff, DNSQR, ARP, send, Ether

    with open("phish_domains.txt") as f:
        phishing_domains = set(domain.strip().lower() for domain in f)

    def log_alert(event, severity="High"):
        conn = sqlite3.connect("phishguard.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (timestamp, event, severity) VALUES (?, ?, ?)",
                       (time.strftime('%Y-%m-%d %H:%M:%S'), event, severity))
        conn.commit()
        conn.close()

    def get_mac(ip):
        from scapy.all import srp
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = srp(broadcast/arp_request, timeout=2, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
        return None

    def spoof(target, spoof_ip):
        mac = get_mac(target)
        if mac:
            pkt = Ether(dst=mac)/ARP(op=2, pdst=target, hwdst=mac, psrc=spoof_ip)
            send(pkt, verbose=False)

    def monitor_dns(pkt):
        if pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode().strip('.').lower()
            for bad_domain in phishing_domains:
                if bad_domain in domain:
                    print(f"[ALERT] Matched phishing domain: {domain}")
                    log_alert(f"Phishing domain query: {domain}", "High")
                    break


    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sniff(filter="udp port 53", prn=monitor_dns, store=0, count=1)
        time.sleep(2)

if __name__ == '__main__':
    app.run(debug=True)