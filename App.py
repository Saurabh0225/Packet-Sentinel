from flask import Flask, render_template, request, jsonify
import pandas as pd
import re

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        df = pd.read_csv(file)

        required_cols = {'Source', 'Destination', 'Protocol', 'Info'}
        if not required_cols.issubset(df.columns):
            return jsonify({
                "error": f"CSV must contain Source, Destination, Protocol, Info"
            }), 400

        # =========================
        # Extract Destination Port from Info column
        # =========================
        def extract_port(info):
            match = re.search(r'>\s*(\d+)', str(info))
            if match:
                return int(match.group(1))
            return None

        df['Destination_Port'] = df['Info'].apply(extract_port)

        # =========================
        # Summary Metrics
        # =========================
        total_packets = len(df)
        unique_sources = df['Source'].nunique()
        unique_destinations = df['Destination'].nunique()

        # =========================
        # Charts
        # =========================
        top_sources = df['Source'].value_counts().head(5)
        top_protocols = df['Protocol'].value_counts().head(5)

        # =========================
        # Alert Detection
        # =========================
        alerts = []

        # 🚨 Port Scan Detection
        port_scan = df.groupby('Source')['Destination_Port'].nunique()
        scanners = port_scan[port_scan > 20]

        for ip in scanners.index:
            alerts.append(f"Port Scan Detected from {ip}")

        # 🚨 Possible DoS
        heavy_traffic = df['Source'].value_counts()
        dos_ips = heavy_traffic[heavy_traffic > 1000]

        for ip in dos_ips.index:
            alerts.append(f"Possible DoS Attack from {ip}")

        # 🚨 Unusual Ports
        common_ports = [80, 443, 53, 22]
        unusual = df[df['Destination_Port'].notna() & 
                     ~df['Destination_Port'].isin(common_ports)]

        if not unusual.empty:
            alerts.append("Unusual Port Activity Detected")

        if not alerts:
            alerts.append("No Suspicious Activity Detected")

        return jsonify({
            "summary": {
                "total_packets": int(total_packets),
                "unique_sources": int(unique_sources),
                "unique_destinations": int(unique_destinations)
            },
            "top_sources": {
                "labels": top_sources.index.tolist(),
                "counts": top_sources.values.tolist()
            },
            "top_protocols": {
                "labels": top_protocols.index.tolist(),
                "counts": top_protocols.values.tolist()
            },
            "alerts": alerts
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)