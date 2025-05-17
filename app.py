import os
import subprocess
import platform
import whois
from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

# Safe websites for testing
SAFE_WEBSITES = [
    "http://testphp.vulnweb.com",
    "http://demo.testfire.net",
    "http://zero.webappsecurity.com",
    "http://xss-game.appspot.com",
    "http://google-gruyere.appspot.com"
]

# Use full path for scan history file
SCAN_HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'scan_history.txt')

#@app.route('/')
#def index():
#    return render_template('index.html', safe_sites=SAFE_WEBSITES)

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/index')
def index():
    return render_template('index.html', safe_sites=SAFE_WEBSITES)

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    scan_type = request.form.get('scan_type')
    result = ""

    if not url:
        return redirect(url_for('index'))

    try:
        clean_url = url.replace("http://", "").replace("https://", "").split('/')[0]

        if scan_type == "ping":
            if platform.system() == "Windows":
                result = subprocess.getoutput(f"ping -n 4 {clean_url}")
            else:
                result = subprocess.getoutput(f"ping -c 4 {clean_url}")

        elif scan_type == "sqlmap":
            command = f"python sqlmap/sqlmap.py -u {url} --batch --crawl=1"
            result = subprocess.getoutput(command)

        elif scan_type == "xss":
            command = f"python XSStrike/xsstrike.py -u {url} --crawl"
            result = subprocess.getoutput(command)

        elif scan_type == "dirsearch":
            command = f"python dirsearch/dirsearch.py -u {url}"
            result = subprocess.getoutput(command)

        elif scan_type == "nmap":
            result = subprocess.getoutput(f"nmap {clean_url}")

        elif scan_type == "whois":
            try:
                domain_info = whois.whois(clean_url)
                result = str(domain_info)
            except Exception as e:
                result = f"WHOIS scan failed: {str(e)}"

        else:
            result = "Invalid scan type selected."

        # Save to history file
        with open(SCAN_HISTORY_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {scan_type.upper()} scan on {url}\n")
            f.write(result + "\n\n")

    except Exception as e:
        result = f"❌ An error occurred during scanning: {str(e)}"

    return render_template('result.html', result=result, url=url, scan_type=scan_type)

@app.route('/history')
def history():
    entries = []
    if os.path.exists(SCAN_HISTORY_FILE):
        with open(SCAN_HISTORY_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for i in range(0, len(lines), 3):
            if i + 1 < len(lines):
                header = lines[i].strip()
                if ']' not in header or "on" not in header:
                    continue  # skip malformed lines

                try:
                    timestamp = header.split(']')[0][1:]
                    scan_info = header.split(']')[1].strip()
                    scan_type = scan_info.split()[0]
                    url = scan_info.split("on", 1)[1].strip()

                    entries.append({
                        'timestamp': timestamp,
                        'scan_type': scan_type,
                        'url': url
                    })
                except Exception:
                    continue  # skip this entry if parsing fails

    return render_template('history.html', history=entries)

@app.route('/delete_history', methods=['POST'])
def delete_history():
    if os.path.exists(SCAN_HISTORY_FILE):
        os.remove(SCAN_HISTORY_FILE)
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
