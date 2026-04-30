import requests
from bs4 import BeautifulSoup
import sys
import os
from urllib.parse import urlparse

def is_redirected_to_captive_portal(test_url="http://example.com"):
    try:
        resp = requests.get(test_url, allow_redirects=True, timeout=8)
        if resp.url != test_url:
            return True, resp.url, resp.text
        return False, resp.url, resp.text
    except Exception as e:
        return False, None, str(e)

def analyze_portal(url, html):
    soup = BeautifulSoup(html, "html.parser")
    findings = []
    # Check for login forms
    forms = soup.find_all("form")
    if not forms:
        findings.append("No forms detected on the portal page.")
    for form in forms:
        action = form.get("action", "")
        full_action = urlparse(action)
        # Check if form posts to HTTP (insecure)
        if full_action.scheme == "http":
            findings.append(f"Form posts to insecure HTTP: {action}")
        # Check if page itself is not HTTPS
        if not url.lower().startswith("https://"):
            findings.append("Portal page is not served over HTTPS.")
        # Check for password fields
        if form.find("input", {"type": "password"}):
            findings.append("Password field detected.")
        # Check for captcha
        if form.find("input", {"type": "captcha"}) or "captcha" in form.text.lower():
            findings.append("Captcha detected in form.")
    # Look for common security headers
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"
    ]
    headers_report = []
    for h in security_headers:
        headers_report.append(f"{h}: Not checked (requests can't get response headers after redirect)")
    return findings, headers_report

def main():
    print("[+] Checking for captive portal...")
    captive, portal_url, html = is_redirected_to_captive_portal()
    report = []
    if captive:
        report.append(f"Captive portal detected! Redirected to: {portal_url}")
        findings, headers_report = analyze_portal(portal_url, html)
        report.extend(findings)
        report.extend(headers_report)
    else:
        report.append("No captive portal detected. Internet access appears normal.")
    # Save report
    out_file = os.path.join(os.getcwd(), "captive_portal_report.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for line in report:
            f.write(line + "\n")
    print(f"[+] Report saved to {out_file}")
    print("\n--- Report ---\n" + "\n".join(report))

if __name__ == "__main__":
    main()
