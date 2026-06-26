
import asyncio
import os
import re
import json
import ssl
import socket
import urllib.request
from datetime import datetime
from rich.panel import Panel
from rich import box

from shared.ui import console
from shared.net import is_ip_address
from shared.config import EXPORTS_DIR, ensure_exports_dir

# ================= OSINT: SSL Inspector =================

async def get_ssl_info(target, is_ip=False):
    try:
        context = ssl.create_default_context()
        def fetch_ssl():
            with socket.create_connection((target, 443), timeout=5) as sock:
                sni = None if is_ip else target
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    return ssock.getpeercert()

        cert = await asyncio.to_thread(fetch_ssl)

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))

        not_after_ts  = ssl.cert_time_to_seconds(cert.get('notAfter', ''))
        not_before_ts = ssl.cert_time_to_seconds(cert.get('notBefore', ''))

        not_after_dt  = datetime.utcfromtimestamp(not_after_ts)
        not_before_dt = datetime.utcfromtimestamp(not_before_ts)

        days_left = (not_after_dt - datetime.utcnow()).days

        sans = []
        if 'subjectAltName' in cert:
            sans = [v for k, v in cert['subjectAltName'] if k == 'DNS'][:5]

        if days_left < 0: status = "expired"
        elif days_left <= 30: status = "warning"
        else: status = "valid"

        return {
            "issued_to":  subject.get('commonName', 'N/A'),
            "issuer":     issuer.get('organizationName', 'N/A'),
            "not_before": not_before_dt.strftime('%Y-%m-%d'),
            "not_after":  not_after_dt.strftime('%Y-%m-%d'),
            "days_left":  days_left,
            "sans":       sans,
            "status":     status,
            "is_ip":      is_ip,
            "error":      None
        }
    except (ConnectionRefusedError, OSError):
        msg = "Port 443 tidak terbuka (wajar untuk IP publik)" if is_ip else "Port 443 tidak terbuka (tidak support HTTPS)"
        return {"error": msg, "status": "error", "is_ip": is_ip, "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}
    except ssl.SSLError as e:
        msg = f"SSL Error (IP tidak support HTTPS langsung): {str(e)[:50]}" if is_ip else f"SSL Error: {str(e)[:60]}"
        return {"error": msg, "status": "error", "is_ip": is_ip, "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}
    except Exception as e:
        return {"error": str(e)[:60], "status": "error", "is_ip": is_ip, "issued_to": "N/A", "issuer": "N/A", "days_left": 0, "sans": []}

# ================= OSINT: DNS Deep Lookup =================

async def get_dns_records(domain):
    results = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
        "spf": False, "dmarc": False, "error": None
    }
    try:
        import dns.resolver
    except ImportError:
        results["error"] = "Library 'dnspython' belum terinstall.\nKetik: pip install dnspython"
        return results

    def fetch_record(rtype):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            if rtype == 'MX':
                return [f"{str(r.exchange).rstrip('.')} (priority {r.preference})" for r in answers]
            elif rtype == 'TXT':
                return [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]
            else:
                return [r.to_text() for r in answers]
        except Exception:
            return []

    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        results[rtype] = await asyncio.to_thread(fetch_record, rtype)

    results['spf']   = any('v=spf1' in txt.lower() for txt in results.get('TXT', []))

    def fetch_dmarc():
        try:
            dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            return True
        except Exception:
            return False

    results['dmarc'] = await asyncio.to_thread(fetch_dmarc)
    return results

# ================= OSINT: WHOIS Lookup =================

def _parse_whois_domain(raw):
    def _find(patterns, text):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val and val.lower() not in ('n/a', 'redacted for privacy', 'data protected', 'not disclosed'):
                    return val
        return "N/A"

    registrar  = _find([r'Registrar:\s*(.+)', r'registrar:\s*(.+)', r'Registrar Name:\s*(.+)'], raw)
    owner = _find([r'Registrant Organization:\s*(.+)', r'Registrant Name:\s*(.+)', r'registrant:\s*(.+)', r'owner:\s*(.+)', r'Organisation:\s*(.+)'], raw)
    country = _find([r'Registrant Country:\s*(.+)', r'country:\s*(.+)', r'Country:\s*(.+)'], raw)
    registered = _find([r'Creation Date:\s*(.+)', r'created:\s*(.+)', r'Created On:\s*(.+)', r'Registration Date:\s*(.+)', r'Domain Registration Date:\s*(.+)'], raw)
    
    if registered != "N/A": registered = registered[:10].replace('/', '-')
    
    expires = _find([r'Registry Expiry Date:\s*(.+)', r'Expiry Date:\s*(.+)', r'Expiration Date:\s*(.+)', r'expires:\s*(.+)', r'Registrar Registration Expiration Date:\s*(.+)'], raw)
    if expires != "N/A": expires = expires[:10].replace('/', '-')

    domain_age = None
    if registered != "N/A":
        try:
            reg_dt     = datetime.strptime(registered[:10], '%Y-%m-%d')
            domain_age = (datetime.utcnow() - reg_dt).days // 365
        except Exception:
            pass

    return {
        "registrar":  registrar, "registered": registered, "expires":    expires,
        "owner":      owner, "country":    country, "domain_age": domain_age,
        "error":      None, "source":     "whois CLI"
    }

def _parse_whois_ip(raw):
    def _find(patterns, text):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val: return val
        return "N/A"

    org = _find([r'OrgName:\s*(.+)', r'org-name:\s*(.+)', r'organisation:\s*(.+)', r'Organization:\s*(.+)', r'owner:\s*(.+)', r'NetName:\s*(.+)'], raw)
    country = _find([r'Country:\s*(.+)', r'country:\s*(.+)'], raw)
    cidr = _find([r'CIDR:\s*(.+)', r'inetnum:\s*(.+)', r'NetRange:\s*(.+)'], raw)

    rir = "N/A"
    for name in ('ARIN', 'APNIC', 'RIPE', 'LACNIC', 'AFRINIC'):
        if name.lower() in raw.lower():
            rir = name
            break

    abuse = _find([r'OrgAbuseEmail:\s*(.+)', r'abuse-mailbox:\s*(.+)', r'Abuse contact:\s*(.+)'], raw)

    return {"org": org, "country": country, "cidr": cidr, "rir": rir, "abuse": abuse, "error": None, "source": "whois CLI"}

async def _whois_cli(target):
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        raw = stdout.decode('utf-8', errors='ignore').strip()
        if len(raw) < 100 or "no match" in raw.lower() or "not found" in raw.lower():
            return None
        return raw
    except Exception:
        return None

async def _rdap_fallback_domain(domain):
    try:
        def fetch_rdap():
            req = urllib.request.Request(
                f"https://rdap.org/domain/{domain}",
                headers={'User-Agent': 'Mozilla/5.0 (Linux; Android 10)', 'Accept': 'application/rdap+json'}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode())

        data = await asyncio.to_thread(fetch_rdap)

        registrar = "N/A"
        owner     = "N/A"
        country   = "N/A"
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            vcard = entity.get('vcardArray', [None, []])[1]
            name  = "N/A"
            for field in vcard:
                if field[0] == 'fn':
                    name = field[3]
                    break
            if 'registrar' in roles:
                registrar = name
            if 'registrant' in roles:
                owner = name
                for field in vcard:
                    if field[0] == 'adr':
                        adr_val = field[3]
                        if isinstance(adr_val, list) and len(adr_val) >= 7:
                            country = adr_val[6] or "N/A"
                        break

        registered = "N/A"
        expires    = "N/A"
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date   = event.get('eventDate', '')[:10]
            if action == 'registration': registered = date
            elif action == 'expiration': expires = date

        domain_age = None
        if registered != "N/A":
            try:
                reg_dt     = datetime.strptime(registered, '%Y-%m-%d')
                domain_age = (datetime.utcnow() - reg_dt).days // 365
            except Exception:
                pass

        return {
            "registrar":  registrar, "registered": registered, "expires":    expires,
            "owner":      owner, "country":    country, "domain_age": domain_age,
            "error":      None, "source":     "RDAP"
        }

    except urllib.error.HTTPError as e:
        return {"error": f"RDAP tidak tersedia (HTTP {e.code})", "registrar": "N/A", "registered": "N/A", "expires": "N/A", "owner": "N/A", "country": "N/A", "domain_age": None, "source": "RDAP"}
    except Exception as e:
        return {"error": f"WHOIS/RDAP gagal: {str(e)[:80]}", "registrar": "N/A", "registered": "N/A", "expires": "N/A", "owner": "N/A", "country": "N/A", "domain_age": None, "source": "RDAP"}

async def get_whois_info(target, is_ip=False):
    raw = await _whois_cli(target)
    if is_ip:
        if raw: return _parse_whois_ip(raw)
        return {"org": "N/A", "country": "N/A", "cidr": "N/A", "rir": "N/A", "abuse": "N/A", "error": "whois CLI tidak tersedia. Ketik: pkg install whois", "source": "whois CLI"}
    else:
        if raw:
            parsed = _parse_whois_domain(raw)
            has_data = any(parsed.get(f, "N/A") != "N/A" for f in ("registrar", "registered", "owner"))
            if has_data: return parsed
            console.print(" [bold yellow][ ↩ ][/bold yellow] [yellow]whois CLI hasilnya kosong, coba RDAP...[/yellow]")
        return await _rdap_fallback_domain(target)

# ================= OSINT: HTTP & Risk =================

async def get_http_headers(target):
    try:
        def fetch_headers():
            for scheme in ('http', 'https'):
                try:
                    req = urllib.request.Request(f"{scheme}://{target}", headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        return dict(resp.headers)
                except Exception:
                    continue
            raise Exception("Koneksi ke target gagal")

        headers = await asyncio.to_thread(fetch_headers)
        h = {k.lower(): v for k, v in headers.items()}

        server     = h.get('server', '-')
        powered_by = h.get('x-powered-by', '-')

        security_headers = {
            'X-Frame-Options':         'x-frame-options' in h,
            'Strict-Transport-Sec':    'strict-transport-security' in h,
            'Content-Security-Policy': 'content-security-policy' in h,
            'X-Content-Type-Options':  'x-content-type-options' in h,
        }

        cdn = None
        srv = server.lower()
        if 'cloudflare' in srv: cdn = 'Cloudflare'
        elif 'cloudfront' in srv or 'x-amz-cf-id' in h: cdn = 'AWS CloudFront'
        elif 'akamai' in srv or 'x-akamai-transformed' in h: cdn = 'Akamai'
        elif 'fastly' in h.get('x-served-by', '').lower() or 'fastly' in srv: cdn = 'Fastly'
        elif 'x-sucuri-id' in h: cdn = 'Sucuri'

        return {"server": server, "powered_by": powered_by, "security_headers": security_headers, "cdn": cdn, "error": None}
    except Exception as e:
        return {"error": str(e)[:80], "server": "-", "powered_by": "-", "security_headers": {}, "cdn": None}

def calculate_risk_verdict(ssl_info, dns_info, whois_info, http_info, target, is_ip=False):
    issues    = []
    positives = []
    score     = 0

    ssl_status = ssl_info.get('status') if ssl_info else 'error'
    if ssl_status == 'expired':
        score += 40
        issues.append(f"SSL Expired ({abs(ssl_info.get('days_left', 0))} hari lalu) ⚠ KRITIKAL")
    elif ssl_status == 'warning':
        score += 20
        issues.append(f"SSL mau expired ({ssl_info.get('days_left', 0)} hari lagi)")
    elif ssl_status == 'error':
        if is_ip: issues.append("SSL via IP tidak tersedia (wajar, bukan indikator risiko)")
        else:
            score += 30
            issues.append("SSL tidak terdeteksi / tidak ada HTTPS")
    else: positives.append(f"SSL Valid ({ssl_info.get('days_left', 0)} hari lagi)")

    cdn = http_info.get('cdn') if http_info and not http_info.get('error') else None
    if cdn: positives.append(f"CDN/WAF: {cdn}")
    else:
        score += 5
        issues.append("Tidak ada CDN/WAF terdeteksi")

    if not is_ip and dns_info and not dns_info.get('error'):
        if dns_info.get('spf'): positives.append("SPF Configured")
        else:
            score += 15
            issues.append("Tidak ada SPF (rawan email spoofing)")
        if dns_info.get('dmarc'): positives.append("DMARC Configured")
        else:
            score += 10
            issues.append("Tidak ada DMARC")

    if http_info and not http_info.get('error'):
        sec     = http_info.get('security_headers', {})
        missing = sum(1 for v in sec.values() if not v)
        if missing == 0: positives.append("Security Headers lengkap")
        else:
            score += missing * 5
            issues.append(f"{missing} Security Header tidak ada")

    if not is_ip and whois_info and not whois_info.get('error'):
        age = whois_info.get('domain_age')
        if age is not None:
            if age < 1:
                score += 20
                issues.append("Domain sangat baru (< 1 tahun) — waspadai phishing")
            elif age >= 5: positives.append(f"Domain sudah lama ({age} tahun)")

    if score >= 50: risk_level, risk_color, risk_emoji = "HIGH",   "red",    "🔴"
    elif score >= 20: risk_level, risk_color, risk_emoji = "MEDIUM", "yellow", "🟡"
    else: risk_level, risk_color, risk_emoji = "LOW",    "green",  "🟢"

    return {"domain": target, "issues": issues, "positives": positives, "risk_level": risk_level, "risk_color": risk_color, "risk_emoji": risk_emoji, "risk_score": score, "cdn": cdn}

async def run_osint_recon_async(target):
    is_ip = is_ip_address(target)
    results = {"domain": target, "ips": [], "geo": {}, "ssl": {}, "dns": {}, "whois": {}, "http": {}, "risk": {}, "trace": "", "is_ip": is_ip}
    label = "IP" if is_ip else "Domain"

    with console.status(f"[bold cyan]Memulai rekon OSINT untuk {label}: {target}...[/bold cyan]", spinner="dots") as status:
        if is_ip:
            results["ips"] = [target]
            console.print(f" [bold cyan][ ℹ ][/bold cyan] [cyan]Target adalah IP address — mode IP aktif[/cyan]")
            try:
                def fetch_geo_ip():
                    req = urllib.request.Request(f"http://ip-api.com/json/{target}", headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=5) as response: return json.loads(response.read().decode())
                results["geo"] = await asyncio.to_thread(fetch_geo_ip)
                console.print(" [bold green][ ✔ ][/bold green] [yellow]Pelacakan GeoIP & ASN (Selesai)[/yellow]")
            except: results["geo"] = {"status": "fail"}
            
            results["ssl"] = await get_ssl_info(target, is_ip=True)
            results["dns"] = {"error": "DNS lookup tidak relevan untuk IP address", "skipped": True}
            results["whois"] = await get_whois_info(target, is_ip=True)
        else:
            try:
                _, _, ip_list = await asyncio.to_thread(socket.gethostbyname_ex, target)
                results["ips"] = ip_list
                console.print(" [bold green][ ✔ ][/bold green] [cyan]Resolusi DNS IP (Selesai)[/cyan]")
            except Exception as e: results["ips"] = []

            if results["ips"]:
                primary_ip = results["ips"][0]
                try:
                    def fetch_geo():
                        req = urllib.request.Request(f"http://ip-api.com/json/{primary_ip}", headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(req, timeout=5) as response: return json.loads(response.read().decode())
                    results["geo"] = await asyncio.to_thread(fetch_geo)
                    console.print(" [bold green][ ✔ ][/bold green] [yellow]Pelacakan GeoIP & ASN (Selesai)[/yellow]")
                except: results["geo"] = {"status": "fail"}

            results["ssl"] = await get_ssl_info(target, is_ip=False)
            results["dns"] = await get_dns_records(target)
            results["whois"] = await get_whois_info(target, is_ip=False)

        results["http"] = await get_http_headers(target)
        try:
            proc = await asyncio.create_subprocess_exec("traceroute", "-m", "15", "-w", "1", target, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            stdout, _ = await proc.communicate()
            trace_output = stdout.decode('utf-8', errors='ignore')
            if "not found" in trace_output.lower() or proc.returncode == 127: results["trace"] = "Perintah traceroute belum diinstall."
            else: results["trace"] = trace_output
        except: results["trace"] = "Perintah traceroute belum diinstall."

        results["risk"] = calculate_risk_verdict(results["ssl"], results["dns"], results["whois"], results["http"], target, is_ip=is_ip)
    return results

# ================= OSINT: UI & Export Functions =================

def draw_risk_verdict(risk_i):
    if not risk_i: return
    risk_level = risk_i.get("risk_level", "N/A")
    risk_color = risk_i.get("risk_color", "white")
    risk_emoji = risk_i.get("risk_emoji", "")
    risk_score = risk_i.get("risk_score", 0)
    issues     = risk_i.get("issues",    [])
    positives  = risk_i.get("positives", [])

    lines = [f" Tingkat Risiko : [{risk_color}]{risk_emoji} {risk_level}[/{risk_color}]  [dim](Score: {risk_score})[/dim]\n"]
    if positives:
        lines.append(" [bold green]✔ Positif:[/bold green]")
        for p in positives: lines.append(f"   [green]+[/green] {p}")
    if issues:
        lines.append("\n [bold red]✖ Perhatian:[/bold red]")
        for i in issues: lines.append(f"   [red]![/red] {i}")
    verdict_text = "\n".join(lines)
    console.print(Panel(verdict_text, title=f"[bold {risk_color}]⚡ Risk Verdict[/bold {risk_color}]", border_style=risk_color, expand=False))

def draw_osint_results(results):
    domain  = results.get("domain", "")
    ips     = results.get("ips",    [])
    geo     = results.get("geo",    {})
    ssl_i   = results.get("ssl",   {})
    dns_i   = results.get("dns",   {})
    whois_i = results.get("whois", {})
    http_i  = results.get("http",  {})
    risk_i  = results.get("risk",  {})
    trace   = results.get("trace",  "")
    is_ip   = results.get("is_ip", False)

    console.print(f"\n[bold magenta]{'='*10} Hasil Analisis OSINT: {domain} {'='*10}[/bold magenta]")

    ip_text = "\n".join([f" [green]➜[/green] {ip}" for ip in ips]) if ips else "[red]Tidak ada IP ditemukan / Resolusi gagal.[/red]"
    console.print(Panel(ip_text, title="[bold cyan]📡 Daftar IP Address[/bold cyan]", border_style="cyan", expand=False))

    if geo and geo.get("status") == "success":
        geo_text = (
            f" [bold]ISP/ASN  :[/bold] {geo.get('isp', 'N/A')} ({geo.get('as', 'N/A')})\n"
            f" [bold]Lokasi   :[/bold] {geo.get('city', 'N/A')}, {geo.get('regionName', 'N/A')}, {geo.get('country', 'N/A')}\n"
            f" [bold]Koordinat:[/bold] {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}"
        )
        console.print(Panel(geo_text, title="[bold yellow]🌍 GeoIP & Identitas Server[/bold yellow]", border_style="yellow", expand=False))

    if ssl_i.get("error"): ssl_text = f"[red]⚠  {ssl_i['error']}[/red]"
    else:
        status_map = {
            "valid":   f"[bold green]✔ Valid[/bold green] ({ssl_i.get('days_left', 0)} hari lagi)",
            "warning": f"[bold yellow]⚠ Segera Renew[/bold yellow] ({ssl_i.get('days_left', 0)} hari lagi)",
            "expired": f"[bold red]✖ EXPIRED[/bold red] ({abs(ssl_i.get('days_left', 0))} hari lalu)"
        }
        ssl_status = status_map.get(ssl_i.get("status", ""), "[dim]N/A[/dim]")
        sans_str   = ", ".join(ssl_i.get("sans", [])) if ssl_i.get("sans") else "[dim]N/A[/dim]"
        ssl_text = (
            f" [bold]Status     :[/bold] {ssl_status}\n"
            f" [bold]Issued To  :[/bold] {ssl_i.get('issued_to', 'N/A')}\n"
            f" [bold]Issuer     :[/bold] {ssl_i.get('issuer', 'N/A')}\n"
            f" [bold]Berlaku    :[/bold] {ssl_i.get('not_before', 'N/A')} s/d {ssl_i.get('not_after', 'N/A')}\n"
            f" [bold]SANs       :[/bold] {sans_str}"
        )
    ssl_border = {"valid": "green", "warning": "yellow", "expired": "red", "error": "red"}.get(ssl_i.get("status", "error"), "red")
    console.print(Panel(ssl_text, title="[bold cyan]🔒 SSL Certificate Inspector[/bold cyan]", border_style=ssl_border, expand=False))

    if is_ip:
        console.print(Panel("[dim]DNS lookup dilewati — input adalah IP address.[/dim]", title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]", border_style="dim", expand=False))
    elif dns_i.get("error"):
        console.print(Panel(f"[red]{dns_i['error']}[/red]", title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]", border_style="red", expand=False))
    else:
        dns_lines = []
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            recs = dns_i.get(rtype, [])
            if recs:
                dns_lines.append(f" [bold cyan][{rtype}][/bold cyan]")
                for r in recs:
                    display = r[:65] + "..." if len(r) > 65 else r
                    dns_lines.append(f"   [dim]➜[/dim] {display}")
        spf_str   = "[green]Ada ✔[/green]"      if dns_i.get("spf")   else "[red]Tidak ada ✖[/red]"
        dmarc_str = "[green]Ada ✔[/green]"      if dns_i.get("dmarc") else "[red]Tidak ada ✖[/red]"
        dns_lines.append(f"\n [bold]SPF  :[/bold] {spf_str}   [bold]DMARC:[/bold] {dmarc_str}")
        dns_text = "\n".join(dns_lines) if dns_lines else "[dim]Tidak ada record ditemukan.[/dim]"
        console.print(Panel(dns_text, title="[bold magenta]🔎 DNS Deep Lookup[/bold magenta]", border_style="magenta", expand=False))

    if whois_i.get("error"):
        whois_text  = f"[red]{whois_i['error']}[/red]"
        whois_title = "[bold yellow]📋 WHOIS[/bold yellow]"
    elif is_ip:
        whois_text = (
            f" [bold]Organisasi :[/bold] {whois_i.get('org',     'N/A')}\n"
            f" [bold]Negara     :[/bold] {whois_i.get('country', 'N/A')}\n"
            f" [bold]CIDR/Range :[/bold] {whois_i.get('cidr',    'N/A')}\n"
            f" [bold]RIR        :[/bold] {whois_i.get('rir',     'N/A')}\n"
            f" [bold]Abuse      :[/bold] {whois_i.get('abuse',   'N/A')}\n"
            f" [bold]Sumber     :[/bold] [dim]{whois_i.get('source', 'N/A')}[/dim]"
        )
        whois_title = "[bold yellow]📋 WHOIS IP Info[/bold yellow]"
    else:
        age       = whois_i.get("domain_age")
        age_str   = f"{age} tahun" if age is not None else "N/A"
        age_color = "green" if (age and age >= 5) else ("yellow" if (age and age >= 1) else "red")
        whois_text = (
            f" [bold]Registrar  :[/bold] {whois_i.get('registrar',  'N/A')}\n"
            f" [bold]Owner      :[/bold] {whois_i.get('owner',      'N/A')}\n"
            f" [bold]Negara     :[/bold] {whois_i.get('country',    'N/A')}\n"
            f" [bold]Registered :[/bold] {whois_i.get('registered', 'N/A')}\n"
            f" [bold]Expires    :[/bold] {whois_i.get('expires',    'N/A')}\n"
            f" [bold]Usia Domain:[/bold] [{age_color}]{age_str}[/{age_color}]\n"
            f" [bold]Sumber     :[/bold] [dim]{whois_i.get('source', 'N/A')}[/dim]"
        )
        whois_title = "[bold yellow]📋 WHOIS Lookup[/bold yellow]"

    console.print(Panel(whois_text, title=whois_title, border_style="yellow", expand=False))

    if http_i.get("error"): http_text = f"[red]{http_i['error']}[/red]"
    else:
        cdn     = http_i.get("cdn")
        cdn_str = f"[bold green]{cdn}[/bold green]" if cdn else "[dim]Tidak terdeteksi[/dim]"
        sec     = http_i.get("security_headers", {})
        sec_lines = []
        for hname, hval in sec.items():
            marker = "[green]✔[/green]" if hval else "[red]✖[/red]"
            sec_lines.append(f"   {marker} {hname}")
        http_text = (
            f" [bold]Server     :[/bold] {http_i.get('server', '-')}\n"
            f" [bold]Powered By :[/bold] {http_i.get('powered_by', '-')}\n"
            f" [bold]CDN / WAF  :[/bold] {cdn_str}\n"
            f" [bold]Security Headers:[/bold]\n"
            + "\n".join(sec_lines)
        )
    console.print(Panel(http_text, title="[bold green]🌐 HTTP Header Fingerprinting[/bold green]", border_style="green", expand=False))

    trace_display = trace.strip() if trace.strip() else "[dim]Tidak tersedia.[/dim]"
    console.print(Panel(trace_display, title="[bold green]🗺  Jalur Rute Jaringan (Traceroute)[/bold green]", border_style="green", expand=False))
    draw_risk_verdict(risk_i)

def check_export_limit():
    ensure_exports_dir()
    files = [f for f in os.listdir(EXPORTS_DIR) if f.startswith("osint_")]
    if len(files) >= 20:
        console.print(f"\n[bold yellow]⚠️  Ada {len(files)} file export di folder exports/[/bold yellow]")
        confirm = input(" Hapus semua file lama? [y/N]: ").strip().lower()
        if confirm == 'y':
            for f in files: os.remove(os.path.join(EXPORTS_DIR, f))
            console.print("[bold green]✅ File lama dihapus.[/bold green]")

def draw_export_prompt():
    console.print("\n[bold cyan]💾 Export Hasil OSINT?[/bold cyan]")
    console.print("   [bold green]1.[/bold green] Export ke JSON")
    console.print("   [bold yellow]2.[/bold yellow] Export ke TXT")
    console.print("   [bold red]0.[/bold red] Lewati / Tidak export")
    choice = input("\n ➜ Pilih format export [1/2/0]: ").strip()
    if choice == '1': return 'json'
    elif choice == '2': return 'txt'
    else: return None

def export_osint_results(results, target, fmt):
    ensure_exports_dir()
    is_ip   = results.get("is_ip", False)
    safe_t  = re.sub(r'[^\w\-.]', '_', target)
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"osint_{safe_t}_{date_str}.{fmt}"
    filepath = os.path.join(EXPORTS_DIR, filename)

    ssl_i, dns_i, whois_i, http_i, risk_i, geo_i = results.get("ssl", {}), results.get("dns", {}), results.get("whois", {}), results.get("http", {}), results.get("risk", {}), results.get("geo", {})

    if fmt == 'json':
        if is_ip:
            whois_section = {"org": whois_i.get("org", "N/A"), "country": whois_i.get("country", "N/A"), "cidr": whois_i.get("cidr", "N/A"), "rir": whois_i.get("rir", "N/A"), "abuse": whois_i.get("abuse", "N/A"), "source": whois_i.get("source", "N/A")}
        else:
            whois_section = {"registrar": whois_i.get("registrar", "N/A"), "registered": whois_i.get("registered", "N/A"), "expires": whois_i.get("expires", "N/A"), "owner": whois_i.get("owner", "N/A"), "country": whois_i.get("country", "N/A"), "domain_age_tahun": whois_i.get("domain_age", None), "source": whois_i.get("source", "N/A")}

        export_data = {
            "target": target, "type": "IP" if is_ip else "Domain", "tanggal": datetime.now().strftime("%d %b %Y, %H:%M WIB"),
            "ip_addresses": results.get("ips", []),
            "geoip": {"isp": geo_i.get("isp", "N/A"), "as": geo_i.get("as", "N/A"), "kota": geo_i.get("city", "N/A"), "negara": geo_i.get("country","N/A")},
            "ssl": {"issued_to": ssl_i.get("issued_to", "N/A"), "issuer": ssl_i.get("issuer", "N/A"), "berlaku_dari": ssl_i.get("not_before", "N/A"), "berlaku_sampai": ssl_i.get("not_after", "N/A"), "sisa_hari": ssl_i.get("days_left", 0), "status": ssl_i.get("status", "N/A"), "sans": ssl_i.get("sans", [])},
            "dns": {"skipped": True} if is_ip else {"A": dns_i.get("A", []), "AAAA": dns_i.get("AAAA", []), "MX": dns_i.get("MX", []), "NS": dns_i.get("NS", []), "TXT": dns_i.get("TXT", []), "spf": dns_i.get("spf", False), "dmarc": dns_i.get("dmarc", False)},
            "whois": whois_section,
            "http_headers": {"server": http_i.get("server", "-"), "powered_by": http_i.get("powered_by", "-"), "cdn_waf": http_i.get("cdn", None), "security_headers": http_i.get("security_headers", {})},
            "risk_verdict": {"risk_level": risk_i.get("risk_level", "N/A"), "risk_score": risk_i.get("risk_score", 0), "issues": risk_i.get("issues", []), "positives": risk_i.get("positives", [])},
            "traceroute": results.get("trace", ""),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    elif fmt == 'txt':
        sep   = "=" * 45
        lines = [sep, f"  HASIL OSINT: {target} ({'IP' if is_ip else 'Domain'})", f"  Tanggal: {datetime.now().strftime('%d %b %Y, %H:%M WIB')}", sep, "", "[IP Address]"]
        for ip in results.get("ips", []): lines.append(f"  -> {ip}")
        lines.append("")

        if geo_i.get("status") == "success":
            lines.extend(["[GeoIP & ASN]", f"  ISP/ASN : {geo_i.get('isp', 'N/A')} ({geo_i.get('as', 'N/A')})", f"  Lokasi  : {geo_i.get('city', 'N/A')}, {geo_i.get('country', 'N/A')}", ""])

        lines.append("[SSL Certificate]")
        if ssl_i.get("error"): lines.append(f"  Info: {ssl_i['error']}")
        else:
            status_map = {"valid": f"Valid ({ssl_i.get('days_left', 0)} hari lagi)", "warning": f"Warning - Segera Renew ({ssl_i.get('days_left', 0)} hari lagi)", "expired": f"EXPIRED ({abs(ssl_i.get('days_left', 0))} hari lalu)"}
            lines.extend([f"  Issued to : {ssl_i.get('issued_to', 'N/A')}", f"  Issuer    : {ssl_i.get('issuer', 'N/A')}", f"  Berlaku   : {ssl_i.get('not_before', 'N/A')}", f"  Expires   : {ssl_i.get('not_after', 'N/A')}", f"  Status    : {status_map.get(ssl_i.get('status', ''), 'N/A')}"])
            if ssl_i.get("sans"): lines.append(f"  SANs      : {', '.join(ssl_i['sans'])}")
        lines.append("")

        if is_ip:
            lines.extend(["[DNS Records]", "  (Dilewati — input adalah IP address)", "", "[WHOIS IP]"])
            if whois_i.get("error"): lines.append(f"  Error: {whois_i['error']}")
            else: lines.extend([f"  Organisasi : {whois_i.get('org', 'N/A')}", f"  Negara     : {whois_i.get('country', 'N/A')}", f"  CIDR/Range : {whois_i.get('cidr', 'N/A')}", f"  RIR        : {whois_i.get('rir', 'N/A')}", f"  Abuse      : {whois_i.get('abuse', 'N/A')}", f"  Sumber     : {whois_i.get('source', 'N/A')}"])
        else:
            lines.append("[DNS Records]")
            if dns_i.get("error"): lines.append(f"  Error: {dns_i['error']}")
            else:
                for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    recs = dns_i.get(rtype, [])
                    if recs:
                        lines.append(f"  [{rtype}]")
                        for r in recs:
                            display = r[:70] + "..." if len(r) > 70 else r
                            lines.append(f"    -> {display}")
                lines.extend([f"  SPF   : {'Ada' if dns_i.get('spf') else 'Tidak ada'}", f"  DMARC : {'Ada' if dns_i.get('dmarc') else 'Tidak ada'}"])
            lines.extend(["", "[WHOIS Domain]"])
            if whois_i.get("error"): lines.append(f"  Error: {whois_i['error']}")
            else:
                lines.extend([f"  Registrar  : {whois_i.get('registrar', 'N/A')}", f"  Registered : {whois_i.get('registered', 'N/A')}", f"  Expires    : {whois_i.get('expires', 'N/A')}", f"  Owner      : {whois_i.get('owner', 'N/A')}", f"  Sumber     : {whois_i.get('source', 'N/A')}"])
                if whois_i.get('domain_age') is not None: lines.append(f"  Domain Age : {whois_i.get('domain_age')} tahun")
        lines.append("")

        lines.append("[HTTP Headers]")
        if http_i.get("error"): lines.append(f"  Error: {http_i['error']}")
        else:
            lines.extend([f"  Server   : {http_i.get('server', '-')}", f"  Tech     : {http_i.get('powered_by', '-')}", f"  CDN/WAF  : {http_i.get('cdn') if http_i.get('cdn') else 'Tidak terdeteksi'}"])
            for hname, hval in http_i.get('security_headers', {}).items(): lines.append(f"  {hname:25}: {'Ada' if hval else 'Tidak ada'}")
        lines.append("")

        lines.extend(["[Risk Verdict]", f"  Level : {risk_i.get('risk_emoji', '')} {risk_i.get('risk_level', 'N/A')} (Score: {risk_i.get('risk_score', 0)})"])
        for p in risk_i.get("positives", []): lines.append(f"  [+] {p}")
        for i in risk_i.get("issues", []): lines.append(f"  [!] {i}")
        lines.extend(["", "[Traceroute]", results.get("trace", "Tidak tersedia"), "", sep])

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    return filepath

async def run_osint_menu():
    console.print("\n")
    target_domain = input(" ➜ Masukkan Domain / IP Target (contoh: google.com atau 8.8.8.8): ").strip()

    if not target_domain:
        console.print("[bold red]Target tidak boleh kosong![/bold red]")
        console.print("\n[dim]----------------------------------------[/dim]")
        input(" Tekan [ENTER] untuk kembali ke menu...")
    else:
        osint_results = await run_osint_recon_async(target_domain)
        draw_osint_results(osint_results)
        
        console.print("\n[dim]----------------------------------------[/dim]")
        
        check_export_limit()
        export_fmt = draw_export_prompt()

        if export_fmt:
            try:
                filepath = export_osint_results(osint_results, target_domain, export_fmt)
                console.print(f"\n[bold green]✅ Hasil berhasil disimpan ke:[/bold green]")
                console.print(f"   [cyan]{filepath}[/cyan]")
            except Exception as e:
                console.print(f"[bold red]Gagal export: {e}[/bold red]")
        else:
            console.print("[dim]Export dilewati.[/dim]")

        console.print("\n[dim]----------------------------------------[/dim]")
        input(" Tekan [ENTER] untuk kembali ke menu...")


