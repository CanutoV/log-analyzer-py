import re
from collections import defaultdict

LOG_FILE = "sample-access.log"

# Limiares para alertas (Thresholds)
FAILED_LOGIN_THRESHOLD = 3
NOT_FOUND_THRESHOLD = 2

# Padrões suspeitos em URLs (SQLi, Path Traversal, etc.)
SUSPICIOUS_PATTERNS = [
    r"union\s+select",
    r"\.\./",
    r"/etc/passwd",
    r"<script>",
]

def analyze_logs(file_path):
    failed_logins = defaultdict(int)
    not_found_counts = defaultdict(int)
    suspicious_requests = []

    # Regex para capturar: IP, Método, URL, Código HTTP
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+- - \[.*?\] "(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/.*?"\s+(?P<status>\d+)'
    )

    with open(file_path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            match = log_pattern.search(line)
            if not match:
                continue

            ip = match.group("ip")
            url = match.group("url")
            status = match.group("status")

            # 1. Contagem de Falhas de Autenticação (HTTP 401)
            if status == "401":
                failed_logins[ip] += 1

            # 2. Contagem de Páginas Não Encontradas (HTTP 404)
            if status == "404":
                not_found_counts[ip] += 1

            # 3. Detecção de Padrões Suspeitos no Payload/URL
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    suspicious_requests.append({
                        "line": line_num,
                        "ip": ip,
                        "url": url,
                        "pattern": pattern
                    })

    # Exibição dos Resultados
    print("\n" + "="*50)
    print(" 🛡️  RELATÓRIO DE ANÁLISE DE LOGS & SEGURANÇA")
    print("="*50 + "\n")

    # Alerta de Brute Force
    print("[+] Análise de Tentativas de Brute Force (HTTP 401):")
    alerts_found = False
    for ip, count in failed_logins.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            print(f"  ⚠️  [ALERTA] IP {ip} excedeu o limite de falhas! Tentativas: {count}")
            alerts_found = True
    if not alerts_found:
        print("  Nenhum comportamento suspeito de brute force detectado.")

    # Alerta de Recon/Scan (404)
    print("\n[+] Análise de Mapeamento/Scan (HTTP 404):")
    alerts_found = False
    for ip, count in not_found_counts.items():
        if count >= NOT_FOUND_THRESHOLD:
            print(f"  ⚠️  [ALERTA] IP {ip} realizando scanner de diretórios! Erros 404: {count}")
            alerts_found = True
    if not alerts_found:
        print("  Nenhum scanner de diretórios detectado.")

    # Alerta de Payloads Suspeitos
    print("\n[+] Requisições com Padrões de Ataque Detectados:")
    if suspicious_requests:
        for req in suspicious_requests:
            print(f"  🚨 Line {req['line']} | IP: {req['ip']} | Pattern: '{req['pattern']}' | URL: {req['url']}")
    else:
        print("  Nenhuma assinatura de ataque encontrada.")

    print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    analyze_logs(LOG_FILE)
