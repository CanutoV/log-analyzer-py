import argparse
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote


LOG_FILE = "sample-access.log"
FAILED_LOGIN_THRESHOLD = 3
NOT_FOUND_THRESHOLD = 2

LOG_PATTERN = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+HTTP/\d(?:\.\d)?"\s+'
    r"(?P<status>\d{3})(?:\s|$)"
)
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
SUSPICIOUS_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("SQL injection (UNION SELECT)", re.compile(r"union\s+select", re.IGNORECASE)),
    ("Path traversal", re.compile(r"\.\./")),
    ("Sensitive file access (/etc/passwd)", re.compile(r"/etc/passwd", re.IGNORECASE)),
    ("Cross-site scripting (<script>)", re.compile(r"<script\b", re.IGNORECASE)),
)


@dataclass
class SuspiciousRequest:
    line: int
    ip: str
    url: str
    pattern: str


@dataclass
class AnalysisResult:
    total_requests: int
    unparsed_lines: int
    failed_logins: Dict[str, int]
    not_found_counts: Dict[str, int]
    failed_login_alerts: Dict[str, int]
    not_found_alerts: Dict[str, int]
    suspicious_requests: List[SuspiciousRequest]
    window_minutes: Optional[int]
    records_without_timestamp: int


def parse_timestamp(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return None


def _peak_counts(
    events: Dict[str, List[datetime]], window: timedelta
) -> Dict[str, int]:
    peaks: Dict[str, int] = {}
    for ip, timestamps in events.items():
        ordered = sorted(timestamps)
        current: Deque[datetime] = deque()
        peak = 0
        for timestamp in ordered:
            current.append(timestamp)
            while timestamp - current[0] > window:
                current.popleft()
            peak = max(peak, len(current))
        peaks[ip] = peak
    return peaks


def analyze_logs(
    file_path: str,
    failed_login_threshold: int = FAILED_LOGIN_THRESHOLD,
    not_found_threshold: int = NOT_FOUND_THRESHOLD,
    window_minutes: Optional[int] = None,
) -> AnalysisResult:
    if failed_login_threshold < 1 or not_found_threshold < 1:
        raise ValueError("Os limiares devem ser maiores que zero.")
    if window_minutes is not None and window_minutes < 1:
        raise ValueError("A janela deve ser maior que zero minutos.")

    failed_logins: Dict[str, int] = defaultdict(int)
    not_found_counts: Dict[str, int] = defaultdict(int)
    failed_events: Dict[str, List[datetime]] = defaultdict(list)
    not_found_events: Dict[str, List[datetime]] = defaultdict(list)
    suspicious_requests: List[SuspiciousRequest] = []
    total_requests = 0
    unparsed_lines = 0
    records_without_timestamp = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as log_file:
        for line_num, line in enumerate(log_file, start=1):
            match = LOG_PATTERN.search(line)
            if not match:
                unparsed_lines += 1
                continue

            total_requests += 1
            ip = match.group("ip")
            url = match.group("url")
            status = int(match.group("status"))
            timestamp = parse_timestamp(match.group("timestamp"))

            if timestamp is None:
                records_without_timestamp += 1

            if status == 401:
                failed_logins[ip] += 1
                if timestamp is not None:
                    failed_events[ip].append(timestamp)
            elif status == 404:
                not_found_counts[ip] += 1
                if timestamp is not None:
                    not_found_events[ip].append(timestamp)

            decoded_url = unquote(url)
            for description, pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(decoded_url):
                    suspicious_requests.append(
                        SuspiciousRequest(line_num, ip, url, description)
                    )

    if window_minutes is None:
        failed_alert_counts = dict(failed_logins)
        not_found_alert_counts = dict(not_found_counts)
    else:
        window = timedelta(minutes=window_minutes)
        failed_alert_counts = _peak_counts(failed_events, window)
        not_found_alert_counts = _peak_counts(not_found_events, window)

    return AnalysisResult(
        total_requests=total_requests,
        unparsed_lines=unparsed_lines,
        failed_logins=dict(failed_logins),
        not_found_counts=dict(not_found_counts),
        failed_login_alerts={
            ip: count
            for ip, count in failed_alert_counts.items()
            if count >= failed_login_threshold
        },
        not_found_alerts={
            ip: count
            for ip, count in not_found_alert_counts.items()
            if count >= not_found_threshold
        },
        suspicious_requests=suspicious_requests,
        window_minutes=window_minutes,
        records_without_timestamp=records_without_timestamp,
    )


def format_text_report(result: AnalysisResult) -> str:
    report = [
        "=" * 58,
        "RELATORIO DE ANALISE DE LOGS E SEGURANCA",
        "=" * 58,
        "",
        "Resumo:",
        "  Requisicoes analisadas: {}".format(result.total_requests),
        "  Linhas ignoradas (formato nao reconhecido): {}".format(
            result.unparsed_lines
        ),
    ]
    if result.window_minutes is None:
        report.append("  Escopo dos alertas: arquivo inteiro")
    else:
        report.append(
            "  Escopo dos alertas: janela de {} minuto(s)".format(result.window_minutes)
        )
    if result.records_without_timestamp:
        report.append(
            "  Registros sem timestamp valido: {} (nao entram nos alertas por janela)".format(
                result.records_without_timestamp
            )
        )

    report.extend(("", "Tentativas de autenticacao (HTTP 401):"))
    if result.failed_login_alerts:
        for ip, count in sorted(result.failed_login_alerts.items()):
            report.append("  ALERTA: {} - {} tentativa(s)".format(ip, count))
    else:
        report.append("  Nenhum alerta acima do limiar.")

    report.extend(("", "Respostas nao encontradas (HTTP 404):"))
    if result.not_found_alerts:
        for ip, count in sorted(result.not_found_alerts.items()):
            report.append("  ALERTA: {} - {} resposta(s)".format(ip, count))
    else:
        report.append("  Nenhum alerta acima do limiar.")

    report.extend(("", "Requisicoes com assinaturas suspeitas:"))
    if result.suspicious_requests:
        for request in result.suspicious_requests:
            escaped_url = json.dumps(request.url, ensure_ascii=False)
            report.append(
                "  Linha {} | IP: {} | Padrao: {} | URL: {}".format(
                    request.line, request.ip, request.pattern, escaped_url
                )
            )
    else:
        report.append("  Nenhuma assinatura encontrada.")
    report.append("\n" + "=" * 58)
    return "\n".join(report)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analisa logs de acesso web em formato Apache/Nginx combined."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default=LOG_FILE,
        help="arquivo de log (padrao: %(default)s)",
    )
    parser.add_argument(
        "--failed-login-threshold",
        type=int,
        default=FAILED_LOGIN_THRESHOLD,
        help="tentativas HTTP 401 para gerar alerta (padrao: %(default)s)",
    )
    parser.add_argument(
        "--not-found-threshold",
        type=int,
        default=NOT_FOUND_THRESHOLD,
        help="respostas HTTP 404 para gerar alerta (padrao: %(default)s)",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        help="considera o pico de eventos dentro desta janela de minutos",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="formato do relatorio",
    )
    parser.add_argument("--output", help="salva o relatorio em um arquivo")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        result = analyze_logs(
            args.log_file,
            failed_login_threshold=args.failed_login_threshold,
            not_found_threshold=args.not_found_threshold,
            window_minutes=args.window_minutes,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.format == "json":
        output = json.dumps(asdict(result), ensure_ascii=False, indent=2)
    else:
        output = format_text_report(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as report_file:
                report_file.write(output + "\n")
        except OSError as error:
            parser.error("nao foi possivel salvar o relatorio: {}".format(error))
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
