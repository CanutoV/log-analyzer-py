# Log Analyzer & Threat Detector

Ferramenta de linha de comando, feita com a biblioteca padrão do Python, para analisar logs de acesso web no formato Apache/Nginx combined.

## Funcionalidades

- Conta respostas HTTP `401` e `404` por endereço de origem.
- Gera alertas por limiar, considerando o arquivo inteiro ou uma janela temporal opcional.
- Detecta assinaturas simples de `UNION SELECT`, path traversal, acesso a `/etc/passwd` e `<script>`; as URLs percent-encoded são decodificadas antes da inspeção.
- Aceita endereços IPv4 e IPv6, informa linhas não reconhecidas e pode emitir relatórios texto ou JSON.

As assinaturas são heurísticas básicas e podem gerar falsos positivos ou não detectar variantes. Este projeto não substitui um SIEM, um WAF ou uma revisão de segurança. Respostas `401` e `404`, isoladamente, não comprovam atividade maliciosa.

## Requisitos

- Python 3.7 ou superior.
- Nenhuma dependência externa.

## Uso

O arquivo `sample-access.log` é usado quando nenhum caminho é informado:

```bash
python analyzer.py
```

Informe outro arquivo e ajuste os limiares:

```bash
python analyzer.py /var/log/nginx/access.log \
  --failed-login-threshold 5 \
  --not-found-threshold 10
```

Para alertar somente quando os eventos ultrapassarem os limiares dentro de uma janela, use `--window-minutes`:

```bash
python analyzer.py access.log --window-minutes 10
```

Os timestamps precisam estar no formato comum do access log, por exemplo `[13/Oct/2026:10:00:01 +0000]`. Registros sem timestamp válido não entram nos alertas por janela e são contabilizados no relatório.

Gere JSON no terminal ou salve um relatório em arquivo:

```bash
python analyzer.py access.log --format json
python analyzer.py access.log --format json --output report.json
```

Use `python analyzer.py --help` para consultar todas as opções. O parser espera o formato combined com IP/host, timestamp, requisição HTTP entre aspas e código de status; linhas de outros formatos são contabilizadas como não reconhecidas.

## Testes

```bash
python -m unittest discover -s tests -v
```