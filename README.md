<div id="top">

<div align="center">

# 🛡️ Log Analyzer & Threat Detector

<em>Analisador de logs de servidores web e detector de anomalias e ameaças de segurança via CLI.</em>

<br>

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Blue%20Team%20%26%20SIEM-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

</div>

---

## 📋 Sumário

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Pré-requisitos e Instalação](#-pré-requisitos-e-instalação)
- [Como Usar](#-como-usar)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Conceitos de Cibersegurança](#-conceitos-de-cibersegurança)

---

## 🛠️ Visão Geral

O **Log Analyzer & Threat Detector** é uma ferramenta desenvolvida em Python para análise automatizada de arquivos de log no padrão Nginx / Apache. O script realiza a varredura do tráfego em busca de comportamentos suspeitos, padrões de varredura maliciosa e tentativas de exploração de vulnerabilidades web (OWASP Top 10).

---

## ✨ Funcionalidades

- **Detecção de Brute Force:** Mapeia endereços IP com um volume anormal de falhas de autenticação (`HTTP 401`).
- **Identificação de Scans & Recon:** Alerta sobre tentativas massivas de varredura de rotas e diretórios inexistentes (`HTTP 404`).
- **Análise de Assinaturas de Ataque (Regex):** Identifica *payloads* maliciosos injetados nas requisições HTTP:
  - **SQL Injection (SQLi)** (ex: `UNION SELECT`, `' OR 1=1`)
  - **Path Traversal / Local File Inclusion (LFI)** (ex: `../`, `/etc/passwd`)
  - **Cross-Site Scripting (XSS)** (ex: `<script>`)

---

## 🚀 Pré-requisitos e Instalação

A ferramenta utiliza apenas **bibliotecas nativas do Python** (`re`, `collections`), dispensando a instalação de pacotes externos via `pip`.

1. **Clone o repositório:**
   ```bash
   git clone git@github.com:canutoV/log-analyzer-py.git