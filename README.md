# Security Headers Checker

Ferramenta de linha de comando para análise de cabeçalhos de segurança HTTP.

Verifica a presença e configuração de headers críticos em qualquer aplicação web,
atribui uma pontuação de segurança (0–100) e gera relatórios detalhados no terminal
ou em JSON.

---

## Headers analisados

| Header | O que protege | Peso |
|---|---|---|
| Content-Security-Policy | Injeção de recursos e XSS | 20 |
| Strict-Transport-Security | Força HTTPS (HSTS) | 20 |
| Permissions-Policy | Acesso a câmera, microfone, geolocalização | 15 |
| X-Frame-Options | Clickjacking | 10 |
| X-Content-Type-Options | MIME-type sniffing | 10 |
| Referrer-Policy | Vazamento de URL no cabeçalho Referer | 10 |
| Cache-Control | Armazenamento indevido em cache | 10 |
| X-XSS-Protection | Filtro XSS legado | 5 |

Cada header é avaliado em três níveis: **seguro**, **moderado** ou **fraco** —
não apenas verificando se está presente, mas se está configurado corretamente.

---

## Instalação
```bash
git clone https://github.com/Kayocma/security-headers-checker.git
cd security-headers-checker
pip install -r requirements.txt
```

---

## Uso

**Analisar uma URL:**
```bash
python checker.py https://example.com
```

**Exportar relatório em JSON:**
```bash
python checker.py https://example.com --json
```

**Analisar múltiplas URLs de um arquivo:**
```bash
python checker.py --file exemplos/urls_exemplo.txt
```

**Múltiplas URLs com exportação JSON:**
```bash
python checker.py --file exemplos/urls_exemplo.txt --json
```

---

## Exemplo de saída
```
╭─────────────────────────────────────────╮
│ Security Headers Checker                │
│ URL alvo :  https://mozilla.org         │
│ URL final:  https://www.mozilla.org/    │
│ HTTP     :  200                         │
╰─────────────────────────────────────────╯

 Header                      Status       Valor              Observação
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Content-Security-Policy     ✔ SEGURO     default-src 'self' Política CSP configurada adequadamente
 Strict-Transport-Security   ✔ SEGURO     max-age=315360...  max-age de 31536000s | preload ativado
 X-Frame-Options             ✔ SEGURO     DENY               Valor 'DENY' protege contra clickjacking
 ...

╭──────────────────────────────────────────╮
│  Pontuação de Segurança: 78/100 — Bom   │
╰──────────────────────────────────────────╯
```

---

## Relatório JSON

Com a flag `--json`, a ferramenta gera um arquivo no formato:
```json
{
  "data_analise": "2026-03-23T01:00:00Z",
  "url_solicitada": "https://mozilla.org",
  "url_final": "https://www.mozilla.org/pt-BR/",
  "codigo_http": 200,
  "pontuacao": 78,
  "headers": [
    {
      "nome": "Content-Security-Policy",
      "presente": true,
      "status": "seguro",
      "observacao": "Política CSP configurada adequadamente",
      "peso": 20,
      "pontos_obtidos": 20
    }
  ]
}
```

---

## Requisitos

- Python 3.9+
- requests
- rich

---

## Referências

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs — HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Mozilla Observatory](https://observatory.mozilla.org/)