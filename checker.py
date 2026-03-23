"""
Security Headers Checker
Analisa cabeçalhos de segurança HTTP de URLs e gera relatório de pontuação.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Definição dos headers analisados e seus critérios de avaliação
# ---------------------------------------------------------------------------

HEADERS_CONFIG = {
    "Content-Security-Policy": {
        "descricao": "Controla quais recursos o navegador pode carregar",
        "peso": 20,
        "avaliar": "_avaliar_csp",
    },
    "Strict-Transport-Security": {
        "descricao": "Força conexões HTTPS (HSTS)",
        "peso": 20,
        "avaliar": "_avaliar_hsts",
    },
    "X-Frame-Options": {
        "descricao": "Protege contra clickjacking",
        "peso": 10,
        "avaliar": "_avaliar_x_frame",
    },
    "X-Content-Type-Options": {
        "descricao": "Impede MIME-type sniffing",
        "peso": 10,
        "avaliar": "_avaliar_x_content_type",
    },
    "Referrer-Policy": {
        "descricao": "Controla informações enviadas no cabeçalho Referer",
        "peso": 10,
        "avaliar": "_avaliar_referrer",
    },
    "Permissions-Policy": {
        "descricao": "Controla acesso a APIs do navegador (câmera, microfone etc.)",
        "peso": 15,
        "avaliar": "_avaliar_permissions",
    },
    "X-XSS-Protection": {
        "descricao": "Filtro XSS legado (obsoleto, mas ainda relevante)",
        "peso": 5,
        "avaliar": "_avaliar_xss_protection",
    },
    "Cache-Control": {
        "descricao": "Controla como respostas são armazenadas em cache",
        "peso": 10,
        "avaliar": "_avaliar_cache_control",
    },
}


# ---------------------------------------------------------------------------
# Funções de avaliação por header
# ---------------------------------------------------------------------------

def _avaliar_csp(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho Content-Security-Policy."""
    valor_lower = valor.lower()

    if "unsafe-inline" in valor_lower and "unsafe-eval" in valor_lower:
        return "fraco", "Contém 'unsafe-inline' e 'unsafe-eval' — efetividade reduzida"
    if "unsafe-inline" in valor_lower:
        return "moderado", "Contém 'unsafe-inline' — considere usar nonces ou hashes"
    if "unsafe-eval" in valor_lower:
        return "moderado", "Contém 'unsafe-eval' — evite quando possível"
    if "default-src" not in valor_lower and "script-src" not in valor_lower:
        return "moderado", "Sem 'default-src' ou 'script-src' definido explicitamente"
    return "seguro", "Política CSP configurada adequadamente"


def _avaliar_hsts(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho Strict-Transport-Security."""
    valor_lower = valor.lower()
    partes = [p.strip() for p in valor_lower.split(";")]

    max_age = 0
    for parte in partes:
        if parte.startswith("max-age="):
            try:
                max_age = int(parte.split("=")[1])
            except ValueError:
                pass

    if max_age < 86400:  # menos de 1 dia
        return "fraco", f"max-age muito curto ({max_age}s) — recomendado >= 31536000"
    if max_age < 31536000:  # menos de 1 ano
        status = "moderado"
        msg = f"max-age de {max_age}s — recomendado >= 31536000 (1 ano)"
    else:
        status = "seguro"
        msg = f"max-age de {max_age}s"

    if "includesubdomains" in valor_lower:
        msg += " | includeSubDomains ativado"
    else:
        msg += " | considere adicionar 'includeSubDomains'"
        if status == "seguro":
            status = "moderado"

    if "preload" in valor_lower:
        msg += " | preload ativado"

    return status, msg


def _avaliar_x_frame(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho X-Frame-Options."""
    valor_upper = valor.strip().upper()
    if valor_upper in ("DENY", "SAMEORIGIN"):
        return "seguro", f"Valor '{valor_upper}' protege contra clickjacking"
    if valor_upper.startswith("ALLOW-FROM"):
        return "moderado", "ALLOW-FROM é obsoleto — use Content-Security-Policy frame-ancestors"
    return "fraco", f"Valor desconhecido: '{valor}'"


def _avaliar_x_content_type(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho X-Content-Type-Options."""
    if valor.strip().lower() == "nosniff":
        return "seguro", "Valor 'nosniff' correto"
    return "fraco", f"Valor inesperado: '{valor}' — deve ser 'nosniff'"


def _avaliar_referrer(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho Referrer-Policy."""
    valor_lower = valor.strip().lower()
    seguros = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
    moderados = {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin"}

    if valor_lower in seguros:
        return "seguro", f"Política '{valor}' limita exposição de dados"
    if valor_lower in moderados:
        return "moderado", f"Política '{valor}' pode expor a URL de origem em alguns cenários"
    if valor_lower in ("unsafe-url", ""):
        return "fraco", f"Política '{valor}' expõe URLs completas — evite"
    return "moderado", f"Valor '{valor}' — verifique se é intencional"


def _avaliar_permissions(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho Permissions-Policy."""
    valor_lower = valor.lower()
    # Verifica se restringe funcionalidades sensíveis
    sensíveis = ["camera", "microphone", "geolocation", "payment"]
    restritos = [f for f in sensíveis if f in valor_lower]

    if len(restritos) == len(sensíveis):
        return "seguro", "Restringe camera, microfone, geolocalização e pagamento"
    if restritos:
        faltando = [f for f in sensíveis if f not in restritos]
        return "moderado", f"Faltam restrições para: {', '.join(faltando)}"
    return "moderado", "Política presente, mas verifique se cobre as permissões necessárias"


def _avaliar_xss_protection(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho X-XSS-Protection (obsoleto)."""
    valor_strip = valor.strip()
    if valor_strip == "0":
        return "moderado", "Valor '0' desabilita o filtro — pode ser intencional com CSP forte"
    if valor_strip.startswith("1; mode=block"):
        return "seguro", "Modo 'block' ativado (header obsoleto, mas aceitável)"
    if valor_strip == "1":
        return "moderado", "Filtro ativo mas sem 'mode=block'"
    return "fraco", f"Valor inesperado: '{valor}'"


def _avaliar_cache_control(valor: str) -> Tuple[str, str]:
    """Avalia o cabeçalho Cache-Control."""
    valor_lower = valor.lower()
    diretivas = [d.strip() for d in valor_lower.split(",")]

    privado_ou_sem_store = "no-store" in diretivas or "private" in diretivas
    no_cache = "no-cache" in diretivas

    if "no-store" in diretivas:
        return "seguro", "Diretiva 'no-store' impede armazenamento em cache"
    if privado_ou_sem_store and no_cache:
        return "seguro", "Cache adequadamente controlado (private + no-cache)"
    if "public" in diretivas and "no-store" not in diretivas:
        return "moderado", "Cache público sem 'no-store' — verifique se é intencional"
    if no_cache:
        return "moderado", "Diretiva 'no-cache' presente, mas considere 'no-store' para dados sensíveis"
    return "moderado", "Revise as diretivas de cache para garantir proteção adequada"


# Mapa de funções de avaliação
_AVALIADORES = {
    "_avaliar_csp": _avaliar_csp,
    "_avaliar_hsts": _avaliar_hsts,
    "_avaliar_x_frame": _avaliar_x_frame,
    "_avaliar_x_content_type": _avaliar_x_content_type,
    "_avaliar_referrer": _avaliar_referrer,
    "_avaliar_permissions": _avaliar_permissions,
    "_avaliar_xss_protection": _avaliar_xss_protection,
    "_avaliar_cache_control": _avaliar_cache_control,
}


# ---------------------------------------------------------------------------
# Lógica principal de análise
# ---------------------------------------------------------------------------

def validar_url(url: str) -> str:
    """
    Valida e normaliza a URL fornecida.

    Adiciona o esquema 'https://' se ausente. Lança ValueError se a URL
    for inválida após normalização.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"URL inválida: '{url}'")

    return url


def buscar_headers(url: str, timeout: int = 10) -> dict:
    """
    Realiza requisição HTTP HEAD (com fallback para GET) e retorna os headers.

    Parâmetros:
        url     : URL alvo já validada
        timeout : tempo máximo de espera em segundos

    Retorna dicionário com os headers de resposta em letras minúsculas como chave.
    """
    headers_requisicao = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    try:
        resposta = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=headers_requisicao,
        )
        # Alguns servidores não respondem HEAD corretamente
        if resposta.status_code in (405, 501) or not resposta.headers:
            resposta = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers_requisicao,
                stream=True,
            )
            resposta.close()

        return dict(resposta.headers), resposta.status_code, resposta.url

    except requests.exceptions.SSLError as e:
        raise ConnectionError(f"Erro de certificado SSL: {e}") from e
    except requests.exceptions.ConnectionError as e:
        raise ConnectionError(f"Falha de conexão: {e}") from e
    except requests.exceptions.Timeout:
        raise TimeoutError(f"Tempo esgotado após {timeout}s tentando conectar a '{url}'")
    except requests.exceptions.MissingSchema as e:
        raise ValueError(f"URL mal formada: {e}") from e
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Erro inesperado na requisição: {e}") from e


def analisar_headers(headers_resposta: dict) -> List[dict]:
    """
    Analisa os headers de segurança presentes na resposta HTTP.

    Retorna lista de dicionários com as informações de cada header analisado:
        - nome          : nome do header
        - descricao     : o que o header faz
        - presente      : bool
        - valor         : str ou None
        - status        : 'seguro' | 'moderado' | 'fraco' | 'ausente'
        - observacao    : mensagem descritiva sobre a avaliação
        - peso          : peso do header na pontuação
        - pontos        : pontos obtidos neste header
    """
    resultados = []

    # Normaliza os keys para case-insensitive lookup
    headers_lower = {k.lower(): v for k, v in headers_resposta.items()}

    for nome_header, config in HEADERS_CONFIG.items():
        chave = nome_header.lower()
        presente = chave in headers_lower
        valor = headers_lower.get(chave)
        peso = config["peso"]

        if presente and valor:
            avaliador = _AVALIADORES[config["avaliar"]]
            try:
                status, observacao = avaliador(valor)
            except Exception:
                status, observacao = "moderado", "Não foi possível avaliar o valor deste header"
        else:
            status = "ausente"
            observacao = "Header não encontrado na resposta"

        # Calcula pontos com base no status
        pontos_map = {"seguro": peso, "moderado": peso // 2, "fraco": peso // 4, "ausente": 0}
        pontos = pontos_map.get(status, 0)

        resultados.append({
            "nome": nome_header,
            "descricao": config["descricao"],
            "presente": presente,
            "valor": valor,
            "status": status,
            "observacao": observacao,
            "peso": peso,
            "pontos": pontos,
        })

    return resultados


def calcular_pontuacao(resultados: List[dict]) -> int:
    """Calcula a pontuação total de segurança (0 a 100)."""
    total_peso = sum(r["peso"] for r in resultados)
    total_pontos = sum(r["pontos"] for r in resultados)
    if total_peso == 0:
        return 0
    return round((total_pontos / total_peso) * 100)


# ---------------------------------------------------------------------------
# Exibição no terminal
# ---------------------------------------------------------------------------

COR_STATUS = {
    "seguro": "green",
    "moderado": "yellow",
    "fraco": "red",
    "ausente": "bright_black",
}

ICONE_STATUS = {
    "seguro": "✔",
    "moderado": "⚠",
    "fraco": "✘",
    "ausente": "–",
}


def _cor_pontuacao(pontuacao: int) -> str:
    """Retorna a cor rich de acordo com a pontuação."""
    if pontuacao >= 80:
        return "bold green"
    if pontuacao >= 50:
        return "bold yellow"
    return "bold red"


def exibir_resultado(url: str, url_final: str, codigo_http: int, resultados: List[dict], pontuacao: int) -> None:
    """Exibe o relatório formatado no terminal usando rich."""

    console.print()
    console.print(Panel(
        f"[bold cyan]Security Headers Checker[/bold cyan]\n"
        f"[dim]URL alvo :[/dim]  {url}\n"
        f"[dim]URL final:[/dim]  {url_final}\n"
        f"[dim]HTTP     :[/dim]  {codigo_http}",
        box=box.ROUNDED,
        border_style="cyan",
    ))

    # Tabela de headers
    tabela = Table(
        show_header=True,
        header_style="bold white",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1),
        expand=True,
    )
    tabela.add_column("Header", style="bold", min_width=28)
    tabela.add_column("Status", min_width=10, justify="center")
    tabela.add_column("Valor", max_width=45, overflow="fold")
    tabela.add_column("Observação", overflow="fold")

    for r in resultados:
        cor = COR_STATUS[r["status"]]
        icone = ICONE_STATUS[r["status"]]
        status_txt = Text(f"{icone} {r['status'].upper()}", style=cor)
        valor_txt = Text(r["valor"] or "—", style="dim" if not r["presente"] else "")
        obs_txt = Text(r["observacao"], style=cor)

        tabela.add_row(r["nome"], status_txt, valor_txt, obs_txt)

    console.print(tabela)

    # Pontuação geral
    cor_pont = _cor_pontuacao(pontuacao)
    nivel = (
        "Excelente" if pontuacao >= 90 else
        "Bom" if pontuacao >= 70 else
        "Regular" if pontuacao >= 50 else
        "Crítico"
    )

    console.print(Panel(
        f"[{cor_pont}]Pontuação de Segurança: {pontuacao}/100 — {nivel}[/{cor_pont}]",
        box=box.ROUNDED,
        border_style=cor_pont.replace("bold ", ""),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Exportação JSON
# ---------------------------------------------------------------------------

def gerar_relatorio_json(url: str, url_final: str, codigo_http: int, resultados: List[dict], pontuacao: int) -> dict:
    """Gera o dicionário de relatório para exportação em JSON."""
    return {
        "data_analise": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url_solicitada": url,
        "url_final": url_final,
        "codigo_http": codigo_http,
        "pontuacao": pontuacao,
        "headers": [
            {
                "nome": r["nome"],
                "descricao": r["descricao"],
                "presente": r["presente"],
                "valor": r["valor"],
                "status": r["status"],
                "observacao": r["observacao"],
                "peso": r["peso"],
                "pontos_obtidos": r["pontos"],
            }
            for r in resultados
        ],
    }


# ---------------------------------------------------------------------------
# Processamento de uma URL
# ---------------------------------------------------------------------------

def processar_url(url_raw: str, exportar_json: bool) -> Optional[dict]:
    """
    Valida, consulta e analisa os headers de segurança de uma URL.

    Retorna o dicionário de relatório ou None em caso de erro.
    """
    try:
        url = validar_url(url_raw.strip())
    except ValueError as e:
        console.print(f"[bold red]URL inválida:[/bold red] {e}")
        return None

    console.print(f"[dim]Consultando {url} ...[/dim]", end="")

    try:
        headers_resp, codigo, url_final = buscar_headers(url)
    except (ConnectionError, TimeoutError, RuntimeError) as e:
        console.print(f"\n[bold red]Erro:[/bold red] {e}")
        return None

    console.print(" [green]OK[/green]")

    resultados = analisar_headers(headers_resp)
    pontuacao = calcular_pontuacao(resultados)
    exibir_resultado(url, url_final, codigo, resultados, pontuacao)

    relatorio = gerar_relatorio_json(url, url_final, codigo, resultados, pontuacao)

    if exportar_json:
        # Nome de arquivo baseado no domínio e timestamp
        dominio = urlparse(url_final).netloc.replace(":", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"relatorio_{dominio}_{timestamp}.json"
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, ensure_ascii=False, indent=2)
        console.print(f"[bold green]Relatório JSON salvo em:[/bold green] {nome_arquivo}\n")

    return relatorio


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

def main() -> None:
    """Ponto de entrada da ferramenta. Processa argumentos e executa a análise."""

    parser = argparse.ArgumentParser(
        prog="checker",
        description="Analisa cabeçalhos de segurança HTTP e gera pontuação de segurança.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos de uso:\n"
            "  python checker.py https://example.com\n"
            "  python checker.py https://example.com --json\n"
            "  python checker.py --file exemplos/urls_exemplo.txt\n"
            "  python checker.py --file exemplos/urls_exemplo.txt --json\n"
        ),
    )

    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument("url", nargs="?", help="URL a ser analisada")
    grupo.add_argument(
        "--file", "-f",
        metavar="ARQUIVO",
        help="Arquivo .txt com uma URL por linha",
    )

    parser.add_argument(
        "--json", "-j",
        action="store_true",
        dest="exportar_json",
        help="Exporta o relatório em formato JSON",
    )

    args = parser.parse_args()

    if args.file:
        # Modo múltiplas URLs
        try:
            with open(args.file, encoding="utf-8") as f:
                linhas = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            console.print(f"[bold red]Arquivo não encontrado:[/bold red] {args.file}")
            sys.exit(1)
        except OSError as e:
            console.print(f"[bold red]Erro ao ler arquivo:[/bold red] {e}")
            sys.exit(1)

        if not linhas:
            console.print("[yellow]Nenhuma URL encontrada no arquivo.[/yellow]")
            sys.exit(0)

        console.print(f"[bold cyan]Analisando {len(linhas)} URL(s) do arquivo:[/bold cyan] {args.file}\n")

        relatorios = []
        for linha in linhas:
            rel = processar_url(linha, args.exportar_json)
            if rel:
                relatorios.append(rel)

        # Resumo final quando há múltiplas URLs
        if len(relatorios) > 1:
            console.print(Panel(
                "[bold white]Resumo da análise[/bold white]",
                box=box.ROUNDED,
                border_style="cyan",
            ))
            tabela_resumo = Table(box=box.SIMPLE, expand=True)
            tabela_resumo.add_column("URL", overflow="fold")
            tabela_resumo.add_column("Pontuação", justify="center", min_width=12)
            tabela_resumo.add_column("Nível", justify="center")

            for rel in relatorios:
                pont = rel["pontuacao"]
                nivel = (
                    "Excelente" if pont >= 90 else
                    "Bom" if pont >= 70 else
                    "Regular" if pont >= 50 else
                    "Crítico"
                )
                cor = _cor_pontuacao(pont)
                tabela_resumo.add_row(
                    rel["url_final"],
                    Text(str(pont), style=cor),
                    Text(nivel, style=cor),
                )
            console.print(tabela_resumo)

    else:
        # Modo URL única
        processar_url(args.url, args.exportar_json)


if __name__ == "__main__":
    main()
