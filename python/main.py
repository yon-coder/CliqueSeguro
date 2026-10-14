import os
import time
import json
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin
import ipaddress
from pathlib import Path
import hashlib
from typing import Dict, List, Set, Tuple, Any, Optional

# Gerenciamento do tldextract usando a base nativa embutida (offline)
try:
    import tldextract
    extractor_offline = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ==============================================================================
# CONFIGURAÇÕES CENTRAIS E CONSTANTES
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_EXPIRACAO_SEGUNDOS = 86400  # Cache válido por 24 horas

HTTP_TIMEOUT_FEEDS = 10
HTTP_TIMEOUT_ANALISE = 4
MAX_REDIRECIONAMENTOS = 3
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
HEADERS = {'User-Agent': USER_AGENT}

# Pesos de Suspeita Heurística
PESO_IP_DIRETO = 25       # Oculta registro de domínio real; forte indicador.
PESO_URL_LONGA = 5        # Indicador fraco isoladamente.
PESO_HTTP = 5             # Indicador fraco isoladamente.
PESO_PALAVRA_CHAVE = 5    # Indicador fraco isoladamente.
PESO_COMBINADO = 15       # Bônus ativado apenas em acúmulo de múltiplos indicadores fracos.
PESO_REDIR_EXTERNO = 20   # Risco maior (redirecionamento para domínios não relacionados).

MAX_SCORE_POSSIVEL = 75

LIMITE_COMPRIMENTO_URL = 75
MINIMO_INDICADORES_FRACOS = 3
PALAVRAS_CHAVE_SUSPEITAS = ['login', 'verify', 'account', 'banking', 'secure', 'update', 'senha']

# Faixas de Pontuação Absoluta (alinhadas ao máximo de 75)
LIMIAR_BAIXO_RISCO = 15      # 0 a 14: Baixo Risco
LIMIAR_RISCO_MODERADO = 30   # 15 a 29: Risco Moderado
LIMIAR_ALTO_RISCO = 50       # 30 a 49: Alto Risco
                             # 50+: Muito Alto Risco

FEEDS_AMEACAS = [
    {"nome": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "tipo": "text"},
    {"nome": "OpenPhish", "url": "https://openphish.com/feed.txt", "tipo": "text"},
    {"nome": "ThreatFox", "url": "https://threatfox.abuse.ch/export/urls/recent/", "tipo": "json"}
]

# ==============================================================================
# FUNÇÕES DE VALIDAÇÃO, NORMALIZAÇÃO E DOMÍNIOS
# ==============================================================================
def eh_url_valida(url: str) -> bool:
    """Valida URLs HTTP(S), rejeitando entradas ambíguas ou malformadas."""
    if not isinstance(url, str):
        return False

    candidata = url.strip()
    if not candidata or any(caractere.isspace() for caractere in candidata):
        return False
    if any(ord(caractere) < 32 or ord(caractere) == 127 for caractere in candidata):
        return False
    if "\\" in candidata:
        return False

    try:
        resultado = urlparse(candidata)
        if resultado.scheme.lower() not in ("http", "https"):
            return False
        hostname = resultado.hostname
        if not hostname or any(caractere.isspace() for caractere in hostname):
            return False
        if resultado.username is not None or resultado.password is not None:
            return False

        porta = resultado.port
        if porta is not None and not (1 <= porta <= 65535):
            return False

        if ":" in hostname:
            try:
                ipaddress.ip_address(hostname.split("%")[0])
            except ValueError:
                return False

        return True
    except (ValueError, UnicodeError):
        return False

def normalizar_url(url: str) -> str:
    """Padroniza URL para comparação; remove fragmentos que não são enviados ao servidor."""
    if not eh_url_valida(url):
        return url
    try:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        if not eh_endereco_ip(hostname):
            hostname = hostname.encode("idna").decode("ascii")
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        porta = parsed.port
        port_str = f":{porta}" if porta is not None and not (
            (scheme == "http" and porta == 80) or (scheme == "https" and porta == 443)
        ) else ""

        path = "" if parsed.path == "/" else parsed.path
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{hostname}{port_str}{path}{query}"
    except (ValueError, UnicodeError):
        return url

def obter_dominio_registravel(hostname: str) -> str:
    """Extrai o domínio registrável usando a Public Suffix List offline."""
    if not hostname:
        return ""
    host_limpo = hostname.strip('[]').lower()

    if eh_endereco_ip(host_limpo):
        return host_limpo

    if HAS_TLDEXTRACT:
        try:
            extracted = extractor_offline(host_limpo)
            dominio_registravel = getattr(extracted, "top_domain_under_public_suffix", "") or getattr(
                extracted, "registered_domain", ""
            )
            if dominio_registravel:
                return dominio_registravel.lower()
        except Exception:
            pass

    partes = host_limpo.split('.')
    if len(partes) <= 1:
        return host_limpo
    return host_limpo

def dominios_relacionados(dom1: str, dom2: str) -> bool:
    """Compara dois hostnames determinando se possuem o mesmo domínio registrável ou IP."""
    if not dom1 or not dom2:
        return False

    h1 = dom1.strip('[]').lower()
    h2 = dom2.strip('[]').lower()

    if h1 == h2:
        return True

    if eh_endereco_ip(h1) or eh_endereco_ip(h2):
        try:
            ip1 = ipaddress.ip_address(h1)
            ip2 = ipaddress.ip_address(h2)
            return ip1 == ip2
        except ValueError:
            return False

    reg1 = obter_dominio_registravel(h1)
    reg2 = obter_dominio_registravel(h2)

    if reg1 and reg2:
        return reg1 == reg2

    return False

def eh_endereco_ip(host: str) -> bool:
    """Valida se uma string de hostname é um IPv4 ou IPv6 válido."""
    if not host:
        return False
    host_limpo = host.strip('[]').split('%')[0]
    try:
        ipaddress.ip_address(host_limpo)
        return True
    except ValueError:
        return False

def eh_ip_privado_ou_reservado(ip_str: str) -> bool:
    """Verifica se um IP é privado, loopback, link-local ou reservado (Proteção SSRF)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip('[]'))
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True

# ==============================================================================
# GESTÃO DE CACHE E PARSERS DE FEEDS
# ==============================================================================
def obter_caminho_cache(feed_url: str) -> Path:
    """Gera um nome estável compatível com os arquivos de cache das versões anteriores."""
    nome_arquivo = hashlib.md5(feed_url.encode("utf-8")).hexdigest() + ".txt"
    return CACHE_DIR / nome_arquivo

def processar_resposta_feed(conteudo: str, tipo_feed: str) -> Set[str]:
    """Extrai URLs válidas de feeds em texto ou JSON."""
    urls: Set[str] = set()
    if not conteudo or not isinstance(conteudo, str):
        return urls

    if tipo_feed == "json":
        try:
            dados = json.loads(conteudo)
        except (json.JSONDecodeError, TypeError):
            return urls
        if isinstance(dados, dict):
            itens = dados.get("urls")
            if itens is None:
                itens = dados.get("data", [])
            if isinstance(itens, dict):
                itens = list(itens.values())
        elif isinstance(dados, list):
            itens = dados
        else:
            itens = []
        if not isinstance(itens, list):
            return urls
        for item in itens:
            u = item.get("url") if isinstance(item, dict) else item
            if isinstance(u, str) and eh_url_valida(u):
                urls.add(normalizar_url(u))
        return urls

    for linha in conteudo.splitlines():
        linha_limpa = linha.strip()
        if linha_limpa and not linha_limpa.startswith("#") and eh_url_valida(linha_limpa):
            urls.add(normalizar_url(linha_limpa))
    return urls

def carregar_base_de_dados() -> Tuple[Dict[str, Set[str]], List[str]]:
    """Carrega as URLs de cada feed salvando em cache individual."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    base_por_feed: Dict[str, Set[str]] = {}
    feeds_com_falha: List[str] = []
    tempo_atual = time.time()

    for item_feed in FEEDS_AMEACAS:
        nome_feed = item_feed["nome"]
        feed_url = item_feed["url"]
        tipo_feed = item_feed["tipo"]
        arquivo_cache = obter_caminho_cache(feed_url)
        urls_feed: Set[str] = set()
        usou_cache_valido = False

        try:
            if arquivo_cache.is_file():
                idade_cache = tempo_atual - arquivo_cache.stat().st_mtime
                usou_cache_valido = 0 <= idade_cache < CACHE_EXPIRACAO_SEGUNDOS
        except OSError:
            usou_cache_valido = False

        if usou_cache_valido:
            try:
                with open(arquivo_cache, 'r', encoding='utf-8') as f:
                    for linha in f:
                        linha_limpa = linha.strip()
                        if linha_limpa and eh_url_valida(linha_limpa):
                            urls_feed.add(normalizar_url(linha_limpa))
                base_por_feed[nome_feed] = urls_feed
                continue
            except Exception:
                pass

        try:
            req = urllib.request.Request(feed_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_FEEDS) as resposta:
                conteudo = resposta.read().decode("utf-8", errors="replace")
                urls_feed = processar_resposta_feed(conteudo, tipo_feed)
                if not urls_feed:
                    raise ValueError("Feed vazio ou formato de resposta não reconhecido")

                arquivo_temporario = arquivo_cache.with_suffix(arquivo_cache.suffix + ".tmp")
                try:
                    with open(arquivo_temporario, "w", encoding="utf-8") as f:
                        for u in sorted(urls_feed):
                            f.write(f"{u}\n")
                    os.replace(arquivo_temporario, arquivo_cache)
                finally:
                    try:
                        if arquivo_temporario.exists():
                            arquivo_temporario.unlink()
                    except OSError:
                        pass
                base_por_feed[nome_feed] = urls_feed
        except Exception:
            feeds_com_falha.append(nome_feed)
            if arquivo_cache.exists():
                try:
                    with open(arquivo_cache, 'r', encoding='utf-8') as f:
                        for linha in f:
                            linha_limpa = linha.strip()
                            if linha_limpa and eh_url_valida(linha_limpa):
                                urls_feed.add(normalizar_url(linha_limpa))
                    base_por_feed[nome_feed] = urls_feed
                except (OSError, UnicodeError):
                    base_por_feed[nome_feed] = set()
            else:
                base_por_feed[nome_feed] = set()

    return base_por_feed, feeds_com_falha

# ==============================================================================
# PROTEÇÃO SSRF E MOTOR DE ANÁLISE DINÂMICA
# ==============================================================================
def validar_ip_destino(hostname: str) -> Tuple[bool, str]:
    """Bloqueia hosts cujo IP literal ou qualquer resposta DNS não seja público."""
    if not isinstance(hostname, str) or not hostname.strip():
        return False, "Hostname ausente"

    host_limpo = hostname.strip().strip("[]")
    if eh_endereco_ip(host_limpo):
        if eh_ip_privado_ou_reservado(host_limpo):
            return False, f"Endereço IP privado/reservado bloqueado ({host_limpo})"
        return True, "IP público válido"

    try:
        host_dns = host_limpo.encode("idna").decode("ascii")
        resultados = socket.getaddrinfo(host_dns, None, type=socket.SOCK_STREAM)
        if not resultados:
            return False, "Hostname não resolveu para nenhum endereço IP"

        ips_resolvidos = set()
        for resultado in resultados:
            try:
                ips_resolvidos.add(resultado[4][0].split("%")[0])
            except (IndexError, TypeError):
                return False, "Resposta DNS em formato inesperado"

        if not ips_resolvidos:
            return False, "Hostname não resolveu para nenhum endereço IP"

        for ip_resolvido in ips_resolvidos:
            if eh_ip_privado_ou_reservado(ip_resolvido):
                return False, f"Resolução DNS direciona para IP privado/reservado ({ip_resolvido})"
        return True, "IP de destino público válido"
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        return False, "Falha na resolução ou validação DNS do hostname"

def classificar_score(score: int) -> Tuple[str, str, str]:
    """Retorna a classificação e recomendações alinhadas à escala de 0 a 75."""
    if score < LIMIAR_BAIXO_RISCO:
        nivel = "BAIXO RISCO ✅"
        explicacao = "A URL não apresentou indícios significativos de comportamento suspeito."
        recomendacao = "Nenhum indicador crítico foi encontrado. Verifique a fonte antes de fornecer dados sensíveis."
    elif score < LIMIAR_RISCO_MODERADO:
        nivel = "RISCO MODERADO ⚠️"
        explicacao = "A URL possui características atípicas isoladas que elevam a suspeita."
        recomendacao = "Acesse apenas se conhecer e confiar no remetente. Evite inserir senhas."
    elif score < LIMIAR_ALTO_RISCO:
        nivel = "ALTO RISCO 🚨"
        explicacao = "A URL reúne múltiplos indicadores associados a fraudes digitais."
        recomendacao = "Recomenda-se não acessar este link. Alta probabilidade de engenharia social."
    else:
        nivel = "MUITO ALTO RISCO ☠️"
        explicacao = "A URL possui padrão comportamental altamente compatível com ameaças digitais."
        recomendacao = "NÃO ACESSE ESTE LINK. Risco iminente de segurança."

    return nivel, explicacao, recomendacao

def testar_redirecionamento_seguro(url: str, domain_original: str) -> Tuple[int, str, str]:
    """Inspeciona redirecionamentos manualmente, validando cada destino antes do próximo salto."""
    if not eh_url_valida(url):
        return 0, "URL inválida; requisição de rede não executada", "URL inválida"
    
    url_atual = url
    saltos = 0

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirectHandler)

    while saltos < MAX_REDIRECIONAMENTOS:
        hostname_atual = urlparse(url_atual).hostname or ""
        pode_conectar, motivo = validar_ip_destino(hostname_atual)
        if not pode_conectar:
            return 0, f"Análise dinâmica bloqueada: {motivo}", "Bloqueado por Proteção SSRF"

        codigo = None
        location = None

        try:
            req = urllib.request.Request(url_atual, headers=HEADERS, method="HEAD")
            try:
                with opener.open(req, timeout=HTTP_TIMEOUT_ANALISE) as resposta:
                    codigo = getattr(resposta, "status", resposta.getcode())
                    cabecalhos = resposta.headers
                    location = cabecalhos.get("Location") if cabecalhos else None
            except urllib.error.HTTPError as e:
                codigo = e.code
                location = e.headers.get("Location") if e.headers else None
                e.close()

            if codigo in (405, 501):
                return 0, "Servidor não permite verificação HEAD", f"HTTP {codigo}"

            if codigo not in (301, 302, 303, 307, 308) or not location:
                return 0, "Sem redirecionamento externo", f"HTTP {codigo if codigo else '200 OK'}"

            destino = urljoin(url_atual, location)
            if not eh_url_valida(destino):
                return 0, "Destino de redirecionamento inválido", "Redirecionamento bloqueado"

            dominio_destino = urlparse(destino).hostname or ""
            valido, motivo_destino = validar_ip_destino(dominio_destino)
            if not valido:
                return 0, f"Redirecionamento para destino interno/reservado bloqueado: {motivo_destino}", "Bloqueado por SSRF no redirecionamento"

            if not dominios_relacionados(domain_original, dominio_destino):
                return PESO_REDIR_EXTERNO, f"Redirecionamento para domínio não relacionado ({dominio_destino})", "Redirecionamento externo detectado"

            url_atual = destino
            saltos += 1

        except (urllib.error.URLError, TimeoutError, socket.timeout):
            return 0, "Não foi possível avaliar redirecionamentos (falha de conexão/timeout)", "Erro de conexão/timeout"
        except (ValueError, UnicodeError):
            return 0, "URL ou resposta de redirecionamento malformada", "URL inválida"
        except Exception as e:
            return 0, "Análise dinâmica não concluída", f"Erro: {type(e).__name__}"

    return 0, f"Limite de {MAX_REDIRECIONAMENTOS} redirecionamentos atingido", "Limite de redirecionamentos"

def analisar_heuristica_url(url: str) -> Dict[str, Any]:
    """Executa a análise dinâmica e atribui pontuação de suspeita à URL sem duplicar indicadores."""
    if not eh_url_valida(url):
        nivel, _, _ = classificar_score(0)
        return {
            "score": 0,
            "max_score": MAX_SCORE_POSSIVEL,
            "nivel": nivel,
            "explicacao": "A URL não passou pela validação inicial.",
            "recomendacao": "Informe uma URL HTTP ou HTTPS válida.",
            "indicadores": ["URL inválida; análise dinâmica não executada."],
            "status_conexao": "Não verificada",
            "redirecionamento": "Não verificado",
        }

    pontos_suspeitos = 0
    indicadores = []
    indicadores_fracos = 0

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. IP Direto
    if eh_endereco_ip(hostname):
        pontos_suspeitos += PESO_IP_DIRETO
        indicadores.append("Uso de endereço IP direto em substituição ao nome de domínio")

    # 2. Comprimento da URL
    if len(url) > LIMITE_COMPRIMENTO_URL:
        pontos_suspeitos += PESO_URL_LONGA
        indicadores_fracos += 1
        indicadores.append(f"Comprimento extenso da URL (maior que {LIMITE_COMPRIMENTO_URL} caracteres)")

    # 3. Palavras-chave no Path/Query
    alvo_busca = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    palavras_encontradas = sorted(list(set([p for p in PALAVRAS_CHAVE_SUSPEITAS if p in alvo_busca])))

    if palavras_encontradas:
        pontos_suspeitos += PESO_PALAVRA_CHAVE
        indicadores_fracos += 1
        indicadores.append(f"Presença de palavras-chave suspeitas no caminho/consulta: [{', '.join(palavras_encontradas)}]")

    # 4. HTTP Não Criptografado
    if parsed.scheme == 'http':
        pontos_suspeitos += PESO_HTTP
        indicadores_fracos += 1
        indicadores.append("Uso de protocolo não criptografado (HTTP)")

    # 5. Efeito Combinado
    if indicadores_fracos >= MINIMO_INDICADORES_FRACOS:
        pontos_suspeitos += PESO_COMBINADO
        indicadores.append("Combinação de múltiplos indicadores de risco secundários")

    # 6. Redirecionamento Seguro
    peso_redir, msg_redir, status_conexao = testar_redirecionamento_seguro(url, hostname)
    pontos_suspeitos += peso_redir
    if peso_redir > 0:
        indicadores.append(msg_redir)

    score_final = min(pontos_suspeitos, MAX_SCORE_POSSIVEL)
    nivel, explicacao, recomendacao = classificar_score(score_final)

    return {
        "score": score_final,
        "max_score": MAX_SCORE_POSSIVEL,
        "nivel": nivel,
        "explicacao": explicacao,
        "recomendacao": recomendacao,
        "indicadores": indicadores,
        "status_conexao": status_conexao,
        "redirecionamento": msg_redir
    }

# ==============================================================================
# RELATÓRIO E INTERFACE
# ==============================================================================
def exibir_relatorio(
    url_analisada: str,
    feeds_encontrados: List[str],
    feeds_com_falha: List[str],
    dados_heuristica: Optional[Dict[str, Any]] = None
) -> None:
    print("\n" + "=" * 65)
    print("           🛡️ RELATÓRIO DE ANÁLISE DE SEGURANÇA DA URL (V3.4)")
    print("=" * 65)
    print(f"📍 URL Analisada      : {url_analisada}")

    if feeds_com_falha:
        print(f"⚠️ AVISO DE FEEDS    : Falha ao consultar {', '.join(feeds_com_falha)}. Análise baseada em dados disponíveis.")

    if feeds_encontrados:
        print(f"📋 Status em Blacklist: ENCONTRADA 🚨 (Fonte: {', '.join(feeds_encontrados)})")
        print("-" * 65)
        print("🚨 CLASSIFICAÇÃO        : AMEAÇA CONFIRMADA ☠️")
        print("📝 Diagnóstico          : A URL consta em bases de dados públicas de ameaças.")
        print("💡 Ação Recomendada     : NÃO ACESSE ESTE LINK em nenhuma hipótese.")
    else:
        print("📋 Status em Blacklist: NÃO ENCONTRADA ✅")
        print("-" * 65)
        if dados_heuristica:
            print(f"📊 Score de Suspeita   : {dados_heuristica['score']}/{dados_heuristica['max_score']}")
            print(f"🚨 Classificação       : {dados_heuristica['nivel']}")
            print(f"📝 Diagnóstico         : {dados_heuristica['explicacao']}")
            print(f"🌐 Status da Conexão   : {dados_heuristica['status_conexao']}")
            print(f"🔄 Redirecionamento    : {dados_heuristica['redirecionamento']}")

            print("\n🚩 Indicadores Identificados:")
            if dados_heuristica['indicadores']:
                for ind in dados_heuristica['indicadores']:
                    print(f"  • {ind}")
            else:
                print("  • Nenhum fator atípico foi identificado.")

            print(f"\n💡 Recomendação        : {dados_heuristica['recomendacao']}")

    print("=" * 65)
    print("ℹ️ Nota: A ausência nas listas ou pontuação baixa não garante 100% de segurança.")
    print("=" * 65 + "\n")

def verificar_url() -> None:
    base_por_feed, feeds_com_falha = carregar_base_de_dados()

    print("-" * 65)
    print("🛡️  SISTEMA HÍBRIDO DE VERIFICAÇÃO DE URLs (V3.4)")
    print(" (1) Blacklists com Suporte a JSON | (2) Análise Heurística SSRF-Safe")
    print(" Digite 'sair' para encerrar.")
    print("-" * 65)

    while True:
        link_usuario = input("🔗 Cole a URL para verificar: ").strip()

        if link_usuario.lower() == 'sair':
            print("Encerrando o programa... Navegue com segurança!")
            break

        if not link_usuario:
            continue

        if not eh_url_valida(link_usuario):
            print("❌ ERRO: URL inválida. Certifique-se de incluir http:// ou https:// e uma porta válida.\n")
            continue

        link_normalizado = normalizar_url(link_usuario)

        feeds_correspondentes = []
        for nome_feed, conjunto_urls in base_por_feed.items():
            if link_normalizado in conjunto_urls or link_usuario in conjunto_urls:
                feeds_correspondentes.append(nome_feed)

        if feeds_correspondentes:
            exibir_relatorio(link_usuario, feeds_encontrados=feeds_correspondentes, feeds_com_falha=feeds_com_falha)
        else:
            print("🔎 URL ausente das blacklists. Executando análise dinâmica...")
            resultado_heuristico = analisar_heuristica_url(link_normalizado)
            exibir_relatorio(
                link_usuario,
                feeds_encontrados=[],
                feeds_com_falha=feeds_com_falha,
                dados_heuristica=resultado_heuristico
            )

if __name__ == "__main__":
    verificar_url()