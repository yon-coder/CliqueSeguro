import urllib.request
from urllib.parse import urlparse
import ipaddress

PESO_IP_DIRETO = 25       # Oculta o registro do domínio real; forte indicador.
PESO_URL_LONGA = 5        # Isoladamente fraco; muito comum em tokens e sessões legítimas.
PESO_HTTP = 5             # Isoladamente fraco; muitos sites antigos ainda utilizam.
PESO_PALAVRA_CHAVE = 5    # Isoladamente fraco; termos como 'login' são usados em sites reais.
PESO_COMBINADO = 15       # Bônus aplicado se múltiplas características fracas ocorrerem juntas.
PESO_REDIR_SUBDOMINIO = 5 # Baixo risco; comum em CDNs e direcionamento para áreas de login.
PESO_REDIR_EXTERNO = 20   # Risco maior; o usuário é levado a um domínio totalmente não relacionado.

FEEDS_AMEACAS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
    "https://threatfox.abuse.ch/export/urls/recent/"
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def eh_url_valida(url: str) -> bool:
    try:
        resultado = urlparse(url)
        return all([resultado.scheme in ('http', 'https'), resultado.netloc])
    except Exception:
        return False

def normalizar_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path == '/':
            path = ''
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url

def dominios_relacionados(dom1: str, dom2: str) -> bool:
    partes1 = dom1.split('.')
    partes2 = dom2.split('.')
    if len(partes1) >= 2 and len(partes2) >= 2:
        return partes1[-2:] == partes2[-2:]
    return dom1 == dom2

def carregar_base_de_dados():
    print("⏳ [Fase 1] Carregando bases de dados estáticas (Blacklists)...")
    urls_maliciosas = set()

    for feed_url in FEEDS_AMEACAS:
        try:
            req = urllib.request.Request(feed_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resposta:
                linhas = resposta.read().decode('utf-8', errors='ignore').splitlines()
                
                for linha in linhas:
                    linha_limpa = linha.strip()
                    if linha_limpa and not linha_limpa.startswith('#'):
                        urls_maliciosas.add(normalizar_url(linha_limpa))
                print(f"  └─ Sucesso ao ler: {feed_url}")
        except Exception as erro:
            print(f"  └─ ⚠️ Falha ao baixar ({feed_url}): {erro}")

    print(f"✅ Bases carregadas! {len(urls_maliciosas):,} URLs conhecidas na memória.\n")
    return urls_maliciosas

def analisar_heuristica_url(url: str) -> dict:
    pontos_suspeitos = 0
    motivos = []
    indicadores_fracos = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc

    try:
        ipaddress.ip_address(domain.split(':')[0])
        pontos_suspeitos += PESO_IP_DIRETO
        motivos.append("Uso de IP direto em vez de nome de domínio.")
    except ValueError:
        pass

    if len(url) > 75:
        pontos_suspeitos += PESO_URL_LONGA
        indicadores_fracos += 1
        motivos.append("Comprimento da URL longo.")

    palavras_chave = ['login', 'verify', 'account', 'banking', 'secure', 'update', 'senha']
    if any(palavra in url.lower() for palavra in palavras_chave):
        pontos_suspeitos += PESO_PALAVRA_CHAVE
        indicadores_fracos += 1
        motivos.append("Contém palavras-chave comumente associadas a áreas sensíveis.")

    if parsed.scheme == 'http':
        pontos_suspeitos += PESO_HTTP
        indicadores_fracos += 1
        motivos.append("Conexão não criptografada (HTTP).")

    if indicadores_fracos >= 3:
        pontos_suspeitos += PESO_COMBINADO
        motivos.append("Combinação de múltiplos indicadores fracos (URL longa, HTTP, palavras-chave).")

    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resposta:
            url_final = resposta.geturl()
            domain_final = urlparse(url_final).netloc
            
            if domain_final != domain:
                if dominios_relacionados(domain, domain_final):
                    pontos_suspeitos += PESO_REDIR_SUBDOMINIO
                    motivos.append(f"Redirecionamento para subdomínio ou domínio relacionado: {domain_final}")
                else:
                    pontos_suspeitos += PESO_REDIR_EXTERNO
                    motivos.append(f"Redirecionamento para domínio externo não relacionado: {domain_final}")
    except Exception as e:
        motivos.append(f"Não foi possível verificar redirecionamentos: {e}")

    if pontos_suspeitos >= 40:
        nivel = "ALTO RISCO 🚨"
    elif pontos_suspeitos >= 20:
        nivel = "MÉDIO RISCO ⚠️"
    else:
        nivel = "BAIXO RISCO ✅"

    return {"score": pontos_suspeitos, "nivel": nivel, "motivos": motivos}

def verificar_url():
    base_urls = carregar_base_de_dados()

    print("-" * 60)
    print("🛡️  SISTEMA HÍBRIDO DE VERIFICAÇÃO DE URLs")
    print(" (1) Checagem em Blacklists  |  (2) Análise Heurística")
    print(" Digite 'sair' para encerrar.")
    print("-" * 60)

    while True:
        link_usuario = input("\n🔗 Cole a URL para verificar: ").strip()

        if link_usuario.lower() == 'sair':
            print("Encerrando... Navegue com segurança!")
            break

        if not link_usuario:
            continue

        if not eh_url_valida(link_usuario):
            print("❌ ERRO: URL inválida. Inclua http:// ou https://")
            continue

        link_normalizado = normalizar_url(link_usuario)

        if link_normalizado in base_urls or link_usuario in base_urls:
            print("\n🚨 RESULTADO: PERIGO EXTREMO!")
            print("  Motivo: A URL está presente em bases globais de distribuição de malware/phishing.")
            print("  Ação Recomendada: NÃO ACESSE ESTE LINK.")
            continue 

        print("🔎 URL não encontrada nas blacklists. Iniciando análise dinâmica...")
        resultado = analisar_heuristica_url(link_normalizado)

        print(f"\n📊 RESULTADO HEURÍSTICO: {resultado['nivel']} (Score: {resultado['score']}/100)")
        
        if resultado['motivos']:
            print("  Indicadores identificados:")
            for motivo in resultado['motivos']:
                print(f"  • {motivo}")
        
        if resultado['score'] == 0:
            print("  Nenhum indicador suspeito foi encontrado pela heurística.")

if __name__ == "__main__":
    verificar_url()