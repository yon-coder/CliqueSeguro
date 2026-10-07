import urllib.request

#feed de texto do URLhaus (abuse.ch)
FEED_URL = "https://urlhaus.abuse.ch/downloads/text/"

def carregar_base_de_dados():
    print("⏳ Atualizando banco de dados de ameaças... aguarde.")
    urls_maliciosas = set()
    
    try:
        #requisita o arquivo de texto
        req = urllib.request.Request(FEED_URL, headers={'User-Agent': 'Mozilla/5.0'})
        resposta = urllib.request.urlopen(req)
        
        #lê e decodifica as linhas
        linhas = resposta.read().decode('utf-8').splitlines()
        
        for linha in linhas:
            #ignora as linhas de comentários (que começam com #) e linhas vazias
            if not linha.startswith('#') and linha.strip():
                urls_maliciosas.add(linha.strip())
                
        print(f"✅ Base carregada! {len(urls_maliciosas)} URLs maliciosas na memória.\n")
        return urls_maliciosas
        
    except Exception as erro:
        print(f"❌ Erro ao baixar o feed: {erro}")
        return set()

def verificar_url():
    base_urls = carregar_base_de_dados()
    
    if not base_urls:
        print("Encerrando o programa por falha no download da base.")
        return

    print("-" * 50)
    print("🛡️ VERIFICADOR DE URLS SUSPEITAS")
    print("Digite 'sair' a qualquer momento para fechar.")
    print("-" * 50)

    while True:
        link_usuario = input("\n🔗 Cole o link aqui: ").strip()
        
        if link_usuario.lower() == 'sair':
            print("Encerrando... Navegue com segurança!")
            break
            
        if not link_usuario:
            continue

        #verifica se o link exato está na lista de bloqueio
        if link_usuario in base_urls:
            print("🚨 STATUS: PERIGOSO!")
            print("   Motivo: Este link está listado em uma base pública de distribuição de malware.")
        else:
            print("⚠️ STATUS: NÃO DEFINIDO / APARENTEMENTE SEGURO")
            print("   Nota: O link não está na nossa base atual de ameaças. Porém, links novos podem")
            print("   ainda não ter sido detectados. Mantenha a cautela.")

if __name__ == "__main__":
    verificar_url()