import unittest
import os
import sys
import shutil
from pathlib import Path

# Adiciona o diretório pai ao sys.path para import do main
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import (
    eh_url_valida,
    normalizar_url,
    dominios_relacionados,
    eh_endereco_ip,
    analisar_heuristica_url,
    processar_resposta_feed,
    eh_ip_privado_ou_reservado,
    MAX_SCORE_POSSIVEL,
    LIMIAR_BAIXO_RISCO,
    LIMIAR_RISCO_MODERADO,
    LIMIAR_ALTO_RISCO
)


class TestVerificadorV33(unittest.TestCase):

    def test_1_dominios_relacionados(self):
        """Valida que subdomínios iguais são relacionados e domínios diferentes .com.br não são."""
        self.assertTrue(dominios_relacionados("www.empresa.com.br", "login.empresa.com.br"))
        self.assertFalse(dominios_relacionados("empresa.com.br", "outro.com.br"))
        self.assertTrue(dominios_relacionados("sub.site.co.uk", "site.co.uk"))
        self.assertFalse(dominios_relacionados("site.co.uk", "outro.co.uk"))

    def test_2_comparacao_ips(self):
        """Valida comparação de IPv4 e IPv6 sem truncamentos."""
        self.assertTrue(eh_endereco_ip("192.168.1.1"))
        self.assertTrue(eh_endereco_ip("[2001:db8::1]"))
        self.assertTrue(dominios_relacionados("192.168.1.1", "192.168.1.1"))
        self.assertFalse(dominios_relacionados("192.168.1.1", "192.168.1.2"))
        self.assertTrue(dominios_relacionados("[2001:db8::1]", "2001:db8::1"))
        self.assertFalse(dominios_relacionados("[2001:db8::1]", "[2001:db8::2]"))

    def test_3_normalizacao_urls(self):
        """Valida normalização preservando caminhos e padronizando esquemas."""
        url_bruta = "HTTP://EXEMPLO.COM:8080/Caminho/Teste/?Query=1#Frag"
        url_norm = normalizar_url(url_bruta)
        self.assertEqual(url_norm, "http://exemplo.com:8080/Caminho/Teste/?Query=1#Frag")

    def test_4_rejeicao_urls_invalidas(self):
        """Valida rejeição de esquemas não permitidos e portas fora de intervalo."""
        self.assertFalse(eh_url_valida("ftp://exemplo.com"))
        self.assertFalse(eh_url_valida("http://"))
        self.assertFalse(eh_url_valida("http://exemplo.com:999999"))
        self.assertTrue(eh_url_valida("http://exemplo.com:8080"))

    def test_5_score_maximo_e_limites(self):
        """Garante que o score máximo do sistema é 75 e as faixas são coerentes."""
        self.assertEqual(MAX_SCORE_POSSIVEL, 75)
        res = analisar_heuristica_url("http://192.168.1.1/login_verify_account_banking_secure_update_senha_longa_longa_longa_longa_longa")
        self.assertLessEqual(res['score'], MAX_SCORE_POSSIVEL)
        self.assertIn(res['nivel'], ["ALTO RISCO 🚨", "MUITO ALTO RISCO ☠️"])

    def test_6_parser_feeds_json_e_texto(self):
        """Valida o parse de respostas de feeds em formato JSON e texto puro."""
        resposta_texto = "http://badsite.com/malware\n# comentario\nhttps://phish.org/login"
        urls_txt = processar_resposta_feed(resposta_texto, "text")
        self.assertEqual(len(urls_txt), 2)

        resposta_json = '{"urls": [{"url": "http://threatsite.com/payload"}]}'
        urls_json = processar_resposta_feed(resposta_json, "json")
        self.assertEqual(len(urls_json), 1)

    def test_7_bloqueio_ssrf_ips_locais(self):
        """Valida bloqueio preventivo para endereços privados/loopback."""
        self.assertTrue(eh_ip_privado_ou_reservado("127.0.0.1"))
        self.assertTrue(eh_ip_privado_ou_reservado("10.0.0.1"))
        self.assertTrue(eh_ip_privado_ou_reservado("::1"))
        self.assertFalse(eh_ip_privado_ou_reservado("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()