"""Testes unitários do Verificador de URLs (CliqueSeguro v3.4).

Os testes são isolados da rede: todas as respostas HTTP e consultas DNS são simuladas.
Execute a partir da pasta python/ com:
    python -m unittest discover -s tests -v
"""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PYTHON_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PYTHON_DIR / "main.py"
_spec = importlib.util.spec_from_file_location("verificador_main", MAIN_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Não foi possível carregar o módulo principal: {MAIN_PATH}")
verificador = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verificador)


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeFeedResponse:
    def __init__(self, content: bytes):
        self.content = content

    def read(self):
        return self.content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, request.get_method(), timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class TestValidacaoENormalizacao(unittest.TestCase):
    def test_aceita_urls_http_https(self):
        self.assertTrue(verificador.eh_url_valida("https://example.com/path"))
        self.assertTrue(verificador.eh_url_valida("http://example.com"))
        self.assertTrue(verificador.eh_url_valida("HTTPS://EXAMPLE.COM"))

    def test_rejeita_esquema_ou_host_invalido(self):
        for url in ("ftp://example.com", "https:///caminho", "", None, "not-a-url"):
            with self.subTest(url=url):
                self.assertFalse(verificador.eh_url_valida(url))

    def test_rejeita_porta_invalida(self):
        self.assertFalse(verificador.eh_url_valida("https://example.com:99999"))
        self.assertFalse(verificador.eh_url_valida("https://example.com:abc"))

    def test_normalizacao_de_esquema_host_e_porta_padrao(self):
        self.assertEqual(
            verificador.normalizar_url("HTTPS://Example.COM:443/path"),
            "https://example.com/path",
        )
        self.assertEqual(
            verificador.normalizar_url("HTTP://EXAMPLE.COM:80/a"),
            "http://example.com/a",
        )

    def test_normalizacao_preserva_query_e_fragmento_na_versao_gemini(self):
        self.assertEqual(
            verificador.normalizar_url("https://Example.com/a?q=1#secao"),
            "https://example.com/a?q=1#secao",
        )

    def test_reconhece_ipv4_e_ipv6(self):
        self.assertTrue(verificador.eh_endereco_ip("8.8.8.8"))
        self.assertTrue(verificador.eh_endereco_ip("2001:4860:4860::8888"))
        self.assertFalse(verificador.eh_endereco_ip("example.com"))


class TestFeeds(unittest.TestCase):
    def test_processa_feed_texto_e_ignora_comentarios(self):
        conteudo = "https://a.example/path\n# comentário\n\ntexto inválido\nhttps://b.example"
        self.assertEqual(
            verificador.processar_resposta_feed(conteudo, "text"),
            {"https://a.example/path", "https://b.example"},
        )

    def test_processa_feed_json_com_lista_urls(self):
        conteudo = '{"urls":["https://a.example", {"url":"https://b.example/path"}]}'
        self.assertEqual(
            verificador.processar_resposta_feed(conteudo, "json"),
            {"https://a.example", "https://b.example/path"},
        )

    def test_processa_feed_json_com_campo_data(self):
        self.assertEqual(
            verificador.processar_resposta_feed(
                '{"data":[{"url":"https://a.example/path"}]}', "json"
            ),
            {"https://a.example/path"},
        )

    def test_json_malformado_ou_conteudo_vazio_nao_quebra(self):
        self.assertEqual(verificador.processar_resposta_feed("{json inválido", "json"), set())
        self.assertEqual(verificador.processar_resposta_feed("", "text"), set())
        self.assertEqual(verificador.processar_resposta_feed(None, "json"), set())

    def test_cache_valido_e_reutilizado_sem_rede(self):
        with tempfile.TemporaryDirectory() as pasta:
            cache_original = verificador.CACHE_DIR
            feeds_originais = verificador.FEEDS_AMEACAS
            try:
                verificador.CACHE_DIR = Path(pasta)
                verificador.FEEDS_AMEACAS = [
                    {"nome": "Teste", "url": "https://feed.example/lista", "tipo": "text"}
                ]
                arquivo = verificador.obter_caminho_cache(verificador.FEEDS_AMEACAS[0]["url"])
                arquivo.write_text("https://malware.example/path\n", encoding="utf-8")
                with patch.object(verificador.urllib.request, "urlopen", side_effect=AssertionError("rede inesperada")):
                    dados, falhas = verificador.carregar_base_de_dados()
                self.assertEqual(dados["Teste"], {"https://malware.example/path"})
                self.assertEqual(falhas, [])
            finally:
                verificador.CACHE_DIR = cache_original
                verificador.FEEDS_AMEACAS = feeds_originais

    def test_feed_remoto_valido_e_salvo_no_cache(self):
        with tempfile.TemporaryDirectory() as pasta:
            cache_original = verificador.CACHE_DIR
            feeds_originais = verificador.FEEDS_AMEACAS
            try:
                verificador.CACHE_DIR = Path(pasta)
                verificador.FEEDS_AMEACAS = [
                    {"nome": "Teste", "url": "https://feed.example/lista", "tipo": "text"}
                ]
                resposta = FakeFeedResponse(b"https://b.example\nhttps://a.example\n")
                with patch.object(verificador.urllib.request, "urlopen", return_value=resposta):
                    dados, falhas = verificador.carregar_base_de_dados()
                arquivo = verificador.obter_caminho_cache(verificador.FEEDS_AMEACAS[0]["url"])
                self.assertEqual(dados["Teste"], {"https://a.example", "https://b.example"})
                self.assertEqual(falhas, [])
                self.assertTrue(arquivo.is_file())
            finally:
                verificador.CACHE_DIR = cache_original
                verificador.FEEDS_AMEACAS = feeds_originais


class TestProtecaoIP(unittest.TestCase):
    def test_bloqueia_ip_privado_loopback_e_reservado(self):
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"):
            with self.subTest(ip=ip):
                self.assertTrue(verificador.eh_ip_privado_ou_reservado(ip))
                self.assertFalse(verificador.validar_ip_destino(ip)[0])

    def test_aceita_ip_publico_conhecido(self):
        self.assertFalse(verificador.eh_ip_privado_ou_reservado("8.8.8.8"))
        self.assertTrue(verificador.validar_ip_destino("8.8.8.8")[0])

    def test_bloqueia_dns_com_algum_endereco_privado(self):
        resposta_publica = (None, None, None, None, ("8.8.8.8", 0))
        resposta_privada = (None, None, None, None, ("192.168.1.10", 0))
        with patch.object(
            verificador.socket,
            "getaddrinfo",
            return_value=[resposta_publica, resposta_privada],
        ):
            permitido, motivo = verificador.validar_ip_destino("misto.example")
        self.assertFalse(permitido)
        self.assertIn("privado/reservado", motivo)

    def test_falha_dns_retorna_bloqueio(self):
        with patch.object(verificador.socket, "getaddrinfo", side_effect=verificador.socket.gaierror):
            permitido, motivo = verificador.validar_ip_destino("nao-resolve.example")
        self.assertFalse(permitido)
        self.assertIn("Falha", motivo)


class TestAnaliseDinamica(unittest.TestCase):
    def test_redirecionamento_externo_e_sinalizado(self):
        opener = FakeOpener([FakeResponse(302, {"Location": "https://evil.example/login"})])
        with patch.object(verificador.urllib.request, "build_opener", return_value=opener), patch.object(
            verificador, "validar_ip_destino", return_value=(True, "ok")
        ), patch.object(verificador, "dominios_relacionados", return_value=False):
            score, mensagem, status = verificador.testar_redirecionamento_seguro(
                "https://example.com", "example.com"
            )
        self.assertEqual(score, verificador.PESO_REDIR_EXTERNO)
        self.assertIn("evil.example", mensagem)
        self.assertEqual(status, "Redirecionamento externo detectado")
        self.assertEqual(opener.requests[0][1], "HEAD")

    def test_redirecionamento_relativo_e_seguido(self):
        opener = FakeOpener([FakeResponse(302, {"Location": "/proxima"}), FakeResponse(200)])
        with patch.object(verificador.urllib.request, "build_opener", return_value=opener), patch.object(
            verificador, "validar_ip_destino", return_value=(True, "ok")
        ), patch.object(verificador, "dominios_relacionados", return_value=True):
            score, _mensagem, status = verificador.testar_redirecionamento_seguro(
                "https://example.com/inicio", "example.com"
            )
        self.assertEqual(score, 0)
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(opener.requests[1][0], "https://example.com/proxima")
        self.assertEqual(status, "HTTP 200")

    def test_redirecionamento_para_ip_privado_e_bloqueado(self):
        opener = FakeOpener([FakeResponse(302, {"Location": "http://127.0.0.1/admin"})])
        def validar(host):
            if host == "127.0.0.1":
                return False, "Endereço IP privado/reservado bloqueado"
            return True, "ok"
        with patch.object(verificador.urllib.request, "build_opener", return_value=opener), patch.object(
            verificador, "validar_ip_destino", side_effect=validar
        ):
            score, mensagem, status = verificador.testar_redirecionamento_seguro(
                "https://example.com", "example.com"
            )
        self.assertEqual(score, 0)
        self.assertIn("bloqueado", mensagem.lower())
        self.assertIn("SSRF", status)

    def test_url_invalida_nao_inicia_analise_dinamica(self):
        with patch.object(
            verificador,
            "testar_redirecionamento_seguro",
            side_effect=AssertionError("a análise dinâmica não deveria ser executada"),
        ):
            resultado = verificador.analisar_heuristica_url("file:///etc/passwd")
        self.assertEqual(resultado["score"], 0)
        self.assertEqual(resultado["status_conexao"], "Não verificada")
        self.assertEqual(resultado["redirecionamento"], "Não verificado")

    def test_score_e_classificacao_de_risco(self):
        self.assertIn("BAIXO RISCO", verificador.classificar_score(0)[0])
        self.assertIn("RISCO MODERADO", verificador.classificar_score(15)[0])
        self.assertIn("ALTO RISCO", verificador.classificar_score(30)[0])
        self.assertIn("MUITO ALTO RISCO", verificador.classificar_score(50)[0])

    def test_heuristica_retorna_campos_esperados(self):
        with patch.object(
            verificador,
            "testar_redirecionamento_seguro",
            return_value=(0, "Sem redirecionamento externo", "HTTP 200"),
        ):
            resultado = verificador.analisar_heuristica_url("https://example.com/path")
        for campo in (
            "score", "max_score", "nivel", "explicacao", "recomendacao",
            "indicadores", "status_conexao", "redirecionamento",
        ):
            with self.subTest(campo=campo):
                self.assertIn(campo, resultado)
        self.assertLessEqual(resultado["score"], resultado["max_score"])


class TestRelatorio(unittest.TestCase):
    def test_relatorio_identifica_url_em_blacklist(self):
        from contextlib import redirect_stdout
        from io import StringIO
        saida = StringIO()
        with redirect_stdout(saida):
            verificador.exibir_relatorio("https://bad.example", ["TesteFeed"], [])
        texto = saida.getvalue()
        self.assertIn("ENCONTRADA", texto)
        self.assertIn("TesteFeed", texto)


if __name__ == "__main__":
    unittest.main(verbosity=2)
