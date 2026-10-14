# 🛡️ CliqueSeguro

O **CliqueSeguro** é um projeto voltado à detecção e prevenção de ameaças digitais, como phishing, golpes e links maliciosos. O projeto reúne recursos de análise de URLs e consulta a bases públicas de segurança para ajudar a identificar links suspeitos.

---

## 🛠️ Stack Tecnológica

- **Backend:** Java
- **Frontend:** XML (desenvolvimento nativo Android)
- **Banco de dados:**
  - **Supabase:** autenticação, gestão de usuários e banco de dados na nuvem.
  - **SQLite:** armazenamento local do histórico de links e consultas.
- **Verificador de URLs:** Python
- **Biblioteca Python:** `tldextract`

---

## 🚀 Requisitos do Sistema

Para instalar e executar o verificador de URLs em Python, você precisa de:

- **Python:** versão 3.9 ou superior recomendada.
- **pip:** gerenciador de pacotes Python.
- **Conexão com a internet:** necessária para consultar os feeds públicos de segurança.
- **Sistema operacional:** Windows, Linux ou macOS.
- **Arquivo `requirements.txt`:** contém as dependências do projeto.

### Dependências

O arquivo `requirements.txt` contém:

```txt
tldextract>=5.1.0
```

A biblioteca `tldextract` é utilizada para auxiliar na identificação de domínios registráveis.

---

## 📦 Instalação

### 1. Instale o Python

Caso ainda não tenha o Python instalado, baixe-o pelo site oficial:

https://www.python.org/downloads/

No Windows, marque a opção **Add Python to PATH** durante a instalação.

Verifique se o Python e o pip estão disponíveis:

```bash
python --version
python -m pip --version
```

No Linux ou macOS, pode ser necessário utilizar `python3` no lugar de `python`.

### 2. Clone o repositório

```bash
git clone https://github.com/yon-coder/CliqueSeguro.git
cd CliqueSeguro
```


### 3. Crie um ambiente virtual

**Windows:**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux ou macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Instale as dependências

Com o ambiente virtual ativado, execute:

```bash
python -m pip install -r requirements.txt
```

Para conferir a instalação:

```bash
python -m pip show tldextract
```

---

## ▶️ Como Executar

1. Abra o terminal na pasta em que está o código Python.
2. Ative o ambiente virtual, caso ainda não esteja ativo.
3. Execute o arquivo principal do verificador.

```bash
python CliqueSeguro.py
```


No Linux ou macOS, se necessário, utilize:

```bash
python3 CliqueSeguro.py
```

**Observação:** o nome do arquivo principal e a forma de interação dependem da implementação atual do código. Se o programa apresentar um menu ou solicitar uma URL, siga as instruções exibidas no terminal.

### Funcionamento

O verificador utiliza feeds públicos de segurança para comparar URLs e aplica critérios heurísticos para identificar características potencialmente suspeitas.

Entre as fontes configuradas estão:

- [URLhaus](https://urlhaus.abuse.ch/)
- [OpenPhish](https://openphish.com/)
- [ThreatFox](https://threatfox.abuse.ch/)

Na primeira execução, o programa pode precisar baixar os feeds. O código também utiliza um diretório de cache para armazenar dados localmente e reduzir consultas repetidas.

**Importante:** uma URL não encontrada nas bases consultadas não é necessariamente segura. Os resultados devem ser considerados uma análise indicativa, não uma garantia de segurança.

---

## 🚀 Funcionalidades

### 🔹 Módulo Base (Sem IA)

- **Verificador de Links:** validação e análise de URLs suspeitas.
- **Consulta a Bases Externas:** verificação em feeds públicos de segurança.
- **Análise Heurística:** avaliação de características potencialmente suspeitas em URLs.

### 🤖 Módulo de Inteligência Artificial

- **Explicação do Perigo:** geração de explicações sobre possíveis riscos.
- **Verificação em Tempo Real:** recursos planejados para ajudar a identificar golpes em diferentes canais de comunicação.

*O funcionamento dessas funcionalidades depende da implementação e das integrações disponíveis em cada versão.*

---

## 💼 Modelo de Negócio

### Estratégia de Renda e Monetização

- **Sistema de Tokens:** limite de verificações gratuitas, com possibilidade de aquisição de saldo adicional.
- **Planos de Assinatura:**
  - **B2C:** recursos destinados ao consumidor final.
  - **B2B:** recursos de proteção para empresas, ainda em definição.
- **Outras fontes de monetização:** em definição.

### Planejamento Financeiro e Custos

- **Fase Inicial:** utilização de cotas gratuitas das tecnologias adotadas, quando disponíveis.
- **Fase de Escala:** possíveis custos com publicação nas lojas de aplicativos, APIs de inteligência artificial e hospedagem.

---

## 🏗️ Infraestrutura e Recursos

| Componente | Estágio Inicial | Estágio Futuro |
|---|---|---|
| Servidor | GitHub Codespaces ou ambiente de desenvolvimento | Amazon AWS ou nuvem dedicada |
| Banco de Dados | Supabase Free | Supabase Pro |
| IA | Modelos gratuitos ou open-source | APIs pagas ou modelos próprios |

---

## 🗺️ Cronograma de Desenvolvimento (Roadmap)

### 🧪 Fase Beta — MVP

- [ ] Cadastro e login de usuários com Supabase.
- [ ] Leitura de QR Code pela câmera.
- [ ] Remoção de rastreadores de URLs.
- [ ] Web scraping simplificado.

### 💳 Versão 1.0 — Monetização

- [ ] Implementação de tokens e limites de uso.
- [ ] Integração com pagamentos por cartão de crédito e PIX.
- [ ] Verificação automática de pagamentos e liberação de recursos Premium.

---

## 📄 Licença

A licença do projeto ainda não foi especificada.
