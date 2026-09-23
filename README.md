# 🛡️ CliqueSeguro

O **CliqueSeguro** é uma solução para detecção e prevenção de ameaças digitais, como *phishing*, golpes e links maliciosos. O projeto combina técnicas tradicionais de análise de dados (*web scraping*, checagem de bancos externos) com Inteligência Artificial para proteger usuários em tempo real através de múltiplos canais de comunicação.

---

## 🛠️ Stack Tecnológica

- **Backend:** Java
- **Frontend:** XML (Desenvolvimento Nativo Android)
- **Banco de Dados:**
  - **Supabase:** Autenticação, gestão de usuários e banco de dados principal na nuvem.
  - **SQLite:** Armazenamento local para histórico de links e consultas rápidas.

---

## 🚀 Funcionalidades

### 🔹 Módulo Base (Sem IA)
* **Verificador de Links:** Validação e análise de URLs suspeitas.
* **Web Scraping:** Extração e verificação do conteúdo da página para identificar padrões maliciosos.
* **Pesquisa em Bancos Externos:** Consulta de reputação de domínio em bases de dados públicas de segurança.
* **Leitor de QR Code (Câmera):** Leitura e verificação de segurança de códigos QR (*Recurso com limite/Premium*).

### 🤖 Módulo Inteligência Artificial
* **Explicação do Perigo:** Geração de relatórios simples explicando de forma didática por que um link ou mensagem é perigoso.
* **Verificador em Tempo Real:** Monitoramento preventivo contra golpes recebidos via:
  * SMS
  * E-mails
  * Telefonemas
  * WhatsApp
  * Navegação Web

---

## 💼 Modelo de Negócio

### Estratégia de Renda & Monetização
* **Sistema de Tokens:** Limite diário de verificações gratuitas de links. Ao atingir o limite, o usuário precisa aguardar o reset ou adquirir mais saldo.
* **Planos de Assinatura:**
  * **B2C (Consumidor Final):** Acesso ilimitado, proteção em tempo real e uso de IA avançada.
  * **B2B (Empresas):** Proteção corporativa para colaboradores (*benefícios em definição*).
* **Outras fontes de monetização:** *Em definição.*

### Planejamento Financeiro & Custos
* **Fase Inicial:** Custo zero ($0), operando integralmente nas cotas gratuitas das tecnologias utilizadas.
* **Fase de Escala (Futuro):**
  * Licença da Apple App Store / Google Play Console.
  * APIs de Inteligência Artificial mais potentes ou hospedagem de modelos próprios.

---

## 🏗️ Infraestrutura e Recursos

| Componente | Estágio Inicial (Gratuito) | Estágio Futuro (Escala) |
| :--- | :--- | :--- |
| **Servidor** | GitHub Codespaces (Plano Pro gratuito) | Amazon AWS / Nuvem Dedicada |
| **Banco de Dados** | Supabase (Plano Free) | Supabase Pro |
| **IA** | Modelos Gratuitos / Open-source | APIs pagas com maior capacidade e precisão |

---

## 🗺️ Cronograma de Desenvolvimento (Roadmap)

### 🧪 Fase Beta (MVP - Sem funções pagas)
- [ ] Módulo de Cadastro e Login de Usuários (Integração Supabase).
- [ ] Leitura de QR Code via Câmera.
- [ ] Sintetizador de links (remoção de *trackers*) e *Web Scraping* simplificado.

### 💳 Versão 1.0 (Monetização)
- [ ] Implementação do sistema de tokens/limites nos recursos Beta (*trackers* e câmera).
- [ ] Integração com métodos de pagamento (Cartão de Crédito e PIX).
- [ ] Verificador automático de pagamento e liberação de recursos *Premium*.
