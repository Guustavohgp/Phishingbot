# 🛡️ Phishing Detection Bot

Um projeto para identificar e sinalizar e-mails potencialmente maliciosos, utilizando integração com a **Gmail API** e técnicas de detecção de phishing.  
O sistema pode ser adaptado para diferentes provedores de e-mail e permite integração futura com IA (como **Google Gemini**) para análise de conteúdo.

## 🔐 Sobre Cibersegurança e Phishing

A **Cibersegurança** é a prática de proteger sistemas, redes e dados contra ataques digitais.  
Entre as ameaças mais comuns, o **Phishing** é um método fraudulento usado para enganar pessoas e obter informações sensíveis, como senhas, dados bancários e informações pessoais.

No Phishing, criminosos se passam por entidades legítimas, geralmente por e-mail, para induzir a vítima a clicar em links maliciosos ou abrir anexos infectados.

### 📌 Tipos comuns de ataques de Phishing:
- **Phishing Tradicional:** e-mails genéricos enviados em massa com links fraudulentos.
- **Spear Phishing:** ataques direcionados a indivíduos ou empresas específicas, usando informações personalizadas.
- **Whaling:** phishing direcionado a executivos e pessoas de alto escalão.
- **Clone Phishing:** cópia de mensagens legítimas, alterando links para versões maliciosas.
- **Smishing:** phishing via mensagens SMS.
- **Vishing:** phishing por chamadas de voz.

💡 Este projeto foi criado como uma ferramenta auxiliar para identificar e bloquear esses tipos de ameaças antes que causem danos.

---

## 🚀 Funcionalidades
- 📧 Conexão com a **Gmail API** usando credenciais OAuth2.
- 🔍 Verificação de e-mails recebidos para identificar padrões suspeitos.
- 📜 Lista de domínios confiáveis e suspeitos.
- 📝 Registro de e-mails sinalizados como phishing.
- 🔮 Preparado para integração com IA para moderação e classificação automática.

## 🗺️ Fluxo de Detecção

```mermaid
flowchart TD
    A[ 📥 Receber E-mails via Gmail API ] --> B{O remetente é confiável?}
    B -- Sim --> C[📌 Classificar como seguro]
    B -- Não --> D{Domínio na lista suspeita?}
    D -- Sim --> E[🚨 Marcar como phishing]
    D -- Não --> F[ 🔍 Analisar padrões suspeitos no conteúdo ]
    F -- Suspeito --> E
    F -- Seguro --> C
    E --> G[📝 Registrar e alertar o usuário]
    C --> H[✅ Finalizar verificação]
