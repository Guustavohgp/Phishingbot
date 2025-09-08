readme:

# 🛡️ Phishing Detection Bot

Um projeto para identificar e sinalizar e-mails potencialmente maliciosos, utilizando integração com a **Gmail API**, **modelo de Machine Learning**, heurísticas e IA (**Google Gemini**) para análise de conteúdo.  
O sistema pode ser adaptado para diferentes provedores de e-mail e está preparado para análises automatizadas de phishing.

---

## 🔐 Sobre Cibersegurança e Phishing

A **Cibersegurança** é a prática de proteger sistemas, redes e dados contra ataques digitais.  
Entre as ameaças mais comuns, o **Phishing** é um método fraudulento usado para enganar pessoas e obter informações sensíveis, como senhas, dados bancários e informações pessoais.

No Phishing, criminosos se passam por entidades legítimas, geralmente por e-mail, para induzir a vítima a clicar em links maliciosos ou abrir anexos infectados.

### 📌 Tipos Comuns de Phishing

| Tipo | Descrição |
|------|-----------|
| 📨 **Phishing Tradicional** | E-mails genéricos enviados em massa com links fraudulentos |
| 🎯 **Spear Phishing** | Ataques direcionados a indivíduos ou empresas específicas |
| 🐋 **Whaling** | Focado em executivos ou pessoas de alto escalão |
| 🔗 **Clone Phishing** | Cópia de mensagens legítimas com links maliciosos |
| 📱 **Smishing** | Phishing via SMS |
| 📞 **Vishing** | Phishing por chamadas de voz |

> Este projeto atua como uma **camada de defesa**, bloqueando ataques antes que causem danos.

---

## 🚀 Funcionalidades

### 📧 Conexão com Gmail
- Integração via OAuth2 para acesso seguro aos e-mails  

### 🔍 Detecção Heurística
- Domínios suspeitos e confiáveis  
- TLDs suspeitos  
- Palavras sensíveis: CPF, cartão, senha, prêmio, etc.  
- Mensagens urgentes ou de pagamento imediato  

### 🧠 Machine Learning
- Random Forest + TF-IDF + 4 features extras  
- Classificação automatizada de e-mails  

### 🤖 Integração com IA
- **Google Gemini** para análise avançada de conteúdo e moderação  

### 📝 Registro e Logs
- Armazena e-mails suspeitos com detalhes das heurísticas e resultados do ML  

### ⚡ Modos Especiais
- **DRY_RUN**: simulação sem mover e-mails  
- Preparado para quarentena e aplicação de labels automáticos no Gmail  

---

## 📦 Requisitos

- **Python 3.9+**  
- Conta **Google Cloud** com **Gmail API** habilitada  
- **Dataset** de phishing (CSV)
- **Instalar** dependências listadas no requirements.txt:
    - Comando: **pip install -r requirements.txt** 

- Arquivos de autenticação:
    - **token.json** (gerado após autorizar acesso à Gmail API)
    - **credentials.json** (credenciais do OAuth da Gmail API)
    - **vertex.json** (credenciais para Vertex AI / Gemini)
---

## 📊 Gmail

O sistema acessa sua caixa de entrada do Gmail, analisa os emails e classifica automaticamente os que forem suspeitos.
Todos os emails detectados como phishing são movidos para uma label exclusiva chamada “Quarentena Phishing”.


- **Caixa de entrada:**
<img width="1828" height="697" alt="image" src="https://github.com/user-attachments/assets/38622441-639e-4ad0-97ea-a5301689a5e2" />


- **Quarentena Phishing:**
<img width="1827" height="698" alt="image" src="https://github.com/user-attachments/assets/40b3ec2a-12ee-4bf0-a160-f921088228b5" />


---

## 🔮 Próximos Passos

- Dashboard em tempo real com **métricas de segurança**  
- Aprimoramento contínuo do modelo ML com **novos datasets**  
- Suporte a **outros provedores de e-mail** e alertas corporativos  


