import re
import os
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt # type: ignore
from datetime import datetime

def gerar_relatorio_completo(caminho_log="logs/phishingbot.log", pasta_saida="relatorios"):
    """
    Gera relatório completo com gráficos e dashboard HTML.
    """
    os.makedirs(pasta_saida, exist_ok=True)

    total_emails = 0
    suspeitos = 0
    registros = []
    niveis = Counter()

    padrao_suspeito = re.compile(r"\[SUSPEITO\]|\[QUARENTENA\]", re.IGNORECASE)
    padrao_ok = re.compile(r"\[OK\]", re.IGNORECASE)
    padrao_nivel = re.compile(r"\[(INFO|WARNING|ERROR|DEBUG)\]")

    with open(caminho_log, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue

            # Conta níveis
            m_nivel = padrao_nivel.search(linha)
            if m_nivel:
                niveis[m_nivel.group(1)] += 1

            if padrao_suspeito.search(linha):
                suspeitos += 1
                total_emails += 1
                registros.append({"tipo": "suspeito", "linha": linha})
            elif padrao_ok.search(linha):
                total_emails += 1
                registros.append({"tipo": "ok", "linha": linha})

    if total_emails == 0:
        print("Nenhum email encontrado nos logs.")
        return

    porcentagem_suspeitos = (suspeitos / total_emails) * 100
    porcentagem_ok = 100 - porcentagem_suspeitos

    # -------------------------------
    # Salvar CSV
    # -------------------------------
    df = pd.DataFrame(registros)
    csv_path = os.path.join(pasta_saida, "relatorio_emails.csv")
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")

    # -------------------------------
    # Gráficos
    # -------------------------------
    grafico_pizza = os.path.join(pasta_saida, "grafico_pizza.png")
    grafico_barras = os.path.join(pasta_saida, "grafico_barras.png")

    # Pizza: proporção suspeitos x normais
    plt.figure(figsize=(4, 4))
    plt.pie(
        [suspeitos, total_emails - suspeitos],
        labels=["Suspeitos", "Normais"],
        autopct="%1.1f%%",
        startangle=140
    )
    plt.title("Proporção de e-mails suspeitos")
    plt.savefig(grafico_pizza, bbox_inches="tight")
    plt.close()

    # Barras: níveis de log (com fallback)
    plt.figure(figsize=(6, 4))

    # Níveis padrão
    niveis_padrao = ["INFO", "WARNING", "ERROR", "DEBUG"]
    valores = [niveis.get(n, 0) for n in niveis_padrao]

    plt.bar(niveis_padrao, valores, color="#40739e")
    plt.title("Distribuição dos níveis de log")
    plt.xlabel("Nível")
    plt.ylabel("Quantidade")

    # Adiciona rótulos de valor acima das barras
    for i, v in enumerate(valores):
        plt.text(i, v + 0.1, str(v), ha="center", fontweight="bold")

    plt.ylim(0, max(valores + [1]) * 1.2)
    plt.savefig(grafico_barras, bbox_inches="tight")
    plt.close()

    # -------------------------------
    # Dashboard HTML
    # -------------------------------
    html_path = os.path.join(pasta_saida, "dashboard_emails.html")
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M")

    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>Relatório de E-mails - PhishingBot</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                background-color: #f5f6fa;
                color: #2f3640;
            }}
            h1 {{
                color: #273c75;
            }}
            .card {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.1);
                padding: 20px;
                margin-bottom: 20px;
            }}
            .stats {{
                display: flex;
                justify-content: space-around;
                margin-bottom: 20px;
            }}
            .stat {{
                text-align: center;
                font-size: 1.2em;
            }}
            img {{
                display: block;
                margin: 0 auto;
                max-width: 80%;
            }}
        </style>
    </head>
    <body>
        <h1>📊 Relatório de E-mails - PhishingBot</h1>
        <p>Gerado em: {data_atual}</p>

        <div class="stats">
            <div class="stat"><b>Total:</b><br>{total_emails}</div>
            <div class="stat"><b>Suspeitos:</b><br>{suspeitos} ({porcentagem_suspeitos:.1f}%)</div>
            <div class="stat"><b>Normais:</b><br>{total_emails - suspeitos} ({porcentagem_ok:.1f}%)</div>
        </div>

        <div class="card">
            <h2>Proporção de E-mails</h2>
            <img src="grafico_pizza.png" alt="Gráfico de Pizza">
        </div>

        <div class="card">
            <h2>Distribuição dos Níveis de Log</h2>
            <img src="grafico_barras.png" alt="Gráfico de Barras">
        </div>

        <div class="card">
            <h2>Resumo dos Logs</h2>
            <p>Arquivo CSV gerado: <b>{csv_path}</b></p>
        </div>
    </body>
    </html>
    """

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print("\n===== RELATÓRIO COMPLETO GERADO =====")
    print(f"Total de e-mails: {total_emails}")
    print(f"Suspeitos: {suspeitos} ({porcentagem_suspeitos:.1f}%)")
    print(f"Normais: {total_emails - suspeitos} ({porcentagem_ok:.1f}%)")
    print(f"Relatório CSV salvo em: {csv_path}")
    print(f"Dashboard HTML salvo em: {html_path}")
    print(f"Gráficos: {grafico_pizza}, {grafico_barras}")


if __name__ == "__main__":
    gerar_relatorio_completo()
