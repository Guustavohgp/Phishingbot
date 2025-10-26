import re
import os
import pandas as pd
from collections import Counter

def gerar_relatorio_analitico(caminho_log="logs/phishingbot.log", saida_csv="relatorio_emails.csv"):
    """
    Gera um relatório com base no log principal do phishing bot.
    O log deve conter mensagens no formato:
      [SUSPEITO] id | motivos | snippet
      [OK] id | snippet
    """
    if not os.path.exists(caminho_log):
        raise FileNotFoundError(f"Arquivo de log não encontrado: {caminho_log}")

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

            # Conta níveis (INFO, WARNING etc.)
            m_nivel = padrao_nivel.search(linha)
            if m_nivel:
                niveis[m_nivel.group(1)] += 1

            # Verifica tipo de email
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

    print("\n===== RELATÓRIO DE ANÁLISE DE E-MAILS =====")
    print(f"Total de e-mails analisados: {total_emails}")
    print(f"E-mails suspeitos: {suspeitos} ({porcentagem_suspeitos:.2f}%)")
    print(f"E-mails normais: {total_emails - suspeitos} ({porcentagem_ok:.2f}%)")
    print("\nNíveis de log:")
    for nivel, qtd in niveis.items():
        print(f"  {nivel}: {qtd}")

    # Salva CSV para controle histórico
    df = pd.DataFrame(registros)
    df.to_csv(saida_csv, index=False, encoding="utf-8-sig")
    print(f"\nRelatório salvo em: {saida_csv}")


if __name__ == "__main__":
    gerar_relatorio_analitico()
