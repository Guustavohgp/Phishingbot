import os
import pandas as pd

# Caminho da pasta onde vai salvar o CSV
folder_path = os.path.join(os.path.dirname(__file__), "datasets", "phishing_dataset")
os.makedirs(folder_path, exist_ok=True)

# Criando dados de exemplo
dados = {
    "text_combined": [
        "Sua conta foi comprometida! Clique aqui para verificar.",
        "Promoção imperdível! Ganhe prêmios agora.",
        "Reunião agendada para amanhã às 10h.",
        "Atualize sua senha imediatamente para evitar bloqueio."
    ],
    "label": [1, 1, 0, 1]  # 1 = phishing, 0 = legítimo
}

df = pd.DataFrame(dados)

# Salvando CSV
csv_path = os.path.join(folder_path, "dataset_teste.csv")
df.to_csv(csv_path, index=False, encoding="utf-8")

print(f"Dataset de teste criado em: {csv_path}")
print(df)