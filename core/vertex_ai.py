import google.generativeai as genai

def vertex_moderator(subject: str, body: str) -> str:
    prompt = f"""
Você é um moderador especialista em phishing.
Classifique o email como 'SUSPEITO' ou 'OK' com 1-2 frases de explicação.
Assunto: {subject}
Corpo: {body}
"""
    response = genai.generate_text(
        model="gemini-1.0-pro",
        prompt=prompt,
        max_output_tokens=150
    )
    return getattr(response, 'result', '').strip()