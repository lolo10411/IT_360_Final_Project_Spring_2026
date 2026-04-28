import os

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def analyze_with_chatgpt(log_line):
    """
    Sends a suspicious Minecraft log event to ChatGPT/OpenAI
    and returns a forensic-style analysis.
    """

    api_key = os.getenv("OPENAI_API_KEY")

    if OpenAI is None:
        return "OpenAI package is not installed. Run: pip install -r requirements.txt"

    if not api_key:
        return "No OPENAI_API_KEY found. AI analysis skipped."

    client = OpenAI(api_key=api_key)

    prompt = f"""
You are a digital forensics assistant analyzing Minecraft server logs for insider threat activity.

Analyze this suspicious log event:
{log_line}

Return:
1. Risk level: Low, Medium, or High
2. Why this event may matter in an insider threat investigation
3. Recommended follow-up evidence to review

Keep the response concise and professional.
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    return response.output_text
