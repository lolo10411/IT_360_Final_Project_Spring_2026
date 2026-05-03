import os

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def analyze_with_chatgpt(log_entry):
    """
    Uses the OpenAI API to provide AI-assisted forensic analysis
    of a suspicious Minecraft server log entry.

    This feature is optional. If no API key is configured, the tool
    still runs and clearly reports that AI analysis was skipped.
    """

    if OpenAI is None:
        return "AI analysis unavailable: OpenAI package is not installed."

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return "AI analysis skipped: OPENAI_API_KEY environment variable is not set."

    client = OpenAI(api_key=api_key)

    prompt = f"""
You are a digital forensics assistant analyzing Minecraft server logs for insider threat activity.

Suspicious log entry:
{log_entry}

Provide:
1. Risk level: Low, Medium, or High
2. Why this event matters in an insider threat investigation
3. Recommended follow-up evidence to review

Keep the response concise and professional.
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    return response.output_text
