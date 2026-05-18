"""
agent.py — AI explanation layer using Gemini.

"""

import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

class FraudAgent:
    """
    Wraps the Gemini API to produce plain-English fraud explanations.

    OOP note: putting this in a class means main.py just does:
        agent = FraudAgent()
        explanation = agent.explain(row, triggers)
    One object, one method — easy to swap the model later.
    """

    def __init__(self):
        # gemini-2.0-flash free
        self.client = genai.Client()
        self.model = "gemini-2.5-flash"

    def explain(self, row: dict, triggers: list[str]) -> str:
        """
        build a prompt from row + triggers, call Gemini, return the text.
        """
        signals = f"""
                Email: {row.get('email')}
                IP: {row.get('IP Address')}
                Country: {row.get('Country')}
                OS: {row.get('OS Name and Version')}
                Triggered rules: {', '.join(triggers) if triggers else 'none'}
                """

        prompt = f"""
                You are a fraud analyst reviewing a trial account signup.
                {signals}
                In 2-3 sentences, explain why this account might look suspicious.
                For email's username (NOT THE DOMAIN), its a randomized prefix for my dataset for privacy, so ignore that.
                What would be the recommended action you suggest: : block / review / approve
                """
        
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt
        )

        return response.text or "No explanation available."
