from openai import OpenAI

from app.ai.models import AIAnalysisResult
from app.ai.prompt import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
)
from app.config import (
    AI_API_KEY,
    AI_BASE_URL,
    AI_MODEL,
)


class AIClient:
    def __init__(self):
        self.client = OpenAI(
            api_key=AI_API_KEY,
            base_url=AI_BASE_URL,
        )

    def analyze(
        self,
        products: list[str],
        cves: list[str],
        article_text: str,
    ) -> AIAnalysisResult:
        prompt = build_analysis_prompt(
            products=products,
            cves=cves,
            article_text=article_text,
        )

        response = self.client.responses.parse(
            model=AI_MODEL,
            instructions=SYSTEM_PROMPT,
            input=prompt,
            text_format=AIAnalysisResult,
        )

        if not response.output_parsed:
            raise RuntimeError(
                'AI response could not be parsed'
            )

        return response.output_parsed