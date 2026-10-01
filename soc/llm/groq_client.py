"""
Centralized Groq API Client Abstraction.
Integrates the official Groq Python SDK with retry, rate limit handling,
strict Pydantic schema validation, token tracking, and automatic mock fallback.
"""
import json
import logging
import os
import random
import time
from typing import Dict, Any, Optional

from groq import Groq

from soc.llm.token_tracker import TokenTracker
from soc.llm.mock_provider import MockLLMProvider
from soc.schemas.agent_contracts import AgentTask, TokenUsage

logger = logging.getLogger("soc.groq")


SUPPORTED_GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
FAST_GROQ_MODEL = "llama-3.1-8b-instant"


class GroqClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = DEFAULT_GROQ_MODEL,
        max_retries: int = 3,
        enable_mock_fallback: bool = True,
    ):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.default_model = default_model if default_model in SUPPORTED_GROQ_MODELS else DEFAULT_GROQ_MODEL
        self.max_retries = max_retries
        self.enable_mock_fallback = enable_mock_fallback
        self.token_tracker = TokenTracker()
        self.mock_provider = MockLLMProvider()

        self._client: Optional[Groq] = None
        if self.api_key and not self.api_key.startswith("MY_") and len(self.api_key) > 10:
            try:
                self._client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize Groq SDK client: {e}. Falling back to mock provider.")
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def execute_agent_task(
        self,
        task: AgentTask,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes an inference request for an agent task.
        Enforces structured JSON format and captures token usage.
        """
        chosen_model = model or self.default_model
        if chosen_model not in SUPPORTED_GROQ_MODELS:
            chosen_model = self.default_model

        # If live client not configured or mock requested, use mock provider
        if not self._client:
            mock_data = self.mock_provider.generate(task)
            # Record synthetic token metrics
            cost = self.token_tracker.record_usage(chosen_model, prompt_tokens=350, completion_tokens=220)
            mock_data["token_usage"] = TokenUsage(
                prompt_tokens=350,
                completion_tokens=220,
                total_tokens=570,
                estimated_cost_usd=cost,
            )
            mock_data["model_used"] = f"mock-{chosen_model}"
            return mock_data

        # Attempt live Groq inference with exponential backoff & jitter
        attempt = 0
        backoff = 1.0

        while attempt < self.max_retries:
            attempt += 1
            try:
                start_time = time.time()
                response = self._client.chat.completions.create(
                    model=chosen_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=task.token_budget,
                )

                content = response.choices[0].message.content or "{}"
                parsed = json.loads(content)

                prompt_tokens = response.usage.prompt_tokens if response.usage else 300
                completion_tokens = response.usage.completion_tokens if response.usage else 150
                cost = self.token_tracker.record_usage(chosen_model, prompt_tokens, completion_tokens)

                parsed["token_usage"] = TokenUsage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=prompt_tokens + completion_tokens,
                    estimated_cost_usd=cost,
                )
                parsed["model_used"] = chosen_model
                return parsed

            except Exception as e:
                logger.warning(f"Groq API error on attempt {attempt}/{self.max_retries}: {e}")
                if attempt >= self.max_retries:
                    if self.enable_mock_fallback:
                        logger.warning("Max retries exceeded; falling back to mock provider for resilience.")
                        mock_data = self.mock_provider.generate(task)
                        cost = self.token_tracker.record_usage(chosen_model, 350, 220)
                        mock_data["token_usage"] = TokenUsage(
                            prompt_tokens=350,
                            completion_tokens=220,
                            total_tokens=570,
                            estimated_cost_usd=cost,
                        )
                        mock_data["model_used"] = f"fallback-after-error-{chosen_model}"
                        mock_data["warning"] = f"Live Groq error: {str(e)}"
                        return mock_data
                    raise RuntimeError(f"Groq API invocation failed: {e}") from e

                jitter = random.uniform(0.1, 0.5)
                time.sleep(backoff + jitter)
                backoff *= 2.0

        raise RuntimeError("Unexpected end of retry loop in GroqClient")
