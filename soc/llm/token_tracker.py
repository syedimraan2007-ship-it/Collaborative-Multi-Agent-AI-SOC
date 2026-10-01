"""
Token Usage Tracker and Inference Cost Calculator.
Tracks prompt tokens, completion tokens, model pricing, and cumulative expenditures.
"""
from typing import Dict
from pydantic import BaseModel, Field


# Pricing estimates per 1M tokens (USD) for Groq hosted models
MODEL_PRICING_PER_MILLION: Dict[str, Dict[str, float]] = {
    "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
    "llama-3.1-70b-versatile": {"input": 0.59, "output": 0.79},
    "llama-3.1-8b-instant": {"input": 0.05, "output": 0.08},
    "mixtral-8x7b-32768": {"input": 0.24, "output": 0.24},
    "gemma2-9b-it": {"input": 0.20, "output": 0.20},
}


class TokenMetrics(BaseModel):
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    calls_count: int = 0


class TokenTracker:
    def __init__(self):
        self._metrics = TokenMetrics()

    def record_usage(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        self._metrics.total_prompt_tokens += prompt_tokens
        self._metrics.total_completion_tokens += completion_tokens
        total = prompt_tokens + completion_tokens
        self._metrics.total_tokens += total
        self._metrics.calls_count += 1

        pricing = MODEL_PRICING_PER_MILLION.get(
            model, {"input": 0.50, "output": 0.70}
        )
        cost = (prompt_tokens / 1_000_000 * pricing["input"]) + (
            completion_tokens / 1_000_000 * pricing["output"]
        )
        self._metrics.total_cost_usd += cost
        return cost

    @property
    def metrics(self) -> TokenMetrics:
        return self._metrics

    def reset(self) -> None:
        self._metrics = TokenMetrics()
