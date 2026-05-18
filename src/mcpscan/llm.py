"""Thin async client for Groq's OpenAI-compatible chat completions API.

Used by semantic detectors (L1 LLM judge). Kept deliberately small so it can
be reused from any detector without dragging in a heavyweight LLM SDK.
"""
import asyncio
import logging

import httpx


logger = logging.getLogger(__name__)


GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"


async def groq_call(
    model: str,
    messages: list[dict],
    api_key: str,
    *,
    timeout: float = 10.0,
    temperature: float = 0.0,
    max_tokens: int = 256,
) -> str | None:
    """One Groq chat completion. Returns the assistant message content, or None on failure.

    Quietly retries once on a 429 (rate limit) after a short sleep. All other
    failures — transport errors, non-2xx responses, malformed JSON — return
    None so the caller can decide to skip the finding instead of crashing the
    whole scan.
    """
    if not api_key:
        return None

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            for attempt in range(2):
                try:
                    resp = await client.post(GROQ_CHAT_URL, json=payload, headers=headers)
                except httpx.RequestError as exc:
                    logger.debug("groq_call transport error: %s", exc)
                    return None

                if resp.status_code == 429 and attempt == 0:
                    logger.debug("groq_call rate-limited, retrying once")
                    await asyncio.sleep(2.0)
                    continue
                if resp.status_code >= 400:
                    logger.debug(
                        "groq_call HTTP %s for model %s: %s",
                        resp.status_code, model, resp.text[:200],
                    )
                    return None

                try:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
                except (ValueError, KeyError, IndexError) as exc:
                    logger.debug("groq_call response parse error: %s", exc)
                    return None
    except asyncio.TimeoutError:
        logger.debug("groq_call timed out after %.1fs", timeout)
        return None

    return None
