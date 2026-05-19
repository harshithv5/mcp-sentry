"""Thin async client for Groq's OpenAI-compatible chat completions API.

Used by semantic detectors (L1 LLM judge). Kept deliberately small so it can
be reused from any detector without dragging in a heavyweight LLM SDK.
"""
import asyncio
import logging
import random

import httpx


logger = logging.getLogger(__name__)


GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

_MAX_RETRIES = 4         # total attempts on 429 = _MAX_RETRIES + 1
_BACKOFF_BASE_SEC = 1.5  # exponential base; capped by _BACKOFF_CAP_SEC
_BACKOFF_CAP_SEC = 30.0


def _parse_retry_after(value: str | None) -> float | None:
    """Return seconds to wait per the Retry-After header, or None if absent/bad.

    Groq returns Retry-After as a decimal number of seconds (e.g. "1.234"); the
    HTTP spec also allows an HTTP-date but we don't bother — falling back to
    exponential backoff is fine.
    """
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


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

    Retries 429s up to `_MAX_RETRIES` times, sleeping for the server-provided
    `Retry-After` when present and exponential backoff with jitter otherwise.
    All other failures — transport errors, non-2xx responses, malformed JSON —
    return None so the caller can skip the finding instead of crashing the scan.
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
            for attempt in range(_MAX_RETRIES + 1):
                try:
                    resp = await client.post(GROQ_CHAT_URL, json=payload, headers=headers)
                except httpx.RequestError as exc:
                    logger.debug("groq_call transport error: %s", exc)
                    return None

                if resp.status_code == 429:
                    if attempt >= _MAX_RETRIES:
                        logger.debug(
                            "groq_call gave up after %d retries on 429 for %s",
                            _MAX_RETRIES, model,
                        )
                        return None
                    retry_after = _parse_retry_after(resp.headers.get("retry-after"))
                    if retry_after is not None:
                        delay = min(retry_after, _BACKOFF_CAP_SEC)
                    else:
                        delay = min(_BACKOFF_BASE_SEC * (2 ** attempt), _BACKOFF_CAP_SEC)
                    delay += random.uniform(0, 0.25)  # small jitter
                    logger.debug(
                        "groq_call 429 for %s (attempt %d/%d), sleeping %.2fs",
                        model, attempt + 1, _MAX_RETRIES, delay,
                    )
                    await asyncio.sleep(delay)
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
