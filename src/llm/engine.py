"""
Phase 4a — LLM Translation Engine.

Unified interface for calling OpenAI and Anthropic APIs to translate
Japanese text strings with strict character-count constraints.

The game uses fullwidth Shift-JIS encoding where each printable character
costs 2 bytes.  The `byte_limit` field in TranslationRequest stores a
*character budget* (not raw bytes) so the LLM prompt can communicate it
naturally.

Supports batch translation with rate-limit-aware dispatch.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.patcher.fullwidth_sjis import fullwidth_byte_count, CONTROL_BYTES

logger = logging.getLogger(__name__)


def _printable_char_count(text: str) -> int:
    """Count printable characters (each costs 2 bytes in fullwidth encoding).
    
    Control bytes (null, newline, etc.) don't count — they pass through
    as 1-byte values and aren't constrained by the font table width.
    """
    return sum(1 for ch in text if ord(ch) not in CONTROL_BYTES)


class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


@dataclass
class TranslationRequest:
    """A single text string to be translated."""
    source_text: str              # Original Japanese text
    byte_limit: int               # Maximum printable character count for the English output
    context: list[str] = field(default_factory=list)  # Surrounding strings for context
    glossary: dict[str, str] = field(default_factory=dict)  # Term → translation overrides
    control_codes: list[str] = field(default_factory=list)  # Codes that must be preserved


@dataclass
class TranslationResult:
    """Result of a single translation."""
    source_text: str
    translated_text: str
    byte_count: int              # Byte length of the translated text
    byte_limit: int              # The limit that was enforced
    within_limit: bool           # True if byte_count <= byte_limit
    tokens_used: int             # API tokens consumed
    attempts: int                # Number of API calls required


class TranslationEngine:
    """
    Unified LLM translation engine supporting OpenAI and Anthropic.

    Applies byte-length constraints and re-prompts the model to abbreviate
    if the translation exceeds the allowed size.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        temperature: float = 0.3,
        max_retries: int = 5,
        rate_limit_delay: float = 0.5,
        system_prompt: str = "",
    ) -> None:
        self._provider = LLMProvider(provider.lower())
        self._model = model
        self._temperature = temperature
        self._max_retries = max_retries
        self._rate_limit_delay = rate_limit_delay
        self._system_prompt = system_prompt
        self._total_tokens = 0
        
        import threading
        self._token_lock = threading.Lock()

        # Initialize API client
        if self._provider == LLMProvider.OPENAI:
            self._client = self._init_openai()
        else:
            self._client = self._init_anthropic()

        logger.info(
            "Translation engine ready: %s / %s (temp=%.1f, retries=%d)",
            self._provider.value, self._model, self._temperature, self._max_retries,
        )

    def _init_openai(self):
        """Initialize OpenAI client."""
        import openai

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY not set. Add it to your .env file."
            )
        return openai.OpenAI(api_key=api_key)

    def _init_anthropic(self):
        """Initialize Anthropic client."""
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY not set. Add it to your .env file."
            )
        return anthropic.Anthropic(api_key=api_key)

    def translate(self, request: TranslationRequest) -> TranslationResult:
        """
        Translate a single text string with byte-length enforcement.

        If the translation exceeds the byte limit, the engine re-prompts
        the LLM with a correction asking for abbreviation, up to max_retries.
        """
        from src.llm.prompts import build_translation_prompt, build_retry_prompt

        prompt = build_translation_prompt(request)
        translated = ""
        tokens_used = 0
        attempts = 0

        for attempt in range(1, self._max_retries + 1):
            attempts = attempt

            # Rate limiting
            if attempt > 1:
                time.sleep(self._rate_limit_delay)

            # Call API
            response_text, tokens = self._call_api(prompt)
            tokens_used += tokens

            # Clean up the response
            translated = response_text.strip()

            # Check character count against budget
            char_count = _printable_char_count(translated)

            if char_count <= request.byte_limit:
                logger.debug(
                    "Translation OK (attempt %d): %d/%d chars",
                    attempt, char_count, request.byte_limit,
                )
                break
            else:
                logger.debug(
                    "Translation too long (attempt %d): %d/%d chars — retrying",
                    attempt, char_count, request.byte_limit,
                )
                # Build a correction prompt
                prompt = build_retry_prompt(
                    request, translated, char_count,
                )

        byte_count = fullwidth_byte_count(translated)
        char_count = _printable_char_count(translated)
        
        with self._token_lock:
            self._total_tokens += tokens_used

        return TranslationResult(
            source_text=request.source_text,
            translated_text=translated,
            byte_count=byte_count,
            byte_limit=request.byte_limit,
            within_limit=char_count <= request.byte_limit,
            tokens_used=tokens_used,
            attempts=attempts,
        )

    def translate_batch(
        self,
        requests: list[TranslationRequest],
        batch_size: int = 20,
        max_workers: int = 20,
    ) -> list[TranslationResult]:
        """
        Translate a batch of strings concurrently with progress logging.

        Args:
            requests: List of TranslationRequest objects.
            batch_size: Number of strings to process before logging progress.
            max_workers: Number of concurrent threads to dispatch to LLM APIs.

        Returns:
            List of TranslationResult objects in the same order.
        """
        import concurrent.futures
        
        results: list[TranslationResult] = [None] * len(requests)
        total = len(requests)
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Map futures to their original index to preserve sequential output map
            future_to_index = {
                executor.submit(self.translate, req): i for i, req in enumerate(requests)
            }
            
            for future in concurrent.futures.as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    logger.error("Error translating string index %d: %s", idx, e)
                
                completed += 1
                if completed % batch_size == 0 or completed == total:
                    # Thread-safe read count
                    with self._token_lock:
                        current_tokens = self._total_tokens
                    success_count = sum(1 for r in results if r is not None and r.within_limit)
                    logger.info(
                        "Progress: %d/%d translated (%d within byte limits, %d tokens used)",
                        completed, total, success_count, current_tokens,
                    )

        # Build list containing the final outputs in perfectly aligned payload order
        return results

    def _call_api(self, messages: list[dict]) -> tuple[str, int]:
        """
        Make a single API call and return (response_text, tokens_used).
        """
        if self._provider == LLMProvider.OPENAI:
            return self._call_openai(messages)
        else:
            return self._call_anthropic(messages)

    def _call_openai(self, messages: list[dict]) -> tuple[str, int]:
        """Call OpenAI API."""
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self._temperature,
            max_tokens=512,
        )

        text = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else 0
        return text, tokens

    def _call_anthropic(self, messages: list[dict]) -> tuple[str, int]:
        """Call Anthropic API."""
        # Extract system message
        system_msg = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                user_messages.append(msg)

        response = self._client.messages.create(
            model=self._model,
            system=system_msg,
            messages=user_messages,
            temperature=self._temperature,
            max_tokens=512,
        )

        text = response.content[0].text if response.content else ""
        tokens = (response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0
        return text, tokens

    @property
    def total_tokens(self) -> int:
        """Total tokens consumed across all API calls."""
        return self._total_tokens
