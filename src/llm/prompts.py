"""
Phase 4b — Translation Prompt Engineering.

Builds system prompts and user messages that enforce:
    1. Exact byte-length ceilings
    2. Preservation of in-text control codes
    3. Contextual consistency via glossary terms
    4. Natural English phrasing with abbreviation fallbacks
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.llm.engine import TranslationRequest


SYSTEM_PROMPT = """You are a professional video game translator specializing in \
Japanese-to-English localization for classic JRPGs. You are translating dialogue \
and menu text for a PlayStation 1 game.

CRITICAL RULES — violating any of these will corrupt the game binary:

1. BYTE LIMIT: Your English translation MUST NOT exceed the specified byte limit. \
Count each ASCII character as 1 byte. If your translation is too long, abbreviate \
naturally. Use contractions, shorter synonyms, or restructure the sentence. \
NEVER pad or truncate mid-word.

2. CONTROL CODES: The source text may contain special byte sequences (control codes) \
like newlines, wait-for-input markers, or color changes. These are marked with \
{CTRL:XX} notation. You MUST preserve every control code EXACTLY as-is in your \
translation, including their position relative to the text.

3. GLOSSARY: When a glossary is provided, you MUST use the specified English terms \
for character names, place names, items, and game-specific terminology. Do not \
improvise alternative translations for glossary terms.

4. TONE: Match the tone of the original. Formal speech should remain formal. \
Casual/rough speech should feel natural in English. Preserve the character's \
personality.

5. OUTPUT FORMAT: Return ONLY the translated English text. No explanations, no \
notes, no markdown formatting. Just the raw translated string."""


def build_translation_prompt(request: TranslationRequest) -> list[dict]:
    """
    Build the full message array for a translation API call.

    Args:
        request: TranslationRequest with source text, byte limit, context, etc.

    Returns:
        List of message dicts ready for the API.
    """
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Build the user prompt
    parts = []

    # Glossary
    if request.glossary:
        glossary_lines = [f"  {jp} → {en}" for jp, en in request.glossary.items()]
        parts.append("GLOSSARY (you MUST use these exact terms):\n" + "\n".join(glossary_lines))

    # Context (surrounding strings for consistency)
    if request.context:
        context_block = "\n".join(f"  [{i+1}] {line}" for i, line in enumerate(request.context))
        parts.append(f"CONTEXT (surrounding dialogue for reference):\n{context_block}")

    # Control codes
    if request.control_codes:
        codes = ", ".join(request.control_codes)
        parts.append(f"CONTROL CODES TO PRESERVE: {codes}")

    # The actual translation request
    parts.append(f"BYTE LIMIT: {request.byte_limit} bytes maximum")
    parts.append(f"SOURCE TEXT (Japanese):\n{request.source_text}")
    parts.append("TRANSLATION (English):")

    user_message = "\n\n".join(parts)
    messages.append({"role": "user", "content": user_message})

    return messages


def build_retry_prompt(
    request: TranslationRequest,
    previous_translation: str,
    previous_byte_count: int,
) -> list[dict]:
    """
    Build a correction prompt when the previous translation exceeded the byte limit.

    Args:
        request: Original TranslationRequest.
        previous_translation: The translation that was too long.
        previous_byte_count: How many bytes it actually was.

    Returns:
        Updated message array asking for a shorter version.
    """
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    overshoot = previous_byte_count - request.byte_limit

    correction = f"""Your previous translation was {previous_byte_count} bytes, \
which is {overshoot} byte(s) over the limit of {request.byte_limit} bytes.

Previous translation: "{previous_translation}"

Please provide a SHORTER translation that fits within {request.byte_limit} bytes. \
Strategies:
- Use contractions (do not → don't, cannot → can't)
- Use shorter synonyms
- Restructure for brevity
- Abbreviate where natural

Original Japanese: {request.source_text}

CORRECTED TRANSLATION (≤ {request.byte_limit} bytes):"""

    messages.append({"role": "user", "content": correction})

    return messages
