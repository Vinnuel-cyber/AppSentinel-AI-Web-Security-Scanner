"""AppSentinel AI Provider Client (V8).

Provides an enterprise-grade OpenAI SDK integration adhering to:
- Official OpenAI Python SDK (>=1.0.0).
- OpenAI Responses API (`client.responses.create`) with Chat Completions fallback.
- Configurable timeouts and exponential retry backoff on transient errors.
- Structured error handling: RateLimitError, AuthenticationError, APIConnectionError.
- Token consumption extraction.
- Offline and mockable client architecture for automated testing.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict, Any

from app.ai.ai_config import AIConfig

logger = logging.getLogger(__name__)


class AIProviderClient(ABC):
    """Abstract interface for application security AI providers."""

    @abstractmethod
    def generate_analysis(
        self,
        instructions: str,
        input_prompt: str,
        max_tokens: Optional[int] = None,
    ) -> Tuple[bool, str, str, Dict[str, int]]:
        """Execute inference against the configured AI provider.

        Returns:
            (success, raw_output, error_message, token_usage)
        """
        pass


class OpenAIClient(AIProviderClient):
    """OpenAI API client implementing Responses API with Chat Completions fallback."""

    def __init__(self, api_key: Optional[str] = None, client: Optional[Any] = None):
        self.api_key = api_key or AIConfig.get_api_key()
        self.model = AIConfig.get_model()
        self.timeout = AIConfig.get_timeout()
        self.max_tokens = AIConfig.get_max_output_tokens()

        if client is not None:
            self._client = client
        elif self.api_key:
            import openai
            self._client = openai.OpenAI(api_key=self.api_key, timeout=float(self.timeout))
        else:
            self._client = None

    @property
    def is_available(self) -> bool:
        """Check if client is initialized with valid credentials."""
        return self._client is not None and bool(self.api_key)

    def generate_analysis(
        self,
        instructions: str,
        input_prompt: str,
        max_tokens: Optional[int] = None,
    ) -> Tuple[bool, str, str, Dict[str, int]]:
        """Generate structured security analysis with retry backoff and error classification."""
        if not self.is_available:
            return (
                False,
                "",
                "OpenAI API client not initialized. Missing API key or AI disabled.",
                {"input_tokens": 0, "output_tokens": 0},
            )

        limit_tokens = max_tokens or self.max_tokens
        max_retries = 2
        delay = 1.0

        for attempt in range(max_retries + 1):
            try:
                # Try official Responses API first
                return self._call_responses_api(instructions, input_prompt, limit_tokens)
            except AttributeError:
                # Responses API not available on client, fallback to chat completions
                try:
                    return self._call_chat_completions(instructions, input_prompt, limit_tokens)
                except Exception as ex:
                    return self._handle_exception(ex, attempt, max_retries)
            except Exception as ex:
                # If responses.create fails due to unknown model or API parameter mismatch, try chat.completions
                err_str = str(ex).lower()
                if "unknown parameter" in err_str or "unsupported" in err_str:
                    try:
                        return self._call_chat_completions(instructions, input_prompt, limit_tokens)
                    except Exception as fallback_ex:
                        return self._handle_exception(fallback_ex, attempt, max_retries)

                retryable, err_msg = self._is_retryable_error(ex)
                if retryable and attempt < max_retries:
                    logger.warning(
                        "AI client transient error on attempt %d/%d: %s. Retrying in %.1fs...",
                        attempt + 1,
                        max_retries,
                        err_msg,
                        delay,
                    )
                    time.sleep(delay)
                    delay *= 2.0
                    continue
                else:
                    return False, "", err_msg, {"input_tokens": 0, "output_tokens": 0}

        return False, "", "Exceeded maximum retry attempts.", {"input_tokens": 0, "output_tokens": 0}

    def _call_responses_api(
        self, instructions: str, input_prompt: str, max_tokens: int
    ) -> Tuple[bool, str, str, Dict[str, int]]:
        """Invoke client.responses.create."""
        response = self._client.responses.create(
            model=self.model,
            instructions=instructions,
            input=input_prompt,
            max_output_tokens=max_tokens,
            timeout=float(self.timeout),
        )

        output_text = ""
        # Extract output text from Response object
        if hasattr(response, "output_text") and response.output_text:
            output_text = response.output_text
        elif hasattr(response, "output"):
            # Check for output parts / items
            output_parts = []
            for item in response.output:
                if hasattr(item, "content"):
                    output_parts.append(str(item.content))
                elif isinstance(item, dict) and "content" in item:
                    output_parts.append(str(item["content"]))
                else:
                    output_parts.append(str(item))
            output_text = "\n".join(output_parts)
        elif hasattr(response, "choices") and response.choices:
            output_text = response.choices[0].message.content or ""

        # Extract usage
        input_tokens = 0
        output_tokens = 0
        if hasattr(response, "usage") and response.usage:
            input_tokens = getattr(response.usage, "input_tokens", 0) or getattr(response.usage, "prompt_tokens", 0)
            output_tokens = getattr(response.usage, "output_tokens", 0) or getattr(response.usage, "completion_tokens", 0)

        return True, output_text, "", {"input_tokens": input_tokens, "output_tokens": output_tokens}

    def _call_chat_completions(
        self, instructions: str, input_prompt: str, max_tokens: int
    ) -> Tuple[bool, str, str, Dict[str, int]]:
        """Invoke client.chat.completions.create as standard fallback."""
        messages = [
            {"role": "system", "content": instructions},
            {"role": "user", "content": input_prompt},
        ]

        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            timeout=float(self.timeout),
        )

        output_text = ""
        if response.choices and len(response.choices) > 0:
            output_text = response.choices[0].message.content or ""

        input_tokens = 0
        output_tokens = 0
        if hasattr(response, "usage") and response.usage:
            input_tokens = getattr(response.usage, "prompt_tokens", 0)
            output_tokens = getattr(response.usage, "completion_tokens", 0)

        return True, output_text, "", {"input_tokens": input_tokens, "output_tokens": output_tokens}

    def _is_retryable_error(self, ex: Exception) -> Tuple[bool, str]:
        """Classify exception as retryable or permanent."""
        import openai

        if isinstance(ex, openai.RateLimitError):
            return False, f"OpenAI rate limit exceeded or quota exhausted: {str(ex)}"
        elif isinstance(ex, openai.AuthenticationError):
            return False, f"OpenAI authentication failed. Invalid API key: {str(ex)}"
        elif isinstance(ex, openai.BadRequestError):
            return False, f"OpenAI invalid request: {str(ex)}"
        elif isinstance(ex, (openai.APIConnectionError, openai.APITimeoutError)):
            return True, f"OpenAI connection error / timeout: {str(ex)}"
        elif isinstance(ex, openai.InternalServerError):
            return True, f"OpenAI server internal error: {str(ex)}"
        elif isinstance(ex, openai.APIStatusError):
            # 5xx are retryable, 4xx are not
            retryable = getattr(ex, "status_code", 500) >= 500
            return retryable, f"OpenAI API error ({getattr(ex, 'status_code', 'unknown')}): {str(ex)}"
        else:
            return False, f"AI client unexpected exception: {str(ex)}"

    def _handle_exception(self, ex: Exception, attempt: int, max_retries: int) -> Tuple[bool, str, str, Dict[str, int]]:
        retryable, err_msg = self._is_retryable_error(ex)
        if retryable and attempt < max_retries:
            time.sleep(1.0)
            return self.generate_analysis("", "", 0)  # will be retried in caller loop
        return False, "", err_msg, {"input_tokens": 0, "output_tokens": 0}


def get_ai_client(client: Optional[Any] = None) -> Optional[AIProviderClient]:
    """Factory creating the appropriate AI client based on configuration."""
    if not AIConfig.is_enabled() and client is None:
        return None

    provider = AIConfig.get_provider()
    if provider == "openai" or client is not None:
        return OpenAIClient(client=client)

    return None
