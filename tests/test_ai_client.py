"""AppSentinel AI Provider Client Tests (V8)."""

from unittest.mock import MagicMock, patch
import pytest
import openai
from app.ai.ai_client import OpenAIClient, get_ai_client


def test_ai_client_unconfigured_disabled():
    """Verify client reports not available when API key is missing."""
    client = OpenAIClient(api_key=None)
    assert client.is_available is False

    success, out, err, tokens = client.generate_analysis("sys", "user")
    assert success is False
    assert "not initialized" in err.lower()
    assert tokens["input_tokens"] == 0


def test_ai_client_responses_api_success():
    """Verify OpenAI client successfully handles responses.create output."""
    mock_sdk = MagicMock()
    mock_resp = MagicMock()
    mock_resp.output_text = '{"analysis_type": "vulnerability_explanation", "summary": "Test OK"}'
    mock_resp.usage.input_tokens = 150
    mock_resp.usage.output_tokens = 320

    mock_sdk.responses.create.return_value = mock_resp

    client = OpenAIClient(api_key="sk-mock-key-12345", client=mock_sdk)
    success, output, err, tokens = client.generate_analysis("instructions", "prompt")

    assert success is True
    assert "Test OK" in output
    assert tokens["input_tokens"] == 150
    assert tokens["output_tokens"] == 320
    assert err == ""
    mock_sdk.responses.create.assert_called_once()


def test_ai_client_chat_completions_fallback():
    """Verify client falls back to chat.completions when responses.create is absent or fails."""
    mock_sdk = MagicMock()
    # Delete responses attribute to trigger chat fallback
    del mock_sdk.responses

    mock_choice = MagicMock()
    mock_choice.message.content = '{"analysis_type": "vulnerability_explanation", "summary": "Chat Fallback OK"}'
    mock_chat_resp = MagicMock()
    mock_chat_resp.choices = [mock_choice]
    mock_chat_resp.usage.prompt_tokens = 110
    mock_chat_resp.usage.completion_tokens = 220

    mock_sdk.chat.completions.create.return_value = mock_chat_resp

    client = OpenAIClient(api_key="sk-mock-key-12345", client=mock_sdk)
    success, output, err, tokens = client.generate_analysis("instructions", "prompt")

    assert success is True
    assert "Chat Fallback OK" in output
    assert tokens["input_tokens"] == 110
    assert tokens["output_tokens"] == 220
    mock_sdk.chat.completions.create.assert_called_once()


def test_ai_client_rate_limit_error_non_retryable():
    """Verify RateLimitError fails immediately without infinite retry loops."""
    mock_sdk = MagicMock()
    mock_req = MagicMock()
    rate_err = openai.RateLimitError("Quota exceeded", response=mock_req, body=None)
    mock_sdk.responses.create.side_effect = rate_err

    client = OpenAIClient(api_key="sk-mock-key-12345", client=mock_sdk)
    success, output, err, tokens = client.generate_analysis("instructions", "prompt")

    assert success is False
    assert "rate limit exceeded" in err.lower() or "quota exhausted" in err.lower()
    # Should not retry multiple times
    assert mock_sdk.responses.create.call_count == 1


def test_ai_client_transient_connection_error_retry():
    """Verify connection errors are retried up to max_retries."""
    mock_sdk = MagicMock()
    conn_err = openai.APIConnectionError(request=MagicMock())

    # Succeed on attempt 2
    mock_resp = MagicMock()
    mock_resp.output_text = '{"summary": "Recovered"}'
    mock_resp.usage.input_tokens = 50
    mock_resp.usage.output_tokens = 50

    mock_sdk.responses.create.side_effect = [conn_err, mock_resp]

    client = OpenAIClient(api_key="sk-mock-key-12345", client=mock_sdk)
    with patch("time.sleep", return_value=None):
        success, output, err, tokens = client.generate_analysis("instructions", "prompt")

    assert success is True
    assert "Recovered" in output
    assert mock_sdk.responses.create.call_count == 2
