"""Gemini LLM Client for LogLens.

This module communicates with Google's Gemini API to generate structured
incident summaries from log analysis prompts.
"""

import os

from google import genai
from google.genai import types


class GeminiClient:
    """Client responsible for communicating with Google Gemini models."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.0-flash",
    ) -> None:
        """Initialize the GeminiClient.

        Args:
            api_key: Optional explicit Gemini API key. If not provided,
                it is read from the GEMINI_API_KEY environment variable.
            model: Gemini model identifier. Defaults to 'gemini-2.0-flash'.

        Raises:
            ValueError: If no API key is provided and GEMINI_API_KEY is unset.
        """
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "GEMINI_API_KEY is not set. Please set the environment variable: "
                "export GEMINI_API_KEY='your_api_key' or pass api_key to the client."
            )

        self.api_key = resolved_key
        self.model = model
        self.client = genai.Client(api_key=self.api_key)

    def generate_summary(self, prompt: str) -> str:
        """Send prompt to Gemini and return the structured JSON response string.

        Args:
            prompt: Structured prompt string constructed by PromptBuilder.

        Returns:
            The raw text response from Gemini (constrained to JSON format).

        Raises:
            RuntimeError: If the API call fails due to network or service errors.
        """
        try:
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            )
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            if not response.text:
                raise RuntimeError("Empty response received from Gemini API.")
            return response.text
        except Exception as err:
            raise RuntimeError(f"Gemini API request failed: {err}") from err

