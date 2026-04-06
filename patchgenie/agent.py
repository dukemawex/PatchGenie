"""PatchGenie agent: sends vulnerability input to an LLM and returns a PatchReport."""

from __future__ import annotations

import json
import os

import openai
from pydantic import ValidationError

from patchgenie.models import PatchReport, VulnerabilityInput

# ---------------------------------------------------------------------------
# System prompt (Codex / GPT-4 family)
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """\
Role: Senior Security Software Engineer (L7)
Objective: You are a specialized agent designed to ingest a CVE (Common \
Vulnerabilities and Exposures) report or a Static Analysis (SAST) alert and \
generate a secure code patch.

Instructions:
1. Analyze – Identify the root cause (e.g., Use-After-Free, SQL Injection, \
Insecure Deserialization, Buffer Overflow, Path Traversal, XSS, SSRF, …).
2. Fix – Provide a code patch that adheres to "Secure by Design" principles. \
Use modern, memory-safe libraries where possible. Do NOT suggest quick fixes \
like suppressing warnings. Fix the logic.
3. Verify – Generate a Python-based "Exploit Proof of Concept" (PoC) that \
demonstrates the vulnerability, and a "Unit Test" that verifies the fix.

Output Format (strict JSON, no markdown fences):
{
  "cve_id": "<string>",
  "vulnerability_analysis": "<string>",
  "vulnerable_code_block": "<string>",
  "secure_patch": "<string>",
  "verification_steps": ["<step1>", "<step2>", "..."]
}

Constraint: Never suggest "quick fixes" like suppressing warnings. Fix the logic.\
"""


class PatchGenieAgent:
    """Wraps an OpenAI chat model to act as a secure-patch agent.

    Parameters
    ----------
    api_key:
        OpenAI API key.  Defaults to the ``OPENAI_API_KEY`` environment variable.
    model:
        Chat model to use.  Defaults to ``gpt-5.4`` (falls back to
        ``PATCHGENIE_MODEL`` env var, then ``gpt-5.4``).
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "OpenAI API key is required. "
                "Set the OPENAI_API_KEY environment variable or pass api_key=."
            )
        self._client = openai.OpenAI(api_key=resolved_key)
        self._model = model or os.environ.get("PATCHGENIE_MODEL", "gpt-5.4")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, vulnerability: VulnerabilityInput) -> PatchReport:
        """Analyse a vulnerability and return a :class:`PatchReport`.

        Parameters
        ----------
        vulnerability:
            Structured input describing the CVE or SAST alert.

        Returns
        -------
        PatchReport
            Validated structured patch report.

        Raises
        ------
        ValueError
            When the model returns malformed JSON or a schema-invalid response.
        openai.OpenAIError
            On upstream API failures.
        """
        user_message = self._build_user_message(vulnerability)
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or ""
        return self._parse_response(raw, vulnerability.cve_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_user_message(vulnerability: VulnerabilityInput) -> str:
        parts: list[str] = [
            f"CVE / Alert ID: {vulnerability.cve_id}",
            f"Description:\n{vulnerability.description}",
        ]
        if vulnerability.language:
            parts.append(f"Language: {vulnerability.language}")
        if vulnerability.vulnerable_code:
            parts.append(f"Vulnerable code snippet:\n```\n{vulnerability.vulnerable_code}\n```")
        if vulnerability.additional_context:
            parts.append(f"Additional context:\n{vulnerability.additional_context}")
        parts.append(
            "\nAnalyse the vulnerability above and respond with the strict JSON format "
            "specified in your instructions."
        )
        return "\n\n".join(parts)

    @staticmethod
    def _parse_response(raw: str, cve_id: str) -> PatchReport:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Model returned non-JSON content for {cve_id!r}: {raw[:200]!r}"
            ) from exc

        # Ensure cve_id is always populated (model may omit it).
        data.setdefault("cve_id", cve_id)

        try:
            return PatchReport.model_validate(data)
        except ValidationError as exc:
            raise ValueError(
                f"Model response does not match PatchReport schema for {cve_id!r}: {exc}"
            ) from exc
