"""Pydantic models for PatchGenie input and output schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class VulnerabilityInput(BaseModel):
    """Structured description of a vulnerability to be analysed."""

    cve_id: str = Field(
        description=(
            "CVE identifier (e.g. 'CVE-2021-44228') or a SAST alert reference "
            "(e.g. 'SAST-001'). Use 'N/A' when no formal identifier exists."
        )
    )
    description: str = Field(
        description=(
            "Free-text description of the vulnerability, copied from the advisory "
            "or SAST report."
        )
    )
    language: str = Field(
        default="",
        description=(
            "Primary programming language of the affected code "
            "(e.g. 'Python', 'C', 'Java')."
        ),
    )
    vulnerable_code: str = Field(
        default="",
        description="The vulnerable code snippet, if available.",
    )
    additional_context: str = Field(
        default="",
        description=(
            "Any extra context that helps the agent produce a better patch "
            "(e.g. framework, version)."
        ),
    )


class PatchReport(BaseModel):
    """Strict JSON output produced by PatchGenieAgent."""

    cve_id: str = Field(description="CVE / SAST identifier, echoed from the input.")
    vulnerability_analysis: str = Field(
        description=(
            "Root-cause analysis: vulnerability class, affected component, and attack vector."
        )
    )
    vulnerable_code_block: str = Field(
        description="The exact vulnerable code block identified by the agent."
    )
    secure_patch: str = Field(
        description="A complete, drop-in replacement that fixes the vulnerability."
    )
    verification_steps: list[str] = Field(
        description=(
            "Ordered list of verification steps, including a Python-based Exploit PoC "
            "and a Unit Test that confirms the fix."
        )
    )
