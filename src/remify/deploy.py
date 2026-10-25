"""Deployment models: where the model runs and whose account pays for it.

- `saas`     : Remify's own Claude API account (proprietary cloud).
- `bedrock`  : customer-managed, Claude on the customer's Amazon Bedrock.
- `vertex`   : customer-managed, Claude on the customer's Google Vertex AI.
- `foundry`  : customer-managed, Claude on the customer's Microsoft Foundry.

In the customer-managed modes, code snippets never leave the customer's cloud
account. Settings are read from REMIFY_* environment variables so the same
container image runs unchanged in every mode.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

MODES = ("saas", "bedrock", "vertex", "foundry")
DEFAULT_MODEL = "claude-opus-5-5"


@dataclass
class Deployment:
    mode: str
    client: object
    model: str
    # Server-side refusal fallbacks exist only on the Claude API.
    supports_fallbacks: bool


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"{name} must be set for this deployment mode")
    return value


def from_env(mode: str | None = None, model: str = DEFAULT_MODEL) -> Deployment:
    import anthropic

    mode = (mode or os.environ.get("REMIFY_DEPLOYMENT", "saas")).lower()
    if mode == "saas":
        return Deployment(mode, anthropic.Anthropic(), model, supports_fallbacks=True)
    if mode == "bedrock":
        client = anthropic.AnthropicBedrockMantle(aws_region=_env("REMIFY_AWS_REGION"))
        return Deployment(mode, client, f"anthropic.{model}", supports_fallbacks=False)
    if mode == "vertex":
        client = anthropic.AnthropicVertex(
            project_id=_env("REMIFY_GCP_PROJECT"),
            region=os.environ.get("REMIFY_GCP_REGION", "global"),
        )
        return Deployment(mode, client, model, supports_fallbacks=False)
    if mode == "foundry":
        client = anthropic.AnthropicFoundry(
            resource=_env("REMIFY_FOUNDRY_RESOURCE"),
            api_key=_env("REMIFY_FOUNDRY_API_KEY"),
        )
        return Deployment(mode, client, model, supports_fallbacks=False)
    raise ValueError(f"unknown deployment mode {mode!r}; expected one of {', '.join(MODES)}")
