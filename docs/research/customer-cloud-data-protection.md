# Action item: evaluate customer-cloud data protection models

Owner: @me · Priority: **High** · Source: memo of 25 Oct 2026 (09:15 Asia/Dubai)

**Question:** when Remify runs in the customer's environment, how do we
(a) keep our remediation logic from being copied, and (b) give a dependable
guarantee that the tool's output and internal data haven't been tampered with?

## Options compared

| # | Model | Protects our IP | Customer data stays in their cloud | Output integrity | Effort | Notes |
|---|---|---|---|---|---|---|
| A | **Split plane**: thin agent in customer cloud, strategy/prompt service in Remify cloud | Strong: logic never ships | Partial: minimal snippet crosses to our control plane | Signed results from our side | Medium | Unacceptable to customers that allow no egress at all |
| B | **Split plane + customer's model account**: agent calls Claude on the customer's Bedrock/Vertex/Foundry; our service sends only *instructions*, never sees code | Strong | **Yes**: code goes only to the customer's own model endpoint | Signed results | Medium | **Recommended default for enterprise** |
| C | **Confidential computing**: full engine in an attested enclave (AWS Nitro Enclaves, Azure/GCP confidential VMs) inside the customer account | Strong: memory unreadable by the host | Yes | Strong: attestation proves which build ran | High | For the strictest customers; per-cloud engineering |
| D | **Licensed, hardened container** (encrypted prompt bundle, license call-home, obfuscation) | Weak–moderate: a determined insider can extract it | Yes | Signed results | Low | Fine for an early pilot, not a moat |
| E | **Fully air-gapped** (local open-weight model + D) | Weak | Yes | Signed results | Very high | Only on demand; fix quality drops |

## Recommendation

1. **Ship B as the enterprise model.** The customer keeps code and model usage
   inside their cloud account. Remify keeps its strategy library, ranking and
   prompt assembly in its own control plane. The agent receives a compiled
   instruction set per finding, valid for a short time and never stored.
2. **Make C the premium tier** for regulated customers who allow no egress at
   all. Start with AWS Nitro Enclaves, since Bedrock is already supported.
3. **Use D only for pilots.**
4. **Output integrity in every mode:** each fix is signed (finding ID +
   SHA-256 of the diff + engine version). The customer's CI runs
   `remify verify` and rejects anything altered. Implemented in
   `src/remify/integrity.py` with HMAC. Move to Ed25519 with the key held in a
   KMS or enclave so customers can verify without holding a secret.

## What's already in the code

- `src/remify/deploy.py`: `saas`, `bedrock`, `vertex`, `foundry` modes. The
  three customer-managed modes send code only to the customer's own model endpoint.
- `src/remify/integrity.py` plus `remify verify`: tamper detection.

## Next steps

- [ ] Define the agent ↔ control-plane protocol for option B (what is sent, TTL, auth).
- [ ] Spike a Nitro Enclave build with attestation-gated key release.
- [ ] Switch signing to Ed25519 with KMS-held keys.
- [ ] Draft the data-handling statement for security questionnaires.
