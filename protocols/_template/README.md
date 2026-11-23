# Protocol template

Copy this folder to a new protocol name only after defining its normative AID/PSID, issuer chain, trust domain, credential scope, validity policy, region policy and runtime support.

Do not copy private keys or certificates from another protocol. Add a policy manifest under `config/protocols/` and explicitly register its trust domain under `config/domains/`.
