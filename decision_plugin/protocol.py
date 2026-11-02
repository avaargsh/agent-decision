from dataclasses import dataclass


@dataclass(frozen=True)
class DecisionTurn:
    protocol_version: str
    invocation_id: str
    tenant_id: str
    agent_id: str
    run_id: str
    turn_id: str
    user_input: str

    @classmethod
    def parse(cls, payload: object) -> 'DecisionTurn':
        if not isinstance(payload, dict):
            raise ValueError('expected JSON object')
        expected = set(cls.__dataclass_fields__)
        if set(payload) != expected:
            raise ValueError('missing or unexpected fields')
        if any(not isinstance(v, str) or not v.strip() or len(v.encode('utf-8')) > 4096 for v in payload.values()):
            raise ValueError('fields must be nonempty bounded strings')
        if payload['protocol_version'] != 'v0.1':
            raise ValueError('unsupported protocol version')
        return cls(**payload)


def decide(turn: DecisionTurn) -> dict:
    # Deterministic reference adapter: no tools, outbound requests or credentials.
    return {'protocol_version': 'v0.1', 'invocation_id': turn.invocation_id,
            'kind': 'final', 'text': f'Accepted: {turn.user_input}'}
