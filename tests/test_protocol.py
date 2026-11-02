import pytest
from decision_plugin.protocol import DecisionTurn, decide

VALID = dict(protocol_version='v0.1', invocation_id='inv-1', tenant_id='t-1',
             agent_id='a-1', run_id='r-1', turn_id='turn-1', user_input='hello')


def test_final_result_is_stable():
    assert decide(DecisionTurn.parse(VALID)) == {
        'protocol_version': 'v0.1', 'invocation_id': 'inv-1',
        'kind': 'final_response', 'text': 'Accepted: hello'}


@pytest.mark.parametrize('field,value', [('protocol_version', 'v2'), ('user_input', ''),
                                          ('invocation_id', 3), ('user_input', 'x' * 4097)])
def test_invalid_fields_rejected(field, value):
    with pytest.raises(ValueError):
        DecisionTurn.parse({**VALID, field: value})


def test_missing_or_extra_fields_rejected():
    with pytest.raises(ValueError):
        DecisionTurn.parse({k: v for k, v in VALID.items() if k != 'run_id'})
    with pytest.raises(ValueError):
        DecisionTurn.parse({**VALID, 'token': 'sensitive'})
