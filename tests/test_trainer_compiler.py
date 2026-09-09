"""Unit tests for deterministic trainer-spec rendering helpers."""

import pytest

from trainer_compiler import (
    _to_int,
    parse_color,
    render_action_block,
    render_feature_block,
    validate_spec,
)


def test_parse_color_converts_rgb_to_windows_colorref():
    assert parse_color('#FF66CC') == 0xCC66FF
    assert parse_color('112233') == 0x332211


def test_parse_color_uses_documented_default_for_invalid_input():
    expected = 0xCC66FF
    for value in (None, '', '#GG66CC', '#FFF', 42):
        assert parse_color(value) == expected


def test_to_int_accepts_decimal_and_hex_inputs():
    assert _to_int(123) == 123
    assert _to_int('0x1A') == 26
    assert _to_int(' 42 ') == 42
    assert _to_int('FF') == 255
    assert _to_int('not an address') == 0


def test_render_blocks_include_expected_fields():
    features = render_feature_block([
        {'name': 'Health', 'type': 'freeze', 'address': '0x1234', 'value': 99.5},
    ])
    actions = render_action_block([
        {'name': 'Refill', 'hotkey': 'VK_F2', 'address': 0x4567, 'value': 100},
    ])

    assert '"Health"' in features
    assert '0x1234ULL' in features
    assert '99.5' in features
    assert '"Refill"' in actions
    assert 'VK_F2' in actions
    assert '0x4567ULL' in actions


def test_validate_spec_rejects_bad_width_and_signature_length():
    with pytest.raises(ValueError, match='width'):
        validate_spec({'features': [{'name': 'HP', 'address': 1, 'width': 3}]})

    long_signature = ' '.join(['90'] * 65)
    with pytest.raises(ValueError, match='maximum is 64'):
        validate_spec({
            'features': [{'name': 'HP', 'address': 1, 'signature': long_signature}]
        })


def test_render_blocks_escape_cpp_names():
    rendered = render_feature_block([{
        'name': 'Health "boost"',
        'type': 'value',
        'address': 0x1234,
        'value': 99,
    }])
    assert 'Health \\"boost\\"' in rendered
