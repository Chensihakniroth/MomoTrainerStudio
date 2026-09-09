"""Pure validation tests for the scanner's user-facing helpers."""

import pytest

from memory_scanner import (
    Candidate,
    _normalize_candidates,
    parse_address_string,
    parse_signature,
    validate_scan_request,
)


def test_validate_scan_request_explains_missing_between_bound():
    with pytest.raises(ValueError, match='both a lower value'):
        validate_scan_request('int32', 'between', 10)


def test_validate_scan_request_rejects_empty_string_and_bad_stride():
    with pytest.raises(ValueError, match='cannot be empty'):
        validate_scan_request('string', 'exact', '')
    with pytest.raises(ValueError, match='between 0 and 8'):
        validate_scan_request('int32', 'exact', 1, fast_scan_digits=9)


def test_normalize_candidates_accepts_legacy_addresses_for_exact_rescans():
    result = _normalize_candidates((addr for addr in [0x1000, 0x2000]), 'exact')
    assert result == [Candidate(0x1000, b''), Candidate(0x2000, b'')]
    with pytest.raises(ValueError, match='no previous value'):
        _normalize_candidates([0x1000], 'changed')


def test_address_parser_keeps_long_decimal_addresses_decimal():
    assert parse_address_string(None, '123456') == (123456, None)
    assert parse_address_string(None, 'ABCDEF') == (0xABCDEF, None)
    assert parse_address_string(None, None)[1] == 'Address must be a string'


def test_signature_parser_reports_bad_tokens():
    assert parse_signature('48, 8B, ??') == (b'\x48\x8b\x00', [False, False, True])
    with pytest.raises(ValueError, match='Did you forget a space'):
        parse_signature('488B05')
