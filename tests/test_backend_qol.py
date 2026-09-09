"""Protocol-level tests that do not require attaching to a real process."""

import pytest

from python_backend import BackendServer


def test_backend_parsers_accept_common_ui_values():
    assert BackendServer._parse_address('0x140001000') == 0x140001000
    assert BackendServer._parse_address('1234') == 1234
    assert BackendServer._parse_size('16') == 16


def test_backend_parsers_reject_unsafe_ranges():
    with pytest.raises(ValueError, match='address is required'):
        BackendServer._parse_address(None)
    with pytest.raises(ValueError, match='outside'):
        BackendServer._parse_size(0)
    with pytest.raises(ValueError, match='outside'):
        BackendServer._parse_size(17 * 1024 * 1024)


def test_backend_status_is_informative_before_attach():
    server = BackendServer()
    status = server.handle_command({'action': 'get_status', 'cmdId': 'status-1'})
    assert status == {
        'status': 'ok',
        'attached': False,
        'pid': None,
        'scan_started': False,
        'scan_count': 0,
        'value_type': None,
        'scan_mode': None,
        'last_scan_ms': 0,
        'cmdId': 'status-1',
    }
    server.close()
