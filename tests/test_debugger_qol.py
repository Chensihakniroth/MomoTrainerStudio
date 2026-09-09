import debugger


def test_split_watch_range_matches_ce_alignment_flow():
    assert debugger.split_watch_range(0x1000, 8) == ((0x1000, 8),)
    assert debugger.split_watch_range(0x1001, 4) == (
        (0x1001, 1), (0x1002, 2), (0x1004, 1)
    )


def test_debug_register_control_allocates_local_slots():
    segments = debugger.split_watch_range(0x1001, 4)
    dr7 = debugger.debug_register_control(segments, 'write')
    assert dr7 & 0x00000400
    assert dr7 & 0x01  # local enable for DR0
    assert dr7 & 0x04  # local enable for DR1
    assert dr7 & 0x10  # local enable for DR2
    assert ((dr7 >> 16) & 0b11) == 0b01  # write trigger
