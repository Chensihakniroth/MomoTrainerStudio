"""Interactive hex memory inspector used by the Studio GUI.

The original hex view was a one-shot text dump.  This window keeps the same
lightweight Win32 read/write path, but adds navigation, refresh, selection
details, change highlighting, and guarded byte editing.
"""

import ctypes
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

import memory_scanner as ms


class HexMemoryViewer(tk.Toplevel):
    """Browse a bounded memory range and optionally edit selected bytes."""

    def __init__(self, parent, process_handle, address, *, colors=None,
                 on_watch=None):
        super().__init__(parent)
        self.process_handle = process_handle
        self.on_watch = on_watch
        self.colors = {
            'bg': '#0d1117',
            'panel': '#161b22',
            'border': '#30363d',
            'fg': '#c9d1d9',
            'muted': '#8b949e',
            'accent': '#58a6ff',
            'btn_bg': '#21262d',
            'btn_fg': '#c9d1d9',
        }
        if colors:
            self.colors.update(colors)

        self.base_address = int(address)
        self.selected_address = self.base_address
        self._range_key = None
        self._original_data = b''
        self._data = b''
        self._changed_at = {}
        self._fade_job = None
        self._refresh_count = 0
        self._last_read_ms = 0.0
        self._refresh_job = None
        self._reading = False
        self._closed = False
        self._select_first_byte_on_next_range = False

        self.title(f"Hex Memory Inspector @ 0x{self.base_address:016X}")
        self.geometry('1000x610')
        self.minsize(760, 420)
        self.configure(bg=self.colors['bg'])
        self.transient(parent)
        self.protocol('WM_DELETE_WINDOW', self.close)

        self.address_var = tk.StringVar(value=f'0x{self.base_address:X}')
        self.size_var = tk.StringVar(value='128')
        # Cheat Engine keeps the memory browser visually live.  Make that the
        # useful default while still allowing the user to pause it explicitly.
        self.auto_var = tk.BooleanVar(value=True)
        self.interval_var = tk.StringVar(value='250 ms')
        self.status_var = tk.StringVar(value='Ready')
        self.info_var = tk.StringVar(value='Select a byte for details')

        self._build_ui()
        self.bind('<Control-r>', lambda _event: self.refresh())
        self.bind('<F5>', lambda _event: self.refresh())
        self.bind('<Control-g>', lambda _event: self._focus_address())
        self.bind('<Control-e>', lambda _event: self.edit_bytes())
        self._select_address(self.base_address)
        self.refresh()
        self._toggle_auto_refresh()

    def _build_ui(self):
        c = self.colors
        header = tk.Frame(self, bg=c['panel'], highlightbackground=c['border'],
                          highlightthickness=1)
        header.pack(fill='x', padx=8, pady=(8, 5))

        tk.Label(header, text='HEX MEMORY INSPECTOR', bg=c['panel'], fg=c['accent'],
                 font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w',
                                                     padx=10, pady=(7, 3))
        tk.Label(header, textvariable=self.status_var, bg=c['panel'], fg=c['muted'],
                 font=('Segoe UI', 8)).grid(row=0, column=1, sticky='e', padx=10,
                                            pady=(7, 3))

        controls = tk.Frame(header, bg=c['panel'])
        controls.grid(row=1, column=0, columnspan=2, sticky='ew', padx=8, pady=(0, 8))
        header.grid_columnconfigure(1, weight=1)

        tk.Label(controls, text='Address', bg=c['panel'], fg=c['muted'],
                 font=('Segoe UI', 8)).pack(side='left', padx=(0, 4))
        self.address_entry = tk.Entry(controls, textvariable=self.address_var,
                                      width=19, font=('Consolas', 9),
                                      bg=c['bg'], fg=c['fg'], insertbackground=c['fg'],
                                      relief='flat', highlightthickness=1,
                                      highlightbackground=c['border'])
        self.address_entry.pack(side='left', padx=(0, 5))
        self.address_entry.bind('<Return>', lambda _event: self._go_to_address())

        tk.Label(controls, text='Bytes', bg=c['panel'], fg=c['muted'],
                 font=('Segoe UI', 8)).pack(side='left', padx=(2, 4))
        self.size_combo = ttk.Combobox(controls, textvariable=self.size_var,
                                       values=('64', '128', '256', '512', '1024', '2048', '4096'),
                                       width=7, state='readonly')
        self.size_combo.pack(side='left', padx=(0, 6))
        self.size_combo.bind('<<ComboboxSelected>>', lambda _event: self.refresh())

        self._button(controls, '← Page', lambda: self._move_page(-1)).pack(side='left', padx=2)
        self._button(controls, 'Page →', lambda: self._move_page(1)).pack(side='left', padx=2)
        self._button(controls, 'Go', self._go_to_address).pack(side='left', padx=2)
        self._button(controls, '↻ Refresh', self.refresh).pack(side='left', padx=2)
        self._button(controls, '✎ Edit Bytes', self.edit_bytes).pack(side='left', padx=2)
        self._button(controls, 'Copy Byte', self.copy_selected_byte).pack(side='left', padx=2)
        self._button(controls, 'Add to Watch', self.add_to_watch).pack(side='left', padx=2)

        tk.Checkbutton(controls, text='Auto refresh', variable=self.auto_var,
                       command=self._toggle_auto_refresh, bg=c['panel'], fg=c['fg'],
                       selectcolor=c['bg'], activebackground=c['panel'],
                       activeforeground=c['fg'], font=('Segoe UI', 8)).pack(side='left', padx=(10, 2))
        self.interval_combo = ttk.Combobox(controls, textvariable=self.interval_var,
                                            values=('100 ms', '250 ms', '500 ms', '1000 ms'),
                                            width=8, state='readonly')
        self.interval_combo.pack(side='left', padx=2)
        self.interval_combo.bind('<<ComboboxSelected>>', lambda _event: self._restart_auto_refresh())

        body = tk.Frame(self, bg=c['border'])
        body.pack(fill='both', expand=True, padx=8, pady=(0, 5))
        self.text = tk.Text(body, wrap='none', undo=False, takefocus=True,
                            font=('Consolas', 10), bg=c['bg'], fg=c['fg'],
                            insertbackground=c['fg'], relief='flat', padx=8, pady=8)
        yscroll = ttk.Scrollbar(body, orient='vertical', command=self.text.yview)
        xscroll = ttk.Scrollbar(body, orient='horizontal', command=self.text.xview)
        self.text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.text.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)

        self.text.tag_configure('offset', foreground=c['muted'])
        self.text.tag_configure('hex', foreground=c['accent'])
        self.text.tag_configure('ascii', foreground=c['fg'])
        self.text.tag_configure('changed', background='#4a3410', foreground='#ffd866')
        self.text.tag_configure('live_changed', background='#1f6f4a', foreground='#d1fae5')
        self.text.tag_configure('live_fade', background='#294a3a', foreground='#9be6b5')
        self.text.tag_configure('selected', background=c['accent'], foreground=c['bg'])
        self.text.tag_configure('target', foreground='#7ee787')
        self.text.bind('<Button-1>', self._on_text_click)
        self.text.bind('<Button-3>', self._on_context_menu)
        self.text.bind('<KeyPress>', self._on_key_press)

        footer = tk.Frame(self, bg=c['panel'], highlightbackground=c['border'],
                          highlightthickness=1)
        footer.pack(fill='x', padx=8, pady=(0, 8))
        tk.Label(footer, textvariable=self.info_var, anchor='w', bg=c['panel'],
                 fg=c['fg'], font=('Consolas', 9)).pack(fill='x', padx=9, pady=6)

    def _button(self, parent, text, command):
        c = self.colors
        return tk.Button(parent, text=text, command=command, font=('Segoe UI', 8),
                         bg=c['btn_bg'], fg=c['btn_fg'], activebackground=c['accent'],
                         activeforeground=c['bg'], relief='flat', padx=7, pady=2,
                         cursor='hand2', highlightthickness=1,
                         highlightbackground=c['border'])

    def _focus_address(self):
        self.address_entry.focus_set()
        self.address_entry.selection_range(0, 'end')

    def _parse_range(self):
        address, error = ms.parse_address_string(self.process_handle,
                                                  self.address_var.get())
        if error:
            raise ValueError(error)
        try:
            size = int(self.size_var.get())
        except (TypeError, ValueError) as exc:
            raise ValueError('Byte count must be an integer') from exc
        if address < 0 or not 1 <= size <= 4096:
            raise ValueError('Address must be non-negative and byte count must be 1-4096')
        return address, size

    def _go_to_address(self):
        """Navigate to the address field and select its first byte."""
        try:
            address, _size = self._parse_range()
        except ValueError as exc:
            self.status_var.set(f'Invalid range: {exc}')
            return
        self.selected_address = address
        self._select_first_byte_on_next_range = True
        self.refresh()

    def _move_page(self, direction):
        """Move by one visible page, preserving the selected-byte offset."""
        try:
            _address, size = self._parse_range()
        except ValueError as exc:
            self.status_var.set(f'Invalid range: {exc}')
            return
        old_base = self.base_address
        new_base = max(0, old_base + (direction * size))
        selected_offset = self.selected_address - old_base
        self.address_var.set(f'0x{new_base:X}')
        self.selected_address = new_base + max(0, min(selected_offset, size - 1))
        self.refresh()

    def refresh(self):
        if self._reading or self._closed:
            return
        try:
            address, size = self._parse_range()
        except ValueError as exc:
            self.status_var.set(f'Invalid range: {exc}')
            return

        self._reading = True
        started = time.perf_counter()
        try:
            data = ms.rblock(self.process_handle, address, size)
            if data is None:
                error = ctypes.get_last_error()
                self.status_var.set(f'Read failed at 0x{address:X} (Win32 error {error})')
                return
            new_range = self._range_key != (address, size)
            previous_data = self._data
            if new_range:
                self._original_data = bytes(data)
                self._range_key = (address, size)
                self._changed_at.clear()
                if self._select_first_byte_on_next_range or not (
                        address <= self.selected_address < address + len(data)):
                    self.selected_address = address
            elif previous_data:
                now = time.monotonic()
                for index, (old, new) in enumerate(zip(previous_data, data)):
                    if old != new:
                        self._changed_at[address + index] = now
                # A partial read must not leave stale addresses marked live.
                for index in range(len(data), len(previous_data)):
                    self._changed_at.pop(address + index, None)
            self._select_first_byte_on_next_range = False
            self.base_address = address
            self.address_var.set(f'0x{address:X}')
            self.title(f'Hex Memory Inspector @ 0x{address:016X}')
            self._data = bytes(data)
            self._refresh_count += 1
            self._last_read_ms = (time.perf_counter() - started) * 1000.0
            self._render()
            suffix = '' if len(data) == size else f' (partial: {len(data)}/{size} bytes)'
            live = 'LIVE' if self.auto_var.get() else 'PAUSED'
            recent = self._recent_change_count()
            change_text = f' • {recent} changed' if recent else ''
            self.status_var.set(
                f'{live} • {len(data):,} bytes @ 0x{address:016X} '
                f'• {self._last_read_ms:.1f} ms{change_text}{suffix}'
            )
            self._schedule_fade_render()
        finally:
            self._reading = False

    def _recent_change_count(self):
        cutoff = time.monotonic() - 1.0
        return sum(timestamp >= cutoff for timestamp in self._changed_at.values())

    def _schedule_fade_render(self):
        if self._fade_job is not None:
            try:
                self.after_cancel(self._fade_job)
            except tk.TclError:
                pass
            self._fade_job = None
        if not self._changed_at or self._closed:
            return
        self._fade_job = self.after(150, self._fade_tick)

    def _fade_tick(self):
        self._fade_job = None
        if self._closed:
            return
        cutoff = time.monotonic() - 1.0
        self._changed_at = {
            address: timestamp
            for address, timestamp in self._changed_at.items()
            if timestamp >= cutoff
        }
        self._render()
        self._schedule_fade_render()

    def _render(self):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        if not self._data:
            self.text.configure(state='disabled')
            return

        for row_start in range(0, len(self._data), 16):
            row = self._data[row_start:row_start + 16]
            row_address = self.base_address + row_start
            self.text.insert('end', f'{row_address:016X}  ', 'offset')
            for index, value in enumerate(row):
                address = row_address + index
                tags = ['hex']
                address_age = self._changed_at.get(address)
                if address_age is not None and time.monotonic() - address_age < 0.35:
                    tags.append('live_changed')
                elif address_age is not None:
                    tags.append('live_fade')
                elif row_start + index < len(self._original_data) and \
                        self._original_data[row_start + index] != value:
                    tags.append('changed')
                if address == self.selected_address:
                    tags.append('selected')
                elif address == self.base_address:
                    tags.append('target')
                self.text.insert('end', f'{value:02X} ', tuple(tags))
            if len(row) < 16:
                self.text.insert('end', '   ' * (16 - len(row)))
            self.text.insert('end', ' | ')
            for index, value in enumerate(row):
                tags = ['ascii']
                address_age = self._changed_at.get(row_address + index)
                if address_age is not None and time.monotonic() - address_age < 0.35:
                    tags.append('live_changed')
                elif address_age is not None:
                    tags.append('live_fade')
                elif row_start + index < len(self._original_data) and \
                        self._original_data[row_start + index] != value:
                    tags.append('changed')
                if row_address + index == self.selected_address:
                    tags.append('selected')
                self.text.insert('end', chr(value) if 32 <= value < 127 else '.', tuple(tags))
            self.text.insert('end', '\n')
        # Keep the widget focusable for arrow/page navigation, but make all
        # keypresses read-only through _on_key_press.
        self.text.configure(state='normal')
        self._update_info()

    def _on_text_click(self, event):
        self.text.focus_set()
        try:
            line, column = self.text.index(f'@{event.x},{event.y}').split('.')
            row = int(line) - 1
            column = int(column)
            if row < 0 or not 18 <= column < 66:
                return
            byte_index = (column - 18) // 3
            if 0 <= byte_index < 16:
                address = self.base_address + row * 16 + byte_index
                if address < self.base_address + len(self._data):
                    self._select_address(address)
        except (ValueError, tk.TclError):
            return

    def _select_address(self, address):
        if self._data and self.base_address <= address < self.base_address + len(self._data):
            self.selected_address = address
            self._render()
        else:
            self.selected_address = int(address)
            self._update_info()

    def _on_key_press(self, event):
        """Navigate like CE's hex view while keeping edits behind Ctrl+E."""
        if event.state & 0x4:  # Ctrl is handled by the window shortcuts.
            return
        offset = self._selected_offset()
        if offset is None:
            return
        delta = {
            'Left': -1,
            'Right': 1,
            'Up': -16,
            'Down': 16,
        }.get(event.keysym)
        if delta is not None:
            target = self.selected_address + delta
            if 0 <= target - self.base_address < len(self._data):
                self._select_address(target)
            return 'break'
        if event.keysym in ('Prior', 'Next'):
            self._move_page(-1 if event.keysym == 'Prior' else 1)
            return 'break'
        if event.keysym == 'Home':
            self._select_address(self.base_address)
            return 'break'
        if event.keysym == 'End':
            self._select_address(self.base_address + len(self._data) - 1)
            return 'break'
        return 'break'

    def _selected_offset(self):
        offset = self.selected_address - self.base_address
        if offset < 0 or offset >= len(self._data):
            return None
        return offset

    def _update_info(self):
        offset = self._selected_offset()
        if offset is None:
            self.info_var.set('Select a byte inside the loaded range for details')
            return
        value = self._data[offset]
        signed = value - 256 if value >= 128 else value
        char = chr(value) if 32 <= value < 127 else '.'
        self.info_var.set(
            f'0x{self.selected_address:016X}  +0x{offset:X}  '
            f'HEX {value:02X}  UINT8 {value}  INT8 {signed}  ASCII {char!r}'
        )

    def _on_context_menu(self, event):
        self._on_text_click(event)
        menu = tk.Menu(self, tearoff=0, bg=self.colors['panel'], fg=self.colors['fg'])
        menu.add_command(label='Edit selected bytes…', command=self.edit_bytes)
        menu.add_command(label='Copy selected byte', command=self.copy_selected_byte)
        menu.add_command(label='Copy selected address', command=self.copy_selected_address)
        menu.add_command(label='Copy visible bytes', command=self.copy_visible_bytes)
        menu.add_command(label='Add selected address to Watch', command=self.add_to_watch)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_selected_byte(self):
        offset = self._selected_offset()
        if offset is None:
            self.status_var.set('Select a byte before copying')
            return
        self.clipboard_clear()
        self.clipboard_append(f'{self._data[offset]:02X}')
        self.status_var.set(f'Copied byte at 0x{self.selected_address:X}')

    def copy_selected_address(self):
        self.clipboard_clear()
        self.clipboard_append(f'0x{self.selected_address:X}')
        self.status_var.set(f'Copied address 0x{self.selected_address:X}')

    def copy_visible_bytes(self):
        if not self._data:
            self.status_var.set('No visible bytes to copy')
            return
        self.clipboard_clear()
        self.clipboard_append(' '.join(f'{value:02X}' for value in self._data))
        self.status_var.set(f'Copied {len(self._data):,} visible bytes')

    def edit_bytes(self):
        offset = self._selected_offset()
        if offset is None:
            self.status_var.set('Select a byte inside the loaded range before editing')
            return
        initial = ' '.join(f'{value:02X}' for value in self._data[offset:offset + 8])
        raw = simpledialog.askstring(
            'Edit memory bytes',
            f'Bytes to write at 0x{self.selected_address:016X}:',
            initialvalue=initial,
            parent=self,
        )
        if raw is None:
            return
        try:
            payload = bytes.fromhex(raw.replace(',', ' '))
        except ValueError:
            messagebox.showerror('Invalid bytes', 'Use hexadecimal bytes such as 90 90 FF.', parent=self)
            return
        if not payload:
            messagebox.showwarning('Nothing to write', 'Enter at least one byte.', parent=self)
            return
        remaining = len(self._data) - offset
        if len(payload) > remaining:
            messagebox.showerror(
                'Write outside view',
                f'The edit contains {len(payload)} bytes but only {remaining} bytes remain in the loaded range.',
                parent=self,
            )
            return
        if not ms.wblock(self.process_handle, self.selected_address, payload):
            error = ctypes.get_last_error()
            messagebox.showerror('Write failed', f'WriteProcessMemory failed (Win32 error {error}).', parent=self)
            return
        self.status_var.set(f'Wrote {len(payload)} bytes at 0x{self.selected_address:X}')
        self.refresh()

    def add_to_watch(self):
        if self.on_watch is None:
            self.status_var.set('Memory Watch is not available')
            return
        address = self.selected_address if self._selected_offset() is not None else self.base_address
        self.on_watch(address)
        self.status_var.set(f'Added 0x{address:X} to Memory Watch')

    def _toggle_auto_refresh(self):
        if self.auto_var.get():
            self._schedule_refresh()
        else:
            self._stop_auto_refresh()

    def _restart_auto_refresh(self):
        if self.auto_var.get():
            self._schedule_refresh()

    def _schedule_refresh(self):
        self._stop_auto_refresh()
        try:
            interval = int(self.interval_var.get().split()[0])
        except (TypeError, ValueError):
            interval = 250
        self._refresh_job = self.after(interval, self._auto_refresh)

    def _auto_refresh(self):
        self._refresh_job = None
        if not self.winfo_exists():
            return
        self.refresh()
        if self.auto_var.get():
            self._schedule_refresh()

    def _stop_auto_refresh(self):
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except tk.TclError:
                pass
            self._refresh_job = None

    def close(self):
        self._closed = True
        self._stop_auto_refresh()
        if self._fade_job is not None:
            try:
                self.after_cancel(self._fade_job)
            except tk.TclError:
                pass
            self._fade_job = None
        self.destroy()
