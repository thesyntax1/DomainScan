import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from domainscan import __version__, helpers, history_store, i18n, profiles, scanner, settings, whois_check


APP_TITLE = "DomainScan"
APP_SUBTITLE = "Legal website and domain intelligence"


def asset_path(name):
    """Locate a bundled asset in both source and frozen (PyInstaller) runs."""
    candidates = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidates.append(os.path.join(base, "domainscan", "assets", name))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", name))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return ""

BG = "#151a21"
PANEL = "#1e242d"
PANEL2 = "#28303c"
ENTRY_BG = "#0f1319"
TEXT = "#e9edf3"
MUTED = "#9aa4b2"
ACCENT = "#2f7cf6"
ACCENT_ACTIVE = "#1f63d6"
BORDER = "#363f4d"
ROW_ALT = "#1a1f27"


class DomainScanApp:
    def __init__(self, root):
        self.root = root
        self.lang = i18n.load_language()
        self.section_keys = ["*all*"]
        self.tree_sections = {}
        self.root.title(APP_TITLE + " " + __version__)
        self.root.geometry("1220x780")
        self.root.minsize(1020, 640)
        self.root.configure(bg=BG)
        self.queue = queue.Queue()
        self.result = None
        self.all_rows = []
        self.watch_stop = None
        self.watch_log = None
        self.scanning = False
        self.ports_var = tk.BooleanVar(value=True)
        self.sub_var = tk.BooleanVar(value=True)
        self.caps = profiles.get_profile("Standard")
        self.cancel_event = None
        self.update_var = tk.BooleanVar(value=bool(settings.get("check_updates", False)))
        self.load_branding()
        self.setup_style()
        self.build_menu()
        self.build_header()
        self.build_input()
        self.build_progress()
        self.build_main()
        self.build_status()
        self.poll_queue()
        try:
            if settings.get("check_updates", False):
                self.check_updates_silent()
        except Exception:
            pass

    def t(self, name, **values):
        return i18n.get(self.lang, name, **values)

    def section_name(self, name):
        return i18n.section(self.lang, name)

    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=self.t("menu_export_json"), command=self.export_json)
        file_menu.add_command(label=self.t("menu_export_csv"), command=self.export_csv)
        file_menu.add_command(label=self.t("menu_export_txt"), command=self.export_txt)
        file_menu.add_command(label=self.t("menu_export_html"), command=self.export_html)
        file_menu.add_separator()
        file_menu.add_command(label=self.t("menu_exit"), command=self.root.destroy)
        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label=self.t("menu_start_scan"), command=self.start_scan)
        scan_menu.add_command(label=self.t("menu_compare"), command=self.compare_scan)
        scan_menu.add_command(label=self.t("menu_history"), command=self.open_history)
        scan_menu.add_command(label=self.t("menu_watch"), command=self.open_watch)
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label=self.t("menu_whois"), command=self.open_whois_lookup)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=self.t("menu_check_updates"), command=self.check_updates)
        help_menu.add_checkbutton(label=self.t("menu_updates_startup"), variable=self.update_var, command=self.on_update_toggle)
        help_menu.add_separator()
        help_menu.add_command(label=self.t("menu_about"), command=self.show_about)
        menubar.add_cascade(label=self.t("menu_file"), menu=file_menu)
        menubar.add_cascade(label=self.t("menu_scan"), menu=scan_menu)
        menubar.add_cascade(label=self.t("menu_tools"), menu=tools_menu)
        menubar.add_cascade(label=self.t("menu_help"), menu=help_menu)
        self.menubar = menubar
        self.root.configure(menu=menubar)

    def setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("TButton", background=PANEL2, foreground=TEXT, borderwidth=0, padding=(12, 7))
        style.map("TButton", background=[("active", ACCENT_ACTIVE)], foreground=[("active", "white")])
        style.configure("Accent.TButton", background=ACCENT, foreground="white", font=("Segoe UI", 10, "bold"), padding=(18, 7))
        style.map("Accent.TButton", background=[("active", ACCENT_ACTIVE)])
        style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=TEXT, bordercolor=BORDER, insertcolor=TEXT, padding=6)
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.configure("TCombobox", fieldbackground=ENTRY_BG, background=PANEL2, foreground=TEXT, arrowcolor=TEXT)
        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=PANEL2, borderwidth=0, thickness=8)
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL2, foreground=TEXT, font=("Segoe UI", 10, "bold"), padding=6)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])

    def load_branding(self):
        self.logo_image = None
        logo_path = asset_path("logo.png")
        if logo_path:
            try:
                self.logo_image = tk.PhotoImage(file=logo_path)
                if self.logo_image.width() > 96:
                    factor = max(1, self.logo_image.width() // 96)
                    self.logo_image = self.logo_image.subsample(factor, factor)
            except Exception:
                self.logo_image = None
        ico_path = asset_path("icon.ico")
        try:
            if ico_path and sys.platform.startswith("win"):
                self.root.iconbitmap(ico_path)
        except Exception:
            pass
        if self.logo_image is not None:
            try:
                self.root.iconphoto(True, self.logo_image)
            except Exception:
                pass

    def build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=16, pady=(14, 4))
        if self.logo_image is not None:
            logo = tk.Label(header, image=self.logo_image, bg=BG)
            logo.pack(side="left", padx=(0, 10))
        title = tk.Label(header, text=APP_TITLE, font=("Segoe UI", 22, "bold"), bg=BG, fg=TEXT)
        title.pack(side="left")
        self.subtitle_label = tk.Label(header, text="  " + self.t("subtitle"), font=("Segoe UI", 11), bg=BG, fg=MUTED)
        self.subtitle_label.pack(side="left", pady=(8, 0))
        self.about_button = ttk.Button(header, text=self.t("about"), command=self.show_about)
        self.about_button.pack(side="right")
        version = ttk.Label(header, text="v" + __version__, style="Muted.TLabel")
        version.pack(side="right", padx=(0, 10), pady=(6, 0))
        self.lang_box = ttk.Combobox(header, values=[label for _, label in i18n.LANGUAGES], state="readonly", width=13)
        self.lang_box.pack(side="right", padx=(0, 10))
        for code, label in i18n.LANGUAGES:
            if code == self.lang:
                self.lang_box.set(label)
        self.lang_box.bind("<<ComboboxSelected>>", lambda event: self.on_language())
        self.lang_label = ttk.Label(header, text=self.t("language_label"), style="Muted.TLabel")
        self.lang_label.pack(side="right", padx=(0, 6), pady=(6, 0))

    def build_input(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=16, pady=8)
        self.target_prompt = ttk.Label(bar, text=self.t("target_label"))
        self.target_prompt.pack(side="left")
        self.target_entry = ttk.Entry(bar, width=44, font=("Segoe UI", 11))
        self.target_entry.pack(side="left", padx=(8, 8))
        self.target_entry.bind("<Return>", lambda event: self.start_scan())
        self.scan_button = ttk.Button(bar, text=self.t("scan"), style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.clear_button = ttk.Button(bar, text=self.t("clear"), command=self.clear_all)
        self.clear_button.pack(side="left", padx=(6, 0))
        self.compare_button = ttk.Button(bar, text=self.t("compare"), command=self.compare_scan)
        self.compare_button.pack(side="left", padx=(6, 0))
        self.ports_check = ttk.Checkbutton(bar, text=self.t("ports"), variable=self.ports_var)
        self.ports_check.pack(side="left", padx=(14, 0))
        self.subs_check = ttk.Checkbutton(bar, text=self.t("subdomains"), variable=self.sub_var)
        self.subs_check.pack(side="left", padx=(8, 0))
        for text, command in (("HTML", self.export_html), ("TXT", self.export_txt), ("CSV", self.export_csv), ("JSON", self.export_json)):
            button = ttk.Button(bar, text=text, command=command)
            button.pack(side="right", padx=(0, 6))

    def build_progress(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill="x", padx=16, pady=(0, 8))
        self.progress = ttk.Progressbar(frame, mode="determinate", maximum=100, style="Horizontal.TProgressbar")
        self.progress.pack(fill="x")
        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", padx=16, pady=(0, 8))
        self.status_label = ttk.Label(bottom, text=self.t("ready"), style="Muted.TLabel")
        self.status_label.pack(side="left")
        self.count_label = ttk.Label(bottom, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

    def build_main(self):
        filter_bar = ttk.Frame(self.root)
        filter_bar.pack(fill="x", padx=16, pady=(0, 6))
        self.search_label = ttk.Label(filter_bar, text=self.t("search"))
        self.search_label.pack(side="left")
        self.search_entry = ttk.Entry(filter_bar, width=36)
        self.search_entry.pack(side="left", padx=(8, 12))
        self.search_entry.bind("<KeyRelease>", lambda event: self.apply_filter())
        self.section_label = ttk.Label(filter_bar, text=self.t("section"))
        self.section_label.pack(side="left")
        self.section_box = ttk.Combobox(filter_bar, values=[self.t("all_sections")], state="readonly", width=24)
        self.section_box.pack(side="left", padx=(8, 0))
        self.section_box.set(self.t("all_sections"))
        self.section_box.bind("<<ComboboxSelected>>", lambda event: self.apply_filter())
        self.profile_label = ttk.Label(filter_bar, text=self.t("profile"))
        self.profile_label.pack(side="left", padx=(16, 0))
        self.profile_box = ttk.Combobox(filter_bar, values=profiles.profile_names(), state="readonly", width=12)
        self.profile_box.pack(side="left", padx=(8, 0))
        self.profile_box.set("Standard")
        self.profile_box.bind("<<ComboboxSelected>>", lambda event: self.on_profile())
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self.tree = ttk.Treeview(main, columns=("item", "value"))
        self.tree.heading("#0", text=self.t("col_section"), anchor="w")
        self.tree.heading("item", text=self.t("col_item"), anchor="w")
        self.tree.heading("value", text=self.t("col_value"), anchor="w")
        self.tree.column("#0", width=210, minwidth=150, stretch=False)
        self.tree.column("item", width=300, minwidth=180, stretch=False)
        self.tree.column("value", width=640, minwidth=200, stretch=True)
        self.tree.tag_configure("odd", background=ROW_ALT)
        vscroll = ttk.Scrollbar(main, orient="vertical", command=self.tree.yview)
        hscroll = ttk.Scrollbar(main, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        main.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", lambda event: self.on_select())
        self.tree.bind("<Double-1>", lambda event: self.copy_value())
        self.tree.bind("<Control-c>", lambda event: self.copy_value())
        self.menu = tk.Menu(self.root, tearoff=0, bg=PANEL2, fg=TEXT, activebackground=ACCENT, activeforeground="white")
        self.menu.add_command(label=self.t("copy_value"), command=self.copy_value)
        self.tree.bind("<Button-3>", self.show_menu)
        detail_frame = ttk.Frame(self.root)
        detail_frame.pack(fill="x", padx=16, pady=(0, 8))
        self.detail_label = ttk.Label(detail_frame, text=self.t("details_hint"), style="Muted.TLabel")
        self.detail_label.pack(anchor="w", pady=(0, 4))
        self.detail = tk.Text(detail_frame, height=5, wrap="word", bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT, relief="flat", font=("TkFixedFont", 10))
        self.detail.pack(fill="x")
        self.detail.insert("1.0", self.t("detail_placeholder"))
        self.detail.configure(state="disabled")

    def build_status(self):
        self.bottom = ttk.Label(self.root, text=self.t("legal_note"), style="Muted.TLabel")
        self.bottom.pack(fill="x", padx=16, pady=(0, 10))

    def on_language(self):
        picked = self.lang_box.get()
        for code, label in i18n.LANGUAGES:
            if label == picked and code != self.lang:
                self.lang = code
                try:
                    i18n.save_language(code)
                except Exception:
                    pass
                self.refresh_language()
                return

    def refresh_language(self):
        try:
            self.menubar.destroy()
        except Exception:
            pass
        self.build_menu()
        self.menu.delete(0, "end")
        self.menu.add_command(label=self.t("copy_value"), command=self.copy_value)
        self.subtitle_label.configure(text="  " + self.t("subtitle"))
        self.about_button.configure(text=self.t("about"))
        self.lang_label.configure(text=self.t("language_label"))
        self.target_prompt.configure(text=self.t("target_label"))
        self.scan_button.configure(text=self.t("cancel") if self.scanning else self.t("scan"))
        self.clear_button.configure(text=self.t("clear"))
        self.compare_button.configure(text=self.t("compare"))
        self.ports_check.configure(text=self.t("ports"))
        self.subs_check.configure(text=self.t("subdomains"))
        self.search_label.configure(text=self.t("search"))
        self.section_label.configure(text=self.t("section"))
        self.profile_label.configure(text=self.t("profile"))
        self.tree.heading("#0", text=self.t("col_section"))
        self.tree.heading("item", text=self.t("col_item"))
        self.tree.heading("value", text=self.t("col_value"))
        self.detail_label.configure(text=self.t("details_hint"))
        self.bottom.configure(text=self.t("legal_note"))
        keep = self.current_section_key()
        self.section_choices(self.section_keys[1:])
        if keep in self.section_keys:
            self.select_section_key(keep)
        else:
            self.select_section_key("*all*")
        self.apply_filter()
        if self.scanning:
            pass
        elif self.result:
            self.status_label.configure(text=self.t("scan_complete", seconds=self.result["meta"]["duration_seconds"]))
        else:
            self.status_label.configure(text=self.t("ready"))
            self.set_detail(self.t("detail_placeholder"))

    def section_choices(self, keys):
        self.section_keys = ["*all*"] + list(keys)
        displays = [self.t("all_sections")] + [self.section_name(key) for key in keys]
        self.section_box.configure(values=displays)
        return displays

    def current_section_key(self):
        try:
            index = list(self.section_box.cget("values")).index(self.section_box.get())
        except ValueError:
            return "*all*"
        if 0 <= index < len(self.section_keys):
            return self.section_keys[index]
        return "*all*"

    def select_section_key(self, key):
        if key == "*all*":
            self.section_box.set(self.t("all_sections"))
        elif key in self.section_keys:
            self.section_box.set(self.section_name(key))

    def on_profile(self):
        self.caps = profiles.get_profile(self.profile_box.get())
        self.ports_var.set(self.caps["include_ports"])
        self.sub_var.set(self.caps["include_subdomains"])

    def start_scan(self):
        if self.scanning:
            return
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning(self.t("missing_target_title"), self.t("missing_target_body"))
            return
        self.scanning = True
        self.cancel_event = threading.Event()
        self.scan_button.configure(text=self.t("cancel"), command=self.cancel_scan, state="normal")
        self.result = None
        self.all_rows = []
        for child in self.tree.get_children():
            self.tree.delete(child)
        self.tree_sections = {}
        self.section_choices([])
        self.select_section_key("*all*")
        self.progress.configure(value=0)
        self.count_label.configure(text="")
        self.set_detail(self.t("scanning", target=target))
        thread = threading.Thread(target=self.worker, args=(target,), daemon=True)
        thread.start()

    def cancel_scan(self):
        if not self.scanning:
            return
        if self.cancel_event is not None:
            self.cancel_event.set()
        self.scan_button.configure(state="disabled")
        self.status_label.configure(text=self.t("cancelling"))

    def reset_scan_button(self):
        self.scan_button.configure(text=self.t("scan"), command=self.start_scan, state="normal")

    def worker(self, target):
        def forward(percent, message):
            self.queue.put(("progress", percent, message))
        try:
            caps = self.caps
            result = scanner.run_scan(
                target,
                on_progress=forward,
                include_ports=self.ports_var.get(),
                include_subdomains=self.sub_var.get(),
                timeout=caps["timeout"],
                crawl_pages=caps["crawl_pages"],
                js_files=caps["js_files"],
                subdomain_web=caps["subdomain_web"],
                include_recon=caps["include_recon"],
                cancel_event=self.cancel_event,
            )
        except ValueError as exc:
            self.queue.put(("invalid", str(exc)))
            return
        except Exception as exc:
            self.queue.put(("error", exc.__class__.__name__ + ": " + str(exc)))
            return
        self.queue.put(("done", result))

    def poll_queue(self):
        try:
            while True:
                message = self.queue.get_nowait()
                kind = message[0]
                if kind == "progress":
                    self.progress.configure(value=message[1])
                    self.status_label.configure(text=message[2])
                elif kind == "done":
                    self.finish_scan(message[1])
                elif kind == "invalid":
                    self.fail_scan(self.t("invalid_target", detail=message[1]))
                elif kind == "error":
                    self.fail_scan(self.t("scan_failed", detail=message[1]))
                elif kind == "watch":
                    if self.watch_log is not None:
                        try:
                            self.watch_log.insert(tk.END, message[1])
                            self.watch_log.see(tk.END)
                        except Exception:
                            pass
                    self.status_label.configure(text=message[1][:120])
                elif kind == "watch_done":
                    self.watch_stop = None
                    self.status_label.configure(text=self.t("watch_finished"))
                elif kind == "update":
                    self.finish_update_check(message[1], message[2], message[3])
        except queue.Empty:
            pass
        self.root.after(120, self.poll_queue)

    def finish_scan(self, result):
        self.scanning = False
        self.cancel_event = None
        self.reset_scan_button()
        self.result = result
        self.progress.configure(value=100)
        meta = result["meta"]
        cancelled = bool(meta.get("cancelled"))
        if cancelled:
            self.status_label.configure(text=self.t("scan_cancelled"))
        else:
            self.status_label.configure(text=self.t("scan_complete", seconds=meta["duration_seconds"]))
        self.count_label.configure(text=self.t("findings", n=meta["findings"]))
        self.all_rows = []
        for section, items in result["sections"].items():
            for key, value in items:
                self.all_rows.append((section, key, value))
        self.section_choices(result["sections"].keys())
        self.select_section_key("*all*")
        self.apply_filter()
        host = result["target"].get("host", "?")
        if cancelled:
            self.set_detail(self.t("scan_cancelled_detail", host=host))
        else:
            self.set_detail(self.t("scan_finished_detail", host=host, n=meta["findings"]))
            try:
                history_store.save_run(result)
            except Exception:
                pass

    def fail_scan(self, text):
        self.scanning = False
        self.cancel_event = None
        self.reset_scan_button()
        self.status_label.configure(text=text)
        messagebox.showerror("DomainScan", text)

    def apply_filter(self):
        query = self.search_entry.get().strip().lower()
        section = self.current_section_key()
        for child in self.tree.get_children():
            self.tree.delete(child)
        self.tree_sections = {}
        grouped = {}
        for sec, key, value in self.all_rows:
            if section != "*all*" and sec != section:
                continue
            if query and query not in key.lower() and query not in value.lower() and query not in sec.lower() and query not in self.section_name(sec).lower():
                continue
            if sec not in grouped:
                grouped[sec] = []
            grouped[sec].append((key, value))
        stripe = 0
        for sec, items in grouped.items():
            parent = self.tree.insert("", "end", text=self.section_name(sec), values=("", self.t("items_suffix", n=len(items))), open=True)
            self.tree_sections[parent] = sec
            for key, value in items:
                if stripe % 2:
                    tags = ("odd",)
                else:
                    tags = ()
                self.tree.insert(parent, "end", text="", values=(key, helpers.short(value, 220)), tags=tags)
                stripe += 1
        if self.result and (query or section != "*all*"):
            shown = 0
            for items in grouped.values():
                shown += len(items)
            self.count_label.configure(text=self.t("shown_of", shown=shown, total=len(self.all_rows)))
        elif self.result:
            self.count_label.configure(text=self.t("findings", n=len(self.all_rows)))

    def selected_row(self):
        selection = self.tree.selection()
        if not selection:
            return None
        item = self.tree.item(selection[0])
        values = item.get("values", [])
        if len(values) < 2 or not values[0]:
            return None
        parent = self.tree.parent(selection[0])
        if parent:
            section = self.tree_sections.get(parent, "")
        else:
            section = ""
        key = str(values[0])
        full = str(values[1])
        for sec, item_key, item_value in self.all_rows:
            if sec == section and item_key == key:
                full = item_value
                break
        return section, key, full

    def on_select(self):
        row = self.selected_row()
        if not row:
            return
        section, key, value = row
        self.set_detail(self.section_name(section) + " / " + key + "\n\n" + value)

    def set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def copy_value(self):
        row = self.selected_row()
        if not row:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(row[2])
        self.status_label.configure(text=self.t("copied", key=row[1]))

    def show_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.menu.post(event.x_root, event.y_root)

    def clear_all(self):
        if self.scanning:
            return
        self.target_entry.delete(0, "end")
        self.search_entry.delete(0, "end")
        self.result = None
        self.all_rows = []
        for child in self.tree.get_children():
            self.tree.delete(child)
        self.tree_sections = {}
        self.section_choices([])
        self.select_section_key("*all*")
        self.progress.configure(value=0)
        self.status_label.configure(text=self.t("ready"))
        self.count_label.configure(text="")
        self.set_detail(self.t("detail_placeholder"))

    def need_result(self):
        if not self.result:
            messagebox.showinfo(self.t("nothing_to_export_title"), self.t("nothing_to_export_body"))
            return False
        return True

    def export_json(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[(self.t("filetype_json"), "*.json")])
        if not path:
            return
        try:
            helpers.export_json(path, self.result)
        except Exception as exc:
            messagebox.showerror(self.t("export_failed_title"), str(exc))
            return
        messagebox.showinfo(self.t("export_complete_title"), self.t("export_json_saved"))

    def export_csv(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[(self.t("filetype_csv"), "*.csv")])
        if not path:
            return
        try:
            helpers.export_csv(path, self.result)
        except Exception as exc:
            messagebox.showerror(self.t("export_failed_title"), str(exc))
            return
        messagebox.showinfo(self.t("export_complete_title"), self.t("export_csv_saved"))

    def export_txt(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[(self.t("filetype_txt"), "*.txt")])
        if not path:
            return
        try:
            helpers.export_txt(path, self.result)
        except Exception as exc:
            messagebox.showerror(self.t("export_failed_title"), str(exc))
            return
        messagebox.showinfo(self.t("export_complete_title"), self.t("export_txt_saved"))

    def compare_scan(self):
        if not self.result or self.scanning:
            messagebox.showinfo(self.t("nothing_to_compare_title"), self.t("nothing_to_compare_body"))
            return
        host = self.result["target"]["host"]
        try:
            previous = history_store.previous_run(host, self.result["meta"]["scanned_at"])
        except Exception:
            previous = None
        if not previous:
            messagebox.showinfo(self.t("no_previous_title"), self.t("no_previous_body", host=host))
            return
        changes = history_store.diff_runs(previous, self.result)
        try:
            changes = changes + history_store.trend_rows(host, self.result)
        except Exception:
            pass
        self.show_changes(changes, self.t("compared_with", stamp=str(previous["meta"].get("scanned_at", "earlier"))))

    def show_changes(self, changes, detail):
        merged = {"Changes": changes}
        for section, items in self.result["sections"].items():
            if section != "Changes":
                merged[section] = items
        self.result["sections"] = merged
        self.all_rows = []
        for section, items in merged.items():
            for key, value in items:
                self.all_rows.append((section, key, value))
        self.section_choices(merged.keys())
        self.select_section_key("Changes")
        self.apply_filter()
        self.set_detail(detail + " " + self.t("change_rows", n=len(changes)))

    def open_history(self):
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t("history_title"))
        dialog.geometry("760x520")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        top = ttk.Frame(dialog, padding=10)
        top.pack(fill=tk.X)
        ttk.Label(top, text=self.t("host_label")).pack(side=tk.LEFT, padx=(0, 6))
        entry = ttk.Entry(top, width=40)
        entry.pack(side=tk.LEFT, padx=(0, 8))
        if self.result:
            entry.insert(0, self.result["target"]["host"])
        else:
            entry.insert(0, self.target_entry.get().strip() or "example.com")
        runs = []

        def refresh():
            runs.clear()
            box.delete(0, tk.END)
            host = entry.get().strip()
            if not host:
                return
            try:
                paths = history_store.list_runs(host)
            except Exception:
                return
            for path in paths[:50]:
                try:
                    data = history_store.load_run(path)
                    label = self.t("run_label", stamp=str(data["meta"].get("scanned_at", "?")), n=str(data["meta"].get("findings", "?")))
                except Exception:
                    label = path + " " + self.t("unreadable")
                runs.append(path)
                box.insert(tk.END, label)
            status.configure(text=self.t("saved_scans", n=len(runs), host=host))

        def load_selected():
            picked = box.curselection()
            if not picked or self.scanning:
                return
            try:
                data = history_store.load_run(runs[picked[0]])
            except Exception as exc:
                messagebox.showerror("DomainScan", self.t("load_failed", error=exc.__class__.__name__))
                return
            self.result = data
            self.progress.configure(value=100)
            meta = data["meta"]
            self.status_label.configure(text=self.t("loaded_saved"))
            self.count_label.configure(text=self.t("findings", n=meta.get("findings", "?")))
            self.all_rows = []
            for section, items in data["sections"].items():
                for key, value in items:
                    self.all_rows.append((section, key, value))
            self.section_choices(data["sections"].keys())
            self.select_section_key("*all*")
            self.apply_filter()
            self.set_detail(self.t("loaded_detail", host=data["target"].get("host", "?"), stamp=str(meta.get("scanned_at", "?"))))
            dialog.destroy()

        def compare_selected():
            picked = box.curselection()
            if len(picked) != 2:
                messagebox.showinfo(self.t("select_two_title"), self.t("select_two_body"))
                return
            first = history_store.load_run(runs[picked[0]])
            second = history_store.load_run(runs[picked[1]])
            if first["meta"].get("scanned_at", "") > second["meta"].get("scanned_at", ""):
                first, second = second, first
            self.result = second
            changes = history_store.diff_runs(first, second)
            self.show_changes(changes, self.t("compared_two", old=str(first["meta"].get("scanned_at", "?")), new=str(second["meta"].get("scanned_at", "?"))))
            dialog.destroy()

        ttk.Button(top, text=self.t("refresh"), command=refresh).pack(side=tk.LEFT)
        box = tk.Listbox(dialog, bg=ENTRY_BG, fg=TEXT, selectmode=tk.EXTENDED, font=("Consolas", 10))
        box.pack(fill=tk.BOTH, expand=True, padx=10)
        bottom = ttk.Frame(dialog, padding=10)
        bottom.pack(fill=tk.X)
        ttk.Button(bottom, text=self.t("load"), command=load_selected).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(bottom, text=self.t("compare_selected"), command=compare_selected).pack(side=tk.LEFT)
        status = ttk.Label(bottom, text="")
        status.pack(side=tk.LEFT, padx=(12, 0))
        refresh()

    def open_watch(self):
        if self.watch_stop is not None and not self.watch_stop.is_set():
            messagebox.showinfo(self.t("watch_running_title"), self.t("watch_running_body"))
            return
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t("watch_title"))
        dialog.geometry("680x460")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        top = ttk.Frame(dialog, padding=10)
        top.pack(fill=tk.X)
        ttk.Label(top, text=self.t("target_label")).pack(side=tk.LEFT, padx=(0, 6))
        entry = ttk.Entry(top, width=30)
        entry.pack(side=tk.LEFT, padx=(0, 8))
        entry.insert(0, self.target_entry.get().strip() or "example.com")
        ttk.Label(top, text=self.t("every_sec")).pack(side=tk.LEFT, padx=(0, 6))
        interval_entry = ttk.Entry(top, width=8)
        interval_entry.pack(side=tk.LEFT, padx=(0, 8))
        interval_entry.insert(0, "300")
        ttk.Label(top, text=self.t("rounds")).pack(side=tk.LEFT, padx=(0, 6))
        rounds_entry = ttk.Entry(top, width=6)
        rounds_entry.pack(side=tk.LEFT)
        rounds_entry.insert(0, "0")
        log = tk.Listbox(dialog, bg=ENTRY_BG, fg=TEXT, font=("Consolas", 10))
        log.pack(fill=tk.BOTH, expand=True, padx=10)
        self.watch_log = log
        bottom = ttk.Frame(dialog, padding=10)
        bottom.pack(fill=tk.X)
        start_button = ttk.Button(bottom, text=self.t("start"))
        stop_button = ttk.Button(bottom, text=self.t("stop"), state="disabled")
        start_button.pack(side=tk.LEFT, padx=(0, 8))
        stop_button.pack(side=tk.LEFT)

        def watch_worker(target, interval, rounds, stop_event):
            caps = profiles.get_profile("Quick")
            round_no = 0
            while not stop_event.is_set():
                round_no += 1
                self.queue.put(("watch", self.t("round_scanning", round=round_no, target=target)))
                try:
                    result = scanner.run_scan(
                        target,
                        include_ports=False,
                        include_subdomains=caps["include_subdomains"],
                        timeout=caps["timeout"],
                        crawl_pages=0,
                        js_files=0,
                        subdomain_web=0,
                        include_recon=False,
                    )
                except Exception as exc:
                    self.queue.put(("watch", self.t("round_failed", round=round_no, error=exc.__class__.__name__)))
                    result = None
                if result is not None:
                    try:
                        history_store.save_run(result)
                        history_store.prune_old(result["target"]["host"])
                        previous = history_store.previous_run(result["target"]["host"], result["meta"]["scanned_at"])
                    except Exception:
                        previous = None
                    if not previous:
                        self.queue.put(("watch", self.t("round_baseline", round=round_no, findings=result["meta"]["findings"])))
                    else:
                        rows = history_store.diff_runs(previous, result)
                        summary = {key: value for key, value in rows if key in ("Added", "Removed", "Changed")}
                        line = self.t("round_delta", round=round_no, added=summary.get("Added", "0"), removed=summary.get("Removed", "0"), changed=summary.get("Changed", "0"))
                        self.queue.put(("watch", line))
                        for key, value in rows:
                            if key in ("Added finding", "Removed finding", "Changed finding"):
                                self.queue.put(("watch", "  " + value[:160]))
                if rounds > 0 and round_no >= rounds:
                    break
                for _ in range(max(interval, 5)):
                    if stop_event.is_set():
                        break
                    stop_event.wait(1)
            self.queue.put(("watch_done", None))

        def start():
            if self.scanning:
                messagebox.showinfo(self.t("busy_title"), self.t("busy_body"))
                return
            try:
                interval = int(interval_entry.get().strip())
                rounds = int(rounds_entry.get().strip())
            except ValueError:
                messagebox.showwarning(self.t("invalid_numbers_title"), self.t("invalid_numbers_body"))
                return
            target = entry.get().strip()
            if not target:
                messagebox.showwarning(self.t("missing_target_title"), self.t("missing_target_watch_body"))
                return
            stop_event = threading.Event()
            self.watch_stop = stop_event
            start_button.configure(state="disabled")
            stop_button.configure(state="normal")
            thread = threading.Thread(target=watch_worker, args=(target, interval, rounds, stop_event), daemon=True)
            thread.start()

        def stop():
            if self.watch_stop is not None:
                self.watch_stop.set()
            start_button.configure(state="normal")
            stop_button.configure(state="disabled")

        def on_close():
            stop()
            self.watch_log = None
            dialog.destroy()

        start_button.configure(command=start)
        stop_button.configure(command=stop)
        dialog.protocol("WM_DELETE_WINDOW", on_close)

    def open_whois_lookup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t("whois_title"))
        dialog.geometry("760x520")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        top = ttk.Frame(dialog, padding=10)
        top.pack(fill=tk.X)
        entry = ttk.Entry(top, width=46)
        entry.pack(side=tk.LEFT, padx=(0, 8))
        entry.insert(0, self.target_entry.get().strip() or "example.com")
        output = tk.Text(dialog, bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT, wrap=tk.WORD, font=("Consolas", 10))
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        def run_query():
            raw = entry.get().strip()
            if not raw:
                return
            output.delete("1.0", tk.END)
            output.insert(tk.END, self.t("looking_up", target=raw) + "\n")
            try:
                resolved = whois_check.resolve_whois_target(raw)
            except Exception as exc:
                output.insert(tk.END, self.t("invalid_target_paren", error=exc.__class__.__name__) + "\n")
                return
            if resolved["note"]:
                output.insert(tk.END, resolved["note"] + "\n")

            def worker():
                try:
                    result = whois_check.collect(resolved["query"], resolved["query"])
                    lines = [key + ": " + value for key, value in result["rows"]]
                except Exception as exc:
                    lines = [self.t("lookup_failed", error=exc.__class__.__name__)]
                dialog.after(0, lambda: show_lines(lines))

            def show_lines(lines):
                output.delete("1.0", tk.END)
                for line in lines:
                    output.insert(tk.END, line + "\n")
                self.set_detail(self.t("whois_finished", target=raw))

            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(top, text=self.t("look_up"), command=run_query).pack(side=tk.LEFT)
        entry.bind("<Return>", lambda event: run_query())

    def export_html(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[(self.t("filetype_html"), "*.html")])
        if not path:
            return
        try:
            helpers.export_html(path, self.result)
        except Exception as exc:
            messagebox.showerror(self.t("export_failed_title"), str(exc))
            return
        messagebox.showinfo(self.t("export_complete_title"), self.t("export_html_saved"))

    def show_about(self):
        messagebox.showinfo(self.t("about_title"), self.t("about_body", version=__version__))

    def on_update_toggle(self):
        try:
            settings.set("check_updates", bool(self.update_var.get()))
        except Exception:
            pass

    def check_updates(self):
        threading.Thread(target=self._check_updates_worker, args=(False,), daemon=True).start()

    def check_updates_silent(self):
        threading.Thread(target=self._check_updates_worker, args=(True,), daemon=True).start()

    def _check_updates_worker(self, silent):
        import requests
        try:
            response = requests.get(
                "https://api.github.com/repos/thesyntax1/DomainScan/releases/latest",
                timeout=6,
                headers={"User-Agent": "DomainScan/" + __version__, "Accept": "application/vnd.github+json"},
            )
            if response.status_code == 200:
                latest = (response.json().get("tag_name") or "").lstrip("v")
                self.queue.put(("update", "ok", latest, silent))
                return
        except Exception:
            pass
        self.queue.put(("update", "failed", "", silent))

    def finish_update_check(self, status, latest, silent):
        if status == "ok":
            if latest and latest != __version__:
                messagebox.showinfo(self.t("update_available_title"), self.t("update_available_body", version=latest))
            elif not silent:
                messagebox.showinfo(self.t("up_to_date_title"), self.t("up_to_date_body", version=__version__))
        elif not silent:
            messagebox.showinfo(self.t("update_failed_title"), self.t("update_failed_body"))


def main():
    root = tk.Tk()
    DomainScanApp(root)
    root.mainloop()
