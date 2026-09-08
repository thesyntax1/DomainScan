import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from domainscan import __version__, helpers, history_store, profiles, scanner, whois_check


APP_TITLE = "DomainScan"
APP_SUBTITLE = "Legal website and domain intelligence"

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
        self.root.title(APP_TITLE + " " + __version__)
        self.root.geometry("1220x780")
        self.root.minsize(1020, 640)
        self.root.configure(bg=BG)
        self.queue = queue.Queue()
        self.result = None
        self.all_rows = []
        self.scanning = False
        self.ports_var = tk.BooleanVar(value=True)
        self.sub_var = tk.BooleanVar(value=True)
        self.caps = profiles.get_profile("Standard")
        self.setup_style()
        self.build_menu()
        self.build_header()
        self.build_input()
        self.build_progress()
        self.build_main()
        self.build_status()
        self.poll_queue()

    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export JSON", command=self.export_json)
        file_menu.add_command(label="Export CSV", command=self.export_csv)
        file_menu.add_command(label="Export TXT", command=self.export_txt)
        file_menu.add_command(label="Export HTML", command=self.export_html)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Start Scan", command=self.start_scan)
        scan_menu.add_command(label="Compare with Previous", command=self.compare_scan)
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="WHOIS Lookup", command=self.open_whois_lookup)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        menubar.add_cascade(label="Help", menu=help_menu)
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

    def build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=16, pady=(14, 4))
        title = tk.Label(header, text=APP_TITLE, font=("Segoe UI", 22, "bold"), bg=BG, fg=TEXT)
        title.pack(side="left")
        subtitle = tk.Label(header, text="  " + APP_SUBTITLE, font=("Segoe UI", 11), bg=BG, fg=MUTED)
        subtitle.pack(side="left", pady=(8, 0))
        about = ttk.Button(header, text="About", command=self.show_about)
        about.pack(side="right")
        version = ttk.Label(header, text="v" + __version__, style="Muted.TLabel")
        version.pack(side="right", padx=(0, 10), pady=(6, 0))

    def build_input(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=16, pady=8)
        prompt = ttk.Label(bar, text="Target:")
        prompt.pack(side="left")
        self.target_entry = ttk.Entry(bar, width=44, font=("Segoe UI", 11))
        self.target_entry.pack(side="left", padx=(8, 8))
        self.target_entry.bind("<Return>", lambda event: self.start_scan())
        self.scan_button = ttk.Button(bar, text="Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="left")
        clear = ttk.Button(bar, text="Clear", command=self.clear_all)
        clear.pack(side="left", padx=(6, 0))
        compare = ttk.Button(bar, text="Compare", command=self.compare_scan)
        compare.pack(side="left", padx=(6, 0))
        ports = ttk.Checkbutton(bar, text="Ports", variable=self.ports_var)
        ports.pack(side="left", padx=(14, 0))
        subs = ttk.Checkbutton(bar, text="Subdomains", variable=self.sub_var)
        subs.pack(side="left", padx=(8, 0))
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
        self.status_label = ttk.Label(bottom, text="Ready. Enter a domain or URL and press Scan.", style="Muted.TLabel")
        self.status_label.pack(side="left")
        self.count_label = ttk.Label(bottom, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

    def build_main(self):
        filter_bar = ttk.Frame(self.root)
        filter_bar.pack(fill="x", padx=16, pady=(0, 6))
        search_label = ttk.Label(filter_bar, text="Search:")
        search_label.pack(side="left")
        self.search_entry = ttk.Entry(filter_bar, width=36)
        self.search_entry.pack(side="left", padx=(8, 12))
        self.search_entry.bind("<KeyRelease>", lambda event: self.apply_filter())
        section_label = ttk.Label(filter_bar, text="Section:")
        section_label.pack(side="left")
        self.section_box = ttk.Combobox(filter_bar, values=["All sections"], state="readonly", width=24)
        self.section_box.pack(side="left", padx=(8, 0))
        self.section_box.set("All sections")
        self.section_box.bind("<<ComboboxSelected>>", lambda event: self.apply_filter())
        profile_label = ttk.Label(filter_bar, text="Profile:")
        profile_label.pack(side="left", padx=(16, 0))
        self.profile_box = ttk.Combobox(filter_bar, values=profiles.profile_names(), state="readonly", width=12)
        self.profile_box.pack(side="left", padx=(8, 0))
        self.profile_box.set("Standard")
        self.profile_box.bind("<<ComboboxSelected>>", lambda event: self.on_profile())
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self.tree = ttk.Treeview(main, columns=("item", "value"))
        self.tree.heading("#0", text="Section", anchor="w")
        self.tree.heading("item", text="Item", anchor="w")
        self.tree.heading("value", text="Value", anchor="w")
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
        self.menu.add_command(label="Copy value", command=self.copy_value)
        self.tree.bind("<Button-3>", self.show_menu)
        detail_frame = ttk.Frame(self.root)
        detail_frame.pack(fill="x", padx=16, pady=(0, 8))
        detail_label = ttk.Label(detail_frame, text="Details (double-click a row to copy its value):", style="Muted.TLabel")
        detail_label.pack(anchor="w", pady=(0, 4))
        self.detail = tk.Text(detail_frame, height=5, wrap="word", bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT, relief="flat", font=("TkFixedFont", 10))
        self.detail.pack(fill="x")
        self.detail.insert("1.0", "Select any row to see the full value here.")
        self.detail.configure(state="disabled")

    def build_status(self):
        self.bottom = ttk.Label(self.root, text="DomainScan collects only publicly available data. Only scan domains you own or are allowed to test.", style="Muted.TLabel")
        self.bottom.pack(fill="x", padx=16, pady=(0, 10))

    def on_profile(self):
        self.caps = profiles.get_profile(self.profile_box.get())
        self.ports_var.set(self.caps["include_ports"])
        self.sub_var.set(self.caps["include_subdomains"])

    def start_scan(self):
        if self.scanning:
            return
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Enter a domain or URL first (example: example.com).")
            return
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.result = None
        self.all_rows = []
        for child in self.tree.get_children():
            self.tree.delete(child)
        self.section_box.configure(values=["All sections"])
        self.section_box.set("All sections")
        self.progress.configure(value=0)
        self.count_label.configure(text="")
        self.set_detail("Scanning " + target + ", please wait...")
        thread = threading.Thread(target=self.worker, args=(target,), daemon=True)
        thread.start()

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
                    self.fail_scan("Invalid target: " + message[1])
                elif kind == "error":
                    self.fail_scan("Scan failed: " + message[1])
        except queue.Empty:
            pass
        self.root.after(120, self.poll_queue)

    def finish_scan(self, result):
        self.scanning = False
        self.scan_button.configure(state="normal")
        self.result = result
        self.progress.configure(value=100)
        meta = result["meta"]
        self.status_label.configure(text="Scan complete in " + str(meta["duration_seconds"]) + " seconds.")
        self.count_label.configure(text=str(meta["findings"]) + " findings")
        self.all_rows = []
        for section, items in result["sections"].items():
            for key, value in items:
                self.all_rows.append((section, key, value))
        sections = ["All sections"] + list(result["sections"].keys())
        self.section_box.configure(values=sections)
        self.apply_filter()
        self.set_detail("Scan of " + result["target"]["host"] + " finished with " + str(meta["findings"]) + " findings.")
        try:
            history_store.save_run(result)
        except Exception:
            pass

    def fail_scan(self, text):
        self.scanning = False
        self.scan_button.configure(state="normal")
        self.status_label.configure(text=text)
        messagebox.showerror("DomainScan", text)

    def apply_filter(self):
        query = self.search_entry.get().strip().lower()
        section = self.section_box.get()
        for child in self.tree.get_children():
            self.tree.delete(child)
        grouped = {}
        for sec, key, value in self.all_rows:
            if section != "All sections" and sec != section:
                continue
            if query and query not in key.lower() and query not in value.lower() and query not in sec.lower():
                continue
            if sec not in grouped:
                grouped[sec] = []
            grouped[sec].append((key, value))
        stripe = 0
        for sec, items in grouped.items():
            parent = self.tree.insert("", "end", text=sec, values=("", str(len(items)) + " items"), open=True)
            for key, value in items:
                if stripe % 2:
                    tags = ("odd",)
                else:
                    tags = ()
                self.tree.insert(parent, "end", text="", values=(key, helpers.short(value, 220)), tags=tags)
                stripe += 1
        if self.result and (query or section != "All sections"):
            shown = 0
            for items in grouped.values():
                shown += len(items)
            self.count_label.configure(text=str(shown) + " of " + str(len(self.all_rows)) + " findings")
        elif self.result:
            self.count_label.configure(text=str(len(self.all_rows)) + " findings")

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
            section = self.tree.item(parent, "text")
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
        self.set_detail(section + " / " + key + "\n\n" + value)

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
        self.status_label.configure(text="Copied: " + row[1])

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
        self.section_box.configure(values=["All sections"])
        self.section_box.set("All sections")
        self.progress.configure(value=0)
        self.status_label.configure(text="Ready. Enter a domain or URL and press Scan.")
        self.count_label.configure(text="")
        self.set_detail("Select any row to see the full value here.")

    def need_result(self):
        if not self.result:
            messagebox.showinfo("Nothing to export", "Run a scan first, then export the report.")
            return False
        return True

    def export_json(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON report", "*.json")])
        if not path:
            return
        try:
            helpers.export_json(path, self.result)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", "JSON report saved.")

    def export_csv(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV report", "*.csv")])
        if not path:
            return
        try:
            helpers.export_csv(path, self.result)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", "CSV report saved.")

    def export_txt(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text report", "*.txt")])
        if not path:
            return
        try:
            helpers.export_txt(path, self.result)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", "Text report saved.")

    def compare_scan(self):
        if not self.result or self.scanning:
            messagebox.showinfo("Nothing to compare", "Run a scan first, then compare it with a previous one.")
            return
        host = self.result["target"]["host"]
        try:
            previous = history_store.previous_run(host, self.result["meta"]["scanned_at"])
        except Exception:
            previous = None
        if not previous:
            messagebox.showinfo("No previous scans", "No earlier scan found for " + host + ".")
            return
        changes = history_store.diff_runs(previous, self.result)
        merged = {"Changes": changes}
        for section, items in self.result["sections"].items():
            merged[section] = items
        self.result["sections"] = merged
        self.all_rows = []
        for section, items in merged.items():
            for key, value in items:
                self.all_rows.append((section, key, value))
        sections = ["All sections"] + list(merged.keys())
        self.section_box.configure(values=sections)
        self.section_box.set("Changes")
        self.apply_filter()
        self.set_detail("Compared with scan from " + str(previous["meta"].get("scanned_at", "earlier")) + ". " + str(len(changes)) + " change rows.")

    def open_whois_lookup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("WHOIS Lookup")
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
            output.insert(tk.END, "Looking up " + raw + "...\n")
            try:
                resolved = whois_check.resolve_whois_target(raw)
            except Exception as exc:
                output.insert(tk.END, "Invalid target (" + exc.__class__.__name__ + ")\n")
                return
            if resolved["note"]:
                output.insert(tk.END, resolved["note"] + "\n")

            def worker():
                try:
                    result = whois_check.collect(resolved["query"], resolved["query"])
                    lines = [key + ": " + value for key, value in result["rows"]]
                except Exception as exc:
                    lines = ["Lookup failed (" + exc.__class__.__name__ + ")"]
                dialog.after(0, lambda: show_lines(lines))

            def show_lines(lines):
                output.delete("1.0", tk.END)
                for line in lines:
                    output.insert(tk.END, line + "\n")
                self.set_detail("WHOIS lookup finished for " + raw + ".")

            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(top, text="Look Up", command=run_query).pack(side=tk.LEFT)
        entry.bind("<Return>", lambda event: run_query())

    def export_html(self):
        if not self.need_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML report", "*.html")])
        if not path:
            return
        try:
            helpers.export_html(path, self.result)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", "HTML report saved.")

    def show_about(self):
        lines = [
            "DomainScan " + __version__,
            "Legal website and domain intelligence.",
            "",
            "Collects only publicly available data:",
            "DNS, subdomains, WHOIS/RDAP, IP geolocation,",
            "BGP, blocklists, HTTP headers, TLS certificates,",
            "mail authentication, page content, technology",
            "markers, web archive history and port reachability.",
            "",
            "Only scan domains you own or are allowed to test.",
        ]
        messagebox.showinfo("About DomainScan", "\n".join(lines))


def main():
    root = tk.Tk()
    DomainScanApp(root)
    root.mainloop()
