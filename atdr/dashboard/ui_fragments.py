from html import escape

SOC_COLORS = {
    "bg": "#070b10",
    "panel": "#0f151d",
    "panel_2": "#151d27",
    "border": "#263445",
    "text": "#e5edf6",
    "muted": "#93a4b7",
    "cyan": "#22d3ee",
    "teal": "#14b8a6",
    "amber": "#f59e0b",
    "red": "#ef4444",
    "green": "#22c55e",
    "blue": "#38bdf8",
    "gray": "#94a3b8",
}

SEVERITY_COLORS = {
    "Low": SOC_COLORS["green"],
    "Medium": SOC_COLORS["amber"],
    "High": "#f97316",
    "Critical": SOC_COLORS["red"],
}

STATUS_COLORS = {
    "open": SOC_COLORS["red"],
    "investigating": SOC_COLORS["amber"],
    "contained": SOC_COLORS["blue"],
    "resolved": SOC_COLORS["green"],
    "false_positive": SOC_COLORS["gray"],
    "reviewed": SOC_COLORS["green"],
    "pending": SOC_COLORS["amber"],
    "needs_changes": SOC_COLORS["red"],
    "active": SOC_COLORS["green"],
    "disabled": SOC_COLORS["gray"],
    "overdue": SOC_COLORS["red"],
    "needs_owner": SOC_COLORS["amber"],
    "due_soon": SOC_COLORS["amber"],
    "on_track": SOC_COLORS["green"],
    "closed": SOC_COLORS["gray"],
}


def safe_text(value) -> str:
    if value is None or value == "":
        return "-"
    return escape(str(value))


def command_panel_html(items: list[dict]) -> str:
    html_items: list[str] = []
    for item in items:
        html_items.append(
            '<div class="atdr-command-item">'
            f'<div class="label">{safe_text(item.get("label"))}</div>'
            f'<div class="value" style="color:{safe_text(item.get("color", "#e5edf6"))};">{safe_text(item.get("value"))}</div>'
            f'<div class="detail">{safe_text(item.get("detail", ""))}</div>'
            "</div>"
        )
    return '<div class="atdr-command-panel"><div class="atdr-command-grid">' + "".join(html_items) + "</div></div>"


def page_hero_html(title: str, subtitle: str, *, eyebrow: str = "SOC Command Center", badges: list[str] | None = None) -> str:
    badge_markup = "".join(badge_html(badge) for badge in (badges or []))
    return (
        '<div class="atdr-page-hero">'
        f'<div class="atdr-hero-eyebrow">{safe_text(eyebrow)}</div>'
        f'<div class="atdr-hero-title">{safe_text(title)}</div>'
        f'<div class="atdr-hero-subtitle">{safe_text(subtitle)}</div>'
        f'<div class="atdr-hero-badges">{badge_markup}</div>'
        "</div>"
    )


def badge_html(label: str, *, color: str | None = None) -> str:
    badge_color = color or STATUS_COLORS.get(label, SOC_COLORS["gray"])
    return f'<span class="atdr-inline-badge" style="--badge-color:{safe_text(badge_color)};">{safe_text(label)}</span>'


def status_badge_html(status: str | None) -> str:
    normalized = (status or "unknown").strip().lower()
    label = normalized.replace("_", " ").title()
    return badge_html(label, color=STATUS_COLORS.get(normalized, SOC_COLORS["gray"]))


def severity_badge_html(severity: str | None) -> str:
    label = severity or "Unknown"
    return badge_html(label, color=SEVERITY_COLORS.get(label, SOC_COLORS["gray"]))


def mission_path_html(items: list[dict]) -> str:
    nodes = []
    for index, item in enumerate(items, start=1):
        nodes.append(
            '<div class="atdr-mission-step">'
            f'<div class="step-index">{index}</div>'
            f'<div class="step-body"><div class="step-label">{safe_text(item.get("label"))}</div>'
            f'<div class="step-proof">{safe_text(item.get("proof"))}</div>'
            f'<div class="step-detail">{safe_text(item.get("detail"))}</div></div>'
            "</div>"
        )
    return '<div class="atdr-mission-path">' + "".join(nodes) + "</div>"


def evidence_card_html(title: str, body: str, *, eyebrow: str = "Evidence", color: str = "#22d3ee") -> str:
    return (
        f'<div class="atdr-evidence-card" style="--accent:{safe_text(color)};">'
        f'<div class="eyebrow">{safe_text(eyebrow)}</div>'
        f'<div class="title">{safe_text(title)}</div>'
        f'<div class="body">{safe_text(body)}</div>'
        "</div>"
    )


def empty_state_html(title: str, body: str, *, tone: str = "#38bdf8") -> str:
    return (
        f'<div class="atdr-empty-state" style="--accent:{safe_text(tone)};">'
        f'<div class="title">{safe_text(title)}</div>'
        f'<div class="body">{safe_text(body)}</div>'
        "</div>"
    )


def result_card_html(title: str, body: str, *, status: str = "Completed", color: str = "#22c55e") -> str:
    return (
        f'<div class="atdr-result-card" style="--accent:{safe_text(color)};">'
        f'<div class="status">{safe_text(status)}</div>'
        f'<div class="title">{safe_text(title)}</div>'
        f'<div class="body">{safe_text(body)}</div>'
        "</div>"
    )


def timeline_row_html(
    event_time: str | None,
    title: str,
    body: str,
    *,
    actor: str | None = None,
    color: str = "#22d3ee",
) -> str:
    actor_label = f'<span class="actor">{safe_text(actor)}</span>' if actor else ""
    return (
        f'<div class="atdr-timeline-row" style="--accent:{safe_text(color)};">'
        '<div class="rail"></div>'
        '<div class="content">'
        f'<div class="meta"><span>{safe_text(event_time)}</span>{actor_label}</div>'
        f'<div class="title">{safe_text(title)}</div>'
        f'<div class="body">{safe_text(body)}</div>'
        "</div>"
        "</div>"
    )


def key_value_grid_html(items: list[dict]) -> str:
    cells = []
    for item in items:
        cells.append(
            '<div class="atdr-kv-cell">'
            f'<div class="key">{safe_text(item.get("label"))}</div>'
            f'<div class="value">{safe_text(item.get("value"))}</div>'
            "</div>"
        )
    return '<div class="atdr-kv-grid">' + "".join(cells) + "</div>"


def readiness_grid_html(items: list[dict]) -> str:
    cells = []
    for item in items:
        ok = bool(item.get("ok"))
        color = SOC_COLORS["green"] if ok else SOC_COLORS["amber"]
        state = item.get("state") or ("Ready" if ok else "Needs Attention")
        cells.append(
            f'<div class="atdr-readiness-cell" style="--accent:{safe_text(color)};">'
            f'<div class="state">{safe_text(state)}</div>'
            f'<div class="label">{safe_text(item.get("label"))}</div>'
            f'<div class="detail">{safe_text(item.get("detail"))}</div>'
            "</div>"
        )
    return '<div class="atdr-readiness-grid">' + "".join(cells) + "</div>"


def presentation_mode_default() -> bool:
    return True


def ranked_list_html(rows: list[dict], *, tone: str = "#14b8a6", limit: int = 8) -> str:
    cleaned = sorted(rows, key=lambda item: item.get("count", 0), reverse=True)[:limit]
    max_count = max((item.get("count", 0) for item in cleaned), default=1) or 1
    html_rows = []
    for item in cleaned:
        count = int(item.get("count", 0))
        pct = max(3, round((count / max_count) * 100))
        html_rows.append(
            '<div class="atdr-rank-row">'
            '<div class="atdr-rank-meta">'
            f'<span>{safe_text(item.get("name", "-"))}</span>'
            f"<span>{count}</span>"
            "</div>"
            f'<div class="atdr-rank-track"><div class="atdr-rank-fill" style="width:{pct}%; background:{safe_text(tone)};"></div></div>'
            "</div>"
        )
    return "".join(html_rows)


def plotly_theme() -> dict:
    return {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"color": SOC_COLORS["text"], "family": "Inter, Segoe UI, Arial, sans-serif"},
        "colorway": [
            SOC_COLORS["cyan"],
            SOC_COLORS["amber"],
            SOC_COLORS["red"],
            SOC_COLORS["teal"],
            SOC_COLORS["blue"],
            SOC_COLORS["green"],
            SOC_COLORS["gray"],
        ],
        "margin": {"l": 8, "r": 8, "t": 34, "b": 8},
        "legend": {"orientation": "h", "y": -0.18},
    }
