import os
import json
import sys
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from atdr.dashboard.ui_fragments import (
    SEVERITY_COLORS,
    SOC_COLORS,
    STATUS_COLORS,
    badge_html,
    command_panel_html,
    empty_state_html,
    evidence_card_html,
    key_value_grid_html,
    mission_path_html,
    page_hero_html,
    plotly_theme,
    presentation_mode_default,
    ranked_list_html,
    readiness_grid_html,
    result_card_html,
    severity_badge_html,
    status_badge_html,
    timeline_row_html,
)


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").strip().rstrip("/")

st.set_page_config(page_title="MFU ATDR", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --atdr-bg: #070b10;
        --atdr-panel: #0f151d;
        --atdr-panel-2: #151d27;
        --atdr-panel-3: #0b1118;
        --atdr-border: rgba(148, 163, 184, 0.22);
        --atdr-muted: #93a4b7;
        --atdr-text: #e5edf6;
        --atdr-teal: #14b8a6;
        --atdr-cyan: #22d3ee;
        --atdr-red: #ef4444;
        --atdr-amber: #f59e0b;
        --atdr-blue: #38bdf8;
        --atdr-green: #22c55e;
    }
    .stApp {
        background:
            linear-gradient(180deg, rgba(12, 18, 26, 0.98) 0%, var(--atdr-bg) 34%),
            var(--atdr-bg);
    }
    .block-container { padding-top: 1rem; max-width: 1580px; }
    #MainMenu, footer { visibility: hidden; }
    [data-testid="stSidebar"] {
        background: #0b1118;
        border-right: 1px solid var(--atdr-border);
    }
    [data-testid="stSidebar"] [role="radiogroup"] label {
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 8px;
        padding: 0.32rem 0.45rem;
        margin: 0.18rem 0;
        background: rgba(15, 21, 29, 0.48);
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {
        border-color: rgba(34, 211, 238, 0.34);
        background: rgba(34, 211, 238, 0.06);
    }
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: var(--atdr-text);
    }
    .atdr-header {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: linear-gradient(180deg, rgba(21, 29, 39, 0.96), rgba(11, 17, 24, 0.98));
        padding: 1rem 1.15rem;
        margin-bottom: 0.95rem;
        box-shadow: 0 18px 40px rgba(0, 0, 0, 0.28);
        border-top: 2px solid rgba(34, 211, 238, 0.36);
    }
    .atdr-page-hero {
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 8px;
        background:
            linear-gradient(135deg, rgba(20, 184, 166, 0.13), rgba(239, 68, 68, 0.06) 48%, rgba(15, 21, 29, 0.96)),
            #0c131b;
        padding: 1.05rem 1.15rem;
        margin: 0.3rem 0 1rem 0;
        box-shadow: 0 18px 42px rgba(0, 0, 0, 0.26);
        position: relative;
        overflow: hidden;
    }
    .atdr-page-hero:before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, var(--atdr-cyan), var(--atdr-amber), var(--atdr-red));
    }
    .atdr-hero-eyebrow {
        color: var(--atdr-cyan);
        font-size: 0.72rem;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 0.065rem;
    }
    .atdr-hero-title {
        color: var(--atdr-text);
        font-size: 1.55rem;
        font-weight: 900;
        line-height: 1.16;
        margin-top: 0.25rem;
    }
    .atdr-hero-subtitle {
        color: var(--atdr-muted);
        max-width: 920px;
        font-size: 0.92rem;
        line-height: 1.45;
        margin-top: 0.32rem;
    }
    .atdr-hero-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 0.45rem;
        margin-top: 0.72rem;
    }
    .atdr-header-top {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: flex-start;
        flex-wrap: wrap;
    }
    .atdr-title {
        color: var(--atdr-text);
        font-size: 1.85rem;
        font-weight: 800;
        line-height: 1.15;
        margin: 0 0 0.35rem 0;
    }
    .atdr-subtitle {
        color: var(--atdr-muted);
        font-size: 0.95rem;
        margin: 0;
    }
    .atdr-chip-row {
        display: flex;
        gap: 0.45rem;
        justify-content: flex-end;
        flex-wrap: wrap;
    }
    .atdr-chip {
        border: 1px solid var(--atdr-border);
        border-radius: 999px;
        color: var(--atdr-text);
        background: #0a1017;
        padding: 0.28rem 0.62rem;
        font-size: 0.78rem;
        font-weight: 700;
        white-space: nowrap;
    }
    .atdr-sidebar-brand {
        border-bottom: 1px solid var(--atdr-border);
        padding: 0.6rem 0 1rem 0;
        margin-bottom: 1rem;
    }
    .atdr-sidebar-brand .name {
        color: var(--atdr-text);
        font-weight: 850;
        font-size: 1rem;
    }
    .atdr-sidebar-brand .desc {
        color: var(--atdr-muted);
        font-size: 0.78rem;
        margin-top: 0.15rem;
    }
    .atdr-card {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: var(--atdr-panel);
        padding: 0.85rem 0.95rem;
        min-height: 106px;
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.22);
        transition: border-color 160ms ease, transform 160ms ease;
    }
    .atdr-card:hover {
        border-color: rgba(20, 184, 166, 0.45);
        transform: translateY(-1px);
    }
    .atdr-card-label {
        color: var(--atdr-muted);
        font-size: 0.72rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.03rem;
        margin-bottom: 0.45rem;
    }
    .atdr-card-value {
        color: var(--atdr-text);
        font-size: 1.62rem;
        font-weight: 850;
        line-height: 1.1;
    }
    .atdr-card-detail {
        color: var(--atdr-muted);
        font-size: 0.82rem;
        margin-top: 0.45rem;
    }
    .atdr-card.teal { border-left: 4px solid var(--atdr-teal); }
    .atdr-card.red { border-left: 4px solid var(--atdr-red); }
    .atdr-card.amber { border-left: 4px solid var(--atdr-amber); }
    .atdr-card.blue { border-left: 4px solid var(--atdr-blue); }
    .atdr-card.green { border-left: 4px solid var(--atdr-green); }
    .atdr-card.gray { border-left: 4px solid #94a3b8; }
    .atdr-command-panel {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: linear-gradient(180deg, #0c131b, #090f16);
        padding: 1rem;
        margin-bottom: 1rem;
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 18px 36px rgba(0,0,0,0.22);
    }
    .atdr-command-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 0.75rem;
    }
    .atdr-command-item {
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        background: #101822;
        padding: 0.85rem 0.95rem;
        position: relative;
        overflow: hidden;
    }
    .atdr-command-item:before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: rgba(34, 211, 238, 0.5);
    }
    .atdr-command-item .label {
        color: var(--atdr-muted);
        font-size: 0.74rem;
        font-weight: 800;
        text-transform: uppercase;
    }
    .atdr-command-item .value {
        color: var(--atdr-text);
        font-size: 1.45rem;
        font-weight: 850;
        margin-top: 0.25rem;
    }
    .atdr-command-item .detail {
        color: var(--atdr-muted);
        font-size: 0.8rem;
        margin-top: 0.25rem;
    }
    .atdr-rank-row {
        margin: 0.42rem 0;
    }
    .atdr-rank-meta {
        display: flex;
        justify-content: space-between;
        gap: 0.75rem;
        color: var(--atdr-text);
        font-size: 0.84rem;
        font-weight: 700;
    }
    .atdr-rank-track {
        height: 0.48rem;
        border-radius: 999px;
        background: rgba(148, 163, 184, 0.15);
        overflow: hidden;
        margin-top: 0.24rem;
    }
    .atdr-rank-fill {
        height: 100%;
        border-radius: 999px;
        background: var(--atdr-teal);
    }
    .atdr-mini-note {
        border-left: 3px solid var(--atdr-blue);
        background: rgba(56, 189, 248, 0.08);
        padding: 0.7rem 0.85rem;
        border-radius: 6px;
        color: var(--atdr-text);
        font-size: 0.9rem;
        margin: 0.55rem 0;
    }
    .atdr-alert-strip {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: var(--atdr-panel);
        padding: 0.9rem 1rem;
        margin: 0.75rem 0;
    }
    .atdr-panel-title {
        color: var(--atdr-text);
        font-size: 0.98rem;
        font-weight: 800;
        margin: 0.25rem 0 0.65rem 0;
        text-transform: uppercase;
        letter-spacing: 0.035rem;
    }
    .atdr-badge {
        display: inline-block;
        padding: 0.2rem 0.55rem;
        border-radius: 0.35rem;
        color: white;
        font-size: 0.82rem;
        font-weight: 800;
    }
    .atdr-inline-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid color-mix(in srgb, var(--badge-color) 62%, transparent);
        background: color-mix(in srgb, var(--badge-color) 17%, transparent);
        color: #f8fafc;
        padding: 0.18rem 0.52rem;
        border-radius: 999px;
        font-size: 0.74rem;
        font-weight: 850;
        text-transform: uppercase;
        letter-spacing: 0.025rem;
        white-space: nowrap;
    }
    .atdr-section-panel {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: rgba(15, 21, 29, 0.82);
        padding: 0.95rem;
        margin-bottom: 0.9rem;
    }
    .atdr-chart-panel {
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        background: #0d141d;
        padding: 0.25rem 0.45rem 0.1rem 0.45rem;
        min-height: 260px;
    }
    .atdr-mission-path {
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
        gap: 0.65rem;
        margin: 0.65rem 0 0.95rem 0;
    }
    .atdr-mission-step {
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 8px;
        background: #101822;
        padding: 0.75rem;
        min-height: 122px;
    }
    .atdr-mission-step .step-index {
        width: 1.55rem;
        height: 1.55rem;
        border-radius: 999px;
        background: rgba(34, 211, 238, 0.14);
        border: 1px solid rgba(34, 211, 238, 0.36);
        color: var(--atdr-cyan);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.78rem;
        font-weight: 900;
        margin-bottom: 0.5rem;
    }
    .atdr-mission-step .step-label {
        color: var(--atdr-text);
        font-weight: 850;
        font-size: 0.9rem;
    }
    .atdr-mission-step .step-proof {
        color: var(--atdr-cyan);
        font-size: 0.82rem;
        font-weight: 800;
        margin-top: 0.25rem;
    }
    .atdr-mission-step .step-detail {
        color: var(--atdr-muted);
        font-size: 0.76rem;
        margin-top: 0.25rem;
        line-height: 1.35;
    }
    .atdr-evidence-card {
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-left: 3px solid var(--accent);
        border-radius: 8px;
        background: #101822;
        padding: 0.82rem 0.9rem;
        margin-bottom: 0.65rem;
    }
    .atdr-evidence-card .eyebrow {
        color: var(--atdr-muted);
        font-size: 0.68rem;
        font-weight: 850;
        text-transform: uppercase;
        letter-spacing: 0.04rem;
    }
    .atdr-evidence-card .title {
        color: var(--atdr-text);
        font-size: 0.98rem;
        font-weight: 850;
        margin-top: 0.2rem;
    }
    .atdr-evidence-card .body {
        color: var(--atdr-muted);
        font-size: 0.8rem;
        line-height: 1.4;
        margin-top: 0.25rem;
    }
    .atdr-empty-state {
        border: 1px dashed color-mix(in srgb, var(--accent) 48%, var(--atdr-border));
        border-radius: 8px;
        background: color-mix(in srgb, var(--accent) 8%, #0d141d);
        padding: 1rem;
        margin: 0.65rem 0;
    }
    .atdr-empty-state .title {
        color: var(--atdr-text);
        font-weight: 850;
        font-size: 0.96rem;
    }
    .atdr-empty-state .body {
        color: var(--atdr-muted);
        font-size: 0.82rem;
        line-height: 1.42;
        margin-top: 0.28rem;
    }
    .atdr-result-card {
        border: 1px solid color-mix(in srgb, var(--accent) 42%, var(--atdr-border));
        border-left: 4px solid var(--accent);
        border-radius: 8px;
        background: color-mix(in srgb, var(--accent) 8%, #101822);
        padding: 0.85rem 0.95rem;
        margin: 0.65rem 0;
    }
    .atdr-result-card .status {
        color: var(--accent);
        font-size: 0.68rem;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 0.05rem;
    }
    .atdr-result-card .title {
        color: var(--atdr-text);
        font-size: 1rem;
        font-weight: 850;
        margin-top: 0.18rem;
    }
    .atdr-result-card .body {
        color: var(--atdr-muted);
        font-size: 0.82rem;
        line-height: 1.42;
        margin-top: 0.25rem;
    }
    .atdr-timeline-row {
        display: grid;
        grid-template-columns: 18px minmax(0, 1fr);
        gap: 0.65rem;
        margin: 0.45rem 0;
    }
    .atdr-timeline-row .rail {
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background: var(--accent);
        box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 20%, transparent);
        margin-top: 0.42rem;
        justify-self: center;
    }
    .atdr-timeline-row .content {
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        background: #101822;
        padding: 0.72rem 0.85rem;
    }
    .atdr-timeline-row .meta {
        display: flex;
        justify-content: space-between;
        gap: 0.8rem;
        color: var(--atdr-muted);
        font-size: 0.7rem;
        font-weight: 800;
        text-transform: uppercase;
    }
    .atdr-timeline-row .actor {
        color: var(--atdr-cyan);
    }
    .atdr-timeline-row .title {
        color: var(--atdr-text);
        font-weight: 850;
        margin-top: 0.22rem;
    }
    .atdr-timeline-row .body {
        color: var(--atdr-muted);
        font-size: 0.8rem;
        line-height: 1.38;
        margin-top: 0.18rem;
    }
    .atdr-kv-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 0.55rem;
        margin: 0.45rem 0 0.75rem 0;
    }
    .atdr-kv-cell {
        border: 1px solid rgba(148, 163, 184, 0.17);
        border-radius: 8px;
        background: #0d141d;
        padding: 0.62rem 0.72rem;
        min-height: 74px;
    }
    .atdr-kv-cell .key {
        color: var(--atdr-muted);
        font-size: 0.68rem;
        font-weight: 850;
        text-transform: uppercase;
        letter-spacing: 0.04rem;
    }
    .atdr-kv-cell .value {
        color: var(--atdr-text);
        font-size: 0.92rem;
        font-weight: 800;
        margin-top: 0.22rem;
        overflow-wrap: anywhere;
    }
    .atdr-readiness-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 0.65rem;
        margin: 0.65rem 0 1rem 0;
    }
    .atdr-readiness-cell {
        border: 1px solid color-mix(in srgb, var(--accent) 34%, var(--atdr-border));
        border-radius: 8px;
        background: color-mix(in srgb, var(--accent) 7%, #101822);
        padding: 0.72rem 0.82rem;
        min-height: 92px;
    }
    .atdr-readiness-cell .state {
        color: var(--accent);
        font-size: 0.68rem;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 0.05rem;
    }
    .atdr-readiness-cell .label {
        color: var(--atdr-text);
        font-size: 0.95rem;
        font-weight: 850;
        margin-top: 0.2rem;
    }
    .atdr-readiness-cell .detail {
        color: var(--atdr-muted);
        font-size: 0.78rem;
        line-height: 1.36;
        margin-top: 0.22rem;
    }
    .atdr-code-caption {
        color: var(--atdr-muted);
        font-size: 0.76rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.04rem;
        margin: 0.25rem 0 0.35rem 0;
    }
    div[data-testid="stTabs"] button {
        border-radius: 6px 6px 0 0;
        font-weight: 750;
    }
    div[data-testid="stTabs"] button p {
        font-size: 0.86rem;
        font-weight: 800;
    }
    div[data-testid="stForm"] {
        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 8px;
        background: rgba(13, 20, 29, 0.72);
        padding: 0.9rem;
    }
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stNumberInput"] input,
    div[data-baseweb="select"] > div {
        border-radius: 6px;
        border-color: rgba(148, 163, 184, 0.25);
        background-color: #0b1118;
    }
    div[data-testid="stDataFrame"] div[role="columnheader"] {
        background: #131c27;
        color: var(--atdr-text);
    }
    .atdr-login {
        border: 1px solid var(--atdr-border);
        border-radius: 8px;
        background: var(--atdr-panel);
        padding: 1.1rem 1.2rem;
        margin-bottom: 1rem;
    }
    div[data-testid="stMetric"] {
        border: 1px solid rgba(148, 163, 184, 0.22);
        border-radius: 8px;
        padding: 0.85rem 1rem;
        background: var(--atdr-panel);
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        background: #0d141d;
    }
    .section-label {
        color: #94a3b8;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.03rem;
        text-transform: uppercase;
        margin-bottom: 0.3rem;
    }
    button[kind="primary"], div[data-testid="stFormSubmitButton"] button {
        border-radius: 6px;
    }
    @media (max-width: 900px) {
        .atdr-command-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .atdr-mission-path { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .atdr-kv-grid { grid-template-columns: repeat(1, minmax(0, 1fr)); }
        .atdr-readiness-grid { grid-template-columns: repeat(1, minmax(0, 1fr)); }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def auth_headers() -> dict[str, str]:
    token = st.session_state.get("access_token")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def api_get(path: str, **params):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        params={k: v for k, v in params.items() if v not in (None, "")},
        headers=auth_headers(),
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def api_post(path: str, json=None, data=None):
    response = requests.post(f"{API_BASE_URL}{path}", json=json, data=data, headers=auth_headers(), timeout=60)
    response.raise_for_status()
    return response.json()


def api_get_response(path: str, **params):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        params={k: v for k, v in params.items() if v not in (None, "")},
        headers=auth_headers(),
        timeout=30,
    )
    response.raise_for_status()
    return response


def api_error_message(exc: requests.RequestException) -> str:
    response = getattr(exc, "response", None)
    if response is None:
        return str(exc)
    request_id = response.headers.get("X-Request-ID")
    detail = response.text
    try:
        payload = response.json()
        detail = payload.get("detail", detail)
        request_id = payload.get("request_id") or request_id
    except ValueError:
        pass
    if isinstance(detail, list):
        detail = "Validation error. Check the submitted fields."
    if request_id:
        return f"{response.status_code}: {detail} (request id: {request_id})"
    return f"{response.status_code}: {detail}"


def show_api_error(title: str, exc: requests.RequestException) -> None:
    st.error(f"{title}: {api_error_message(exc)}")


def as_frame(rows) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def safe_text(value) -> str:
    if value is None or value == "":
        return "-"
    return escape(str(value))


def app_header(page_name: str, user: dict, health_status: str) -> None:
    role = user.get("role", "unknown")
    username = user.get("username", "unknown")
    st.markdown(
        f"""
        <div class="atdr-header">
            <div class="atdr-header-top">
                <div>
                    <div class="atdr-title">MFU AI-Driven Threat Detection and Response</div>
                    <p class="atdr-subtitle">Security operations dashboard for Palo Alto firewall log monitoring.</p>
                </div>
                <div class="atdr-chip-row">
                    <span class="atdr-chip">API {safe_text(health_status)}</span>
                    <span class="atdr-chip">{safe_text(username)}</span>
                    <span class="atdr-chip">{safe_text(role)}</span>
                    <span class="atdr-chip">{safe_text(page_name)}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def sidebar_brand(health_status: str) -> None:
    st.sidebar.markdown(
        f"""
        <div class="atdr-sidebar-brand">
            <div class="name">MFU ATDR</div>
            <div class="desc">SOC prototype command center</div>
            <div class="desc">API status: {safe_text(health_status)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value, detail: str = "", tone: str = "teal") -> None:
    st.markdown(
        f"""
        <div class="atdr-card {safe_text(tone)}">
            <div class="atdr-card-label">{safe_text(label)}</div>
            <div class="atdr-card-value">{safe_text(value)}</div>
            <div class="atdr-card-detail">{safe_text(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def command_panel(items: list[dict]) -> None:
    st.markdown(command_panel_html(items), unsafe_allow_html=True)


def page_hero(title: str, subtitle: str, *, eyebrow: str = "SOC Command Center", badges: list[str] | None = None) -> None:
    st.markdown(page_hero_html(title, subtitle, eyebrow=eyebrow, badges=badges), unsafe_allow_html=True)


def empty_state(title: str, body: str, *, tone: str = "#38bdf8") -> None:
    st.markdown(empty_state_html(title, body, tone=tone), unsafe_allow_html=True)


def result_card(title: str, body: str, *, status: str = "Completed", color: str = "#22c55e") -> None:
    st.markdown(result_card_html(title, body, status=status, color=color), unsafe_allow_html=True)


def detail_grid(items: list[dict]) -> None:
    st.markdown(key_value_grid_html(items), unsafe_allow_html=True)


def readiness_grid(items: list[dict]) -> None:
    st.markdown(readiness_grid_html(items), unsafe_allow_html=True)


def is_presentation_mode() -> bool:
    return bool(st.session_state.get("presentation_mode", presentation_mode_default()))


def render_timeline(rows: list[dict], *, limit: int = 8, color: str = "#22d3ee") -> None:
    for row in rows[:limit]:
        title = row.get("event_type") or row.get("action") or "Event"
        body = row.get("summary") or row.get("details") or f"{row.get('target_type', '-')}:{row.get('target_value', '-')}"
        event_time = row.get("event_time") or row.get("created_at") or row.get("executed_at")
        st.markdown(
            timeline_row_html(event_time, title, body, actor=row.get("actor") or row.get("executed_by"), color=color),
            unsafe_allow_html=True,
        )


def render_operation_result(result: dict, *, title: str, success_detail: str = "Operation completed.") -> None:
    if "import" in result or "detection" in result:
        import_part = result.get("import", {})
        detection_part = result.get("detection", {})
        body = (
            f"Imported: {import_part.get('imported', '-')} | Parsed: {import_part.get('parsed', '-')} | "
            f"Evaluated: {detection_part.get('evaluated', '-')} | Alerts: {detection_part.get('created_alerts', '-')}"
        )
        result_card(title, body, status="Success", color=SOC_COLORS["green"])
        return
    count_parts = []
    for key in (
        "imported",
        "parsed",
        "failed",
        "evaluated",
        "candidate_logs",
        "created_alerts",
        "scored",
        "anomalies",
        "anomaly_rate",
        "training_log_count",
    ):
        if key in result:
            count_parts.append(f"{key.replace('_', ' ').title()}: {result[key]}")
    body = "; ".join(count_parts) if count_parts else result.get("message", success_detail)
    result_card(title, body, status="Success", color=SOC_COLORS["green"])


def demo_readiness_items(health: dict, summary: dict, ml_report: dict, audit_rows: list[dict]) -> list[dict]:
    checks = health.get("checks", {})
    db_status = checks.get("database", {}).get("status")
    response_status = checks.get("response_mode", {}).get("status")
    model_exists = bool(ml_report.get("model_status", {}).get("artifact_exists"))
    total_logs = int(summary.get("total_logs", 0) or 0)
    total_alerts = int(summary.get("total_alerts", 0) or 0)
    return [
        {"label": "API Health", "ok": health.get("status") == "ok", "detail": f"FastAPI status: {health.get('status', 'unknown')}"},
        {"label": "Database", "ok": db_status == "ok", "detail": f"Database check: {db_status or 'unknown'}"},
        {"label": "Sample Logs", "ok": total_logs > 0, "detail": f"{total_logs} normalized logs available"},
        {"label": "Alerts", "ok": total_alerts > 0, "detail": f"{total_alerts} grouped alerts available"},
        {"label": "ML Artifact", "ok": model_exists, "detail": "Assistive model artifact is ready" if model_exists else "Train ML model if this is part of the demo"},
        {"label": "Response Mode", "ok": response_status == "simulation", "detail": f"Current mode: {response_status or 'unknown'}"},
        {"label": "Audit Activity", "ok": bool(audit_rows), "detail": f"{len(audit_rows)} recent audit event(s) loaded"},
    ]


def plotly_config() -> dict:
    return {"displayModeBar": False, "responsive": True}


def style_figure(fig: go.Figure, *, title: str | None = None, height: int = 260) -> go.Figure:
    theme = plotly_theme()
    fig.update_layout(
        paper_bgcolor=theme["paper_bgcolor"],
        plot_bgcolor=theme["plot_bgcolor"],
        font=theme["font"],
        colorway=theme["colorway"],
        margin=theme["margin"],
        legend=theme["legend"],
        height=height,
        title={"text": title or "", "font": {"size": 15, "color": SOC_COLORS["text"]}, "x": 0.02},
    )
    fig.update_xaxes(gridcolor="rgba(148,163,184,0.12)", zeroline=False)
    fig.update_yaxes(gridcolor="rgba(148,163,184,0.12)", zeroline=False)
    return fig


def chart_panel(fig: go.Figure) -> None:
    with st.container(border=True):
        st.plotly_chart(fig, use_container_width=True, config=plotly_config())


def donut_chart(title: str, values: dict | list[dict], colors: dict | None = None) -> None:
    if isinstance(values, dict):
        labels = [str(label) for label, count in values.items()]
        counts = [int(count or 0) for count in values.values()]
    else:
        labels = [str(item.get("name", "-")) for item in values]
        counts = [int(item.get("count", 0) or 0) for item in values]
    if not labels or sum(counts) == 0:
        empty_state(title, "No records are available for this chart yet.", tone=SOC_COLORS["gray"])
        return
    marker_colors = [colors.get(label, SOC_COLORS["cyan"]) for label in labels] if colors else None
    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=counts,
                hole=0.62,
                marker={"colors": marker_colors} if marker_colors else None,
                textinfo="label+percent",
                textfont={"size": 11},
            )
        ]
    )
    chart_panel(style_figure(fig, title=title))


def horizontal_bar_chart(title: str, rows: list[dict], *, color: str = "#22d3ee", limit: int = 8) -> None:
    cleaned = sorted(rows, key=lambda item: item.get("count", 0), reverse=True)[:limit]
    if not cleaned:
        empty_state(title, "No ranked records are available yet.", tone=SOC_COLORS["gray"])
        return
    labels = [str(item.get("name", "-")) for item in cleaned][::-1]
    counts = [int(item.get("count", 0) or 0) for item in cleaned][::-1]
    fig = go.Figure(data=[go.Bar(x=counts, y=labels, orientation="h", marker_color=color, text=counts, textposition="auto")])
    fig.update_layout(yaxis={"automargin": True})
    chart_panel(style_figure(fig, title=title))


def render_distribution(title: str, rows: list[dict]):
    st.markdown(f'<div class="atdr-panel-title">{safe_text(title)}</div>', unsafe_allow_html=True)
    df = as_frame(rows)
    if df.empty:
        empty_state(title, "No distribution data is available yet.", tone=SOC_COLORS["gray"])
        return
    horizontal_bar_chart(title, rows)


def render_ranked_list(title: str, rows: list[dict], tone: str = "#14b8a6", limit: int = 8):
    st.markdown(f'<div class="atdr-panel-title">{safe_text(title)}</div>', unsafe_allow_html=True)
    if not rows:
        empty_state(title, "No ranked data is available yet.", tone=SOC_COLORS["gray"])
        return
    st.markdown(ranked_list_html(rows, tone=tone, limit=limit), unsafe_allow_html=True)


def posture_from_summary(summary: dict) -> tuple[str, str, str]:
    critical = int(summary.get("critical_open_alerts", 0) or 0)
    high = int(summary.get("high_open_alerts", 0) or 0)
    unassigned = int(summary.get("unassigned_active_alerts", 0) or 0)
    anomaly_rate = float(summary.get("anomaly_rate", 0) or 0)
    if critical:
        return "Critical", "#ef4444", f"{critical} critical open alert(s) need immediate triage"
    if high > 10 or anomaly_rate > 5:
        return "Elevated", "#f97316", "High alert volume or ML anomaly rate needs review"
    if unassigned > 20:
        return "Watch", "#f59e0b", "Queue has many unassigned active alerts"
    return "Stable", "#22c55e", "No critical open conditions detected"


def group_metadata(alert: dict) -> dict:
    for rule in alert.get("matched_rules_json", []):
        if rule.get("code") == "group_metadata":
            return rule
    return {}


def sla_summary(item: dict) -> tuple[str, str, str]:
    sla = item.get("sla") or {}
    label = str(sla.get("label") or "-")
    state = str(sla.get("state") or "unknown").replace("_", " ").title()
    due_at = str(sla.get("due_at") or "-")
    return label, state, due_at


def matched_rule_rows(alert: dict) -> list[dict]:
    return [rule for rule in alert.get("matched_rules_json", []) if rule.get("code") != "group_metadata"]


def evidence_preview(log_ids: list[int], limit: int = 12) -> pd.DataFrame:
    rows = []
    for log_id in log_ids[:limit]:
        log = api_get(f"/api/logs/{log_id}")
        rows.append(
            {
                "id": log.get("id"),
                "time": log.get("generated_time") or log.get("receive_time"),
                "src_ip": log.get("src_ip"),
                "dst_ip": log.get("dst_ip"),
                "app": log.get("app"),
                "action": log.get("action"),
                "protocol": log.get("protocol"),
                "dst_port": log.get("dst_port"),
                "bytes": log.get("bytes"),
                "app_risk": log.get("app_risk"),
                "is_anomaly": log.get("is_anomaly"),
            }
        )
    return as_frame(rows)


def badge(label: str, color: str) -> None:
    st.markdown(
        f'<span class="atdr-badge" style="background:{safe_text(color)};">{safe_text(label)}</span>',
        unsafe_allow_html=True,
    )


def section_label(label: str) -> None:
    st.markdown(f'<div class="section-label">{label}</div>', unsafe_allow_html=True)


def login_page() -> None:
    left, middle, right = st.columns([1, 1.2, 1])
    with middle:
        st.markdown(
            """
            <div class="atdr-login">
                <div class="atdr-card-label">Secure Console</div>
                <div class="atdr-card-value" style="font-size:1.55rem;">Sign In</div>
                <div class="atdr-card-detail">Use the demo SOC accounts or your configured user.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", type="primary")
        if submitted:
            try:
                token = api_post("/api/auth/login", json={"username": username, "password": password})
                st.session_state["access_token"] = token["access_token"]
                st.session_state["current_user"] = {
                    "username": token["username"],
                    "role": token["role"],
                }
                st.rerun()
            except requests.HTTPError:
                st.error("Invalid username or password.")
        st.caption("Demo accounts: admin/admin123 and analyst/analyst123")


def require_login() -> dict:
    if not st.session_state.get("access_token"):
        login_page()
        st.stop()
    try:
        user = api_get("/api/auth/me")
    except requests.HTTPError:
        st.session_state.pop("access_token", None)
        st.session_state.pop("current_user", None)
        st.warning("Your session expired. Please sign in again.")
        login_page()
        st.stop()
    st.session_state["current_user"] = user
    return user


def overview_page():
    summary = api_get("/api/dashboard/summary")
    posture, posture_color, posture_detail = posture_from_summary(summary)
    page_hero(
        "Operational Monitoring",
        "Live SOC overview for evidence ingestion, alert pressure, workflow health, response safety, and ML-assisted anomaly signals.",
        badges=["Rule-first detection", "Raw evidence retained", "ML assistive", "Response simulated"],
    )
    command_panel(
        [
            {"label": "Security Posture", "value": posture, "detail": posture_detail, "color": posture_color},
            {
                "label": "Active Queue",
                "value": summary.get("active_alerts", 0),
                "detail": "Open, investigating, contained",
                "color": "#0ea5e9",
            },
            {
                "label": "Critical Open",
                "value": summary.get("critical_open_alerts", 0),
                "detail": "Requires immediate analyst review",
                "color": "#ef4444",
            },
            {
                "label": "Unassigned",
                "value": summary.get("unassigned_active_alerts", 0),
                "detail": "Active alerts without owner",
                "color": "#f59e0b",
            },
        ]
    )

    section_label("Operations Snapshot")
    c1, c2, c3, c4 = st.columns(4)
    severities = summary.get("severity_counts", {})
    with c1:
        metric_card("Logs Ingested", summary.get("total_logs", 0), "Normalized firewall events", "teal")
    with c2:
        metric_card("Active Alerts", summary.get("total_alerts", 0), "Grouped detection findings", "red")
    with c3:
        metric_card("ML Anomalies", summary.get("ml_anomaly_logs", 0), "IsolationForest assisted flags", "blue")
    with c4:
        metric_card("Anomaly Rate", f"{summary.get('anomaly_rate', 0)}%", "Percent of parsed logs", "amber")

    c5, c6, c7, c8 = st.columns(4)
    with c5:
        metric_card("Active Suppressions", summary.get("active_suppressions", 0), "Noise-control rules", "gray")
    with c6:
        metric_card("Suppressed Hits", summary.get("suppressed_hits", 0), "Events hidden by suppressions", "blue")
    with c7:
        metric_card("Watchlist Items", summary.get("active_watchlist_items", 0), "Priority indicators", "amber")
    with c8:
        metric_card("Watchlist Hits", summary.get("watchlist_hits", 0), "Matched indicator events", "red")

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        metric_card("Low", severities.get("Low", 0), "Informational triage", "green")
    with s2:
        metric_card("Medium", severities.get("Medium", 0), "Review recommended", "amber")
    with s3:
        metric_card("High", severities.get("High", 0), "Priority investigation", "blue")
    with s4:
        metric_card("Critical", severities.get("Critical", 0), "Immediate response", "red")

    status_counts = summary.get("status_counts", {})
    section_label("Alert Workflow")
    w1, w2, w3, w4, w5 = st.columns(5)
    with w1:
        metric_card("Open", status_counts.get("open", 0), "Needs triage", "red")
    with w2:
        metric_card("Investigating", status_counts.get("investigating", 0), "Owned by analyst", "amber")
    with w3:
        metric_card("Contained", status_counts.get("contained", 0), "Response applied", "blue")
    with w4:
        metric_card("Resolved", status_counts.get("resolved", 0), "Closed findings", "green")
    with w5:
        metric_card("False Positive", status_counts.get("false_positive", 0), "Suppressed noise", "gray")

    section_label("Detection Breakdown")
    left, middle, right = st.columns(3)
    with left:
        horizontal_bar_chart("Top Alert Types", summary.get("top_alert_types", []), color=SOC_COLORS["red"])
    with middle:
        horizontal_bar_chart("Suspicious Source IPs", summary.get("top_suspicious_source_ips", []), color=SOC_COLORS["amber"])
    with right:
        donut_chart("Actions", summary.get("action_distribution", []))

    left, middle, right = st.columns(3)
    with left:
        horizontal_bar_chart("Destination Countries", summary.get("top_destination_countries", []), color=SOC_COLORS["blue"])
    with middle:
        donut_chart("Protocols", summary.get("protocol_distribution", []))
    with right:
        horizontal_bar_chart("App Risk", summary.get("app_risk_distribution", []), color="#f97316")

    section_label("SOC Distribution")
    d1, d2 = st.columns(2)
    with d1:
        donut_chart("Severity Mix", summary.get("severity_counts", {}), colors=SEVERITY_COLORS)
    with d2:
        donut_chart(
            "Workflow State",
            {key.replace("_", " ").title(): value for key, value in summary.get("status_counts", {}).items()},
            colors={key.replace("_", " ").title(): value for key, value in STATUS_COLORS.items()},
        )

    section_label("Recent Alerts")
    alerts = as_frame(summary.get("recent_alerts", []))
    if alerts.empty:
        empty_state("No Recent Alerts", "Run detection after importing logs to populate this triage queue.", tone=SOC_COLORS["green"])
    else:
        card_col, table_col = st.columns([1.05, 1.2])
        with card_col:
            for alert_row in alerts.to_dict("records")[:4]:
                severity = alert_row.get("severity", "Unknown")
                status = str(alert_row.get("status") or "open").replace("_", " ").title()
                sla_label, sla_state, sla_due = sla_summary(alert_row)
                st.markdown(
                    evidence_card_html(
                        f"Alert #{alert_row.get('id')} | Score {alert_row.get('threat_score')}",
                        f"{alert_row.get('title', '-')} | {alert_row.get('src_ip', '-')} -> {alert_row.get('dst_ip', '-')} | Evidence: {alert_row.get('evidence_count', '-')} | SLA due: {sla_due}",
                        eyebrow=f"{severity} / {status} / {sla_label} {sla_state}",
                        color=SEVERITY_COLORS.get(severity, SOC_COLORS["cyan"]),
                    ),
                    unsafe_allow_html=True,
                )
        with table_col:
            display_alerts = alerts.copy()
            display_alerts["sla_state"] = display_alerts["sla"].map(lambda value: (value or {}).get("state", "-") if isinstance(value, dict) else "-")
            columns = ["id", "severity", "status", "sla_state", "threat_score", "evidence_count", "src_ip", "dst_ip", "created_at"]
            st.dataframe(
                display_alerts[[col for col in columns if col in display_alerts.columns]],
                hide_index=True,
                use_container_width=True,
                column_config={"threat_score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100)},
            )

def executive_demo_page():
    health = api_get("/health")
    summary = api_get("/api/dashboard/summary")
    ml_report = api_get("/api/ml/report")
    audit_rows = api_get("/api/audit", limit=8)
    critical_alerts = api_get("/api/alerts", severity="Critical", status="open", limit=8)
    posture, posture_color, posture_detail = posture_from_summary(summary)

    page_hero(
        "Supervisor Demo Command Center",
        "A guided story of how ATDR ingests Palo Alto evidence, creates explainable detections, supports analyst workflow, simulates safe response, and records audit proof.",
        eyebrow="MFU ATDR",
        badges=["Senior project complete", "Lab-pilot path", "No real firewall changes"],
    )
    command_panel(
        [
            {"label": "Project Stage", "value": "Lab Pilot", "detail": "Beyond demo prototype", "color": "#14b8a6"},
            {"label": "Security Posture", "value": posture, "detail": posture_detail, "color": posture_color},
            {"label": "Evidence Logs", "value": summary.get("total_logs", 0), "detail": "Raw + normalized storage", "color": "#0ea5e9"},
            {"label": "Critical Open", "value": summary.get("critical_open_alerts", 0), "detail": "Supervisor-ready triage metric", "color": "#ef4444"},
        ]
    )

    section_label("Operational Story")
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        metric_card("Ingest", summary.get("total_logs", 0), "Palo Alto evidence retained", "teal")
    with s2:
        metric_card("Detect", summary.get("total_alerts", 0), "Grouped explainable alerts", "red")
    with s3:
        metric_card("Investigate", summary.get("active_alerts", 0), "SOC workflow queue", "amber")
    with s4:
        metric_card("Respond", "Simulated", "Audit-safe containment", "blue")

    st.markdown(
        """
        <div class="atdr-mini-note">
            Supervisor framing: ATDR keeps raw evidence, creates rule-first explainable detections,
            uses ML only as assistive scoring, and keeps response actions simulated for safety.
        </div>
        """,
        unsafe_allow_html=True,
    )

    section_label("System Readiness")
    checks = health.get("checks", {})
    r1, r2, r3, r4, r5 = st.columns(5)
    with r1:
        metric_card("API", health.get("status", "unknown").upper(), "FastAPI service health", "green" if health.get("status") == "ok" else "amber")
    with r2:
        db_status = checks.get("database", {}).get("status", "unknown")
        metric_card("Database", db_status.upper(), "SQLite demo or PostgreSQL lab mode", "green" if db_status == "ok" else "red")
    with r3:
        response_status = checks.get("response_mode", {}).get("status", "unknown")
        metric_card("Response", response_status.title(), "No real firewall changes", "blue")
    with r4:
        model_status = checks.get("ml_model", {}).get("status", "unknown")
        metric_card("ML Artifact", model_status.title(), "Assistive model file state", "green" if model_status == "ready" else "amber")
    with r5:
        metric_card("Raw Evidence", summary.get("total_logs", 0), "Logs retained before parsing", "teal")

    checklist_tab, story_tab, evidence_tab, ai_tab, roadmap_tab = st.tabs(
        ["Demo Checklist", "SOC Snapshot", "Audit Proof", "AI Governance", "Production Roadmap"]
    )

    with checklist_tab:
        st.markdown(
            mission_path_html(
                [
                    {"label": "Ingest", "proof": f"{summary.get('total_logs', 0)} logs", "detail": "Raw Palo Alto evidence retained."},
                    {"label": "Detect", "proof": f"{summary.get('total_alerts', 0)} alerts", "detail": "Rule-first grouped findings."},
                    {"label": "Investigate", "proof": f"{summary.get('active_alerts', 0)} active", "detail": "Assign, note, escalate, resolve."},
                    {"label": "Respond", "proof": response_status.title(), "detail": "Simulated containment only."},
                    {"label": "Audit", "proof": f"{len(audit_rows)} recent", "detail": "Actor, target, time, details."},
                    {"label": "ML Governance", "proof": f"{len(ml_report.get('drift_signals', []))} drift", "detail": "Assistive anomaly evidence."},
                ]
            ),
            unsafe_allow_html=True,
        )
        st.info(
            "Current stage: senior project prototype complete; lab-pilot readiness mostly ready; production deployment still requires Docker/PostgreSQL validation, HTTPS, backups, baseline tuning, and approved firewall integration."
        )

    with story_tab:
        left, right = st.columns([1.05, 0.95])
        with left:
            section_label("Critical Queue")
            critical_df = as_frame(critical_alerts)
            if critical_df.empty:
                st.markdown(
                    evidence_card_html("No Critical Open Alerts", "The current queue has no open Critical findings.", eyebrow="Queue", color=SOC_COLORS["green"]),
                    unsafe_allow_html=True,
                )
            else:
                for alert_row in critical_alerts[:5]:
                    st.markdown(
                        evidence_card_html(
                            f"Alert #{alert_row.get('id')} | Score {alert_row.get('threat_score')}",
                            f"{alert_row.get('title', '-')} | Owner: {alert_row.get('assigned_to') or 'Unassigned'} | Evidence logs: {alert_row.get('evidence_count', '-')}",
                            eyebrow=f"{alert_row.get('severity', 'Critical')} / {alert_row.get('status', 'open')}",
                            color=SOC_COLORS["red"],
                        ),
                        unsafe_allow_html=True,
                    )
        with right:
            horizontal_bar_chart("Top Detection Themes", summary.get("top_alert_types", []), color=SOC_COLORS["red"], limit=7)

    with evidence_tab:
        audit_df = as_frame(audit_rows)
        if audit_df.empty:
            empty_state("No Recent Audit Records", "Audit proof appears here after workflow or response actions.", tone=SOC_COLORS["amber"])
        else:
            for row in audit_rows[:5]:
                st.markdown(
                    evidence_card_html(
                        f"{row.get('action', '-')}",
                        f"{row.get('actor', '-')} -> {row.get('target_type', '-')}:{row.get('target_value', '-')} at {row.get('created_at', '-')}",
                        eyebrow="Audit Proof",
                        color=SOC_COLORS["cyan"],
                    ),
                    unsafe_allow_html=True,
                )

    with ai_tab:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Model Artifact", "Ready" if ml_report["model_status"]["artifact_exists"] else "Missing", "Tracked artifact", "green")
        with c2:
            metric_card("Anomaly Rate", f"{ml_report['anomaly_rate']}%", "Latest stored state", "amber")
        with c3:
            metric_card("Scored Logs", ml_report["scored_log_count"], "Logs with ML scores", "teal")
        with c4:
            metric_card("Baseline Pool", ml_report["dataset_profile"]["baseline_candidate_count"], "Candidate normal logs", "blue")
        left, right = st.columns(2)
        with left:
            horizontal_bar_chart("Anomalous Apps", ml_report.get("top_anomalous_apps", []), color=SOC_COLORS["amber"])
        with right:
            horizontal_bar_chart("Anomalous Source IPs", ml_report.get("top_anomalous_src_ips", []), color=SOC_COLORS["red"])
        drift = as_frame(ml_report.get("drift_signals", []))
        if not drift.empty:
            section_label("Baseline Drift Signals")
            for row in drift.to_dict("records")[:5]:
                level = str(row.get("level") or "info").lower()
                st.markdown(
                    evidence_card_html(
                        row.get("metric", "Drift Signal"),
                        f"Training: {row.get('training_value', '-')} | Current: {row.get('current_value', '-')} | {row.get('message', '-')}",
                        eyebrow=level.title(),
                        color=SOC_COLORS["red"] if level == "high" else SOC_COLORS["amber"],
                    ),
                    unsafe_allow_html=True,
                )
        else:
            empty_state("No Drift Signals", "Current traffic remains inside the available baseline comparison thresholds.", tone=SOC_COLORS["green"])

    with roadmap_tab:
        roadmap = [
            {"area": "Deployment", "current": "Local SQLite + Docker scaffolding", "next": "Validate PostgreSQL Compose on Docker host"},
            {"area": "Network Ingestion", "current": "File import + localhost UDP receiver", "next": "Pilot syslog forwarding from lab firewall"},
            {"area": "Identity", "current": "JWT users and admin management", "next": "Password policy and campus identity integration"},
            {"area": "Response", "current": "Simulation mode with audit trail", "next": "Approved firewall connector with allowlist and rollback"},
            {"area": "ML", "current": "Governed IsolationForest baseline training", "next": "Baseline validation window and drift monitoring"},
        ]
        for item in roadmap:
            st.markdown(
                evidence_card_html(
                    item["area"],
                    f"Current: {item['current']} | Next: {item['next']}",
                    eyebrow="Production Path",
                    color=SOC_COLORS["blue"],
                ),
                unsafe_allow_html=True,
            )


def log_explorer_page():
    page_hero(
        "Log Explorer",
        "Search normalized firewall telemetry, inspect raw Palo Alto evidence, and pivot suspicious events into investigation context.",
        badges=["Raw line preserved", "Quoted CSV safe", "Anomaly flags visible"],
    )
    st.markdown(
        """
        <div class="atdr-mini-note">
            Search normalized firewall events, inspect raw evidence, and pivot from suspicious IPs or applications into alert context.
        </div>
        """,
        unsafe_allow_html=True,
    )
    section_label("Filters")
    with st.form("log_filters"):
        c1, c2, c3, c4 = st.columns(4)
        src_ip = c1.text_input("Source IP")
        dst_ip = c2.text_input("Destination IP")
        app = c3.text_input("App")
        action = c4.selectbox("Action", ["", "allow", "deny", "drop", "alert", "reset-client", "reset-server"])
        c5, c6, c7, c8 = st.columns(4)
        severity = c5.selectbox("Severity", ["", "Low", "Medium", "High", "Critical"])
        country = c6.text_input("Country")
        generated_from = c7.text_input("From", placeholder="2026/05/20 13:36:15")
        generated_to = c8.text_input("To", placeholder="2026/05/20 13:40:00")
        submitted = st.form_submit_button("Search")

    params = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "app": app,
        "action": action,
        "severity": severity,
        "country": country,
        "generated_from": generated_from,
        "generated_to": generated_to,
        "limit": 300,
    }
    logs = api_get("/api/logs", **params)
    df = as_frame(logs)
    section_label("Logs")
    if df.empty:
        empty_state("No Logs Match These Filters", "Try clearing one filter or importing the sample Palo Alto log file from Demo Controls.", tone=SOC_COLORS["amber"])
        return
    columns = [
        "id",
        "generated_time",
        "src_ip",
        "dst_ip",
        "app",
        "action",
        "protocol",
        "src_zone",
        "dst_zone",
        "dst_port",
        "app_risk",
        "is_anomaly",
    ]
    st.dataframe(
        df[[col for col in columns if col in df.columns]],
        hide_index=True,
        use_container_width=True,
        column_config={
            "app_risk": st.column_config.ProgressColumn("App Risk", min_value=0, max_value=5),
            "is_anomaly": st.column_config.CheckboxColumn("Anomaly"),
        },
    )
    selected = st.selectbox("Selected Log", df["id"].tolist())
    detail = api_get(f"/api/logs/{selected}")
    section_label("Selected Evidence")
    detail_grid(
        [
            {"label": "Generated Time", "value": detail.get("generated_time")},
            {"label": "Source", "value": f"{detail.get('src_ip')}:{detail.get('src_port')}"},
            {"label": "Destination", "value": f"{detail.get('dst_ip')}:{detail.get('dst_port')}"},
            {"label": "Application", "value": detail.get("app")},
            {"label": "Action", "value": detail.get("action")},
            {"label": "Zones", "value": f"{detail.get('src_zone')} -> {detail.get('dst_zone')}"},
            {"label": "Protocol", "value": detail.get("protocol")},
            {"label": "App Risk", "value": detail.get("app_risk")},
            {"label": "ML Anomaly", "value": "Yes" if detail.get("is_anomaly") else "No"},
        ]
    )
    with st.expander("Raw Evidence", expanded=True):
        st.markdown('<div class="atdr-code-caption">Original syslog line retained for evidence</div>', unsafe_allow_html=True)
        st.code(detail.get("raw_line") or "")
    with st.expander("Parsed Payload", expanded=not is_presentation_mode()):
        st.json(detail.get("parsed_json", {}))


def alerts_page():
    page_hero(
        "Alert Triage Workbench",
        "Prioritize grouped detections, inspect matched rules and raw evidence, manage workflow state, and record safe response actions.",
        badges=["Explainable scoring", "Evidence linked", "Workflow audited"],
    )
    c0, c1, c2, c3, c4 = st.columns(5)
    queue = c0.selectbox(
        "Queue",
        ["Custom", "Critical Open", "Assigned To Me", "Unassigned", "Recently Updated", "False Positive Review"],
        key="alert_queue",
    )
    severity_default = "Critical" if queue == "Critical Open" else ""
    status_default = "open" if queue == "Critical Open" else "false_positive" if queue == "False Positive Review" else ""
    severity = c1.selectbox("Severity", ["", "Low", "Medium", "High", "Critical"], index=["", "Low", "Medium", "High", "Critical"].index(severity_default), key="alert_severity")
    status = c2.selectbox(
        "Status",
        ["", "open", "investigating", "contained", "resolved", "false_positive"],
        index=["", "open", "investigating", "contained", "resolved", "false_positive"].index(status_default),
        key="alert_status",
    )
    ownership_default = "Assigned to me" if queue == "Assigned To Me" else "Unassigned" if queue == "Unassigned" else ""
    ownership = c3.selectbox("Ownership", ["", "Assigned to me", "Unassigned"], index=["", "Assigned to me", "Unassigned"].index(ownership_default), key="alert_ownership")
    if c4.button("Run Detection"):
        result = api_post("/api/detection/run", json=None)
        render_operation_result(result, title="Detection Run Completed")

    alert_params = {"severity": severity, "status": status, "limit": 300}
    if queue == "Recently Updated":
        alert_params["sort_by"] = "updated"
    if ownership == "Assigned to me":
        alert_params["mine"] = True
    elif ownership == "Unassigned":
        alert_params["unassigned"] = True
    alerts = api_get("/api/alerts", **alert_params)
    df = as_frame(alerts)
    if df.empty:
        empty_state("No Alerts In This Queue", "Change the queue filters or run detection after importing logs.", tone=SOC_COLORS["green"])
        return
    if "sla" in df.columns:
        df["sla_state"] = df["sla"].map(lambda value: (value or {}).get("state", "-") if isinstance(value, dict) else "-")

    open_count = len(df[df["status"].isin(["open", "investigating", "contained"])]) if "status" in df.columns else len(df)
    critical_count = len(df[df["severity"] == "Critical"]) if "severity" in df.columns else 0
    assigned_count = int(df["assigned_to"].notna().sum()) if "assigned_to" in df.columns else 0
    q1, q2, q3 = st.columns(3)
    with q1:
        metric_card("Queue", len(df), "Filtered alerts", "teal")
    with q2:
        metric_card("Active", open_count, "Open/investigating/contained", "amber")
    with q3:
        metric_card("Critical", critical_count, f"{assigned_count} assigned", "red")

    table_columns = [
        "id",
        "severity",
        "threat_score",
        "evidence_count",
        "status",
        "sla_state",
        "assigned_to",
        "src_ip",
        "dst_ip",
        "title",
        "created_at",
    ]
    st.dataframe(
        df[[col for col in table_columns if col in df.columns]],
        hide_index=True,
        use_container_width=True,
        column_config={
            "threat_score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100),
            "title": st.column_config.TextColumn("Title", width="large"),
            "assigned_to": st.column_config.TextColumn("Owner"),
        },
    )
    selected = st.selectbox("Selected Alert", df["id"].tolist())
    alert = api_get(f"/api/alerts/{selected}")
    metadata = group_metadata(alert)
    sla_label, sla_state, sla_due = sla_summary(alert)

    st.markdown(
        f"""
        <div class="atdr-alert-strip">
            <div class="atdr-card-label">Selected Incident</div>
            <div style="font-size:1.25rem; font-weight:850; color:#e5edf6;">{safe_text(alert["title"])}</div>
            <div style="margin-top:0.45rem;">{severity_badge_html(alert.get("severity"))} {status_badge_html(alert.get("status"))}</div>
            <div class="atdr-card-detail">Owner: {safe_text(alert.get("assigned_to"))} | Ticket: {safe_text(alert.get("ticket_reference"))} | SLA: {safe_text(sla_label)} / {safe_text(sla_state)} / due {safe_text(sla_due)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    c1, c2, c3, c4, c5 = st.columns(5)
    score = alert["threat_score"]
    score_tone = "red" if score >= 81 else "blue" if score >= 61 else "amber" if score >= 31 else "green"
    with c1:
        metric_card("Threat Score", score, "0 to 100 scoring", score_tone)
    with c2:
        metric_card("Severity", alert["severity"], "Rule-based priority", score_tone)
        badge(alert["severity"], SEVERITY_COLORS.get(alert["severity"], "#64748b"))
    with c3:
        metric_card("Evidence", alert.get("evidence_count", len(alert.get("evidence_log_ids", []))), "Linked raw logs", "teal")
    with c4:
        metric_card("Status", alert["status"].replace("_", " ").title(), "SOC workflow state", "blue")
        badge(alert["status"].replace("_", " ").title(), STATUS_COLORS.get(alert["status"], "#64748b"))
    with c5:
        metric_card("Type", alert["alert_type"], "Detection category", "gray")
    st.markdown(
        evidence_card_html(
            f"SLA: {sla_label} / {sla_state}",
            f"Due at {sla_due}. Assign an owner and record investigation notes for High and Critical alerts.",
            eyebrow="Triage SLA",
            color=STATUS_COLORS.get(str(alert.get("sla", {}).get("state", "")).lower(), SOC_COLORS["amber"]),
        ),
        unsafe_allow_html=True,
    )

    summary_tab, rules_tab, evidence_tab, workflow_tab, response_tab, report_tab = st.tabs(
        ["Summary", "Matched Rules", "Evidence", "Workflow", "Response", "Report"]
    )

    with summary_tab:
        st.markdown(
            evidence_card_html("Why This Alert Fired", alert["explanation"], eyebrow="Detection Explanation", color=SEVERITY_COLORS.get(alert["severity"], SOC_COLORS["cyan"])),
            unsafe_allow_html=True,
        )
        st.markdown(
            evidence_card_html("Recommended Analyst Action", alert["recommended_response"], eyebrow="Triage Guidance", color=SOC_COLORS["amber"]),
            unsafe_allow_html=True,
        )
        if metadata:
            left, right = st.columns(2)
            with left:
                st.markdown(
                    evidence_card_html(
                        "Observed Window",
                        f"First seen {metadata.get('first_seen', '-')}; last seen {metadata.get('last_seen', '-')}. Sources: {metadata.get('unique_src_count', '-')}; destinations: {metadata.get('unique_dst_count', '-')}.",
                        eyebrow="Grouped Evidence",
                        color=SOC_COLORS["cyan"],
                    ),
                    unsafe_allow_html=True,
                )
            with right:
                st.markdown(
                    evidence_card_html(
                        "Network Shape",
                        f"Actions: {', '.join(metadata.get('actions', [])) or '-'} | Protocols: {', '.join(metadata.get('protocols', [])) or '-'} | Ports: {', '.join(str(port) for port in metadata.get('sample_dst_ports', [])) or '-'}",
                        eyebrow="Traffic Context",
                        color=SOC_COLORS["teal"],
                    ),
                    unsafe_allow_html=True,
                )
            src_samples = ", ".join(metadata.get("sample_src_ips", [])[:8]) or "-"
            dst_samples = ", ".join(metadata.get("sample_dst_ips", [])[:8]) or "-"
            st.markdown(
                evidence_card_html("Sample Entities", f"Sources: {src_samples} | Destinations: {dst_samples}", eyebrow="Evidence Pivot", color=SOC_COLORS["blue"]),
                unsafe_allow_html=True,
            )

    with rules_tab:
        rules = matched_rule_rows(alert)
        rules_df = as_frame(rules)
        if rules_df.empty:
            empty_state("No Matched Rules", "This alert has no recorded rule metadata.", tone=SOC_COLORS["gray"])
        else:
            for rule in rules[:10]:
                score_value = int(float(rule.get("score") or 0))
                st.markdown(
                    evidence_card_html(
                        f"{rule.get('code', '-')} | +{score_value}",
                        f"{rule.get('explanation', '-')} Matched logs: {rule.get('matched_log_count', '-')}",
                        eyebrow=rule.get("title", "Matched Rule"),
                        color=SOC_COLORS["red"] if score_value >= 25 else SOC_COLORS["amber"],
                    ),
                    unsafe_allow_html=True,
                )

    with evidence_tab:
        evidence_ids = alert.get("evidence_log_ids", [])
        preview = evidence_preview(evidence_ids)
        if preview.empty:
            empty_state("No Evidence Logs", "Every generated alert should link to normalized logs. Re-run detection if this is unexpected.", tone=SOC_COLORS["red"])
        else:
            st.dataframe(preview, hide_index=True, use_container_width=True)
            evidence_selected = st.selectbox("Evidence Log", preview["id"].tolist(), key=f"evidence_{selected}")
            detail = api_get(f"/api/logs/{evidence_selected}")
            detail_grid(
                [
                    {"label": "Time", "value": detail.get("generated_time")},
                    {"label": "Source", "value": f"{detail.get('src_ip')}:{detail.get('src_port')}"},
                    {"label": "Destination", "value": f"{detail.get('dst_ip')}:{detail.get('dst_port')}"},
                    {"label": "App", "value": detail.get("app")},
                    {"label": "Action", "value": detail.get("action")},
                    {"label": "Risk", "value": detail.get("app_risk")},
                ]
            )
            with st.expander("Raw Evidence"):
                st.code(detail.get("raw_line") or "")
            with st.expander("Parsed Evidence", expanded=not is_presentation_mode()):
                st.json(detail.get("parsed_json", {}))

    with workflow_tab:
        left, right = st.columns([1, 2])
        with left:
            section_label("Ownership")
            detail_grid(
                [
                    {"label": "Assigned To", "value": alert.get("assigned_to") or "Unassigned"},
                    {"label": "Assigned At", "value": alert.get("assigned_at")},
                    {"label": "Priority Owner", "value": alert.get("priority_owner")},
                    {"label": "Ticket", "value": alert.get("ticket_reference")},
                    {"label": "Escalation", "value": alert.get("escalation_reason")},
                    {"label": "Last Updated", "value": alert.get("updated_at")},
                ]
            )
            if st.button("Assign To Me", key=f"assign_me_{selected}"):
                api_post(f"/api/alerts/{selected}/assign/me")
                st.rerun()
            with st.form(f"escalate_form_{selected}"):
                section_label("Escalation")
                priority_owner = st.text_input("Priority Owner", value=alert.get("priority_owner") or current_user["username"])
                ticket_reference = st.text_input("Ticket Reference", value=alert.get("ticket_reference") or "")
                escalation_reason = st.text_area("Escalation Reason", value=alert.get("escalation_reason") or "", height=90)
                escalate_submitted = st.form_submit_button("Escalate")
            if escalate_submitted:
                api_post(
                    f"/api/alerts/{selected}/escalate",
                    json={
                        "priority_owner": priority_owner,
                        "ticket_reference": ticket_reference or None,
                        "escalation_reason": escalation_reason,
                    },
                )
                st.rerun()
            if current_user["role"] == "admin":
                with st.form(f"assign_form_{selected}"):
                    assigned_to = st.text_input("Assign To Username", value=alert.get("assigned_to") or "")
                    submitted = st.form_submit_button("Assign")
                if submitted:
                    api_post(f"/api/alerts/{selected}/assign", json={"username": assigned_to})
                    st.rerun()

            section_label("Add Note")
            with st.form(f"note_form_{selected}"):
                note = st.text_area("Investigation Note", height=120)
                note_submitted = st.form_submit_button("Save Note")
            if note_submitted:
                api_post(f"/api/alerts/{selected}/notes", json={"note": note})
                st.rerun()

        with right:
            section_label("Timeline")
            timeline = as_frame(api_get(f"/api/alerts/{selected}/timeline"))
            if timeline.empty:
                empty_state("No Timeline Events", "Workflow updates, notes, escalations, and response actions will appear here.", tone=SOC_COLORS["blue"])
            else:
                render_timeline(timeline.to_dict("records"), limit=10, color=SOC_COLORS["cyan"])

            section_label("Notes")
            notes = as_frame(api_get(f"/api/alerts/{selected}/notes"))
            if notes.empty:
                empty_state("No Analyst Notes", "Add investigation notes to preserve reasoning for handoff and supervisor review.", tone=SOC_COLORS["amber"])
            else:
                for note_row in notes.to_dict("records")[:8]:
                    st.markdown(
                        evidence_card_html(
                            note_row.get("author", "-"),
                            note_row.get("note", "-"),
                            eyebrow=note_row.get("created_at", "Analyst Note"),
                            color=SOC_COLORS["amber"],
                        ),
                        unsafe_allow_html=True,
                    )

    with response_tab:
        left, right = st.columns([2, 1])
        candidate_ips = []
        if alert.get("src_ip"):
            candidate_ips.append(alert["src_ip"])
        candidate_ips.extend(ip for ip in metadata.get("sample_src_ips", []) if ip not in candidate_ips)
        target_ip = None
        with left:
            if candidate_ips:
                target_ip = st.selectbox("Response Target", candidate_ips, key=f"target_{selected}")
            else:
                st.warning("No source IP is available for this grouped alert.")
            st.markdown(
                evidence_card_html(
                    "Recommended Analyst Action",
                    alert["recommended_response"],
                    eyebrow="Response Guidance",
                    color=SOC_COLORS["amber"],
                ),
                unsafe_allow_html=True,
            )
        with right:
            if st.button("Investigating", key=f"investigating_{selected}"):
                api_post(f"/api/alerts/{selected}/investigate")
                st.rerun()
            if st.button("Contained", key=f"contained_{selected}"):
                api_post(f"/api/alerts/{selected}/contain")
                st.rerun()
            if st.button("Resolved", key=f"resolve_{selected}"):
                api_post(f"/api/alerts/{selected}/resolve")
                st.rerun()
            if st.button("False Positive", key=f"false_positive_{selected}"):
                api_post(f"/api/alerts/{selected}/false-positive")
                st.rerun()
            if current_user["role"] == "admin":
                if target_ip and st.button("Block Selected IP", key=f"block_{selected}"):
                    api_post(
                        "/api/response/block-ip",
                        json={"target_ip": target_ip, "reason": f"Alert {selected}", "alert_id": selected},
                    )
                    st.rerun()
            else:
                st.caption("Admin role required for simulated block actions.")

    with report_tab:
        st.markdown(
            evidence_card_html(
                "Incident Report Export",
                "Download structured evidence for supervisor review, report appendix, or analyst handoff.",
                eyebrow="Presentation Evidence",
                color=SOC_COLORS["cyan"],
            ),
            unsafe_allow_html=True,
        )
        report_json = api_get(f"/api/alerts/{selected}/report")
        st.download_button(
            "Download JSON Report",
            data=json.dumps(report_json, default=str, indent=2),
            file_name=f"alert-{selected}-report.json",
            mime="application/json",
        )
        csv_response = api_get_response(f"/api/alerts/{selected}/report", format="csv")
        st.download_button(
            "Download CSV Evidence",
            data=csv_response.text,
            file_name=f"alert-{selected}-report.csv",
            mime="text/csv",
        )
        html_response = api_get_response(f"/api/alerts/{selected}/report", format="html")
        st.download_button(
            "Download HTML Report",
            data=html_response.text,
            file_name=f"alert-{selected}-report.html",
            mime="text/html",
        )
        pdf_response = api_get_response(f"/api/alerts/{selected}/report", format="pdf")
        st.download_button(
            "Download PDF Report",
            data=pdf_response.content,
            file_name=f"alert-{selected}-report.pdf",
            mime="application/pdf",
        )
        with st.expander("Technical JSON Preview", expanded=not is_presentation_mode()):
            st.json(report_json)


def response_center_page():
    page_hero(
        "Response Center",
        "Simulated containment workspace for block/unblock decisions, response audit evidence, and safe analyst operations.",
        badges=["Simulation mode", "Admin-controlled", "Audit required"],
    )
    section_label("Response Center")
    is_admin = current_user["role"] == "admin"
    blocked = api_get("/api/response/blocked-ips", active_only=True)
    audit_rows = api_get("/api/audit", limit=100)
    response_audit = [
        row for row in audit_rows if row.get("action") in {"block_ip", "unblock_ip", "simulated_block_ip", "simulated_unblock_ip"}
    ]
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("Response Mode", "Simulated", "No firewall device is modified", "blue")
    with c2:
        metric_card("Active Blocks", len(blocked), "Prototype containment list", "red")
    with c3:
        metric_card("Recent Actions", len(response_audit), "Audited response events", "teal")

    st.markdown(
        evidence_card_html(
            "Simulation Mode Is Enabled",
            "Response actions create blocked-IP records and audit evidence only. No real firewall device is modified by this prototype.",
            eyebrow="Safety Control",
            color=SOC_COLORS["blue"],
        ),
        unsafe_allow_html=True,
    )

    section_label("Simulated Block IP")
    with st.form("block_ip"):
        c1, c2 = st.columns([1, 3])
        target_ip = c1.text_input("IP Address")
        reason = c2.text_input("Reason")
        if st.form_submit_button("Block", disabled=not is_admin):
            api_post("/api/response/block-ip", json={"target_ip": target_ip, "reason": reason})
            result_card("Simulated Block Recorded", f"{target_ip} was added to the prototype blocked-IP list.", status="Audited", color=SOC_COLORS["red"])
    if not is_admin:
        st.info("Admin role required for simulated block and unblock actions.")

    df = as_frame(blocked)
    section_label("Blocked IPs")
    if df.empty:
        empty_state("No Active Simulated Blocks", "Blocked IP records will appear here after an admin applies a simulated containment action.", tone=SOC_COLORS["green"])
    else:
        for row in df.to_dict("records")[:6]:
            st.markdown(
                evidence_card_html(
                    row.get("ip_address", "-"),
                    f"Reason: {row.get('reason', '-')} | Created by: {row.get('created_by', '-')} | Created at: {row.get('created_at', '-')}",
                    eyebrow="Simulated Block",
                    color=SOC_COLORS["red"],
                ),
                unsafe_allow_html=True,
            )
        if not is_presentation_mode():
            st.dataframe(df, hide_index=True, use_container_width=True)
        selected = st.selectbox("Unblock IP", df["ip_address"].tolist())
        if st.button("Unblock", disabled=not is_admin):
            api_post("/api/response/unblock-ip", json={"target_ip": selected, "reason": "Analyst unblock"})
            st.rerun()

    recent_df = as_frame(response_audit)
    section_label("Recent Response Audit")
    if recent_df.empty:
        empty_state("No Response Audit Events", "Simulated block and unblock actions will create audit evidence here.", tone=SOC_COLORS["blue"])
    else:
        render_timeline(response_audit, limit=8, color=SOC_COLORS["red"])

def suppressions_page():
    page_hero(
        "Threat Controls",
        "Govern suppression rules and watchlists so recurring noise is controlled without hiding useful evidence.",
        badges=["Suppression review", "Watchlist boosts", "Admin audited"],
    )
    section_label("Threat Controls")
    suppression_tab, watchlist_tab, review_tab = st.tabs(["Suppressions", "Watchlist", "Review Queue"])

    with suppression_tab:
        if current_user["role"] == "admin":
            with st.form("create_suppression"):
                c1, c2, c3 = st.columns(3)
                src_ip = c1.text_input("Source IP")
                app = c2.text_input("App")
                alert_type = c3.text_input("Alert Type")
                reason = st.text_area("Reason", height=90)
                submitted = st.form_submit_button("Create Suppression", type="primary")
            if submitted:
                api_post(
                    "/api/suppressions",
                    json={
                        "src_ip": src_ip or None,
                        "app": app or None,
                        "alert_type": alert_type or None,
                        "reason": reason,
                    },
                )
                st.rerun()
        else:
            st.info("Admin role required to create, review, or disable suppression rules.")

        rules = as_frame(api_get("/api/suppressions", active_only=False))
        if rules.empty:
            empty_state("No Suppression Rules", "Create a suppression only after confirming a noisy source/app/rule combination is known-benign.", tone=SOC_COLORS["blue"])
        else:
            c1, c2, c3 = st.columns(3)
            with c1:
                metric_card("Active Rules", int(rules["active"].sum()) if "active" in rules.columns else 0, "Currently suppressing noise", "gray")
            with c2:
                metric_card("Suppressed Hits", int(rules["suppressed_count"].sum()) if "suppressed_count" in rules.columns else 0, "Total matched suppressions", "blue")
            with c3:
                pending = len(rules[rules["review_status"].isin(["pending", "needs_changes"])]) if "review_status" in rules.columns else 0
                metric_card("Needs Review", pending, "Suppression governance queue", "amber")
            section_label("Suppression Review Queue")
            review_candidates = rules[rules["review_status"].isin(["pending", "needs_changes"])] if "review_status" in rules.columns else rules.head(0)
            if review_candidates.empty:
                empty_state("No Suppressions Need Review", "Active suppression governance is currently clear.", tone=SOC_COLORS["green"])
            else:
                for row in review_candidates.to_dict("records")[:4]:
                    st.markdown(
                        evidence_card_html(
                            f"Rule #{row.get('id')} | {row.get('src_ip') or row.get('app') or row.get('alert_type') or 'Any match'}",
                            f"Hits: {row.get('suppressed_count', 0)} | Reason: {row.get('reason', '-')}",
                            eyebrow=str(row.get("review_status") or "pending").replace("_", " ").title(),
                            color=SOC_COLORS["amber"],
                        ),
                        unsafe_allow_html=True,
                    )

            columns = [
                "id",
                "active",
                "review_status",
                "src_ip",
                "app",
                "alert_type",
                "suppressed_count",
                "last_matched_at",
                "created_by",
                "reviewed_by",
                "reason",
            ]
            display_rules = rules.copy()
            if "active" in display_rules.columns:
                display_rules["control_state"] = display_rules["active"].map(lambda value: "Active" if value else "Disabled")
            columns = [
                "id",
                "control_state",
                "review_status",
                "src_ip",
                "app",
                "alert_type",
                "suppressed_count",
                "last_matched_at",
                "created_by",
                "reviewed_by",
                "reason",
            ]
            st.dataframe(display_rules[[col for col in columns if col in display_rules.columns]], hide_index=True, use_container_width=True)
            active_rules = rules[rules["active"] == True] if "active" in rules.columns else pd.DataFrame()
            if current_user["role"] == "admin" and not rules.empty:
                selected_rule = st.selectbox("Selected Suppression", rules["id"].tolist(), key="selected_suppression")
                c1, c2 = st.columns(2)
                with c1:
                    review_status = st.selectbox("Review Status", ["pending", "reviewed", "needs_changes"], key="suppression_review_status")
                    review_notes = st.text_area("Review Notes", height=80, key="suppression_review_notes")
                    if st.button("Save Review"):
                        api_post(
                            f"/api/suppressions/{selected_rule}/review",
                            json={"review_status": review_status, "review_notes": review_notes or None},
                        )
                        st.rerun()
                with c2:
                    if not active_rules.empty:
                        disable_rule = st.selectbox("Disable Active Suppression", active_rules["id"].tolist())
                        if st.button("Disable Selected Rule"):
                            api_post(f"/api/suppressions/{disable_rule}/disable")
                            st.rerun()

    with watchlist_tab:
        if current_user["role"] == "admin":
            with st.form("create_watchlist"):
                c1, c2, c3 = st.columns(3)
                indicator_type = c1.selectbox("Indicator Type", ["src_ip", "dst_ip", "app"])
                indicator_value = c2.text_input("Indicator Value")
                severity_boost = c3.number_input("Severity Boost", min_value=5, max_value=60, value=35, step=5)
                description = st.text_area("Description", height=90)
                submitted = st.form_submit_button("Add Watchlist Indicator", type="primary")
            if submitted:
                api_post(
                    "/api/watchlists",
                    json={
                        "indicator_type": indicator_type,
                        "indicator_value": indicator_value,
                        "description": description,
                        "severity_boost": int(severity_boost),
                    },
                )
                st.rerun()
        else:
            st.info("Admin role required to create or disable watchlist indicators.")

        watchlist = as_frame(api_get("/api/watchlists", active_only=False))
        if watchlist.empty:
            empty_state("No Watchlist Indicators", "Add priority source IPs, destination IPs, or applications that should raise analyst attention.", tone=SOC_COLORS["amber"])
        else:
            c1, c2, c3 = st.columns(3)
            with c1:
                metric_card("Active Indicators", int(watchlist["active"].sum()), "Enabled watchlist entries", "amber")
            with c2:
                metric_card("Total Matches", int(watchlist["match_count"].sum()), "Detection matches", "red")
            with c3:
                metric_card("Max Boost", int(watchlist["severity_boost"].max()), "Score contribution", "blue")
            section_label("High Attention Indicators")
            top_watchlist = watchlist.sort_values(by="match_count", ascending=False).head(4) if "match_count" in watchlist.columns else watchlist.head(4)
            for row in top_watchlist.to_dict("records"):
                st.markdown(
                    evidence_card_html(
                        f"{row.get('indicator_type', '-')} = {row.get('indicator_value', '-')}",
                        f"Matches: {row.get('match_count', 0)} | Severity boost: {row.get('severity_boost', '-')} | {row.get('description', '-')}",
                        eyebrow="Watchlist Indicator",
                        color=SOC_COLORS["amber"],
                    ),
                    unsafe_allow_html=True,
                )
            columns = [
                "id",
                "control_state",
                "indicator_type",
                "indicator_value",
                "severity_boost",
                "match_count",
                "last_matched_at",
                "created_by",
                "description",
            ]
            display_watchlist = watchlist.copy()
            if "active" in display_watchlist.columns:
                display_watchlist["control_state"] = display_watchlist["active"].map(lambda value: "Active" if value else "Disabled")
            st.dataframe(display_watchlist[[col for col in columns if col in display_watchlist.columns]], hide_index=True, use_container_width=True)
            active_items = watchlist[watchlist["active"] == True] if "active" in watchlist.columns else pd.DataFrame()
            if current_user["role"] == "admin" and not active_items.empty:
                selected_item = st.selectbox("Disable Watchlist Indicator", active_items["id"].tolist())
                if st.button("Disable Indicator"):
                    api_post(f"/api/watchlists/{selected_item}/disable")
                    st.rerun()

    with review_tab:
        section_label("Suppressed And False Positive Review")
        rules = as_frame(api_get("/api/suppressions", active_only=False))
        false_positive_alerts = as_frame(api_get("/api/alerts", status="false_positive", limit=100))
        left, right = st.columns(2)
        with left:
            st.markdown("Suppression review prevents permanent hiding of useful security signals.")
            if rules.empty:
                empty_state("No Suppressions To Review", "Review entries will appear after suppression rules are created.", tone=SOC_COLORS["blue"])
            else:
                review_columns = ["id", "review_status", "active", "suppressed_count", "last_matched_at", "reason", "review_notes"]
                st.dataframe(rules[[col for col in review_columns if col in rules.columns]], hide_index=True, use_container_width=True)
        with right:
            st.markdown("False positives should feed back into suppression rules only after review.")
            if false_positive_alerts.empty:
                empty_state("No False Positive Alerts", "Alerts marked false positive will appear here for governance review.", tone=SOC_COLORS["green"])
            else:
                fp_columns = ["id", "severity", "threat_score", "src_ip", "alert_type", "title", "updated_at"]
                st.dataframe(false_positive_alerts[[col for col in fp_columns if col in false_positive_alerts.columns]], hide_index=True, use_container_width=True)


def user_admin_page():
    page_hero(
        "User Administration",
        "Manage analyst and admin accounts for the demo environment. Security-sensitive changes are restricted and audited.",
        badges=["Admin only", "JWT users", "Audited changes"],
    )
    if current_user["role"] != "admin":
        st.warning("Admin role required.")
        return
    section_label("Create User")
    with st.form("create_user"):
        c1, c2, c3 = st.columns(3)
        username = c1.text_input("Username")
        full_name = c2.text_input("Full Name")
        role = c3.selectbox("Role", ["analyst", "admin"])
        password = st.text_input("Temporary Password", type="password")
        submitted = st.form_submit_button("Create User", type="primary")
    if submitted:
        api_post(
            "/api/users",
            json={"username": username, "full_name": full_name or None, "role": role, "password": password},
        )
        st.rerun()

    section_label("Users")
    users = as_frame(api_get("/api/users"))
    if users.empty:
        empty_state("No Users", "Create an admin or analyst account to access protected workflows.", tone=SOC_COLORS["amber"])
        return
    st.dataframe(users[["id", "username", "full_name", "role", "is_active", "created_at"]], hide_index=True, use_container_width=True)

    selected = st.selectbox("Selected User", users["id"].tolist())
    c1, c2, c3 = st.columns(3)
    if c1.button("Disable User"):
        api_post(f"/api/users/{selected}/disable")
        st.rerun()
    new_role = c2.selectbox("New Role", ["analyst", "admin"], key="user_role_change")
    if c2.button("Change Role"):
        api_post(f"/api/users/{selected}/role", json={"role": new_role})
        st.rerun()
    new_password = c3.text_input("Reset Password", type="password")
    if c3.button("Reset Password"):
        api_post(f"/api/users/{selected}/reset-password", json={"new_password": new_password})
        result_card("Password Reset Recorded", "The selected user's password was reset and the admin action was audited.", status="Audited", color=SOC_COLORS["green"])


def audit_log_page():
    page_hero(
        "Audit Log",
        "Trace who did what, when, and why across authentication, alert workflow, suppressions, response, and admin operations.",
        badges=["Actor attribution", "Response proof", "Security trail"],
    )
    rows = api_get("/api/audit", limit=500)
    df = as_frame(rows)
    if df.empty:
        empty_state("No Audit Records", "Security and workflow events will appear here after users interact with the system.", tone=SOC_COLORS["amber"])
    else:
        c1, c2, c3 = st.columns(3)
        with c1:
            metric_card("Audit Events", len(df), "Latest records loaded", "teal")
        with c2:
            actors = df["actor"].nunique() if "actor" in df.columns else 0
            metric_card("Actors", actors, "Users and services", "blue")
        with c3:
            actions = df["action"].nunique() if "action" in df.columns else 0
            metric_card("Action Types", actions, "Tracked operations", "amber")
        c1, c2, c3 = st.columns(3)
        actor = c1.selectbox("Actor", [""] + sorted(df["actor"].dropna().unique().tolist())) if "actor" in df.columns else ""
        action = c2.selectbox("Action", [""] + sorted(df["action"].dropna().unique().tolist())) if "action" in df.columns else ""
        target_type = c3.selectbox("Target Type", [""] + sorted(df["target_type"].dropna().unique().tolist())) if "target_type" in df.columns else ""
        filtered = df.copy()
        if actor:
            filtered = filtered[filtered["actor"] == actor]
        if action:
            filtered = filtered[filtered["action"] == action]
        if target_type:
            filtered = filtered[filtered["target_type"] == target_type]
        chart_left, chart_right = st.columns(2)
        with chart_left:
            if "action" in filtered.columns:
                action_rows = filtered["action"].value_counts().head(8).reset_index()
                horizontal_bar_chart(
                    "Audit Actions",
                    [{"name": row["action"], "count": row["count"]} for _, row in action_rows.iterrows()],
                    color=SOC_COLORS["cyan"],
                )
        with chart_right:
            if "actor" in filtered.columns:
                actor_rows = filtered["actor"].value_counts().head(8).reset_index()
                horizontal_bar_chart(
                    "Audit Actors",
                    [{"name": row["actor"], "count": row["count"]} for _, row in actor_rows.iterrows()],
                    color=SOC_COLORS["amber"],
                )
        section_label("Recent Audit Timeline")
        render_timeline(filtered.to_dict("records"), limit=10, color=SOC_COLORS["cyan"])
        columns = ["created_at", "actor", "action", "target_type", "target_value", "details"]
        section_label("Audit Evidence Table")
        st.dataframe(filtered[[col for col in columns if col in filtered.columns]], hide_index=True, use_container_width=True)


def demo_controls_page():
    page_hero(
        "Demo Controls",
        "Prepare a repeatable supervisor demo from clean data reset through detection, ML scoring, audit proof, and evidence bundle export.",
        badges=["Admin only", "Repeatable demo", "Evidence export"],
    )
    section_label("Demo Operations")
    if current_user["role"] != "admin":
        st.warning("Admin role required for demo operations.")
        return

    health = api_get("/health")
    summary = api_get("/api/dashboard/summary")
    ml_report = api_get("/api/ml/report")
    audit_rows = api_get("/api/audit", limit=5)
    section_label("Pre-Demo Readiness")
    readiness_grid(demo_readiness_items(health, summary, ml_report, audit_rows))

    limit = st.number_input("Operation Limit", min_value=0, max_value=100000, value=5000, step=500)
    use_ml = st.checkbox("Use ML during detection", value=False)
    payload = {"limit": int(limit) if limit else 0, "sample_path": None}
    st.markdown(
        """
        <div class="atdr-mini-note">
            Use this page to prepare a clean supervisor demo: reset/import, run detection, optionally refresh ML,
            then export the evidence bundle for your report appendix.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        mission_path_html(
            [
                {"label": "Reset", "proof": "Clean state", "detail": "Clear demo records before the presentation."},
                {"label": "Import", "proof": "Palo Alto logs", "detail": "Load sample firewall evidence."},
                {"label": "Detect", "proof": "Grouped alerts", "detail": "Create explainable findings."},
                {"label": "Train", "proof": "Baseline model", "detail": "Optional IsolationForest refresh."},
                {"label": "Score", "proof": "Anomaly flags", "detail": "Apply assistive ML scoring."},
                {"label": "Export", "proof": "Demo bundle", "detail": "Generate appendix evidence."},
            ]
        ),
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        if st.button("Reset Demo Data"):
            result = api_post("/api/demo/reset", json={"limit": payload["limit"], "use_ml": use_ml})
            render_operation_result(result, title="Demo Data Reset", success_detail="Demo state was reset.")
        if st.button("Import Sample Logs"):
            result = api_post("/api/demo/import-sample", json=payload)
            render_operation_result(result, title="Sample Logs Imported")
    with c2:
        if st.button("Run Detection"):
            result = api_post("/api/demo/run-detection", json={"limit": payload["limit"], "use_ml": use_ml})
            render_operation_result(result, title="Detection Completed")
        if st.button("Train ML Model"):
            result = api_post("/api/demo/train-ml", json=payload)
            render_operation_result(result, title="ML Training Completed")
    with c3:
        if st.button("Apply ML Scoring"):
            result = api_post("/api/demo/apply-ml", json=payload)
            render_operation_result(result, title="ML Scoring Completed")
    with c4:
        alert_id = st.number_input("Report Alert ID", min_value=0, value=0, step=1)
        if st.button("Generate Demo Evidence Bundle", type="primary"):
            result = api_post(
                "/api/demo/export-bundle",
                json={"alert_id": int(alert_id) if alert_id else None, "top_alert_limit": 10, "audit_limit": 50},
            )
            counts = result.get("counts", {})
            result_card(
                "Demo Evidence Bundle Generated",
                f"Export directory: {result.get('export_dir')} | Top alerts: {counts.get('top_alerts', '-')} | Audit events: {counts.get('audit_events', '-')}",
                status="Ready",
                color=SOC_COLORS["green"],
            )


def ml_governance_page():
    page_hero(
        "ML Governance",
        "Monitor IsolationForest as an assistive prioritization layer while keeping rule explanations and analyst judgment primary.",
        badges=["Assistive AI", "Baseline aware", "Drift monitored"],
    )
    report = api_get("/api/ml/report")
    status = report["model_status"]
    profile = report["dataset_profile"]
    st.markdown(
        evidence_card_html(
            "AI Is Assistive, Not Authoritative",
            "IsolationForest helps prioritize unusual traffic. Analysts should validate anomalies with rules, raw evidence, and network context before response actions.",
            eyebrow="ML Governance",
            color=SOC_COLORS["amber"],
        ),
        unsafe_allow_html=True,
    )
    section_label("Model Readiness")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Artifact", "Ready" if status["artifact_exists"] else "Missing", "Saved model file", "green" if status["artifact_exists"] else "amber")
    with c2:
        metric_card("Current Anomalies", status["current_anomaly_logs"], "Flagged normalized logs", "blue")
    with c3:
        metric_card("Anomaly Rate", f"{status['current_anomaly_rate']}%", "Across stored logs", "amber")
    with c4:
        metric_card("Contamination", status["contamination"], "Expected anomaly ratio", "gray")

    section_label("Dataset Profile")
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        metric_card("Total Logs", profile["total_logs"], "Available for analysis", "teal")
    with p2:
        metric_card("Baseline Candidates", profile["baseline_candidate_count"], "Safer training pool", "green")
    with p3:
        metric_card("High Risk Logs", profile["high_risk_logs"], f"{profile['high_risk_rate']}% of logs", "red")
    with p4:
        metric_card("Deny/Drop Logs", profile["deny_drop_logs"], f"{profile['deny_drop_rate']}% of logs", "amber")

    if profile.get("recommendations"):
        with st.expander("Training Recommendations", expanded=not is_presentation_mode()):
            for recommendation in profile["recommendations"]:
                st.markdown(
                    evidence_card_html("Training Recommendation", recommendation, eyebrow="Baseline Guidance", color=SOC_COLORS["amber"]),
                    unsafe_allow_html=True,
                )

    section_label("Evaluation Report")
    r1, r2, r3, r4 = st.columns(4)
    with r1:
        metric_card("Scored Logs", report["scored_log_count"], "Logs with ML score", "teal")
    with r2:
        metric_card("Anomalies", report["anomaly_count"], "Currently flagged", "blue")
    with r3:
        delta = report["run_comparison"].get("anomaly_rate_delta")
        metric_card("Rate Delta", "-" if delta is None else f"{delta}%", "Latest vs previous scoring", "amber")
    with r4:
        anomaly_stats = report.get("score_stats_anomalies", {})
        metric_card("Lowest Score", anomaly_stats.get("min"), "Lower means more unusual", "gray")

    st.info(report["run_comparison"]["interpretation"])
    if report.get("recommendations"):
        with st.expander("Evaluation Recommendations", expanded=False):
            for recommendation in report["recommendations"]:
                st.markdown(
                    evidence_card_html("Evaluation Recommendation", recommendation, eyebrow="ML Review", color=SOC_COLORS["blue"]),
                    unsafe_allow_html=True,
                )

    drift_signals = as_frame(report.get("drift_signals", []))
    if not drift_signals.empty:
        section_label("Baseline Drift Monitoring")
        for row in drift_signals.to_dict("records")[:6]:
            level = str(row.get("level") or "info").lower()
            st.markdown(
                evidence_card_html(
                    row.get("metric", "Drift Signal"),
                    f"Training: {row.get('training_value', '-')} | Current: {row.get('current_value', '-')} | Delta: {row.get('delta_pct', '-')}% | {row.get('message', '-')}",
                    eyebrow=level.title(),
                    color=SOC_COLORS["red"] if level == "high" else SOC_COLORS["amber"],
                ),
                unsafe_allow_html=True,
            )

    latest_training = status.get("latest_training")
    latest_scoring = status.get("latest_scoring")
    left, right = st.columns(2)
    with left:
        section_label("Latest Training")
        if latest_training:
            detail_grid(
                [
                    {"label": "Status", "value": latest_training.get("status")},
                    {"label": "Version", "value": latest_training.get("model_version")},
                    {"label": "Trained By", "value": latest_training.get("actor")},
                    {"label": "Training Logs", "value": latest_training.get("training_log_count")},
                    {"label": "Created At", "value": latest_training.get("created_at")},
                    {"label": "Message", "value": latest_training.get("message")},
                ]
            )
        else:
            empty_state("No Training Run", "Train the model from a baseline candidate window before relying on anomaly scores.", tone=SOC_COLORS["amber"])
    with right:
        section_label("Latest Scoring")
        if latest_scoring:
            detail_grid(
                [
                    {"label": "Status", "value": latest_scoring.get("status")},
                    {"label": "Scored Logs", "value": latest_scoring.get("scored_log_count")},
                    {"label": "Anomalies", "value": latest_scoring.get("anomaly_count")},
                    {"label": "Anomaly Rate", "value": latest_scoring.get("anomaly_rate")},
                    {"label": "Created At", "value": latest_scoring.get("created_at")},
                    {"label": "Message", "value": latest_scoring.get("message")},
                ]
            )
        else:
            empty_state("No Scoring Run", "Apply scoring after training to refresh anomaly flags on normalized logs.", tone=SOC_COLORS["blue"])

    section_label("Feature Set")
    features = as_frame([{"feature": feature} for feature in status.get("feature_columns", [])])
    if features.empty:
        empty_state("No Feature Metadata", "Feature names will appear after the ML detector is configured or trained.", tone=SOC_COLORS["gray"])
    else:
        detail_grid([{"label": "Feature", "value": row["feature"]} for row in features.to_dict("records")[:12]])

    if current_user["role"] == "admin":
        section_label("Admin Operations")
        limit = st.number_input("Training/Scoring Limit", min_value=1, max_value=100000, value=5000, step=500)
        baseline_only = st.checkbox("Baseline-only training", value=True)
        b1, b2, b3 = st.columns(3)
        with b1:
            max_app_risk = st.number_input("Max App Risk", min_value=1, max_value=5, value=3, step=1)
        with b2:
            exclude_unknown = st.checkbox("Exclude unknown apps", value=True)
        with b3:
            exclude_existing = st.checkbox("Exclude existing anomalies", value=True)
        training_payload = {
            "limit": int(limit),
            "baseline_only": baseline_only,
            "max_app_risk": int(max_app_risk),
            "exclude_unknown_apps": exclude_unknown,
            "exclude_existing_anomalies": exclude_existing,
        }
        left, right = st.columns(2)
        with left:
            if st.button("Train Model", type="primary"):
                result = api_post("/api/ml/train", json=training_payload)
                render_operation_result(result, title="Model Training Completed")
        with right:
            if st.button("Apply Scoring"):
                result = api_post("/api/ml/score", json={"limit": int(limit)})
                render_operation_result(result, title="ML Scoring Completed")
    else:
        st.info("Admin role required to train or score the ML model.")

    section_label("Dataset Distributions")
    dist_left, dist_mid, dist_right = st.columns(3)
    with dist_left:
        horizontal_bar_chart("Actions", profile.get("action_distribution", []), color=SOC_COLORS["teal"])
    with dist_mid:
        horizontal_bar_chart("App Risk", profile.get("app_risk_distribution", []), color="#f97316")
    with dist_right:
        horizontal_bar_chart("Top Apps", profile.get("top_apps", []), color=SOC_COLORS["blue"])

    section_label("Anomalous Patterns")
    a1, a2, a3 = st.columns(3)
    with a1:
        horizontal_bar_chart("Anomalous Source IPs", report.get("top_anomalous_src_ips", []), color=SOC_COLORS["red"])
    with a2:
        horizontal_bar_chart("Anomalous Apps", report.get("top_anomalous_apps", []), color=SOC_COLORS["amber"])
    with a3:
        horizontal_bar_chart("Anomalous Ports", report.get("top_anomalous_dst_ports", []), color=SOC_COLORS["cyan"])

    samples = as_frame(report.get("sample_anomalies", []))
    if not samples.empty:
        section_label("Most Unusual Sample Logs")
        sample_columns = [
            "id",
            "generated_time",
            "src_ip",
            "dst_ip",
            "app",
            "action",
            "protocol",
            "dst_port",
            "app_risk",
            "anomaly_score",
        ]
        if is_presentation_mode():
            for row in samples.to_dict("records")[:5]:
                st.markdown(
                    evidence_card_html(
                        f"Log #{row.get('id')} | Score {row.get('anomaly_score')}",
                        f"{row.get('src_ip', '-')} -> {row.get('dst_ip', '-')} | App: {row.get('app', '-')} | Port: {row.get('dst_port', '-')}",
                        eyebrow="Anomalous Sample",
                        color=SOC_COLORS["amber"],
                    ),
                    unsafe_allow_html=True,
                )
        else:
            st.dataframe(samples[[col for col in sample_columns if col in samples.columns]], hide_index=True, use_container_width=True)

    section_label("Model Run History")
    runs = as_frame(api_get("/api/ml/runs", limit=30))
    if runs.empty:
        empty_state("No Model Runs", "Training and scoring history will appear after admin ML operations.", tone=SOC_COLORS["amber"])
    else:
        columns = [
            "id",
            "operation",
            "status",
            "actor",
            "model_version",
            "training_log_count",
            "scored_log_count",
            "anomaly_count",
            "anomaly_rate",
            "created_at",
            "message",
        ]
        if is_presentation_mode():
            render_timeline(
                [
                    {
                        "created_at": row.get("created_at"),
                        "action": f"{row.get('operation', '-')} / {row.get('status', '-')}",
                        "details": f"Actor: {row.get('actor', '-')} | Scored: {row.get('scored_log_count', '-')} | Anomalies: {row.get('anomaly_count', '-')}",
                    }
                    for row in runs.to_dict("records")
                ],
                limit=8,
                color=SOC_COLORS["blue"],
            )
        else:
            st.dataframe(runs[[col for col in columns if col in runs.columns]], hide_index=True, use_container_width=True)


try:
    health = api_get("/health")
    health_status = health["status"]
except requests.RequestException as exc:
    app_header("Offline", {"username": "guest", "role": "offline"}, "unavailable")
    show_api_error(f"API is unavailable at {API_BASE_URL}", exc)
    st.stop()

if not st.session_state.get("access_token"):
    app_header("Sign In", {"username": "guest", "role": "guest"}, health_status)
current_user = require_login()
sidebar_brand(health_status)
st.sidebar.write(f"{current_user['username']} ({current_user['role']})")
presentation_mode = st.sidebar.toggle(
    "Presentation Mode",
    value=st.session_state.get("presentation_mode", presentation_mode_default()),
    help="Keeps the dashboard cleaner for supervisor demo screenshots while leaving technical evidence accessible.",
)
st.session_state["presentation_mode"] = presentation_mode
if st.sidebar.button("Logout"):
    st.session_state.pop("access_token", None)
    st.session_state.pop("current_user", None)
    st.rerun()

pages = ["Executive Demo", "Overview", "Log Explorer", "Alerts", "ML Governance", "Threat Controls", "Response Center", "Audit Log"]
if current_user["role"] == "admin":
    pages.extend(["User Admin", "Demo Controls"])
page = st.sidebar.radio("Workspace", pages)
st.sidebar.caption(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
app_header(page, current_user, health_status)

try:
    if page == "Executive Demo":
        executive_demo_page()
    elif page == "Overview":
        overview_page()
    elif page == "Log Explorer":
        log_explorer_page()
    elif page == "Alerts":
        alerts_page()
    elif page == "ML Governance":
        ml_governance_page()
    elif page == "Threat Controls":
        suppressions_page()
    elif page == "Response Center":
        response_center_page()
    elif page == "User Admin":
        user_admin_page()
    elif page == "Demo Controls":
        demo_controls_page()
    else:
        audit_log_page()
except requests.HTTPError as exc:
    show_api_error("API request failed", exc)
except requests.RequestException as exc:
    show_api_error("Could not reach API", exc)
