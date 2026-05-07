"""ui.py — Shared UI helpers and theme constants."""

from contextlib import contextmanager
import streamlit as st

NEON_GREEN = "#00ff88"
NEON_RED   = "#ff2d55"
NEON_BLUE  = "#00cfff"


def inject_css():
    st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@400;600;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
        background: radial-gradient(circle at center, #0B1120 0%, #000000 100%);
        background-color: #0b1120;
        background-image:
            linear-gradient(rgba(0,255,242,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,242,0.03) 1px, transparent 1px);
        background-size: 40px 40px;
        animation: cyber-pulse 4s linear infinite;
        color: #e0e6ed;
    }}
    @keyframes cyber-pulse {{
        0%   {{ background-position: 0 0; }}
        100% {{ background-position: 40px 40px; }}
    }}
    .glass-card {{
        background: rgba(17,25,40,0.7);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 8px 32px 0 rgba(0,0,0,0.8);
        transition: border 0.3s ease, box-shadow 0.3s ease;
    }}
    .fleet-card {{
        background: rgba(17,25,40,0.7);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
        text-align: center;
        transition: all 0.2s ease-in-out;
        box-shadow: 0 8px 32px 0 rgba(0,0,0,0.8);
    }}
    .fleet-card:hover {{
        border: 1px solid {NEON_GREEN};
        box-shadow: 0 0 15px rgba(0,255,242,0.4);
    }}
    .neon-safe      {{ border: 1px solid rgba(0,255,242,0.4) !important; box-shadow: 0 0 10px rgba(0,255,242,0.1) !important; }}
    .neon-compromised {{ border: 1px solid rgba(255,0,127,0.5) !important; box-shadow: 0 0 15px rgba(255,0,127,0.4) !important; }}
    @keyframes pulse {{
        0%   {{ box-shadow: 0 0 0 0   rgba(255,0,127,0.6); }}
        70%  {{ box-shadow: 0 0 0 20px rgba(255,0,127,0);  }}
        100% {{ box-shadow: 0 0 0 0   rgba(255,0,127,0);  }}
    }}
    .pulse-red {{ animation: pulse 2s infinite !important; border: 1px solid #ff007f !important; }}
    @keyframes pulse-stress {{
        0%   {{ border: 1px solid rgba(255,0,127,0.4); box-shadow: 0 0 0 0   rgba(255,0,127,0.4); }}
        70%  {{ border: 1px solid rgba(255,0,127,1);   box-shadow: 0 0 10px 5px rgba(255,0,127,0); }}
        100% {{ border: 1px solid rgba(255,0,127,0.4); box-shadow: 0 0 0 0   rgba(255,0,127,0);  }}
    }}
    .pulse-stress {{ animation: pulse-stress 1.5s infinite !important; }}
    @keyframes blinker {{ 50% {{ opacity: 0; }} }}
    div.stButton > button {{
        background: transparent !important;
        border: 1px solid #00fff2 !important;
        color: #00fff2 !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
    }}
    div.stButton > button:hover {{
        background: rgba(0,255,242,0.1) !important;
        box-shadow: 0 0 10px rgba(0,255,242,0.5) !important;
    }}
    .section-header {{
        font-family: 'Source Code Pro', monospace;
        font-size: 1.1rem;
        font-weight: 700;
        margin-bottom: 15px;
        color: {NEON_GREEN};
        text-transform: uppercase;
        letter-spacing: 1.2px;
    }}
    [data-testid="stSidebar"] {{
        background-color: rgba(11,17,32,0.85);
        backdrop-filter: blur(12px);
        border-right: 1px solid rgba(255,255,255,0.1);
    }}
    h1, h2, h3 {{ color: white !important; font-family: 'Source Code Pro', monospace !important; text-transform: uppercase; }}
    .stDataFrame {{ background: transparent !important; }}
    div[data-testid="stVerticalBlockBorderWrapper"] > div {{
        background: rgba(17,25,40,0.7) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 16px !important;
        box-shadow: 0 8px 32px 0 rgba(0,0,0,0.8) !important;
        padding: 24px !important;
        margin-bottom: 24px !important;
        transition: border 0.3s ease, box-shadow 0.3s ease !important;
    }}
    .attack-progress {{
        background: rgba(255,0,127,0.15);
        border: 1px solid rgba(255,0,127,0.4);
        border-radius: 8px;
        padding: 10px 12px;
        margin-top: 8px;
        font-size: 0.85em;
        color: #ff007f;
    }}
</style>""", unsafe_allow_html=True)


@contextmanager
def glass_card(extra_class: str = "", extra_style: str = ""):
    """Wraps content in a styled container using Streamlit's native border container.

    Uses st.container(border=True) so there are no stray empty markdown blocks,
    then overrides the default border appearance via injected CSS to match the
    glass-card design. extra_class / extra_style are stored as data attributes
    so callers can still pass pulse/stress classes — those animations are applied
    via a zero-height marker div that precedes the container.
    """
    classes   = f"glass-card {extra_class}".strip()
    has_extra = bool(extra_class or extra_style)

    if has_extra:
        # A single fully self-contained div (open+close in one markdown call)
        # used purely as a CSS animation/style hook — zero height, no visible box.
        st.markdown(
            f'<div class="{classes}" style="height:0;min-height:0;padding:0;'
            f'margin:0;overflow:hidden;{extra_style}"></div>',
            unsafe_allow_html=True,
        )

    with st.container(border=True):
        yield


def section_header(title: str, right_html: str = ""):
    inner = f"<span>{title}</span>{right_html}"
    style = "display:flex;justify-content:space-between;" if right_html else ""
    st.markdown(
        f'<div class="section-header" style="{style}">{inner}</div>',
        unsafe_allow_html=True,
    )