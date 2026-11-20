"""
Payment-Run Provenance Guard — dashboard.   Run:  streamlit run app.py
"""
import hashlib
import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from engine.auth import (ROLES, can, change_own_password, create_user, load_users, reset_password, set_active,
                         verify)
from engine.guard import RULES, Settings, evaluate, load_folder, load_uploads, metrics
from engine.report import build_report
from engine.tour import tour_script
import streamlit.components.v1 as components
from engine.workflow import FINAL, STATUS_TEXT, Workflow

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "data" / "sample"
STATE = ROOT / "state"
RULES_FILE = STATE / "rules.json"
RED, BLACK, GREY, LIGHT = "#C8102E", "#161616", "#8C8C8C", "#F5F5F5"
AMBER, GREEN, NAVY = "#D97706", "#2E7D32", "#161616"
DEC_COLOR = {"HOLD": RED, "REVIEW": AMBER, "ALLOW": "#7FA98A"}
DEC_WORD = {"HOLD": "Payment stopped", "REVIEW": "Needs a second look", "ALLOW": "Safe to pay"}

st.set_page_config(page_title="Provenance Guard · CR-26-047", page_icon="🛡️", layout="wide")
st.markdown(f"""
<style>
html, body, [class*="css"] {{font-family: "Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif;}}
.stApp {{background:{LIGHT};}}
.block-container {{padding-top: 2.6rem; max-width: 1400px;}}
header[data-testid="stHeader"] {{background:transparent;}}
section[data-testid="stSidebar"] {{background:white; border-right:1px solid #E2E2E2;}}
.pg-bar {{background:linear-gradient(110deg,#0E0E0E 0%,#1C1C1C 65%,#2A2A2A 100%); color:white; padding:18px 26px;
  border-radius:14px; display:flex; align-items:center; gap:18px; box-shadow:0 6px 18px rgba(0,0,0,.18);
  border-bottom:4px solid {RED};}}
.pg-bar .logo {{font-size:2.3rem; line-height:1;}}
.pg-bar h1 {{color:white; font-size:1.55rem; margin:0; padding:0; font-weight:700; letter-spacing:.2px;}}
.pg-bar p {{color:#BDBDBD; margin:3px 0 0 0; font-size:.93rem;}}
.pg-bar .tag {{margin-left:auto; background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.25);
  padding:6px 12px; border-radius:20px; font-size:.82rem; color:#EDEDED; white-space:nowrap;}}
div[role="tablist"] {{gap:4px; background:white; padding:6px; border-radius:12px; border:1px solid #E2E2E2;
  flex-wrap:wrap !important; overflow:visible !important;}}
.stTabs [data-testid="stTab"] {{border-radius:8px; padding:7px 13px; margin:0 !important;}}
.stTabs [data-testid="stTab"]:hover {{background:#F0F0F0;}}
.stTabs [data-testid="stTab"][aria-selected="true"] {{background:{NAVY};}}
.stTabs [data-testid="stTab"][aria-selected="true"] p {{color:white !important; font-weight:600;}}
.stTabs [data-testid="stTab"]::after, .stTabs [data-testid="stTab"]::before {{display:none !important;}}
.pg-card {{background:white; border:1px solid #E2E2E2; border-radius:12px; padding:16px 18px;
  box-shadow:0 1px 3px rgba(16,24,40,.05); height:100%;}}
.pg-kpi {{background:white; border:1px solid #E2E2E2; border-radius:12px; padding:14px 16px;
  border-top:4px solid {NAVY}; box-shadow:0 1px 3px rgba(16,24,40,.05); min-height:118px;}}
.pg-kpi .v {{font-size:2rem; font-weight:700; color:{NAVY}; line-height:1.1;}}
.pg-kpi .l {{font-size:.85rem; color:#5C5C5C; margin-top:2px;}}
.pg-kpi .s {{font-size:.78rem; color:#8C8C8C;}}
.pg-kpi.hold {{border-top-color:{RED};}} .pg-kpi.hold .v {{color:{RED};}}
.pg-kpi.review {{border-top-color:{AMBER};}} .pg-kpi.review .v {{color:{AMBER};}}
.pg-kpi.allow {{border-top-color:{GREEN};}} .pg-kpi.allow .v {{color:{GREEN};}}
.pg-intro {{background:white; border-left:5px solid {NAVY}; border-radius:8px; padding:10px 16px; margin:4px 0 14px 0;
  color:#334; font-size:.95rem; border:1px solid #E2E2E2; border-left-width:5px;}}
.pg-step {{border-left:6px solid {GREEN}; background:white; padding:10px 14px; margin:7px 0; border-radius:8px;
  border-top:1px solid #E6E6E6; border-right:1px solid #E6E6E6; border-bottom:1px solid #E6E6E6;}}
.pg-step.bad {{border-left-color:{RED}; background:#FFF5F6;}}
.pg-step.good {{border-left-color:{GREEN};}}
.pg-pill {{display:inline-block; padding:3px 12px; border-radius:14px; color:white; font-weight:700; font-size:.82rem;
  letter-spacing:.3px; vertical-align:middle;}}
.pg-test {{background:#FFF8E1; border:1px solid #F0D58A; padding:8px 14px; border-radius:10px; font-size:.88rem;
  margin:10px 0 6px 0;}}
.pg-user {{background:{NAVY}; color:white; padding:12px 14px; border-radius:10px; border-left:5px solid {RED};}}
.pg-user b {{font-size:1.05rem;}}
.pg-user span {{color:#BDBDBD; font-size:0.85rem;}}
.pg-hist {{font-size:0.9rem; color:#444; border-left:3px solid #DDD; padding-left:10px; margin:6px 0;}}
.pg-how {{display:flex; gap:12px; margin:8px 0 4px 0;}}
.pg-how .b {{flex:1; background:white; border:1px solid #E2E2E2; border-radius:12px; padding:14px 16px;}}
.pg-how .n {{display:inline-block; width:28px; height:28px; border-radius:50%; background:{NAVY}; color:white;
  text-align:center; line-height:28px; font-weight:700; margin-bottom:6px;}}
.pg-how h4 {{margin:2px 0 4px 0; font-size:1.02rem; color:{NAVY};}}
.pg-how p {{margin:0; color:#4A4A4A; font-size:.9rem;}}
.pg-big {{border-radius:14px; padding:18px 22px; color:white; margin-bottom:10px;}}
.pg-big h2 {{color:white; margin:0; font-size:1.7rem;}} .pg-big p {{margin:4px 0 0 0; color:rgba(255,255,255,.88);}}
.pg-held {{background:white; border:1px solid #F1C9CF; border-left:6px solid {RED}; border-radius:10px;
  padding:10px 14px; margin:6px 0;}}
.pg-held b {{color:{NAVY};}} .pg-held .why {{color:#5C5C5C; font-size:.86rem;}}
.pg-login-h {{font-size:1.6rem; font-weight:700; color:{NAVY}; margin-top:18px;}}
.pg-login-s {{color:#5C5C5C; font-size:.92rem; margin-bottom:10px; border-left:3px solid {RED}; padding-left:10px;}}
.pg-legend span {{margin-right:14px; font-size:.88rem;}}
@media (max-width: 800px) {{
  .block-container {{padding:3.2rem .7rem 2rem .7rem;}}
  .pg-bar {{flex-wrap:wrap; padding:14px 16px; gap:10px;}}
  .pg-bar .logo {{font-size:1.7rem;}}
  .pg-bar h1 {{font-size:1.15rem;}}
  .pg-bar p {{font-size:.82rem;}}
  .pg-bar .tag {{margin-left:0; white-space:normal; font-size:.72rem;}}
  .pg-how {{flex-direction:column;}}
  .pg-big {{padding:14px 16px;}}
  .pg-big h2 {{font-size:1.2rem;}}
  .pg-kpi {{min-height:0; margin-bottom:8px;}}
  .pg-kpi .v {{font-size:1.6rem;}}
  div[role="tablist"] {{flex-wrap:nowrap !important; overflow-x:auto !important;}}
  .stTabs [data-testid="stTab"] {{padding:6px 9px; flex:0 0 auto;}}
  .pg-legend span {{display:inline-block; margin:4px 10px 4px 0;}}
}}
div[data-testid="stExpander"] {{background:white; border-radius:10px;}}
</style>
""", unsafe_allow_html=True)

BAR = """<div class="pg-bar"><div class="logo">🛡️</div><div><h1>Payment-Run Provenance Guard</h1>
<p>Checks where every vendor bank-detail change came from, and stops the payment if the trail doesn't hold up</p></div>
<div class="tag">CR-26-047 · Harbor &amp; Finch Freight · Team Brute Force</div></div>"""


def intro(text):
    st.markdown(f'<div class="pg-intro">{text}</div>', unsafe_allow_html=True)


def kpi(col, value, label, sub="", kind=""):
    col.markdown(f'<div class="pg-kpi {kind}"><div class="v">{value}</div><div class="l">{label}</div>'
                 f'<div class="s">{sub}</div></div>', unsafe_allow_html=True)


def pill(dec, color=None):
    return f'<span class="pg-pill" style="background:{color or DEC_COLOR.get(dec, GREY)}">{dec}</span>'


# ================================================================== sign-in
ss = st.session_state
if "user" not in ss:
    st.markdown(BAR, unsafe_allow_html=True)
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown('<div class="pg-login-h">Sign in</div><div class="pg-login-s">Authorised Harbor &amp; Finch '
                    'staff only. Every attempt is logged.</div>', unsafe_allow_html=True)
        with st.form("login"):
            un = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            ok = st.form_submit_button("Sign in", type="primary", width="stretch")
        if ok:
            user = verify(un, pw)
            wf_login = Workflow(STATE, "auth")
            if user:
                ss.user = user
                wf_login.log(user, "sign in")
                st.rerun()
            else:
                wf_login.log({"username": un or "-", "name": "-", "role": None}, "sign in", result="denied",
                             detail="wrong username or password, or account disabled")
                st.error("Sign-in failed. Check your username and password, or contact IT Security.")
        st.caption("No account? Accounts are created only by IT Security. Ask your IT Security Administrator; "
                   "you'll get a temporary password to change on first sign-in.")
    st.stop()

user = ss.user
role = ROLES[user["role"]]

if user.get("must_change"):
    st.markdown(BAR, unsafe_allow_html=True)
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown(f'<div class="pg-login-h">Set your own password</div><div class="pg-login-s">Welcome, '
                    f'{user["name"]}. IT Security gave you a temporary password; choose your own before '
                    f'continuing.</div>', unsafe_allow_html=True)
        with st.form("pwchange"):
            old_pw = st.text_input("Temporary password", type="password")
            new_pw = st.text_input("New password", type="password",
                                   help="At least 10 characters with upper- and lower-case letters, a number and a symbol.")
            new_pw2 = st.text_input("Repeat new password", type="password")
            ok2 = st.form_submit_button("Save password", type="primary", width="stretch")
        if ok2:
            err = "The two new passwords don't match." if new_pw != new_pw2 else change_own_password(user, old_pw, new_pw)
            if err:
                st.error(err)
            else:
                Workflow(STATE, "auth").log(user, "change own password")
                ss.user = dict(user, must_change=False)
                st.rerun()
        if st.button("Sign out", width="stretch"):
            for k in list(ss.keys()):
                del ss[k]
            st.rerun()
    st.stop()

# ================================================================== rules (shared, saved by IT Security)
DEFAULTS = dict(hold=60, review=30, window=3, watch=7, exp_nets="10.20.4.0/24", int_nets="172.16.0.0/16",
                min_days=3, **{f"on_{k}": True for k in RULES}, **{f"w_{k}": v[1] for k, v in RULES.items()},
                e02_offset=-330, e05_offset=0)


def saved_rules():
    r = dict(DEFAULTS)
    if RULES_FILE.exists():
        r.update({k: v for k, v in json.loads(RULES_FILE.read_text()).items() if k in DEFAULTS})
    return r


if not can(user, "settings") or not ss.get("rules_loaded"):
    for k, v in saved_rules().items():
        ss[k] = v
    ss.rules_loaded = True

settings = Settings(
    hold_threshold=ss.hold, review_threshold=ss.review, risk_window_days=ss.window, watch_window_days=ss.watch,
    expected_networks=[x.strip() for x in ss.exp_nets.split(",") if x.strip()],
    internal_networks=[x.strip() for x in ss.int_nets.split(",") if x.strip()],
    behaviour_min_days=ss.min_days, clock_offsets={"E02": ss.e02_offset, "E05": ss.e05_offset},
    enabled={k: ss[f"on_{k}"] for k in RULES}, weights={k: ss[f"w_{k}"] for k in RULES})

# ================================================================== sidebar
with st.sidebar:
    st.markdown(f'<div class="pg-user"><b>{user["name"]}</b><br><span>{role["title"]}</span></div>',
                unsafe_allow_html=True)
    st.caption(role["duty"])
    if st.button("Sign out", width="stretch"):
        Workflow(STATE, "auth").log(user, "sign out")
        for k in list(ss.keys()):
            del ss[k]
        st.rerun()
    st.divider()
    st.header("Data")
    source = st.radio("Source", ["Sample test data", "Upload evidence files"], index=0)
    uploads = None
    if source == "Upload evidence files":
        uploads = st.file_uploader("CSV / JSON files named E19…, E18…, E01…, E03…, E04…, E15…, E17…",
                                   type=["csv", "json"], accept_multiple_files=True)
    st.caption("Required: E19. Recommended: E18 + E01, E03, E04, E15, E17.")


@st.cache_data(show_spinner=False)
def _sample():
    return load_folder(SAMPLE)


@st.cache_data(show_spinner="Rebuilding provenance chains…")
def _run(data, settings_json):
    return evaluate(data, Settings(**json.loads(settings_json)))


data = _sample() if source == "Sample test data" else load_uploads(uploads or [])
if "E19" not in data:
    st.markdown(BAR, unsafe_allow_html=True)
    st.info("Upload at least the E19 vendor change log, or switch to the sample test data in the sidebar.")
    st.stop()

dataset_id = "sample" if source == "Sample test data" else \
    "upload_" + hashlib.md5(data["E19"].to_csv(index=False).encode()).hexdigest()[:10]
wf = Workflow(STATE, dataset_id)

decisions, clocks = _run(data, json.dumps(settings.__dict__, default=list))
labels = data.get("LABELS")
m = metrics(decisions, labels)
bank = decisions[decisions["is_bank"]].copy()
queue_state = wf.all()
bank["workflow"] = [STATUS_TEXT[wf.status_of(queue_state.get(c, {}), d)] if d in ("HOLD", "REVIEW") else ""
                    for c, d in zip(bank["change_id"], bank["decision"])]

with st.sidebar:
    if can(user, "release"):
        st.divider()
        if st.button("Reset demo queue", width="stretch", help="Clears every call-back and decision (demo only)."):
            wf.reset(user)
            st.rerun()

_gl, _gr = st.columns([6, 1])
with _gr:
    if st.button("🧭 Guide", key="guide_btn", type="primary", width="stretch",
                 help="Take a guided tour of the tabs that matter for your role"):
        ss.tour_nonce = ss.get("tour_nonce", 0) + 1
st.markdown(BAR, unsafe_allow_html=True)
if labels is not None:
    st.markdown('<div class="pg-test">⚠️ <b>Test data.</b> The sample dataset is synthetic, built in the case file '
                'formats with planted attacks. Results here are not findings from the case evidence.</div>',
                unsafe_allow_html=True)
if ss.get("flash"):
    kind, msg = ss.pop("flash")
    st.toast(("✅ " if kind == "ok" else "⛔ ") + msg)

components.html(tour_script(user["role"]), height=0)
if ss.get("tour_nonce") and ss.get("tour_done") != ss.tour_nonce:
    ss.tour_done = ss.tour_nonce
    components.html("<script>(function go(n){const P=window.parent;if(P.__pgStart){P.__pgStart();}"
                    "else if(n<40){setTimeout(()=>go(n+1),150);}})(0);</script>"
                    f"<!-- tour {ss.tour_nonce} -->", height=0)
TAB_NAMES = ["🏠 Start here", "📊 Overview", "🔎 Investigate", "📋 All changes", "✋ Approvals",
             "🧪 Try it live", "🎯 Accuracy", "⚙️ Rules", "🗂️ Data", "🧾 Audit"]
if can(user, "manage_users"):
    TAB_NAMES.append("👥 Staff accounts")
tabs = st.tabs(TAB_NAMES, key="main_tabs", on_change="rerun")
cnt = bank["decision"].value_counts()
n_hold, n_rev, n_allow = int(cnt.get("HOLD", 0)), int(cnt.get("REVIEW", 0)), int(cnt.get("ALLOW", 0))
waiting = int(sum(1 for w in bank["workflow"] if w and not any(x in w for x in ("Released", "Blocked", "Cleared"))))
nr = bank.loc[bank["ts_utc"] == bank["ts_utc"].max(), "next_run"]
next_run_txt = pd.Timestamp(nr.iloc[0]).strftime("%d %b %Y") if len(nr) else "—"

# 0 ------------------------------------------------------------------ start here
with tabs[0]:
    st.markdown(f'<div class="pg-big" style="background:linear-gradient(110deg,{RED},#9E0C24)">'
                f'<h2>✋ {n_hold} vendor payments stopped before the next run</h2>'
                f'<p>{n_rev} more need a second look · {n_allow} bank-detail changes look normal and can be paid · '
                f'next payment run: <b>{next_run_txt}</b></p></div>', unsafe_allow_html=True)
    st.markdown(f'''<div class="pg-how">
<div class="b"><span class="n">1</span><h4>Trace</h4><p>Every vendor bank-detail change is linked back to the API call,
the access key, the network it came from, the staff sign-in and the outside company's warning list.</p></div>
<div class="b"><span class="n">2</span><h4>Score</h4><p>{len(RULES)} plain-English checks add points. 60+ stops the
payment, 30+ asks a person to look. No single check can stop a payment alone: two must agree.</p></div>
<div class="b"><span class="n">3</span><h4>Act</h4><p>Two different people decide: an accountant calls the vendor on
the number already on file, then the Finance Manager releases or blocks. Every step is logged.</p></div>
</div>''', unsafe_allow_html=True)
    st.markdown(f'<div class="pg-legend">{pill("HOLD")} <span>{DEC_WORD["HOLD"]}</span> {pill("REVIEW")} '
                f'<span>{DEC_WORD["REVIEW"]}</span> {pill("ALLOW")} <span>{DEC_WORD["ALLOW"]}</span></div>',
                unsafe_allow_html=True)
    st.write("")
    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### Payments stopped right now")
        top = bank[bank["decision"] == "HOLD"].sort_values(["score", "ts_utc"], ascending=[False, False]).head(5)
        for r in top.itertuples():
            why = " · ".join(x.split(" — ")[0] for x in r.reasons.split(" | ")[:3])
            st.markdown(f'<div class="pg-held"><b>{r.change_id} · {r.vendor_name}</b> &nbsp;{pill("HOLD")} '
                        f'&nbsp;score <b>{r.score}</b><br><span class="why">{why}</span></div>',
                        unsafe_allow_html=True)
        if n_hold > 5:
            st.caption(f"…and {n_hold - 5} more. Open **🔎 Investigate** to see the full trail of any one.")
    with right:
        st.markdown("#### Your next step")
        tips = {"callback": "Open <b>✋ Approvals</b>, call each vendor on the number <b>already on file</b>, and "
                            "record whether they confirmed.",
                "release": "Open <b>✋ Approvals</b>. Changes the accountant has confirmed wait for you to "
                           "release or block.",
                "settings": "Open <b>⚙️ Rules</b> to tune thresholds, or <b>🧪 Try it live</b> to test an attack.",
                "read": "Everything is read-only for you. <b>🧾 Audit</b> shows who did what, and when."}
        key = next(k for k in ("callback", "release", "settings") if can(user, k)) \
            if any(can(user, k) for k in ("callback", "release", "settings")) else "read"
        st.markdown(f'<div class="pg-card">Signed in as <b>{user["name"]}</b> ({role["title"]}).<br><br>'
                    f'{tips[key]}<br><br><b>{waiting}</b> stopped or flagged changes still wait for a person.</div>',
                    unsafe_allow_html=True)
        st.write("")
        st.markdown("#### Where to look")
        st.markdown("- **📊 Overview**: every bank change on one timeline\n"
                    "- **🔎 Investigate**: the full trail, link by link\n"
                    "- **🧪 Try it live**: make up a change and watch it get scored\n"
                    "- **🎯 Accuracy**: how it did on 14 planted attacks")

# 1 ------------------------------------------------------------------ overview
with tabs[1]:
    intro("Each dot is one vendor bank-detail change. <b>Higher = riskier.</b> Red dots are stopped payments; "
          "they cluster just before the payment runs (red dotted lines), which is exactly when a fraudster strikes.")
    k = st.columns(6)
    kpi(k[0], len(decisions), "Vendor changes checked", "all fields")
    kpi(k[1], len(bank), "Bank-detail changes", "the ones that move money")
    kpi(k[2], n_hold, "Payments stopped", "HOLD · score 60+", "hold")
    kpi(k[3], n_rev, "Need a second look", "REVIEW · score 30–59", "review")
    kpi(k[4], n_allow, "Safe to pay", "ALLOW · under 30", "allow")
    kpi(k[5], waiting, "Waiting for a person", "in the approval queue")
    st.write("")
    st.markdown(f"**Data runs to** {decisions['ts_utc'].max():%d %b %Y %H:%M} UTC · "
                f"**next payment run** {next_run_txt}")
    fig = go.Figure()
    for dec in ["ALLOW", "REVIEW", "HOLD"]:
        d = bank[bank["decision"] == dec]
        fig.add_trace(go.Scatter(
            x=pd.to_datetime(d["ts_ist"]), y=d["score"], mode="markers", name=f"{dec}: {DEC_WORD[dec]}",
            marker=dict(color=DEC_COLOR[dec], size=15 if dec == "HOLD" else 10, line=dict(color="white", width=1.5)),
            customdata=d[["change_id", "vendor_name", "field", "reasons"]],
            hovertemplate="<b>%{customdata[0]}</b> %{customdata[1]}<br>%{customdata[2]} · score %{y}"
                          "<br>%{customdata[3]}<extra></extra>"))
    lo, hi = pd.to_datetime(bank["ts_ist"]).min(), pd.to_datetime(bank["ts_ist"]).max()
    for dt in pd.date_range(lo.normalize(), hi.normalize() + pd.Timedelta(days=20)):
        if dt.day in settings.payment_days:
            fig.add_vline(x=dt, line=dict(color=RED, dash="dot", width=1))
            fig.add_annotation(x=dt, y=106, text=f"pay run {dt:%d %b}", showarrow=False, font=dict(color=RED, size=10))
    fig.add_hrect(y0=settings.hold_threshold, y1=110, fillcolor=RED, opacity=0.05, line_width=0)
    fig.add_hrect(y0=settings.review_threshold, y1=settings.hold_threshold, fillcolor=AMBER, opacity=0.06,
                  line_width=0)
    fig.add_hline(y=settings.hold_threshold, line=dict(color=RED, width=1))
    fig.add_hline(y=settings.review_threshold, line=dict(color=AMBER, width=1, dash="dash"))
    fig.update_layout(height=450, margin=dict(l=10, r=10, t=30, b=10), plot_bgcolor="white", paper_bgcolor="white",
                      yaxis=dict(title="Risk score (0–100)", range=[-5, 112], gridcolor="#EEEEEE"),
                      xaxis=dict(title="When the change was made (India time)", gridcolor="#EEEEEE"),
                      legend=dict(orientation="h", y=-0.18))
    st.plotly_chart(fig, width="stretch")
    st.caption("Shaded bands: red = stop the payment (60+), amber = a person takes a second look (30–59). "
               "Hover over a dot to see why it scored what it did.")

# 3 ------------------------------------------------------------------ all bank changes
with tabs[3]:
    intro("Every bank-detail change with its decision and the plain-English reasons. Non-payment edits "
          "(address, email…) are checked but can't redirect money, so they're left out of this list.")
    pick = st.multiselect("Show", ["HOLD", "REVIEW", "ALLOW"], default=["HOLD", "REVIEW"],
                          format_func=lambda d: f"{d}: {DEC_WORD[d]}")
    view = bank[bank["decision"].isin(pick)].sort_values(["score", "ts_utc"], ascending=[False, True])
    st.dataframe(
        view[["change_id", "ts_ist", "vendor_name", "field", "changed_by", "channel", "approval_ref", "actor_ip",
              "days_to_run", "score", "decision", "workflow", "reasons"]],
        hide_index=True, width="stretch", height=460,
        column_config={"score": st.column_config.ProgressColumn("score", min_value=0, max_value=100, format="%d"),
                       "ts_ist": "time (IST)", "days_to_run": "days to run", "workflow": "queue status",
                       "reasons": st.column_config.TextColumn("reasons", width="large")})
    st.caption(f"{len(view)} of {len(bank)} bank-detail changes shown. Other vendor edits: "
               f"{int((~decisions['is_bank']).sum())} rows.")


def history(rec):
    out = []
    for act, verb in [("escalate", "Escalated"), ("callback", "Call-back recorded"), ("clear", "Cleared"),
                      ("release", "Released"), ("block", "Blocked")]:
        if rec.get(f"{act}_by"):
            out.append(f"{verb} by <b>{rec[f'{act}_name']}</b> at {rec[f'{act}_at']}"
                       + (f" · <i>{rec[f'{act}_note']}</i>" if rec.get(f"{act}_note") else ""))
    return out


# 2 ------------------------------------------------------------------ chain
with tabs[2]:
    intro("Pick a change to see its <b>provenance chain</b>: each link from the change back to who made it, "
          "with what key, from where, and when. ✅ = the link checks out, ❌ = it doesn't.")
    order = bank.sort_values(["score", "ts_utc"], ascending=[False, True])
    opts = [f"{r.change_id} · {r.vendor_name} · {r.field} · {r.decision} {r.score}" for r in order.itertuples()]
    choice = st.selectbox("Pick a bank-detail change", opts)
    r = order.iloc[opts.index(choice)]
    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"### {r.vendor_name} — {r.field} {pill(r.decision)}", unsafe_allow_html=True)
        st.markdown(f"`{r.old_value}` → `{r.new_value}` · {r.ts_ist} IST")
        for i, step in enumerate(r.chain, 1):
            cls, icon = ("good", "✅") if step["ok"] else ("bad", "❌")
            st.markdown(f'<div class="pg-step {cls}"><b>{i}. {step["step"]}</b> {icon}<br>{step["detail"]}</div>',
                        unsafe_allow_html=True)
    with right:
        st.metric("Risk score", f"{r.score} / 100")
        st.progress(min(int(r.score), 100) / 100)
        st.markdown("**Why**")
        for x in (r.reasons.split(" | ") if r.reasons else ["Every link checks out."]):
            st.markdown(f"- {x}")
        if r.workflow:
            st.markdown(f"**Queue status:** {r.workflow}")
            for h in history(queue_state.get(r.change_id, {})):
                st.markdown(f'<div class="pg-hist">{h}</div>', unsafe_allow_html=True)

# 4 ------------------------------------------------------------------ hold queue
with tabs[4]:
    intro("Stopped and flagged payments wait here for people. <b>Two different people</b> must agree before a "
          "stopped payment goes ahead: a call-back on the old number on file, then the Finance Manager's release.")
    st.markdown(f"Signed in as **{user['name']}**, {role['title']}. {role['duty']}")
    with st.expander("How approval works (two-person rule)"):
        st.markdown(
            "1. **HOLD** changes wait for a **call-back**. The Senior Accountant calls the vendor on the number "
            "**already on file** (never one supplied with the change) and records the result.\n"
            "2. A confirmed call-back goes to the **Finance Manager**, who releases it. The person who released "
            "it must be different from the person who did the call-back.\n"
            "3. A failed call-back, or anything that looks wrong, is **blocked** by the Finance Manager or IT "
            "Security.\n"
            "4. **REVIEW** changes are cleared or escalated to HOLD.\n"
            "5. Nobody can act on a change they made. Every action, and every refused attempt, is in the audit trail.")
    qitems = bank[bank["decision"].isin(["HOLD", "REVIEW"])].sort_values(["decision", "ts_utc"])
    stat = {c: wf.status_of(queue_state.get(c, {}), d) for c, d in zip(qitems.change_id, qitems.decision)}
    q = st.columns(5)
    kpi(q[0], sum(v in ("open", "escalated") for v in stat.values()), "Waiting for call-back", "Senior Accountant", "hold")
    kpi(q[1], sum(v == "callback_confirmed" for v in stat.values()), "Waiting for Finance Manager", "release or block")
    kpi(q[2], sum(v == "open_review" for v in stat.values()), "Need a second look", "clear or escalate", "review")
    kpi(q[3], sum(v in ("released", "cleared") for v in stat.values()), "Released / cleared", "", "allow")
    kpi(q[4], sum(v == "blocked" for v in stat.values()), "Blocked as fraud", "")
    st.write("")

    def needs_me(s):
        return ((s in ("open", "escalated") and can(user, "callback"))
                or (s == "callback_confirmed" and can(user, "release"))
                or (s == "callback_failed" and can(user, "block"))
                or (s == "open_review" and can(user, "clear")))

    show = st.radio("Show", ["Needs my action", "All open", "Everything"], horizontal=True,
                    index=0 if (can(user, "callback") or can(user, "release")) else 1)
    if show == "Needs my action":
        qitems = qitems[[needs_me(stat[c]) for c in qitems.change_id]]
    elif show == "All open":
        qitems = qitems[[stat[c] not in FINAL for c in qitems.change_id]]
    if not len(qitems):
        st.info("Nothing waiting for your role right now." if show == "Needs my action" else "Queue is empty.")

    def do(fn, *a):
        ok, msg = fn(user, *a)
        ss.flash = ("ok" if ok else "err", msg)
        st.rerun()

    for r in qitems.itertuples():
        s = stat[r.change_id]
        rec = queue_state.get(r.change_id, {})
        ch = dict(change_id=r.change_id, changed_by=r.changed_by, decision=r.decision)
        head = f"{'🔴' if r.decision == 'HOLD' else '⚫'} {r.decision} · {r.change_id} · {r.vendor_name} · " \
               f"{r.field} · score {r.score} · {STATUS_TEXT[s]}"
        with st.expander(head, expanded=(len(qitems) <= 3)):
            st.markdown(f"`{r.old_value}` → `{r.new_value}` · changed {r.ts_ist} IST by `{r.changed_by}` · "
                        f"next run **{r.next_run}**")
            st.caption(r.reasons.replace(" | ", " · "))
            if r.callback_note:
                (st.warning if "OLD" in r.callback_note else st.info)("📞 " + r.callback_note)
            for h in history(rec):
                st.markdown(f'<div class="pg-hist">{h}</div>', unsafe_allow_html=True)
            if s in FINAL:
                continue
            note = st.text_input("Note (who you spoke to, what was checked)", key=f"note_{r.change_id}")
            b = st.columns(4)
            if s in ("open", "escalated"):
                if b[0].button("✅ Vendor confirmed", key=f"cbok_{r.change_id}", disabled=not can(user, "callback"),
                               help="Senior Accountant: call the vendor on the number already on file"):
                    do(wf.callback, ch, True, note)
                if b[1].button("❌ Vendor did not confirm", key=f"cbno_{r.change_id}",
                               disabled=not can(user, "callback")):
                    do(wf.callback, ch, False, note)
            if s == "callback_confirmed":
                if b[0].button("Release change", key=f"rel_{r.change_id}", type="primary",
                               disabled=not can(user, "release"),
                               help="Finance Manager only, and not the person who did the call-back"):
                    do(wf.release, ch, note)
            if s == "open_review":
                if b[0].button("Clear: looks legitimate", key=f"clr_{r.change_id}", disabled=not can(user, "clear")):
                    do(wf.clear, ch, note)
                if b[1].button("Escalate to HOLD", key=f"esc_{r.change_id}", disabled=not can(user, "escalate")):
                    do(wf.escalate, ch, note)
            if b[3].button("⛔ Block as fraud", key=f"blk_{r.change_id}", disabled=not can(user, "block"),
                           help="Finance Manager or IT Security"):
                do(wf.block, ch, note)

# 5 ------------------------------------------------------------------ try it live
with tabs[5]:
    intro("Make up a vendor bank-detail change and see how the guard scores it, <b>instantly</b>. Pick a ready-made "
          "scenario or change any field. Your test is scored together with all the evidence files, but it is "
          "<b>never added</b> to the real data or the approval queue.")
    e19 = data["E19"]
    bank_rows = e19[e19["field"].astype(str).str.contains("bank|account|ifsc", case=False, regex=True)]
    vendors = (e19.drop_duplicates("vendor_id").sort_values("vendor_name")[["vendor_id", "vendor_name"]]
               .itertuples(index=False))
    vendors = {v.vendor_id: v.vendor_name for v in vendors}
    keys = data["E04"]["credential_id"].tolist() if "E04" in data else ["key_tb_7f3a"]
    key_label = ({r["credential_id"]: f'{r["credential_id"]} · {r["integration"]}' for _, r in data["E04"].iterrows()}
                 if "E04" in data else {k: k for k in keys})
    staff = sorted(e19.loc[e19["channel"].astype(str) != "api", "changed_by"].dropna().astype(str).unique())
    used_accounts = bank_rows.loc[bank_rows["field"] == "bank_account", ["new_value", "vendor_name"]] \
        .drop_duplicates("new_value")
    IPS = {"TallyBridge private link (10.20.4.11)": "10.20.4.11",
           "Attacker IP on the warning list (185.220.101.47)": "185.220.101.47",
           "Unknown cloud server (52.66.140.201)": "52.66.140.201",
           "Harbor & Finch office (172.16.10.31)": "172.16.10.31",
           "Staff home broadband (49.207.183.12)": "49.207.183.12",
           "Foreign IP (77.83.246.15)": "77.83.246.15"}
    LOGINS = ["Normal: usual city and device", "New device and new city", "MFA bypassed",
              "Many failed passwords, then success"]
    SCEN = {
        "🦹 Stolen TallyBridge key": dict(t_who="Software (API key)", t_key="key_tb_7f3a",
                                          t_ip="Attacker IP on the warning list (185.220.101.47)",
                                          t_ua="TallyBridge-Sync/3.2", t_appr="", t_mule=True, t_phone=False),
        "🎭 Stolen staff login": dict(t_who="Staff member", t_staff=staff[0] if staff else "", t_appr="",
                                       t_ip="Foreign IP (77.83.246.15)", t_login="New device and new city",
                                       t_mule=False, t_phone=False),
        "☎️ Phone-then-bank scam": dict(t_who="Staff member", t_staff=staff[0] if staff else "", t_appr="APR-2026-0999",
                                        t_ip="Harbor & Finch office (172.16.10.31)", t_login=LOGINS[0],
                                        t_mule=False, t_phone=True),
        "✅ Normal approved update": dict(t_who="Staff member", t_staff=staff[0] if staff else "",
                                          t_appr="APR-2026-0420", t_ip="Harbor & Finch office (172.16.10.31)",
                                          t_login=LOGINS[0], t_mule=False, t_phone=False),
    }
    T_DEFAULTS = dict(t_vendor=next(iter(vendors)), t_field="bank_account", t_who="Software (API key)",
                      t_key="key_tb_7f3a" if "key_tb_7f3a" in keys else keys[0], t_staff=staff[0] if staff else "",
                      t_ip="Attacker IP on the warning list (185.220.101.47)", t_ua="TallyBridge-Sync/3.2",
                      t_login=LOGINS[0], t_appr="", t_mule=False, t_phone=False,
                      t_date=pd.Timestamp("2026-09-06").date(), t_time=pd.Timestamp("2026-09-06 03:15").time())
    for kk, vv in T_DEFAULTS.items():
        ss.setdefault(kk, vv)

    def _scen(name):
        for kk, vv in SCEN[name].items():
            ss[kk] = vv
        ss.t_result = None

    st.markdown("**Quick scenarios**")
    qc = st.columns(len(SCEN))
    for i, nm in enumerate(SCEN):
        qc[i].button(nm, on_click=_scen, args=(nm,), width="stretch", key=f"scen_{i}")

    f1, f2, f3 = st.columns(3)
    with f1:
        st.markdown("**1 · The change**")
        st.selectbox("Vendor", list(vendors), format_func=lambda v: f"{vendors[v]} ({v})", key="t_vendor")
        st.selectbox("Field changed", ["bank_account", "ifsc"], key="t_field")
        st.date_input("Date (India time)", key="t_date", min_value=pd.Timestamp("2026-06-03").date(),
                      max_value=pd.Timestamp("2026-09-30").date())
        st.time_input("Time (India time)", key="t_time")
        st.checkbox("Use an account already given to another vendor", key="t_mule",
                    help="Fraudsters often reuse one 'mule' account for several vendors.")
    with f2:
        st.markdown("**2 · Who made it, from where**")
        st.radio("Made by", ["Software (API key)", "Staff member"], key="t_who", horizontal=True)
        if ss.t_who == "Software (API key)":
            st.selectbox("Access key (from E04)", keys, format_func=lambda k: key_label.get(k, k), key="t_key")
            st.selectbox("Client software version", ["TallyBridge-Sync/3.1", "TallyBridge-Sync/3.2"], key="t_ua",
                         help="3.1 is what TallyBridge normally runs; 3.2 is on the outside company's warning list.")
        else:
            st.selectbox("Staff member", staff, key="t_staff")
            st.selectbox("How they signed in just before (E03)", LOGINS, key="t_login")
        st.selectbox("Came from network", list(IPS), key="t_ip")
    with f3:
        st.markdown("**3 · Paperwork**")
        st.text_input("Approval reference (leave blank = none)", key="t_appr", placeholder="e.g. APR-2026-0420")
        st.checkbox("Vendor's phone number was changed 3 days earlier", key="t_phone",
                    help="A scammer changes the phone first so the call-back reaches them.")
        st.write("")
        go_btn = st.button("🧪 Score this change", type="primary", width="stretch")

    if go_btn:
        ist = pd.Timestamp.combine(ss.t_date, ss.t_time)
        t_utc = ist - pd.Timedelta(hours=5, minutes=30)
        fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:00Z")
        vid, vname = ss.t_vendor, vendors[ss.t_vendor]
        prev = bank_rows[(bank_rows["vendor_id"] == vid) & (bank_rows["field"] == ss.t_field)]
        old = prev["new_value"].iloc[-1] if len(prev) else ("HDFC0001234" if ss.t_field == "ifsc" else "00112233445566")
        if ss.t_mule and ss.t_field == "bank_account":
            others = used_accounts[used_accounts["vendor_name"] != vname]
            new = others["new_value"].iloc[-1] if len(others) else "50100478821936"
        else:
            new = "SBIN0009999" if ss.t_field == "ifsc" else "77701234567890"
        ip = IPS[ss.t_ip]
        api_made = ss.t_who == "Software (API key)"
        actor = ss.t_key if api_made else ss.t_staff
        test = {k: v.copy() for k, v in data.items()}
        rows = []
        if ss.t_phone:
            rows.append(dict(ts_utc=fmt(t_utc - pd.Timedelta(days=3)), change_id="chg-TEST-0", vendor_id=vid,
                             vendor_name=vname, field="phone", old_value="+91-44-22000000",
                             new_value="+91-98400-00000", changed_by=staff[0] if staff else actor, channel="ui",
                             approval_ref="APR-2026-0998", source_ip="172.16.10.31", request_id=""))
        rows.append(dict(ts_utc=fmt(t_utc), change_id="chg-TEST-1", vendor_id=vid, vendor_name=vname,
                         field=ss.t_field, old_value=old, new_value=new, changed_by=actor,
                         channel="api" if api_made else "ui", approval_ref=ss.t_appr.strip(), source_ip=ip,
                         request_id="req-TEST-1" if api_made else ""))
        test["E19"] = pd.concat([test["E19"], pd.DataFrame(rows).astype(str)], ignore_index=True)
        if api_made:
            k18 = "E18" if "E18" in test else "E01"
            if k18 in test:
                test[k18] = pd.concat([test[k18], pd.DataFrame([dict(
                    ts_utc=fmt(t_utc), request_id="req-TEST-1", api_key_id=actor, caller_ip=ip,
                    user_agent=ss.t_ua, endpoint=f"/api/v2/vendors/{vid}", method="PATCH",
                    records_returned="1", status="200")]).astype(str)], ignore_index=True)
        elif "E03" in test:
            li = t_utc - pd.Timedelta(minutes=25)
            base = dict(user=actor, source_ip=ip, auth_method="password+mfa", failure_reason="")
            hist = test["E03"][test["E03"]["user"] == actor]
            city = hist["city"].mode().iloc[0] if len(hist) else "Chennai"
            devs = hist["device_id"].replace("", pd.NA).dropna()
            dev = devs.iloc[-1] if len(devs) else "LAP-TEST-01"
            sso = []
            if ss.t_login == "Many failed passwords, then success":
                for j in range(4):
                    sso.append(dict(base, ts_utc=fmt(li - pd.Timedelta(minutes=10 - 2 * j)), event_id=f"sso-T{j}",
                                    city=city, mfa_result="not_attempted", device_id=dev, result="failure",
                                    failure_reason="bad_password"))
            sso.append(dict(base, ts_utc=fmt(li), event_id="sso-T9",
                            city="Amsterdam" if ss.t_login == "New device and new city" else city,
                            mfa_result="bypassed" if ss.t_login == "MFA bypassed" else "success",
                            device_id="WIN-UNKNOWN-99" if ss.t_login == "New device and new city" else dev,
                            result="success"))
            test["E03"] = pd.concat([test["E03"], pd.DataFrame(sso).astype(str)], ignore_index=True)
        try:
            dec_t, _ = evaluate(test, settings)
            ss.t_result = dec_t[dec_t["change_id"] == "chg-TEST-1"].iloc[0].to_dict()
            wf.log(user, "live test", "chg-TEST-1",
                   f"{ss.t_result['decision']} {ss.t_result['score']} (not added to the real data)")
        except Exception as ex:  # keep the demo alive whatever is typed
            ss.t_result = {"error": str(ex)}

    res = ss.get("t_result")
    if res and "error" in res:
        st.error(f"Couldn't score that change: {res['error']}")
    elif res:
        st.divider()
        col = DEC_COLOR[res["decision"]]
        a, b = st.columns([2, 3])
        with a:
            st.markdown(f'<div class="pg-big" style="background:{col}"><h2>{res["decision"]} · {res["score"]}/100</h2>'
                        f'<p>{DEC_WORD[res["decision"]]}</p></div>', unsafe_allow_html=True)
            st.markdown(f"`{res['old_value']}` → `{res['new_value']}` · {res['vendor_name']} · {res['ts_ist']} IST")
            st.markdown("**Points added**")
            for x in (res["reasons"].split(" | ") if res["reasons"] else ["Nothing suspicious: every link checks out."]):
                st.markdown(f"- {x}")
            if res.get("callback_note"):
                (st.warning if "OLD" in res["callback_note"] else st.info)("📞 " + res["callback_note"])
        with b:
            st.markdown("**The provenance chain for your test change**")
            for i, step in enumerate(res["chain"], 1):
                cls, icon = ("good", "✅") if step["ok"] else ("bad", "❌")
                st.markdown(f'<div class="pg-step {cls}"><b>{i}. {step["step"]}</b> {icon}<br>{step["detail"]}</div>',
                            unsafe_allow_html=True)

# 6 ------------------------------------------------------------------ accuracy
with tabs[6]:
    intro("How well it works on the test data, where we know the truth: 14 planted attacks and tricky normal "
          "events designed to cause false alarms.")
    if not m:
        st.info("Accuracy needs labelled data. The real case logs have no labels, so this tab works on the "
                "sample test data (or any folder with a labels_*.csv).")
    else:
        a = st.columns(4)
        kpi(a[0], f"{m['fraud_held']} / {m['frauds']}", "Attacks stopped (HOLD)", f"{m['detection_rate']}%", "hold")
        kpi(a[1], f"{m['fraud_held'] + m['fraud_review']} / {m['frauds']}", "Attacks caught (HOLD + REVIEW)",
            f"{m['flagged_rate']}% · none slipped through", "review")
        kpi(a[2], f"{m['benign_held']} / {m['benign']}", "False alarms: normal changes stopped",
            f"{m['false_alarm_rate']}%", "allow")
        kpi(a[3], m["benign_review"], "Normal changes sent for a second look", "a person checks, nothing blocked")
        st.write("")
        t = m["table"]
        st.markdown("**Decision vs truth**")
        st.dataframe(pd.crosstab(t["label"], t["decision"]).reindex(columns=["HOLD", "REVIEW", "ALLOW"],
                                                                     fill_value=0), width="stretch")
        st.markdown("**Every attack, every normal change that was flagged, and the tricky normal events**")
        st.dataframe(t[(t["label"] == "fraud") | (t["decision"] != "ALLOW")
                       | t["scenario"].astype(str).str.startswith("tricky")]
                     [["change_id", "scenario", "label", "decision", "score", "reasons"]]
                     .sort_values(["label", "score"], ascending=[False, False]), hide_index=True, width="stretch")
        st.caption("Ordinary activity in the test data (month-end clean-ups, approved updates, TallyBridge "
                   "contact syncs, staff working from home) is checked here to confirm it is not held.")

# 7 ------------------------------------------------------------------ settings
with tabs[7]:
    st.subheader("Rule settings")
    edit = can(user, "settings")
    if edit:
        st.caption("You own the rules. Changes preview live for you; press **Save for everyone** to apply them "
                   "to every user.")
    else:
        st.info(f"Read-only for {role['title']}. Only IT Security can change the detection rules.")
    c1, c2, c3 = st.columns(3)
    c1.slider("HOLD at score ≥", 30, 100, key="hold", disabled=not edit)
    c1.slider("REVIEW at score ≥", 10, 90, key="review", disabled=not edit)
    c2.slider("Risk window: days before a run", 0, 10, key="window", disabled=not edit)
    c2.slider("Watch window: days before a run", 0, 14, key="watch", disabled=not edit)
    c3.text_input("Expected integration networks (CIDR, comma-separated)", key="exp_nets", disabled=not edit)
    c3.text_input("Office networks", key="int_nets", disabled=not edit)
    c3.number_input("Approved bank-change days before a key counts as 'normal'", 1, 30, key="min_days",
                    disabled=not edit)
    st.markdown("**Rules and weights**")
    cols = st.columns(2)
    for i, (k, (desc, _)) in enumerate(RULES.items()):
        with cols[i % 2]:
            x1, x2 = st.columns([3, 1])
            x1.checkbox(desc, key=f"on_{k}", disabled=not edit)
            x2.number_input("points", 0, 100, key=f"w_{k}", label_visibility="collapsed", disabled=not edit)
    st.markdown("**Clock offsets** (minutes added to reach UTC)")
    o1, o2 = st.columns(2)
    o1.number_input("E02 HelpDeskr (tenant local time)", -720, 720, key="e02_offset", disabled=not edit)
    o2.number_input("E05 BlueVault (unsynchronised clock)", -1440, 1440, key="e05_offset", disabled=not edit)
    if edit:
        s1, s2, _ = st.columns([1, 1, 3])
        if s1.button("Save for everyone", type="primary"):
            cur = {k: ss[k] for k in DEFAULTS}
            changed = {k: v for k, v in cur.items() if v != saved_rules()[k]}
            STATE.mkdir(exist_ok=True)
            RULES_FILE.write_text(json.dumps(cur, indent=1))
            wf.log(user, "save rules", "", json.dumps(changed) if changed else "no changes")
            ss.flash = ("ok", "Rules saved for every user.")
            st.rerun()
        def _defaults():
            for k, v in DEFAULTS.items():
                ss[k] = v
        s2.button("Reset to defaults", on_click=_defaults)

# 8 ------------------------------------------------------------------ data + clocks
with tabs[8]:
    intro("Which evidence files were read, and how every clock was converted to UTC before anything was joined. "
          "Different systems record time differently; a wrong time zone would break the whole trail.")
    st.subheader("Files loaded")
    names = {"E01": "LedgerOne API log", "E18": "LedgerOne API log (1–7 Sep)", "E19": "Vendor record change log",
             "E04": "Connected software register", "E15": "Private-link flow log", "E17": "Indicator list",
             "E02": "HelpDeskr audit log", "E03": "Staff sign-in (SSO) log", "E05": "BlueVault log",
             "LABELS": "Ground-truth labels (TEST only)"}
    st.dataframe(pd.DataFrame([dict(file=k, contents=names.get(k, "—"), rows=len(v),
                                     columns=", ".join(map(str, v.columns[:8]))) for k, v in sorted(data.items())]),
                 hide_index=True, width="stretch")
    missing = [k for k in ("E18", "E01", "E03", "E04", "E15", "E17") if k not in data]
    if missing:
        st.warning("Not loaded: " + ", ".join(missing) + ". The guard still runs, with fewer links in each chain.")
    st.subheader("Every timestamp converted to UTC")
    st.dataframe(clocks, hide_index=True, width="stretch")
    st.caption("India time (IST) is shown alongside for readability. Offsets for E02 (tenant local time) and E05 "
               "(unsynchronised clock) are set in ⚙️ Rules.")

# 9 ------------------------------------------------------------------ audit + export
with tabs[9]:
    st.subheader("Export for the proof pack")
    e1, e2, e3 = st.columns(3)
    out = decisions.drop(columns=["chain"]).merge(bank[["change_id", "workflow"]], on="change_id", how="left")
    if e1.download_button("decisions.csv", out.to_csv(index=False), "decisions.csv", "text/csv"):
        wf.log(user, "export", "", "decisions.csv")
    if e2.download_button("report.md", build_report(decisions, clocks, m, settings), "report.md", "text/markdown"):
        wf.log(user, "export", "", "report.md")
    qdf = pd.DataFrame([dict(change_id=k, **v) for k, v in queue_state.items()])
    if len(qdf) and e3.download_button("hold_queue.csv", qdf.to_csv(index=False), "hold_queue.csv", "text/csv"):
        wf.log(user, "export", "", "hold_queue.csv")
    st.caption("The same engine runs without the dashboard:  python run_guard.py <folder> --out output")

    st.divider()
    st.subheader("Audit trail")
    st.caption("Every sign-in, call-back, release, block, rule change and refused attempt, newest first. "
               "Append-only file: state/audit_log.jsonl")
    log = pd.DataFrame(wf.audit())
    if not len(log):
        st.info("No actions yet.")
    else:
        log = log[log["dataset"].isin([dataset_id, "auth"])].iloc[::-1]
        a1, a2, a3 = st.columns(3)
        a1.metric("Actions recorded", int((log["result"] == "ok").sum()))
        a2.metric("Refused attempts", int((log["result"] == "denied").sum()))
        a3.metric("People involved", int(log.loc[log["user"] != "-", "user"].nunique()))
        only = st.selectbox("Filter", ["Everything", "Queue decisions only", "Refused attempts only"])
        if only == "Queue decisions only":
            log = log[log["change_id"].astype(str) != ""]
        elif only == "Refused attempts only":
            log = log[log["result"] == "denied"]
        st.dataframe(log[["time", "name", "role", "action", "change_id", "result", "detail"]], hide_index=True,
                     width="stretch", height=min(460, 40 + 35 * max(len(log), 1)),
                     column_config={"detail": st.column_config.TextColumn("detail", width="large")})
        st.download_button("audit_log.csv", log.to_csv(index=False), "audit_log.csv", "text/csv")


# 10 ----------------------------------------------------------------- staff accounts (IT Security only)
if can(user, "manage_users"):
    with tabs[10]:
        intro("Only IT Security can create, disable or reset staff accounts. There is no self-sign-up. New staff get "
              "a temporary password and must set their own at first sign-in. Every change is written to the audit trail.")
        wfa = Workflow(STATE, "auth")
        users_now = load_users()
        st.dataframe(pd.DataFrame([dict(username=k, name=v["name"], role=ROLES[v["role"]]["title"],
                                        status="Active" if v.get("active", True) else "Disabled",
                                        password="Temporary (must change)" if v.get("must_change") else "Set by user",
                                        created_by=v.get("created_by", "-"), created=v.get("created_at", "-"))
                                   for k, v in sorted(users_now.items())]), hide_index=True, width="stretch")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Create a staff account")
            with st.form("newuser", clear_on_submit=True):
                nu = st.text_input("Username", placeholder="e.g. ravi.kumar")
                nn = st.text_input("Full name")
                nr = st.selectbox("Role", list(ROLES), format_func=lambda r: ROLES[r]["title"])
                npw = st.text_input("Temporary password", type="password",
                                    help="At least 10 characters with upper- and lower-case letters, a number and a symbol. "
                                         "Give it to the person in person or by phone, never by email.")
                if st.form_submit_button("Create account", type="primary"):
                    err = create_user(user, nu, nn, nr, npw)
                    if err:
                        st.error(err)
                        wfa.log(user, "create account", nu, err, result="denied")
                    else:
                        wfa.log(user, "create account", nu.strip().lower(), f"role {ROLES[nr]['title']}")
                        st.toast(f"Account {nu.strip().lower()} created. They must change the password at first sign-in.")
                        st.rerun()
        with c2:
            st.markdown("#### Change an existing account")
            others = [k for k in sorted(users_now) if k != user["username"]]
            who = st.selectbox("Account", others,
                               format_func=lambda k: f"{k} · {users_now[k]['name']} · {ROLES[users_now[k]['role']]['title']}")
            active = users_now[who].get("active", True) if who else True
            b1, b2 = st.columns(2)
            if b1.button("Disable account" if active else "Re-enable account", width="stretch"):
                err = set_active(user, who, not active)
                wfa.log(user, "disable account" if active else "re-enable account", who, err or "",
                        result="denied" if err else "ok")
                st.rerun()
            with st.form("resetpw", clear_on_submit=True):
                rpw = st.text_input("New temporary password", type="password")
                if st.form_submit_button("Reset password"):
                    err = reset_password(user, who, rpw)
                    if err:
                        st.error(err)
                    else:
                        wfa.log(user, "reset password", who, "temporary password issued")
                        st.toast(f"Password reset for {who}. They must change it at next sign-in.")
