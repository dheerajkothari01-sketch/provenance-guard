"""Role-based guided tour. Injects a small script into the page that adds a 'Guide' button (top right) and walks
the signed-in user through the tabs that matter to their role, clicking each tab for them."""
import json

COMMON_START = [
    dict(sel=".pg-bar", title="Welcome to Provenance Guard",
         text="This tool checks where every vendor bank-detail change came from, and stops the payment if the trail "
              "doesn't hold up. This short tour shows you the parts that matter for your role."),
    dict(sel=".pg-user", title="Your role",
         text="You're signed in here. What you can do (call back, release, block, change rules) depends on this role, "
              "and the system enforces it, not just the screen."),
    dict(tab="Start here", title="Start here",
         text="The answer first: how many payments are stopped before the next run, the top stopped changes, and "
              "your next step."),
]
STEPS = {
    "accountant": [
        dict(tab="Investigate", title="Investigate a change",
             text="Pick any change to see its full trail, link by link. ❌ marks the link that broke."),
        dict(tab="Approvals", title="Your main job: the call-back",
             text="Open each stopped change and call the vendor on the number ALREADY ON FILE, never one sent with the "
                  "change. If the app warns the phone changed recently, call the OLD number it shows. Then record "
                  "'confirmed' or 'not confirmed'. You can't release money yourself: the Finance Manager does."),
        dict(tab="Try it live", title="Try it live",
             text="Make up a change and see how it would be scored. Nothing you test here touches the real data."),
        dict(tab="Audit", title="Audit trail",
             text="Every sign-in and action, including yours, is recorded with name, role and time."),
    ],
    "finance_manager": [
        dict(tab="Overview", title="Overview",
             text="Every bank-detail change on one timeline. Red dots are stopped payments, clustered just before "
                  "the payment runs."),
        dict(tab="Approvals", title="Your main job: the final decision",
             text="After the Senior Accountant records the call-back, you release the change (vendor confirmed) or "
                  "block it as fraud. Nobody can release a change they made or called back themselves."),
        dict(tab="Investigate", title="Check the evidence",
             text="Before deciding, open the change here to see exactly which links in its trail failed."),
        dict(tab="Accuracy", title="Can we trust it?",
             text="Results on test data: attacks caught and normal changes wrongly stopped."),
    ],
    "it_security": [
        dict(tab="Overview", title="Overview",
             text="Every bank-detail change on one timeline, scored 0-100 against the payment calendar."),
        dict(tab="Investigate", title="Investigate",
             text="The provenance chain for any change: API call, key, network, private link, warning list, staff "
                  "sign-in, call-back number and payment date."),
        dict(tab="Rules", title="You own the rules",
             text="Tune thresholds, time windows, trusted networks and each rule's points. Changes apply to everyone "
                  "and are logged. Only IT Security can edit them."),
        dict(tab="Staff accounts", title="You create staff accounts",
             text="There is no self-sign-up. Create accounts here with a temporary password; the person must set "
                  "their own at first sign-in. Disable leavers immediately."),
        dict(tab="Try it live", title="Test an attack",
             text="Simulate a stolen key, a stolen login or a phone-then-bank scam and see how the rules score it."),
        dict(tab="Audit", title="Audit trail",
             text="Every sign-in, refused attempt, rule change and account change, with who and when."),
    ],
    "auditor": [
        dict(tab="All changes", title="All changes",
             text="Every bank-detail change with its score, decision, queue status and the plain-English reasons."),
        dict(tab="Investigate", title="Investigate",
             text="Follow any change's trail across the evidence files, link by link."),
        dict(tab="Accuracy", title="Accuracy",
             text="How well the rules perform on labelled test data, including false alarms and misses."),
        dict(tab="Audit", title="Audit trail and exports",
             text="Who did what and when, including refused attempts. Download the decisions and report here."),
        dict(tab="Rules", title="Rules (read-only for you)",
             text="You can see every rule and threshold, but only IT Security can change them."),
    ],
}
COMMON_END = [dict(btn="Guide", title="That's the tour",
                   text="Press 🧭 Guide (top right) any time to see this tour again.")]

JS = r"""
(function(){
  const P = window.parent, D = P.document;
  P.__pgSteps = STEPS_JSON;
  if (P.__pgTourReady) { return; }
  P.__pgTourReady = true;
  const css = D.createElement('style');
  css.textContent = `
  #pg-tour-hole{position:fixed;z-index:1000002;border-radius:10px;box-shadow:0 0 0 9999px rgba(0,0,0,.62);
    outline:3px solid #C8102E;transition:all .25s ease;pointer-events:none}
  #pg-tour-tip{position:fixed;z-index:1000003;width:380px;max-width:calc(100vw - 24px);background:#fff;border-radius:12px;padding:16px 18px;
    font-family:'Segoe UI',Arial,sans-serif;box-shadow:0 12px 34px rgba(0,0,0,.35);border-top:5px solid #C8102E}
  #pg-tour-tip h4{margin:0 0 6px;font-size:17px;color:#161616}
  #pg-tour-tip p{margin:0 0 12px;font-size:14px;color:#333;line-height:1.45}
  #pg-tour-tip .row{display:flex;align-items:center;gap:8px}
  #pg-tour-tip .n{color:#8C8C8C;font-size:12px;margin-right:auto}
  #pg-tour-tip button{border:1px solid #CCC;background:#fff;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:13px}
  #pg-tour-tip button.go{background:#161616;color:#fff;border-color:#161616}`;
  D.head.appendChild(css);
  let i = 0;
  function el(s){
    if (s.tab) return [...D.querySelectorAll('[data-testid="stTab"]')].find(t => t.innerText.includes(s.tab));
    if (s.btn) return [...D.querySelectorAll('button')].find(b => b.innerText.includes(s.btn));
    return D.querySelector(s.sel);
  }
  function end(){ ['pg-tour-hole','pg-tour-tip'].forEach(id => { const e = D.getElementById(id); if (e) e.remove(); }); }
  function show(){
    const steps = P.__pgSteps; const s = steps[i]; let e = el(s);
    if (!e) { if (i < steps.length - 1) { i++; return show(); } return end(); }
    if (s.tab) { e.click(); }
    setTimeout(() => {
      e = el(s) || e;
      e.scrollIntoView({block:'center', behavior:'smooth'});
      setTimeout(() => {
        const r = e.getBoundingClientRect(), pad = 6;
        let h = D.getElementById('pg-tour-hole'); if (!h) { h = D.createElement('div'); h.id='pg-tour-hole'; D.body.appendChild(h); }
        Object.assign(h.style, {left:(r.left-pad)+'px', top:(r.top-pad)+'px', width:(r.width+2*pad)+'px', height:(r.height+2*pad)+'px'});
        let t = D.getElementById('pg-tour-tip'); if (!t) { t = D.createElement('div'); t.id='pg-tour-tip'; D.body.appendChild(t); }
        t.innerHTML = `<h4>${s.title}</h4><p>${s.text}</p><div class="row"><span class="n">${i+1} of ${steps.length}</span>`+
          (i>0?`<button data-a="back">Back</button>`:'')+`<button data-a="skip">Close</button>`+
          `<button class="go" data-a="next">${i<steps.length-1?'Next':'Finish'}</button></div>`;
        const W = P.innerWidth, H = P.innerHeight;
        let top = r.bottom + 14; if (top + 190 > H) top = Math.max(12, r.top - 200);
        const tw = Math.min(380, W - 24); let left = Math.min(Math.max(12, r.left), W - tw - 12);
        Object.assign(t.style, {top: top+'px', left: left+'px'});
        t.onclick = ev => { const a = ev.target.getAttribute('data-a'); if (!a) return;
          if (a==='next') { if (i < steps.length-1) { i++; show(); } else end(); }
          else if (a==='back') { i--; show(); } else end(); };
      }, 450);
    }, s.tab ? 700 : 50);
  }
  P.__pgStart = () => { end(); i = 0; show(); };
  setInterval(() => { if (!D.querySelector('.pg-user')) end(); }, 1500);
  D.addEventListener('keydown', ev => { if (ev.key === 'Escape') end(); });
})();
"""


def tour_script(role: str) -> str:
    steps = COMMON_START + STEPS.get(role, []) + COMMON_END
    js = JS.replace("STEPS_JSON", json.dumps(steps))
    return ("<script>(function(){const D=window.parent.document;const s=D.createElement('script');"
            f"s.textContent={json.dumps(js)};D.body.appendChild(s);}})();</script>")
