from olympus.nodes.protocol import PROTOCOL_ID

_CONSOLE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Olympus nodes</title>
<style>
:root { color-scheme: dark light; --bg:#0d1117; --panel:#161b22; --line:#30363d;
  --text:#e6edf3; --muted:#8b949e; --ok:#3fb950; --warn:#d29922; --bad:#f85149; --accent:#58a6ff; }
* { box-sizing:border-box; }
body { margin:0; padding:0 0 3rem; background:var(--bg); color:var(--text);
  font:16px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
header { position:sticky; top:0; z-index:2; background:var(--panel);
  border-bottom:1px solid var(--line); padding:0.75rem 1rem;
  display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap; }
h1 { font-size:1.05rem; margin:0; flex:1 1 auto; }
main { padding:1rem; display:grid; gap:1rem; max-width:52rem; margin:0 auto; }
section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:1rem; }
h2 { font-size:0.8rem; text-transform:uppercase; letter-spacing:0.08em;
  color:var(--muted); margin:0 0 0.75rem; }
button { font:inherit; min-height:44px; padding:0 1rem; border-radius:10px;
  border:1px solid var(--line); background:#21262d; color:var(--text); cursor:pointer; }
button.primary { background:var(--accent); border-color:var(--accent); color:#08111f;
  font-weight:600; }
button.danger { background:var(--bad); border-color:var(--bad); color:#1b0503; font-weight:600; }
input, select { font:inherit; min-height:44px; width:100%; padding:0 0.75rem; border-radius:10px;
  border:1px solid var(--line); background:#0d1117; color:var(--text); }
label { display:block; font-size:0.8rem; color:var(--muted); margin:0.5rem 0 0.25rem; }
.node { border-top:1px solid var(--line); padding:0.75rem 0; }
.node:first-of-type { border-top:0; padding-top:0; }
.row { display:flex; align-items:baseline; gap:0.5rem; flex-wrap:wrap; }
.name { font-weight:600; }
.pill { font-size:0.72rem; padding:0.15rem 0.5rem; border-radius:999px;
  border:1px solid var(--line); color:var(--muted); }
.pill.online { color:var(--ok); border-color:var(--ok); }
.pill.offline, .pill.pending { color:var(--muted); }
.pill.quarantined { color:var(--warn); border-color:var(--warn); }
.pill.revoked { color:var(--bad); border-color:var(--bad); }
.meta { color:var(--muted); font-size:0.82rem; word-break:break-all; }
.jobs li { list-style:none; border-top:1px solid var(--line); padding:0.6rem 0; }
.jobs { margin:0; padding:0; }
.banner { border-radius:10px; padding:0.6rem 0.85rem; font-weight:600; }
.banner.frozen { background:#3d1618; color:var(--bad); border:1px solid var(--bad); }
.banner.live { background:#12261a; color:var(--ok); border:1px solid var(--ok); }
.actions { display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.75rem; }
.hidden { display:none; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:0.85em; }
</style>
</head>
<body>
<header>
  <h1>Olympus nodes</h1>
  <span class="meta">__PROTOCOL__</span>
  <button id="refresh" type="button">Refresh</button>
</header>
<main>
  <section id="signin">
    <h2>Operator credential</h2>
    <p class="meta">Held in this tab's session storage only. It is never stored on the server
      and never written to disk.</p>
    <label for="token">Bearer credential</label>
    <input id="token" type="password" autocomplete="off" spellcheck="false">
    <label for="commander">Commander</label>
    <input id="commander" value="local-jerry" autocomplete="off" spellcheck="false">
    <label for="lease">Authority lease</label>
    <input id="lease" value="development-lease" autocomplete="off" spellcheck="false">
    <div class="actions"><button class="primary" id="connect" type="button">Connect</button></div>
  </section>

  <section id="control" class="hidden">
    <h2>Dispatch control</h2>
    <div id="banner" class="banner live">Dispatch live</div>
    <div class="actions">
      <button class="danger" id="freeze" type="button">Freeze dispatch</button>
      <button id="unfreeze" type="button">Unfreeze</button>
    </div>
  </section>

  <section id="nodes" class="hidden"><h2>Machines</h2><div id="nodelist"></div></section>
  <section id="run" class="hidden">
    <h2>Run a capability</h2>
    <label for="capability">Capability</label>
    <select id="capability"></select>
    <label for="target">Node</label>
    <select id="target"></select>
    <div class="actions"><button class="primary" id="dispatch" type="button">Dispatch</button></div>
    <p class="meta" id="dispatchStatus"></p>
  </section>
  <section id="jobs" class="hidden"><h2>Jobs</h2><ul class="jobs" id="joblist"></ul></section>
  <section id="errors" class="hidden"><h2>Last error</h2><p class="meta" id="error"></p></section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const state = { epoch: 0, timer: null };

function headers() {
  return {
    "Authorization": "Bearer " + sessionStorage.getItem("olympusToken"),
    "X-Olympus-Commander": sessionStorage.getItem("olympusCommander"),
    "X-Olympus-Authority-Lease": sessionStorage.getItem("olympusLease"),
    "Content-Type": "application/json",
  };
}

async function call(path, options) {
  const response = await fetch(path, Object.assign({ headers: headers() }, options || {}));
  if (!response.ok) {
    throw new Error(path + " -> " + response.status + " " + (await response.text()).slice(0, 200));
  }
  return response.status === 204 ? null : response.json();
}

function showError(message) {
  $("errors").classList.remove("hidden");
  $("error").textContent = message;
}

function renderNodes(payload) {
  state.epoch = payload.freeze_epoch;
  $("banner").className = "banner " + (payload.dispatch_frozen ? "frozen" : "live");
  $("banner").textContent = payload.dispatch_frozen
    ? "Dispatch FROZEN at epoch " + payload.freeze_epoch
    : "Dispatch live";
  const list = $("nodelist");
  list.textContent = "";
  const target = $("target");
  target.textContent = "";
  const any = document.createElement("option");
  any.value = ""; any.textContent = "any eligible node";
  target.appendChild(any);
  for (const node of payload.nodes) {
    const box = document.createElement("div");
    box.className = "node";
    const row = document.createElement("div");
    row.className = "row";
    const name = document.createElement("span");
    name.className = "name"; name.textContent = node.node_name;
    const pill = document.createElement("span");
    pill.className = "pill " + node.state; pill.textContent = node.state;
    const platform = document.createElement("span");
    platform.className = "pill"; platform.textContent = node.platform + " / " + node.architecture;
    row.append(name, pill, platform);
    const meta = document.createElement("div");
    meta.className = "meta";
    const age = node.heartbeat_age_seconds === null
      ? "never" : Math.round(node.heartbeat_age_seconds) + "s ago";
    meta.textContent = "agent " + node.agent_version + " · heartbeat " + age
      + " · capabilities " + (node.effective_capabilities.join(", ") || "none")
      + " · output trust " + node.output_trust_label;
    box.append(row, meta);
    list.appendChild(box);
    if (node.state === "online") {
      const option = document.createElement("option");
      option.value = node.node_id; option.textContent = node.node_name;
      target.appendChild(option);
    }
  }
  if (!payload.nodes.length) {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "No machines enrolled yet.";
    list.appendChild(empty);
  }
}

function renderJobs(payload) {
  const list = $("joblist");
  list.textContent = "";
  for (const job of payload.jobs.slice(0, 20)) {
    const item = document.createElement("li");
    const row = document.createElement("div");
    row.className = "row";
    const pill = document.createElement("span");
    pill.className = "pill"; pill.textContent = job.status;
    const name = document.createElement("span");
    name.className = "name"; name.textContent = job.capability;
    row.append(pill, name);
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = job.job_id + " · " + job.progress_events + " progress events"
      + (job.last_message ? " · " + job.last_message : "")
      + (job.reason ? " · " + job.reason : "");
    item.append(row, meta);
    list.appendChild(item);
  }
  if (!payload.jobs.length) {
    const empty = document.createElement("li");
    empty.className = "meta"; empty.textContent = "No jobs yet.";
    list.appendChild(empty);
  }
}

async function refresh() {
  try {
    renderNodes(await call("/v1/nodes"));
    renderJobs(await call("/v1/nodes/jobs"));
    $("errors").classList.add("hidden");
  } catch (error) {
    showError(String(error.message || error));
  }
}

async function connect() {
  sessionStorage.setItem("olympusToken", $("token").value.trim());
  sessionStorage.setItem("olympusCommander", $("commander").value.trim());
  sessionStorage.setItem("olympusLease", $("lease").value.trim());
  try {
    const capabilities = await call("/v1/nodes/capabilities");
    const select = $("capability");
    select.textContent = "";
    for (const capability of capabilities.filter((item) => item.status === "enabled")) {
      const option = document.createElement("option");
      option.value = capability.name;
      option.textContent = capability.name + " — " + capability.title;
      select.appendChild(option);
    }
  } catch (error) {
    showError(String(error.message || error));
    return;
  }
  for (const id of ["control", "nodes", "run", "jobs"]) $(id).classList.remove("hidden");
  $("signin").classList.add("hidden");
  await refresh();
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(refresh, 5000);
}

$("connect").addEventListener("click", connect);
$("refresh").addEventListener("click", refresh);
$("freeze").addEventListener("click", async () => {
  try {
    await call("/v1/nodes/control/freeze",
      { method: "POST", body: JSON.stringify({ reason: "console freeze" }) });
    await refresh();
  } catch (error) { showError(String(error.message || error)); }
});
$("unfreeze").addEventListener("click", async () => {
  try {
    await call("/v1/nodes/control/unfreeze", {
      method: "POST",
      body: JSON.stringify({ expected_freeze_epoch: state.epoch, reason: "console unfreeze" }),
    });
    await refresh();
  } catch (error) { showError(String(error.message || error)); }
});
$("dispatch").addEventListener("click", async () => {
  const body = { capability: $("capability").value, parameters: {} };
  if ($("target").value) body.node_id = $("target").value;
  try {
    const accepted = await call("/v1/nodes/jobs", { method: "POST", body: JSON.stringify(body) });
    $("dispatchStatus").textContent = "accepted " + accepted.job_id;
    await refresh();
  } catch (error) { showError(String(error.message || error)); }
});
</script>
</body>
</html>
"""


def render_node_console() -> str:
    """Render the self-contained operator console.

    The page ships no third-party assets and embeds no data, so serving the
    shell reveals nothing. Every data call it makes is separately authorized.
    """
    return _CONSOLE.replace("__PROTOCOL__", PROTOCOL_ID)
