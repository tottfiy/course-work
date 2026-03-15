async function jget(url){
  const r = await fetch(url);
  return r.json();
}

function updateStartBtn(){
  const btn = document.getElementById("startBtn");
  if(!btn) return;
  const anyChecked = [...document.querySelectorAll("#tools input")].some(x => x.checked && !x.disabled);
  btn.disabled = !anyChecked;
}

function pillClass(status){
  const s = String(status || "").toLowerCase();
  if(s === "done") return "pill pill-ok";
  if(s === "running") return "pill pill-run";
  if(s === "queued") return "pill pill-warn";
  if(!s) return "pill pill-ghost";
  return "pill pill-ghost";
}

async function loadTools(){
  const box = document.getElementById("tools");
  const tools = await jget("/api/tools");

  box.innerHTML = "";

  Object.entries(tools).forEach(([name, v]) => {
    const avail = v[0];
    const reason = v[1];

    const card = document.createElement("div");
    card.className = "tool-card";

    const top = document.createElement("div");
    top.style.display = "flex";
    top.style.alignItems = "center";
    top.style.gap = "10px";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = name;
    cb.disabled = !avail;
    cb.checked = avail;
    cb.onchange = updateStartBtn;

    const label = document.createElement("span");
    label.textContent = name;
    label.style.fontWeight = "800";

    top.appendChild(cb);
    top.appendChild(label);

    const note = document.createElement("div");
    note.className = "note";
    note.textContent = avail ? "available" : reason;

    card.appendChild(top);
    card.appendChild(note);

    card.onclick = () => {
      if(cb.disabled) return;
      cb.checked = !cb.checked;
      updateStartBtn();
    };

    box.appendChild(card);
  });
  updateStartBtn();
}

async function loadRuns(){
  const box = document.getElementById("runs");
  const runs = await jget("/api/runs");

  box.innerHTML = "";

  if(!runs.length){
    box.textContent = "No runs yet";
    return;
  }

  runs.forEach(r => {
    const row = document.createElement("div");
    row.className = "runrow";

    const left = document.createElement("div");
    left.style.display = "flex";
    left.style.flexDirection = "column";
    left.style.gap = "3px";

    const a = document.createElement("a");
    a.href = `/runs/${r.run_id}`;
    a.textContent = r.run_id;

    const sub = document.createElement("div");
    sub.className = "hint";
    sub.textContent = r.started_at ? `Started: ${r.started_at}` : "";

    left.appendChild(a);
    if(sub.textContent) left.appendChild(sub);

    const s = document.createElement("span");
    s.className = pillClass(r.status);
    s.textContent = String(r.status || "").toUpperCase() || "—";

    row.appendChild(left);
    row.appendChild(s);

    box.appendChild(row);
  });
  updateStartBtn();
}

async function startScan(){
  const selected = [...document.querySelectorAll("#tools input")]
    .filter(x => x.checked)
    .map(x => x.value);

  if(!selected.length){
    document.getElementById("startResult").textContent = "Select at least one tool.";
    updateStartBtn();
    return;
  }

  const params = new URLSearchParams();
  selected.forEach(t => params.append("tools", t));

  const startBtn = document.getElementById("startBtn");
  startBtn.disabled = true;
  startBtn.textContent = "Starting...";

  try{
    const r = await fetch("/api/run?" + params.toString(), {method:"POST"});
    const data = await r.json();
    document.getElementById("startResult").textContent = "Started: " + data.run_id;
    await loadRuns();
  } finally {
    startBtn.textContent = "Run Selected";
    updateStartBtn();
  }
}

document.getElementById("startBtn").onclick = startScan;

document.getElementById("selectAll").onclick = () => {
  document.querySelectorAll("#tools input").forEach(x => {
    if(!x.disabled) x.checked = true;
  });
  updateStartBtn();
};

document.getElementById("clearAll").onclick = () => {
  document.querySelectorAll("#tools input").forEach(x => x.checked = false);
  updateStartBtn();
};

loadTools();
loadRuns();

updateStartBtn();
