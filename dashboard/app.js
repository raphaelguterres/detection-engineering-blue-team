const data = window.DETECTION_DASHBOARD;
const labels = { detections: "detecções", techniques: "técnicas MITRE", tactics: "táticas", regression_pairs: "pares de regressão" };
const metrics = document.querySelector("#metrics");
const filter = document.querySelector("#severity-filter");
const body = document.querySelector("#detections");

Object.entries(data.summary).forEach(([key, value]) => {
  metrics.insertAdjacentHTML("beforeend", `<article class="metric"><strong>${value}</strong><span>${labels[key]}</span></article>`);
});

const maxTactic = Math.max(...Object.values(data.tactics));
document.querySelector("#tactics").innerHTML = Object.entries(data.tactics).map(([name, count]) => `
  <div class="bar-row"><div><span>${name}</span><b>${count}</b></div><i><em style="width:${(count / maxTactic) * 100}%"></em></i></div>`).join("");

Object.keys(data.severities).forEach((severity) => filter.insertAdjacentHTML("beforeend", `<option value="${severity}">${severity}</option>`));

function renderRows() {
  const selected = filter.value;
  body.innerHTML = data.detections.filter((item) => selected === "all" || item.severity === selected).map((item) => `
    <tr><td><strong>${item.id}</strong><small>${item.status}</small></td><td>${item.technique}</td><td>${item.tactic}</td><td><span class="severity ${item.severity}">${item.severity}</span></td><td><a href="../${item.simulation}">simulação segura ↗</a></td></tr>`).join("");
}
filter.addEventListener("change", renderRows);
renderRows();
