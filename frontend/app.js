const state = {
  mode: "text",
  lastResult: null,
};

const $ = (id) => document.getElementById(id);

const textInput = $("textInput");
const imageInput = $("imageInput");
const dropzone = $("dropzone");

const samples = {
  safe: "The bank security team will contact you tomorrow.",
  phishing: "URGENT: verify your account immediately. Click this link https://example.com/login and enter your password.",
  pressure: "Your account will be suspended immediately. Do not tell anyone. You must act now or access will be blocked.",
};

function setMode(mode) {
  state.mode = mode;
  $("textTab").classList.toggle("active", mode === "text");
  $("imageTab").classList.toggle("active", mode === "image");
  $("textMode").classList.toggle("hidden", mode !== "text");
  $("imageMode").classList.toggle("hidden", mode !== "image");
  $("analyzeLabel").textContent = mode === "text" ? "Analyze message" : "Analyze image";
}

function severityTone(severity) {
  const tones = {
    NONE: "var(--good)", LOW: "var(--good)", MEDIUM: "var(--warn)",
    HIGH: "#ff9b6b", CRITICAL: "var(--danger)",
  };
  return tones[severity] || "var(--accent)";
}

function scoreRing(score, severity) {
  const safeScore = Math.max(0, Math.min(10, Number(score) || 0));
  const deg = safeScore * 36;
  $("scoreRing").style.background = `conic-gradient(${severityTone(severity)} ${deg}deg, #1a2a3e ${deg}deg)`;
  $("overallScore").textContent = safeScore.toFixed(1);
}

function prettyCategory(value) {
  return value.split("_").map((x) => x.charAt(0).toUpperCase() + x.slice(1)).join(" ");
}

function renderSummary(result) {
  const severity = String(result.overall_severity || "none").toUpperCase();
  const categories = result.detected_categories || [];
  const correlations = result.correlations || [];

  scoreRing(result.overall_cvss, severity);
  $("overallSeverity").textContent = severity;
  $("overallSeverity").style.color = severityTone(severity);
  $("resultTitle").textContent = categories.length ? `${categories.length} threat categor${categories.length > 1 ? "ies" : "y"} detected` : "No significant threats detected";
  $("resultSubtitle").textContent = categories.length ? "Review the detector evidence below before deciding what to do next." : "The current input did not match the configured threat patterns.";
  $("processingTime").textContent = result.meta ? `${result.meta.processing_ms} ms` : "—";
  $("categoryCount").textContent = categories.length;
  $("correlationCount").textContent = correlations.length;

  const strip = $("categoryStrip");
  strip.innerHTML = categories.length
    ? categories.map((c) => `<span class="category-chip">${prettyCategory(c)}</span>`).join("")
    : `<div class="category-empty">No detections.</div>`;

  $("explanation").textContent = result.explanation || "No explanation available.";
  $("correlations").innerHTML = correlations.length
    ? correlations.map((c) => `<div class="correlation-item">${escapeHtml(c)}</div>`).join("")
    : `<span class="muted">No correlations.</span>`;

  const recommendations = result.recommendations || [];
  $("recommendations").innerHTML = recommendations.length
    ? recommendations.map((r) => `<div class="recommendation-item">${escapeHtml(r)}</div>`).join("")
    : `<div class="muted">No recommendations.</div>`;

  const extracted = result.extracted_text;
  if (extracted !== undefined) {
    $("extractedPanel").classList.remove("hidden");
    $("extractedText").textContent = extracted || "[OCR returned no text]";
  } else {
    $("extractedPanel").classList.add("hidden");
  }
}

function renderDetectors(detections) {
  const host = $("detections");
  if (!detections || !detections.length) {
    host.innerHTML = `<div class="empty-state"><div class="empty-icon">◎</div><h3>No detector output</h3><p>The engine returned no detector records.</p></div>`;
    return;
  }

  host.innerHTML = detections.map((d) => {
    const statusClass = d.detected ? "status-yes" : "status-no";
    const statusText = d.detected ? "DETECTED" : "CLEAR";
    const indicatorTags = (d.indicators || []).map((i) => `<span class="tag">${escapeHtml(i.name)} · ${(Number(i.confidence) * 100).toFixed(0)}%</span>`).join("");
    const evidence = (d.evidence || []).slice(0, 8).map((e) => {
      const pos = (e.start !== null && e.end !== null && e.start !== undefined && e.end !== undefined) ? `${e.start}-${e.end}` : "";
      return `<div class="evidence-line"><span class="evidence-quote">“${escapeHtml(e.text)}”</span><span class="evidence-pos">${pos}</span></div>`;
    }).join("");
    const vector = d.cvss_metrics?.vector_string || "";
    return `
      <article class="detector-card">
        <div class="detector-head">
          <div class="detector-name">${escapeHtml(prettyCategory(d.category || "unknown").toUpperCase())}</div>
          <div class="detector-status ${statusClass}">${statusText}</div>
        </div>
        <div class="detector-body">
          <div class="detector-stats">
            <div class="stat"><div class="stat-label">Confidence</div><div class="stat-value">${(Number(d.confidence || 0) * 100).toFixed(0)}%</div></div>
            <div class="stat"><div class="stat-label">CVSS</div><div class="stat-value">${Number(d.cvss_score || 0).toFixed(1)}</div></div>
            <div class="stat"><div class="stat-label">Severity</div><div class="stat-value" style="color:${severityTone(String(d.severity || "none").toUpperCase())}">${escapeHtml(String(d.severity || "none").toUpperCase())}</div></div>
          </div>
          ${indicatorTags ? `<div class="list-title">Indicators</div><div class="tag-list">${indicatorTags}</div>` : ""}
          ${evidence ? `<div class="list-title">Evidence</div>${evidence}` : ""}
          ${vector ? `<div class="list-title">CVSS Vector</div><div class="vector">${escapeHtml(vector)}</div>` : ""}
        </div>
      </article>`;
  }).join("");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[char]));
}

function showError(message) {
  $("errorBox").textContent = message;
  $("errorBox").classList.remove("hidden");
}

function clearError() {
  $("errorBox").classList.add("hidden");
  $("errorBox").textContent = "";
}

async function runAnalysis() {
  clearError();
  $("analyzeBtn").disabled = true;
  $("analyzeLabel").textContent = "Analyzing…";
  try {
    let response;
    if (state.mode === "text") {
      const text = textInput.value.trim();
      if (!text) throw new Error("Enter some text first.");
      response = await fetch("/api/analyze/text", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
    } else {
      const file = imageInput.files?.[0];
      if (!file) throw new Error("Choose an image first.");
      const form = new FormData();
      form.append("file", file);
      response = await fetch("/api/analyze/image", { method: "POST", body: form });
    }

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Analysis failed.");
    state.lastResult = data;
    renderSummary(data);
    renderDetectors(data.detections);
  } catch (error) {
    showError(error.message || "Unexpected error.");
  } finally {
    $("analyzeBtn").disabled = false;
    $("analyzeLabel").textContent = state.mode === "text" ? "Analyze message" : "Analyze image";
  }
}

async function checkApi() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error("offline");
    $("apiStatus").innerHTML = `<span class="status-dot" style="background:var(--good)"></span> API online`;
  } catch {
    $("apiStatus").innerHTML = `<span class="status-dot" style="background:var(--danger)"></span> API offline`;
  }
}

$("textTab").addEventListener("click", () => setMode("text"));
$("imageTab").addEventListener("click", () => setMode("image"));
$("analyzeBtn").addEventListener("click", runAnalysis);
$("clearBtn").addEventListener("click", () => {
  textInput.value = "";
  imageInput.value = "";
  $("fileName").textContent = "No file selected";
  $("extractedPanel").classList.add("hidden");
  $("detections").innerHTML = `<div class="empty-state"><div class="empty-icon">◎</div><h3>No analysis yet</h3><p>Run an analysis to see detector confidence, indicators, evidence, and CVSS metrics.</p></div>`;
  $("explanation").textContent = "SENTINEL will summarize the combined result here.";
  $("recommendations").innerHTML = `<div class="muted">No recommendations yet.</div>`;
  $("correlations").innerHTML = `<span class="muted">No correlations.</span>`;
  $("overallSeverity").textContent = "NO ANALYSIS";
  $("overallSeverity").style.color = "var(--accent)";
  $("overallScore").textContent = "0.0";
  $("processingTime").textContent = "—";
  $("categoryCount").textContent = "0";
  $("correlationCount").textContent = "0";
  $("categoryStrip").innerHTML = `<div class="category-empty">No detections yet.</div>`;
  scoreRing(0, "NONE");
  clearError();
});

textInput.addEventListener("input", () => {
  $("charCount").textContent = `${textInput.value.length} / 25000`;
});

imageInput.addEventListener("change", () => {
  $("fileName").textContent = imageInput.files?.[0]?.name || "No file selected";
});

dropzone.addEventListener("dragover", (event) => { event.preventDefault(); dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("dragover");
  const file = event.dataTransfer.files?.[0];
  if (file) {
    try {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      imageInput.files = transfer.files;
    } catch {
      // Some browsers restrict programmatic assignment; the label still updates.
    }
    $("fileName").textContent = file.name;
  }
});

document.querySelectorAll(".sample-btn").forEach((button) => {
  button.addEventListener("click", () => {
    setMode("text");
    textInput.value = samples[button.dataset.sample];
    textInput.dispatchEvent(new Event("input"));
  });
});

$("jsonBtn").addEventListener("click", async () => {
  if (!state.lastResult) return showError("Run an analysis before copying JSON.");
  try {
    await navigator.clipboard.writeText(JSON.stringify(state.lastResult, null, 2));
    $("jsonBtn").textContent = "Copied";
    setTimeout(() => { $("jsonBtn").textContent = "Copy JSON"; }, 1200);
  } catch {
    showError("The browser blocked clipboard access.");
  }
});

checkApi();
setInterval(checkApi, 15000);
