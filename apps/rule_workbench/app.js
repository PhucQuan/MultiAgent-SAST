const state = {
  config: null,
  latestBundle: null,
};

const elements = {
  artifactPreview: document.getElementById("artifact-preview"),
  artifactTabs: document.getElementById("artifact-tabs"),
  buildButton: document.getElementById("build-button"),
  bundleForm: document.getElementById("bundle-form"),
  family: document.getElementById("family"),
  inputPath: document.getElementById("input-path"),
  language: document.getElementById("language"),
  legacyFormat: document.getElementById("legacy-format"),
  limit: document.getElementById("limit"),
  normalizedFormat: document.getElementById("normalized-format"),
  outputDir: document.getElementById("output-dir"),
  profile: document.getElementById("profile"),
  provenanceSource: document.getElementById("provenance-source"),
  seedSuggestions: document.getElementById("seed-suggestions"),
  snapshotVersion: document.getElementById("snapshot-version"),
  statusText: document.getElementById("status-text"),
  summaryCard: document.getElementById("summary-card"),
  validationFormat: document.getElementById("validation-format"),
};

async function boot() {
  try {
    setStatus("Loading workbench config...");
    const response = await fetch("/api/config");
    const config = await response.json();
    state.config = config;
    hydrateForm(config);
    setStatus("Ready.");
  } catch (error) {
    setStatus(`Config load failed: ${error.message}`, true);
  }
}

function hydrateForm(config) {
  fillSelect(elements.seedSuggestions, config.seed_inputs.map((item) => item.path), "");
  fillSelect(elements.language, config.languages, config.defaults.language);
  fillSelect(elements.family, config.families, config.defaults.family);
  fillSelect(elements.profile, config.profiles, config.defaults.profile);

  elements.normalizedFormat.value = config.defaults.normalized_format;
  elements.validationFormat.value = config.defaults.validation_format;
  elements.legacyFormat.value = config.defaults.legacy_format;
  elements.provenanceSource.value = config.defaults.provenance_source;
  elements.snapshotVersion.value = config.defaults.snapshot_version;

  const firstSeed = config.seed_inputs[0]?.path || "";
  elements.seedSuggestions.value = firstSeed;
  elements.inputPath.value = firstSeed;
  elements.outputDir.value = firstSeed ? deriveOutputDir(firstSeed) : "";
}

function fillSelect(select, values, selectedValue) {
  select.innerHTML = "";
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    option.selected = value === selectedValue;
    select.appendChild(option);
  });
}

function deriveOutputDir(inputPath) {
  const trimmed = inputPath.trim();
  if (!trimmed) {
    return "";
  }
  const parts = trimmed.split("/");
  const fileName = parts[parts.length - 1] || "bundle";
  const stem = fileName.replace(/\.[^.]+$/, "");
  return `reports/rule_review/${stem}`;
}

function setStatus(message, isError = false) {
  elements.statusText.textContent = message;
  elements.statusText.dataset.state = isError ? "error" : "ok";
}

function setSummary(bundle) {
  if (!bundle) {
    elements.summaryCard.classList.add("empty");
    elements.summaryCard.textContent = "Run the bundle builder to see artifact paths and validation status.";
    return;
  }

  elements.summaryCard.classList.remove("empty");
  const verdict = bundle.valid ? "valid" : "needs fixes";
  elements.summaryCard.innerHTML = `
    <div class="summary-topline">
      <strong>${verdict}</strong>
      <span>${bundle.rules_checked} rule(s)</span>
      <span>${bundle.error_count} error(s)</span>
      <span>${bundle.warning_count} warning(s)</span>
    </div>
  `;
}

function setArtifactTabs(artifacts) {
  elements.artifactTabs.innerHTML = "";
  const entries = Object.entries(artifacts).filter(([, path]) => Boolean(path));
  if (!entries.length) {
    elements.artifactPreview.textContent = "No artifact selected.";
    return;
  }

  entries.forEach(([label, path], index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "artifact-tab";
    button.textContent = label.replace(/_/g, " ");
    button.dataset.path = path;
    if (index === 0) {
      button.classList.add("active");
    }
    button.addEventListener("click", async () => {
      document
        .querySelectorAll(".artifact-tab")
        .forEach((item) => item.classList.toggle("active", item === button));
      await loadArtifact(path);
    });
    elements.artifactTabs.appendChild(button);
  });

  loadArtifact(entries[0][1]).catch((error) => {
    elements.artifactPreview.textContent = `Artifact preview failed: ${error.message}`;
  });
}

async function loadArtifact(path) {
  setStatus(`Loading artifact ${path}...`);
  const response = await fetch(`/api/artifact?path=${encodeURIComponent(path)}`);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Unable to load artifact.");
  }

  const header = [`# ${payload.path}`];
  if (payload.truncated) {
    header.push("# Preview truncated to keep the browser responsive.");
  }
  header.push("");
  elements.artifactPreview.textContent = `${header.join("\n")}${payload.content}`;
  setStatus(`Loaded ${payload.path}.`);
}

async function handleSubmit(event) {
  event.preventDefault();
  const payload = {
    input_path: elements.inputPath.value.trim(),
    output_dir: elements.outputDir.value.trim(),
    language: elements.language.value,
    family: elements.family.value,
    limit: elements.limit.value.trim(),
    normalized_format: elements.normalizedFormat.value,
    validation_format: elements.validationFormat.value,
    profile: elements.profile.value,
    provenance_source: elements.provenanceSource.value.trim(),
    snapshot_version: elements.snapshotVersion.value.trim(),
    legacy_format: elements.legacyFormat.value,
  };

  elements.buildButton.disabled = true;
  setStatus("Building review bundle...");

  try {
    const response = await fetch("/api/build-review-bundle", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Bundle build failed.");
    }

    state.latestBundle = result;
    setSummary(result.bundle);
    setArtifactTabs(result.bundle.artifacts);
    setStatus(`Bundle ready in ${result.output_dir}.`);
  } catch (error) {
    setSummary(null);
    elements.artifactTabs.innerHTML = "";
    elements.artifactPreview.textContent = `Bundle build failed: ${error.message}`;
    setStatus(`Build failed: ${error.message}`, true);
  } finally {
    elements.buildButton.disabled = false;
  }
}

elements.seedSuggestions.addEventListener("change", () => {
  const selectedPath = elements.seedSuggestions.value;
  elements.inputPath.value = selectedPath;
  elements.outputDir.value = deriveOutputDir(selectedPath);
});

elements.inputPath.addEventListener("input", () => {
  if (!elements.outputDir.matches(":focus")) {
    elements.outputDir.value = deriveOutputDir(elements.inputPath.value);
  }
});

elements.bundleForm.addEventListener("submit", handleSubmit);

boot();
