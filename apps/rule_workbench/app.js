const QUICK_PROMPTS = [
  {
    label: "Command",
    text: [
      "Python command injection via shell-enabled subprocess.",
      "Sources: request.args.get(), input()",
      "Sinks: subprocess.run(..., shell=True), os.system()",
      "Sanitizers: shlex.quote()",
    ].join("\n"),
  },
  {
    label: "Path",
    text: [
      "Python path traversal when user input reaches file reads.",
      "Sources: request.args.get(), input()",
      "Sinks: open(), pathlib.Path.read_text()",
      "Sanitizers: pathlib.Path.resolve() under a trusted root",
    ].join("\n"),
  },
  {
    label: "SQLi",
    text: [
      "Python SQL injection through string-built queries.",
      "Sources: request.args.get(), input()",
      "Sinks: cursor.execute(), connection.execute()",
      "Sanitizers: parameterized queries",
    ].join("\n"),
  },
];

const state = {
  config: null,
  latestDraft: null,
};

const elements = {
  artifactPreview: document.getElementById("artifact-preview"),
  artifactTabs: document.getElementById("artifact-tabs"),
  chatFeed: document.getElementById("chat-feed"),
  clearDraftButton: document.getElementById("clear-draft-button"),
  draftBuildButton: document.getElementById("draft-build-button"),
  draftDescription: document.getElementById("draft-description"),
  draftFamily: document.getElementById("draft-family"),
  draftForm: document.getElementById("draft-form"),
  draftLanguage: document.getElementById("draft-language"),
  draftOutputDir: document.getElementById("draft-output-dir"),
  draftProfile: document.getElementById("draft-profile"),
  draftRuleId: document.getElementById("draft-rule-id"),
  draftSeedInput: document.getElementById("draft-seed-input"),
  draftSeedSuggestions: document.getElementById("draft-seed-suggestions"),
  draftTitle: document.getElementById("draft-title"),
  quickExamples: document.getElementById("quick-examples"),
  statusText: document.getElementById("status-text"),
  summaryCard: document.getElementById("summary-card"),
};

async function boot() {
  seedChatFeed();
  renderQuickExamples();
  setSummary(null);

  try {
    setStatus("Loading...");
    const response = await fetch("/api/config");
    const config = await response.json();
    state.config = config;
    hydrateForm(config);
    setStatus("Ready");
  } catch (error) {
    appendChatMessage("assistant", `Config load failed: ${error.message}`, true);
    setStatus(`Config load failed: ${error.message}`, true);
  }
}

function seedChatFeed() {
  elements.chatFeed.innerHTML = "";
  appendChatMessage(
    "assistant",
    "Describe a rule. Optional: Sources, Sinks, Sanitizers."
  );
}

function renderQuickExamples() {
  elements.quickExamples.innerHTML = "";

  QUICK_PROMPTS.forEach((prompt) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "example-chip";
    button.textContent = prompt.label;
    button.addEventListener("click", () => {
      elements.draftDescription.value = prompt.text;
      elements.draftDescription.focus();
    });
    elements.quickExamples.appendChild(button);
  });
}

function hydrateForm(config) {
  const seedPaths = config.seed_inputs.map((item) => item.path);

  fillSelect(elements.draftSeedSuggestions, seedPaths, "");
  fillSelect(elements.draftLanguage, config.languages, config.defaults.language);
  fillSelect(elements.draftFamily, config.families, config.defaults.family);
  fillSelect(elements.draftProfile, config.profiles, config.defaults.profile);

  const firstSeed = config.seed_inputs[0]?.path || "";
  elements.draftSeedSuggestions.value = firstSeed;
  elements.draftSeedInput.value = firstSeed;
  elements.draftOutputDir.value = firstSeed ? deriveDraftOutputDir(firstSeed) : "";
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

function deriveDraftOutputDir(inputPath) {
  const trimmed = inputPath.trim();
  if (!trimmed) {
    return "";
  }
  const parts = trimmed.split("/");
  const fileName = parts[parts.length - 1] || "draft";
  const stem = fileName.replace(/\.[^.]+$/, "");
  return `reports/rule_review/${stem}_draft`;
}

function setStatus(message, isError = false) {
  elements.statusText.textContent = message;
  elements.statusText.dataset.state = isError ? "error" : "ok";
}

function setSummary(draft) {
  if (!draft) {
    elements.summaryCard.classList.add("empty");
    elements.summaryCard.textContent = "No draft yet.";
    return;
  }

  const verdict = draft.valid ? "valid" : "needs fixes";
  elements.summaryCard.classList.remove("empty");
  elements.summaryCard.innerHTML = `
    <div class="summary-topline">
      <strong>${verdict}</strong>
      <span class="summary-pill">${draft.rules_checked} rule</span>
      <span class="summary-pill">${draft.error_count} error</span>
      <span class="summary-pill">${draft.warning_count} warning</span>
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
  setStatus("Loading artifact...");
  const response = await fetch(`/api/artifact?path=${encodeURIComponent(path)}`);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Unable to load artifact.");
  }

  const header = [`# ${payload.path}`];
  if (payload.truncated) {
    header.push("# Preview truncated.");
  }
  header.push("");
  elements.artifactPreview.textContent = `${header.join("\n")}${payload.content}`;
  setStatus("Artifact loaded");
}

function appendChatMessage(role, text, isError = false) {
  const article = document.createElement("article");
  article.className = `chat-message ${role}`;

  const badge = document.createElement("span");
  badge.className = "message-role";
  badge.textContent = role === "user" ? "You" : isError ? "Error" : "Aegis";

  const bubble = document.createElement("div");
  bubble.className = `message-bubble${isError ? " message-error" : ""}`;

  const body = document.createElement("div");
  body.className = "message-text";
  body.textContent = text;

  bubble.appendChild(body);
  article.appendChild(badge);
  article.appendChild(bubble);
  elements.chatFeed.appendChild(article);
  elements.chatFeed.scrollTop = elements.chatFeed.scrollHeight;
}

function resetComposer() {
  elements.draftDescription.value = "";
  elements.draftTitle.value = "";
  elements.draftRuleId.value = "";
  elements.draftDescription.focus();
}

async function handleDraftSubmit(event) {
  event.preventDefault();

  const payload = {
    description: elements.draftDescription.value.trim(),
    seed_input_path: elements.draftSeedInput.value.trim(),
    output_dir: elements.draftOutputDir.value.trim(),
    language: elements.draftLanguage.value,
    family: elements.draftFamily.value,
    profile: elements.draftProfile.value,
    title: elements.draftTitle.value.trim(),
    rule_id: elements.draftRuleId.value.trim(),
  };

  if (!payload.description) {
    setStatus("Describe a rule first", true);
    elements.draftDescription.focus();
    return;
  }

  appendChatMessage("user", payload.description);
  elements.draftBuildButton.disabled = true;
  setStatus("Building draft...");

  try {
    const response = await fetch("/api/build-draft-bundle", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Draft build failed.");
    }

    state.latestDraft = result;
    setSummary(result.draft);
    setArtifactTabs(result.draft.artifacts);
    appendChatMessage(
      "assistant",
      `Draft ready. ${result.draft.rules_checked} rule, ${result.draft.error_count} error, ${result.draft.warning_count} warning.`
    );
    setStatus("Draft ready");
  } catch (error) {
    setSummary(null);
    elements.artifactTabs.innerHTML = "";
    elements.artifactPreview.textContent = `Draft build failed: ${error.message}`;
    appendChatMessage("assistant", `Draft build failed: ${error.message}`, true);
    setStatus(`Draft build failed: ${error.message}`, true);
  } finally {
    elements.draftBuildButton.disabled = false;
  }
}

elements.draftSeedSuggestions.addEventListener("change", () => {
  const selectedPath = elements.draftSeedSuggestions.value;
  elements.draftSeedInput.value = selectedPath;
  elements.draftOutputDir.value = deriveDraftOutputDir(selectedPath);
});

elements.draftSeedInput.addEventListener("input", () => {
  if (!elements.draftOutputDir.matches(":focus")) {
    elements.draftOutputDir.value = deriveDraftOutputDir(elements.draftSeedInput.value);
  }
});

elements.clearDraftButton.addEventListener("click", resetComposer);
elements.draftForm.addEventListener("submit", handleDraftSubmit);
elements.draftDescription.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    elements.draftForm.requestSubmit();
  }
});

boot();
