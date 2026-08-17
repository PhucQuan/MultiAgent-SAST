# Lovable Prompt cho Findings Dashboard Redesign

## 1. Cach dung

Co the dua nguyen prompt ben duoi cho Lovable hoac mot AI frontend khac.
Neu can, dua them 2 file sau de no co them context:

- `53-dashboard-redesign-spec-v2.md`
- `54-dashboard-functional-content-checklist.md`

## 2. Prompt chinh de paste vao Lovable

```text
Design and build a clean enterprise-style web dashboard for reviewing static code security findings from exported JSON reports.

Product context:
- This is not a marketing site.
- This is not an AI chatbot UI.
- This is a local security review console for an Aegis-SAST project.
- The dashboard sits on top of exported report JSON files and local reviewer feedback.
- Do not design around scanner internals, AST views, or terminal output.

Primary goal:
- Help a reviewer quickly move through a queue of SAST findings, inspect evidence, and record review decisions.

Visual direction:
- Serious enterprise security product.
- Light theme.
- Inspired by Datadog Code Security, Snyk Code, and GitHub security alert tables.
- Compact, clean, highly scannable.
- Use subtle borders and restrained shadows.
- Avoid anything that looks like AI demo UI, glassmorphism, hero sections, oversized cards, glowing gradients, or excessive pill badges.

Layout direction:
- Desktop layout should prioritize a 3-column structure:
  1. Left report explorer
  2. Center findings review queue
  3. Right finding detail pane
- If you add a slim app rail, keep it visually quiet.
- Do not create a separate always-visible fourth column just for actions.
- Review actions must live inside the selected finding detail pane.

Top bar requirements:
- Page title: "Static Code Findings"
- Small subtitle: "Local review console for exported Aegis reports"
- Show active report summary on the right:
  - report name
  - scan profile
  - timestamp
  - total findings
- Show a compact summary strip for:
  - actionable
  - needs review
  - reports loaded
  - reviewed locally
- Include actions:
  - Import JSON
  - Refresh reports
  - Optional: Export feedback

Left explorer requirements:
- Title: "Reports"
- Sections:
  - saved reports list
  - quick actions
  - reviewer memory summary
- Each report item should show:
  - report name
  - shortened target path
  - report type
  - total findings
  - actionable count
  - timestamp
- Selected report should be obvious but subtle.

Center queue requirements:
- Make the center area feel like a real security review table, not a card gallery.
- Include a compact filter toolbar with:
  - text search
  - status filter
  - severity filter
  - language filter
  - family filter
  - include muted checkbox
- Search placeholder:
  - "Search by file, family, reason code, or note"
- Findings table should support these columns or a compact variation:
  - risk
  - finding
  - location
  - review
- Each row should show:
  - severity
  - title
  - location
  - status
  - confidence
  - reviewer override if present
  - at most 1 or 2 small secondary tags
- Selected row needs a clear left accent and background state.

Right detail pane requirements:
- This pane is for the currently selected finding.
- Organize it into either tabs or clearly separated sections:
  - Overview
  - Evidence
  - Review
- Overview must include:
  - title
  - severity
  - triage status
  - confidence
  - file path and line
  - language
  - AI triage summary
  - recommendation
  - manual review warning if needed
- Evidence must include:
  - evidence path
  - source context
  - sink context
  - workflow route
  - reason codes
  - optional graph slice stats
  - optional agent reviews
- Review must include:
  - disposition buttons:
    - Confirmed
    - Needs-review
    - False-positive
    - Suppressed
  - mute / unmute
  - reviewer note textarea
  - save note
  - reset local review state
  - last updated

Data assumptions:
- Assume the UI receives normalized report data with:
  - report summary
  - findings
  - triage summary
  - severity summary
- Each finding may include:
  - message
  - severity
  - status
  - confidence
  - family
  - filePath
  - line
  - language
  - explanation
  - recommendation
  - evidencePath
  - sourceContext
  - sinkContext
  - reasonCodes
  - workflowRoute
  - graphSlice
  - agentReviews
  - manualReviewRequired
- Local reviewer memory may include:
  - disposition
  - note
  - muted
  - updatedAt

UX constraints:
- The findings queue should be the dominant area of the page.
- The UI should feel calm, not flashy.
- Do not use oversized headers.
- Do not make every panel equally loud.
- Reduce visual clutter from too many badges.
- Use simple language. Avoid overusing words like "agent", "copilot", or "AI assistant" in the visible UI.

Responsive behavior:
- Desktop: 3-column review layout.
- Tablet: collapse explorer or detail into drawers.
- Mobile: stacked layout, selected finding opens a full-screen detail view.

Implementation preferences:
- React + Next.js + Tailwind CSS.
- Clean component structure.
- Reusable table row, sidebar item, stat cell, detail section, and review controls.
- Keep the architecture boundary clean: the UI reads exported report data and local review state only.

Deliverables:
- A polished desktop-first dashboard page.
- Responsive tablet/mobile layout.
- A realistic mock data example.
- Clean component naming and easy-to-read structure.

Important:
- Make it look like a real security product, not an AI-generated dashboard toy.
```

## 3. Prompt bo sung neu muon Lovable uu tien structure hon visual

```text
Please optimize this dashboard for information hierarchy and review workflow first, visual decoration second.

The main UX problem in the current version is clutter:
- too many simultaneous panels
- not enough width for the findings queue
- too many pills and card-like boxes
- review actions were separated into their own column

Fix that by:
- making the findings table the main focus
- moving review actions inside the selected finding detail pane
- using a compact toolbar and summary strip
- reducing visual noise
- using a real enterprise table layout
```

## 4. Functional block de paste rieng neu can

```text
Required functionality:
- list saved reports
- import JSON report
- refresh reports
- select a report
- display active report summary
- search findings
- filter by status
- filter by severity
- filter by language
- filter by family
- toggle include muted
- show findings table
- select a finding
- show finding details
- show AI triage summary
- show recommendation
- show source and sink code context
- show evidence path
- allow reviewer disposition override
- allow mute/unmute
- allow reviewer note save
- allow local review reset
- allow feedback export

Out of scope:
- scanner engine
- AST visualization as the main page
- direct CLI orchestration
- auth system
- multi-user collaboration
- CI/CD management
```

## 5. Ket luan

Neu muon giao cho AI khac code lai, thu tu de dua context nen la:

1. file spec V2
2. file checklist chuc nang
3. prompt Lovable

Nhu vay AI kia se de ra giao dien sach hon va it bi lap lai nhung loi "chan chit" cua ban vua roi.
