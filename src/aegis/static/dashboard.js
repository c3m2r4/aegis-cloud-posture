"use strict";

(() => {
  const page = document.body.dataset.page;
  const outcomes = ["PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR"];
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const pageSize = 20;
  const byId = (id) => document.getElementById(id);
  let comparisonRunsById = new Map();

  function node(tag, className, text) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (text !== undefined && text !== null) result.textContent = String(text);
    return result;
  }

  function clear(target) {
    target.replaceChildren();
  }

  async function getJson(url) {
    let response;
    try {
      response = await fetch(url, { method: "GET", credentials: "same-origin", headers: { Accept: "application/json" } });
    } catch (_error) {
      throw new Error("The local AEGIS API could not be reached. Check that aegis-web is running.");
    }
    if (!response.ok) {
      const error = new Error(response.status === 404 ? "The requested saved assessment was not found." :
        response.status === 422 ? "The requested assessment or filter is invalid." :
        "The saved assessment data is temporarily unavailable.");
      error.status = response.status;
      throw error;
    }
    try {
      return await response.json();
    } catch (_error) {
      throw new Error("The local API returned an unreadable response.");
    }
  }

  async function postJson(url, payload) {
    let response;
    try {
      response = await fetch(url, { method: "POST", credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    } catch (_error) {
      throw new Error("The local AEGIS API could not be reached. A submitted assessment may continue on the server.");
    }
    if (!response.ok) {
      const messages = { 403: "The request did not pass the dashboard same-origin check.",
        409: "The workflow is not ready or another local scan is running.",
        413: "The request was too large.", 415: "The local API rejected the request format.",
        422: "The request needs valid explicit confirmation.", 503: "The local AEGIS service could not complete this step." };
      throw new Error(messages[response.status] || "The local AEGIS service rejected this request.");
    }
    try { return await response.json(); }
    catch (_error) { throw new Error("The local API returned an unreadable response."); }
  }

  function showError(target, message, retry) {
    clear(target);
    target.hidden = false;
    target.append(node("span", "", message));
    if (retry) {
      const button = node("button", "", "Retry");
      button.type = "button";
      button.addEventListener("click", retry);
      target.append(button);
    }
  }

  function hideError(target) {
    target.hidden = true;
    clear(target);
  }

  function empty(target, heading, detail) {
    clear(target);
    const box = node("div", "empty-state");
    box.append(node("strong", "", heading), node("p", "", detail));
    target.append(box);
  }

  function badge(value, kind = "status") {
    const normalized = typeof value === "string" ? value.toUpperCase() : "UNKNOWN";
    const known = kind === "outcome" ? outcomes : kind === "severity" ? severities : ["RUNNING", "COMPLETED", "PARTIAL", "FAILED", "SUCCESS", "UNSUPPORTED", "ERROR"];
    const safe = known.includes(normalized) ? normalized.toLowerCase() : "neutral";
    return node("span", `badge badge-${safe}`, normalized.replaceAll("_", " "));
  }

  function statusLabel(value) {
    return typeof value === "string" ? value.replaceAll("_", " ") : "UNKNOWN";
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Timestamp unavailable";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function shortId(value) {
    return typeof value === "string" && value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value || "—";
  }

  function appendCell(row, content, className = "") {
    const cell = node("td", className);
    if (content instanceof Node) cell.append(content);
    else cell.textContent = content === undefined || content === null ? "—" : String(content);
    row.append(cell);
    return cell;
  }

  function table(headers, className = "") {
    const wrapper = node("div", "table-wrap");
    const tableElement = node("table", className);
    const head = node("thead");
    const headerRow = node("tr");
    headers.forEach((label) => {
      const heading = node("th", "", label);
      heading.scope = "col";
      headerRow.append(heading);
    });
    head.append(headerRow);
    tableElement.append(head, node("tbody"));
    wrapper.append(tableElement);
    return { wrapper, body: tableElement.tBodies[0] };
  }

  function setLoading(target, message) {
    clear(target);
    const loading = node("div", "loading-state", message);
    loading.setAttribute("role", "status");
    loading.setAttribute("aria-live", "polite");
    target.append(loading);
  }

  async function assessmentSummaries(items) {
    return Promise.all(items.map(async (item) => {
      try {
        const detail = await getJson(`/api/assessments/${encodeURIComponent(item.id)}`);
        return { item, detail };
      } catch (_error) {
        return { item, detail: null };
      }
    }));
  }

  function appendAssessmentRow(body, item, detail, withSearch = false) {
    const row = node("tr");
    const idLink = node("a", "assessment-link", item.id);
    idLink.href = `/assessments/${encodeURIComponent(item.id)}`;
    idLink.title = item.id;
    appendCell(row, idLink);
    const date = node("span", "table-date", formatDate(item.started_at));
    appendCell(row, date);
    appendCell(row, badge(item.status));
    appendCell(row, detail ? String(detail.scope.cloud_resource_count) : "—", "table-summary");
    const findings = detail ? node("span", "table-summary", String(detail.summary.finding_count)) : node("span", "table-summary", "—");
    if (detail) findings.append(node("span", "table-subtle", `${detail.summary.by_outcome.FAIL || 0} FAIL · ${detail.summary.by_outcome.NOT_SUPPORTED || 0} unsupported`));
    appendCell(row, findings);
    if (withSearch) row.dataset.search = `${item.id} ${item.status} ${item.started_at}`.toLowerCase();
    body.append(row);
  }

  async function loadOverview() {
    const errorBox = byId("overview-error");
    hideError(errorBox);
    ["outcome-list", "severity-list", "recent-assessments", "inventory-types", "inventory-services", "top-findings", "evidence-gaps"]
      .forEach((id) => setLoading(byId(id), "Loading persisted assessment data…"));
    try {
      const [overview, history] = await Promise.all([getJson("/api/overview"), getJson("/api/assessments?limit=8&offset=0")]);
      byId("metric-total").textContent = String(history.total);
      const latest = overview.latest_assessment;
      byId("context-status").textContent = latest ? statusLabel(latest.status) : "No saved runs";
      byId("context-region").textContent = latest ? (latest.region || "Region unavailable") : "—";
      let endpointLabel = "No assessment history";
      if (latest?.endpoint) {
        try {
          const endpoint = new URL(latest.endpoint);
          endpointLabel = endpoint.host;
        } catch (_error) {
          endpointLabel = "Configured endpoint";
        }
      }
      byId("context-endpoint").textContent = endpointLabel;
      byId("metric-time").textContent = latest ? `Assessment started ${formatDate(latest.started_at)}` : "Create a saved assessment with the AEGIS CLI";
      byId("metric-resources").textContent = latest ? String(overview.resource_count) : "—";
      const latestDiscovery = overview.coverage.discovery?.last_successful_discovery_at;
      byId("inventory-discovery-time").textContent = latestDiscovery
        ? `Last successful discovery operation: ${formatDate(latestDiscovery)}` : "No successful discovery operation recorded.";
      const serviceInventory = byId("inventory-services");
      clear(serviceInventory);
      const serviceCounts = latest ? (overview.resources_by_service || {}) : {};
      const serviceCoverage = latest ? (overview.coverage.discovery?.services || []) : [];
      if (!serviceCoverage.length) empty(serviceInventory, "No discovery records", "Service counts appear after a discovery run.");
      else serviceCoverage.forEach((item) => {
        const row = node("div", "inventory-service-row");
        row.append(
          node("span", "inventory-service-name", item.service),
          badge(item.state),
          node("strong", "inventory-service-count", serviceCounts[item.service] || 0),
        );
        serviceInventory.append(row);
      });
      const deferred = overview.coverage.discovery?.deferred_operations || [];
      byId("inventory-deferred").textContent = deferred.map((item) =>
        `${item.service}:${item.operation} was verified but deferred: ${item.reason}`
      ).join(" ");
      byId("inventory-unassessed").textContent = latest
        ? `${overview.discovered_but_unassessed_count || 0} discovered resources have no persisted rule evaluation; this is not a pass.`
        : "";
      byId("metric-findings").textContent = latest ? String(overview.summary.finding_count) : "—";
      const statusBadge = byId("latest-status-badge");
      clear(statusBadge);
      statusBadge.append(latest ? badge(latest.status) : badge("NO DATA"));
      const types = byId("inventory-types");
      clear(types);
      const resourceTypes = latest ? (overview.resource_types || []) : [];
      if (!resourceTypes.length) empty(types, "No resource types recorded", "This assessment has no normalized resource inventory.");
      else resourceTypes.forEach((type) => {
        const item = node("div", "inventory-type");
        item.append(node("span", "inventory-type-mark", "◈"), node("span", "inventory-type-name", type));
        types.append(item);
      });
      const coverageNote = byId("coverage-note");
      if (latest && ["RUNNING", "PARTIAL", "FAILED"].includes(latest.status)) {
        coverageNote.hidden = false;
        coverageNote.textContent = latest.status === "RUNNING" ? "This assessment is still running; its findings and coverage are incomplete." : latest.status === "PARTIAL" ? "This assessment has incomplete collection or evaluation coverage." : "This assessment did not complete successfully.";
        const link = node("a", "", "Review details");
        link.href = `/assessments/${encodeURIComponent(latest.id)}`;
        coverageNote.append(link);
      } else coverageNote.hidden = true;
      byId("coverage-detail-link").href = latest ? `/assessments/${encodeURIComponent(latest.id)}` : "/assessments";
      byId("findings-view-all").href = latest ? `/assessments/${encodeURIComponent(latest.id)}` : "/assessments";
      byId("coverage-operations").textContent = String(overview.coverage.operation_count);
      const ruleErrors = overview.summary.by_outcome.ERROR || 0;
      const ruleUnsupported = overview.summary.by_outcome.NOT_SUPPORTED || 0;
      byId("coverage-errors").textContent = String(overview.coverage.errors.length + ruleErrors);
      byId("coverage-unsupported").textContent = String(overview.coverage.unsupported_checks.length + ruleUnsupported);
      byId("coverage-incomplete").textContent = String((overview.coverage.incomplete_operations || []).length);
      const statusList = byId("coverage-status-list");
      clear(statusList);
      Object.entries(overview.coverage.by_status).forEach(([name, count]) => {
        const row = node("div", "coverage-status-row");
        row.append(node("span", "", statusLabel(name)), node("strong", "", count));
        statusList.append(row);
      });

      const outcomes = byId("outcome-list");
      clear(outcomes);
      if (!latest) empty(outcomes, "No assessment history", "Run an assessment with the AEGIS CLI. This page only displays saved results.");
      else outcomes.append(...Object.entries(overview.summary.by_outcome).map(([name, count]) => {
        const row = node("div", "outcome-row");
        const label = node("span", "outcome-name");
        label.append(node("span", `outcome-mark ${name.toLowerCase()}`), document.createTextNode(statusLabel(name)));
        row.append(label, node("span", "outcome-count", count));
        return row;
      }));
      const severityList = byId("severity-list");
      clear(severityList);
      if (!latest) empty(severityList, "No findings recorded", "Severity counts are available after an assessment is saved.");
      else severityList.append(...Object.entries(overview.summary.by_severity).map(([name, count]) => {
        const row = node("div", "severity-row");
        const label = node("span", "severity-name");
        label.append(node("span", `severity-mark ${name.toLowerCase()}`), document.createTextNode(name));
        row.append(label, node("span", "severity-count", count));
        return row;
      }));
      const failed = latest ? (overview.summary.by_outcome.FAIL || 0) : 0;
      const totalEvaluations = latest ? overview.summary.finding_count : 0;
      const circumference = 2 * Math.PI * 48;
      const ringValue = byId("outcome-ring-value");
      ringValue.setAttribute("stroke-dasharray", `${totalEvaluations ? circumference * failed / totalEvaluations : 0} ${circumference}`);
      byId("outcome-ring").setAttribute("aria-label", `${failed} confirmed FAIL outcomes out of ${totalEvaluations} rule evaluations`);
      ringValue.classList.toggle("has-fail", failed > 0);

      const topFindings = byId("top-findings");
      const evidenceGaps = byId("evidence-gaps");
      if (latest) {
        const findingBase = `/api/assessments/${encodeURIComponent(latest.id)}/findings?limit=5&offset=0`;
        const [failures, unsupported, errors] = await Promise.all([
          getJson(`${findingBase}&outcome=FAIL`),
          getJson(`${findingBase}&outcome=NOT_SUPPORTED`),
          getJson(`${findingBase}&outcome=ERROR`)
        ]);
        renderFindingList(topFindings, failures.items, "No confirmed failures", "No FAIL outcomes were recorded for this assessment.");
        renderFindingList(evidenceGaps, [...unsupported.items, ...errors.items].slice(0, 5), "No rule evidence gaps", "No NOT_SUPPORTED or ERROR rule outcomes were recorded.");
      } else {
        empty(topFindings, "No findings available", "Save an assessment to review its persisted rule results.");
        empty(evidenceGaps, "No coverage data available", "Save an assessment to see unsupported and errored checks.");
      }
      const recentTarget = byId("recent-assessments");
      clear(recentTarget);
      if (!history.items.length) empty(recentTarget, "No saved assessments", "Assessment history will appear here after the CLI saves a run.");
      else {
        const grid = table(["Assessment", "Started", "Status", "Resources", "Findings"], "recent-table");
        const rows = await assessmentSummaries(history.items);
        rows.forEach(({ item, detail }) => appendAssessmentRow(grid.body, item, detail));
        recentTarget.append(grid.wrapper);
      }
    } catch (error) {
      showError(errorBox, error.message, loadOverview);
      ["outcome-list", "severity-list", "recent-assessments", "inventory-types", "inventory-services", "top-findings", "evidence-gaps"]
        .forEach((id) => empty(byId(id), "Data unavailable", "Retry the persisted data request."));
      byId("inventory-deferred").textContent = "";
    }
  }

  function renderFindingList(target, items, heading, detail) {
    clear(target);
    if (!items.length) {
      empty(target, heading, detail);
      return;
    }
    items.forEach((finding) => {
      const row = node("article", "command-finding");
      const icon = node("span", `case-icon ${finding.outcome === "FAIL" ? "case-icon-red" : "case-icon-amber"}`, finding.outcome === "FAIL" ? "▲" : "◇");
      const content = node("div", "command-finding-content");
      const headingRow = node("div", "command-finding-heading");
      headingRow.append(node("strong", "", finding.title || finding.rule_id || "Rule evaluation"), badge(finding.severity, "severity"));
      content.append(headingRow);
      content.append(node("div", "command-finding-resource", `${finding.rule_id || "Unknown rule"} · ${finding.resource_type || "Unknown resource"} / ${finding.resource_id || "identity unavailable"}`));
      content.append(node("p", "command-finding-reason", finding.reason || finding.description || "No rationale was recorded."));
      row.append(icon, content);
      target.append(row);
    });
  }

  let historyOffset = 0;
  let historyTotal = 0;
  let historyItems = [];
  async function loadHistory() {
    const errorBox = byId("history-error");
    hideError(errorBox);
    setLoading(byId("assessment-table"), "Loading assessment history…");
    byId("page-previous").disabled = true;
    byId("page-next").disabled = true;
    try {
      const data = await getJson(`/api/assessments?limit=${pageSize}&offset=${historyOffset}`);
      historyItems = data.items;
      historyTotal = data.total;
      byId("history-count").textContent = `${historyTotal} saved assessment${historyTotal === 1 ? "" : "s"}`;
      const target = byId("assessment-table");
      clear(target);
      if (!historyItems.length) empty(target, "No assessment history", "No saved runs were found in the configured local database.");
      else {
        const grid = table(["Assessment ID", "Started", "Status", "Resources", "Findings"], "assessment-list-table");
        const rows = await assessmentSummaries(historyItems);
        rows.forEach(({ item, detail }) => appendAssessmentRow(grid.body, item, detail, true));
        target.append(grid.wrapper);
        filterHistoryRows();
      }
      const first = historyTotal ? historyOffset + 1 : 0;
      const last = Math.min(historyOffset + historyItems.length, historyTotal);
      byId("page-indicator").textContent = `${first}–${last} of ${historyTotal}`;
      byId("page-previous").disabled = historyOffset <= 0;
      byId("page-next").disabled = historyOffset + pageSize >= historyTotal;
    } catch (error) {
      showError(errorBox, error.message, loadHistory);
      empty(byId("assessment-table"), "History unavailable", "Retry the saved assessment request.");
    }
  }

  function filterHistoryRows() {
    const query = byId("history-search").value.trim().toLowerCase();
    document.querySelectorAll("#assessment-table tbody tr").forEach((row) => {
      row.hidden = Boolean(query) && !row.dataset.search.includes(query);
    });
  }

  const sectionOffsets = { findings: 0, resources: 0, operations: 0 };
  const sectionTotals = { findings: 0, resources: 0, operations: 0 };
  const resourceFilters = { service: "", resourceType: "" };
  let findingPageItems = [];
  let currentAssessmentId = "";

  async function loadDetail() {
    currentAssessmentId = document.body.dataset.assessmentId;
    const errorBox = byId("detail-error");
    hideError(errorBox);
    byId("detail-loading").hidden = false;
    byId("detail-content").hidden = true;
    try {
      const data = await getJson(`/api/assessments/${encodeURIComponent(currentAssessmentId)}`);
      const assessment = data.assessment;
      byId("detail-loading").hidden = true;
      byId("detail-content").hidden = false;
      const headingBadge = byId("detail-status");
      clear(headingBadge);
      headingBadge.append(badge(assessment.status));
      document.title = `Assessment ${shortId(assessment.id)} · AEGIS`;
      const summary = byId("assessment-summary");
      clear(summary);
      const cards = [
        ["STATUS", statusLabel(assessment.status), assessment.status === "RUNNING" ? "Collection/evaluation still in progress" : assessment.status === "PARTIAL" ? "Some checks lack complete evidence" : assessment.status === "FAILED" ? "Assessment did not complete" : "Persisted assessment state"],
        ["STARTED", formatDate(assessment.started_at), assessment.completed_at ? `Completed ${formatDate(assessment.completed_at)}` : "Completion time unavailable"],
        ["CLOUD RESOURCES", data.scope.cloud_resource_count, data.scope.resource_types.join(", ") || "No resource types recorded"],
        ["FINDINGS", data.summary.finding_count, `${data.summary.by_outcome.FAIL || 0} confirmed FAIL outcomes`]
      ];
      cards.forEach(([label, value, note]) => {
        const card = node("article", "metric-card");
        card.append(node("div", "metric-label", label), node("div", "metric-value metric-status", value), node("div", "metric-note", note));
        summary.append(card);
      });
      const partial = byId("partial-notice");
      const ruleErrors = data.summary.by_outcome.ERROR || 0;
      const ruleUnsupported = data.summary.by_outcome.NOT_SUPPORTED || 0;
      if (assessment.status !== "COMPLETED" || data.coverage.errors.length || data.coverage.unsupported_checks.length || ruleErrors || ruleUnsupported) {
        partial.hidden = false;
        partial.textContent = `Assessment is ${statusLabel(assessment.status)}: ${data.coverage.errors.length} operation errors, ${data.coverage.unsupported_checks.length} unsupported operations, ${ruleErrors} rule errors, and ${ruleUnsupported} unsupported rule outcomes. This is not a security pass.`;
      } else partial.hidden = true;
      byId("report-markdown").href = `/api/assessments/${encodeURIComponent(currentAssessmentId)}/reports/markdown`;
      byId("report-json").href = `/api/assessments/${encodeURIComponent(currentAssessmentId)}/reports/json`;
      await Promise.all([loadFindings(), loadResources(), loadOperations()]);
      byId("report-markdown").onclick = (event) => downloadReport(event, "markdown");
      byId("report-json").onclick = (event) => downloadReport(event, "json");
    } catch (error) {
      byId("detail-loading").hidden = true;
      showError(errorBox, error.message, loadDetail);
    }
  }

  function makeFindingCard(finding) {
    const card = node("article", "finding-card");
    const top = node("div", "finding-topline");
    top.append(badge(finding.outcome, "outcome"), badge(finding.severity, "severity"), node("span", "mono muted small-text", finding.rule_id));
    card.append(top, node("h3", "finding-title", finding.title || finding.rule_id || "Finding"));
    const metadata = node("div", "finding-meta");
    metadata.append(node("span", "", `Resource: ${finding.resource_type || "unknown"} / ${finding.resource_id || "unknown"}`));
    metadata.append(node("span", "", `Assessed: ${formatDate(finding.assessed_at)}`));
    card.append(metadata, node("p", "finding-reason", finding.reason || finding.description || "No rationale was recorded."));
    const refs = Array.isArray(finding.evidence_refs) ? finding.evidence_refs : [];
    const evidence = node("div", "finding-extra");
    evidence.append(node("strong", "", "Evidence references: "));
    evidence.append(document.createTextNode(refs.length ? refs.map((ref) => `operation ${ref.operation_id ?? "unknown"} ${ref.service || ""}:${ref.operation || ""} · ${ref.status || "unknown"} · SHA-256 ${ref.evidence_sha256 || "unavailable"}`).join("; ") : "none recorded"));
    card.append(evidence);
    if (finding.remediation) {
      const remediation = node("div", "finding-extra");
      remediation.append(node("strong", "", finding.outcome === "FAIL" ? "Advisory remediation: " : "General rule guidance: "));
      remediation.append(document.createTextNode(finding.remediation));
      if (finding.outcome !== "FAIL") remediation.append(document.createTextNode(" (not a determination that changes are needed)"));
      card.append(remediation);
    }
    return card;
  }

  async function loadFindings() {
    const target = byId("findings-list");
    setLoading(target, "Loading findings from this assessment…");
    const query = new URLSearchParams({ limit: String(pageSize), offset: String(sectionOffsets.findings) });
    if (byId("finding-outcome").value) query.set("outcome", byId("finding-outcome").value);
    if (byId("finding-severity").value) query.set("severity", byId("finding-severity").value);
    try {
      const data = await getJson(`/api/assessments/${encodeURIComponent(currentAssessmentId)}/findings?${query}`);
      sectionTotals.findings = data.total;
      findingPageItems = data.items;
      renderFindingPage();
      updatePager("findings", "findings-page");
    } catch (error) {
      showError(target, error.message, loadFindings);
    }
  }

  function renderFindingPage() {
    const target = byId("findings-list");
    clear(target);
    const term = byId("finding-search").value.trim().toLowerCase();
    const visible = findingPageItems.filter((item) => `${item.rule_id} ${item.title} ${item.resource_type} ${item.resource_id} ${item.reason}`.toLowerCase().includes(term));
    if (!visible.length) empty(target, findingPageItems.length ? "No matches on this page" : "No findings in this result", findingPageItems.length ? "Try a different search term or load another page." : "No findings matched the selected outcome and severity. This is not a compliance conclusion.");
    else visible.forEach((finding) => target.append(makeFindingCard(finding)));
  }

  function makeResourceCard(resource) {
    const card = node("article", "resource-card");
    card.append(node("div", "resource-type", resource.resource_type || "Unknown resource type"));
    card.append(node("h3", "resource-title", resource.name || resource.resource_id || "Unnamed resource"));
    card.append(node("div", "resource-id", resource.resource_id || "Resource identity unavailable"));
    const attributes = resource.attributes && typeof resource.attributes === "object" ? Object.entries(resource.attributes) : [];
    const details = node("dl", "attribute-list");
    const safeAttributes = attributes.filter(([key]) => !/(secret|password|credential|token|authorization|private.?key|access.?key|user.?data|session.?key)/i.test(key));
    safeAttributes.slice(0, 12).forEach(([key, value]) => {
      details.append(node("dt", "", key), node("dd", "", typeof value === "string" ? value : JSON.stringify(value)));
    });
    if (safeAttributes.length > 12) details.append(node("dt", "", "Additional fields"), node("dd", "", `${safeAttributes.length - 12} fields omitted from this view`));
    if (safeAttributes.length) card.append(details);
    card.append(node("div", "finding-extra", `Observed ${formatDate(resource.observed_at)} · source ${resource.source_service || "unknown"}:${resource.source_operation || "unknown"}`));
    return card;
  }

  async function loadResources() {
    const target = byId("resources-list");
    setLoading(target, "Loading normalized resources…");
    try {
      const query = new URLSearchParams({ limit: String(pageSize), offset: String(sectionOffsets.resources) });
      if (resourceFilters.service) query.set("service", resourceFilters.service);
      if (resourceFilters.resourceType) query.set("resource_type", resourceFilters.resourceType);
      const data = await getJson(`/api/assessments/${encodeURIComponent(currentAssessmentId)}/resources?${query}`);
      const updateOptions = (id, values, selected) => {
        const select = byId(id);
        if (select.options.length > 1) return;
        values.forEach((value) => select.append(new Option(value, value)));
        select.value = selected;
      };
      updateOptions("resource-service", data.available_filters.services, resourceFilters.service);
      updateOptions("resource-type", data.available_filters.resource_types, resourceFilters.resourceType);
      sectionTotals.resources = data.total;
      clear(target);
      if (!data.items.length) empty(target, "No resources on this page", "This assessment did not persist resource records in this page of results.");
      else {
        const grid = node("div", "resource-grid");
        data.items.forEach((resource) => grid.append(makeResourceCard(resource)));
        target.append(grid);
      }
      updatePager("resources", "resources-page");
    } catch (error) {
      showError(target, error.message, loadResources);
    }
  }

  async function loadOperations() {
    const target = byId("operations-list");
    setLoading(target, "Loading persisted operation status…");
    try {
      const data = await getJson(`/api/assessments/${encodeURIComponent(currentAssessmentId)}/operations?limit=${pageSize}&offset=${sectionOffsets.operations}`);
      sectionTotals.operations = data.total;
      clear(target);
      if (!data.items.length) empty(target, "No operations on this page", "No operation records were returned for this assessment page.");
      else data.items.forEach((operation) => {
        const row = node("article", "operation-row");
        const name = node("div", "operation-name", operation.operation || "Unknown operation");
        name.append(node("span", "operation-service", operation.service || "Unknown service"));
        const statusMessage = operation.status === "SUCCESS" ? "Read completed" : operation.status === "UNSUPPORTED" ? "This operation is not supported by the configured local environment." : operation.status === "INCOMPLETE" ? "The API returned more pages; remaining pages were not fetched because pagination has not been verified." : operation.status === "ERROR" ? "The operation returned an error; affected checks are incomplete." : "Operation state unavailable.";
        row.append(name, badge(operation.status), node("div", "operation-error", statusMessage));
        row.append(node("div", "operation-hash", operation.evidence_sha256 ? `SHA-256 ${operation.evidence_sha256}` : "No response hash"));
        target.append(row);
      });
      updatePager("operations", "operations-page");
    } catch (error) {
      showError(target, error.message, loadOperations);
    }
  }

  function updatePager(section, labelId) {
    const offset = sectionOffsets[section];
    const total = sectionTotals[section];
    const start = total ? offset + 1 : 0;
    byId(labelId).textContent = `${start}–${Math.min(offset + pageSize, total)} of ${total}`;
    byId(`${section}-previous`).disabled = offset <= 0;
    byId(`${section}-next`).disabled = offset + pageSize >= total;
  }

  async function downloadReport(event, format) {
    event.preventDefault();
    const errorBox = byId("detail-error");
    hideError(errorBox);
    try {
      const response = await fetch(`/api/assessments/${encodeURIComponent(currentAssessmentId)}/reports/${format}`, { credentials: "same-origin" });
      if (!response.ok) throw new Error(response.status === 404 ? "The saved report was not found." : "The report export is temporarily unavailable.");
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = node("a");
      link.href = objectUrl;
      link.download = `aegis-assessment-${currentAssessmentId}.${format === "json" ? "json" : "md"}`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (error) {
      showError(errorBox, error.message || "The report export is temporarily unavailable.");
    }
  }

  async function loadComparePicker() {
    const errorBox = byId("comparison-error");
    hideError(errorBox);
    try {
      const data = await getJson("/api/assessments?limit=100&offset=0");
      const previous = byId("previous-assessment");
      const current = byId("current-assessment");
      comparisonRunsById = new Map(data.items.map((item) => [item.id, item]));
      clear(previous);
      clear(current);
      previous.append(node("option", "", "Choose previous run"));
      current.append(node("option", "", "Choose later run"));
      data.items.forEach((item) => {
        const label = `${formatDate(item.started_at)} · ${statusLabel(item.status)} · ${shortId(item.id)}`;
        const oldOption = node("option", "", label); oldOption.value = item.id; previous.append(oldOption);
        const newOption = node("option", "", label); newOption.value = item.id; current.append(newOption);
      });
      if (!data.items.length) {
        previous.disabled = true; current.disabled = true; byId("run-comparison").disabled = true;
        empty(byId("comparison-results"), "No assessment history", "Save at least two assessments with the AEGIS CLI to compare persisted findings.");
      }
      const params = new URLSearchParams(window.location.search);
      if (params.has("previous")) previous.value = params.get("previous");
      if (params.has("current")) current.value = params.get("current");
      if (!params.has("previous") && !params.has("current") && data.items.length >= 2) {
        const latest = data.items[0];
        const prior = data.items.slice(1).find((item) => item.endpoint === latest.endpoint && item.started_at < latest.started_at);
        if (prior) {
          previous.value = prior.id;
          current.value = latest.id;
        }
      }
      validateComparisonSelection();
      previous.addEventListener("change", validateComparisonSelection);
      current.addEventListener("change", validateComparisonSelection);
    } catch (error) {
      showError(errorBox, error.message, loadComparePicker);
    }
  }

  function validateComparisonSelection() {
    const previousId = byId("previous-assessment").value;
    const currentId = byId("current-assessment").value;
    const errorBox = byId("comparison-error");
    const button = byId("run-comparison");
    let message = "";
    if (previousId && currentId) {
      const previous = comparisonRunsById.get(previousId);
      const current = comparisonRunsById.get(currentId);
      if (!previous || !current) message = "One selected run is not in the saved history list. Reload the page and choose again.";
      else if (previousId === currentId) message = "Choose two different assessment runs.";
      else if (previous.endpoint !== current.endpoint) message = "Choose runs from the same endpoint.";
      else if (current.started_at <= previous.started_at) message = "Choose the earlier run as Previous and the later run as Current.";
    }
    if (message) showError(errorBox, message);
    else hideError(errorBox);
    button.disabled = !previousId || !currentId || Boolean(message);
    return !button.disabled;
  }

  function findingDescription(entry) {
    const finding = entry.finding || entry.current || entry.previous || entry.resource || entry;
    const box = node("div", "comparison-item");
    const headline = [finding.title, finding.rule_id, finding.outcome, finding.severity].filter(Boolean).join(" · ");
    box.append(node("div", "comparison-category", headline || entry.assessment || "Inventory change"));
    const details = node("div", "comparison-description");
    const resource = [finding.resource_type, finding.resource_id].filter(Boolean).join(" / ");
    details.append(node("div", "", resource || "Resource identity unavailable"));
    if (finding.reason) details.append(node("div", "", finding.reason));
    if (entry.previous && entry.current && !entry.finding) {
      const before = entry.previous.name || entry.previous.resource_id || "previously observed";
      const after = entry.current.name || entry.current.resource_id || "currently observed";
      details.append(node("div", "", `Previous: ${before} · Current: ${after}`));
    }
    if (entry.reason) details.append(node("div", "comparison-note", entry.reason));
    box.append(details);
    return box;
  }

  function renderComparison(target, data) {
    clear(target);
    const summary = node("section", "panel comparison-group");
    summary.append(node("div", "eyebrow", "COMPARISON SUMMARY"), node("h2", "", `${shortId(data.comparison.previous_assessment_id)} → ${shortId(data.comparison.current_assessment_id)}`));
    const countLine = node("p", "", "Finding and inventory classifications returned by the AEGIS comparison engine.");
    summary.append(countLine);
    target.append(summary);
    const findingOrder = ["new", "resolved", "unchanged", "changed", "not_reassessed", "uncomparable"];
    findingOrder.forEach((classification) => {
      const entries = data.findings[classification] || [];
      const group = node("section", "panel comparison-group");
      const count = data.summary.findings[classification];
      group.append(node("h2", "", `${statusLabel(classification)} · ${count}`));
      const explanation = classification === "resolved" ? "The persisted comparison engine confirms these transitions from evidence-backed results." : classification === "not_reassessed" ? "No matching current evaluation was found; these findings are not confirmed resolved." : classification === "uncomparable" ? "Stable rule or resource identity was unavailable or duplicated." : "Classification is taken directly from the persisted comparison result.";
      group.append(node("p", "", explanation));
      if (!entries.length) group.append(node("div", "muted small-text", "No items"));
      else entries.forEach((entry) => group.append(findingDescription(entry)));
      target.append(group);
    });
    ["added", "removed", "modified", "unchanged"].forEach((classification) => {
      const entries = data.inventory[classification] || [];
      const group = node("section", "panel comparison-group");
      group.append(node("h2", "", `Inventory ${classification} · ${data.summary.inventory[classification]}`));
      if (!entries.length) group.append(node("div", "muted small-text", "No items"));
      else entries.forEach((entry) => group.append(findingDescription(entry)));
      target.append(group);
    });
  }

  async function runComparison() {
    const previous = byId("previous-assessment").value;
    const current = byId("current-assessment").value;
    const errorBox = byId("comparison-error");
    const loading = byId("comparison-loading");
    if (!validateComparisonSelection()) {
      if (!previous || !current) showError(errorBox, "Choose both a previous and a current assessment.");
      return;
    }
    loading.hidden = false;
    byId("run-comparison").disabled = true;
    try {
      const result = await getJson(`/api/comparisons/${encodeURIComponent(previous)}/${encodeURIComponent(current)}`);
      renderComparison(byId("comparison-results"), result);
    } catch (error) {
      showError(errorBox, error.message);
    } finally {
      loading.hidden = true;
      // A changed selection may have become invalid while the request was pending.
      validateComparisonSelection();
    }
  }

  function keyValue(rows) {
    const list = node("div", "workflow-kv");
    rows.forEach(([label, value]) => list.append(node("span", "", label), node("strong", "", value)));
    return list;
  }

  function renderPreview(data) {
    const target = byId("workflow-preview");
    clear(target);
    target.append(node("h3", "", "Configured scope"));
    target.append(keyValue([["Endpoint", data.endpoint], ["Region", data.region],
      ["Database", data.database.state === "not_created" ? "Will initialize when scan starts" : data.database.state],
      ["Pagination", data.pagination_supported ? "Supported" : "Disabled; continuation markers show as incomplete"]]));
    const operations = node("ul", "workflow-list");
    data.operations.forEach((item) => operations.append(node("li", "", `${item.service}:${item.operation} → ${item.resource_type || "operation"}`)));
    target.append(node("h3", "", "Verified read operations"), operations);
    const rules = node("ul", "workflow-list");
    data.rules.forEach((item) => rules.append(node("li", "", `${item.id} · ${item.severity} · ${item.title} (${item.resource_type})`)));
    target.append(node("h3", "", "Rules evaluated"), rules);
    const limitations = node("ul", "workflow-list");
    data.unsupported_capabilities.forEach((item) => limitations.append(node("li", "", item)));
    target.append(node("h3", "", "Known limitations"), limitations);
    const outputs = node("ul", "workflow-list");
    data.expected_outputs.forEach((item) => outputs.append(node("li", "", item)));
    target.append(node("h3", "", "Saved outputs"), outputs);
    target.append(node("p", "workflow-copy", data.network_notice));
    byId("workflow-preflight").disabled = false;
  }

  function renderPreflight(data) {
    const target = byId("workflow-checks");
    clear(target);
    target.hidden = false;
    data.checks.forEach((item) => {
      const row = node("div", "workflow-check");
      const stateClass = item.state === "PASS" ? "pass" : item.state === "FAIL" || item.state === "BLOCKED" ? "fail" : "partial";
      row.append(node("span", `badge badge-${stateClass}`, item.state));
      const content = node("div");
      content.append(node("strong", "", item.id.replaceAll("_", " ")),
        node("p", "", item.message), node("p", "", `Next step: ${item.next_step}`));
      row.append(content);
      target.append(row);
    });
    if (data.identity) target.append(node("p", "muted small-text", `Verified account: ${data.identity}`));
    if (data.operations.length) {
      target.append(node("h3", "", "Operation check results"));
      const list = node("ul", "workflow-list");
      data.operations.forEach((item) => list.append(node("li", "", `${item.service}:${item.operation} — ${item.state}${item.error_code ? ` (${item.error_code})` : ""}; ${item.resource_count} resources observed`)));
      target.append(list);
    }
    target.append(node("a", "text-link", "Open setup guide for failed checks and recovery →"));
    target.lastChild.href = "/guide";
    const readiness = byId("workflow-readiness");
    readiness.textContent = data.readiness;
    readiness.className = `badge ${data.readiness === "READY" ? "badge-pass" : data.readiness === "BLOCKED" ? "badge-fail" : "badge-partial"}`;
    byId("workflow-confirmation").hidden = data.readiness === "BLOCKED";
    byId("workflow-start").disabled = data.readiness === "BLOCKED";
  }

  async function openWorkflow() {
    const dialog = byId("assessment-dialog");
    if (!dialog.open) dialog.showModal();
    const error = byId("workflow-error");
    hideError(error);
    byId("workflow-preview").replaceChildren(node("div", "loading-state", "Loading local assessment preview…"));
    byId("workflow-checks").hidden = true;
    byId("workflow-confirmation").hidden = true;
    byId("workflow-run").hidden = true;
    byId("workflow-readiness").textContent = "Preflight required";
    byId("workflow-readiness").className = "badge badge-neutral";
    byId("workflow-start").disabled = true;
    byId("workflow-preflight").disabled = true;
    try {
      const preview = await getJson("/api/assessment-preview");
      renderPreview(preview);
    } catch (requestError) {
      showError(error, requestError.message);
    }
  }

  async function startPreflight() {
    const button = byId("workflow-preflight");
    const error = byId("workflow-error");
    hideError(error);
    button.disabled = true;
    button.textContent = "Checking endpoint and read operations…";
    try {
      const result = await postJson("/api/preflight", {});
      renderPreflight(result);
    } catch (requestError) {
      showError(error, requestError.message);
      byId("workflow-readiness").textContent = "Preflight unavailable";
      byId("workflow-readiness").className = "badge badge-fail";
      byId("workflow-confirmation").hidden = true;
    } finally {
      button.disabled = false;
      button.textContent = "Run preflight checks again";
    }
  }

  function showRunState(status) {
    const target = byId("workflow-run");
    clear(target);
    target.hidden = false;
    target.append(node("div", "workflow-run-state", `${status.state} · ${status.message}`));
    if (status.started_at) target.append(node("p", "muted small-text", `Started ${formatDate(status.started_at)}`));
    if (status.completed_at) target.append(node("p", "muted small-text", `Finished ${formatDate(status.completed_at)}`));
    if (status.error_type) target.append(node("p", "muted small-text", `Internal error category: ${status.error_type}. Details are hidden.`));
    if (["RUNNING", "QUEUED"].includes(status.state)) {
      target.append(node("p", "workflow-copy", "Waiting for the server’s next confirmed state. No percentage estimate is available; closing this page does not cancel the run."));
    }
  }

  async function pollRun(runId) {
    try {
      const status = await getJson(`/api/assessment-runs/${encodeURIComponent(runId)}`);
      showRunState(status);
      if (["COMPLETED", "PARTIAL", "FAILED"].includes(status.state)) {
        if (status.assessment_id) window.location.assign(`/assessments/${encodeURIComponent(status.assessment_id)}`);
        else showError(byId("workflow-error"), `${status.message} Use the setup guide to review the prerequisites and try again.`);
        return;
      }
      if (status.state === "UNKNOWN") {
        const target = byId("workflow-run");
        const detail = status.assessment_url || (status.assessment_id ? `/assessments/${encodeURIComponent(status.assessment_id)}` : null);
        if (detail) {
          const link = node("a", "text-link", "Review saved assessment evidence →");
          link.href = detail;
          target.append(link);
        }
        const history = node("a", "text-link", "Open assessment history →");
        history.href = status.history_url || "/assessments";
        target.append(history);
        return;
      }
    } catch (error) {
      if (error.status === 404) {
        const target = byId("workflow-run");
        clear(target);
        target.hidden = false;
        target.append(node("p", "workflow-copy", "This run status is no longer available in this web process. Check saved assessment history before starting another scan."));
        const history = node("a", "text-link", "Open assessment history →");
        history.href = "/assessments";
        target.append(history);
        return;
      }
      showRunState({ state: "RUNNING", message: "Run status is unavailable. A browser disconnect does not establish whether server-side work has stopped; check assessment history before retrying." });
    }
    window.setTimeout(() => pollRun(runId), 1500);
  }

  async function confirmAssessment() {
    const button = byId("workflow-start");
    button.disabled = true;
    byId("workflow-preflight").disabled = true;
    hideError(byId("workflow-error"));
    try {
      const started = await postJson("/api/assessment-runs", { confirmation: true });
      byId("workflow-confirmation").hidden = true;
      showRunState({ state: started.state, message: "Assessment accepted. Waiting for the worker." });
      pollRun(started.run_id);
    } catch (requestError) {
      showError(byId("workflow-error"), requestError.message);
      button.disabled = false;
      byId("workflow-preflight").disabled = false;
    }
  }

  function bindCommandCopies() {
    document.querySelectorAll(".copy-command").forEach((button) => button.addEventListener("click", async () => {
      const command = button.dataset.copy || "";
      const status = byId("copy-status");
      try {
        await navigator.clipboard.writeText(command);
        if (status) status.textContent = "Command copied. Replace any profile or assessment ID placeholders before running it.";
        button.textContent = "Copied";
      } catch (_error) {
        if (status) status.textContent = "Clipboard access is unavailable. Select and copy the command text directly.";
      }
    }));
  }

  if (page === "overview") {
    loadOverview();
    byId("overview-refresh").addEventListener("click", loadOverview);
    byId("new-assessment").addEventListener("click", openWorkflow);
    byId("workflow-close").addEventListener("click", () => byId("assessment-dialog").close());
    byId("workflow-cancel").addEventListener("click", () => byId("assessment-dialog").close());
    byId("workflow-preflight").addEventListener("click", startPreflight);
    byId("workflow-start").addEventListener("click", confirmAssessment);
    if (new URLSearchParams(window.location.search).get("action") === "new-assessment") openWorkflow();
  }
  if (page === "assessments") {
    loadHistory();
    byId("history-search").addEventListener("input", filterHistoryRows);
    byId("page-previous").addEventListener("click", () => { historyOffset = Math.max(0, historyOffset - pageSize); loadHistory(); });
    byId("page-next").addEventListener("click", () => { if (historyOffset + pageSize < historyTotal) { historyOffset += pageSize; loadHistory(); } });
  }
  if (page === "assessment") {
    loadDetail();
    byId("finding-filter").addEventListener("click", () => { sectionOffsets.findings = 0; loadFindings(); });
    byId("finding-search").addEventListener("input", renderFindingPage);
    byId("resource-filter").addEventListener("click", () => {
      resourceFilters.service = byId("resource-service").value;
      resourceFilters.resourceType = byId("resource-type").value;
      sectionOffsets.resources = 0;
      loadResources();
    });
    ["findings", "resources", "operations"].forEach((section) => {
      byId(`${section}-previous`).addEventListener("click", () => { sectionOffsets[section] = Math.max(0, sectionOffsets[section] - pageSize); ({ findings: loadFindings, resources: loadResources, operations: loadOperations })[section](); });
      byId(`${section}-next`).addEventListener("click", () => { if (sectionOffsets[section] + pageSize < sectionTotals[section]) { sectionOffsets[section] += pageSize; ({ findings: loadFindings, resources: loadResources, operations: loadOperations })[section](); } });
    });
  }
  if (page === "compare") {
    loadComparePicker();
    byId("run-comparison").addEventListener("click", runComparison);
  }
  if (page === "guide") bindCommandCopies();
})();
