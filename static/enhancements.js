/* Enhances the core investigation view with analyst-owned next actions. */
(function () {
  const baseRender = window.render;
  const baseRenderMap = window.renderMap;

  function planFor(result) {
    const urgent = result.risk_score >= 61;
    const moderate = result.risk_score >= 31 && result.risk_score < 61;
    const headline = urgent ? "Contain and preserve evidence" : moderate ? "Verify before taking action" : "Record and monitor";
    const steps = urgent ? [
      ["Preserve the original", "Keep the .eml file and this case hash unchanged. Do not forward or edit the evidence."],
      ["Avoid the embedded content", "Do not click links, open attachments, or reply to this message."],
      ["Verify through a trusted channel", "Use the organisation's official website or known phone number, never contact details in the email."],
      ["Escalate the case", "Share the case JSON or report with your security team, help desk, or email administrator."],
    ] : moderate ? [
      ["Preserve the email", "Keep the original .eml and evidence hash before changing or deleting anything."],
      ["Verify the request", "Check the sender using an independently trusted contact channel."],
      ["Inspect before interacting", "Do not open links or attachments until verification is complete."],
      ["Report if suspicious", "Give the forensic report to your security or IT team for review."],
    ] : [
      ["Keep the evidence record", "Retain the report and original email if this relates to an important account or transaction."],
      ["Confirm unusual requests", "If the request is unexpected, verify it using a trusted organisation contact."],
      ["Do not over-interpret routing", "A cloud mail relay in another country is normal and does not prove malicious activity."],
    ];
    return { headline, steps };
  }

  function actionPlan(result) {
    const plan = planFor(result);
    return `<article class="card action-plan"><div class="action-plan-top"><div><h2>Recommended analyst actions</h2><h3>${plan.headline}</h3></div><span class="plan-level ${result.risk_level.toLowerCase()}">${result.risk_level}</span></div><p class="sub">Choose the steps appropriate to your organisation's incident-response policy. These controls only track your review in this browser.</p><ol>${plan.steps.map(([title, detail], index) => `<li><label><input type="checkbox" data-action-step="${index}"><span><b>${title}</b><small>${detail}</small></span></label></li>`).join("")}</ol><div class="action-plan-footer"><span class="sub" id="action-progress">0 of ${plan.steps.length} steps marked complete</span><button class="action" type="button" id="copy-case">Copy case ID <b>↗</b></button></div></article>`;
  }

  function intelligencePanel(result) {
    const signals = result.intelligence_signals || [];
    return `<article class="card intelligence-panel"><div class="action-plan-top"><div><h2>Investigation intelligence</h2><h3>Content and identity triage</h3></div><span class="plan-level">EXPLAINABLE</span></div><div class="intel-grid">${signals.map(signal => `<div class="intel-item ${signal.severity}"><b>${signal.severity === 'review' ? 'REVIEW' : 'INFO'}</b><strong>${signal.label}</strong><span>${signal.detail}</span></div>`).join('')}</div></article>`;
  }

  function printableLocationSummary(result) {
    const entity = result.organization_context;
    const relay = (result.infrastructure || []).find(item => item.lookup_status === 'enriched');
    return `<article class="card location-summary"><h2>Location evidence summary</h2><div class="location-evidence"><div><b>Verified organisation context</b><span>${entity ? `${entity.organization} - ${entity.location_label}` : 'No verified organisation profile available for this sender domain.'}</span></div><div><b>Observed mail infrastructure</b><span>${relay ? `${relay.ip} - ${relay.city}, ${relay.region}, ${relay.country} - ${relay.isp || relay.organization}` : 'No enriched public mail-relay IP was available.'}</span></div></div><p class="sub">These are separate evidence types. An organisation can send email through cloud infrastructure in another country.</p></article>`;
  }

  window.renderMap = function (...args) {
    baseRenderMap(...args);
    const mapElement = document.querySelector('#map');
    const refresh = () => { if (window.geoMap) window.geoMap.invalidateSize({ animate: false, pan: false }); };
    requestAnimationFrame(() => setTimeout(refresh, 120));
    if (mapElement && window.ResizeObserver) new ResizeObserver(refresh).observe(mapElement);
  };

  window.render = function (result) {
    baseRender(result);
    const target = document.querySelector("#result .investigation-head");
    target.insertAdjacentHTML("afterend", actionPlan(result));
    document.querySelector("#result .action-plan").insertAdjacentHTML("afterend", intelligencePanel(result));
    document.querySelector("#result .limitations").insertAdjacentHTML("beforebegin", printableLocationSummary(result));
    const checks = [...document.querySelectorAll("[data-action-step]")];
    const progress = document.querySelector("#action-progress");
    checks.forEach(check => check.addEventListener("change", () => {
      progress.textContent = `${checks.filter(item => item.checked).length} of ${checks.length} steps marked complete`;
    }));
    document.querySelector("#copy-case").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(result.investigation_id); }
      catch (_) { /* Clipboard support is optional; the visible case ID remains available. */ }
    });
  };
})();
