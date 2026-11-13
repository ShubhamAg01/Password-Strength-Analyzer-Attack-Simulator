document.addEventListener("DOMContentLoaded", () => {
  const tabBtns = document.querySelectorAll(".nav-item");
  const tabContents = document.querySelectorAll(".view-panel");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(btn.getAttribute("data-tab"));
      if (target) target.classList.add("active");
    });
  });

  const pwdInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-pwd");
  if (toggleBtn && pwdInput) {
    toggleBtn.addEventListener("click", () => {
      const isPassword = pwdInput.getAttribute("type") === "password";
      pwdInput.setAttribute("type", isPassword ? "text" : "password");
      toggleBtn.innerHTML = isPassword
        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>`
        : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
    });
  }

  document.querySelectorAll(".chip").forEach(btn => {
    btn.addEventListener("click", () => {
      if (pwdInput) {
        pwdInput.value = btn.getAttribute("data-pwd");
        triggerAnalysis();
      }
    });
  });

  let debounceTimer = null;
  if (pwdInput) {
    pwdInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(triggerAnalysis, 200);
    });
  }

  async function triggerAnalysis() {
    const password = pwdInput.value;
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      updateAnalyzerUI(data);
    } catch (err) {
      console.error(err);
    }
  }

  function getSemanticColor(rating) {
    switch (rating.toLowerCase()) {
      case "very weak": return "var(--semantic-critical)";
      case "weak": return "var(--semantic-warning)";
      case "fair": return "var(--semantic-warning)";
      case "strong": return "var(--semantic-positive)";
      case "very strong": return "var(--semantic-positive)";
      default: return "var(--text-muted)";
    }
  }

  function updateAnalyzerUI(data) {
    const scoreVal = document.getElementById("score-val");
    const scoreBar = document.getElementById("score-bar");
    const ratingDot = document.getElementById("rating-dot");
    const ratingText = document.getElementById("rating-text");
    const ratingDesc = document.getElementById("rating-desc");

    const color = getSemanticColor(data.rating);

    scoreVal.textContent = data.score;
    scoreBar.style.width = `${Math.max(4, data.score)}%`;
    scoreBar.style.backgroundColor = color;
    ratingDot.style.backgroundColor = color;
    ratingText.textContent = data.rating;
    ratingText.style.color = color;

    let desc = "Low resistance to offline dictionary attacks";
    if (data.score >= 80) desc = "Enterprise-grade resilience; computationally infeasible to crack";
    else if (data.score >= 60) desc = "Resistant against offline dictionary and rule-based vectors";
    else if (data.score >= 40) desc = "Moderate resilience; susceptible to targeted rule mutations";
    ratingDesc.textContent = desc;

    document.getElementById("m-len").textContent = data.password_length;
    document.getElementById("m-shannon").textContent = `${data.shannon_entropy} b/c`;
    document.getElementById("m-pool").textContent = data.pool_size;
    document.getElementById("m-raw").textContent = `${data.raw_pool_entropy} bits`;
    document.getElementById("m-penalty").textContent = `-${data.pattern_penalty} bits`;
    document.getElementById("m-effective").textContent = `${data.effective_entropy} bits`;

    const ct = data.crack_times;
    document.getElementById("ct-throttled").textContent = ct.online_throttled;
    document.getElementById("ct-unthrottled").textContent = ct.online_unthrottled;
    document.getElementById("ct-gpu").textContent = ct.offline_fast_gpu_md5;
    document.getElementById("ct-bcrypt").textContent = ct.offline_slow_bcrypt;

    const vList = document.getElementById("vulnerabilities-list");
    vList.innerHTML = "";
    if (data.patterns_detected && data.patterns_detected.length > 0) {
      data.patterns_detected.forEach(p => {
        const li = document.createElement("li");
        li.textContent = p;
        vList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "No sequential, spatial, or dictionary patterns identified";
      vList.appendChild(li);
    }

    const fList = document.getElementById("feedback-list");
    fList.innerHTML = "";
    if (data.feedback && data.feedback.length > 0) {
      data.feedback.forEach(f => {
        const li = document.createElement("li");
        li.textContent = f;
        fList.appendChild(li);
      });
    }
  }

  triggerAnalysis();

  const btnRunAttack = document.getElementById("btn-run-attack");
  const btnHashHelper = document.getElementById("btn-hash-helper");
  const simHashInput = document.getElementById("sim-hash-input");
  const simHelperInput = document.getElementById("sim-plaintext-helper");

  if (btnHashHelper) {
    btnHashHelper.addEventListener("click", async () => {
      const plain = simHelperInput.value.trim();
      const algo = document.querySelector('input[name="sim-algo"]:checked').value;
      if (!plain) return;

      btnHashHelper.textContent = "Computing...";
      try {
        const res = await fetch("/api/hash", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: plain, bcrypt_rounds: 8 })
        });
        const data = await res.json();
        simHashInput.value = data[algo];
      } catch (e) {
        console.error(e);
      } finally {
        btnHashHelper.textContent = "Hash and load";
      }
    });
  }

  if (btnRunAttack) {
    btnRunAttack.addEventListener("click", async () => {
      const algo = document.querySelector('input[name="sim-algo"]:checked').value;
      const targetHash = simHashInput.value.trim();
      const attackTypeSelect = document.getElementById("sim-attack-type").value;

      if (!targetHash) {
        alert("Please specify a target hash.");
        return;
      }

      const simStatusTag = document.getElementById("sim-status-tag");
      const indicatorDot = simStatusTag.querySelector(".indicator-dot");
      const indicatorLabel = simStatusTag.querySelector(".indicator-label");
      const simBanner = document.getElementById("sim-banner");

      indicatorDot.style.backgroundColor = "var(--semantic-warning)";
      indicatorLabel.textContent = "Running";
      simBanner.className = "telemetry-banner";
      simBanner.textContent = `Executing ${attackTypeSelect} attack against ${algo.toUpperCase()} digest...`;
      btnRunAttack.disabled = true;

      const payload = {
        target_hash: targetHash,
        algorithm: algo,
        attack_type: attackTypeSelect === "brute_force" ? "brute_force" : "dictionary",
        enable_rules: attackTypeSelect === "hybrid"
      };

      try {
        const res = await fetch("/api/attack", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        document.getElementById("res-status").textContent = data.cracked ? "Cracked (Vulnerable)" : "Exhausted (Not found)";
        document.getElementById("res-plaintext").textContent = data.cracked_password || "None";
        document.getElementById("res-hash").textContent = data.target_hash;
        document.getElementById("res-algo").textContent = data.algorithm.toUpperCase();
        document.getElementById("res-attempts").textContent = data.attempts.toLocaleString();
        document.getElementById("res-time").textContent = `${data.elapsed_seconds} s`;
        document.getElementById("res-rate").textContent = `${data.hash_rate_per_sec.toLocaleString()} H/s`;

        if (data.cracked) {
          simBanner.className = "telemetry-banner status-success";
          simBanner.textContent = `Match identified: Plaintext recovered in ${data.elapsed_seconds} seconds`;
          indicatorDot.style.backgroundColor = "var(--semantic-positive)";
          indicatorLabel.textContent = "Cracked";
        } else {
          simBanner.className = "telemetry-banner status-exhausted";
          simBanner.textContent = "Keyspace exhausted: No collision found in wordlist";
          indicatorDot.style.backgroundColor = "var(--semantic-critical)";
          indicatorLabel.textContent = "Exhausted";
        }
      } catch (err) {
        simBanner.textContent = "Error executing simulation";
        console.error(err);
      } finally {
        btnRunAttack.disabled = false;
      }
    });
  }

  async function loadTestCases() {
    try {
      const res = await fetch("/api/testcases");
      const cases = await res.json();
      const tbody = document.getElementById("testcases-body");
      tbody.innerHTML = "";

      cases.forEach(tc => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${tc.id}</strong></td>
          <td>${tc.category}</td>
          <td><code>${tc.plaintext}</code></td>
          <td>${tc.md5_hash.substring(0, 10)}...</td>
          <td>${tc.sha1_hash.substring(0, 10)}...</td>
          <td>${tc.bcrypt_hash.substring(0, 12)}...</td>
          <td><button type="button" class="btn-table" data-tc='${JSON.stringify(tc)}'>Load MD5</button></td>
        `;
        tbody.appendChild(tr);
      });

      document.querySelectorAll(".btn-table").forEach(btn => {
        btn.addEventListener("click", () => {
          const tc = JSON.parse(btn.getAttribute("data-tc"));
          document.querySelector('button[data-tab="tab-simulator"]').click();
          document.querySelector('input[name="sim-algo"][value="md5"]').checked = true;
          simHashInput.value = tc.md5_hash;
          simHelperInput.value = tc.plaintext;
        });
      });
    } catch (e) {
      console.error(e);
    }
  }

  loadTestCases();
});
