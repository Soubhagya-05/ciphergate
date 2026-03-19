const TOKEN_KEY = "ciphergateToken";
let securityScoreChart;
let dashboardRefreshTimer;
let securityRefreshTimer;

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function setMessage(element, message, type) {
  if (!element) return;
  element.textContent = message;
  element.className = `form-message ${type || ""}`.trim();
}

async function apiFetch(url, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.message || "Request failed.");
    error.status = response.status;
    throw error;
  }

  return data;
}

function formatDate(dateValue) {
  if (!dateValue) return "Not available";
  return new Date(dateValue).toLocaleString();
}

function requireAuth() {
  if (!getToken()) {
    window.location.href = "/login.html";
    return false;
  }
  return true;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getRiskToneText(label) {
  if (label === "LOW") return "LOW";
  if (label === "HIGH") return "HIGH";
  return "MEDIUM";
}

function countryCodeToFlag(countryCode) {
  const normalized = String(countryCode || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(normalized)) return "";
  return String.fromCodePoint(...[...normalized].map((char) => 127397 + char.charCodeAt(0)));
}

function normalizeIpAddress(ipAddress) {
  const raw = String(ipAddress || "").trim();

  if (!raw) return "";

  if (raw.startsWith("::ffff:")) {
    return raw.replace("::ffff:", "");
  }

  return raw;
}

function isPrivateOrLocalIp(ipAddress) {
  const normalized = normalizeIpAddress(ipAddress);

  return (
    normalized === "::1" ||
    normalized === "127.0.0.1" ||
    normalized === "0.0.0.0" ||
    normalized === "localhost" ||
    normalized.startsWith("192.168.") ||
    normalized.startsWith("10.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(normalized) ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

async function lookupLocation(ipAddress) {
  if (!ipAddress || ipAddress === "Unknown IP") return "Unavailable";

  const normalized = normalizeIpAddress(ipAddress);

  if (isPrivateOrLocalIp(normalized)) {
    return "Local Network / Development";
  }

  try {
    const response = await fetch(`https://ipapi.co/${encodeURIComponent(normalized)}/json/`);
    const data = await response.json();

    if (data?.city && data?.country_name) {
      return `${data.city}, ${data.country_name}`;
    }

    if (data?.country_name) {
      return data.country_name;
    }

    return "Location unavailable";
  } catch (error) {
    return "Location unavailable";
  }
}

async function getUserLocation() {
  try {
    const response = await fetch("https://ipapi.co/json/");
    const data = await response.json();

    const ip = normalizeIpAddress(data?.ip || "");

    if (!ip || isPrivateOrLocalIp(ip)) {
      return {
        ip,
        location: "Local Network / Development Mode",
        countryCode: ""
      };
    }

    const parts = [data?.city, data?.region, data?.country_name].filter(Boolean);

    return {
      ip,
      location: parts.length ? parts.join(", ") : "Location unavailable",
      countryCode: String(data?.country_code || data?.country || "").toUpperCase()
    };
  } catch (error) {
    return {
      ip: "",
      location: "Location unavailable",
      countryCode: ""
    };
  }
}

function renderTimeline(container, timeline = []) {
  if (!container) return;

  if (!timeline.length) {
    container.innerHTML = '<p class="empty-state">No recent events recorded.</p>';
    return;
  }

  container.innerHTML = timeline
    .map(
      (entry) => `
        <div class="timeline-item">
          <div class="timeline-marker timeline-${escapeHtml(entry.status)}"></div>
          <div class="timeline-copy">
            <div class="timeline-row">
              <strong>${escapeHtml(entry.time)}</strong>
              <span class="mini-status">${escapeHtml(entry.status.toUpperCase())}</span>
            </div>
            <p>${escapeHtml(entry.title)}</p>
            <small>${escapeHtml(entry.detail)}</small>
          </div>
        </div>
      `
    )
    .join("");
}

function renderRecommendations(container, items = []) {
  if (!container) return;
  container.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function renderSuspiciousReasons(container, reasons = [], detected = false) {
  const title = document.getElementById("suspiciousTitle");
  if (!container) return;
  if (title) {
    title.textContent = detected ? "Suspicious Login Detected" : "Suspicious Login Monitor";
  }
  container.innerHTML = reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
}

function renderSessions(container, sessions = []) {
  if (!container) return;

  if (!sessions.length) {
    container.innerHTML = '<p class="empty-state">No active sessions detected.</p>';
    return;
  }

  container.innerHTML = sessions
    .map(
      (session) => `
        <div class="session-item ${session.current ? "current-session" : ""}">
          <div>
            <strong>${escapeHtml(
              session.device.replace("Desktop • ", "").replace("Mobile • ", "")
            )}</strong>
            <p>Status: Active</p>
            <p>Login Time: ${escapeHtml(formatDate(session.loginTime))}</p>
            <p>${escapeHtml(session.current ? "Current Device" : session.relativeTime)}</p>
          </div>
          <div class="session-actions">
            <span class="session-ip">${escapeHtml(session.ipAddress)}</span>
            ${
              session.current
                ? '<span class="current-session-label">Current Device</span>'
                : `<button class="ghost-btn terminate-session-btn" data-session-id="${escapeHtml(
                    session.id
                  )}" type="button">Terminate Session</button>`
            }
          </div>
        </div>
      `
    )
    .join("");
}

function renderSystemStatus(status, alertMessage) {
  const statusEl = document.getElementById("systemStatus");
  const alertEl = document.getElementById("securityAlert");

  if (statusEl) {
    statusEl.textContent = `System Status: ${status || "SECURE"}`;
    statusEl.classList.toggle("risk-detected", status === "RISK DETECTED");
  }

  if (alertEl) {
    if (alertMessage) {
      alertEl.textContent = alertMessage;
      alertEl.classList.remove("hidden");
    } else {
      alertEl.textContent = "";
      alertEl.classList.add("hidden");
    }
  }
}

function renderRiskCard(risk = {}) {
  const scoreEl = document.getElementById("riskScore");
  const labelEl = document.getElementById("riskLabel");
  const summaryEl = document.getElementById("riskSummary");
  const cardEl = document.getElementById("riskCard");

  if (!scoreEl || !labelEl || !summaryEl || !cardEl) return;

  scoreEl.textContent = risk.score ?? "--";
  labelEl.textContent = `Risk Level: ${getRiskToneText(risk.label)}`;
  summaryEl.textContent =
    risk.label === "LOW"
      ? "Low-risk behavior pattern detected across recent sign-ins."
      : risk.label === "HIGH"
        ? "Critical anomalies detected. Review active sessions and recent events."
        : "Some trust signals changed. Monitor recent devices and locations.";

  cardEl.classList.remove("risk-safe", "risk-warning", "risk-suspicious");
  cardEl.classList.add(
    risk.label === "LOW"
      ? "risk-safe"
      : risk.label === "HIGH"
        ? "risk-suspicious"
        : "risk-warning"
  );
}

function renderSecurityChart(trend = []) {
  const canvas = document.getElementById("securityScoreChart");
  if (!canvas || typeof Chart === "undefined") return;

  const fallbackTrend = [
    { label: "08:00", score: 86 },
    { label: "10:00", score: 82 },
    { label: "12:00", score: 78 },
    { label: "14:00", score: 80 },
    { label: "16:00", score: 76 },
    { label: "18:00", score: 72 }
  ];
  const effectiveTrend = trend.length ? trend : fallbackTrend;
  const labels = effectiveTrend.map((point) => point.label);
  const values = effectiveTrend.map((point) => point.score);

  if (securityScoreChart) {
    securityScoreChart.destroy();
  }

  securityScoreChart = new Chart(canvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Security Score",
          data: values,
          borderColor: "#0d6dfd",
          backgroundColor: "rgba(13, 109, 253, 0.14)",
          fill: true,
          borderWidth: 3,
          tension: 0.35,
          pointRadius: 4,
          pointBackgroundColor: "#ffffff",
          pointBorderColor: "#0d6dfd",
          pointBorderWidth: 2
        }
      ]
    },
    options: {
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          min: 0,
          max: 100,
          grid: { color: "rgba(148, 163, 184, 0.15)" },
          ticks: { color: "#6e7f96" }
        },
        x: {
          grid: { display: false },
          ticks: { color: "#6e7f96" }
        }
      }
    }
  });
}

async function handleRegisterPage() {
  const form = document.getElementById("registerForm");
  const message = document.getElementById("formMessage");

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    try {
      await apiFetch("/register", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      setMessage(message, "Registration successful. Redirecting to login...", "success");
      form.reset();
      setTimeout(() => {
        window.location.href = "/login.html";
      }, 1200);
    } catch (error) {
      setMessage(message, error.message, "error");
    }
  });
}

async function handleLoginPage() {
  const form = document.getElementById("loginForm");
  const message = document.getElementById("formMessage");

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    try {
      const locationData = await getUserLocation();
      const data = await apiFetch("/login", {
        method: "POST",
        body: JSON.stringify({
          ...payload,
          ip: locationData.ip,
          location: locationData.location,
          countryCode: locationData.countryCode
        })
      });

      saveToken(data.token);
      setMessage(message, data.message || "Login successful.", "success");
      setTimeout(() => {
        window.location.href = "/dashboard.html";
      }, 900);
    } catch (error) {
      setMessage(message, error.message, "error");
    }
  });
}

async function handleDashboardPage() {
  if (!requireAuth()) return;

  try {
    const data = await apiFetch("/dashboard");
    const user = data.user;

    document.getElementById("userName").textContent = user.name;
    document.getElementById("userEmail").textContent = user.email;
    const initialEl = document.getElementById("userInitial");
    if (initialEl) {
      initialEl.textContent = (user.name || "C").trim().charAt(0).toUpperCase();
    }
    document.getElementById("lastLogin").textContent = formatDate(user.lastLoginAt);
    document.getElementById("currentDevice").textContent = user.currentDevice;
    document.getElementById("currentIp").textContent = user.currentIp;
    document.getElementById("securityStatus").textContent = user.securityStatus;
    document.getElementById("currentLocation").textContent =
      user.currentLocation || "Location unavailable";

    renderRiskCard(data.risk);
    renderSessions(document.getElementById("activeSessionsList"), data.activeSessions);
    renderSuspiciousReasons(
      document.getElementById("suspiciousReasonList"),
      data.suspiciousReasons,
      data.suspiciousDetected
    );
    renderSystemStatus(data.systemStatus, data.alertMessage);
    renderTimeline(document.getElementById("securityTimeline"), data.timeline);
    renderRecommendations(document.getElementById("recommendationList"), data.recommendations);
    renderSecurityChart(data.trend);
  } catch (error) {
    if (error.status === 401) {
      clearToken();
      window.location.href = "/login.html";
    }
  }
}

async function terminateSession(sessionId) {
  await apiFetch("/terminate-session", {
    method: "POST",
    body: JSON.stringify({ sessionId })
  });
}

async function terminateAllSessions() {
  await apiFetch("/terminate-all-sessions", {
    method: "POST",
    body: JSON.stringify({})
  });
}

async function handleSecurityPage() {
  if (!requireAuth()) return;

  const body = document.getElementById("securityLogsBody");
  const pageRisk = document.getElementById("securityPageRisk");

  try {
    const data = await apiFetch("/security-logs");
    const rows = data.logs || [];
    renderTimeline(document.getElementById("securityActivityTimeline"), data.timeline || []);
    if (pageRisk && data.risk) {
      pageRisk.textContent = `${data.risk.score}/100 · ${data.risk.label}`;
    }

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="5">No login activity recorded yet.</td></tr>';
      return;
    }

    body.innerHTML = rows
      .map((entry) => {
        const statusClass =
          entry.status === "success"
            ? "status-success"
            : entry.status === "suspicious"
              ? "status-suspicious"
              : "status-failure";
        const flag = countryCodeToFlag(entry.countryCode);
        const locationLabel = `${flag ? `${flag} ` : ""}${entry.location || "Location unavailable"}`;

        return `
          <tr>
            <td>${escapeHtml(formatDate(entry.loginTime))}</td>
            <td>${escapeHtml(entry.ipAddress)}</td>
            <td>${escapeHtml(locationLabel)}</td>
            <td>${escapeHtml(entry.device)}</td>
            <td><span class="status-pill ${statusClass}">${escapeHtml(entry.status.toUpperCase())}</span></td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    if (error.status === 401) {
      clearToken();
      window.location.href = "/login.html";
      return;
    }

    body.innerHTML = '<tr><td colspan="5">Unable to load security logs.</td></tr>';
  }
}

function bindSessionTermination() {
  document.addEventListener("click", async (event) => {
    const button = event.target.closest(".terminate-session-btn");
    if (!button) return;

    const { sessionId } = button.dataset;
    if (!sessionId) return;

    try {
      button.disabled = true;
      button.textContent = "Terminating...";
      await terminateSession(sessionId);
      await handleDashboardPage();
    } catch (error) {
      button.disabled = false;
      button.textContent = "Unable to Terminate";
    }
  });
}

function bindTerminateAllSessions() {
  const button = document.getElementById("terminateAllSessionsBtn");
  if (!button) return;

  button.addEventListener("click", async () => {
    try {
      button.disabled = true;
      button.textContent = "Terminating...";
      await terminateAllSessions();
      clearToken();
      window.location.href = "/login.html";
    } catch (error) {
      button.disabled = false;
      button.textContent = "Unable to Terminate";
    }
  });
}

function startRealtimeUpdates(page) {
  if (page === "dashboard") {
    clearInterval(dashboardRefreshTimer);
    dashboardRefreshTimer = setInterval(() => {
      handleDashboardPage();
    }, 15000);
  }

  if (page === "security") {
    clearInterval(securityRefreshTimer);
    securityRefreshTimer = setInterval(() => {
      handleSecurityPage();
    }, 15000);
  }
}

function bindLogout() {
  const logoutButtons = document.querySelectorAll("#logoutBtn");
  logoutButtons.forEach((button) => {
    button.addEventListener("click", () => {
      clearToken();
      window.location.href = "/login.html";
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  bindLogout();
  bindSessionTermination();
  bindTerminateAllSessions();
  startRealtimeUpdates(page);

  if (page === "register") handleRegisterPage();
  if (page === "login") handleLoginPage();
  if (page === "dashboard") handleDashboardPage();
  if (page === "security") handleSecurityPage();
});
