function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not available";
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
}

const weekdayOrder = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

function formatScheduleDays(days) {
  const selected = Array.isArray(days) ? days : String(days || "").split(",");
  return weekdayOrder.filter(day => selected.includes(day)).join(", ") || "Days TBD";
}

function formatTime(value) {
  return value ? String(value).slice(0, 5) : "Time TBD";
}

function formatHours(value) {
  const hours = Number(value) || 0;
  return Number.isInteger(hours) ? String(hours) : hours.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
}

function isOpportunityFinished(endDateValue) {
  if (!endDateValue) return false;
  const endDate = new Date(endDateValue);
  if (Number.isNaN(endDate.getTime())) return false;
  endDate.setHours(23, 59, 59, 999);
  return endDate < new Date();
}

function statusBadgeClass(status) {
  if (status === "accepted") return "bg-success";
  if (status === "rejected") return "bg-danger";
  return "bg-warning text-dark";
}

function parseCompletedHistory(value) {
  if (!value) return [];
  return String(value).split("||").filter(Boolean);
}

function parseApplicationAnswers(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseProfileEndorsements(value) {
  if (!value) return [];
  return String(value).split("||").filter(Boolean).map(item => {
    const [title, rating, comment, strengths, ngo, opportunity] = item.split("~~");
    return { title, rating, comment, strengths, ngo, opportunity };
  });
}

const applicantParams = new URLSearchParams(window.location.search);
const selectedOpportunityId = Number(applicantParams.get("opportunity_id"));
const selectedOpportunityTitle = applicantParams.get("title")
  ? decodeURIComponent(applicantParams.get("title"))
  : "";
let applicants = [];
let activeStatusFilter = "all";

function initials(name) {
  return String(name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0].toUpperCase())
    .join("") || "?";
}

function updateFilterCounts() {
  const counts = applicants.reduce((acc, applicant) => {
    const status = String(applicant.status || "pending").toLowerCase();
    acc.all += 1;
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, { all: 0, pending: 0, accepted: 0, rejected: 0 });

  ["all", "pending", "accepted", "rejected"].forEach(status => {
    const el = document.getElementById(`count-${status}`);
    if (el) el.textContent = counts[status] || 0;
  });
}

function filteredApplicants() {
  if (activeStatusFilter === "all") return applicants;
  return applicants.filter(applicant => String(applicant.status || "pending").toLowerCase() === activeStatusFilter);
}

function loadApplicants() {
  if (!Number.isInteger(selectedOpportunityId) || selectedOpportunityId < 1) {
    document.getElementById("applicantsList").innerHTML =
      "<li class='list-group-item text-danger'>Please open applicants from a specific opportunity on the NGO dashboard.</li>";
    return;
  }

  fetch(`api/applicants?opportunity_id=${selectedOpportunityId}`, {
    headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      applicants = Array.isArray(data) ? data : [];
      updateFilterCounts();
      renderApplicants();
    })
    .catch(err => {
      console.error("Error fetching applicants:", err);
      document.getElementById("applicantsList").innerHTML =
        `<li class='list-group-item text-danger'>${escapeHTML(err.message || "Failed to load applicants.")}</li>`;
    });
}

function renderApplicants() {
      const list = document.getElementById("applicantsList");
      const visibleApplicants = filteredApplicants();
      const visibleCount = document.getElementById("visibleCount");
      if (visibleCount) {
        visibleCount.textContent = `${visibleApplicants.length} shown`;
      }
      list.innerHTML = "";

      if (applicants.length === 0) {
        list.innerHTML = "<li class='list-group-item'>No applicants found for this opportunity.</li>";
        return;
      }

      if (visibleApplicants.length === 0) {
        list.innerHTML = `<li class='list-group-item'>No ${activeStatusFilter} applicants found.</li>`;
        return;
      }

      visibleApplicants.forEach(applicant => {
        const listItem = document.createElement("li");
        listItem.className = "list-group-item applicant-card";

        const status = String(applicant.status || "pending").toLowerCase();
        const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);
        const confirmed = applicant.attendance_confirmed === "YES";
        const completedHistory = parseCompletedHistory(applicant.completed_history);
        const profileEndorsements = parseProfileEndorsements(applicant.profile_endorsements);
        const hoursRequired = Number(applicant.hours_required) || 0;
        const applicationAnswers = parseApplicationAnswers(applicant.application_answers);

        let statusButtons = "";
        if (status !== "accepted") {
          statusButtons += `
            <button class="btn btn-success btn-sm me-2"
                    onclick="updateStatus(${applicant.id}, 'accepted')">
              Accept
            </button>`;
        }
        if (status !== "rejected") {
          statusButtons += `
            <button class="btn btn-danger btn-sm"
                    onclick="updateStatus(${applicant.id}, 'rejected')">
              Reject
            </button>`;
        }

        let attendanceHTML = "";
        if (confirmed) {
          attendanceHTML = `
            <div class="alert alert-success mt-3 mb-0">
              Attendance confirmed. ${formatHours(applicant.hours_completed)} hours were added to this volunteer.
            </div>`;
        } else if (status === "accepted") {
          attendanceHTML = `
            <div class="border rounded-3 p-3 mt-3 bg-light">
              <label class="form-label fw-bold" for="hours-${applicant.id}">Completed hours</label>
              <div class="d-flex flex-wrap gap-2">
                <input id="hours-${applicant.id}" class="form-control" type="number" min="0.25" step="0.25"
                       max="${hoursRequired || 999}" value="${hoursRequired || 1}" style="max-width: 160px;">
                <button class="btn btn-primary"
                        onclick="confirmAttendance(${applicant.id})">
                  Confirm Attendance
                </button>
              </div>
              <small class="text-muted">You can confirm attendance whenever the NGO has verified the volunteer's participation.</small>
            </div>`;
        }

        let feedbackHTML = "";
        if (confirmed) {
          const existing = Boolean(applicant.volunteer_feedback_id);
          feedbackHTML = existing ? `
            <div class="border rounded-3 p-3 mt-3 bg-white">
              <div class="d-flex flex-wrap justify-content-between align-items-center gap-2">
                <strong>Volunteer feedback submitted</strong>
              </div>
              <small class="text-muted">This endorsement was sent to the volunteer. Feedback can only be submitted once.</small>
            </div>`
          : `
            <div class="border rounded-3 p-3 mt-3 bg-white">
              <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                <strong>Leave volunteer feedback</strong>
              </div>
              <div class="row g-2">
                <div class="col-md-3">
                  <label class="form-label" for="vol-rating-${applicant.id}">Rating</label>
                  <select id="vol-rating-${applicant.id}" class="form-select">
                    ${[5, 4, 3, 2, 1].map(value => `
                      <option value="${value}">
                        ${value} star${value === 1 ? "" : "s"}
                      </option>
                    `).join("")}
                  </select>
                </div>
                <div class="col-md-9">
                  <label class="form-label" for="vol-title-${applicant.id}">Endorsement title</label>
                  <input id="vol-title-${applicant.id}" class="form-control" maxlength="120"
                         placeholder="Reliable, thoughtful team contributor"
                         value="">
                </div>
                <div class="col-12">
                  <label class="form-label" for="vol-comment-${applicant.id}">Feedback visible to the volunteer</label>
                  <textarea id="vol-comment-${applicant.id}" class="form-control" rows="3" maxlength="1200"
                            placeholder="Describe their contribution, attitude, reliability, and impact."></textarea>
                </div>
                <div class="col-12">
                  <label class="form-label" for="vol-strengths-${applicant.id}">Strengths or skills noticed</label>
                  <input id="vol-strengths-${applicant.id}" class="form-control" maxlength="800"
                         placeholder="Communication, punctuality, empathy"
                         value="">
                </div>
              </div>
              <button class="btn btn-primary mt-3" onclick="saveVolunteerFeedback(${applicant.id})">
                Save Feedback
              </button>
            </div>`;
        }

        const opportunityFeedbackHTML = applicant.opportunity_feedback_id ? `
          <div class="border rounded-3 p-3 mt-3 bg-white">
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
              <strong>Volunteer's feedback about this opportunity</strong>
              <span class="badge bg-info text-dark">${Number(applicant.opportunity_feedback_rating) || 0}/5 rating</span>
            </div>
            <p class="mb-1">${escapeHTML(applicant.opportunity_feedback_comment || "")}</p>
            ${applicant.opportunity_feedback_impact_story ? `<small class="text-muted"><strong>Impact note:</strong> ${escapeHTML(applicant.opportunity_feedback_impact_story)}</small>` : ""}
          </div>
        ` : "";

        const historyHTML = completedHistory.length
          ? `<ul class="mb-0">${completedHistory.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>`
          : "<span class='text-muted'>No confirmed previous opportunities yet.</span>";
        const profileEndorsementsHTML = profileEndorsements.length
          ? `<div class="mt-3">
              <strong>Profile endorsements shared by volunteer:</strong>
              <div class="row g-2 mt-1">
                ${profileEndorsements.map(item => `
                  <div class="col-md-6">
                    <div class="border rounded-3 p-3 bg-light h-100">
                      <div class="d-flex justify-content-between gap-2">
                        <strong>${escapeHTML(item.title || "Endorsement")}</strong>
                        <span class="badge bg-info text-dark">${Number(item.rating) || 0}/5</span>
                      </div>
                      <p class="mb-1 mt-2">${escapeHTML(item.comment || "")}</p>
                      ${item.strengths ? `<small class="text-muted"><strong>Strengths:</strong> ${escapeHTML(item.strengths)}</small><br>` : ""}
                      <small class="text-muted">${escapeHTML(item.ngo || "NGO")} | ${escapeHTML(item.opportunity || "Opportunity")}</small>
                    </div>
                  </div>
                `).join("")}
              </div>
            </div>`
          : "";

        listItem.innerHTML = `
          <div class="applicant-card-header">
            <div class="d-flex align-items-start gap-3">
              <div class="applicant-avatar">${escapeHTML(initials(applicant.name))}</div>
              <div>
              <h5 class="mb-1">${escapeHTML(applicant.name)}</h5>
              <div class="text-muted">${escapeHTML(applicant.email)}</div>
              <div class="text-muted">City: ${escapeHTML(applicant.city || "Not provided")}</div>
              </div>
            </div>
            <span class="badge ${statusBadgeClass(status)} fs-6">${statusLabel}</span>
          </div>

          <div class="applicant-card-body">
          <div class="row g-3">
            <div class="col-md-6">
              <strong>Applied for:</strong>
              <div>${escapeHTML(applicant.opportunity_name)}</div>
              <div class="text-muted">Ends: ${formatDate(applicant.end_date)}</div>
              <div class="text-muted">Days: ${formatScheduleDays(applicant.schedule_days)}</div>
              <div class="text-muted">Timing: ${formatTime(applicant.start_time)} - ${formatTime(applicant.end_time)}</div>
              <div class="text-muted">Required hours: ${formatHours(hoursRequired)}</div>
            </div>
            <div class="col-md-6">
              <strong>Volunteer record:</strong>
              <div class="mini-stat-row">
                <span class="mini-stat">${formatHours(applicant.total_hours)} confirmed hours</span>
                <span class="mini-stat">${escapeHTML(applicant.skills || "Skills not provided")}</span>
              </div>
            </div>
          </div>

          <div class="mt-3">
            <strong>Previous completed opportunities:</strong>
            ${historyHTML}
          </div>

          ${profileEndorsementsHTML}

          ${applicationAnswers.length ? `
            <div class="mt-3">
              <strong>Application answers:</strong>
              <ul class="mb-0">
                ${applicationAnswers.map(item => `
                  <li><strong>${escapeHTML(item.question || "Question")}:</strong> ${escapeHTML(item.answer || "No answer")}</li>
                `).join("")}
              </ul>
            </div>
          ` : ""}

          <div class="action-row">
            ${statusButtons}
          </div>

          ${attendanceHTML}
          ${feedbackHTML}
          ${opportunityFeedbackHTML}
          </div>
        `;

        list.appendChild(listItem);
      });
}

function saveVolunteerFeedback(applicationId) {
  const rating = document.getElementById(`vol-rating-${applicationId}`).value;
  const endorsement_title = document.getElementById(`vol-title-${applicationId}`).value.trim();
  const comment = document.getElementById(`vol-comment-${applicationId}`).value.trim();
  const strengths = document.getElementById(`vol-strengths-${applicationId}`).value.trim();

  fetch(`api/feedback/volunteer/${applicationId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("token")}`
    },
    body: JSON.stringify({ rating, endorsement_title, comment, strengths })
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      alert(data.message || "Feedback saved.");
      loadApplicants();
    })
    .catch(err => {
      console.error("Error saving volunteer feedback:", err);
      alert(err.message || "Could not save feedback.");
    });
}

function updateStatus(applicationId, status) {
  fetch(`api/applications/${applicationId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("token")}`
    },
    body: JSON.stringify({ status })
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      alert(data.message || `Application ${status} successfully.`);
      loadApplicants();
    })
    .catch(err => {
      console.error("Error updating status:", err);
      alert(err.message || "Could not update status.");
    });
}

function confirmAttendance(applicationId) {
  const input = document.getElementById(`hours-${applicationId}`);
  const hoursCompleted = Number(input && input.value);

  if (!Number.isFinite(hoursCompleted) || hoursCompleted < 0.25) {
    alert("Please enter completed hours of at least 0.25.");
    return;
  }

  fetch(`api/applications/${applicationId}/attendance`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("token")}`
    },
    body: JSON.stringify({ hours_completed: hoursCompleted })
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      alert(data.message || "Attendance confirmed.");
      loadApplicants();
    })
    .catch(err => {
      console.error("Error confirming attendance:", err);
      alert(err.message || "Could not confirm attendance.");
    });
}

document.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("token");
  if (!token) {
    alert("Please login first.");
    window.location.href = "login.html";
    return;
  }

  const title = document.getElementById("applicantTitle");
  const subtitle = document.getElementById("applicantSubtitle");
  if (selectedOpportunityTitle && title) {
    title.textContent = `Applicants for ${selectedOpportunityTitle}`;
  }
  if (subtitle) {
    subtitle.textContent = "This page shows only the volunteers who applied to the selected opportunity.";
  }

  document.querySelectorAll(".status-filter").forEach(button => {
    button.addEventListener("click", () => {
      activeStatusFilter = button.dataset.status;
      document.querySelectorAll(".status-filter").forEach(btn => btn.classList.remove("active"));
      button.classList.add("active");
      renderApplicants();
    });
  });

  loadApplicants();
});
