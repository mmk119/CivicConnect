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

function renderList(items, emptyText) {
  return items.length
    ? `<ul class="mb-0">${items.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>`
    : `<span class="text-muted">${escapeHTML(emptyText)}</span>`;
}

function openVolunteerProfile(applicationId) {
  const applicant = applicants.find(item => Number(item.id) === Number(applicationId));
  if (!applicant) return;

  const completedHistory = parseCompletedHistory(applicant.completed_history);
  const profileEndorsements = parseProfileEndorsements(applicant.profile_endorsements);
  const skills = String(applicant.skills || "")
    .split(",")
    .map(skill => skill.trim())
    .filter(Boolean);

  document.getElementById("volunteerProfileTitle").textContent = applicant.name || "Volunteer Profile";
  document.getElementById("volunteerProfileSubtitle").textContent = `${applicant.email || ""}${applicant.city ? " | " + applicant.city : ""}`;
  document.getElementById("volunteerProfileBody").innerHTML = `
    <div class="profile-preview-grid mb-3">
      <div class="profile-preview-stat">
        <span class="text-muted">Confirmed Hours</span>
        <strong>${formatHours(applicant.total_hours)}</strong>
      </div>
      <div class="profile-preview-stat">
        <span class="text-muted">Application Status</span>
        <strong>${escapeHTML(String(applicant.status || "pending"))}</strong>
      </div>
      <div class="profile-preview-stat">
        <span class="text-muted">Current Opportunity</span>
        <strong>${formatHours(applicant.hours_completed)} hrs</strong>
      </div>
    </div>

    <div class="profile-preview-section mb-3">
      <h6><i class="fas fa-screwdriver-wrench"></i> Skills</h6>
      ${skills.length ? skills.map(skill => `<span class="profile-chip">${escapeHTML(skill)}</span>`).join("") : "<span class='text-muted'>No skills listed.</span>"}
    </div>

    <div class="profile-preview-section mb-3">
      <h6><i class="fas fa-briefcase"></i> Past Completed Experiences</h6>
      ${renderList(completedHistory, "No confirmed previous opportunities yet.")}
    </div>

    <div class="profile-preview-section">
      <h6><i class="fas fa-comment-dots"></i> Profile Endorsements</h6>
      ${profileEndorsements.length ? profileEndorsements.map(item => `
        <div class="border rounded-3 p-3 mb-2 bg-white">
          <div class="d-flex justify-content-between gap-2">
            <strong>${escapeHTML(item.title || "Endorsement")}</strong>
            <span class="badge bg-info text-dark">${Number(item.rating) || 0}/5</span>
          </div>
          <p class="mb-1 mt-2">${escapeHTML(item.comment || "")}</p>
          ${item.strengths ? `<small class="text-muted"><strong>Strengths:</strong> ${escapeHTML(item.strengths)}</small><br>` : ""}
          <small class="text-muted">${escapeHTML(item.ngo || "NGO")} | ${escapeHTML(item.opportunity || "Opportunity")}</small>
        </div>
      `).join("") : "<span class='text-muted'>No profile endorsements shared yet.</span>"}
    </div>
  `;

  const modal = new bootstrap.Modal(document.getElementById("volunteerProfileModal"));
  modal.show();
}

const volunteerFeedbackTags = [
  "Reliable",
  "Punctual",
  "Strong communicator",
  "Team player",
  "Empathetic",
  "Took initiative"
];

function toggleVolunteerTag(applicationId, tag) {
  const button = document.querySelector(`[data-volunteer-feedback-app="${applicationId}"][data-tag="${CSS.escape(tag)}"]`);
  if (button) button.classList.toggle("active");
}

function selectedVolunteerTags(applicationId) {
  return Array.from(document.querySelectorAll(`[data-volunteer-feedback-app="${applicationId}"].active`))
    .map(button => button.dataset.tag)
    .filter(Boolean);
}

function updateVolunteerFeedbackCounter(applicationId) {
  const textarea = document.getElementById(`vol-comment-${applicationId}`);
  const counter = document.getElementById(`vol-comment-count-${applicationId}`);
  if (textarea && counter) counter.textContent = `${textarea.value.length}/1200`;
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

        const opportunityEnded = isOpportunityFinished(applicant.end_date);

        let statusButtons = "";
        if (!opportunityEnded) {
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
        }

        let attendanceHTML = "";
        if (confirmed) {
          attendanceHTML = `
            <div class="alert alert-success mt-3 mb-0">
              Attendance confirmed. ${formatHours(applicant.hours_completed)} hours were added to this volunteer.
            </div>`;
        } else if (applicant.completion_status === "no_show") {
          attendanceHTML = `
            <div class="alert alert-warning mt-3 mb-0">
              Volunteer marked as no-show.
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
                <button class="btn btn-outline-danger"
                        onclick="markNoShow(${applicant.id})">
                  Mark No-show
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
                <a class="btn btn-outline-primary btn-sm" href="ngo-feedback.html?opportunity_id=${selectedOpportunityId}&application_id=${applicant.id}">
                  View Feedback
                </a>
              </div>
              <small class="text-muted">This endorsement was sent to the volunteer. Feedback can only be submitted once.</small>
            </div>`
          : `
            <div class="border rounded-3 p-3 mt-3 bg-white">
              <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                <strong>Leave volunteer feedback</strong>
                <a class="btn btn-primary btn-sm" href="ngo-feedback.html?opportunity_id=${selectedOpportunityId}&application_id=${applicant.id}">
                  Open Feedback Page
                </a>
              </div>
              <small class="text-muted">Feedback is completed on a dedicated page so applicant cards stay focused.</small>
            </div>`;
        }

        const opportunityFeedbackHTML = applicant.opportunity_feedback_id
          ? `<span class="mini-stat">Volunteer submitted opportunity feedback</span>`
          : "";

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
              <button class="applicant-avatar" type="button" onclick="openVolunteerProfile(${applicant.id})" aria-label="View ${escapeHTML(applicant.name)} profile">${escapeHTML(initials(applicant.name))}</button>
              <div>
              <h5 class="mb-1">
                <button class="volunteer-name-button" type="button" onclick="openVolunteerProfile(${applicant.id})">
                  ${escapeHTML(applicant.name)}
                </button>
              </h5>
              <div class="text-muted">${escapeHTML(applicant.email)}</div>
              <div class="text-muted">City: ${escapeHTML(applicant.city || "Not provided")}</div>
              </div>
            </div>
            <span class="badge ${statusBadgeClass(status)} fs-6">${statusLabel}</span>
          </div>

          <div class="applicant-card-body">
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
          </div>
        `;

        list.appendChild(listItem);
      });
}

function saveVolunteerFeedback(applicationId) {
  const rating = document.getElementById(`vol-rating-${applicationId}`).value;
  const endorsement_title = document.getElementById(`vol-title-${applicationId}`).value.trim();
  const comment = document.getElementById(`vol-comment-${applicationId}`).value.trim();
  const strengthsInput = document.getElementById(`vol-strengths-${applicationId}`).value.trim();
  const strengths = [strengthsInput, ...selectedVolunteerTags(applicationId)].filter(Boolean).join(", ");

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
      showAlert(data.message || "Feedback saved.", () => loadApplicants());
    })
    .catch(err => {
      console.error("Error saving volunteer feedback:", err);
      showAlert(err.message || "Could not save feedback.");
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
      showAlert(data.message || `Application ${status} successfully.`, () => loadApplicants());
    })
    .catch(err => {
      console.error("Error updating status:", err);
      showAlert(err.message || "Could not update status.");
    });
}

function confirmAttendance(applicationId) {
  const input = document.getElementById(`hours-${applicationId}`);
  const hoursCompleted = Number(input && input.value);

  if (!Number.isFinite(hoursCompleted) || hoursCompleted < 0.25) {
    showAlert("Please enter completed hours of at least 0.25.");
    return;
  }

  showConfirm("Confirming attendance will unlock this volunteer's certificate and record completed hours. Continue?", () => {
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
      showAlert(data.message || "Attendance confirmed.", () => loadApplicants());
    })
    .catch(err => {
      console.error("Error confirming attendance:", err);
      showAlert(err.message || "Could not confirm attendance.");
    });
  });
}

function markNoShow(applicationId) {
  showConfirm("Mark this accepted volunteer as no-show? They will not receive hours or a certificate.", () => {
  fetch(`api/applications/${applicationId}/no-show`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`
    }
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      showAlert(data.message || "Volunteer marked as no-show.", () => loadApplicants());
    })
    .catch(err => {
      console.error("Error marking no-show:", err);
      showAlert(err.message || "Could not mark no-show.");
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("token");
  if (!token) {
    showAlert("Please login first.", () => { window.location.href = "login.html"; });
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
