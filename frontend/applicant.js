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

function loadApplicants() {
  fetch("api/applicants", {
    headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
  })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    })
    .then(data => {
      const list = document.getElementById("applicantsList");
      list.innerHTML = "";

      if (!Array.isArray(data) || data.length === 0) {
        list.innerHTML = "<li class='list-group-item'>No applicants found.</li>";
        return;
      }

      data.forEach(applicant => {
        const listItem = document.createElement("li");
        listItem.className = "list-group-item mb-3 rounded-3 shadow-sm";

        const status = String(applicant.status || "pending").toLowerCase();
        const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);
        const finished = isOpportunityFinished(applicant.end_date);
        const confirmed = applicant.attendance_confirmed === "YES";
        const completedHistory = parseCompletedHistory(applicant.completed_history);
        const hoursRequired = Number(applicant.hours_required) || 0;

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
              Attendance confirmed. ${Number(applicant.hours_completed) || 0} hours were added to this volunteer.
            </div>`;
        } else if (status === "accepted" && finished) {
          attendanceHTML = `
            <div class="border rounded-3 p-3 mt-3 bg-light">
              <label class="form-label fw-bold" for="hours-${applicant.id}">Completed hours</label>
              <div class="d-flex flex-wrap gap-2">
                <input id="hours-${applicant.id}" class="form-control" type="number" min="1"
                       max="${hoursRequired || 999}" value="${hoursRequired || 1}" style="max-width: 160px;">
                <button class="btn btn-primary"
                        onclick="confirmAttendance(${applicant.id})">
                  Confirm Attendance
                </button>
              </div>
              <small class="text-muted">This is available only after the opportunity ends.</small>
            </div>`;
        } else if (status === "accepted") {
          attendanceHTML = `
            <div class="alert alert-info mt-3 mb-0">
              Attendance confirmation will be available after ${formatDate(applicant.end_date)}.
            </div>`;
        }

        const historyHTML = completedHistory.length
          ? `<ul class="mb-0">${completedHistory.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>`
          : "<span class='text-muted'>No confirmed previous opportunities yet.</span>";

        listItem.innerHTML = `
          <div class="d-flex flex-wrap justify-content-between align-items-start gap-3 mb-3">
            <div>
              <h5 class="mb-1">${escapeHTML(applicant.name)}</h5>
              <div class="text-muted">${escapeHTML(applicant.email)}</div>
              <div class="text-muted">City: ${escapeHTML(applicant.city || "Not provided")}</div>
            </div>
            <span class="badge ${statusBadgeClass(status)} fs-6">${statusLabel}</span>
          </div>

          <div class="row g-3">
            <div class="col-md-6">
              <strong>Applied for:</strong>
              <div>${escapeHTML(applicant.opportunity_name)}</div>
              <div class="text-muted">Ends: ${formatDate(applicant.end_date)}</div>
              <div class="text-muted">Required hours: ${hoursRequired}</div>
            </div>
            <div class="col-md-6">
              <strong>Volunteer record:</strong>
              <div>Total confirmed hours: <span class="fw-bold">${Number(applicant.total_hours) || 0}</span></div>
              <div>Skills: ${escapeHTML(applicant.skills || "Not provided")}</div>
            </div>
          </div>

          <div class="mt-3">
            <strong>Previous completed opportunities:</strong>
            ${historyHTML}
          </div>

          <div class="mt-3">
            ${statusButtons}
          </div>

          ${attendanceHTML}
        `;

        list.appendChild(listItem);
      });
    })
    .catch(err => {
      console.error("Error fetching applicants:", err);
      document.getElementById("applicantsList").innerHTML =
        `<li class='list-group-item text-danger'>${escapeHTML(err.message || "Failed to load applicants.")}</li>`;
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

  if (!Number.isInteger(hoursCompleted) || hoursCompleted < 1) {
    alert("Please enter a valid number of completed hours.");
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

  loadApplicants();
});
