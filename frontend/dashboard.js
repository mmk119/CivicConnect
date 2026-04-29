function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("userRole");
    localStorage.removeItem("user_id");
    localStorage.removeItem("ngo_id");
    localStorage.removeItem("opportunityPreview");
    alert("You have been logged out.");
    window.location.href = "login.html";
}

function getTokenPayload() {
    const token = localStorage.getItem("token");
    if (!token) return null;

    try {
        return JSON.parse(atob(token.split(".")[1]));
    } catch (error) {
        console.error("Error decoding token:", error);
        return null;
    }
}

function requireNgoAccess() {
    const payload = getTokenPayload();

    if (!payload) {
        alert("You must be logged in to access this page.");
        window.location.href = "login.html";
        return null;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    if (payload.exp < currentTime) {
        alert("Session expired. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
        return null;
    }

    if (payload.role !== "NGO" || !payload.ngo_id) {
        alert("Only NGO accounts can create volunteering opportunities.");
        window.location.href = "opportunities.html";
        return null;
    }

    return payload;
}

const weekdayOrder = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];
let editingOpportunityId = null;
let loadedOpportunities = [];

function getSelectedScheduleDays() {
    return Array.from(document.querySelectorAll("#scheduleDays input:checked")).map(input => input.value);
}

function getDateOnly(value) {
    if (!value) return null;
    const parts = value.split("-").map(Number);
    if (parts.length !== 3 || parts.some(part => !Number.isFinite(part))) return null;
    return new Date(parts[0], parts[1] - 1, parts[2]);
}

function calculateScheduleHours() {
    const startDate = getDateOnly(document.getElementById("start_date").value);
    const endDate = getDateOnly(document.getElementById("end_date").value);
    const startTime = document.getElementById("start_time").value;
    const endTime = document.getElementById("end_time").value;
    const selectedDays = getSelectedScheduleDays();

    if (!startDate || !endDate || selectedDays.length === 0 || !startTime || !endTime) {
        return { hours: 0, message: "Choose dates, days, and timing" };
    }

    if (endDate < startDate) {
        return { hours: 0, message: "End date must be after start date" };
    }

    const [startHour, startMinute] = startTime.split(":").map(Number);
    const [endHour, endMinute] = endTime.split(":").map(Number);
    const minutesPerSession = (endHour * 60 + endMinute) - (startHour * 60 + startMinute);

    if (minutesPerSession <= 0) {
        return { hours: 0, message: "End time must be after start time" };
    }

    const jsDayToCode = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
    let sessions = 0;
    const cursor = new Date(startDate);
    while (cursor <= endDate) {
        if (selectedDays.includes(jsDayToCode[cursor.getDay()])) sessions += 1;
        cursor.setDate(cursor.getDate() + 1);
    }

    if (sessions === 0) {
        return { hours: 0, message: "No selected weekdays fall inside this date range" };
    }

    const duration = Math.round((minutesPerSession / 60) * 100) / 100;
    const hours = Math.round((sessions * duration) * 100) / 100;
    return {
        hours,
        message: `${hours} total hours (${sessions} session${sessions === 1 ? "" : "s"} x ${duration} hrs)`
    };
}

function updateHoursPreview() {
    const result = calculateScheduleHours();
    document.getElementById("hours_required").value = result.hours || "";
    document.getElementById("hoursPreview").textContent = result.message;
    return result;
}

function formatScheduleDays(days) {
    const selected = Array.isArray(days) ? days : String(days || "").split(",");
    return weekdayOrder.filter(day => selected.includes(day)).join(", ") || "Days TBD";
}

function formatTime(value) {
    return value ? String(value).slice(0, 5) : "Time TBD";
}

function getApplicationQuestions() {
    return document.getElementById("application_questions").value
        .split(/\r?\n/)
        .map(question => question.trim())
        .filter(Boolean)
        .slice(0, 5);
}

async function loadNgoApprovalStatus() {
    const token = localStorage.getItem("token");
    const notice = document.getElementById("approvalNotice");
    const form = document.getElementById("opportunityForm");
    const previewBtn = document.getElementById("previewBtn");
    const submitBtn = document.getElementById("submitBtn");

    try {
        const response = await fetch("/api/ngo-profile", {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });

        if (!response.ok) throw new Error("Could not load NGO approval status.");

        const data = await response.json();
        const status = data.approval_status || "pending";
        const canPost = status === "approved";

        if (!canPost) {
            notice.classList.remove("d-none");
            notice.textContent = status === "rejected"
                ? "Your NGO account was rejected by the admin, so you cannot post opportunities."
                : "Your NGO account is pending admin approval. You can post opportunities after approval.";
        } else {
            notice.classList.add("d-none");
            notice.textContent = "";
        }

        form.querySelectorAll("input, textarea, select").forEach(control => {
            control.disabled = !canPost;
        });
        previewBtn.disabled = !canPost;
        submitBtn.disabled = !canPost;

        return canPost;
    } catch (error) {
        console.error(error);
        notice.classList.remove("d-none");
        notice.textContent = "Could not verify NGO approval status. Please refresh or log in again.";
        form.querySelectorAll("input, textarea, select").forEach(control => {
            control.disabled = true;
        });
        previewBtn.disabled = true;
        submitBtn.disabled = true;
        return false;
    }
}

function loadOpportunities() {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("Please login first.");
        window.location.href = "login.html";
        return;
    }

    fetch("/api/opportunities", {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    })
        .then(res => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        })
        .then(data => {
            loadedOpportunities = Array.isArray(data) ? data : [];
            const list = document.getElementById("opportunitiesList");
            list.innerHTML = "";

            if (loadedOpportunities.length === 0) {
                list.innerHTML = "<li class='list-group-item'>No opportunities available.</li>";
                return;
            }

            loadedOpportunities.forEach(op => {
                const li = document.createElement("li");
                li.className = "list-group-item d-flex flex-wrap justify-content-between align-items-center gap-2";
                li.innerHTML = `
                    <span>${op.title} - ${op.field || "No field"} - ${formatScheduleDays(op.schedule_days)} ${formatTime(op.start_time)}-${formatTime(op.end_time)} - ${op.hours_required || 0} hours - ${new Date(op.start_date).toDateString()} - ${op.location}<br>
                    <small>Applicants: ${op.pending_count || 0} pending / ${op.accepted_count || 0} accepted / ${op.rejected_count || 0} rejected | Capacity: ${op.accepted_count || 0}/${op.capacity || 0}</small></span>
                    <span class="d-flex flex-wrap gap-2">
                        <button class="btn btn-info btn-sm" onclick="viewApplicants(${op.opportunity_id}, '${encodeURIComponent(op.title || "Opportunity")}')">
                            View Applicants
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="editOpportunity(${op.opportunity_id})">
                            Edit
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteOpportunity(${op.opportunity_id})">
                            Delete
                        </button>
                    </span>`;
                list.appendChild(li);
            });
        })
        .catch(err => {
            console.error("Error fetching opportunities:", err);
            document.getElementById("opportunitiesList").innerHTML =
                "<li class='list-group-item text-danger'>Failed to load opportunities.</li>";
        });
}

function submitOpportunity() {
    const payload = requireNgoAccess();
    if (!payload) return;

    const title = document.getElementById("title").value.trim();
    const field = document.getElementById("field").value;
    const description = document.getElementById("description").value.trim();
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const hoursRequired = Number(document.getElementById("hours_required").value);
    const capacity = Number(document.getElementById("capacity").value);
    const location = document.getElementById("location").value.trim();
    const applicationQuestions = getApplicationQuestions();
    const scheduleDays = getSelectedScheduleDays();
    const startTime = document.getElementById("start_time").value;
    const endTime = document.getElementById("end_time").value;
    const scheduleResult = updateHoursPreview();

    if (!title || !field || !description || !startDate || !endDate || !capacity || !location || scheduleDays.length === 0 || !startTime || !endTime) {
        alert("Please fill in all fields before submitting.");
        return;
    }

    if (!scheduleResult.hours) {
        alert(scheduleResult.message);
        return;
    }

    if (!Number.isInteger(capacity) || capacity < 1) {
        alert("Number of volunteers needed must be a positive whole number.");
        return;
    }

    const token = localStorage.getItem("token");
    const opportunityData = {
        title,
        field,
        description,
        start_date: startDate,
        end_date: endDate,
        schedule_days: scheduleDays,
        start_time: startTime,
        end_time: endTime,
        hours_required: hoursRequired,
        capacity,
        location,
        application_questions: applicationQuestions
    };

    const url = editingOpportunityId ? `/api/opportunities/${editingOpportunityId}` : "/api/opportunities/ins";
    const method = editingOpportunityId ? "PATCH" : "POST";

    fetch(url, {
        method,
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify(opportunityData)
    })
        .then(response => response.json().then(data => ({ ok: response.ok, data })))
        .then(({ ok, data }) => {
            if (!ok) {
                alert(data.error || "Failed to submit opportunity.");
                return;
            }

            alert(data.message || "Opportunity submitted successfully!");
            localStorage.removeItem("opportunityPreview");
            cancelEditOpportunity(false);
            updateHoursPreview();
            loadOpportunities(payload.ngo_id);
        })
        .catch(error => {
            console.error("Error submitting opportunity:", error);
            alert("Failed to submit opportunity.");
        });
}

function deleteOpportunity(opportunityId) {
    const payload = requireNgoAccess();
    if (!payload) return;
    if (!confirm("Are you sure you want to delete this opportunity?")) return;

    const token = localStorage.getItem("token");

    fetch(`/api/opportunities/${opportunityId}`, {
        method: "DELETE",
        headers: {
            "Authorization": `Bearer ${token}`
        }
    })
        .then(response => response.json())
        .then(data => {
            alert(data.message || data.error || "Request completed.");
            loadOpportunities(payload.ngo_id);
        })
        .catch(error => console.error("Error deleting opportunity:", error));
}

function loadPreviewIntoForm() {
    const storedData = localStorage.getItem("opportunityPreview");
    if (!storedData) return;

    const opportunity = JSON.parse(storedData);

    document.getElementById("title").value = opportunity.title || "";
    document.getElementById("field").value = opportunity.field || "";
    document.getElementById("description").value = opportunity.description || "";
    document.getElementById("start_date").value = opportunity.start_date || "";
    document.getElementById("end_date").value = opportunity.end_date || "";
    document.querySelectorAll("#scheduleDays input").forEach(input => {
        input.checked = Array.isArray(opportunity.schedule_days)
            ? opportunity.schedule_days.includes(input.value)
            : String(opportunity.schedule_days || "").split(",").includes(input.value);
    });
    document.getElementById("start_time").value = formatTime(opportunity.start_time) === "Time TBD" ? "" : formatTime(opportunity.start_time);
    document.getElementById("end_time").value = formatTime(opportunity.end_time) === "Time TBD" ? "" : formatTime(opportunity.end_time);
    document.getElementById("hours_required").value = opportunity.hours_required || "";
    document.getElementById("capacity").value = opportunity.capacity || "";
    document.getElementById("location").value = opportunity.location || "";
    document.getElementById("application_questions").value = Array.isArray(opportunity.application_questions)
        ? opportunity.application_questions.join("\n")
        : "";
    updateHoursPreview();
}

function editOpportunity(opportunityId) {
    const opportunity = loadedOpportunities.find(op => Number(op.opportunity_id) === Number(opportunityId));
    if (!opportunity) {
        alert("Opportunity not found.");
        return;
    }

    editingOpportunityId = opportunity.opportunity_id;
    document.getElementById("title").value = opportunity.title || "";
    document.getElementById("field").value = opportunity.field || "";
    document.getElementById("description").value = opportunity.description || "";
    document.getElementById("start_date").value = String(opportunity.start_date || "").slice(0, 10);
    document.getElementById("end_date").value = String(opportunity.end_date || "").slice(0, 10);
    document.querySelectorAll("#scheduleDays input").forEach(input => {
        input.checked = String(opportunity.schedule_days || "").split(",").includes(input.value);
    });
    document.getElementById("start_time").value = formatTime(opportunity.start_time) === "Time TBD" ? "" : formatTime(opportunity.start_time);
    document.getElementById("end_time").value = formatTime(opportunity.end_time) === "Time TBD" ? "" : formatTime(opportunity.end_time);
    document.getElementById("capacity").value = opportunity.capacity || "";
    document.getElementById("location").value = opportunity.location || "";
    document.getElementById("application_questions").value = (() => {
        try {
            const parsed = JSON.parse(opportunity.application_questions || "[]");
            return Array.isArray(parsed) ? parsed.join("\n") : "";
        } catch {
            return "";
        }
    })();
    document.getElementById("submitBtn").textContent = "Update";
    document.getElementById("previewBtn").disabled = true;
    document.getElementById("cancelEditBtn").classList.remove("d-none");
    updateHoursPreview();
    document.getElementById("opportunityForm").scrollIntoView({ behavior: "smooth", block: "start" });
}

function cancelEditOpportunity(showMessage = true) {
    editingOpportunityId = null;
    document.getElementById("opportunityForm").reset();
    document.getElementById("submitBtn").textContent = "Submit";
    document.getElementById("previewBtn").disabled = false;
    document.getElementById("cancelEditBtn").classList.add("d-none");
    updateHoursPreview();
    if (showMessage) alert("Edit cancelled.");
}

function showPreview() {
    const payload = requireNgoAccess();
    if (!payload) return;

    const title = document.getElementById("title").value.trim();
    const field = document.getElementById("field").value;
    const description = document.getElementById("description").value.trim();
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const hoursRequired = Number(document.getElementById("hours_required").value);
    const capacity = Number(document.getElementById("capacity").value);
    const location = document.getElementById("location").value.trim();
    const applicationQuestions = getApplicationQuestions();
    const scheduleDays = getSelectedScheduleDays();
    const startTime = document.getElementById("start_time").value;
    const endTime = document.getElementById("end_time").value;
    const scheduleResult = updateHoursPreview();

    if (!title || !field || !description || !startDate || !endDate || !capacity || !location || scheduleDays.length === 0 || !startTime || !endTime) {
        alert("Please fill in all required fields before previewing.");
        return;
    }

    if (!scheduleResult.hours) {
        alert(scheduleResult.message);
        return;
    }

    if (!Number.isInteger(capacity) || capacity < 1) {
        alert("Number of volunteers needed must be a positive whole number.");
        return;
    }

    const previewData = {
        title,
        field,
        description,
        start_date: startDate,
        end_date: endDate,
        schedule_days: scheduleDays,
        start_time: startTime,
        end_time: endTime,
        hours_required: hoursRequired,
        capacity,
        location,
        application_questions: applicationQuestions
    };

    localStorage.setItem("opportunityPreview", JSON.stringify(previewData));
    window.location.href = "preview.html";
}

function viewApplicants(opportunityId, encodedTitle = "") {
    const payload = requireNgoAccess();
    if (!payload) return;

    if (!opportunityId) {
        alert("Please choose a specific opportunity first.");
        return;
    }

    window.location.href = `applicant.html?opportunity_id=${opportunityId}&title=${encodedTitle}`;
}

document.addEventListener("DOMContentLoaded", () => {
    const payload = requireNgoAccess();
    if (!payload) return;

    const userEmail = document.getElementById("userEmail");
    if (userEmail) {
        userEmail.textContent = payload.email;
    }

    loadOpportunities(payload.ngo_id);
    loadNgoApprovalStatus();
    ["start_date", "end_date", "start_time", "end_time"].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.addEventListener("change", updateHoursPreview);
    });
    document.querySelectorAll("#scheduleDays input").forEach(input => {
        input.addEventListener("change", updateHoursPreview);
    });

    const params = new URLSearchParams(window.location.search);
    if (params.get("fromPreview") === "1") {
        loadPreviewIntoForm();
    } else {
        localStorage.removeItem("opportunityPreview");
        document.getElementById("opportunityForm").reset();
        updateHoursPreview();
    }
});
