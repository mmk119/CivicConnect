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
            const list = document.getElementById("opportunitiesList");
            list.innerHTML = "";

            if (!Array.isArray(data) || data.length === 0) {
                list.innerHTML = "<li class='list-group-item'>No opportunities available.</li>";
                return;
            }

            data.forEach(op => {
                const li = document.createElement("li");
                li.className = "list-group-item d-flex justify-content-between align-items-center";
                li.innerHTML = `
                    <span>${op.title} - ${new Date(op.start_date).toDateString()} - ${op.location}</span>
                    <button class="btn btn-danger btn-sm" onclick="deleteOpportunity(${op.opportunity_id})">
                        Delete
                    </button>`;
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
    const description = document.getElementById("description").value.trim();
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const location = document.getElementById("location").value.trim();

    if (!title || !description || !startDate || !endDate || !location) {
        alert("Please fill in all fields before submitting.");
        return;
    }

    const token = localStorage.getItem("token");
    const opportunityData = {
        title,
        description,
        start_date: startDate,
        end_date: endDate,
        location
    };

    fetch("/api/opportunities/ins", {
        method: "POST",
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
            document.getElementById("opportunityForm").reset();
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
    document.getElementById("description").value = opportunity.description || "";
    document.getElementById("start_date").value = opportunity.start_date || "";
    document.getElementById("end_date").value = opportunity.end_date || "";
    document.getElementById("location").value = opportunity.location || "";
}

function showPreview() {
    const payload = requireNgoAccess();
    if (!payload) return;

    const title = document.getElementById("title").value.trim();
    const description = document.getElementById("description").value.trim();
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const location = document.getElementById("location").value.trim();

    if (!title || !description || !startDate || !endDate || !location) {
        alert("Please fill in all required fields before previewing.");
        return;
    }

    const previewData = {
        title,
        description,
        start_date: startDate,
        end_date: endDate,
        location
    };

    localStorage.setItem("opportunityPreview", JSON.stringify(previewData));
    window.location.href = "preview.html";
}

function viewApplicants() {
    const payload = requireNgoAccess();
    if (!payload) return;

    window.location.href = `applicant.html?ngo_id=${payload.ngo_id}`;
}

document.addEventListener("DOMContentLoaded", () => {
    const payload = requireNgoAccess();
    if (!payload) return;

    const userEmail = document.getElementById("userEmail");
    if (userEmail) {
        userEmail.textContent = payload.email;
    }

    loadOpportunities(payload.ngo_id);

    const params = new URLSearchParams(window.location.search);
    if (params.get("fromPreview") === "1") {
        loadPreviewIntoForm();
    } else {
        localStorage.removeItem("opportunityPreview");
        document.getElementById("opportunityForm").reset();
    }
});
