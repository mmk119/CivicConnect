function getOpportunityId() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get("opportunity_id");
}

document.addEventListener("DOMContentLoaded", function() {
    const token = localStorage.getItem("token");
    if (!token) {
        showAlert("Session expired. Please log in again.", () => { window.location.href = "login.html"; });
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        document.getElementById("email").value = payload.email;
        document.getElementById("opportunityId").value = getOpportunityId();
        validateOpportunityCanAcceptApplications(getOpportunityId());
    } catch (error) {
        console.error("Error decoding token:", error);
        showAlert("Invalid session. Please log in again.", () => { localStorage.removeItem("token"); window.location.href = "login.html"; });
    }
});

function disableApplyForm(message) {
    const applyButton = document.querySelector(".btn-success");
    if (applyButton) {
        applyButton.disabled = true;
        applyButton.textContent = message;
    }
}

function isClosedOpportunity(opportunity) {
    return ["closed", "completed", "archived"].includes(String(opportunity?.status || "open").toLowerCase());
}

async function validateOpportunityCanAcceptApplications(opportunityId) {
    if (!opportunityId) {
        disableApplyForm("Unavailable");
        return;
    }

    try {
        const response = await fetch(`/api/opportunities/${opportunityId}`);
        const opportunity = await response.json();
        if (!response.ok) throw new Error(opportunity.error || "Could not load opportunity.");

        if (isClosedOpportunity(opportunity)) {
            disableApplyForm("Applications Closed");
        }
    } catch (error) {
        console.error("Error loading opportunity:", error);
        disableApplyForm("Unavailable");
    }
}

function applyForOpportunity() {
    const token = localStorage.getItem("token");
    if (!token) {
        showAlert("Session expired. Please log in again.", () => { window.location.href = "login.html"; });
        return;
    }

    const opportunityId = document.getElementById("opportunityId").value;
    const fullName = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const phone = document.getElementById("phone").value;

    if (!fullName || !email || !phone) {
        showAlert("Please fill in all fields before applying.");
        return;
    }

    const applicationData = { opportunity_id: opportunityId, full_name: fullName, email, phone };

    fetch("/api/applications", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify(applicationData)
        })
        .then(async response => {
            const data = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(data.error || "Application failed.");
            return data;
        })
        .then(data => {
            showAlert(data.message, () => { window.location.href = "index.html"; });
        })
        .catch(error => {
            console.error("Error applying for opportunity:", error);
            showAlert(error.message || "Application failed.");
        });
}


function cancelApplication() {
    window.location.href = "index.html";
}
