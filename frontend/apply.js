function getOpportunityId() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get("opportunity_id");
}

document.addEventListener("DOMContentLoaded", function() {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("Session expired. Please log in again.");
        window.location.href = "login.html";
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        document.getElementById("email").value = payload.email;
        document.getElementById("opportunityId").value = getOpportunityId();
    } catch (error) {
        console.error("Error decoding token:", error);
        alert("Invalid session. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
    }
});


function applyForOpportunity() {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("Session expired. Please log in again.");
        window.location.href = "login.html";
        return;
    }

    const opportunityId = document.getElementById("opportunityId").value;
    const fullName = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const phone = document.getElementById("phone").value;

    if (!fullName || !email || !phone) {
        alert("Please fill in all fields before applying.");
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
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            window.location.href = "index.html";
        })
        .catch(error => console.error("Error applying for opportunity:", error));
}


function cancelApplication() {
    window.location.href = "index.html";
}