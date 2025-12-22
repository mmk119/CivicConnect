function logout() {
    localStorage.removeItem("token");
    alert("You have been logged out.");
    window.location.href = "login.html";
}

// Fetch and display opportunities based on NGO ID
function loadOpportunities() {
    const token = localStorage.getItem("token");
    if (!token) {
      alert("Please login first.");
      return window.location.href = "login.html";
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
          <span>${op.title} — ${new Date(op.start_date).toDateString()} — ${op.location}</span>
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

// Redirect user to the apply page
function redirectToApplyPage(opportunityId) {
    window.location.href = `apply.html?opportunity_id=${opportunityId}`;
}

// Submit a new opportunity with NGO ID
function submitOpportunity() {
    const title = document.getElementById("title").value;
    const description = document.getElementById("description").value;
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const location = document.getElementById("location").value;


    if (!title || !description || !startDate || !endDate || !location) {
        alert("Please fill in all fields before submitting.");
        return;
    }

    const token = localStorage.getItem("token");
    if (!token) {
        alert("Session expired. Please log in again.");
        window.location.href = "login.html";
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        const ngoId = payload?.ngo_id || 1; // 🔥 Hardcode ngo_id = 1 if none exists (dev-only)

        const opportunityData = {
            title,
            description,
            start_date: startDate,
            end_date: endDate,
            location,
            ngo_id: ngoId 
        };

        fetch("/api/opportunities/ins", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify(opportunityData)
        })
            .then(response => response.json())
            .then(data => {
                console.log("🟡 Response from POST /api/opportunities:", data);
                if (data.message) {
                    alert(data.message);
                } else {
                    alert("Something went wrong. Check console.");
                }
                const payload = JSON.parse(atob(token.split(".")[1]));
                loadOpportunities(payload.ngo_id);
            })
            .catch(error => console.error("Error submitting opportunity:", error));
    } catch (error) {
        console.error("Error decoding token:", error);
        alert("Invalid session. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
    }
}

// Delete an opportunity (only the NGO that created it can delete it)
function deleteOpportunity(opportunityId) {
    if (!confirm("Are you sure you want to delete this opportunity?")) return;

    const devBypass = false;
    let token = localStorage.getItem("token");

    let ngoId = null;

    if (devBypass) {
        console.warn("🚧 DEV MODE: Token checks are bypassed for delete.");
        token = "dev-mode";
        ngoId = 1;
    } else {
        if (!token) {
            alert("Session expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const payload = JSON.parse(atob(token.split(".")[1]));
        ngoId = payload.ngo_id;
    }

    fetch(`/api/opportunities/${opportunityId}`, {
        method: "DELETE",
        headers: {
            "Authorization": `Bearer ${token}`
        }
    })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            const payload = JSON.parse(atob(token.split(".")[1]));
            loadOpportunities(ngoId); // ✅ use mocked ngoId too
        })
        .catch(error => console.error("Error deleting opportunity:", error));
}

document.addEventListener("DOMContentLoaded", () => {
    loadOpportunities();
    const token = localStorage.getItem("token");

    if (!token) {
        alert("You must be logged in to access this page.");
        window.location.href = "login.html";
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        const currentTime = Math.floor(Date.now() / 1000);

        if (payload.exp < currentTime) {
            alert("Session expired. Please log in again.");
            localStorage.removeItem("token");
            window.location.href = "login.html";
            return;
        }

        const userEmail = document.getElementById("userEmail");
        if (userEmail) {
            userEmail.textContent = payload.email;
        }

        if (payload.role === "NGO_Representative") {
            loadOpportunities(payload.ngo_id);
        }

        //fetchFiles();
        loadPreviewIntoForm();

    } catch (error) {
        console.error("Error decoding token:", error);
        alert("Invalid session. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
    }
});

function loadPreviewIntoForm() {
    const storedData = localStorage.getItem("opportunityPreview");
    if (!storedData) return;

    const opportunity = JSON.parse(storedData);

    document.getElementById("title").value = opportunity.title || '';
    document.getElementById("description").value = opportunity.description || '';
    document.getElementById("start_date").value = opportunity.start_date || '';
    document.getElementById("end_date").value = opportunity.end_date || '';
    document.getElementById("location").value = opportunity.location || '';
}

function showPreview() {
    const title = document.getElementById("title").value;
    const description = document.getElementById("description").value;
    const startDate = document.getElementById("start_date").value;
    const endDate = document.getElementById("end_date").value;
    const location = document.getElementById("location").value;

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
    const token = localStorage.getItem("token");

    if (!token) {
        alert("Session expired. Please log in again.");
        window.location.href = "login.html";
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1])); // Decode token
        const ngoId = payload.ngo_id; // Extract NGO ID

        if (!ngoId) {
            alert("Unable to fetch NGO ID. Please log in again.");
            return;
        }

        // Redirect to applicant.html with NGO ID as query parameter
        window.location.href = `applicant.html?ngo_id=${ngoId}`;
    } catch (error) {
        console.error("Error decoding token:", error);
        alert("Invalid session. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
    }
}
