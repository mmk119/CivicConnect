function loadApplicants(ngoId) {
  fetch(`api/applicants?ngo_id=${ngoId}`, {
    headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
  })
  .then(res => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
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
      listItem.className = "list-group-item d-flex flex-column";

      // buttons same as before…
      let buttonsHTML = "";
      if (applicant.status !== "Accepted") {
        buttonsHTML += `
          <button class="btn btn-success btn-sm me-2"
                  onclick="updateStatus(${applicant.id}, 'Accepted')">
            Accept
          </button>`;
      }
      if (applicant.status !== "Rejected") {
        buttonsHTML += `
          <button class="btn btn-danger btn-sm"
                  onclick="updateStatus(${applicant.id}, 'Rejected')">
            Reject
          </button>`;
      }

      listItem.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-2">
          <div>
            <strong>${applicant.name}</strong> &lt;${applicant.email}&gt;
          </div>
          <div>
            <span class="badge bg-secondary">${applicant.status}</span>
          </div>
        </div>

        <div class="mb-1">
          <em>Opportunity:</em> ${applicant.opportunity_name}
        </div>
        <div class="mb-1">
          <em>Skills:</em> ${applicant.skills || '—'}
        </div>

        <div>
          ${buttonsHTML}
        </div>
      `;

      list.appendChild(listItem);
    });
  })
  .catch(err => {
    console.error("Error fetching applicants:", err);
    document.getElementById("applicantsList").innerHTML =
      "<li class='list-group-item text-danger'>Failed to load applicants.</li>";
  });
}

  
  function updateStatus(applicationId, status) {
    fetch(`api/applications/${applicationId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ status })  // now 'Accepted' or 'Rejected'
    })
    .then(res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then(data => {
      alert(data.message || `Application ${status} successfully.`);
      // reload the list so that the button disappears
      loadApplicants(localStorage.getItem('ngo_id'));
    })
    .catch(err => {
      console.error('Error updating status:', err);
      alert('Could not update status. Check console for details.');
    });
  }
  

document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("Please login first.");
        window.location.href = "login.html";
        return;
    }

    try {
        const ngoId = localStorage.getItem("ngo_id");

        if (!ngoId) {
            console.error("NGO ID not found in localStorage");
            return;
        }

        loadApplicants(ngoId);
    } catch (err) {
        console.error("Error decoding token or extracting NGO ID:", err);
        alert("Session expired or invalid. Please log in again.");
        localStorage.removeItem("token");
        window.location.href = "login.html";
    }
});