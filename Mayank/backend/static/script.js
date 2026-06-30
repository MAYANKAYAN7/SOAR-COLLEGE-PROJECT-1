// ==============================
// SOAR Dashboard Script
// ==============================

// Load everything when page opens
window.onload = function () {

    loadDashboard();
    loadHealth();
    loadCases();
    loadTimeline(1);

};

// ==============================
// Dashboard
// ==============================

async function loadDashboard() {

    try {

        const response = await fetch("/dashboard");
        const data = await response.json();

        document.getElementById("totalAlerts").innerText =
            data.total_alerts;

        document.getElementById("criticalAlerts").innerText =
            data.critical_alerts;

        document.getElementById("openCases").innerText =
            data.open_cases;

        document.getElementById("resolvedCases").innerText =
            data.resolved_cases;

        document.getElementById("playbooksExecuted").innerText =
            data.playbooks_executed;

    }

    catch (error) {

        console.error("Dashboard Error:", error);

    }

}

// ==============================
// Health Status
// ==============================

async function loadHealth() {

    try {

        const response = await fetch("/health");
        const data = await response.json();

        document.getElementById("systemStatus").innerText =
            data.status;

        document.getElementById("healthStatus").innerText =
            data.status;

    }

    catch (error) {

        console.error("Health Error:", error);

    }

}

// ==============================
// Cases
// ==============================

async function loadCases() {

    try {

        const response = await fetch("/cases");

        const data = await response.json();

        let table = document.getElementById("caseTable");

        table.innerHTML = "";

        data.forEach(function (c) {

            table.innerHTML += `

            <tr>

                <td>${c.case_id}</td>

                <td>${c.title}</td>

                <td>${c.severity}</td>

                <td>${c.assigned_to}</td>

                <td>${c.status}</td>

            </tr>

            `;

        });

    }

    catch (error) {

        console.error("Cases Error:", error);

    }

}

// ==============================
// Timeline
// ==============================

async function loadTimeline(caseId) {

    try {

        const response = await fetch(`/timeline/${caseId}`);

        const data = await response.json();

        let timeline = document.getElementById("timeline");

        timeline.innerHTML = "";

        data.timeline.forEach(function (event) {

            timeline.innerHTML += `

            <li>

                ${event.timestamp} - ${event.action}

            </li>

            `;

        });

    }

    catch (error) {

        console.error("Timeline Error:", error);

    }

}

// ==============================
// Submit Alert
// ==============================

document.getElementById("alertForm").addEventListener("submit", async function (e) {

    e.preventDefault();

    const alertData = {

        source_ip: document.getElementById("source_ip").value,

        alert_type: document.getElementById("alert_type").value,

        timestamp: new Date().toISOString()

    };

    try {

        const response = await fetch("/alert", {

            method: "POST",

            headers: {

                "Content-Type": "application/json"

            },

            body: JSON.stringify(alertData)

        });

        const result = await response.json();

        alert("Alert submitted successfully!");

        console.log(result);

        document.getElementById("alertForm").reset();

        loadDashboard();

        loadCases();

        loadTimeline(1);

    }

    catch (error) {

        console.error("Alert Submission Error:", error);

    }

});