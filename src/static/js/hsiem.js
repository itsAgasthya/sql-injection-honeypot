// Initialize Bootstrap components
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all tooltips
    var tooltips = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltips.map(function (tooltip) {
        return new bootstrap.Tooltip(tooltip)
    });

    // Initial data load
    refreshEvents();
    refreshSystemStatus();
    refreshVulnerabilityAssessment();
});

// Refresh events table
function refreshEvents() {
    fetch('/api/hsiem/events')
        .then(response => response.json())
        .then(data => {
            updateEventsTable(data.events);
            updateStats(data.stats);
        })
        .catch(error => console.error('Error fetching events:', error));
}

// Refresh system status
function refreshSystemStatus() {
    fetch('/api/hsiem/system')
        .then(response => response.json())
        .then(data => {
            updateSystemStatus(data);
        })
        .catch(error => console.error('Error fetching system status:', error));
}

// Refresh vulnerability assessment
function refreshVulnerabilityAssessment() {
    fetch('/api/hsiem/assessment')
        .then(response => response.json())
        .then(data => {
            updateVulnerabilityAssessment(data);
        })
        .catch(error => console.error('Error fetching vulnerability assessment:', error));
}

// Show event details in modal
function showDetails(eventId) {
    fetch(`/api/hsiem/events/${eventId}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('event-details').textContent = 
                JSON.stringify(data, null, 2);
            new bootstrap.Modal(document.getElementById('eventModal')).show();
        })
        .catch(error => console.error('Error fetching event details:', error));
}

// Update events table with new data
function updateEventsTable(events) {
    const tbody = document.getElementById('events-table');
    tbody.innerHTML = '';
    
    events.forEach(event => {
        const row = document.createElement('tr');
        row.className = `severity-${event.severity.toLowerCase()}`;
        
        row.innerHTML = `
            <td>${event.timestamp}</td>
            <td>${event.type}</td>
            <td>${event.source_ip}</td>
            <td>${event.risk_score.toFixed(2)}</td>
            <td><span class="badge bg-${event.severity.toLowerCase()}">${event.severity}</span></td>
            <td>
                <button class="btn btn-sm btn-info" onclick="showDetails('${event.id}')">
                    View
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Update statistics cards
function updateStats(stats) {
    document.querySelector('.bg-danger .card-text').textContent = stats.critical;
    document.querySelector('.bg-warning .card-text').textContent = stats.high;
    document.querySelector('.bg-info .card-text').textContent = stats.medium;
    document.querySelector('.bg-success .card-text').textContent = stats.low;
}

// Update system status panel
function updateSystemStatus(data) {
    const statusDiv = document.getElementById('system-status');
    let html = '<ul class="list-group">';
    
    // Process Information
    html += '<li class="list-group-item">';
    html += '<h6 class="mb-2">Processes</h6>';
    html += `<span class="badge bg-primary">${data.processes.length} Running</span>`;
    html += '</li>';
    
    // Network Information
    html += '<li class="list-group-item">';
    html += '<h6 class="mb-2">Network Connections</h6>';
    html += `<span class="badge bg-info">${data.network_connections.length} Active</span>`;
    html += '</li>';
    
    // Digital Signatures
    if (data.digital_signatures) {
        const validSigs = data.digital_signatures.filter(sig => sig.signature_valid).length;
        html += '<li class="list-group-item">';
        html += '<h6 class="mb-2">Digital Signatures</h6>';
        html += `<span class="badge bg-success">${validSigs} Valid</span> `;
        html += `<span class="badge bg-danger">${data.digital_signatures.length - validSigs} Invalid</span>`;
        html += '</li>';
    }
    
    // Registry Information (Windows)
    if (data.registry && data.registry.StartupItems) {
        html += '<li class="list-group-item">';
        html += '<h6 class="mb-2">Registry Startup Items</h6>';
        html += `<span class="badge bg-warning">${Object.keys(data.registry.StartupItems).length} Items</span>`;
        html += '</li>';
    }
    
    html += '</ul>';
    statusDiv.innerHTML = html;
}

// Update vulnerability assessment panel
function updateVulnerabilityAssessment(data) {
    const assessmentDiv = document.getElementById('vulnerability-assessment');
    let html = '';
    
    // Risk Score
    html += `<div class="alert alert-${getSeverityClass(data.severity)}">`;
    html += `<h4 class="alert-heading">Risk Score: ${data.risk_score.toFixed(2)}</h4>`;
    html += `<p>Severity Level: ${data.severity}</p>`;
    html += '</div>';
    
    // Details
    html += '<ul class="list-group">';
    
    // Suspicious Processes
    if (data.details.suspicious_processes && data.details.suspicious_processes.length > 0) {
        html += '<li class="list-group-item list-group-item-danger">';
        html += `<strong>Suspicious Processes:</strong> ${data.details.suspicious_processes.length}`;
        html += '</li>';
    }
    
    // Network Issues
    if (data.details.open_ports && data.details.open_ports.length > 0) {
        html += '<li class="list-group-item list-group-item-warning">';
        html += `<strong>Open Ports:</strong> ${data.details.open_ports.length}`;
        html += '</li>';
    }
    
    // Failed Signatures
    if (data.details.failed_digital_signatures && data.details.failed_digital_signatures.length > 0) {
        html += '<li class="list-group-item list-group-item-danger">';
        html += `<strong>Failed Signatures:</strong> ${data.details.failed_digital_signatures.length}`;
        html += '</li>';
    }
    
    // Registry Issues
    if (data.details.unknown_startup_items && Object.keys(data.details.unknown_startup_items).length > 0) {
        html += '<li class="list-group-item list-group-item-warning">';
        html += `<strong>Unknown Startup Items:</strong> ${Object.keys(data.details.unknown_startup_items).length}`;
        html += '</li>';
    }
    
    html += '</ul>';
    
    // Last Updated
    html += `<div class="text-muted mt-2">Last updated: ${new Date(data.timestamp).toLocaleString()}</div>`;
    
    assessmentDiv.innerHTML = html;
}

// Helper function to get Bootstrap severity class
function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'danger';
        case 'high':
            return 'warning';
        case 'medium':
            return 'info';
        case 'low':
            return 'success';
        default:
            return 'secondary';
    }
}

// Auto-refresh data every 30 seconds
setInterval(() => {
    refreshEvents();
    refreshSystemStatus();
    refreshVulnerabilityAssessment();
}, 30000); 