document.getElementById('start-btn').addEventListener('click', function () {
    fetch('/start_ids', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        const statusDiv = document.getElementById('status');
        if (data.status === "started") {
            statusDiv.className = 'alert alert-success';
            statusDiv.textContent = 'IDS started successfully!';
        } else if (data.status === "already_running") {
            statusDiv.className = 'alert alert-warning';
            statusDiv.textContent = 'IDS is already running.';
        } else {
            statusDiv.className = 'alert alert-danger';
            statusDiv.textContent = `Error: ${data.message || 'Failed to start IDS.'}`;
        }
    })
    .catch(error => {
        const statusDiv = document.getElementById('status');
        statusDiv.className = 'alert alert-danger';
        statusDiv.textContent = 'An error occurred while starting IDS.';
    });
});

document.getElementById('stop-btn').addEventListener('click', function () {
    fetch('/stop_ids', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        const statusDiv = document.getElementById('status');
        if (data.status === "stopped") {
            statusDiv.className = 'alert alert-success';
            statusDiv.textContent = 'IDS stopped successfully!';
        } else {
            statusDiv.className = 'alert alert-warning';
            statusDiv.textContent = 'IDS is not running.';
        }
    })
    .catch(error => {
        const statusDiv = document.getElementById('status');
        statusDiv.className = 'alert alert-danger';
        statusDiv.textContent = 'An error occurred while stopping IDS.';
    });
});
