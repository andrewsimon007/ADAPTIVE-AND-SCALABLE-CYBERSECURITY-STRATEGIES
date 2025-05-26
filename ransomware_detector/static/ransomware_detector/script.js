function startMonitoring() {
    const statusElement = document.getElementById("status");
    statusElement.textContent = "Scanning...";
    statusElement.style.color = "yellow";

    setTimeout(() => {
        statusElement.textContent = "Threat Detected!";
        statusElement.style.color = "red";

        setTimeout(() => {
            statusElement.textContent = "Mitigating...";
            statusElement.style.color = "orange";

            setTimeout(() => {
                statusElement.textContent = "Secure";
                statusElement.style.color = "green";
            }, 2000);
        }, 2000);
    }, 2000);
}
let monitoring = false;
let interval;

function startMonitoring() {
    const button = document.querySelector("button");
    
    if (!monitoring) {
        monitoring = true;
        button.textContent = "Stop Monitoring";

        // Send request to Django to start monitoring
        fetch('/start_monitoring/', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.status === "started") {
                    document.getElementById("status").textContent = "Monitoring...";
                }
            });

        
        interval = setInterval(updateMonitoringStatus, 3000);
    } else {
        monitoring = false;
        button.textContent = "Start Monitoring";

        
        fetch('/stop_monitoring/', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.status === "stopped") {
                    document.getElementById("status").textContent = "Idle";
                }
            });

        clearInterval(interval);
    }
}

function updateMonitoringStatus() {
    fetch('/get_monitoring_status/')
        .then(response => response.json())
        .then(data => {
            document.getElementById("status").textContent = data.status;
        });
}
