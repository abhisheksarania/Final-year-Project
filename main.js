document.addEventListener('DOMContentLoaded', function() {
    // File upload handling for scanning
    const scanForm = document.getElementById('scan-form');
    const scanFileInput = document.getElementById('scan-file-input');
    const scanFileLabel = document.getElementById('scan-file-label');
    const scanProgressContainer = document.getElementById('scan-progress-container');
    const scanProgressBar = document.getElementById('scan-progress-bar');
    const scanStatusText = document.getElementById('scan-status-text');
    const scanResults = document.getElementById('scan-results');
    
    // Update file label when a file is selected for scanning
    if (scanFileInput) {
        scanFileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const fileName = this.files[0].name;
                scanFileLabel.textContent = fileName;
                scanFileLabel.classList.add('file-selected');
            } else {
                scanFileLabel.textContent = 'Choose file';
                scanFileLabel.classList.remove('file-selected');
            }
        });
    }
    
    // Handle form submission for scanning
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!scanFileInput.files || !scanFileInput.files[0]) {
                showAlert('Please select a file to scan', 'danger');
                return;
            }
            
            // Show progress
            scanProgressContainer.classList.remove('d-none');
            scanProgressBar.style.width = '10%';
            scanProgressBar.setAttribute('aria-valuenow', 10);
            scanStatusText.textContent = 'Analyzing file...';
            
            // Create form data
            const formData = new FormData();
            formData.append('file', scanFileInput.files[0]);
            
            // Send request to server
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                // Update progress
                scanProgressBar.style.width = '50%';
                scanProgressBar.setAttribute('aria-valuenow', 50);
                scanStatusText.textContent = 'Processing results...';
                
                return response.json();
            })
            .then(data => {
                // Update progress to complete
                scanProgressBar.style.width = '100%';
                scanProgressBar.setAttribute('aria-valuenow', 100);
                
                if (data.error) {
                    // Show error message
                    scanStatusText.textContent = 'Scan failed';
                    scanProgressBar.classList.remove('bg-primary', 'bg-success');
                    scanProgressBar.classList.add('bg-danger');
                    showAlert(data.error, 'danger');
                } else {
                    // Show success message
                    scanStatusText.textContent = 'Scan complete';
                    scanProgressBar.classList.remove('bg-primary', 'bg-danger');
                    scanProgressBar.classList.add('bg-success');
                    
                    // Display scan results
                    scanResults.classList.remove('d-none');
                    
                    const resultHtml = `
                        <div class="card ${data.is_ransomware ? 'bg-danger' : 'bg-success'}">
                            <div class="card-body">
                                <h5 class="card-title">Scan Results for ${data.filename}</h5>
                                <p class="card-text">
                                    <strong>Detection:</strong> ${data.is_ransomware ? 'Ransomware Detected' : 'Clean File'}<br>
                                    <strong>Confidence:</strong> ${(data.confidence * 100).toFixed(2)}%
                                </p>
                                ${data.is_ransomware || data.encryption_detected ? 
                                    `<div class="mt-3">
                                        <a href="/report/${data.scan_id}" class="btn btn-light me-2">View Full Report</a>
                                        <a href="/decrypt?scan_id=${data.scan_id}" class="btn btn-warning">
                                            <i class="fas fa-key"></i> Attempt Decryption
                                        </a>
                                    </div>` : 
                                    `<div class="mt-3">
                                        <a href="/report/${data.scan_id}" class="btn btn-light">View Full Report</a>
                                    </div>`
                                }
                            </div>
                        </div>
                    `;
                    
                    scanResults.innerHTML = resultHtml;
                    
                    // Also show an alert
                    if (data.is_ransomware) {
                        showAlert(`Warning: Ransomware detected in file "${data.filename}" with ${(data.confidence * 100).toFixed(2)}% confidence.`, 'danger');
                    } else {
                        showAlert(`File "${data.filename}" is clean with ${(data.confidence * 100).toFixed(2)}% confidence.`, 'success');
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                scanStatusText.textContent = 'Error during scan';
                scanProgressBar.classList.remove('bg-primary', 'bg-success');
                scanProgressBar.classList.add('bg-danger');
                showAlert('An error occurred during scan. Please try again.', 'danger');
            });
        });
    }
    
    // Function to show alerts
    function showAlert(message, type) {
        const alertContainer = document.getElementById('alert-container');
        if (alertContainer) {
            const alert = document.createElement('div');
            alert.className = `alert alert-${type} alert-dismissible fade show`;
            alert.role = 'alert';
            alert.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            
            alertContainer.appendChild(alert);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 300);
            }, 5000);
        }
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
