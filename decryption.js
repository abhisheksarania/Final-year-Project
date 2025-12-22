document.addEventListener('DOMContentLoaded', function() {
    // File upload handling for decryption
    const decryptionForm = document.getElementById('decryption-form');
    const fileInput = document.getElementById('file-input');
    const fileLabel = document.getElementById('file-label');
    const batchFileInput = document.getElementById('batch-file-input');
    const batchFileLabel = document.getElementById('batch-file-label');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const statusText = document.getElementById('status-text');
    const decryptionResults = document.getElementById('decryption-results');
    
    // Mode selection handling
    const singleFileMode = document.getElementById('single-file-mode');
    const batchMode = document.getElementById('batch-mode');
    const singleFileContainer = document.getElementById('single-file-container');
    const batchModeContainer = document.getElementById('batch-mode-container');
    
    // Handle decryption mode change
    if (singleFileMode && batchMode) {
        singleFileMode.addEventListener('change', function() {
            if (this.checked) {
                singleFileContainer.classList.remove('opacity-50');
                batchModeContainer.classList.add('opacity-50');
                batchFileInput.disabled = true;
                fileInput.disabled = false;
            }
        });
        
        batchMode.addEventListener('change', function() {
            if (this.checked) {
                // Batch mode is coming soon, so show a message
                showAlert('Batch mode is coming soon. Please use single file mode for now.', 'info');
                singleFileMode.checked = true;
                batchMode.checked = false;
            }
        });
    }
    
    // Update file label when a file is selected
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const fileName = this.files[0].name;
                fileLabel.innerHTML = `<i class="fas fa-file"></i> ${fileName}`;
                fileLabel.classList.add('file-selected');
                
                // Show estimated decryption time based on file size
                const fileSize = this.files[0].size;
                const estimatedTime = Math.max(5, Math.round(fileSize / (1024 * 1024) * 2)); // Rough estimate: 2 seconds per MB
                statusText.textContent = `Estimated processing time: ~${estimatedTime} seconds`;
                statusText.classList.remove('d-none');
            } else {
                fileLabel.innerHTML = '<i class="fas fa-file-upload"></i> Choose encrypted file';
                fileLabel.classList.remove('file-selected');
                statusText.classList.add('d-none');
            }
        });
    }
    
    // Handle form submission for decryption
    if (decryptionForm) {
        decryptionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!fileInput.files || !fileInput.files[0]) {
                showAlert('Please select a file to decrypt', 'danger');
                return;
            }
            
            // Show progress
            progressContainer.classList.remove('d-none');
            progressBar.style.width = '10%';
            progressBar.setAttribute('aria-valuenow', 10);
            statusText.textContent = 'Analyzing encryption...';
            
            // Create form data
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            // Add scan ID if available
            const scanIdField = document.getElementById('scan-id');
            if (scanIdField && scanIdField.value) {
                formData.append('scan_id', scanIdField.value);
            }
            
            // Add processing priority
            const processingPriority = document.getElementById('processing-priority');
            if (processingPriority && processingPriority.value) {
                formData.append('processing_priority', processingPriority.value);
                
                // Update status text with processing mode
                let priorityText = "";
                if (processingPriority.value === 'thorough') {
                    priorityText = " (Thorough mode - may take longer)";
                } else if (processingPriority.value === 'fast') {
                    priorityText = " (Fast mode - reduced accuracy)";
                }
                statusText.textContent += priorityText;
            }
            
            // Initialize decryption stages
            const decryptionStages = [
                { percent: 10, text: 'Analyzing file structure...' },
                { percent: 20, text: 'Detecting encryption type...' },
                { percent: 30, text: 'Developing AI decryption strategy...' },
                { percent: 40, text: 'Attempting key extraction...' },
                { percent: 60, text: 'Applying decryption algorithms...' },
                { percent: 80, text: 'Validating decrypted content...' },
                { percent: 95, text: 'Finalizing results...' }
            ];
            
            // Track current stage
            let currentStage = 0;
            
            // Function to update progress animation
            function updateProgressStage() {
                if (currentStage < decryptionStages.length) {
                    const stage = decryptionStages[currentStage];
                    progressBar.style.width = stage.percent + '%';
                    progressBar.setAttribute('aria-valuenow', stage.percent);
                    statusText.textContent = stage.text;
                    currentStage++;
                    
                    // Schedule next stage update (simulate real-time progress)
                    if (currentStage < decryptionStages.length) {
                        setTimeout(updateProgressStage, 1200); // Time between stages
                    }
                }
            }
            
            // Start progress animation immediately
            updateProgressStage();
            
            // Send request to server
            fetch('/decrypt', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                return response.json();
            })
            .then(data => {
                // Update progress to complete
                progressBar.style.width = '100%';
                progressBar.setAttribute('aria-valuenow', 100);
                
                if (data.error) {
                    // Show error message
                    statusText.textContent = 'Decryption failed';
                    progressBar.classList.remove('bg-primary', 'bg-success');
                    progressBar.classList.add('bg-danger');
                    showAlert(data.error, 'danger');
                } else {
                    // Show success message and redirect
                    statusText.textContent = 'Decryption complete';
                    progressBar.classList.remove('bg-primary', 'bg-danger');
                    progressBar.classList.add('bg-success');
                    
                    // Show detailed results before redirect
                    decryptionResults.classList.remove('d-none');
                    
                    // Set the message based on success level
                    let message = 'Decryption completed successfully!';
                    let resultClass = 'success';
                    
                    if (data.success_level === 'partial') {
                        message = 'Partial decryption achieved. Some file content was recovered.';
                        resultClass = 'warning';
                    } else if (data.success_level === 'failed') {
                        message = 'Decryption attempt completed but was unsuccessful.';
                        resultClass = 'danger';
                    }
                    
                    // Display detailed decryption results
                    decryptionResults.innerHTML = `
                        <div class="alert alert-${data.success_level === 'failed' ? 'warning' : 'success'}">
                            <h5><i class="fas fa-${data.success_level === 'full' ? 'check-circle' : data.success_level === 'partial' ? 'exclamation-triangle' : 'times-circle'}"></i> ${message}</h5>
                            <div class="d-flex justify-content-between align-items-center mt-3">
                                <div>
                                    <span class="badge bg-${resultClass}">
                                        ${data.success_level === 'full' ? 'Successfully Decrypted' : 
                                          data.success_level === 'partial' ? 'Partially Decrypted' : 
                                          'Decryption Failed'}
                                    </span>
                                </div>
                                <button class="btn btn-primary btn-sm" id="view-report-btn">
                                    <i class="fas fa-chart-bar"></i> View Full Report
                                </button>
                            </div>
                        </div>
                    `;
                    
                    // Add event listener to the report button
                    document.getElementById('view-report-btn').addEventListener('click', function() {
                        window.location.href = '/decryption_report/' + data.decryption_id;
                    });
                    
                    showAlert(message, data.success_level === 'failed' ? 'warning' : 'success');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                statusText.textContent = 'Error during decryption';
                progressBar.classList.remove('bg-primary', 'bg-success');
                progressBar.classList.add('bg-danger');
                showAlert('An error occurred during decryption. Please try again.', 'danger');
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
    
    // Initialize tooltip for the decryption process explanation
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
