// Log management functions
function copyLogs() {
    const logs = document.querySelector('.log-content').innerText;
    navigator.clipboard.writeText(logs)
        .then(() => showAlert('success', 'Logs đã được sao chép vào clipboard!'))
        .catch(err => showAlert('danger', 'Lỗi khi sao chép logs: ' + err));
}

function downloadLogs() {
    const logs = document.querySelector('.log-content').innerText;
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ids_logs.txt';
    a.click();
    window.URL.revokeObjectURL(url);
}

function clearLogs() {
    if (confirm('Bạn có chắc chắn muốn xóa tất cả logs?')) {
        const clearBtn = document.querySelector('#clearLogsBtn');
        const originalText = clearBtn.innerHTML;
        clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang xóa...';
        clearBtn.disabled = true;

        fetch('/clear_logs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                document.querySelector('.log-content').innerHTML = '';
                showAlert('success', 'Logs đã được xóa thành công!');
                
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                throw new Error(data.message || 'Không thể xóa logs');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert('danger', `Lỗi: ${error.message}`);
        })
        .finally(() => {
            clearBtn.innerHTML = originalText;
            clearBtn.disabled = false;
        });
    }
}

function showAlert(type, message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const container = document.querySelector('.dashboard-card');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}

// Initialize event listeners when document is ready
document.addEventListener('DOMContentLoaded', () => {
    // Add any initialization code here if needed
});