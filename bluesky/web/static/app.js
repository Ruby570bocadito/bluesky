/**
 * Bluesky Web Dashboard - JavaScript
 */

document.addEventListener('DOMContentLoaded', function () {
    // Auto-refresh uptime display
    setInterval(updateUptime, 60000);
});

function updateUptime() {
    const el = document.getElementById('uptime-display');
    if (el) {
        fetch('/api/status')
            .then(r => r.json())
            .then(data => {
                el.innerHTML = `<i class="bi bi-clock"></i> ${data.uptime}`;
            })
            .catch(() => {});
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999;';
        document.body.appendChild(container);
    }

    const colors = {
        info: 'bg-primary',
        success: 'bg-success',
        error: 'bg-danger',
        warning: 'bg-warning text-dark',
    };

    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white ${colors[type] || colors.info} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>`;

    document.getElementById('toastContainer').appendChild(toast);

    const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copiado al portapapeles', 'success');
    }).catch(() => {
        // Fallback
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        showToast('Copiado al portapapeles', 'success');
    });
}

function viewResult(result) {
    const modal = document.getElementById('resultModal');
    if (!modal) return;

    const pre = document.getElementById('resultJson');
    pre.textContent = JSON.stringify(result, null, 2);

    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}
