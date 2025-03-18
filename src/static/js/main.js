// Add CSRF token to all AJAX requests
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Show loading spinner
function showLoading() {
    const spinner = document.createElement('div');
    spinner.className = 'spinner-border text-primary';
    spinner.setAttribute('role', 'status');
    spinner.innerHTML = '<span class="visually-hidden">Loading...</span>';
    document.body.appendChild(spinner);
}

// Hide loading spinner
function hideLoading() {
    const spinner = document.querySelector('.spinner-border');
    if (spinner) {
        spinner.remove();
    }
}

// Handle form submission errors
function handleFormError(form, error) {
    const errorDiv = form.querySelector('.alert-danger') || document.createElement('div');
    errorDiv.className = 'alert alert-danger';
    errorDiv.textContent = error.message || 'An error occurred. Please try again.';
    if (!form.querySelector('.alert-danger')) {
        form.insertBefore(errorDiv, form.firstChild);
    }
} 