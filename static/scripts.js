document.addEventListener('DOMContentLoaded', function() {
    const toggleInput = document.getElementById('darkModeToggle');
    const prefersDark = localStorage.getItem('dark-mode') === 'true';

    if (prefersDark) {
        document.body.classList.add('dark-mode');
        toggleInput.checked = true;
    }

    if (toggleInput) {
        toggleInput.addEventListener('change', function() {
            const isDark = toggleInput.checked;
            document.body.classList.toggle('dark-mode', isDark);
            localStorage.setItem('dark-mode', isDark);
        });
    }
});
