function validateEmail() {
    const emailField = document.getElementById('email');
    const emailError = document.getElementById('emailError');
    const collegeDomainPattern = /^[a-zA-Z0-9._%+-]+@gcoej\.ac\.in$/;

    if (!collegeDomainPattern.test(emailField.value)) {
        emailError.textContent = 'Please enter a valid GCOEJ email address (e.g., yourrollno@gcoej.ac.in).';
        return false;
    } else {
        emailError.textContent = ''; // Clear any previous error message
    }

    return validatePassword();
}

function validatePassword() {
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm_password');
    const passwordError = document.getElementById('passwordError');

    if (passwordField.value !== confirmPasswordField.value) {
        passwordError.textContent = 'Passwords do not match.';
        return false;
    } else {
        passwordError.textContent = ''; // Clear any previous error message
    }

    return true;
}
