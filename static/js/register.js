if (registerBtn) {
    registerBtn.addEventListener("click", () => {
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;

        if (!email || !password) {
            alert("Please enter your email and password");
            return;
        }

        registerUser(email, password);
    });
}
