
document.addEventListener("DOMContentLoaded", () => {
    const menuToggle = document.getElementById("menuToggle");
    const navLinks = document.getElementById("navLinks");
    const year = document.getElementById("year");

    if (year) {
        year.textContent = new Date().getFullYear();
    }

    if (menuToggle && navLinks) {
        menuToggle.addEventListener("click", () => {
            const isOpen = navLinks.classList.toggle("open");

            menuToggle.setAttribute("aria-expanded", String(isOpen));
            menuToggle.textContent = isOpen ? "✕" : "☰";
        });

        navLinks.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => {
                navLinks.classList.remove("open");
                menuToggle.setAttribute("aria-expanded", "false");
                menuToggle.textContent = "☰";
            });
        });
    }
});
