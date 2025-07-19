document$.subscribe(() => {
    const elements = document.querySelectorAll('.md-nav__link, .md-tag');

    for (const element of elements) {
        const html = element.innerHTML.trim();
        const match = html.match(/MASVS-(NETWORK|STORAGE|CRYPTO|AUTH|PLATFORM|CODE|RESILIENCE|PRIVACY)(-\d)?/);
        if (!match) continue;

        let key = match[0].replace(/-\d$/, "");
        let slug = key.toLowerCase(); // masvs-network
        let baseClass = `masvs-${slug.split('-')[1]}`;

        if (element.classList.contains("md-tag")) {
            element.classList.add(`md-tag--${baseClass}`);
        } else {
            element.classList.add("masvs-link", `masvs-link--${baseClass}`);
        }

        if (html.includes("MSTG-")) {
            element.style.color = "#aaaaaa";
            element.title = "This ID is deprecated. Please use the MASVS v2 IDs instead.";
        }
    }
});
