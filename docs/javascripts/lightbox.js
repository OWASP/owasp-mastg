function updateImageClasses() {

  const isMobile = window.matchMedia("(max-width: 768px)").matches;
  document.querySelectorAll("a.glightbox, a.no-click-image").forEach(function (el) {
      if (isMobile) {
        el.classList.remove("glightbox");
        el.classList.add("no-click-image");
      } else {
        el.classList.add("glightbox");
        el.classList.remove("no-click-image");
      }
    });

  if(lightbox){
    lightbox.destroy()
    lightbox.reload()
  }

  const allLightboxTriggers = document.querySelectorAll('.glightbox')
  if (allLightboxTriggers) {
    allLightboxTriggers.forEach(function(trigger) {
      trigger.addEventListener('click', function(e) {
        const isMobile = window.matchMedia("(max-width: 768px)").matches
        console.log("clicky", isMobile)
        e.preventDefault()
        let targetHref = this.getAttribute('href')
        if(isMobile) {
          e.stopPropagation()
          return true;
        }
        lightbox.setElements([{'href': targetHref}])
        lightbox.open()
      })
    })
  }
}

// On MkDocs page load
document$.subscribe(() => {
  updateImageClasses();
});

// On window resize
$(window).on("resize", updateImageClasses);
