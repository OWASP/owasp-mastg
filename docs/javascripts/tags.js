document$.subscribe(function() {
  $('.md-tag').each(function() {
    const $tag = $(this);
    const href = $tag.attr('href');

    // Disable clicking if it links to /tags
    if (href && href.includes('/tags')) {
      $tag.on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
      }).css({
        'pointer-events': 'none',
        'cursor': 'default',
        'text-decoration': 'none'
      });
    }

    // Add class if it has any class starting with "md-tag--"
    const hasTagClass = [...this.classList].some(cls => cls.startsWith('md-tag--'));
    if (!hasTagClass) {
      $tag.addClass('md-tag-inactive');
    }
  });
});