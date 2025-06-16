document$.subscribe(function(){
    
    $('.md-tag').each(function() {
    const href = $(this).attr('href');
    if (href && href.includes('/tags')) {
      $(this).on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
      }).css({
        'pointer-events': 'none',
        'cursor': 'default',
        'text-decoration': 'none'
      });
    }
  });
});