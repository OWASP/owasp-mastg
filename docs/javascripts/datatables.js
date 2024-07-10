document$.subscribe(function() {
    $('table').DataTable({
        paging: false, // Disable pagination
        order: [], // Disable auto-sorting
        dom: '<"top"if>rt<"bottom"lp><"clear">' // Custom layout with entries info on top
    });
});
