document$.subscribe(function() {
    $('table').DataTable({
        paging: false,
        dom: '<"top"if>rt<"bottom"lp><"clear">'
    });
});
