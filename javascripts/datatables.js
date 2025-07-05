
document$.subscribe(function() {
    // Add DataTable to all tables, but not the advanced tests table
    $('table').not("#table_tests table").DataTable({
        paging: false, // Disable pagination
        order: [], // Disable auto-sorting
        dom: '<"top"if>rt<"bottom"lp><"clear">'
    });
});