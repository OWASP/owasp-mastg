$(function() {
  var table;

  // 1) When your DataTable is created, keep a reference and push our custom filter:
  document$.subscribe(function() {
    table = $('#table_tests table').DataTable({
      paging: false,           // no pagination
      order: [8, 'asc'],               // no initial sort
      columnDefs: [
      {
        targets: 0,          // index of the first column
        visible: false       // hide it
      }
    ],
    rowGroup: {
        dataSrc: 8
    },
      layout: {
        topStart: ['buttons','search'],
        topEnd:   null,
        bottomStart: 'info',
        bottomEnd:   'paging'
      },
    });

    // 2) Custom search: consider both toggles
    $.fn.dataTable.ext.search.push(function(settings, rowData) {

      // if it's deprecated and we don't want to show those, return false
      var status = (rowData[7] || '').toLowerCase();
      console.log(status)
      console.log($('#tests-btn-deprecated').hasClass('active'))
      if(! $('#tests-btn-deprecated').hasClass('active')){
        if (status.indexOf("pending") !== -1 || status.indexOf("deprecated") !== -1 ){
          return false
        }
      }


      // Grab the OS‐column text and normalize
      var osText = (rowData[2] || '').toLowerCase();

      // Which toggles are active?
      var androidActive = $('#tests-btn-android').hasClass('active');
      var iosActive     = $('#tests-btn-ios').hasClass('active');

      // If neither is active, show everything
      if (!androidActive && !iosActive) {
        return true;
      }

      // Build list of required substrings
      var required = [];
      if (androidActive) required.push('android');
      if (iosActive)     required.push('ios');

      // Only include row if any required terms are present
      return required.some(function(term) {
        return osText.indexOf(term) !== -1;
      });
    });
  });

 // 3) Wire up BOTH toggle buttons: Android & iOS
  $('#tests-btn-android, #tests-btn-ios, #tests-btn-deprecated').on('click', function() {
    $(this).toggleClass('active');
    $(this).blur()
    if (table) {
      table.draw();  // re-draw applies the filter
    }
  });



  function applyGroupClasses() {
    $('#table_tests table')
      .find('tr.dtrg-group th')
      .each(function(){
        const txt  = $(this).text().trim();
        // turn “No group” → “no-group”, “Group 123” → “group-123”, etc.
        const slug = txt.toLowerCase()
        // add class to the <tr> and/or the <th>
        const cls = 'table-hr-' + slug;
        $(this).addClass(cls);
        $(this).closest('tr.dtrg-group').addClass(cls);
      });
  }
  table.on('draw', applyGroupClasses);
  // initial pass
  applyGroupClasses();
});
