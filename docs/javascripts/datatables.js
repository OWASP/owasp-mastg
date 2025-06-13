$(function () {
  var table;

  // 1) When your DataTable is created, keep a reference and push our custom filter:
  document$.subscribe(function () {
    table = $('#table_tests table').DataTable({
      info: false,
      paging: false,           // no pagination
      order: [8, 'asc'],               // no initial sort
      columnDefs: [
        {
          targets: [0, 8],          // index of the first column
          visible: false       // hide it
        },
        {
          targets: "_all",
          orderable: false
        }
      ],
      rowGroup: {
        dataSrc: 8
      },
      layout: {
        topStart: ['buttons'],
        topEnd: ['buttons'],
        bottomStart: 'info',
        bottomEnd: 'paging'
      },
      initComplete: function () {
        // $(this.api().table().header()).hide();
        // this.api().draw();
      }
    });
    $.fn.dataTable.ext.search.push(function (settings, rowData) {
      // 1) deprecated toggle
      var status = (rowData[7] || '').toLowerCase();
      var showDeprecated = $('#tests-btn-deprecated').hasClass('active');
      if (!showDeprecated && /pending|deprecated/.test(status)) {
        return false;
      }

      // 2) OS toggles
      var osText = (rowData[2] || '').toLowerCase();
      var osFilters = [
        { btn: '#tests-btn-android', keyword: 'android' },
        { btn: '#tests-btn-ios', keyword: 'ios' }
      ];
      var activeOs = osFilters.filter(f => $(f.btn).hasClass('active'));
      // if exactly one OS is active, require its keyword in the cell
      if (activeOs.length === 1 && osText.indexOf(activeOs[0].keyword) === -1) {
        return false;
      }
      // (0 or 2 active → no OS filtering)

      // 3) Level toggles
      var levelFilters = [
        { btn: '#tests-btn-l1', keyword: 'l1', column: 3 },
        { btn: '#tests-btn-l2', keyword: 'l2' , column: 4},
        { btn: '#tests-btn-lr', keyword: 'r' , column: 5}
      ];
      var activeLevels = levelFilters.filter(f => $(f.btn).hasClass('active'));
      // if 1 or 2 active (but not all 3), require at least one match
      if (activeLevels.length > 0 && activeLevels.length < levelFilters.length) {
        var anyMatch = activeLevels.some(f => rowData[f.column].toLowerCase().indexOf(f.keyword) !== -1);
        if (!anyMatch) {
          return false;
        }
      }
      // (0 or 3 active → no level filtering)

      return true;
    });

  });

  table.draw();

  // 3) Wire up BOTH toggle buttons: Android & iOS
  $('#tests-btn-android, #tests-btn-ios, #tests-btn-deprecated, #tests-btn-l1, #tests-btn-l2, #tests-btn-lr').on('click', function () {
    $(this).toggleClass('active');
    $(this).blur()
    if (table) {
      table.draw();  // re-draw applies the filter
    }
  });



  function applyGroupClasses() {
    $('#table_tests table')
      .find('tr.dtrg-group th')
      .each(function () {
        const txt = $(this).text().trim();
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
