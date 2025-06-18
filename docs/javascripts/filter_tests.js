document$.subscribe(function() {
  configureTestsTable();
});
function configureTestsTable() {
  // Check if we're on a page with a test table
  const dataTable = $('#table_tests table').get(0);
  if (!dataTable) return;
  
  // Define filter types and their corresponding column indices and match criteria
  const filters = [
    {
      id: 'filter-status-deprecated',
      label: 'Show Deprecated',
      type: 'status',
      value: 'deprecated',
      columnIndex: 7, // Status column
      invertLogic: true // Invert logic for deprecated filter - hide by default, show when checked
    },
    {
      id: 'filter-platform-android',
      label: 'Android',
      type: 'platform',
      value: 'android',
      columnIndex: 2 // Platform column
    },
    {
      id: 'filter-platform-ios',
      label: 'iOS',
      type: 'platform',
      value: 'ios',
      columnIndex: 2 // Platform column
    },
    {
      id: 'filter-platform-network',
      label: 'Network',
      type: 'platform',
      value: 'network',
      columnIndex: 2 // Platform column
    },
    {
      id: 'filter-profile-l1',
      label: 'L1',
      type: 'profile',
      value: 'L1',
      columnIndex: 3 // L1 column
    },
    {
      id: 'filter-profile-l2',
      label: 'L2',
      type: 'profile',
      value: 'L2',
      columnIndex: 4 // L2 column
    },
    {
      id: 'filter-profile-r',
      label: 'R',
      type: 'profile',
      value: 'R',
      columnIndex: 5 // R column
    },
    {
      id: 'filter-profile-p',
      label: 'P',
      type: 'profile',
      value: 'P',
      columnIndex: 6 // P column
    }
  ];
  
  // Create main filters container
  const mainFilterContainer = document.createElement('div');
  mainFilterContainer.className = 'mastg-filters-wrapper';
  mainFilterContainer.style.padding = '1rem';
  mainFilterContainer.style.marginBottom = '1.5rem';

  mainFilterContainer.style.backgroundColor = 'var(--md-default-fg-color--lightest, rgba(0, 0, 0, 0.05))';
  mainFilterContainer.style.borderRadius = '4px';
  mainFilterContainer.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';
  
  // Create the filter UI rows
  const filterContainer = document.createElement('div');
  filterContainer.className = 'mastg-filters';
  filterContainer.style.display = 'flex';
  filterContainer.style.flexWrap = 'wrap';
  filterContainer.style.gap = '1rem';
  
  // Create a separate row for filter groups
  const filterGroupsRow = document.createElement('div');
  filterGroupsRow.style.display = 'flex';
  filterGroupsRow.style.flexWrap = 'wrap';
  filterGroupsRow.style.gap = '1rem';
  filterGroupsRow.style.alignItems = 'center';
  filterGroupsRow.style.width = '100%';
  
  // Group filters by type for better organization
  const filterGroups = {
    status: { label: 'Status:', filters: [] },
    platform: { label: 'Platform:', filters: [] },
    profile: { label: 'Profile:', filters: [] }
  };
  
  // Organize filters by group
  filters.forEach(filter => {
    filterGroups[filter.type].filters.push(filter);
  });
  
  // Create the filter checkboxes grouped by type
  Object.keys(filterGroups).forEach(groupKey => {
    const group = filterGroups[groupKey];
    
    const groupContainer = document.createElement('div');
    groupContainer.className = 'filter-group';
    groupContainer.style.display = 'flex';
    groupContainer.style.alignItems = 'center';
    groupContainer.style.gap = '0.5rem';
    
    const groupLabel = document.createElement('span');
    groupLabel.textContent = group.label;
    groupLabel.style.fontWeight = 'bold';
    groupLabel.style.minWidth = '70px';
    groupLabel.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';
    groupContainer.appendChild(groupLabel);
    
    group.filters.forEach(filter => {
      const toggleLabel = document.createElement('label');
      toggleLabel.className = 'md-toggle__label';
      toggleLabel.style.display = 'flex';
      toggleLabel.style.alignItems = 'center';
      toggleLabel.style.cursor = 'pointer';
      toggleLabel.style.marginRight = '0.5rem';
      toggleLabel.style.padding = '0.25rem 0.5rem';
      toggleLabel.style.border = '1px solid var(--md-default-fg-color--lightest, rgba(0, 0, 0, 0.1))';
      toggleLabel.style.borderRadius = '4px';
      toggleLabel.style.backgroundColor = 'var(--md-default-bg-color, white)';
      toggleLabel.style.transition = 'background-color 0.2s, border-color 0.2s';
      toggleLabel.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';
      
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = filter.id;
      checkbox.dataset.type = filter.type;
      checkbox.dataset.value = filter.value;
      checkbox.dataset.columnIndex = filter.columnIndex;
      if (filter.invertLogic) {
        checkbox.dataset.invertLogic = 'true';
      }
      checkbox.style.marginRight = '6px';
      
      // Add hover effect
      toggleLabel.addEventListener('mouseover', function() {
        if (!checkbox.checked) {
          toggleLabel.style.backgroundColor = 'var(--md-default-fg-color--lightest, rgba(0, 0, 0, 0.05))';
        }
      });
      
      toggleLabel.addEventListener('mouseout', function() {
        if (!checkbox.checked) {
          toggleLabel.style.backgroundColor = 'var(--md-default-bg-color, white)';
        }
      });
      
      // Add active state styling
      checkbox.addEventListener('change', function() {
        if (checkbox.checked) {
          toggleLabel.style.backgroundColor = 'var(--md-primary-fg-color--transparent, rgba(13, 110, 253, 0.1))';
          toggleLabel.style.borderColor = 'var(--md-primary-fg-color--light, rgba(13, 110, 253, 0.5))';
        } else {
          toggleLabel.style.backgroundColor = 'var(--md-default-bg-color, white)';
          toggleLabel.style.borderColor = 'var(--md-default-fg-color--lightest, rgba(0, 0, 0, 0.1))';
        }
      });
      
      const labelText = document.createTextNode(filter.label);
      
      toggleLabel.appendChild(checkbox);
      toggleLabel.appendChild(labelText);
      groupContainer.appendChild(toggleLabel);
      
      // Add event listener to checkbox
      checkbox.addEventListener('change', filterTable);
    });
    
    filterGroupsRow.appendChild(groupContainer);
  });
  
  // Add search field
  const searchContainer = document.createElement('div');
  searchContainer.className = 'filter-group';
  searchContainer.style.display = 'flex';
  searchContainer.style.alignItems = 'center';
  searchContainer.style.gap = '0.5rem';
  
  const searchLabel = document.createElement('span');
  searchLabel.textContent = "Search:";
  searchLabel.style.fontWeight = 'bold';
  searchLabel.style.minWidth = '70px';
  searchLabel.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';

  const searchInput = document.createElement('input');
  searchInput.type = 'text'
  searchInput.id = "filter-search"
  searchInput.style.fontWeight = 'bold';
  searchInput.style.minWidth = '300px'

  searchInput.style.padding = '10px';
  searchInput.style.border = '1px solid #ccc';
  searchInput.style.borderRadius = '5px';

  searchContainer.appendChild(searchLabel)
  searchContainer.appendChild(searchInput);
  filterGroupsRow.appendChild(searchContainer);

  searchInput.addEventListener('keyup', filterTable);


  // Create bottom row container
  const bottomRow = document.createElement('div');
  bottomRow.style.display = 'flex';
  bottomRow.style.justifyContent = 'space-between';
  bottomRow.style.alignItems = 'center';
  bottomRow.style.width = '100%';

  // Create span on the left
  const infoSpan = document.createElement('span');
  infoSpan.id = "filter-info";
  infoSpan.style.fontWeight = 'bold';
  infoSpan.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';

  // Create clear button on the right
  const clearButton = document.createElement('button');
  clearButton.textContent = 'Clear All Filters';
  clearButton.style.padding = '0.3rem 0.75rem';
  clearButton.style.border = '1px solid var(--md-default-fg-color--lightest, rgba(0, 0, 0, 0.1))';
  clearButton.style.borderRadius = '4px';
  clearButton.style.backgroundColor = 'var(--md-default-fg-color--lightest, #f8f8f8)';
  clearButton.style.color = 'var(--md-default-fg-color, rgba(0, 0, 0, 0.87))';
  clearButton.style.cursor = 'pointer';
  clearButton.style.transition = 'background-color 0.2s';

  // Append span and button to bottom row
  bottomRow.appendChild(infoSpan);
  bottomRow.appendChild(clearButton);

  // Append bottom row to filter container
  filterGroupsRow.appendChild(bottomRow);

  
  // Add hover effect to button
  clearButton.addEventListener('mouseover', function() {
    clearButton.style.backgroundColor = 'var(--md-accent-fg-color--transparent, #e9e9e9)';
  });
  
  clearButton.addEventListener('mouseout', function() {
    clearButton.style.backgroundColor = 'var(--md-default-fg-color--lightest, #f8f8f8)';
  });
  
  clearButton.addEventListener('click', function() {
    const checkboxes = mainFilterContainer.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => {
      cb.checked = false;
      cb.dispatchEvent(new Event('change'));
    });
    filterTable();
  });
  
  filterContainer.appendChild(filterGroupsRow);
  
  // Add filter container to main container
  mainFilterContainer.appendChild(filterContainer);
  
  // Add the filter container before the table
  const tableWrapper = dataTable.closest('.dataTables_wrapper');
  
  // Insert the filters before the table wrapper
  tableWrapper.parentNode.insertBefore(mainFilterContainer, tableWrapper);
  
  // Initialize table - hide deprecated items by default
  setTimeout(() => {
    // Hide deprecated items on page load
    const rows = dataTable.querySelectorAll('tbody tr');
    rows.forEach(function(row) {
      const statusCell = row.querySelector('td:nth-child(8)'); // Status column
      if (statusCell && (statusCell.textContent.includes('deprecated') || 
                         statusCell.innerHTML.includes('status:deprecated'))) {
        row.style.display = 'none';
      }
    });
    
    // Update the showing count
    const info = $("#filter-info")[0]
    if (info) {
      const totalRows = rows.length;
      const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none').length;
      if (visibleRows < totalRows) {
        info.textContent = `Showing ${visibleRows} of ${totalRows} entries (filtered)`;
      }
    }
  }, 0);
  
  // Function to filter the table
  function filterTable() {
    const activeFilters = {};
    
    // Collect all active filters
    const checkboxes = mainFilterContainer.querySelectorAll('input[type="checkbox"]:checked');

    // build up a new anchor for URL
    var anchor = []

    checkboxes.forEach(checkbox => {
      const type = checkbox.dataset.type;
      const value = checkbox.dataset.value;

      // extract filter name
      anchor.push(checkbox.dataset.value.toLowerCase())
      
      if (!activeFilters[type]) {
        activeFilters[type] = [];
      }
      activeFilters[type].push({
        value: value,
        columnIndex: parseInt(checkbox.dataset.columnIndex)
      });
    });

    history.replaceState(null, null, '#' + anchor.join(';'));


    
    // First, handle the special case of deprecated items - hide them by default
    let showDeprecatedChecked = false;
    const deprecatedCheckbox = mainFilterContainer.querySelector('#filter-status-deprecated');
    if (deprecatedCheckbox && deprecatedCheckbox.checked) {
      showDeprecatedChecked = true;
    }

    // By default, hide deprecated items if the checkbox is not checked
    const rows = dataTable.querySelectorAll('tbody tr');
    
    const searchTerm = mainFilterContainer.querySelector('#filter-search').value.toLowerCase()

    rows.forEach(function(row) {
      let shouldShow = true;
      
      // First, check if the row is deprecated
      const statusCell = row.querySelector('td:nth-child(8)'); // Status column
      const isDeprecated = statusCell && (statusCell.textContent.includes('deprecated') || 
                                         statusCell.innerHTML.includes('status:deprecated'));
      
      // Handle deprecated items specially:
      // - If "Show Deprecated" is not checked, hide deprecated items
      // - If "Show Deprecated" is checked, allow them to be shown (subject to other filters)
      if (isDeprecated && !showDeprecatedChecked) {
        shouldShow = false;
      } else {
        // Apply each regular filter type (excluding the deprecated filter which we handled separately)
        Object.keys(activeFilters).forEach(filterType => {
          // Skip the status filter which we handled separately
          if (filterType === 'status') return;
          
          // If any filter in this type matches, we'll keep the row
          let typeMatch = false;
          
          activeFilters[filterType].forEach(filter => {
            const cell = row.querySelector(`td:nth-child(${filter.columnIndex + 1})`);
            if (!cell) return;
            
            let isMatch = false;
            
            // Platform filter
            if (filterType === 'platform') {
              isMatch = cell.textContent.toLowerCase().includes(filter.value.toLowerCase()) || 
                      cell.innerHTML.includes(`platform:${filter.value.toLowerCase()}`);
            } 
            // Profile filters (L1, L2, R, P)
            else if (filterType === 'profile') {
              // Check which profile this filter is for
              if (filter.value === 'L1') {
                isMatch = cell.querySelector('.mas-dot-blue');
              } else if (filter.value === 'L2') {
                isMatch = cell.querySelector('.mas-dot-green');
              } else if (filter.value === 'R') {
                isMatch = cell.querySelector('.mas-dot-orange');
              } else if (filter.value === 'P') {
                isMatch = cell.querySelector('.mas-dot-purple');
              }
            }
            
            if (isMatch) {
              typeMatch = true;
            }
          });
          
          // If no filters of this type matched, hide the row
          if (!typeMatch && activeFilters[filterType].length > 0) {
            shouldShow = false;
          }
        });
      }
      
      // If we have no active filters except possibly the deprecated filter, 
      // and the deprecated filter is not checked, show all non-deprecated rows
      if (Object.keys(activeFilters).length === 0 || 
          (Object.keys(activeFilters).length === 1 && 'status' in activeFilters && !showDeprecatedChecked)) {
        shouldShow = !isDeprecated || showDeprecatedChecked;
      }
      
      if(searchTerm.length > 0){
        const title = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
        if(title.indexOf(searchTerm) === -1){
          shouldShow = false;
        }
      }
      
      row.style.display = shouldShow ? '' : 'none';
    });
    
    // Update the "Showing X to Y of Z entries" text
    const info = $("#filter-info")[0]
    if (info) {
      const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none').length;
      const totalRows = rows.length;
      if (visibleRows < totalRows) {
        info.textContent = `Showing ${visibleRows} of ${totalRows} entries (filtered)`;
      } else {
        info.textContent = `Showing 1 to ${totalRows} of ${totalRows} entries`;
      }
    }
  }
  $(function() {
    const hash = window.location.hash;
    if (!hash) return;
  
    const mapping = {
      "android": "#filter-platform-android",
      "ios": "#filter-platform-ios",
      "network": "#filter-platform-network",
      "l1": "#filter-profile-l1",
      "l2": "#filter-profile-l2",
      "r": "#filter-profile-r",
      "p": "#filter-profile-p",
    }

    const items = hash.substring(1).split(';');
  
    items.forEach(function(item) {
      const checkbox = $(mapping[item]);
      if (checkbox.length) {
        checkbox.prop('checked', true).trigger('change');
      }
    });
  
    if(items.length > 0){
      filterTable()
    }
  });
};
