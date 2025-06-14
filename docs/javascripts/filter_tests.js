document.addEventListener('DOMContentLoaded', function() {
  // Check if we're on a page with a test table
  const dataTable = document.getElementById('DataTables_Table_0');
  if (!dataTable) return;
  
  // Define filter types and their corresponding column indices and match criteria
  const filters = [
    {
      id: 'filter-status-deprecated',
      label: 'Show Deprecated Only',
      type: 'status',
      value: 'deprecated',
      columnIndex: 7 // Status column
    },
    {
      id: 'filter-platform-android',
      label: 'Android Only',
      type: 'platform',
      value: 'android',
      columnIndex: 2 // Platform column
    },
    {
      id: 'filter-platform-ios',
      label: 'iOS Only',
      type: 'platform',
      value: 'ios',
      columnIndex: 2 // Platform column
    },
    {
      id: 'filter-profile-l1',
      label: 'L1 Only',
      type: 'profile',
      value: 'L1',
      columnIndex: 3 // L1 column
    },
    {
      id: 'filter-profile-l2',
      label: 'L2 Only',
      type: 'profile',
      value: 'L2',
      columnIndex: 4 // L2 column
    },
    {
      id: 'filter-profile-r',
      label: 'R Only',
      type: 'profile',
      value: 'R',
      columnIndex: 5 // R column
    },
    {
      id: 'filter-profile-p',
      label: 'P Only',
      type: 'profile',
      value: 'P',
      columnIndex: 6 // P column
    }
  ];
  
  // Create main filters container
  const mainFilterContainer = document.createElement('div');
  mainFilterContainer.className = 'mastg-filters-wrapper';
  mainFilterContainer.style.marginBottom = '1rem';
  mainFilterContainer.style.padding = '1rem';
  mainFilterContainer.style.backgroundColor = 'rgba(0, 0, 0, 0.05)';
  mainFilterContainer.style.borderRadius = '4px';
  
  // Create the filter UI rows
  const filterContainer = document.createElement('div');
  filterContainer.className = 'mastg-filters';
  filterContainer.style.display = 'flex';
  filterContainer.style.flexWrap = 'wrap';
  filterContainer.style.gap = '1rem';
  filterContainer.style.marginBottom = '1rem';
  
  // Create a separate row for filter groups and search
  const filterGroupsRow = document.createElement('div');
  filterGroupsRow.style.display = 'flex';
  filterGroupsRow.style.flexWrap = 'wrap';
  filterGroupsRow.style.gap = '1rem';
  filterGroupsRow.style.alignItems = 'center';
  filterGroupsRow.style.width = '100%';
  filterGroupsRow.style.marginBottom = '0.5rem';
  
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
    groupContainer.style.marginBottom = '0.5rem';
    
    const groupLabel = document.createElement('span');
    groupLabel.textContent = group.label;
    groupLabel.style.fontWeight = 'bold';
    groupLabel.style.minWidth = '70px';
    groupContainer.appendChild(groupLabel);
    
    group.filters.forEach(filter => {
      const toggleLabel = document.createElement('label');
      toggleLabel.className = 'md-toggle__label';
      toggleLabel.style.display = 'flex';
      toggleLabel.style.alignItems = 'center';
      toggleLabel.style.cursor = 'pointer';
      toggleLabel.style.marginRight = '0.5rem';
      toggleLabel.style.padding = '0.25rem 0.5rem';
      toggleLabel.style.border = '1px solid rgba(0, 0, 0, 0.1)';
      toggleLabel.style.borderRadius = '4px';
      toggleLabel.style.backgroundColor = 'white';
      toggleLabel.style.transition = 'background-color 0.2s, border-color 0.2s';
      
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = filter.id;
      checkbox.dataset.type = filter.type;
      checkbox.dataset.value = filter.value;
      checkbox.dataset.columnIndex = filter.columnIndex;
      checkbox.style.marginRight = '6px';
      
      // Add hover effect
      toggleLabel.addEventListener('mouseover', function() {
        if (!checkbox.checked) {
          toggleLabel.style.backgroundColor = 'rgba(0, 0, 0, 0.05)';
        }
      });
      
      toggleLabel.addEventListener('mouseout', function() {
        if (!checkbox.checked) {
          toggleLabel.style.backgroundColor = 'white';
        }
      });
      
      // Add active state styling
      checkbox.addEventListener('change', function() {
        if (checkbox.checked) {
          toggleLabel.style.backgroundColor = 'rgba(13, 110, 253, 0.1)';
          toggleLabel.style.borderColor = 'rgba(13, 110, 253, 0.5)';
        } else {
          toggleLabel.style.backgroundColor = 'white';
          toggleLabel.style.borderColor = 'rgba(0, 0, 0, 0.1)';
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
  
  // Clear all filters button
  const clearButton = document.createElement('button');
  clearButton.textContent = 'Clear All Filters';
  clearButton.style.padding = '0.3rem 0.75rem';
  clearButton.style.border = '1px solid rgba(0, 0, 0, 0.1)';
  clearButton.style.borderRadius = '4px';
  clearButton.style.backgroundColor = '#f8f8f8';
  clearButton.style.cursor = 'pointer';
  clearButton.style.marginLeft = 'auto';
  clearButton.style.transition = 'background-color 0.2s';
  
  // Add hover effect to button
  clearButton.addEventListener('mouseover', function() {
    clearButton.style.backgroundColor = '#e9e9e9';
  });
  
  clearButton.addEventListener('mouseout', function() {
    clearButton.style.backgroundColor = '#f8f8f8';
  });
  
  clearButton.addEventListener('click', function() {
    const checkboxes = mainFilterContainer.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => {
      cb.checked = false;
      cb.dispatchEvent(new Event('change'));
    });
    filterTable();
  });
  
  filterGroupsRow.appendChild(clearButton);
  filterContainer.appendChild(filterGroupsRow);
  
  // Add filter container to main container
  mainFilterContainer.appendChild(filterContainer);
  
  // Add the filter container before the table
  const tableWrapper = dataTable.closest('.dataTables_wrapper');
  
  // Insert the filters before the table wrapper
  tableWrapper.parentNode.insertBefore(mainFilterContainer, tableWrapper);
  
  // Function to filter the table
  function filterTable() {
    const activeFilters = {};
    
    // Collect all active filters
    const checkboxes = mainFilterContainer.querySelectorAll('input[type="checkbox"]:checked');
    checkboxes.forEach(checkbox => {
      const type = checkbox.dataset.type;
      const value = checkbox.dataset.value;
      
      if (!activeFilters[type]) {
        activeFilters[type] = [];
      }
      activeFilters[type].push({
        value: value,
        columnIndex: parseInt(checkbox.dataset.columnIndex)
      });
    });
    
    const rows = dataTable.querySelectorAll('tbody tr');
    
    rows.forEach(function(row) {
      let shouldShow = true;
      
      // Apply each filter type
      Object.keys(activeFilters).forEach(filterType => {
        // If any filter in this type matches, we'll keep the row
        let typeMatch = false;
        
        activeFilters[filterType].forEach(filter => {
          const cell = row.querySelector(`td:nth-child(${filter.columnIndex + 1})`);
          if (!cell) return;
          
          let isMatch = false;
          
          // Status filter
          if (filterType === 'status') {
            isMatch = cell.textContent.includes(filter.value) || 
                    cell.innerHTML.includes(`status:${filter.value}`);
          } 
          // Platform filter
          else if (filterType === 'platform') {
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
      
      // If we have no active filters, show all rows
      if (Object.keys(activeFilters).length === 0) {
        shouldShow = true;
      }
      
      row.style.display = shouldShow ? '' : 'none';
    });
    
    // Update the "Showing X to Y of Z entries" text
    const info = tableWrapper.querySelector('.dataTables_info');
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
});
