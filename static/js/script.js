$(document).ready(function() {
    // Add your JavaScript code here
    
    // Initialize the datepicker
    $("#id_start_date").datepicker();
    $("#id_end_date").datepicker();
  });
  

  // script.js
// Toggle Dark Mode

function toggleDarkMode() {
  const body = document.body;
  body.classList.toggle('dark-mode');
}

