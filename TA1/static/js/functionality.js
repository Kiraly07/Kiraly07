document.addEventListener('DOMContentLoaded', function () {
    const emailTable = document.getElementById('email_table');
    const alertEmailInput = document.getElementById('alert_email');
    const addEmailButton = document.getElementById('add_email');
    const saveEmailsButton = document.getElementById('save_emails');

    // Add email to the table
    addEmailButton.addEventListener('click', function () {
        const email = alertEmailInput.value.trim();
        if (email) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${emailTable.rows.length + 1}</td>
                <td>${email}</td>
                <td>
                    <button class="btn btn-danger btn-sm remove-email">
                        <i class="fas fa-trash"></i> Remove
                    </button>
                </td>
            `;
            emailTable.appendChild(row);
            alertEmailInput.value = '';

            // Add event listener to the remove button
            row.querySelector('.remove-email').addEventListener('click', function () {
                row.remove();
                updateTableIndices();
            });
        }
    });

    // Save emails to the server
    saveEmailsButton.addEventListener('click', function () {
        const emails = Array.from(emailTable.rows).map(row => row.cells[1].textContent);
        fetch('/save-email-recipients', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ emails }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Email recipients saved successfully!');
            } else {
                alert('Failed to save email recipients.');
            }
        })
        .catch(error => {
            alert('An error occurred while saving email recipients.');
        });
    });

    // Update table indices after removing a row
    function updateTableIndices() {
        Array.from(emailTable.rows).forEach((row, index) => {
            row.cells[0].textContent = index + 1;
        });
    }
});
