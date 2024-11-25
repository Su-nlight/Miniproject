// Backend API URL
const apiUrl = 'https://your-backend-api.com/get-data'; // Replace with your actual API URL

// Fetch passwords and display them
document.getElementById('fetchButton').addEventListener('click', () => {
    const resultContainer = document.getElementById('resultContainer');
    const dataList = document.getElementById('dataList');

    // Show loading state (optional)
    resultContainer.innerHTML = `<p>Loading...</p>`;
    resultContainer.style.display = 'flex';

    fetch(apiUrl, {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer your-auth-token', // Add your token
            'Content-Type': 'application/json'
        }
    })
        .then(response => response.json())
        .then(data => {
            // Populate the list with passwords
            dataList.innerHTML = ''; // Clear existing data
            data.forEach(item => {
                const listItem = document.createElement('li');
                listItem.innerHTML = `
                    <div>
                        <span>${item.appName}: ${item.password}</span>
                        <button onclick="checkPassword('${item.password}')">Check Password</button>
                    </div>
                `;
                dataList.appendChild(listItem);
            });
        })
        .catch(error => {
            console.error('Error:', error);
            resultContainer.innerHTML = `<p>Error fetching passwords. Please try again.</p>`;
        });
});

// Password Checkup Function
function checkPassword(password) {
    // Evaluate password strength
    const result = evaluatePasswordStrength(password);

    // Display result in modal
    const modal = document.getElementById('checkupModal');
    const resultElement = document.getElementById('checkupResult');

    resultElement.textContent = result.message;
    resultElement.style.color = result.color;

    modal.style.display = 'block';

    // Close Modal Button
    document.getElementById('closeModal').onclick = () => {
        modal.style.display = 'none';
    };
}

// Evaluate Password Strength
function evaluatePasswordStrength(password) {
    const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
    const mediumRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/;

    if (strongRegex.test(password)) {
        return { message: 'Strong Password!', color: 'green' };
    } else if (mediumRegex.test(password)) {
        return { message: 'Moderate Password. Add special characters and lengthen it.', color: 'orange' };
    } else {
        return { message: 'Weak Password! Use a mix of uppercase, lowercase, numbers, and special characters.', color: 'red' };
    }
}
