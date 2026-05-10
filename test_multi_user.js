const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
const STUDENT_PASSWORD = 'CUPunjab'; // From .env

const USERS = [
    '2310991224',
    '2310991225',
    '2310991226'
];

async function testMultipleUsers() {
    console.log('--- Testing Multiple Student Creations ---');

    for (const username of USERS) {
        try {
            console.log(`Creating user ${username}...`);
            const res = await axios.post(`${BASE_URL}/api/auth/login`, { username, password: STUDENT_PASSWORD });
            if (res.data.user.role === 'student') {
                console.log(`✅ Success: ${username}`);
            } else {
                console.error(`❌ Failed: ${username} - Unexpected response`);
            }
        } catch (e) {
            console.error(`❌ Error creating ${username}:`, e.response?.data || e.message);
        }
    }
}

testMultipleUsers();
