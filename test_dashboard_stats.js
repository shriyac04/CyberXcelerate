const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
const ADMIN_USER = 'root';
const ADMIN_PASS = 'Admin@@'; // From .env

async function run() {
    try {
        console.log('--- TEST: Dashboard Stats ---');

        // 1. Admin Login
        console.log('1. Logging in as Admin...');
        const adminRes = await axios.post(`${BASE_URL}/api/auth/login`, {
            username: ADMIN_USER,
            password: ADMIN_PASS
        });
        const adminToken = adminRes.data.accessToken;
        console.log('   Admin login success.');

        // 2. Fetch Dashboard Stats
        console.log('2. Fetching Dashboard Stats...');
        const res = await axios.get(`${BASE_URL}/api/admin/dashboard-stats`, {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        console.log('   Stats retrieved successfully.');
        console.log('   Summary:', res.data.summary);
        console.log('   Timeline (Logins):', res.data.timeline.logins.length, 'days');
        console.log('   File Types:', res.data.fileTypes);
        console.log('   Top Users:', res.data.topUsers);

    } catch (error) {
        console.error('TEST FAILED:', error.message);
        if (error.response) console.error('Response data:', error.response.data);
    }
}

run();
