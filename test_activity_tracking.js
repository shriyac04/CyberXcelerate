const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');

const BASE_URL = 'http://localhost:3000';
const STUDENT_USER = '1234567890'; // 10-digit roll
const STUDENT_PASS = 'CUPunjab';
const ADMIN_USER = 'root';
const ADMIN_PASS = 'Admin@@'; // From .env

async function run() {
    try {
        console.log('--- TEST: Activity Tracking ---');

        // 1. Student Login (should create history)
        console.log('1. Logging in as Student...');
        const studentRes = await axios.post(`${BASE_URL}/api/auth/login`, {
            username: STUDENT_USER,
            password: STUDENT_PASS
        });
        const studentToken = studentRes.data.accessToken;
        console.log('   Student login success.');

        // 2. Student Submission
        console.log('2. Submitting a file as Student...');
        const form = new FormData();
        form.append('file', Buffer.from('dummy content'), 'test_sample.exe');
        form.append('package', 'exe');

        try {
            await axios.post(`${BASE_URL}/api/upload`, form, {
                headers: {
                    ...form.getHeaders(),
                    'Authorization': `Bearer ${studentToken}`
                },
                timeout: 2000 // 2 seconds timeout
            });
            // It might fail if CAPE is not running, but we just want to see if DB saved it.
            // server.js saves to DB *after* CAPE response. 
            // If CAPE is down, it won't save submission. User said "you are free to modify schema", 
            // but I modified server.js to save *if* CAPE succeeds. 
            // Let's see if we can trick it or if CAPE is mocked.
            // The user's env has CAPE at 10.20.8.79. It probably won't be reachable.
            // However, the user request was "how many samples were submitted".
            // If the upload fails, it isn't submitted.
            console.log('   Submission attempt made.');
        } catch (e) {
            console.log('   Submission failed (expected if CAPE is down):', e.message);
        }

        // 3. Admin Login
        console.log('3. Logging in as Admin...');
        const adminRes = await axios.post(`${BASE_URL}/api/auth/login`, {
            username: ADMIN_USER,
            password: ADMIN_PASS // Try 'root' or null? code says null fallback or match
        });
        const adminToken = adminRes.data.accessToken;
        console.log('   Admin login success.');

        // 4. Check User Stats
        console.log('4. Fetching User Stats...');
        const statsRes = await axios.get(`${BASE_URL}/api/admin/users`, {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        const studentStats = statsRes.data.find(u => u.username === STUDENT_USER);
        if (studentStats) {
            console.log('   Found student stats:', studentStats);
            if (studentStats.totalLogins > 0) console.log('   SUCCESS: Login tracked.');
            else console.error('   FAILURE: Login NOT tracked.');
        } else {
            console.error('   FAILURE: Student user not found in stats.');
        }

        // 5. Check User Details
        console.log('5. Fetching Student Details...');
        const detailRes = await axios.get(`${BASE_URL}/api/admin/users/${STUDENT_USER}`, {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        console.log('   Login History Length:', detailRes.data.loginHistory.length);
        console.log('   Submissions Length:', detailRes.data.submissions.length);

    } catch (error) {
        console.error('TEST FAILED:', error.message);
        if (error.response) console.error('Response data:', error.response.data);
    }
}

run();
