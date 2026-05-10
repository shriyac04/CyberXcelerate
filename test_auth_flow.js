const axios = require('axios');

const BASE_URL = 'http://localhost:3000';
const ADMIN_USER = { username: 'root', password: 'Admin@@' }; // From .env
const STUDENT_USER = { username: '2310991223', password: 'CUPunjab' }; // From .env

async function testAuth() {
    console.log('--- Testing Auth Flow ---');

    // 1. Admin Login
    try {
        console.log('1. Testing Admin Login...');
        const res = await axios.post(`${BASE_URL}/api/auth/login`, ADMIN_USER);
        if (res.data.user.role === 'admin' && res.data.accessToken) {
            console.log('✅ Admin Login Success');
            await testAdminAccess(res.data.accessToken);
        } else {
            console.error('❌ Admin Login Failed: Incorrect role or missing token');
        }
    } catch (e) {
        console.error('❌ Admin Login Error:', e.response?.data || e.message);
    }

    // 2. Student Login
    try {
        console.log('\n2. Testing Student Login...');
        const res = await axios.post(`${BASE_URL}/api/auth/login`, STUDENT_USER);
        if (res.data.user.role === 'student' && res.data.accessToken) {
            console.log('✅ Student Login Success');
            await testStudentAccess(res.data.accessToken);
        } else {
            console.error('❌ Student Login Failed: Incorrect role or missing token');
        }
    } catch (e) {
        console.error('❌ Student Login Error:', e.response?.data || e.message);
    }

    // 3. Invalid Student Login (Wrong Password)
    try {
        console.log('\n3. Testing Invalid Student Login...');
        await axios.post(`${BASE_URL}/api/auth/login`, { ...STUDENT_USER, password: 'wrongpassword' });
        console.error('❌ Invalid Login Failed: Should have returned 401');
    } catch (e) {
        if (e.response?.status === 401) {
            console.log('✅ Invalid Login Handled Correctly (401)');
        } else {
            console.error('❌ Invalid Login Unexpected Error:', e.message);
        }
    }
}

async function testAdminAccess(token) {
    try {
        console.log('   -> Testing Admin Access to /api/es/stats...');
        await axios.get(`${BASE_URL}/api/es/stats`, { headers: { Authorization: `Bearer ${token}` } });
        console.log('   ✅ Admin can access stats');
    } catch (e) {
        console.error('   ❌ Admin failed to access stats:', e.response?.data || e.message);
    }
}

async function testStudentAccess(token) {
    try {
        console.log('   -> Testing Student Access to /api/es/stats (Should Fail)...');
        await axios.get(`${BASE_URL}/api/es/stats`, { headers: { Authorization: `Bearer ${token}` } });
        console.error('   ❌ Student accessed protected route!');
    } catch (e) {
        if (e.response?.status === 403) {
            console.log('   ✅ Student correctly blocked (403)');
        } else {
            console.error('   ❌ Unexpected error for student access:', e.response?.status, e.message);
        }
    }
}

testAuth();
