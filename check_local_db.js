const mongoose = require('mongoose');

const MONGODB_URI = 'mongodb://127.0.0.1:27017/cape_local_test';

async function checkDB() {
    try {
        console.log('Connecting to Local MongoDB:', MONGODB_URI);
        await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('Connected successfully!');
        await mongoose.disconnect();
    } catch (err) {
        console.error('Error connecting to local DB:', err.message);
    }
}

checkDB();
