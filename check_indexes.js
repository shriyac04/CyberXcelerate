const mongoose = require('mongoose');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI;

async function checkIndexes() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to DB.');
        
        const indexes = await mongoose.connection.db.collection('users').indexes();
        console.log('Indexes:', JSON.stringify(indexes, null, 2));
        
        await mongoose.disconnect();
    } catch (err) {
        console.error(err);
    }
}

checkIndexes();
