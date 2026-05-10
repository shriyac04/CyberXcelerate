const mongoose = require('mongoose');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI;

async function checkUsers() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to DB.');
        
        const users = await mongoose.connection.db.collection('users').find({}).toArray();
        console.log('Users found:', users);
        
        await mongoose.disconnect();
    } catch (err) {
        console.error(err);
    }
}

checkUsers();
