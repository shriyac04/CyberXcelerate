const mongoose = require('mongoose');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cape';

async function checkDB() {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('Connected.');

        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('\nCollections found:');
        if (collections.length === 0) console.log('   (none)');
        
        for (const col of collections) {
            const count = await mongoose.connection.db.collection(col.name).countDocuments();
            console.log(` - ${col.name}: ${count} documents`);
        }
        
        console.log('\nDisconnecting...');
        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

checkDB();
