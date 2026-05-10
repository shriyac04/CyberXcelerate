require('dotenv').config();
const { Client } = require('@elastic/elasticsearch');

const ES_NODE = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';
const ES_INDEX = process.env.ELASTICSEARCH_INDEX || 'cape-direct-v2';

const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

const client = new Client({
    node: ES_NODE,
    auth: { 
        username: ES_USERNAME, 
        password: ES_PASSWORD 
    },
    tls: {
        rejectUnauthorized: false
    }
});

async function run() {
    try {
        const health = await client.cluster.health();
        console.log('Cluster Health:', health.status);

        const indexExists = await client.indices.exists({ index: ES_INDEX });
        console.log(`Index '${ES_INDEX}' exists:`, indexExists);

        if (indexExists) {
            const count = await client.count({ index: ES_INDEX });
            console.log(`Document count in '${ES_INDEX}':`, count.count);
            
            // Try to fetch one document
            const search = await client.search({
                index: ES_INDEX,
                size: 1
            });
            console.log('Sample document:', JSON.stringify(search.hits.hits[0]?._source, null, 2));
        }

    } catch (err) {
        console.error('Error:', err);
    }
}

run();
