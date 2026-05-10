require('dotenv').config();
const { Client } = require('@elastic/elasticsearch');

const ES_NODE = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';
const ES_INDEX = process.env.ELASTICSEARCH_INDEX || 'cape-direct-v2';
const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

const client = new Client({
    node: ES_NODE,
    auth: { username: ES_USERNAME, password: ES_PASSWORD },
    tls: { rejectUnauthorized: false }
});

async function run() {
    try {
        const result = await client.search({
            index: ES_INDEX,
            size: 1,
            body: { query: { match_all: {} } }
        });
        
        if (result.hits.hits.length > 0) {
            console.log('Sample Document Keys:', Object.keys(result.hits.hits[0]._source));
            // Check for nested analysis.start_time
            const source = result.hits.hits[0]._source;
            if (source.analysis) {
                console.log('analysis keys:', Object.keys(source.analysis));
            }
        } else {
            console.log('No documents found.');
        }
    } catch (err) {
        console.error('Error:', err);
    }
}

run();
