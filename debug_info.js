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
            const source = result.hits.hits[0]._source;
            if (source.info) {
                console.log('info keys:', Object.keys(source.info));
                console.log('info content:', JSON.stringify(source.info, null, 2));
            }
        }
    } catch (err) {
        console.error('Error:', err);
    }
}

run();
