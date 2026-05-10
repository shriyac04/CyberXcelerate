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
        console.log('Testing deep pagination (offset 10000)...');
        const body = {
            from: 10000,
            size: 20,
            sort: [{ "info.id": { order: "desc" } }],
            query: { match_all: {} },
            _source: ["info.id"],
            track_total_hits: true
        };

        const result = await client.search({
            index: ES_INDEX,
            body
        });
        console.log('Success:', result.hits.total);
    } catch (err) {
        console.error('Error:', err.meta?.body?.error?.root_cause?.[0]?.reason || err.message);
    }
}

run();
