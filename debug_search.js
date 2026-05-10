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
        console.log('Testing search query...');
        const body = {
            from: 0,
            size: 20,
            sort: [{ "@timestamp": { order: "desc" } }],
            query: { match_all: {} },
            _source: ["target.file.name", "target.file.sha256", "info.score", "info.duration", "@timestamp", "analysis.start_time"]
        };

        const result = await client.search({
            index: ES_INDEX,
            body
        });
        console.log('Success:', result.hits.total);
    } catch (err) {
        console.error('Full Error:', JSON.stringify(err, null, 2));
        if (err.meta) {
            console.error('Meta body:', err.meta.body);
        }
    }
}

run();
