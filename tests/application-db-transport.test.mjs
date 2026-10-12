import assert from 'node:assert/strict';
import test from 'node:test';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
test('managed database tools match existing application TLS and private Unix socket tests remain local',()=>{
 assert.deepEqual(applicationDatabaseSsl('postgresql://fixture:unused@managed.example:25060/app'),{rejectUnauthorized:false});
 assert.deepEqual(applicationDatabaseSsl('postgres://localhost/app'),{rejectUnauthorized:false});
 assert.equal(applicationDatabaseSsl('postgres://localhost/app?host=%2Fhome%2Fcodex%2Fprivate-socket'),false);
 assert.throws(()=>applicationDatabaseSsl('https://example.invalid'),/PostgreSQL/);
});
