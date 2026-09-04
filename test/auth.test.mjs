import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {NotifAuth} from '../dist/index.js';
let server,issuer,keys,responseToken,requests=0;
const clientId='pk_live_example';
const profile={id:'example',tenant_id:'example-tenant',phone_e164:'+15555550100',display_name:null,provider:'whatsapp',mode:'LIVE',first_seen_at:'2026-01-01T00:00:00Z',metadata:{}};
async function token({aud=clientId,iss=issuer,exp='5m',value=profile}={}) {
 return new SignJWT({profile:value}).setProtectedHeader({alg:'RS256',kid:'example-key'}).setIssuer(iss).setAudience(aud).setSubject('example-subject').setIssuedAt().setExpirationTime(exp).setJti('example-jti').sign(keys.privateKey);
}
before(async()=>{
 keys=await generateKeyPair('RS256');const jwk={...await exportJWK(keys.publicKey),kid:'example-key',alg:'RS256',use:'sig'};
 server=createServer((req,res)=>{res.setHeader('content-type','application/json');if(req.url==='/.well-known/jwks.json')return res.end(JSON.stringify({keys:[jwk]}));requests++;res.end(JSON.stringify({token:responseToken,profile:{phone_e164:'untrusted'}}));});
 await new Promise(resolve=>server.listen(0,'localhost',resolve));issuer=`http://localhost:${server.address().port}`;
});
after(()=>new Promise(resolve=>server.close(resolve)));
const sdk=(extra={})=>new NotifAuth({issuer,clientId,redirectUri:'https://app.example/callback',...extra});
test('builds a PKCE S256 authorization request with independent random transactions',()=>{
 const auth=sdk(),a=auth.begin(),b=auth.begin(),url=new URL(a.url);
 assert.notEqual(a.transaction.state,b.transaction.state);
 assert.notEqual(a.transaction.verifier,b.transaction.verifier);
 assert.equal(url.searchParams.get('code_challenge'),createHash('sha256').update(a.transaction.verifier).digest('base64url'));
 assert.equal(url.searchParams.get('code_challenge_method'),'S256');
});
test('rejects insecure or non-origin issuers',()=>{
 for(const url of ['http://untrusted.example','https://example.test/path','https://user:pass@example.test','https://example.test?query=1'])assert.throws(()=>sdk({issuer:url}));
});
test('rejects state mismatch before sending an exchange request',async()=>{
 const auth=sdk(),tx=auth.begin().transaction,count=requests;
 await assert.rejects(auth.complete('example-code','wrong-state',tx));assert.equal(requests,count);
});
test('returns the verified signed profile rather than an unsigned duplicate',async()=>{
 responseToken=await token();const auth=sdk(),tx=auth.begin().transaction;
 const result=await auth.complete('example-code',tx.state,tx);
 assert.equal(result.phone_e164,profile.phone_e164);assert.equal(result.subject,'example-subject');
});
test('rejects a token intended for another application',async()=>{await assert.rejects(sdk().verify(await token({aud:'another-client'})));});
test('rejects another issuer and expired tokens',async()=>{
 await assert.rejects(sdk().verify(await token({iss:'https://untrusted.example'})));
 await assert.rejects(sdk().verify(await token({exp:Math.floor(Date.now()/1000)-60})));
});
test('separates live and sandbox identities',async()=>{
 const jwt=await token({value:{...profile,mode:'TEST',provider:'sandbox'}});
 await assert.rejects(sdk().verify(jwt));
 assert.equal((await sdk({allowSandbox:true}).verify(jwt)).profile.mode,'TEST');
});
test('rejects inconsistent provider and mode claims',async()=>{
 await assert.rejects(sdk().verify(await token({value:{...profile,provider:'sandbox'}})));
});
