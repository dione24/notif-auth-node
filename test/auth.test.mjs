import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {NotifAuth,NotifAuthError} from '../dist/index.js';
let server,issuer,keys,responseToken,requests=0,lastBody,reply=null;
const clientId='pk_live_example';
const profile={id:'example',tenant_id:'example-tenant',phone_e164:'+15555550100',display_name:null,provider:'whatsapp',mode:'LIVE',first_seen_at:'2026-01-01T00:00:00Z',metadata:{}};
async function token({aud=clientId,iss=issuer,exp='5m',value=profile}={}) {
 return new SignJWT({profile:value}).setProtectedHeader({alg:'RS256',kid:'example-key'}).setIssuer(iss).setAudience(aud).setSubject('example-subject').setIssuedAt().setExpirationTime(exp).setJti('example-jti').sign(keys.privateKey);
}
before(async()=>{
 keys=await generateKeyPair('RS256');const jwk={...await exportJWK(keys.publicKey),kid:'example-key',alg:'RS256',use:'sig'};
 server=createServer((req,res)=>{
  res.setHeader('content-type','application/json');if(req.url==='/.well-known/jwks.json')return res.end(JSON.stringify({keys:[jwk]}));
  let raw='';req.on('data',c=>raw+=c);req.on('end',()=>{
   requests++;lastBody={path:req.url,...JSON.parse(raw||'{}')};
   if(reply){const r=reply;reply=null;res.statusCode=r.status;for(const [k,v] of Object.entries(r.headers||{}))res.setHeader(k,v);return res.end(typeof r.body==='string'?r.body:JSON.stringify(r.body));}
   if(req.url==='/server/otp/send')return res.end(JSON.stringify({challenge_id:'01JABCDEFGHJKMNPQRSTVWXYZ0',phone_masked:'+1555•••0100',expires_at:'2026-01-01T00:05:00Z',resend_after_seconds:60,sends_left:2}));
   res.end(JSON.stringify({token:responseToken,profile:{phone_e164:'untrusted'}}));
  });
 });
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
test('maps API errors to NotifAuthError with status, request id and retry hints',async()=>{
 reply={status:400,body:{error:'invalid_grant',error_code:'expired_code',request_id:'req-1'}};
 await assert.rejects(sdk().exchange('example-code','v'.repeat(43)),e=>e instanceof NotifAuthError && e.code==='expired_code' && e.requestId==='req-1' && e.status===400);
 reply={status:429,headers:{'retry-after':'42'},body:{error:'invalid_request',error_code:'otp_too_soon',request_id:'req-2'}};
 await assert.rejects(sdk({clientSecret:'secret'}).sendOtp('22300000001'),e=>e.code==='otp_too_soon' && e.retryAfterSeconds===42 && e.status===429);
});
test('reports a non-JSON gateway failure as NotifAuthError',async()=>{
 reply={status:502,body:'<html>Bad gateway</html>'};
 await assert.rejects(sdk().exchange('example-code','v'.repeat(43)),e=>e instanceof NotifAuthError && e.code==='exchange_failed' && e.status===502);
});
test('server OTP requires the client secret and sends nothing without it',async()=>{
 const count=requests;
 await assert.rejects(sdk().sendOtp('22300000001'),e=>e.code==='missing_client_secret');
 await assert.rejects(sdk().verifyOtp('01JABCDEFGHJKMNPQRSTVWXYZ0','123456'),e=>e.code==='missing_client_secret');
 assert.equal(requests,count);
});
test('server OTP send posts the documented fields and returns the challenge',async()=>{
 const challenge=await sdk({clientSecret:'secret'}).sendOtp('22300000001',{endUserIp:'203.0.113.9',locale:'fr'});
 assert.deepEqual(lastBody,{path:'/server/otp/send',client_id:clientId,client_secret:'secret',phone_e164:'22300000001',end_user_ip:'203.0.113.9',locale:'fr'});
 assert.equal(challenge.challenge_id,'01JABCDEFGHJKMNPQRSTVWXYZ0');assert.equal(challenge.resend_after_seconds,60);
});
test('server OTP verify returns the verified signed profile',async()=>{
 responseToken=await token();
 const result=await sdk({clientSecret:'secret'}).verifyOtp('01JABCDEFGHJKMNPQRSTVWXYZ0','123456');
 assert.equal(lastBody.path,'/server/otp/verify');assert.equal(lastBody.challenge_id,'01JABCDEFGHJKMNPQRSTVWXYZ0');assert.equal(lastBody.code,'123456');
 assert.equal(result.phone_e164,profile.phone_e164);assert.equal(result.subject,'example-subject');
 reply={status:422,body:{error:'invalid_request',error_code:'otp_invalid',attempts_left:3}};
 await assert.rejects(sdk({clientSecret:'secret'}).verifyOtp('01JABCDEFGHJKMNPQRSTVWXYZ0','000000'),e=>e.code==='otp_invalid' && e.attemptsLeft===3);
});
test('server OTP verify rejects a forged token',async()=>{
 responseToken=await token({aud:'another-client'});
 await assert.rejects(sdk({clientSecret:'secret'}).verifyOtp('01JABCDEFGHJKMNPQRSTVWXYZ0','123456'));
});
