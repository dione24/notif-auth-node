import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
export interface Profile {id:string;tenant_id:string;phone_e164:string;display_name:string|null;provider:'whatsapp'|'sandbox';mode:'LIVE'|'TEST';first_seen_at:string;metadata:Record<string,unknown>}
export interface Options {clientId:string;clientSecret?:string;issuer?:string;redirectUri?:string;allowSandbox?:boolean}
export interface Transaction {state:string;verifier:string;redirectUri:string}
export class NotifAuthError extends Error {
  constructor(public readonly code:string, public readonly requestId?:string){super(`Notif Auth: ${code}`);this.name='NotifAuthError';}
}
export class NotifAuth {
  private issuer:string;
  private jwks:ReturnType<typeof createRemoteJWKSet>;
  constructor(private readonly options:Options){
    this.issuer=options.issuer || 'https://auth.notif.ml';
    const url=new URL(this.issuer);
    if(url.protocol!=='https:' && !(url.protocol==='http:' && url.hostname==='localhost'))throw new NotifAuthError('insecure_issuer');
    if(url.pathname!=='/' || url.search || url.hash || url.username || url.password)throw new NotifAuthError('invalid_issuer');
    this.issuer=url.origin;
    this.jwks=createRemoteJWKSet(new URL(`${this.issuer}/.well-known/jwks.json`),{timeoutDuration:5000});
  }
  begin(redirectUri=this.options.redirectUri){
    if(!redirectUri)throw new NotifAuthError('missing_redirect_uri');
    const transaction={state:randomBytes(32).toString('base64url'),verifier:randomBytes(32).toString('base64url'),redirectUri};
    const query=new URLSearchParams({response_type:'code',client_id:this.options.clientId,redirect_uri:redirectUri,state:transaction.state,code_challenge_method:'S256',code_challenge:createHash('sha256').update(transaction.verifier).digest('base64url')});
    return {url:`${this.issuer}/authorize?${query}`,transaction};
  }
  async complete(code:string,state:string,transaction:Transaction){
    const a=Buffer.from(state),b=Buffer.from(transaction.state);
    if(a.length!==b.length || !timingSafeEqual(a,b))throw new NotifAuthError('invalid_state');
    return this.exchange(code,transaction.verifier,transaction.redirectUri);
  }
  async exchange(code:string,codeVerifier:string,redirectUri=this.options.redirectUri){
    if(!redirectUri)throw new NotifAuthError('missing_redirect_uri');
    const response=await fetch(`${this.issuer}/token`,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:this.options.clientId,client_secret:this.options.clientSecret,code,code_verifier:codeVerifier,redirect_uri:redirectUri}),signal:AbortSignal.timeout(10000)});
    const data=await response.json() as {token?:string;error?:string;error_code?:string;request_id?:string};
    if(!response.ok || !data.token)throw new NotifAuthError(data.error_code || data.error || 'exchange_failed',data.request_id);
    // Return the signed profile, never trust the unsigned duplicate in the body.
    const claims=await this.verify(data.token);
    return {...claims.profile,subject:claims.sub,token:data.token};
  }
  async verify(token:string):Promise<JWTPayload & {profile:Profile;sub:string}>{
    const {payload}=await jwtVerify(token,this.jwks,{issuer:this.issuer,audience:this.options.clientId,algorithms:['RS256'],requiredClaims:['sub','iat','exp','jti'],maxTokenAge:'15m',clockTolerance:5});
    const profile=payload.profile as Profile | undefined;
    if(!profile || typeof profile.phone_e164!=='string' || typeof profile.tenant_id!=='string' || !payload.sub)throw new NotifAuthError('invalid_profile');
    const allowTest=this.options.allowSandbox ?? this.options.clientId.startsWith('pk_test_');
    if(profile.mode==='TEST' && !allowTest)throw new NotifAuthError('sandbox_identity_rejected');
    if(!['TEST','LIVE'].includes(profile.mode) || (profile.mode==='TEST'?profile.provider!=='sandbox':profile.provider!=='whatsapp'))throw new NotifAuthError('invalid_profile');
    return payload as JWTPayload & {profile:Profile;sub:string};
  }
}
