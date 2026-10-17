import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
export interface Profile {id:string;tenant_id:string;phone_e164:string;display_name:string|null;provider:'whatsapp'|'sandbox';mode:'LIVE'|'TEST';first_seen_at:string;metadata:Record<string,unknown>}
export interface Options {clientId:string;clientSecret?:string;issuer?:string;redirectUri?:string;allowSandbox?:boolean}
export interface Transaction {state:string;verifier:string;redirectUri:string}
/** Verified profile returned by complete(), exchange() and verifyOtp(). */
export type VerifiedProfile = Profile & {subject:string;token:string};
/** Response of POST /server/otp/send. A resend within the code lifetime keeps the same challenge_id. */
export interface OtpChallenge {challenge_id:string;phone_masked:string;expires_at:string;resend_after_seconds:number;sends_left:number}
export interface OtpOptions {/** IP address of the end user, used for per-user rate limits. */endUserIp?:string;locale?:string}
export interface NotifAuthErrorDetails {status?:number;retryAfterSeconds?:number;attemptsLeft?:number;cause?:unknown}
export class NotifAuthError extends Error {
  public readonly status?:number;
  public readonly retryAfterSeconds?:number;
  public readonly attemptsLeft?:number;
  constructor(public readonly code:string, public readonly requestId?:string, details:NotifAuthErrorDetails={}){
    super(`Notif Auth: ${code}`,details.cause===undefined?undefined:{cause:details.cause});this.name='NotifAuthError';
    this.status=details.status;this.retryAfterSeconds=details.retryAfterSeconds;this.attemptsLeft=details.attemptsLeft;
  }
}
type ApiBody = {token?:string;error?:string;error_code?:string;request_id?:string;retry_after_seconds?:number;attempts_left?:number} & Record<string,unknown>;
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
  async complete(code:string,state:string,transaction:Transaction):Promise<VerifiedProfile>{
    const a=Buffer.from(state),b=Buffer.from(transaction.state);
    if(a.length!==b.length || !timingSafeEqual(a,b))throw new NotifAuthError('invalid_state');
    return this.exchange(code,transaction.verifier,transaction.redirectUri);
  }
  async exchange(code:string,codeVerifier:string,redirectUri=this.options.redirectUri):Promise<VerifiedProfile>{
    if(!redirectUri)throw new NotifAuthError('missing_redirect_uri');
    const data=await this.post('/token',{grant_type:'authorization_code',client_id:this.options.clientId,client_secret:this.options.clientSecret,code,code_verifier:codeVerifier,redirect_uri:redirectUri},'exchange_failed');
    return this.signedProfile(data,'exchange_failed');
  }
  /** Server-to-server OTP (CONFIDENTIAL clients only): sends a six-digit code on WhatsApp to the number. */
  async sendOtp(phoneE164:string,options:OtpOptions={}):Promise<OtpChallenge>{
    const data=await this.post('/server/otp/send',{...this.credentials(),phone_e164:phoneE164,end_user_ip:options.endUserIp,locale:options.locale},'otp_send_failed');
    if(typeof data.challenge_id!=='string')throw new NotifAuthError('otp_send_failed',data.request_id);
    return {challenge_id:data.challenge_id,phone_masked:String(data.phone_masked),expires_at:String(data.expires_at),resend_after_seconds:Number(data.resend_after_seconds),sends_left:Number(data.sends_left)};
  }
  /** Checks the code of a sendOtp() challenge and returns the same verified profile as exchange(). */
  async verifyOtp(challengeId:string,code:string,options:Pick<OtpOptions,'endUserIp'>={}):Promise<VerifiedProfile>{
    const data=await this.post('/server/otp/verify',{...this.credentials(),challenge_id:challengeId,code,end_user_ip:options.endUserIp},'otp_verify_failed');
    return this.signedProfile(data,'otp_verify_failed');
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
  private credentials(){
    if(!this.options.clientSecret)throw new NotifAuthError('missing_client_secret');
    return {client_id:this.options.clientId,client_secret:this.options.clientSecret};
  }
  private async signedProfile(data:ApiBody,fallback:string):Promise<VerifiedProfile>{
    if(typeof data.token!=='string' || !data.token)throw new NotifAuthError(fallback,data.request_id);
    // Return the signed profile, never trust the unsigned duplicate in the body.
    const claims=await this.verify(data.token);
    return {...claims.profile,subject:claims.sub,token:data.token};
  }
  private async post(path:string,body:Record<string,unknown>,fallback:string):Promise<ApiBody>{
    let response:Response;
    try {response=await fetch(`${this.issuer}${path}`,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});}
    catch(cause){throw new NotifAuthError('network_error',undefined,{cause});}
    let data:ApiBody={};
    try {const parsed=await response.json();if(parsed && typeof parsed==='object')data=parsed as ApiBody;}
    catch(cause){if(response.ok)throw new NotifAuthError(fallback,undefined,{status:response.status,cause});}
    if(!response.ok){
      const header=Number(response.headers.get('retry-after'));
      const retryAfterSeconds=typeof data.retry_after_seconds==='number'?data.retry_after_seconds:Number.isFinite(header) && header>0?header:undefined;
      throw new NotifAuthError(data.error_code || data.error || fallback,data.request_id,{status:response.status,retryAfterSeconds,attemptsLeft:typeof data.attempts_left==='number'?data.attempts_left:undefined});
    }
    return data;
  }
}
