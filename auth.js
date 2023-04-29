const fs = require('fs');
const fetch = require('node-fetch');
const crypto = require('crypto');
const {decode, encode} = require('url-safe-base64');
const base64url = require('base64url');
const srpit = require('srpit');
const usersecrets = require('./usersecrets.json');

// User-defined information from usersecrets.json
const authNotes = false;
const domain = usersecrets.domain;
const email = usersecrets.email;
const secret = usersecrets.secret;
const password = usersecrets.password;
const accountID = usersecrets.accountID;
const deviceUuid = usersecrets.deviceUuid;
const userUuid = usersecrets.userUuid;

const skFormat = secret.substring(0,2);
const skId = secret.substring(3,9);
var authJson = {
    "email": email,
    "skFormat": skFormat,
    "skid": skId,
    "userUuid": userUuid,
    "deviceUuid": deviceUuid
};

var url = `https://${domain}/api/v3/auth/start`;
var headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
    "Accept-Language": "en", "Origin": `https://${domain}`, "Pragma": "no-cache",
    "op-user-agent": "1|B|1479|c3jubh5wh3t2fqzt6id4xeno54|||Chrome|111.0.0.0|Windows|10.0|", // TODO - might need to snatch this from an example request
    "sec-ch-ua": `"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"`, "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": `"Windows"`, "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin",
}

var sessionId, requestCnt, sessionHmac, hmac1_enc;
var myUserUuid, myAccountUuid;
var masterKeySet = {mp: {}, priKey: {}, pubKey: {}, spriKey: {}, spubKey: {}};

function b64encode(x) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(x)));
}

function toCharCode(s) {
    for (var bytes = new Uint8Array(s.length), c = 0; c < s.length; c += 1) {
        bytes[c] = s.charCodeAt(c);
    }
    return bytes;
}

function pad_512(arr) {
    var arr_padded = new Uint8Array(512);
    arr_padded.set(arr, 512 - arr.length);
    return arr_padded;
}

function hex2arr(h) {
    if (h.length % 2 == 1) {h = '0' + h;} // pad extra 0 in case
    var arr = new Uint8Array(h.length / 2);
    for (var i = 0; i < h.length-1; i += 2) {
	arr[i/2] = parseInt(h.slice(i, i+2), 16);
    }
    return arr;
}

function mod_pow(b, e, m) {
    var res = BigInt(1);
    while (e > 0) {
	if ((e % BigInt(2)) == BigInt(1)) {
	    res = BigInt(BigInt((res*b)) % m);
	}
	e = BigInt(e >> BigInt(1));
	b = (b*b) % m;
    }
    return res;
}

// HKDF, PBKDF2 for generating the AUK and SRP-x
async function derive_key(salt, method, iterations, name) {
    // Derive AUK or SRP-x
    if (authNotes) console.log(`\n*** Deriving ${name} ***`);
    if (authNotes) console.log(`salt: ${salt}`);

    // Step 5
    salt = toCharCode(atob(decode(salt)));
    var method_ab = toCharCode(method);
    var email_ab = toCharCode(email);
    var s = crypto.hkdfSync('sha256', salt, email, method_ab, 32);
    if (authNotes) console.log(`[Step 5] s: ` + new Uint8Array(s));

    // Step 6
    var pass_ab = toCharCode(password);
    var k_m = crypto.pbkdf2Sync(pass_ab, s, iterations, 32, 'sha256');
    if (authNotes) console.log(`[Step 6] k_m: ` + new Uint8Array(k_m));

    // Step 7
    var secret_ab = toCharCode(secret.slice(9).replace(/-/g, ''));
    method_ab = toCharCode(skFormat);
    accountID_ab = toCharCode(skId);
    var k_a = crypto.hkdfSync('sha256', secret_ab, accountID_ab, method_ab, 32);
    if (authNotes) console.log(`[Step 7] k_a: ` + new Uint8Array(k_a));

    // Step 8
    var ka_arr = new Uint8Array(k_a);
    var km_arr = new Uint8Array(k_m);
    for (var k_out = new Uint8Array(32), c = 0; c < 32; c += 1) {
        k_out[c] = ka_arr[c] ^ km_arr[c];
    }
    key_out = Buffer.from(k_out).toString('hex');
    if (authNotes) console.log(`k_out = ${k_out}\n${name} = ${key_out}\n*** End of derivation ***\n`);
    return key_out;
}

async function start() {
    const requestOptions = {method: 'POST', headers: headers, body: JSON.stringify(authJson)};
    var respJson;
    await fetch(url, requestOptions).then(response => response.json()).then(data => {respJson = data;});
    sessionId = respJson.sessionID; // TODO - manual add-in for testing
    if (authNotes) console.log(respJson); 
    if (authNotes) console.log("\n\nDeriving SRP-x");
    if (authNotes) console.log("---------------------------------------------------");

    var userAuth = respJson.userAuth;
    srp_x = await derive_key(userAuth.salt, userAuth.method, userAuth.iterations, 'SRP-x');

    // calculate big A
    if (authNotes) console.log("\n\nDeriving Session Key");
    if (authNotes) console.log("---------------------------------------------------");
    var little_a = await crypto.randomBytes(32);
    little_a_hex = little_a.toString('hex'); // TODO - manual add-in for testing
    params = srpit.PARAMS["4096"];
    little_a = BigInt('0x' + little_a_hex);
    big_a = mod_pow(BigInt(params.g), little_a, BigInt(params.N));
    little_a_hex = little_a.toString(16);
    big_a_hex = big_a.toString(16);
    if (authNotes) console.log(`g: ${params.g}\nn: ${params.N.toString(16)}\n\nlittle_a: ${little_a_hex}\n\nbig_a: ${big_a_hex}\n`);
    
    // Send big_a to server and receive big_b
    headers['x-agilebits-session-id'] = sessionId;
    const requestOptions2 = {method: 'POST', headers: headers, body: JSON.stringify({"userA": big_a_hex})};
    var url2 = `https://${domain}/api/v2/auth`;
    var v2AuthRespJson;
    await fetch(url2, requestOptions2).then(response => response.json()).then(data => {v2AuthRespJson = data;});
    big_b_hex = v2AuthRespJson.userB; // TODO - manual add-in for testing
    if (authNotes) console.log(`big_b: ${big_b_hex}\n`);

    // prepare integers for hashing to calculate k and u
    N_b = pad_512(hex2arr(params.N.toString(16)));
    g_b = pad_512(hex2arr(params.g.toString(16)));
    A_b = pad_512(hex2arr(big_a_hex));
    B_b = pad_512(hex2arr(big_b_hex));
    if (authNotes) console.log(`N_b (${N_b.length})\ng_b (${g_b.length})\nA_b (${A_b.length})\nB_b (${B_b.length})\n`);
    
    // calculate k = Sha256(N || g)
    const hash1 = await crypto.createHash('sha256');
    hash1.update(N_b);
    hash1.update(g_b);
    k = hash1.digest().toString('hex');
    k_i = BigInt('0x' + k);
    if (authNotes) console.log(`k: ${k}`);

    // calculate u = Sha256(A || B)
    const hash2 = await crypto.createHash('sha256');
    hash2.update(A_b);
    hash2.update(B_b);
    u = hash2.digest().toString('hex');
    u_i = BigInt('0x' + u);
    if (authNotes) console.log(`u: ${u}`);
    
    // calculate exp = a + u*x
    srp_x_i = BigInt('0x' + srp_x);
    var exp = (little_a + (u_i * srp_x_i)) % BigInt(params.N);
    if (authNotes) console.log(`\nexp: ${exp.toString(16)}\n`);

    // calculate base = B - k*(g^x)
    big_b_i = BigInt('0x' + big_b_hex);
    v = mod_pow(BigInt(params.g), srp_x_i, BigInt(params.N));
    var base = (big_b_i - ((k_i * v) % BigInt(params.N))) % BigInt(params.N);
    if (authNotes) console.log(`base: ${base.toString(16)}\n`);

    // calculate sessionKey = base^exp
    var sessionKey = mod_pow(base, exp, BigInt(params.N));
    const hash3 = await crypto.createHash('sha256');
    hash3.update(sessionKey.toString(16));
    sessionKey_hashed = hash3.digest().toString('hex');
    if (authNotes) console.log(`sessionKey: ${sessionKey_hashed}\n`);

    // import sessionKey & export key as JWK
    var sKey_imported = await crypto.subtle.importKey("raw", hex2arr(sessionKey_hashed), {name: 'AES-GCM', length: 256}, true, ["encrypt", "decrypt"]);
    var sKey_jwk = await crypto.subtle.exportKey('jwk', sKey_imported); 
    if (authNotes) console.log(sKey_jwk);
    
    // derive HMAC 
    if (authNotes) console.log("\n\nDeriving Verification Properties");
    if (authNotes) console.log("---------------------------------------------------");
    const hmac1 = await crypto.createHmac('sha256', hex2arr(sessionKey_hashed)); 
    hmac1.update('He never wears a Mac, in the pouring rain. Very strange.');
    hmac1_enc = hmac1.digest();
    if (authNotes) console.log(`hmac1: ${hmac1_enc.toString('hex')}`);
    sessionHmac = await crypto.createHmac('sha256', hmac1_enc); 
    
    // derive clientVerifyHash and serverVerifyHash
    const hash4 = await crypto.createHash('sha256'), hash5 = await crypto.createHash('sha256');
    const hash6 = await crypto.createHash('sha256'), hash7 = await crypto.createHash('sha256');
    const hash8 = await crypto.createHash('sha256');
   
    // clientVerifyHash
    hash4.update(respJson.accountKeyUuid);
    hash5.update(sessionId);
    var sessIdHash = hash5.digest();
    hash6.update(hash4.digest());
    hash6.update(sessIdHash);
    var clientVerifyHash = hash6.digest();
    if (authNotes) console.log(`\nclientVerifyHash: ${base64url(clientVerifyHash)}`);
   
    // serverVerifyHash
    hash7.update(base64url(clientVerifyHash));
    var hash7_test = hash7.digest();
    hash8.update(sessIdHash);
    hash8.update(hash7_test);
    var serverVerifyHash = hash8.digest();
    if (authNotes) console.log(`serverVerifyHash: ${base64url(serverVerifyHash)}\n`);
    
    // derive MAC header
    requestCnt = 1;
    var macMessage = `${sessionId}|POST|${domain}/api/v2/auth/verify?|v1|${requestCnt}`;
    if (authNotes) console.log(`macMessage: ${macMessage}`);
    sessionHmac.update(macMessage);
    sessionHmac_out = sessionHmac.digest().slice(0,12);
    sessionHmac_out_enc = base64url(sessionHmac_out); 
    var macHeader = `v1|${requestCnt}|${sessionHmac_out_enc}`;
    if (authNotes) console.log(`hmac2_out: ${sessionHmac_out.toString('hex')}\nX-AgileBits-MAC: ${macHeader}\n`);

    // create verify JSON and encrypt it
    vfJson = {
    	"sessionId": sessionId,
    	"clientVerifyHash": base64url(clientVerifyHash),
    	"client": "1Password Extension/20242",
    	"device": {
            "uuid": deviceUuid, "clientName": "1Password Extension", "clientVersion": "20242",
            "name": "Chrome", "model": "111.0.0.0", "osName": "Windows", "osVersion": "10.0",
            "userAgent": headers["User-Agent"], "fromDeviceInit": true
    	}
    };
    if (authNotes) console.log(JSON.stringify(vfJson));
    
    vfJsonArr = JSON.stringify(vfJson);
    vfIv = await crypto.randomBytes(12); // TODO - manual add-in for testing --- hex2arr(<iv_hex>)
    var cipher = await crypto.createCipheriv('aes-256-gcm', sKey_imported, vfIv);
    var vfJsonArr_enc = cipher.update(vfJsonArr, 'utf8', 'hex');
    vfJsonArr_enc += cipher.final('hex');
    var vfAuthTag = cipher.getAuthTag();
    if (authNotes) console.log(`\nvfJsonArr_enc: ${vfJsonArr_enc}\n\nvfAuthTag: ${vfAuthTag.toString('hex')}`);

    // send verification JSON
    if (authNotes) console.log("\n\nSending Verification");
    if (authNotes) console.log("---------------------------------------------------");
    data_buff = Buffer.from(vfJsonArr_enc + vfAuthTag.toString('hex'), 'hex');
    vfJson_enc = {
	"kid": sessionId,
	"enc": "A256GCM",
	"cty": "b5+jwk+json",
	"iv": base64url(vfIv),
	"data": base64url(data_buff)
    };

    headers['x-agilebits-mac'] = macHeader;
    const requestOptions3 = {method: 'POST', headers: headers, body: JSON.stringify(vfJson_enc)};
    var url3 = `https://${domain}/api/v2/auth/verify`;
    var v2AuthVerifyRespJson;
    await fetch(url3, requestOptions3).then(response => response.json()).then(data => {v2AuthVerifyRespJson = data;});
    if (authNotes) console.log(v2AuthVerifyRespJson);

    if (v2AuthVerifyRespJson.iv == undefined) {
	return;
    }
 
    // decrypt and check server verification token
    serverVfCt_dec = await aes_gcm_decrypt(v2AuthVerifyRespJson.iv, sKey_imported, v2AuthVerifyRespJson.data);
    var serverVfJson = JSON.parse(serverVfCt_dec)
    if (authNotes) console.log(serverVfJson);
    
    if (serverVfJson.serverVerifyHash !== base64url(serverVerifyHash)) {
	console.log(`ruh roh raggy.... verification failed\n${serverVfJson.serverVerifyHash} !== ${base64url(serverVerifyHash)}`);
	return;
    }

    myUserUuid = serverVfJson.userUuid;
    myAccountUuid = serverVfJson.accountUuid;

    api_tests(sKey_imported);
}

async function send_enc_request(endpoint, method, key, params, body, debug=false) {
    const url = new URL(`https://${domain}${endpoint}`);
    url.search = new URLSearchParams(params);
    console.log("\n---------------------------------------------------");
    console.log(`Sending ${method} request to ${endpoint}${url.search}`);
    var params_enc = (url.search.length == 0 ? '?' : url.search);

    // derive MAC header
    requestCnt += 1;
    sessionHmac = await crypto.createHmac('sha256', hmac1_enc);
    var macMessage = `${sessionId}|${method}|${domain}${endpoint}${params_enc}|v1|${requestCnt}`;
    //console.log(`macMessage: ${macMessage}`);
    sessionHmac.update(macMessage);
    sessionHmac_out = sessionHmac.digest().slice(0,12);
    sessionHmac_out_enc = base64url(sessionHmac_out);
    var macHeader = `v1|${requestCnt}|${sessionHmac_out_enc}`;
    //console.log(`sessionHmac_out: ${sessionHmac_out.toString('hex')}\nX-AgileBits-MAC: ${macHeader}\n`);
    headers['x-agilebits-mac'] = macHeader;

    var options, response;
    if (method === "PATCH" || method === "POST" || method == "PUT") {
	// encrypt body
    	ivGen = await crypto.randomBytes(12);
    	var cipher = await crypto.createCipheriv('aes-256-gcm', masterKeySet.sessionKey, ivGen);
    	var bodyCt = cipher.update(JSON.stringify(body), 'utf8', 'hex');
    	bodyCt += cipher.final('hex');
    	var authTag = cipher.getAuthTag();

	//console.log(sessionId);
	data_buff = Buffer.from(bodyCt + authTag.toString('hex'), 'hex');
	newBody = {cty: 'b5+jwk+json', enc: 'A256GCM', data: base64url(data_buff), kid: sessionId, iv: base64url(ivGen)};
	//console.log(newBody); 
	options = {method: method, headers: headers, body: JSON.stringify(newBody)};
	//console.log(method);
    } else {
	options = {method: method, headers: headers};
    }

    // send request
    if (debug) {
	await fetch(url, options).then(data => {response = data;});
	console.log(response.status);
	var retJson = await response.json();
	console.log(response.statusText);
	return retJson;
    } 
    await fetch(url, options).then(resp => resp.json()).then(data => {response = data;});

    if (response.iv == undefined) {
        console.log("iv undefined");
	console.log(response.status);
	return response;
    }

    // decrypt response
    iv = base64url.toBuffer(response.iv);
    data = base64url.toBuffer(response.data);
    ct = data.slice(0, -16);
    tag = data.slice(-16);

    ciph = await crypto.createDecipheriv('aes-256-gcm', key, iv);
    pt = ciph.update(ct, 'utf8', 'utf8');
    ptJson = JSON.parse(pt);
    //console.log(pt);
    return ptJson;
}

async function aes_gcm_decrypt(iv, key, data) {
    iv = base64url.toBuffer(iv);
    data = base64url.toBuffer(data);
    ct = data.slice(0, -16);
    tag = data.slice(-16);
    ciph = await crypto.createDecipheriv('aes-256-gcm', key, iv);
    pt = ciph.update(ct, 'utf8', 'utf8');
    return pt;
}

async function decrypt_vault_item(itemInfo, vaultKey) {
    console.log(`decrypting vault item ${itemInfo.uuid}`);
    pt = await aes_gcm_decrypt(itemInfo.encDetails.iv, vaultKey, itemInfo.encDetails.data);
    ptJson = JSON.parse(pt);
    return ptJson;
}

async function decrypt_vault_key(vaultInfo) {
    console.log(`decrypting vault key for ${vaultInfo.vaultUuid}`);
    
    var encKeyJson = vaultInfo.encVaultKey;
    var priKey = masterKeySet.priKey;
    
    data = base64url.toBuffer(encKeyJson.data);
    dec = await crypto.privateDecrypt(priKey, data);
    decJson = JSON.parse(Buffer.from(dec).toString('utf8')); 
    console.log(decJson);

    importedKey = await crypto.subtle.importKey("jwk", decJson, {name: 'AES-GCM', length: 256}, true, ["encrypt", "decrypt"]);
    return importedKey;
}

async function decrypt_keyset(sessionKey, keysetsJson) {
    console.log("decrypting keys baby!");
    if (authNotes) console.log(keysetsJson);
    var key_enc, iv, data, ct, tag, ciph, pt;

    // Derive AUK - same method as SRP-x
    var encSymKey = keysetsJson.keysets[0].encSymKey;
    auk = await derive_key(encSymKey.p2s, 'PBES2g-HS256', encSymKey.p2c, 'AUK');

    // Decrypt Master Password
    auk_key = await crypto.subtle.importKey("raw", hex2arr(auk), {name: 'AES-GCM', length: 256}, true, ["encrypt", "decrypt"]);
    pt = await aes_gcm_decrypt(encSymKey.iv, auk_key, encSymKey.data)
    mp_jwk = JSON.parse(pt)
    console.log(`kid: ${mp_jwk.kid}`);
    mp_key = await crypto.subtle.importKey("jwk", mp_jwk, {name: 'AES-GCM', length: 256}, true, ["encrypt", "decrypt"]);
    masterKeySet.mp = mp_key;
    masterKeySet.sessionKeyKid = mp_jwk.kid;

    // Use Master Password to decrypt encPriKey
    var encPriKey = keysetsJson.keysets[0].encPriKey;
    pt = await aes_gcm_decrypt(encPriKey.iv, mp_key, encPriKey.data);
    priKey_jwk = JSON.parse(pt);
    priKey_key = await crypto.subtle.importKey("jwk", priKey_jwk, {name: 'RSA-OAEP', hash: "SHA-1"}, true, ["decrypt"]);
    masterKeySet.priKey = priKey_key;

    // Use Master Password to decrypt pubKey
    masterKeySet.pubKey = keysetsJson.keysets[0].pubKey;

    // Use Master Password to decrypt encSPriKey
    var encSPriKey = keysetsJson.keysets[0].encSPriKey;
    pt = await aes_gcm_decrypt(encSPriKey.iv, mp_key, encSPriKey.data);
    spriKey_jwk = JSON.parse(pt);
    if (authNotes) console.log(spriKey_jwk);
    spriKey_key = await crypto.subtle.importKey("jwk", spriKey_jwk, {name: 'ECDSA', namedCurve: 'P-256'}, true, ["sign"]);
    masterKeySet.spriKey = spriKey_key;

    // Use Master Password to decrypt encSPriKey
    masterKeySet.spubKey = keysetsJson.keysets[0].spubKey;
    masterKeySet.sessionKey = sessionKey;
}

async function api_tests(sessionKey) {
    console.log("\n\nStarting API Testing");
    console.log("---------------------------------------------------");
    console.log(`\nMY INFO:\n\tUser Uuid: ${myUserUuid}\n\tAccount Uuid: ${myAccountUuid}\n`);

    // GET /api/v2/overview
    var overviewJson = await send_enc_request('/api/v2/overview', 'GET', sessionKey, {}, {});
    var vaults = overviewJson.vaults;
    console.log(overviewJson);

    // GET /api/v2/keysets
    var keysetsJson = await send_enc_request('/api/v2/account/keysets', 'GET', sessionKey, {}, {});
    var keysets = await decrypt_keyset(sessionKey, keysetsJson);
    console.log(keysetsJson);
}

start();
