# Random-Bytes Generator on Cloudflare Worker
This is our Hash-based Key Derivator Function (HKDF) based on javascript's crypto module.

It is being used from some platforms that our clients use that cannot do Key Derivation.

The source code will be kept up to date here, but the actual live source code will also be on the endpoint.

It currently runs on a Cloudflare Worker so you can rest assured that nothing is being logged by us. It is intentionally not calculated on our servers so it remains impossible for us to have access to your data, even in the case of one of our servers being compromised, we still would not be able to decrypt your data.

The Cloudflare account where this Worker runs is secured by
* Cloudflare, of course, and their security policies.
* A long, cryptographically secure pseudorandom and secret email.
* A 4096 characters cryptographically secure pseudorandom and secret password with Letters, Numbers and Special Characters.
* Enforced Multi-factor authentication using a physical hardware security key from Yubico.
* Email notifications and alerts.
 
These secrets are not shared with employees, are not anywhere on the internet/cloud, they are stored using state of the art encryption offline and only 2 people have access to them.

We open sourced this random generator so our clients can audit and actually see what we are doing on the backend and they can rest assured that their values are not being logged or read by us.

Exposing the source code will not weaken security as, in reality, the actual Key Derivaton occurs in one simple piece of code:

```javascript
new Uint8Array(await crypto.subtle.exportKey('raw', 
  await crypto.subtle.deriveKey(
    {name: 'HKDF', salt: Salt, info: Info, hash: 'SHA-384'},
    await crypto.subtle.importKey('raw', Key, 'HKDF', false, ['deriveKey']),
    {name: 'HMAC', hash: "SHA-384", length: byteLength},
    true,
    ['sign']
  )
)).join()
```

Keep in mind that we can do all of this so easily because we are using Javascript's SubtleCrypto interface of the Web Crypto API which is a module that has been audited by many experts and is considered secure.

The rest of the code is meant for HMAC and Authentication, which means, our clients need to sign their requests to this API for that request to be Valid. They will also need 3 pre-shared unique secret keys that they can request to us:
* Custom header name
* Custom header value
* An HMAC super secret key


Additionally, we have setup a firewall to further enforce the following values:
* Custom header name
* Custom header value
* Request Origin and Referrer
* Allowed IP addresses (Logged by Cloudflare). These IPs need to be enabled on a client by client basis.

Note: Rate-Limiting is also enabled.

We are aware that all of this security and transparency just for a HKDF might be overkill for some, but it is meant to be representative on the fact that we take security, privacy and transparency very seriously for our clients, as even in a simple application like this one, we will be making no compromises.

Also, we won't be processing a lot of data with HMAC, so it shouldn't be very taxing to process requests.

You can read more about HMAC Authentication using Cloudflare Workers, here: https://developers.cloudflare.com/workers/examples/signing-requests/
