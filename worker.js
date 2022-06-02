(function () {

  // Developed and open sourced by Bethel Consulting Group Limited.
  // More information here: https://github.com/BethelConsultingDev/hash-based-key-derivator-function

  // TL;DR: This source code is so our clients can audit what our
  // Hash-based Key Derivator actually does on the backend
  // and can rest assured that their values are not being 
  // logged or read by us. 
  
  // Every part of the code is commented so that it is easy to understand even if you're not a programmer
  
  // If you are seeing this
  // * You used the wrong parameters
  // * You are not properly authenticated
  // * You just want to take a look at our source code :)

  
  // This line captures the full source code of this worker
  const SourceCode = '(' + arguments.callee.toString() + ')()';

  // This is going to help us encode data later on
  const encoder = new TextEncoder();


  // addEventListener basically listens for your requests and then
  // sends them to our handleRequest function
  // If something is wrong it will just show this entire source code
  // to the one making the request
  addEventListener("fetch", (event) => {
    event.respondWith(
      handleRequest(event.request).catch(

        // In the event there is an error, you will see the source code
        // If you're not authenticated, you will see the source code
        // If you open this worker's URL on a Web Browser, you will see the source code

        (err) => new Response(SourceCode, { status: 500 })
      )
    );
  });


  // We Derive your key on a single step. We do not log anything
  const HKDF = async (Key, Salt, Info, byteLength) => new Response(
    new Uint8Array(await crypto.subtle.exportKey('raw', 
      await crypto.subtle.deriveKey(
        {name: 'HKDF', salt: Salt, info: Info, hash: 'SHA-384'},
        await crypto.subtle.importKey('raw', Key, 'HKDF', false, ['deriveKey']),
        {name: 'HMAC', hash: "SHA-384", length: byteLength},
        true,
        ['sign']
      )
    )).join()
  );


  // Utility function to convert ByteString to Uint8Array
  // Taken from: https://developers.cloudflare.com/workers/examples/signing-requests/
  // Completely unmodified, we only changed the name of the function
  function ByteString_To_Uint8Array(byteString) {
    const ui = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; ++i) {
      ui[i] = byteString.charCodeAt(i);
    }
    return ui;
  }


  // Utility function to compare in constant time to prevent timing attacks.
  // Based on Salesforce's Buffer Equal Constant Time
  // https://github.com/salesforce/buffer-equal-constant-time/blob/master/index.js
  // Please read their license information here:
  // https://github.com/salesforce/buffer-equal-constant-time/blob/master/LICENSE.txt

  function Compare(a, b) {

    // If anything fails, it means the values were not valid or had some
    // sort of problem, so it will return false, meaning, the two values
    // are not the same
    try {

    // We need to encode a and b as fixed length raw bynary buffers
    // In this case it will encode everything as Unsigned Int Arrays
    a = encoder.encode(a);
    b = encoder.encode(b);


    // If the byte length is different, they are not the same values
    if(a.length !== b.length) {
      return false;
    }

    // We will check every byte of data within both values to make sure
    // they are the same.

    // In simple words, if two values are the same and we XOR them, the
    // result should be 0. XOR is a comparisson between 0s and 1s.
    // If we XOR two 0s, we get 0. If we XOR two 1s, we get 0
    var c = 0;
    for (let i = 0; i < a.length; i++) {
      /*jshint bitwise:false */
      c |= a[i] ^ b[i];
    }

    // At the end, if c is 0, it means both values were the same, if not
    // then they were different.
    return c === 0


    } catch (err) {
      return false;
    }
    
  }


  // This is where we will handle your request 
  // TL;DR: We will basically just authenticate you first and then start Derivating your Key
  // that you are requesting and give it to you as is
  async function handleRequest(request) {

    const { searchParams , pathname } = new URL(request.url);
    
    // Step 1: Authentication

    // Step 1a: Making sure you gave us everything we need on your request
    const psk = request.headers.has(AUTH_HEADER_KEY) ? request.headers.get(AUTH_HEADER_KEY) : undefined;
    let Key = searchParams.has('Key') ? searchParams.get('Key') : undefined; // If you're not using Uint8Array, it NEEDS to be in Base64 as it's more consistent
    let Salt = searchParams.has('Salt') ? searchParams.get('Salt') : undefined; // Needs to be Uint8Array.join()
    let Info = searchParams.has('Info') ? searchParams.get('Info') : undefined;
    let byteLength = searchParams.has('byteLength') ? Number(searchParams.get('byteLength')) : undefined;
    const receivedMacBase64 = request.headers.has('hmac') ? request.headers.get('hmac') : undefined;

    if (
        // Are you using the right method to reach us?
        request.method != "GET" || pathname != "/" || !pathname.startsWith("/array-key")
        
        // We make sure we actually have the data to both Authenticate you and Derivate your Key
        || Compare(psk, AUTH_HEADER_VALUE) || !receivedMacBase64 || !Key || !Salt || !Info || !isFinite(byteLength)

        // Now we make sure the Key Length is valid
        || byteLength <= 0 // It has to be higher than 0
        || byteLength > 1024 // It has to be lower than 1024 (We set this limit to prevent overloading the worker due to abuse)
        
    ) throw new Error;


    // From here, we will verify if you're authorized to use this API by using HMAC Authentication
    // Yes, we know it's overkill... But it's better than having someone abusing this API without authorization
    // We have also implemented rate-limiting and firewall rules in order to prevent abuse.
    // Also, we are hashing a small amount of data, so HMAC Authentication should not be very taxing

    // Step 1b: Importing the key that we'll use to verify you have access to this API
    const key =  await crypto.subtle.importKey(
      'raw',
      encoder.encode(SUPER_SECRET_KEY),
      { name: 'HMAC', hash: 'SHA-384' },
      false,
      ['verify']
    );


    // Step 1c: Build the string we will authenticate
    const dataToAuthenticate = `${pathname}~Key=${Key}~Salt=${Salt}~Info=${Info}~byteLength=${byteLength}~${AUTH_HEADER_KEY}=${AUTH_HEADER_VALUE}`;


    // Step 1d: Get the received MAC into a buffer type that crypto.subtle.verify() can read
    const receivedMac = ByteString_To_Uint8Array(atob(receivedMacBase64));


    // Step 1e: Finally, we verify what you sent to see if you're authorized
    const verified = await crypto.subtle.verify(
      'HMAC',
      key,
      receivedMac,
      encoder.encode(dataToAuthenticate)
    );


    // Step 1f: If you're not verified, you're out
    if (!verified) throw new Error;

    
    // Step 2: If you got this far, you are properly authenticated, so we will
    // Derive the key you requested and just give it to you as is
    Key = pathname.startsWith("/array-key") ? new Uint8Array(Key.split(',')) : ByteString_To_Uint8Array(atob(Key));
    Salt = new Uint8Array(Salt.split(','));
    Info = encoder.encode(Info);
    byteLength *= 8;
    return HKDF(Key, Salt, Info, byteLength)

  }
})();
