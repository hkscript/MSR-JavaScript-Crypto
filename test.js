msrCrypto = require('./lib/msrcrypto')
// var jwkToPem = require('jwk-to-pem')
console.log(msrCrypto)
var cry = msrCrypto;

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// var cry=crypto;cry.toBase64=msrCrypto.toBase64;
(async () => {
    let enc = new TextEncoder();
    let dec = new TextDecoder();
    cryptoKey = await cry.subtle.generateKey({
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }, true, ["encrypt", "decrypt"])

    console.log(cryptoKey)
    // priKey = await cry.subtle.exportKey('pkcs8', cryptoKey.privateKey);
    pubKey = await cry.subtle.exportKey('spki', cryptoKey.publicKey).catch(e => console.error(e));
    console.log("=========", pubKey, "=========")
    // pem=jwkToPem(pubKey)
    console.log(buf2hex(pubKey))
    pem=cry.toBase64(pubKey)
    console.log("=========", pem, "=========")


    pk = await cry.subtle.importKey(
        "spki",
        cry.fromBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmz61o9gRuBLmfUg7Av/35uuh4SiWnruVUX0DKl67J7qgZXf2xzxQHrbqZgRvdmlo8FzvGnWuzOclOyVwifOyUW2SOKr/YtkS6qjMMfjkRXquC1hpJtx5HzP9abTGrIaYB1ZLaHLhPU9+ae6KB+KM/BaiwcoXhd67VEaIs3oEcorYe92zePX8VndWccKtaLrJZqNBaFsTZxq6jbH3Roy13pVyqfxBZ13HiC3aSq3pTfKXJ7TOilEwOCnEwArJxolp9MWRGbyv2z1yrtijRfvGY2wIeH54VOWiHYo4Tff2vEz2uu+U0ZdY5AISBKKjNmOUrxRXckOSju+EtKAYjwtQVwIDAQAB"),
        { name: "RSA-OAEP", hash: "sha-256" },
        true,
        ["encrypt"])


    encrypted = await cry.subtle.encrypt(
        { name: "RSA-OAEP", label: new Int8Array([]) }
        , cryptoKey.publicKey
        , enc.encode("hello")
    ).catch(e => console.error(e))



    console.log(encrypted)

    data = await cry.subtle.decrypt(
        { name: "RSA-OAEP", label: new Int8Array([]) }
        , cryptoKey.privateKey
        , encrypted
        // , base642buf("mec92YP3/0hjYDEOuf/cUhbhPRW6tyH218K7kgl7CYKLCxAwEEP5mb1RKnCetZnco09Cx9cgqP5BJC9U342fK4Uzjq5txtcc7rpr3xrnAvGAyt9IHkc9D5LW/ggAyqaS6QmTVxIwAdEJK9QKbWhkbnzOuigNC/cb+hJuEUqWbP6Eab0LSZCp83q3H6kCZZjvU5QP1DCFZwTDnbzLQPYvk2INQQiQZ4EznMiFakN8PU8tT157+xAAAhRigXF4zQmxZZjQOIQvXNWdY26Rq5dxamtlqrHNX6BeNPFrZbuWF5TjgN6mwYJmjQdFNLf+rziWsuO0YBH4JqTr3AhiK3+yAw==")
        // , hex2buf("1d00ca095f18ec130c5f6883aa1a1ec756903bdfe7ee88d4d43cfc2f3ad68c03114ffb9de45dbc7c0a1cd2de9b53694ec63862b5bdd88fd228a510f88ecfd14fd7a8f344e81d1dd59c1b78277199ba5c0d02282b397b1b39538fbdba1d60ac177431ac1874e760174d555c50da2204edce0fef949c3db8d8aa4ed033487516374379a8dd99bec298510938a17e616618f38fb8316a0f330f48b46bce9868278d93741fe9d4449d62215c34118b656cd83aa530fb3b67b6941ff7fd5958001b3f196e9b5e0aef3e80c9b61bcd7908500281d04e9879a9b76c3da58648feda68f84e3c39fc7e4570f6cc47fb6b5bb90431643f3e99ad15058673c27be5536be42b")
    )

    console.log(dec.decode(data))


})();
