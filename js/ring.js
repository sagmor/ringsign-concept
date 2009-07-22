/*
  option:
    members: array of RSAKey objects; 
    signer: index of the real signer;
    
    returns { v, [x] }
  
*/

function g (ki, x) {
  return ki.doPublic(x);
}

function E (key, x) {
  var i, aBlock;
  var bpb = 128 / 8;          // bytes per block
  var ct = new Array();;                                 // ciphertext

  ct = new Array();
  var expandedKey = new keyExpansion(hex2s(key));

  for (var block=0; block < x.length / bpb; block++) {
    aBlock = x.slice(block*bpb, (block+1)*bpb);
    ct = ct.concat(AESencrypt(aBlock, expandedKey));
  }

  return new BigInteger(byteArrayToHex(ct),16);
}

function Ei(key, c) {
   var bpb = 128 / 8;          // bytes per block
   var pt = new Array();                   // plaintext array
   var aBlock;                             // a decrypted block
   var block;                              // current block number
   
   var expandedKey = new prepare_decryption(hex2s(key));


   for (var block=0; block < c.length / bpb; block++) {
     aBlock = c.slice(block*bpb, (block+1)*bpb);
     pt = pt.concat(AESdecrypt(aBlock, expandedKey));
   }
   
   return new BigInteger(byteArrayToHex(pt),16);
}

// k = SHA1('').substring(8); x = (new BigInteger(512, new SecureRandom())).toByteArray(); c = E(k,x).toByteArray(); Ei(k,c).toByteArray() == x

// k = SHA1('').substring(8); x = getRandomBytes(128/8); c = hexToByteArray(E(k,x).toString(16)); hexToByteArray(Ei(k,c).toString(16))
// hexToByteArray(Ei(k,c).toString(16))


function ring_sign (message, members, signer) {
  
  function getRandValue() {
    return new BigInteger( byteArrayToHex(getRandomBytes(512/8)), 16);
  }
  
  function getXs(length) {
    a = new Array(length);
    for (var i=0; i < length; i++) {
      a[i] = getRandValue();
    }
    
    return a;
  }
  
  var k = SHA1(message).substring(8);
  
  var xs = getXs(members.length)
  xs[signer] = null;
  
  var glue = getRandomBytes(512/8);
  
  var a = E(k, glue)
  for (var j=0; j < signer; j++) {
    a = E(k, hexToByteArray(g(members[j], xs[j]).xor(a).toString(16)) );
  }

  var b = Ei(k, glue);

  for (var j=members.length-1; j > signer; j--) {
    b = Ei(k, hexToByteArray( g(members[j], xs[j]).xor(b).toString(16) ));
  }
  
  var yi = b.xor(a);
  
  signer_key = members[signer];
  
  xs[signer] = members[signer].doPrivate(yi);
  
  for (var i=0; i < xs.length; i++) {
    xs[i] = xs[i].toString(16);
  };
  
  return {
    'v': byteArrayToHex(glue),
    'x': xs
  };
}

function ring_valid (message, v, xss, keys) {
  var xs = new Array(xss.length); 
  var glue = hexToByteArray(v);
  
  for (var i=0; i < xss.length; i++) {
    xs[i] = new BigInteger(xss[i],16);
  };
  
  var k = SHA1(message).substring(8);
  
  var a = E(k, glue)
  for (var j=0; j < xss.length; j++) {
    a = E(k, hexToByteArray( g(keys[j], xs[j]).xor(a).toString(16) ));
  }
  
  window.console.log(a.toString(16));
  window.console.log(byteArrayToHex(glue).replace(/^0+/,''));
  
  return a.toString(16) == byteArrayToHex(glue).replace(/^0+/,'');
}

function hexToByteArray(hex) {
  
  if (!hex) return;
  
  if (hex.length % 2)
    hex = '0'+hex;

  var result = new Array(hex.length/2);

  for (var i=0; i<result.length; i++)
    result[i] = parseInt(hex.substring(i*2, i*2+2), 16);

  return result;
}