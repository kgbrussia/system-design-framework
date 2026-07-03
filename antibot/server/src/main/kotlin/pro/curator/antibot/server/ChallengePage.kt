package pro.curator.antibot.server

/**
 * The LOCAL, TEST-ONLY challenge page served at /v1/challenge/page (guide §14).
 *
 * Purpose: exercise the native -> WebView -> JS -> bridge round-trip only.
 * The JS reads `cid` and `n` from the query string, computes
 * sha256("curator:cid:n") — matching [pro.curator.antibot.protocol.ChallengeCrypto]
 * on the server — and returns it via the `AntiBotBridge` JS interface (and also
 * exposes it as window.__antibotAnswer for evaluateJavascript polling).
 *
 * A production challenge would be opaque/obfuscated and collect real browser
 * fingerprint signals; this one is deliberately reproducible so it can be tested.
 */
internal object ChallengePage {

    fun html(): String = PAGE

    private val PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AntiBot Challenge (test)</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; padding: 24px; }
  code { word-break: break-all; }
  .muted { color: #777; }
</style>
</head>
<body>
<h3>AntiBot challenge (test page)</h3>
<p class="muted">This local page only verifies the native&lt;-&gt;WebView&lt;-&gt;server integration.</p>
<p>challengeId: <code id="cid"></code></p>
<p>answer: <code id="out">computing…</code></p>
<script>
// Compact SHA-256 (works without a secure context, unlike crypto.subtle).
function sha256(ascii){
  function rightRotate(value, amount){ return (value>>>amount) | (value<<(32-amount)); }
  var mathPow=Math.pow, maxWord=mathPow(2,32), result='';
  var words=[], asciiBitLength=ascii.length*8;
  var hash=sha256.h=sha256.h||[], k=sha256.k=sha256.k||[], primeCounter=k.length;
  var isComposite={};
  for(var candidate=2; primeCounter<64; candidate++){
    if(!isComposite[candidate]){
      for(var i=0;i<313;i+=candidate){ isComposite[i]=candidate; }
      hash[primeCounter]=(mathPow(candidate,0.5)*maxWord)|0;
      k[primeCounter++]=(mathPow(candidate,1/3)*maxWord)|0;
    }
  }
  ascii+='\x80';
  while(ascii.length%64-56) ascii+='\x00';
  for(i=0;i<ascii.length;i++){
    var j=ascii.charCodeAt(i);
    if(j>>8) return;
    words[i>>2]|=j<<((3-i)%4)*8;
  }
  words[words.length]=((asciiBitLength/maxWord)|0);
  words[words.length]=(asciiBitLength);
  for(j=0;j<words.length;){
    var w=words.slice(j,j+=16);
    var oldHash=hash;
    hash=hash.slice(0,8);
    for(i=0;i<64;i++){
      var w15=w[i-15], w2=w[i-2];
      var a=hash[0], e=hash[4];
      var temp1=hash[7]
        + (rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25))
        + ((e&hash[5])^((~e)&hash[6]))
        + k[i]
        + (w[i]=i<16?w[i]:(
            w[i-16]
            + (rightRotate(w15,7)^rightRotate(w15,18)^(w15>>>3))
            + w[i-7]
            + (rightRotate(w2,17)^rightRotate(w2,19)^(w2>>>10))
          )|0
        );
      var temp2=(rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22))
        + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
      hash=[(temp1+temp2)|0].concat(hash);
      hash[4]=(hash[4]+temp1)|0;
    }
    for(i=0;i<8;i++){ hash[i]=(hash[i]+oldHash[i])|0; }
  }
  for(i=0;i<8;i++){
    for(j=3;j+1;j--){
      var b=(hash[i]>>(j*8))&255;
      result+=((b<16)?'0':'')+b.toString(16);
    }
  }
  return result;
}

(function(){
  var params = new URLSearchParams(location.search);
  var cid = params.get('cid') || '';
  var n = params.get('n') || '';
  document.getElementById('cid').textContent = cid;
  var answer = sha256('curator:' + cid + ':' + n);
  document.getElementById('out').textContent = answer;
  // Expose for evaluateJavascript polling.
  window.__antibotAnswer = answer;
  // Return through the native JS bridge if present.
  try {
    if (window.AntiBotBridge && typeof window.AntiBotBridge.onChallengeSolved === 'function') {
      window.AntiBotBridge.onChallengeSolved(answer);
    }
  } catch (e) {}
})();
</script>
</body>
</html>
""".trimIndent()
}
