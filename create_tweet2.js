import got from 'got';
import crypto from 'crypto';
import OAuth from 'oauth-1.0a';
import qs from 'querystring';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const consumer_key = process.env.CONSUMER_KEY;
const consumer_secret = process.env.CONSUMER_SECRET;
const requestTokenURL = 'https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write';
const authorizeURL = new URL('https://api.twitter.com/oauth/authorize');
const accessTokenURL = 'https://api.twitter.com/oauth/access_token';
const oauth = OAuth({
  consumer: {

    // Twitter API
    key: '000000000000000000000',
    secret: '000000000000000000000000000000000'

  },
  signature_method: 'HMAC-SHA1',
  hash_function: (baseString, key) => crypto.createHmac('sha1', key).update(baseString).digest('base64')
});

// Daha önce paylaşılan haber başlıklarını saklamak için bir dizi oluşturun
const paylasilanHaberBasliklari = [];

async function input(prompt) {
  return new Promise(async (resolve, reject) => {
    rl.question(prompt, (out) => {
      rl.close();
      resolve(out);
    });
  });
}

async function requestToken() {
  const authHeader = oauth.toHeader(oauth.authorize({
    url: requestTokenURL,
    method: 'POST'
  }));

  const req = await got.post(requestTokenURL, {
    headers: {
      Authorization: authHeader["Authorization"]
    }
  });
  if (req.body) {
    return qs.parse(req.body);
  } else {
    throw new Error('Cannot get an OAuth request token');
  }
}

async function accessToken({
  oauth_token,
  oauth_token_secret
}, verifier) {
  const authHeader = oauth.toHeader(oauth.authorize({
    url: accessTokenURL,
    method: 'POST'
  }));
  const path = `https://api.twitter.com/oauth/access_token?oauth_verifier=${verifier}&oauth_token=${oauth_token}`
  const req = await got.post(path, {
    headers: {
      Authorization: authHeader["Authorization"]
    }
  });
  if (req.body) {
    return qs.parse(req.body);
  } else {
    throw new Error('Cannot get an OAuth request token');
  }
}

// Sadece belirli haber kaynaklarından gelen haberleri filtrelemek için bir fonksiyon
function isAllowedSource(sourceName) {
  const allowedSources = [
    'Sözcü',
    'DonanımHaber',
    'Google News',
    'Habertürk',
    'webtekno',
    'Milliyet',
    'Haberport',
    'ShiftDelete.Net',
    'Cumhuriyet',
    'T24',
    'Milli Gazete',
    'NTV',
    'Onedio',
  ];

  return allowedSources.includes(sourceName);
}

async function getRequest({
  oauth_token,
  oauth_token_secret
}) {
  const haberLinki = 'https://newsapi.org/v2/top-headlines?country=tr&category=technology&apiKey=787188c5c62648d5ab8441f64c23c1ef';
  const haberVerisi = await got(haberLinki).json();

  if (haberVerisi.articles && haberVerisi.articles.length > 0) {
    const sonHaber = haberVerisi.articles[0];

    // Haber kaynağını kontrol et
    if (sonHaber.source && isAllowedSource(sonHaber.source.name)) {
      // Daha önce paylaşılan bir haber mi kontrol et
      if (!paylasilanHaberBasliklari.includes(sonHaber.title)) {
        // Eğer daha önce paylaşılmamışsa, paylaşılan haber başlıklarına ekle
        paylasilanHaberBasliklari.push(sonHaber.title);

        const data = {
          "text": `${sonHaber.title}\n ${sonHaber.url}`
        };

        const endpointURL = 'https://api.twitter.com/2/tweets';
        const token = {
          key: oauth_token,
          secret: oauth_token_secret
        };

        const authHeader = oauth.toHeader(oauth.authorize({
          url: endpointURL,
          method: 'POST'
        }, token));

        const req = await got.post(endpointURL, {
          json: data,
          responseType: 'json',
          headers: {
            Authorization: authHeader["Authorization"],
            'user-agent': "v2CreateTweetJS",
            'content-type': "application/json",
            'accept': "application/json"
          }
        });

        if (req.body) {
          console.dir(req.body, { depth: null });
        } else {
          throw new Error('Unsuccessful request');
        }
      } else {
        console.log('Bu haber daha önce paylaşıldı.');
      }
    }
  }
}

(async () => {
  try {
    // Request token al
    const oAuthRequestToken = await requestToken();
    // Yetkilendirme al
    authorizeURL.searchParams.append('oauth_token', oAuthRequestToken.oauth_token);
    console.log('Lütfen şuraya gidin ve yetkilendirin:', authorizeURL.href);
    const pin = await input('PIN\'i buraya yapıştırın: ');
    // Erişim token'ı al
    const oAuthAccessToken = await accessToken(oAuthRequestToken, pin.trim());

    // Her 10 saniyede bir getRequest fonksiyonunu çağırmak için setInterval kullan
    setInterval(async () => {
      await getRequest(oAuthAccessToken);
    }, 100000);

  } catch (e) {
    console.log(e);
    process.exit(-1);
  }
})();
