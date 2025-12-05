const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const qs = require("querystring");
const { HttpsProxyAgent } = require("https-proxy-agent"); // Tambahkan ini

const app = express();
app.use(express.json());

const versionName = "2.48.22";
const versionCode = "24822";
const lang = "en_US";
const client = "web";
const channelCode = "webgp";
const serverNode = "sgp1";
const secret = "2018red8688RendfingerSxxd";

// Daftar proxy: IP:PORT:USERNAME:PASSWORD
const proxies = [];

// Pilih proxy random
function pickProxy() {
  const p = proxies[Math.floor(Math.random() * proxies.length)];
  const [host, port, username, password] = p.split(":");
  return { host, port, username, password };
}

function generateUUID(len = 50) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(
    { length: len },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join("");
}

function md5(x) {
  return crypto.createHash("md5").update(x).digest("hex");
}

function formatPem(key) {
  const formatted = key.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

function rsaEncrypt(rsaKey, password) {
  const pemKey = formatPem(rsaKey);

  const encTimestamp = (Date.now() + 2000).toString();

  const payload = {
    userPwd: password,
    timestamp: encTimestamp,
  };

  const json = JSON.stringify(payload);

  return {
    encrypted: crypto
      .publicEncrypt(
        {
          key: pemKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(json)
      )
      .toString("base64"),
  };
}

// Gunakan Axios instance tapi tanpa default baseURL karena nanti pakai proxy agent
async function requestWithProxy(url, data, proxy) {
  const { host, port, username, password } = proxy;
  const agent = new HttpsProxyAgent(
    `http://${username}:${password}@${host}:${port}`
  );

  return axios.post(url, qs.stringify(data), {
    httpsAgent: agent,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Api-Version": versionCode,
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    },
    timeout: 15000,
  });
}

async function getKey(username, uuid, timestamp) {
  const proxy = pickProxy(); // Pilih proxy baru
  const signString = `channelCode=${channelCode}&client=${client}&lang=${lang}&timestamp=${timestamp}&userName=${username}&uuid=${uuid}`;
  const sign = md5(signString + secret);

  const body = {
    userName: username,
    timestamp,
    uuid,
    client,
    lang,
    channelCode,
    versionName,
    versionCode,
    sign,
  };

  const res = await requestWithProxy(
    "https://twplay.redfinger.com/osfingerlogin/user/getKey.html",
    body,
    proxy
  );

  return res.data;
}

async function loginRedfinger({
  username,
  password,
  rsaPubKey,
  signKey,
  userId,
  uuid,
}) {
  const proxy = pickProxy();
  const timestamp = (Date.now() + 9000).toString();
  const signString = `channelCode=${channelCode}&client=${client}&lang=${lang}&timestamp=${timestamp}&userName=${username}&uuid=${uuid}`;
  const sign = md5(signString + secret);

  const hash1 = md5(`${userId}##${password}`);
  const token = md5(hash1 + signKey);

  const encryptedPwd = rsaEncrypt(rsaPubKey, { userPwd: password, timestamp });

  const url =
    `https://twplay.redfinger.com/osfingerlogin/user/v2/getUser.html?lang=${lang}&client=${client}&uuid=${uuid}` +
    `&versionName=${versionName}&versionCode=${versionCode}` +
    `&channelCode=${channelCode}&serverNode=${serverNode}` +
    `&htjJsEnv=h5&htjApp=universe&sign=${sign}`;

  const body = {
    userName: username,
    token,
    deviceLockCode: "",
    externalCode: "",
    newUserPwd: encryptedPwd,
    rsaPubKeyMd5: md5(rsaPubKey),
  };

  const res = await requestWithProxy(url, body, proxy);
  return res.data;
}

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.json({ status: "error", message: "email & password required" });

  try {
    const uuid = generateUUID();
    const timestamp = Date.now().toString();

    const keyData = await getKey(email, uuid, timestamp);

    if (keyData.resultCode !== 0) {
      return res.json({
        status: "error",
        message: "getKey failed",
        raw: keyData,
      });
    }

    const { rsaPubKey, signKey, userId } = keyData.resultInfo;

    const loginRes = await loginRedfinger({
      username: email,
      password,
      rsaPubKey,
      signKey,
      userId,
      uuid,
    });

    if (loginRes.resultCode !== 0) {
      return res.json({
        status: "error",
        message: loginRes.resultMsg,
        raw: loginRes,
      });
    }

    const session = loginRes.resultInfo.session;

    return res.json({
      status: "ok",
      userId,
      session,
    });
  } catch (err) {
    return res.json({
      status: "error",
      message: err.message,
    });
  }
});

app.listen(3000, () => {
  console.log("API berjalan di http://localhost:3000");
});
