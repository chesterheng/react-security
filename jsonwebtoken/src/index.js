const jwt = require("jsonwebtoken");
const hmacSHA256 = require("crypto-js/hmac-sha256");
const Base64 = require("crypto-js/enc-base64");

const header = {
  alg: "HS256",
  typ: "JWT",
};
const payload = {
  sub: "1234567890",
  name: "John Doe",
  iat: 1516239022,
};
const jwtSecret = "secret123";
const encodingReplacements = {
  "+": "_",
  "/": "_",
  "=": "",
};
const makeUrlSafe = (encoded) =>
  encoded.replace(/[+/=]/g, (match) => encodingReplacements[match]);

const encode = (obj) => {
  const encoded = btoa(JSON.stringify(obj));
  return makeUrlSafe(encoded);
};

const makeSignature = (header, payload, secret) => {
  const hashed = hmacSHA256(`${encode(header)}.${encode(payload)}`, secret);
  const stringified = Base64.stringify(hashed);
  return makeUrlSafe(stringified);
};

const getJwt = (header, payload, signature) =>
  `${header}.${payload}.${signature}`;

// Anatomy of a JSON Web Token
const encodeHeader = encode(header);
const encodePayload = encode(payload);
const signature = makeSignature(header, payload, jwtSecret);
const manualToken = getJwt(encodeHeader, encodePayload, signature);

// Sign a JSON Web Token
const autoToken = jwt.sign(payload, jwtSecret);
