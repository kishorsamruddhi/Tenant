const jwt = require("jsonwebtoken");

const ACCESS_TOKEN_SECRET =
  process?.env?.ACCESS_TOKEN_SECRET || "ACCESS_TOKEN_SECRET";
const ACCESS_TOKEN_EXPIRE_IN = process?.env?.ACCESS_TOKEN_EXPIRE_IN || "30s";

const REFRESH_TOKEN_SECRET =
  process?.env?.REFRESH_TOKEN_SECRET || "REFRESH_TOKEN_SECRET ";
const REFRESH_TOKEN_EXPIRE_IN = process?.env?.REFRESH_TOKEN_EXPIRE_IN || "7d";

function generateAccessToken({ _id, name, email }) {
  return jwt.sign({ user: { _id, name, email } }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRE_IN,
    algorithm: "HS256",
  });
}

function generateRefreshToken(userId) {
  return jwt.sign({ userId }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRE_IN,
    algorithm: "HS256",
  });
}

function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_TOKEN_SECRET, {}, function (err, decoded) {
    if (err) {
      throw new Error(err?.message);
    } else {
      return decoded;
    }
  });
}

function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_TOKEN_SECRET, {}, function (err, decoded) {
    if (err) {
      throw new Error(err?.message);
    } else {
      return decoded;
    }
  });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
