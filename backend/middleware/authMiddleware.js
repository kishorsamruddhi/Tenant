const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { verifyAccessToken } = require("../controllers/token-handler");


const protect = (req, res, next) => {
  try {
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer ")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res
        .status(401)
        .json({ message: "Not authorized, no token provided" });
    }

    const decoded = verifyAccessToken(token);

    const user = decoded?.user;

    if (!mongoose.isValidObjectId(user._id)) {
      return res
        .status(401)
        .json({ message: "Invalid token: malformed user ID" });
    }

    req.user = new mongoose.Types.ObjectId(user._id);

    return next();
  } catch (error) {
    return res
      .status(401)
      .json({ message: error?.message || "Not authorized, token invalid" });
  }
};

module.exports = { protect };
