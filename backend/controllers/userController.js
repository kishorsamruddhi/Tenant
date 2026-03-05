// controllers/userController.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/User.model");
const { Api_Erorr_Response, Api_Response } = require("./response-handler");

const {
  generateRefreshToken,
  generateAccessToken,
  verifyRefreshToken,
} = require("./token-handler");

// REGISTER USER ---------

const COOKIES_REFRESH_TOKEN_OPTIONS = {
  maxAge: 1 * 1000 * 60 * 60 * 24 * 7, 
  httpOnly: true,
  secure: true,
  path: "/auth/refresh",
};

const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res
        .status(400)
        .json(Api_Erorr_Response({ message: "User already exists" }));
    }

    const user = await User.create({
      name,
      email,
      password,
    });

    if (user) {
      const { _id, name, email } = user;
      const data = { _id, name, email };

      const refreshToken = generateRefreshToken(user._id);

      user.refreshToken = refreshToken;
      await user.save();

      res.cookie("refreshToken", refreshToken, COOKIES_REFRESH_TOKEN_OPTIONS);

      return res.status(201).json(
        Api_Response({
          user: data,
          token: generateAccessToken(data),
        }),
      );
    } else {
      return res
        .status(400)
        .json(Api_Erorr_Response({ message: "Invalid user data" }));
    }
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Server error during registration" });
  }
};

// LOGIN USER ---------

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne(
      { email },
      { _id: 1, name: 1, email: 1, password: 1 },
    );
    if (user === null) {
      return res
        .status(404)
        .json(Api_Erorr_Response({ message: "User not found" }));
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (user && isPasswordMatched) {
      const { _id, name, email } = user;
      const data = { _id, name, email };

      const refreshToken = generateRefreshToken(user._id);

      user.refreshToken = refreshToken;
      await user.save();

      res.cookie("refreshToken", refreshToken, COOKIES_REFRESH_TOKEN_OPTIONS);

      return res.json(
        Api_Response({
          user: data,
          token: generateAccessToken(data),
          refreshToken,
        }),
      );
    } else {
      return res
        .status(404)
        .json(Api_Erorr_Response({ message: "Incorrect Password" }));
    }
  } catch (error) {
    return res.status(400).json({ message: error?.message });
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) throw new Error("refreshToken not found in payload");

    const isJWTRefreshTokenValid = verifyRefreshToken(refreshToken);

    const user = await User.findOne(
      { _id: isJWTRefreshTokenValid.userId },
      { _id: 1, name: 1, email: 1, refreshToken: 1 },
    );
    if (!user) throw new Error("User not found");

    if (refreshToken !== user.refreshToken) {
      throw new Error("Refresh Token is not vaild.");
    }

    const { _id, name, email } = user;
    const newRefreshToken = generateRefreshToken(user._id);
    const newAccessToken = generateAccessToken({ _id, name, email });
    user.refreshToken = newRefreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, COOKIES_REFRESH_TOKEN_OPTIONS);
    return res.status(201).json(
      Api_Response({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      }),
    );
  } catch (error) {
    res.status(403).json(Api_Erorr_Response({ message: error?.message }));
  }
};

const logout = async (req, res) => {
  const { refreshToken } = req.body;

  await User.updateOne({ refreshToken }, { $set: { refreshToken: null } });

  res.sendStatus(204);
};

module.exports = {
  registerUser,
  loginUser,
  refresh,
  logout,
};
