require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
//const randomString = require("crypto-random-string");
const User = require("./models/userRegistraion");
const AccessToken = require("./models/accessToken");
const Address = require("./models/address");

const router = express.Router();
const app = express();
app.use(bodyParser.json());
app.use(router);

mongoose
  .connect(process.env.DATABASE_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    reconnectTries: 3,
    reconnectInterval: 500,
    useFindAndModify: false,
  })
  .then(() => {
    console.log("Link established to database");
  })
  .catch((err) => {
    console.log("No link to database.", err);
  });

router.post("/user/register", async (req, res) => {
  try {
    let {
      firstName,
      secondName,
      userName,
      password,
      confirmPassword,
      email,
    } = req.body;
    let validatedPassword;
    if (password === confirmPassword) {
      validatedPassword = await bcrypt.hash(password, 10);
    } else {
      throw "password did not match";
    }
    let userRecord = await User.findOne({
      $or: [{ email: email }, { userName: userName }],
    });
    if (userRecord) {
      console.log("user");
      throw "username or email is already exist";
    }

    let userData = {
      firstName: firstName,
      secondName: secondName,
      userName: userName,
      password: validatedPassword,
      email: email,
    };
    let user = new User(userData);
    await user.save();

    res.json({
      error: 0,
      message: "registered successfully",
      data: null,
    });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

router.post("/user/login", async (req, res) => {
  try {
    let username = req.body.username;
    let password = req.body.password;
    const user = await User.findOne({ userName: username });
    if (!user) {
      throw "user not found";
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      throw "not a valid password";
    }
    var accessToken = randomString({ length: 20, type: "base64" });
    let accessTokenData = {
      userId: user._id,
      accessToken: accessToken,
    };
    let tokendata = new AccessToken(accessTokenData);
    await tokendata.save();

    res.json({
      error: 0,
      message: "successfully login",
      data: [
        {
          token: accessToken,
          userId: user._id,
        },
      ],
    });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

router.get("/user/get/:id", verifyToken, async (req, res) => {
  try {
    User.findOne({ _id: req.params.id })
      .populate("addresses")
      .then((user) => {
        res.json({
          error: 0,
          message: "fetched data successfully",
          data: [user],
        });
      });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

router.put("/user/delete", verifyToken, async (req, res) => {
  try {
    await User.findOneAndDelete({
      _id: req.headers.token,
    });
    res.json({
      error: 0,
      message: "user deleted successfully",
      data: null,
    });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

router.get("/user/list/:page", verifyToken, async (req, res) => {
  try {
    let skip = req.params.page * 10;
    const userList = await User.find().skip(skip).limit(10);
    res.json({
      error: 0,
      message: "user list",
      data: [userList],
    });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

router.post("/user/address", verifyToken, async (req, res) => {
  try {
    let { address, city, state, pinCode, phone } = req.body;
    let userId = req.headers.token;
    let userAddress = {
      userId: userId,
      address: address,
      city: city,
      state: state,
      pinCode: pinCode,
      phone: phone,
    };
    const userAddressData = new Address(userAddress);
    const addressData = await userAddressData.save();
    await User.findOneAndUpdate(
      { _id: addressData.userId },
      { $push: { addresses: addressData._id } },
      { new: true }
    );
    res.json({
      error: 0,
      message: "address successfully saved",
      data: null,
    });
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
});

async function verifyToken(req, res, next) {
  try {
    const token = await AccessToken.findOne({ accessToken: req.headers.token });
    if (!token) {
      throw "invalid token";
    }
    const expiryTime = new Date(token.expiry).valueOf();
    const currentTime = Date.now();
    if (currentTime > expiryTime) {
      await AccessToken.findOneAndDelete({ _id: token._id });
      throw "token is expired , login again";
    }
    next();
  } catch (error) {
    res.json({
      err: 1,
      message: error.message,
      error,
    });
  }
}

app.listen(3000, () => {
  console.log("connected ");
});
