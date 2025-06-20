import { Router } from "express";
import user from "../helper/user.js";
import jwt from "jsonwebtoken";

const router = Router();

const CheckLogged = (req, res, next) => {
  const { token = null } = req.cookies;
  jwt.verify(token, process.env.JWT_SECRET, async (err, decode) => {
    if (decode?._id?.length === 24) {
      try {
        let userData = await user.get_user(decode?._id);

        if (userData) {
          res.status(208).json({
            status: 208,
            message: "Already Logged",
            data: userData,
          });
        }
      } catch (err) {
        console.log(err);
        res.clearCookie("token");
        next();
      }
    } else {
      res.clearCookie("token");
      next();
    }
  });
};

router.get("/checkLogged", CheckLogged, (req, res) => {
  res.status(405).json({
    status: 405,
    message: "User not logged",
  });
});

router.post("/register", CheckLogged, async (req, res) => {
  let { name, email, password, rePassword, google } = req.body;
  if (password?.length >= 8 && password === rePassword) {
    if (google) {
      try {
        let googleCheck = await axios.get(
          "https://www.googleapis.com/oauth2/v3/userinfo",
          {
            headers: {
              Authorization: `Bearer ${google}`,
            },
          }
        );

        if (
          googleCheck?.data?.email &&
          googleCheck?.data?.email?.toLowerCase() === email?.toLowerCase()
        ) {
          const response = await user.register_direct({
            name,
            email: email?.toLowerCase(),
            password,
          });

          res.status(200).json({
            status: 200,
            google: true,
            message: "Successfully Registered",
          });
        } else {
          res.status(500).json({
            status: 500,
            message: "Something Wrong",
          });
        }
      } catch (err) {
        res.status(500).json({
          status: 500,
          message: err,
        });
      }
    } else {
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        try {
          await user.register_direct({
            name,
            email: email.toLowerCase(),
            password,
          });
          res.status(200).json({
            status: 200,
            message: "Successfully Registered",
          });
        } catch (err) {
          res.status(500).json({
            status: 500,
            message: err,
          });
        }
      } else {
        res.status(422).json({
          status: 422,
          message: "Enter email",
        });
      }
    }
  } else {
    res.status(422).json({
      status: 422,
      message:
        "Password length must be at least 8 and passwords must match",
    });
  }
});

router.get("/login", CheckLogged, async (req, res) => {
  let { email, password, google } = req.query;

  if (google) {
    try {
      let googleCheck = await axios.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        {
          headers: {
            Authorization: `Bearer ${google}`,
          },
        }
      );

      if (googleCheck?.data?.email) {
        const response = await user.getUserByEmail(
          googleCheck.data.email?.toLowerCase()
        );

        let token = jwt.sign(
          {
            _id: response._id,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "24h",
          }
        );

        res
          .status(200)
          .cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 86400000),
          })
          .json({
            status: 200,
            message: "Success",
            data: response,
          });
      } else {
        res.status(500).json({
          status: 500,
          message: "Something Wrong",
        });
      }
    } catch (err) {
      res.status(500).json({
        status: 500,
        message: err,
      });
    }
  } else {
    if (email && password?.length >= 8) {
      try {
        const response = await user.login_manual(email.toLowerCase(), password);

        let token = jwt.sign(
          {
            _id: response._id,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "24h",
          }
        );

        res
          .status(200)
          .cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 86400000),
          })
          .json({
            status: 200,
            message: "Success",
            data: response,
          });
      } catch (err) {
        res.status(500).json({
          status: 500,
          message: err,
        });
      }
    } else {
      res.status(422).json({
        status: 422,
        message: "Email or Password Wrong",
      });
    }
  }
});

router.get("/logout", (req, res) => {
  res.clearCookie("token").status(200).json({
    status: 200,
    message: "LogOut",
  });
});

export default router;
