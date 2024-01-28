import express from "express";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const db = new pg.Client({
  connectionString:
    "postgresql://josephiannuzzelli4561:f5LIBtRr7OQF@ep-billowing-morning-02647692.us-east-2.aws.neon.tech/Users?sslmode=require",
});
db.connect()
  .then(() => console.log("Connected to Database!"))
  .catch((e) => console.log(e));

const app = express();
const port = 3000;

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

app.get("/api/apikey", async (req, res) => {
  try {
    const apikey = uuidv4();
    const checkIfApikey = await db.query(
      "SELECT * FROM apikeys WHERE apikeyid = $1",
      [apikey]
    );
    if (checkIfApikey.rows.length > 0) {
      return res.status(406);
    }
    await db.query("INSERT INTO apikeys(apikeyid) VALUES($1)", [apikey]);
    return res.json({ apikey: apikey });
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    type signupDetails = {
      apikey: string;
      username: string;
      password: string;
      email: string;
      fname: string;
      lname: string;
    };
    const user: signupDetails = req.body;
    if (
      user.apikey &&
      user.username &&
      user.password &&
      user.email &&
      user.fname &&
      user.lname
    ) {
      const checkApiKey = await db.query(
        "SELECT * FROM apikeys WHERE apikeyid = $1",
        [user.apikey]
      );
      if (checkApiKey.rows.length <= 0) {
        return res.status(401);
      }
      const checkUsername = await db.query(
        "SELECT * FROM users WHERE username = $1 AND apisession = $2",
        [user.username, user.apikey]
      );
      const checkEmail = await db.query(
        "SELECT * FROM users WHERE email = $1 AND apisession = $2",
        [user.email, user.apikey]
      );
      if (checkEmail.rows.length <= 0 || checkUsername.rows.length <= 0) {
        return res.status(401);
      }

      const hashedPassword = await bcrypt.hash(user.password, 10);

      const userObject = await db.query(
        "INSERT INTO users(username, password, email, fname, lname, apisession) VALUES($1, $2, $3, $4, $5, $6) RETURNING username, email, fname, lname",
        [
          user.username,
          hashedPassword,
          user.email,
          user.fname,
          user.lname,
          user.apikey,
        ]
      );

      const userJWT = jwt.sign(
        userObject.rows[0],
        process.env.JWT_SECRET as string
      );
      return res.json({ userJWT: userJWT });
    } else {
      return res.status(404);
    }
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    type loginDetails = {
      apikey: string;
      username: string;
      password: string;
    };
    const user: loginDetails = req.body;
    if (user.apikey && user.username && user.password) {
      const checkApiKey = await db.query(
        "SELECT * FROM apikeys WHERE apikeyid = $1",
        [user.apikey]
      );
      if (checkApiKey.rows.length <= 0) {
        return res.status(401);
      }
      let checkUsername = await db.query(
        "SELECT * FROM users WHERE username = $1 AND apisession = $2",
        [user.username, user.apikey]
      );
      if (checkUsername.rows.length <= 0) {
        const checkEmail = await db.query(
          "SELECT * FROM users WHERE email = $1 AND apisession = $2",
          [user.username, user.apikey]
        );
        if (checkEmail.rows.length <= 0) {
          return res.status(401);
        }
        checkUsername = checkEmail;
      }

      const checkPassword = await bcrypt.compare(
        user.password,
        checkUsername.rows[0].password
      );

      if (checkPassword) {
        const userDetails = await db.query(
          "SELECT username, email, fname, lname FROM users WHERE userid = $1 AND apisession = $2",
          [checkUsername.rows[0].userid, user.apikey]
        );
        const userJWT = jwt.sign(
          userDetails.rows[0],
          process.env.JWT_SECRET as string
        );
        return res.json({ userJWT: userJWT });
      } else {
        return res.status(401);
      }
    } else {
      return res.status(404);
    }
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.post("/api/auth/getuser", async (req, res) => {
  try {
    type getUserDetails = {
      apikey: string;
      jwtKEY: string;
    };
    const user: getUserDetails = req.body;

    if (user.apikey && user.jwtKEY) {
      const userObject = jwt.verify(
        user.jwtKEY,
        process.env.JWT_SECRET as string
      );
      return res.json({ user: userObject });
    } else {
      return res.status(404);
    }
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.listen(port);
