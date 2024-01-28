import express from "express";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

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
    if (checkIfApikey) {
      return res.status(406);
    }
    await db.query("INSERT INTO apikeys(apikeyid) VALUES($1)", [apikey]);
    return res.json({ apikey: apikey });
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.listen(port);
