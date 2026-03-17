const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

// 반드시 길고 복잡하게 바꾸세요
const JWT_SECRET = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_KEY_pururusepopandab0502;

// 실제 운영 시 아이디/비밀번호 바꾸세요
const OWNER_USERNAME = "owner";
// 비밀번호: warmhug1234
const OWNER_PASSWORD_HASH = "$2b$10$B6D5Yg8z2vWl4Q1ru4AfNuD3yyx8l5mYoS8N0nJ3P97s1KAAqQmH2";

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "private-data.json");

app.use(cors({
  origin: true,
  credentials: false
}));
app.use(express.json({ limit: "1mb" }));

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify({
        nickname: "",
        stats: { todayHugs: 0, weekWarmth: 0 },
        emotions: [],
        reports: 0,
        suspensions: 0,
        rooms: { friend: [], comfort: [], help: [] }
      }, null, 2),
      "utf8"
    );
  }
}

function readPrivateData() {
  ensureDataFile();
  const raw = fs.readFileSync(DATA_FILE, "utf8");
  return JSON.parse(raw);
}

function writePrivateData(data) {
  ensureDataFile();
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "인증이 필요합니다." });
  }

  const [type, token] = authHeader.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "토큰 형식이 올바르지 않습니다." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "유효하지 않은 토큰입니다." });
  }
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, message: "Warmhug private server running" });
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ message: "아이디와 비밀번호가 필요합니다." });
    }

    if (username !== OWNER_USERNAME) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const ok = await bcrypt.compare(password, OWNER_PASSWORD_HASH);

    if (!ok) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const token = jwt.sign(
      { username: OWNER_USERNAME, role: "owner" },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "로그인 성공",
      token
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "로그인 처리 중 오류가 발생했습니다." });
  }
});

app.get("/api/private-data", authRequired, (req, res) => {
  try {
    const privateData = readPrivateData();
    return res.json({
      message: "불러오기 성공",
      privateData
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "데이터 불러오기 실패" });
  }
});

app.post("/api/private-data", authRequired, (req, res) => {
  try {
    const { privateData } = req.body || {};

    if (!privateData || typeof privateData !== "object") {
      return res.status(400).json({ message: "저장할 privateData가 필요합니다." });
    }

    writePrivateData(privateData);

    return res.json({
      message: "저장 성공",
      privateData
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "데이터 저장 실패" });
  }
});

app.listen(PORT, () => {
  ensureDataFile();
  console.log(`Warmhug private server listening on http://localhost:${PORT}`);
});
