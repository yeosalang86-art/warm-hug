const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = 3000;
const JWT_SECRET = "warmhug_super_secret_key_change_this_2026_very_long_key";

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Database("warmhug.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER PRIMARY KEY,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

function defaultUserData(username = "") {
  return {
    nickname: username || "",
    stats: {
      todayHugs: 0,
      weekWarmth: 0
    },
    emotions: [],
    reports: 0,
    suspensions: 0,
    rooms: {
      friend: [],
      comfort: [],
      help: []
    }
  };
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "로그인이 필요합니다." });
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
  res.json({ ok: true, message: "Warmhug server running" });
});

app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ message: "아이디와 비밀번호를 입력해주세요." });
    }

    if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) {
      return res.status(400).json({
        message: "아이디는 영문, 숫자, 밑줄(_)만 사용 가능하며 4~20자여야 합니다."
      });
    }

    if (password.length < 4 || password.length > 50) {
      return res.status(400).json({
        message: "비밀번호는 4자 이상 50자 이하로 입력해주세요."
      });
    }

    const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if (existing) {
      return res.status(409).json({ message: "이미 사용 중인 아이디입니다." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const insertUser = db.prepare(`
      INSERT INTO users (username, password_hash)
      VALUES (?, ?)
    `);

    const result = insertUser.run(username, passwordHash);
    const userId = result.lastInsertRowid;

    const insertData = db.prepare(`
      INSERT INTO user_data (user_id, data_json)
      VALUES (?, ?)
    `);

    insertData.run(userId, JSON.stringify(defaultUserData(username)));

    const user = { id: userId, username };
    const token = createToken(user);

    return res.json({
      message: "회원가입이 완료되었습니다.",
      token,
      user: {
        id: userId,
        username
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "회원가입 중 오류가 발생했습니다." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ message: "아이디와 비밀번호를 입력해주세요." });
    }

    const user = db.prepare(`
      SELECT id, username, password_hash
      FROM users
      WHERE username = ?
    `).get(username);

    if (!user) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const token = createToken(user);

    return res.json({
      message: "로그인 성공",
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "로그인 중 오류가 발생했습니다." });
  }
});

app.get("/api/me", authRequired, (req, res) => {
  return res.json({
    user: {
      id: req.user.userId,
      username: req.user.username
    }
  });
});

app.get("/api/my-data", authRequired, (req, res) => {
  try {
    const row = db.prepare(`
      SELECT data_json
      FROM user_data
      WHERE user_id = ?
    `).get(req.user.userId);

    if (!row) {
      return res.json({ data: defaultUserData(req.user.username) });
    }

    return res.json({
      data: JSON.parse(row.data_json)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "데이터 불러오기에 실패했습니다." });
  }
});

app.post("/api/my-data", authRequired, (req, res) => {
  try {
    const { data } = req.body || {};

    if (!data || typeof data !== "object") {
      return res.status(400).json({ message: "저장할 데이터가 필요합니다." });
    }

    const row = db.prepare(`
      SELECT user_id
      FROM user_data
      WHERE user_id = ?
    `).get(req.user.userId);

    if (row) {
      db.prepare(`
        UPDATE user_data
        SET data_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(JSON.stringify(data), req.user.userId);
    } else {
      db.prepare(`
        INSERT INTO user_data (user_id, data_json)
        VALUES (?, ?)
      `).run(req.user.userId, JSON.stringify(data));
    }

    return res.json({
      message: "저장되었습니다."
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "데이터 저장에 실패했습니다." });
  }
});

app.listen(PORT, () => {
  console.log(`Warmhug server running at http://localhost:${PORT}`);
});
