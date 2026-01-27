# 🔐 Authentication System Explained (Beginner's Guide)

## 1. The "Mystery of the Incorrect Password" 🕵️‍♂️
**What happened?**
For 1.5 days, the login failed with "Incorrect Password" even though we *knew* the password was `analyst123`.

**The Root Cause:**
- **Hashing**: When we save a password, we don't save "analyst123". We save a mathematical garble like `pbkdf2:sha256...ax93...` which is ~100 characters long.
- **The Glitch**: Your database column for passwords was accidentally set to limit text to **10 characters** (e.g., `VARCHAR(10)`).
- **The Result**: 
    - We sent: `pbkdf2:sha256:600000$xK7j...` (102 chars)
    - Database saved: `pbkdf2:sha` (10 chars)
    - When verifying: The computer compared the full hash against the cut-off hash and said "NO MATCH! ❌"

**The Fix:**
1. We ran a SQL command (`ALTER TABLE...`) to change the column type to `TEXT` (unlimited length).
2. We ran `seed_users.py` to delete the old broken users and create new ones with full, correct hashes.

---

## 2. How Our Authentication Works (The Flow) 🌊

Here is the exact journey of your data when you click "Login":

### Step 1: The Courier (Frontend) 🚚
- **File**: `src/components/Login.jsx`
- **Action**: You type "analyst" and click Login.
- **Logic**: The React app packages this into a JSON parcel: `{ "username": "analyst", "password": "analyst123" }` and sends it to the Backend.

### Step 2: The Gatekeeper (Backend API) 🛡️
- **File**: `backend/api/auth.py` -> `login_user()`
- **Action**: The server receives the parcel.
- **Logic**: 
    1. It asks the Database: "Give me the file for user 'analyst'".
    2. The Database replies: "Here is the user. Their stored password hash is `pbkdf2:sha256...`".

### Step 3: The Verification (The Math) 🧮
- **File**: `backend/api/auth.py`
- **Tool**: `werkzeug.security.check_password_hash`
- **Action**: The backend takes your input (`analyst123`), hashes it *right now*, and sees if it matches the *stored hash*.
- **Visual**: 
    - `Hash("analyst123")` == `Stored_Hash`? -> **YES/NO**

### Step 4: The VIP Pass (JWT Token) 🎟️
- **If YES**: The server doesn't just say "OK". It creates a **JWT (JSON Web Token)**.
- **What is it?**: A digital ID card that says "This is Analyst, Valid until tomorrow".
- **Signature**: The server signs it with a secret key so no one can fake it.
- **Action**: The server sends this Token back to the Frontend.

### Step 5: The Memory (Browser Storage) 🧠
- **File**: `src/contexts/AuthContext.jsx`
- **Action**: The Frontend receives the Token.
- **Logic**: It saves the Token into `localStorage`. This is like putting the VIP pass in your pocket. 
- **Result**: You are now "Logged In".

### Step 6: Using the Pass (Protected Routes) 👮
- **File**: `src/utils/api.js`
- **Action**: Now you want to see Alerts. The Frontend sends a request to `/alerts`.
- **Logic**: Our "Interceptor" automatically grabs the VIP Pass (Token) from your pocket and staples it to the request header (`Authorization: Bearer <token>`).
- **Backend Check**: The backend sees the token, verifies the signature, and lets you pass.

---

## 3. Glossary for Beginners 📖

| Term | Definition | Analogy |
|------|------------|---------|
| **Plain Text** | The password as you type it (`analyst123`) | Writing a secret on a postcard. Bad! |
| **Hashing** | Scrambling the password into random characters (`pbkdf2...`) | Putting the secret through a paper shredder. You can't put it back together, but you can match the confetti. |
| **Salt** | Random data added to the password before hashing | Adding random spices so two identical steaks taste different. |
| **JWT** | JSON Web Token | A wristband at a concert. It proves you paid. |
| **Bearer Token** | The type of token we use | "Whoever *bears* (holds) this token is allowed in." |
| **CORS** | Cross-Origin Resource Sharing | A security guard asking "Are you allowed to talk to this server?" |
| **Seed Script** | `seed_users.py` | A robot that deletes everything and builds it fresh, so we always have a clean start. |

---

## 4. Why is this "Enterprise Grade"? 🏢
1. **We never store passwords**: Only hashes. If hackers steal the DB, they get nothing useful.
2. **Stateless**: The server doesn't remember you. The Token proves who you are. This makes the server very fast.
3. **Role-Based**: The Token contains your role (`analyst`). The frontend uses this to show/hide the "Debug Dashboard" automatically.
