## Goal
1. Register a user
2. Login a user
3. Allow him to access the dashboard, but after login only

### Information
Registration - firstname, lastname, email, password
Login - email, password

#### Model
User
1. firstname
2. lastname
3. email
4. password
5. token

#### Controller
/register
1. Collect all info from frontend - req.body
2. Validate - if all data exists, if not, send a note
3. Check if user already exists, if yes, don't proceed
4. Encrypt the password
5. Save to DB and send a key (token)

/Login
1. Collect all info from frontend - req.body
2. Validate - if all data exists, if not, send a note
3. Check if user already exists, if yes proceed
4. Match the password - Password is already encrypted
5. Create a key(token) for user and send it (direct, cookie)

/Login
1. Check if key is valid
2. Allow him the access

#### Config
Database connection