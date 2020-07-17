import fs from 'fs';
import bodyParser from 'body-parser';
import jsonServer from 'json-server';
import jwt from 'jsonwebtoken';


type User = {
  username: string;
  password: string;
}

const server = jsonServer.create();
const router = jsonServer.router('./db.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', { encoding: 'utf-8' }));

server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json())
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';
const expiresIn = '1h';

// Create a token from a payload 
function createToken(payload: User) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn })
}

// Verify the token 
function verifyToken(token: string) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err)
}

// Check if the user exists in database
function isAuthenticated({ username, password }: User) {
  return userdb.users.findIndex((user: User) => user.username === username && user.password === password) !== -1
}

server.post('/auth/login', (req, res) => {
  console.log(req.body);
  const { username, password }: User = req.body;
  if (isAuthenticated({ username, password }) === false) {
    const status = 401;
    const message = 'Incorrect username or password';
    res.status(status).json({ status, message });
    return;
  }
  const access_token = createToken({ username, password });
  res.status(200).json({ access_token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Bad authorization header'
    res.status(status).json({ status, message })
    return
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1])
    next()
  } catch (err) {
    const status = 401
    const message = 'Error: access_token is not valid'
    res.status(status).json({ status, message })
  }
});

server.use(router)

server.listen(8000, () => {
  console.log('Run Auth API Server')
})