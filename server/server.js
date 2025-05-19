const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const app = express();
require('dotenv').config();
const session = require('express-session');

app.use(session({
  secret: 'mi-clave-secreta', // cámbiala por algo más seguro
  resave: false,
  saveUninitialized: false
}));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true });

app.post('/register', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  await User.create({ email: req.body.email, password: hashedPassword });
  res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.userId = user._id;
    req.session.userName = user.name;
    res.redirect('/index(users).html');  // 👈 Redirección aquí
  } else {
    res.send('Credenciales inválidas');
  }
});

app.get('/index(users)', (req, res) => {
  if (req.session.userId) {
    res.sendFile(__dirname + '/public/index(users).html');
  } else {
    res.redirect('/login.html');  // 👈 Redirige si no está logueado
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

app.get('/api/usuario', (req, res) => {
  if (req.session.userId) {
    res.json({ name: req.session.userName });
  } else {
    res.status(401).json({ error: 'No autenticado' });
  }
});


app.listen(3000, () => console.log('Servidor corriendo en http://localhost:3000'));
