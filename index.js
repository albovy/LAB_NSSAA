const express = require('express');
const passport = require('passport');
const logger = require('morgan');
const LocalStrategy = require('passport-local').Strategy;
const jwtStrategy = require('passport-jwt').Strategy;
const githubStrategy = require('passport-github2').Strategy;
const path = require('path');
const jwt  = require('jsonwebtoken');
const jwtSecret= require('crypto').randomBytes(32);
const cookieParser = require('cookie-parser');
const fortune = require('fortune-teller');
const PORT = 3000;
const fakeDb = require("./fake-db.json");
const bcrypt = require('bcryptjs');
const app = express();
app.use(logger('dev'))
app.use(express.json()); //Used to parse JSON bodies
app.use(express.urlencoded({extended:true})); //Parse URL-encoded bodies
app.use(cookieParser())


const GITHUB_CLIENT_ID = "a57a5678b7870738315b";
const GITHUB_CLIENT_SECRET = "4be6b0c95eda828b1f8fbb79055632bd304444f6";

passport.use('local',new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password',
        session:false
    },(username,password,done)=>{

       /*if(username === 'walrus' && password === 'walrus'){
            const user = {
                username:'walrus',
                description:'descripción'
            }
            return done(null,user);
        }
        return done(null,false);*/
        const passwordHash = fakeDb[username];
        if(passwordHash && bcrypt.compareSync(password,passwordHash)){
                const user ={
                    username: username,
                    description: 'usuario'
                }
                return done(null,user);
            }
        return done(null,false);
    }
));

passport.use('github', new githubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/callback"
  },
  function(accessToken, refreshToken, profile, done) {
      
    if(profile){
        return done(null, profile);
    }
    return done(null, err)
  }
));




var cookieExtractor = function(req) {
    var token = null;
    if (req && req.cookies) token = req.cookies['jwt'];
    return token;
  };
var jwtOptions = {

    jwtFromRequest: cookieExtractor,
    secretOrKey: jwtSecret,
    issuer: "localhost:3000",
    audience: "localhost:3000"
};
/* PASSPORT */
passport.use('jwt', new jwtStrategy(jwtOptions,(jwt_payload,done) =>{

    if(jwt_payload){
        return done(null,jwt_payload);
    }
    return done(null,err);
}));
app.use(passport.initialize());
/*  ------------------ */
const myLogger = (req,res,next)=>{
    //console.log(req.cookies)
     next();
}


app.use((err,req,res,next)=>{
    console.log(err.stack);
    res.status(500).send('There was an error')

});
app.use(myLogger);


app.get('/', passport.authenticate('jwt',{session:false,failureRedirect: '/login'}),(req,res)=>{
    res.send(fortune.fortune()+ '<a href="http://localhost:3000/logout">logout</a>');
})


app.get('/user',(req,res)=>{
    const user = {
        username:"walrus",
        description:"description"
    }
    res.json(user)
});

app.get('/login',(req,res)=>{
    res.sendFile(path.join(__dirname,"login.html"));
});

app.post('/login', passport.authenticate('local',{session : false,failureRedirect: '/login'}),(req,res)=>{
    const payload ={
        exam:{
            name: "Alejandro",
            surname: "Borrajo Viéitez"
        },
        iss: "localhost:3000",
        sub: req.user.username,
        aud: "localhost:3000",
        exp: Math.floor(Date.now() / 1000) + 604800
    }
    const token = jwt.sign(payload,jwtSecret);
    res.cookie('jwt',token);
    res.redirect('/');
});

app.get('/logout', passport.authenticate('jwt',{session:false,failureRedirect:'/login'}),(req,res)=>{
    res.clearCookie('jwt');
    res.redirect('/login');
});

app.get('/auth/github', passport.authenticate('github', { scope: [ 'profile:username' ] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    //res.redirect('/');
  });

app.listen(PORT,()=>{
    console.log(`Listening at http://localhost:${PORT}`);
});