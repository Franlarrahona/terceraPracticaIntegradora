import passport from "passport";
import local from "passport-local";
import jwt from 'passport-jwt';

import config from '../config.js'
import usersManager from "../services/users.dao.mdb.js";
import { isValidPassword } from "../services/utils.js";

const localStrategy = local.Strategy;
const jwtStrategy = jwt.Strategy;
const jwtExtractor = jwt.ExtractJwt;
const manager = new usersManager();

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) token = req.cookies[`${config.APP_NAME}_cookie`];
    
    return token;
}



passport.use('jwtlogin', new jwtStrategy(
    {
        jwtFromRequest: jwtExtractor.fromExtractors([cookieExtractor]),
        secretOrKey: config.SECRET
    },
    async (jwt_payload, done) => {
        try {
            return done(null, jwt_payload);
        } catch (err) {
            return done(err);
        }
    }
));


const initAuthStrategies = () =>{
    passport.use('login', new localStrategy(
        {passReqToCallback: true, usernameField: 'email'},
        async (req, username, password, done) =>{
            try{
                const foundUser = await manager.getOne({email: username});

                if(foundUser && isValidPassword(password, foundUser.password)) {
                    const {password, ...filteredFoundUser} = foundUser;
                    return done (null, filteredFoundUser);
                }else{
                    return done (null, false);

                }
            } catch (err) {
                return done(err, false);
            }
        }
    ));
    passport.serializeUser((user, done) => {
        done(null, user);
    })
        
    passport.deserializeUser((user, done) => {
        done(null, user);
    })
}

export default initAuthStrategies;