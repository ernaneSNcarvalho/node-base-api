import passport from 'passport';
import dotenv from 'dotenv';
import {Strategy as JWTStrategy, ExtractJwt} from 'passport-jwt';
import {User} from '../models/User';
import {Request, Response, NextFunction} from 'express';
import jwt from 'jsonwebtoken';

dotenv.config();

const NotAuthorizedJson = {status: 401, message: 'Nao autorizado'}

const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET as string
}

passport.use(new JWTStrategy(options, async(payload, done) => {
    const user = await User.findByPk(payload.id);
    if(user){
        return done(null, user);
    }else{
        return done(NotAuthorizedJson, false);
    }
}));

export const generateToken = (data: any) => {
    return jwt.sign(data, process.env.JWT_SECRET as string);
}

export const privateRoute = (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate('jwt', (err, user) => {
        req.user = user;
        return user ? next() : next(NotAuthorizedJson)
    })(req, res, next);
}

export default passport;