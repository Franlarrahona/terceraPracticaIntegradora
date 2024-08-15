import { Router } from "express";
import passport from "passport";

import config from "../config.js";
import { createHash, isValidPassword,createToken, verifyRequiredBody, handlePolicies } from "../services/utils.js";
import UsersController from "../controllers/user.controller.js";
import initAuthStrategies from "../auth/passport.strategies.js";
import nodemailer from 'nodemailer';


const router = Router();
const controller = new UsersController();
const transport = nodemailer.createTransport({
    service:'gmail',
    port:587,
    auth:{
        user:config.GMAIL_APP_USER,
        pass:config.GMAIL_APP_PASS
    }
})
initAuthStrategies()


router.post('/login', verifyRequiredBody(['email', 'password']), async (req, res) => {
    try {
        const { email, password } = req.body;
        const foundUser = await controller.getOne({ email: email });

        if (foundUser && isValidPassword(password, foundUser.password)) {
            const { password, ...filteredFoundUser } = foundUser;
            req.session.user = filteredFoundUser;
            req.session.save(err => {
                if (err) return res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });

                res.redirect('/products/1');
            });
        } else {
            res.status(401).send({ origin: config.SERVER, payload: 'Datos de acceso no válidos' });
        }
    } catch (err) {
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });
    }
});
router.post('/jwtlogin', verifyRequiredBody(['email', 'password']), passport.authenticate('login', { failureRedirect: `/login?error=${encodeURI('Usuario o clave no válidos')}`}), async (req, res) => {
    try {
        const token = createToken(req.user, '1h');
        res.cookie(`${config.APP_NAME}_cookie`, token, { maxAge: 60 * 60 * 1000, httpOnly: true });
        res.redirect('/products/1');
    } catch (err) {
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });
    }
});

router.post('/register', async(req,res) =>{
    try{
        const {firstName, lastName, email, password} = req.body;
        const foundUser = await controller.getOne({email:email});
        

        if(!foundUser){
            const process = await controller.add({firstName, lastName, email, password: createHash(password)});
            res.status(200).send({origin: config.SERVER, payload: process});
        }else{
            res.status(400).send({ origin: config.SERVER, payload:'el email ya se encuentra registrado'})
        }
    }catch (err){
        res.status(500).send({origin: config.SERVER, payload: null, error: err.message});
    }
});
router.get('/logout', async(req,res) =>{
    try{
        req.session.destroy((err) =>{
            if(err) return res.status(500).send({origin: config.SERVER, payload:'error al ejecutar logout', error:err})
            res.redirect('/login')
        });
    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message})
    }
})

router.post('/pplogin', verifyRequiredBody(['email','password']), passport.authenticate('pplogin', {failureRedirect: `/login?error=${encodeURI('Usuario o clave no válidos')}`}), async ( req, res) =>{
    try{

        req.session.user = req.user;
        req.session.save( err =>{
            if(err) return res.status(500).send({ origin: config.SERVER, payload: null, error:err.message});
            res.redirect('/products/1');

        });
    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message});
    }
});

router.post('/changePassword', async(req,res) =>{
    try{
        const {email} = req.body
        req.session.email = email
        res.send(email)
        const verifyEmail = await controller.getOne({ email: email })
        console.log(verifyEmail)
        
        if(!verifyEmail){
            res.status(401).send({ origin: config.SERVER, payload: 'el correo ingresado no corresponde a un correo vinculado a una cuenta  ' })
        }else{
            const confirmation = await transport.sendMail({
                from:` propietario de la pagina <${config.GMAIL_APP_USER}`,
                to:email,
                subject: 'cambio de contraseña ',
                html:'<a href="http://localhost:5050/nuevaPassword">cambiar contraseña</a>'
            })
            req.session.save(err => {
                if (err) return res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });

                res.redirect('/sentMail')
            });
                
        }
    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message})
    }
})

router.post('/newPassword', async(req,res) =>{
    try{
        const {password} = req.body;
        const email = req.session.email
        console.log(email);

    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message})
    }
})


export default router;