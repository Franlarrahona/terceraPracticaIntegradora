import express from "express";
import cors from "cors";
import handlebars from 'express-handlebars';
import session from 'express-session';
import fileStore from 'session-file-store';
import passport from 'passport';


import config from './config.js';
import cartsRoutes from './routes/carts.routes.js';
import productsRoutes from './routes/products.routes.js';
import sessionsRoutes from './routes/sessions.routes.js';
import usersRoutes from './routes/user.routes.js';
import MongoSingleton from "./services/mongo.singleton.js";
import sessionRouter from './routes/sessions.routes.js';
import viewsRoutes from './routes/views.routes.js'

try{
    
    const app = express();

    const httpServer = app.listen(config.PORT, () =>{
        MongoSingleton.getInstance();
        console.log(`backend funcionando en ${config.PORT}`);
    })
    
    app.use(express.json())
    app.use(express.urlencoded({extended: true}))
    app.use (cors({ origin: '*', methods: 'GET, POST, PUT, DELETE' }));

    const fileStorage = fileStore(session)
    app.use(session({
    store: new fileStorage ({path: './sessions', ttl:100, retries: 0}),
    secret: config.SECRET,
    resave:true,
    saveUninitialized: false
    }));

    app.use(passport.initialize());
    app.use(passport.session());

    app.engine('handlebars', handlebars.engine());
    app.set('views', `src/views`);
    app.set('view engine', 'handlebars');

    app.use('/',viewsRoutes);
    app.use('/api/carts', cartsRoutes);
    app.use('/api/products', productsRoutes);
    app.use('/api/sessions', sessionsRoutes);
    app.use('/api/users', usersRoutes)
    app.use('/api/sessions', sessionRouter);
    app.use('/static', express.static(`src/public`));

}catch(err){
    console.log(`error al iniciar banckend (${err.message})`)
}

