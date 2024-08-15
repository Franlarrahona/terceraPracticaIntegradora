import { Router } from "express";
import config from "../config.js";
import ProductsController from "../controllers/products.controller.js";

const router = Router();
const controller = new ProductsController()



router.get('/products/:page', async (req, res) => {
    const data = await controller.get(config.PRODUCTS_PER_PAGE, req.params.page)
    console.log(data)
    if (!req.session.user) return res.redirect('/login');
    res.render('products', { data: data , user:req.session.user });
})

/*router.get("/products", async  (req, res) => {
    const products = await controller.get()
    if (!req.session.user) return res.redirect('/login');
    res.render('products', {products:products, user:req.session.user })
})*/

router.get("/login", async (req,res) =>{
    if (req.session.user) return res.redirect('/profile');
    res.render('login', {})
})

router.get('/profile', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    
    const user = await req.session.user;


    console.log(user)
    console.log(req.session.user)
    res.render('profile', { user: user});
});

router.get('/register', (req, res) =>{
    res.render('register',{})
})

router.get('/cambioDePassword', (req,res) =>{
    res.render('changePassword',{})
})

router.get('/sentMail', (req,res) =>{
    res.render('sentmail',{})
})
router.get('/nuevaPassword', (req,res) =>{
    res.render('newPassword',{})
})

export default router