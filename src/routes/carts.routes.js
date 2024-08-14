import { Router } from "express";
import Controller from "../controllers/carts.controller.js"
import nodemailer from 'nodemailer';
import  config  from "../config.js";

const router = Router();
const controller = new Controller();
/*const transport = nodemailer.createTransport({
    service:'gmail',
    port:587,
    auth:{
        user: config.GMAIL_APP_USER,
        pass: config.GMAIL_APP_PASS
    }
})
*/

router.get('/mail', async(req,res) =>{
    try{
        const confirmation = await transport.sendMail({
            from: `programador estudiante <${config.GMAIL_APP_USER}>`,
            to:'correo ficticio @gmail.com',
            subject:'intento de mailing',
            html:'<h1> texto de prueba </h1>'
        })
        res.status(200).send({status:"ok", data: confirmation})
    }catch(err){
        res.status(500).send({status: 'err', data: err.message})
    }
})

router.get('/', async (req, res) =>{
    try{
        res.status(200).send({ status: 'ok' , data: await controller.get() });
    }catch(err){
        res.status(500).send({ status: 'err', data: err.message });
    }
})

router.get('/one/:cid', async (req, res) =>{
    try{
        const process = await controller.getById(req.params.cid)
        res.status(200).send({ status: 'ok' , data: process });
    }catch(err){
        res.status(500).send({ status: 'err', data: err.message });
    }
})

router.post('/', async(req,res) =>{
    try{
        const process = await controller.add(req.body)
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.put('/:id', async(req,res) =>{
    try{
        const filter = {_id: req.params.id };
        const update = req.body;
        const options = {new: true};
        const process = await controller.update(filter, update, options)
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.delete('/:cid', async(req,res) =>{
    try{
        const filter = {_id: req.params.cid}
        const process = await controller.delete(filter)
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.delete('/:cid/products', async (req, res) =>{
    try{
        const filter = {_id: req.params.cid};
        const update = {"id": filter, "products": []}
        const options = { new: true };
        const process = await controller.deleteProducts(filter, update, options)

        res.status(200).send({ origin: config.SERVER, payload: process });
    }catch (err) {
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });
    }
})

router.delete('/:cid/products/:pid',async (req, res) =>{
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;
        const process= await controller.deleteOneProduct(cid,pid)
        
        res.status(200).send({origin: config.SERVER,  payload: process});
        
    }catch (err) {
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });
    }
})


export default router;
