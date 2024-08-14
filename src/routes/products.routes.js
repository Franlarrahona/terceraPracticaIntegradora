import { Router } from "express";
import Controller from '../controllers/products.controller.js'
import { verifyToken, handlePolicies, adminAuth } from "../services/utils.js";

const router = Router();
const controller = new Controller();

router.get('/', async (req,res) =>{
    try{
        res.status(200).send({ status: 'ok', data: await controller.get() });
    }catch(err){
        res.status(500).send({ satus: 'err', data: err.message});
    }
})

router.get('/one/:id',async(req,res) =>{
    try{
        res.status(200).send({status:'ok', data: await controller.getById(req.params.id)})
    }catch(err){
        res.status(500).send({status: 'err', data: err.message});
    }
})

router.post('/',verifyToken, handlePolicies(['admin']), async(req,res) =>{
    try{
        const process = await controller.add(req.body)
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.put('/:id',verifyToken, handlePolicies(['admin']), async(req,res) =>{
    try{
        const filter = {_id: req.params.id};
        const update = req.body;
        const option = {new:true};

        const process = await manager.update(filter, update, option)
        res.status(200).send({ status:'ok', data: await process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.delete('/:id',verifyToken, handlePolicies(['admin']), async(req,res) =>{
    try{
        const filter = {_id: req.params.id}
        const process = await manager.delete(filter)
        
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

export default router;