import { Router } from "express";
import Controller from '../controllers/user.controller.js'

const router = Router();
const controller = new Controller();

router.get('/', async(req,res) =>{
    try{
        res.status(200).send({ status:'ok', data: await controller.get()});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.post('/', async(req,res) =>{
    try{
        const process = await controller.add(req.body);

        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.put('/:id', async(req,res) =>{
    try{
        const filter = {_id: req.params.id };
        const update = req.body;
        const options = {new: true };
        const process = await controller.update(filter, update, options)
        res.status(200).send({ status:'ok', data: process});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

router.delete('/:id', async(req,res) =>{
    try{
        res.status(200).send({ status:'ok', data: await controller.delete()});
    }catch(err){
        res.status(500).send({ status:'err', data: err.message});
    }
})

export default router;