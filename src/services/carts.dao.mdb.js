import cartsModel from "../models/carts.model.js";

class cartsServices{
    constructor(){
        this.cart = cartsModel
    }
    async get(){
        try{
            const process = cartsModel.find().lean();
            return await process
        }catch(err){
            return err.message;
        }
    }
    async getById(id){
        try{
            const process = cartsModel.findById(id).lean();
            return await process
        }catch(err){
            return err.message;
        }
    }
    async add(newData){
        try{
            const process = cartsModel.create(newData)
            return await process
        }catch(err){
            return err.message
        }
    }
    async update(filter,update, options){
        try{
            const process = cartsModel.findOneAndUpdate(filter, update, options);
            return await process
        }catch(err){
            return err.message
        }
    }
    async delete(filter){
        try{
            const process = cartsModel.findOneAndDelete(filter)
            return await process
        }catch(err){
            return err.message
        }
    }
    async deleteProducts(filter, update, options){
        try{
            const process = cartsModel.findOneAndUpdate(filter, update, options) 
            return await process
        }catch(err){
            return err.message
        }
    }

    async deleteOneProduct(cid, pid){
        try{
            const process = this.cart.findByIdAndUpdate(
                cid,
                {$pull: {products: {'_id': new mongoose.TypesObjectId(pid)}}},
                {new:true}
            );
            return await process
        }catch(err){
            return err.message
        }
    }
}

export default cartsServices;