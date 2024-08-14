import cartsServices from "../services/carts.dao.mdb.js";

const service = new cartsServices();

class cartsController {
    constructor(){

    }
    async get(){
        try{
            return service.get()
        }catch(err){
            return err.message
        }

    }
    async getById(){
        try{
            return service.getById(id)
        }catch(err){
            return err.message
        }

    }
    async add(newData){
        try{
            return service.add(newData)
        }catch(err){
            return err.message
        }
    }
    async update(filter, update, options) {
        try{
            return service.update(filter, update, options)
        }catch(err){
            return err.message
        }
    }
    async delete(filter){
        try{
            return service.delete(filter)
        }catch(err){
            return err.message
        }
    }
    async deleteProducts(filter, update, options){
        try{
            return service.deleteProducts(filter, update, options)
        }catch(err){
            return err.message
        }
    }
    async deleteOneProduct(cid,pid){
        try{
            return service.deleteOneProduct(cid,pid)
        }catch(err){
            return err.message
        }
    }
}
export default cartsController;