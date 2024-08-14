import usersService from "../services/users.dao.mdb.js";

const service = new usersService()

class userController {
    constructor(){
    
    }
    async get(){
        try{
            return await service.get()
        }catch(err){
            return err.message
        }
    }
    async getOne(filter){
        try {
            return await service.getOne(filter);
        } catch (err) {
            return err.message;
        };
    };
    async getById(id){
        try{
            return await service.getById(id)
        }catch(err){
            return err.message;
        }
    }
    async add(newData){
        try{
            return await service.add(newData)
        }catch(err){
            return err.message
        }
    }
    async update(filter, update, options){
        try{
            return await service.update(filter, update, options);
        }catch(err){
            return err.message
        }
    }
    async delete(id){
        try{
            return await service.delete(id)
        }catch(err){
            return err.message
        }
    }
}
export default userController;