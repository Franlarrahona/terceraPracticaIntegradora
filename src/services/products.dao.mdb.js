import productsModel from '../models/products.model.js';

class productsService {
    constructor(){

    }
    async get(limit = 10 , page = 1){
        try{
            return limit === 0 ? await productsModel.find().lean():  await productsModel.paginate({}, {page: page, limit: 10 , lean: true});
        }catch(err){
            return err.message;
        }
    }
    async getById(id){
        try{
            return await productsModel.findById(id).lean();
        }catch(err){
            return err.message
        };
    }
    async add(newData){
        try{
            return await productsModel.create(newData);
        }catch(err){
            return err.message;
        }
    }
    async update(filter, update, options){
        try{
            return await productsModel.findOneAndUpdate(filter, update, options);
        }catch(err){    
            return err.message
        }
    }
    async delete(filter){
        try{
            return await productsModel.findOneAndDelete(filter);
        }catch(err){
            return err.message
        }
    }
}


export default productsService;