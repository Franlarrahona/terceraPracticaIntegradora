import productsService from "../services/products.dao.mdb.js";

const service = new productsService()

class ProductsDTO {
    constructor(product) {
        this.product = product;
        this.product.title = this.product.title.toUpperCase();
    }
}


class productsController {
    constructor(){

    }
    async get(limit, page){
        try{
            return await service.get(limit, page);
        }catch(err){
            return err.message;
        }
    }
    async getById(id){
        try{
            return await service.getById(id);
        }catch(err){
            return err.message;
        }
    }
    async add(data){
        try{
            const normalizedData = new ProductsDTO(newData);
            return await service.add(normalizedData.product);
        }catch(err){
            return err.message
        }
    }
    async update(filter, update, options) {
        try{
            return await service.update(filter, update, options)
        }catch(err){
            return err.message
        }
    }  
    async delete(filter){
        try{
            return await service.delete(filter)
        }catch(err){
            return err.message
        }

    }
}
export default productsController;