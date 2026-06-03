'use strict';

module.exports = function configureMongoose(mongoose) {
    if (!mongoose || typeof mongoose.set !== 'function') return mongoose;
    mongoose.set('useFindAndModify', false);
    mongoose.set('useCreateIndex', true);
    return mongoose;
};
