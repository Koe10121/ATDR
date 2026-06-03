export default (to, from, next) => {
    let auth = true;
    if(auth == true){
        next({ name: 'Pages' });
        return false;
    }
}
