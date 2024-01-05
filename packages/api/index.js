const { createWebServer } = require('./src/web-server');
require('dotenv').config()

function serve() {

    process.title = "HoodySupportSystem"

    const server = createWebServer(process.env.CERTS_DIR)

    server.listen(process.env.PORT, process.env.HOSTNAME, () => {
        if(process.env.CERTS_DIR){
            console.log(`Server is runnig at https://${process.env.HOSTNAME}:${process.env.PORT}/`);
        } else {
            console.log(`Server is runnig at http://${process.env.HOSTNAME}:${process.env.PORT}/`);
        }
    })
}

serve();
