const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin')

module.exports = () => {
    return {
        mode: 'development',
        entry: {
            client_test: path.resolve(__dirname, '..', '..', 'test', 'index.test.js')
        },
        plugins:[
            new HtmlWebpackPlugin({
                template: path.join(__dirname, '..', '..', 'test', 'index.html') ,
                filename: 'index.html'
            })
        ],
        devServer: {
            compress: true,
            port: 8080,
            hot: true,
            static: [
                path.join(__dirname, '..', '..', '..', '..', '/') // should point to wherever node_modules is
            ],
            open: true
        }
    }
};