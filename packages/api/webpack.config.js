const path = require("path");
const webpack = require("webpack");
const HtmlWebpackPlugin = require('html-webpack-plugin')

require('dotenv').config()

module.exports = () => {
    return {
        mode: 'production',
        entry: {
            test_page: './test/test-page/index.js'
        },
        output: {
            path: path.resolve(__dirname, 'dist'),
            filename: '[name].bundle.js'
        },
        experiments: {
            outputModule: true,
        },
        plugins: [
            new webpack.DefinePlugin({
                HOSTNAME: JSON.stringify(process.env.HOSTNAME),
                PORT: JSON.stringify(process.env.PORT)
            }),
            new HtmlWebpackPlugin({
                template: path.join(__dirname, 'test', 'test-page', 'index.html') ,
                filename: 'index.html'
            })
        ],
        devServer: {
            compress: true,
            port: 8080,
            hot: true,
            static: {
                directory: path.join(__dirname, '/')
            }
        }
    }
};