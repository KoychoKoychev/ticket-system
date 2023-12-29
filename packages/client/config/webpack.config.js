const path = require("path");

module.exports = () => {
    return {
        mode: 'production',
        entry: {
            client: path.resolve(__dirname, '..', 'index.js')
        },
        output: {
            path: path.resolve(__dirname, '..', 'dist'),
            filename: '[name].js',
            library: {
                type: 'commonjs-static'
            }
        },
        optimization: {
            minimize: false,
        },
        experiments: {
            outputModule: true,
        }
    }
};