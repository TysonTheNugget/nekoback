const path = require('path');

module.exports = {
  mode: 'development', // Use development for debugging
  entry: './entry.js',
  output: {
    filename: 'sats-connect-bundle.js',
    path: path.resolve(__dirname, 'static'),
    library: 'SatsConnect', // Expose as window.SatsConnect
    libraryTarget: 'umd', // Universal Module Definition
    globalObject: 'window',
  },
  resolve: {
    fallback: {
      crypto: false,
    },
  },
};