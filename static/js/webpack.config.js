const path = require('path');

module.exports = {
  entry: './entry.js',  // Entry file is in the root directory
  output: {
    filename: 'sats-connect-bundle.js',
    path: path.resolve(__dirname, 'static')  // Output to the 'static' folder
  },
  resolve: {
    fallback: {
      "crypto": false
    }
  }
};